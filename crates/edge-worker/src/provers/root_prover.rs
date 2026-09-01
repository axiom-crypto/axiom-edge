//! Root Prover implementation (behind `evm-prove`).
//!
//! Reconstructs a `VmStarkProof` from the worker's final internal proof and
//! hands it to `sdk_v2::prover::RootProver::prove`, which owns the root
//! tracegen + wrap-retry loop:
//!
//!   loop {
//!       if let Some(ctx) = generate_proving_ctx(stark_proof.clone()) { break ctx }
//!       stark_proof = wrap(stark_proof);   // wrap closure, supplied by us
//!   }
//!   prove_from_ctx(ctx)
//!
//! We only supply the wrap closure, which is edge-specific: it rewraps through
//! the `internal_recursive_prover` the worker already holds (the agg prover's
//! recursive layer), replicating `AggProver::wrap_proof` without owning an
//! `AggProver` or threading `InternalLayerMetadata` across the wire.
//!
//! Mock mode emits a byte-vec root proof so the in-process EVM prove is
//! testable without real keys.

use eyre::Result;
#[cfg(feature = "mock-provers")]
use std::time::{Duration, Instant};
use tracing::{info, instrument};

use protocol::RootProofState;

use super::RootProverJob;

/// Execute root proving on the final internal stark proof (mock path only; real
/// builds drive `prove_root_with_prover` from the worker pool).
#[cfg(feature = "mock-provers")]
#[instrument(skip_all, fields(
    proof_id = %job.context.proof_uuid,
))]
pub fn prove_root(job: RootProverJob) -> Result<RootProofState> {
    info!(
        "Starting root prove for proof {} (mock path)",
        job.context.proof_uuid
    );

    prove_root_impl(job)
}

#[cfg(feature = "mock-provers")]
fn prove_root_impl(_job: RootProverJob) -> Result<RootProofState> {
    let start = Instant::now();
    std::thread::sleep(Duration::from_millis(50));
    let prove_time_ms = start.elapsed().as_millis() as u64;

    let mock_proof = proof::RootProof(vec![0u8; 2048]);
    Ok(RootProofState {
        proof: Some(proof::encode_root_proof(&mock_proof)?),
        prove_time_ms,
        sub_metrics: std::collections::HashMap::new(),
    })
}

// ============================================================================
// Real prover implementation (default, gated on `evm-prove`)
// ============================================================================

#[cfg(all(not(feature = "mock-provers"), feature = "evm-prove"))]
mod real_impl {
    use super::super::real_prover_types::{
        ChildVkKind, InternalProver, RecursionEngine, RootEngine, RootProver,
        VerifierCircuitType,
    };
    use super::*;
    use crate::artifacts::ArtifactStore;
    use continuations_v2::circuit::inner::ProofsType;
    use sdk_v2::prover::RootProver as SdkRootProver;
    use std::sync::Arc;
    use verify_stark::VmStarkProof;

    /// Reusable root prover state, built once per root worker thread.
    ///
    /// Holds the wrapped sdk-v2 root prover plus its own
    /// `internal_recursive_prover` (the wrap-retry path's executor) and a
    /// cached recursion engine. The recursive internal prover is built
    /// locally from the agg key — keygen-equivalent to the one inside
    /// `InternalProverInstance`, but owned independently so the root worker
    /// thread doesn't need to share state with internal worker threads (and
    /// `RootProver`'s access pattern is single-threaded against this prover).
    ///
    /// `root_engine` is cached here  — `create_engine()`
    /// is non-trivial (FRI/whir parameter materialization)
    pub struct RootProverInstance {
        pub root_prover: RootProver,
        pub internal_recursive_prover: Arc<InternalProver>,
        pub root_engine: RootEngine,
    }

    impl RootProverInstance {
        /// Construct from the global artifact store. Builds a fresh
        /// `internal_recursive_prover` from the agg key (so the wrap-retry
        /// path inside root prove doesn't depend on the internal worker's
        /// instance) and then a `RootProver` over it + `root_pk`.
        ///
        /// `EdgeArtifacts.evm` must be `Some(...)`; the caller is the root
        /// worker thread, which is only spawned when `evm-prove` is enabled.
        /// If `evm: None` (no halo2_pk_path configured, or deferral mode +
        /// cached_pk.root_pk missing), construction fails — the worker logs
        /// and the thread exits, leaving `/readyz` not ready for evm-typed
        /// proofs.
        pub fn new() -> Result<Self> {
            let artifact_store = ArtifactStore::global()
                .ok_or_else(|| eyre::eyre!("Artifact store not initialized"))?;
            let edge_artifacts = artifact_store
                .get_edge_artifacts()
                .ok_or_else(|| eyre::eyre!("Edge artifacts not loaded"))?;
            let evm = edge_artifacts
                .evm
                .as_ref()
                .ok_or_else(|| eyre::eyre!("EVM artifacts not loaded (halo2_pk_path missing?)"))?;

            // `Some(def_hook_*_commit)` in deferral mode, `None`
            // otherwise. `is_deferral_deployment` is the same toggle.
            let def_hook_cached_commit = edge_artifacts.def_hook_cached_commit();
            let def_hook_commit = edge_artifacts.def_hook_commit();
            let is_deferral_deployment = edge_artifacts.is_deferral_deployment();

            // Build the recursive internal prover (the wrap-retry executor).
            // Equivalent to AggProver::from_pk's `internal_recursive_prover`
            // arm (sdk/src/prover/agg.rs:127-131).
            info!(
                "Creating RootProverInstance: internal_recursive_prover (deferral_mode={})",
                is_deferral_deployment
            );
            let internal_for_leaf_vk = Arc::new(
                edge_artifacts
                    .agg_stark_pk
                    .prefix
                    .internal_for_leaf
                    .get_vk(),
            );
            let internal_recursive_prover: InternalProver =
                InternalProver::from_pk::<RecursionEngine>(
                    internal_for_leaf_vk,
                    edge_artifacts.agg_stark_pk.internal_recursive.clone(),
                    VerifierCircuitType::InternalRecursive,
                    def_hook_cached_commit,
                );
            let internal_recursive_prover = Arc::new(internal_recursive_prover);

            // Construction mirrors sdk-v2 builder.rs:404 (root_prover_seed).
            let internal_recursive_vk = internal_recursive_prover.get_vk();
            let internal_recursive_vk_commit = internal_recursive_prover
                .get_self_vk_pcs_data()
                .ok_or_else(|| {
                    eyre::eyre!(
                        "internal_recursive_prover has no self_vk_pcs_data; \
                         construct with VerifierCircuitType::InternalRecursive"
                    )
                })?
                .commitment
                .into();

            let system_config = edge_artifacts.app_pk.app_vm_pk.vm_config.as_ref();
            let memory_dimensions = system_config.memory_config.memory_dimensions();
            let num_user_pvs = system_config.num_public_values;

            info!("Creating RootProverInstance: sdk root prover...");
            let root_prover = SdkRootProver::from_pk(
                internal_recursive_vk,
                internal_recursive_vk_commit,
                evm.root_pk.root_pk.clone(),
                memory_dimensions,
                num_user_pvs,
                def_hook_commit,
                Some(evm.root_pk.trace_heights.clone()),
            );
            // Cache the recursion engine up-front so each root-prove call
            // skips the FRI/whir parameter rematerialization. The engine is
            // immutable and shared across all proves on this worker thread.
            let root_engine = root_prover.create_engine();
            info!("RootProverInstance created successfully");

            Ok(Self {
                root_prover,
                internal_recursive_prover,
                root_engine,
            })
        }
    }

    /// Execute root proving using a provided prover instance.
    #[instrument(skip_all, fields(
        proof_id = %job.context.proof_uuid,
    ))]
    pub fn prove_root_with_prover(
        job: RootProverJob,
        prover_instance: &RootProverInstance,
    ) -> Result<RootProofState> {
        info!(
            "Starting root prove (with prover) for proof {}",
            job.context.proof_uuid
        );

        prove_root_impl_with_prover(job, prover_instance)
    }

    fn prove_root_impl_with_prover(
        job: RootProverJob,
        prover_instance: &RootProverInstance,
    ) -> Result<RootProofState> {
        // Reconstruct `VmStarkProof` from the worker's final internal proof.
        // The edge's `ProofWithPublicValue<F>` carries both `Proof<SC>` and the
        // user public values proof; root prove needs them combined.
        let final_internal_proof = job.final_internal_proof;
        let user_pvs_proof = final_internal_proof.user_public_values.ok_or_else(|| {
            eyre::eyre!(
                "final internal proof is missing user_public_values; \
                 cannot reconstruct VmStarkProof for root prove"
            )
        })?;

        let stark_proof = VmStarkProof {
            inner: final_internal_proof.proof,
            user_pvs_proof,
            deferral_merkle_proofs: job.deferral_merkle_proofs,
        };

        let proof_has_deferral = job.proof_has_deferral;
        let internal_recursive_prover = prover_instance.internal_recursive_prover.clone();

        // Delegate the root tracegen + wrap-retry loop to the SDK's
        // `RootProver::prove`. We only supply the edge-specific wrap closure;
        // it rewraps through the recursive internal prover (no
        // `InternalLayerMetadata`, so we don't reuse `AggProver::wrap_proof`).
        const MAX_ROOT_TRACEGEN_RETRIES: usize = 8;
        let _ = telemetry::span_timing::drain_span_timings();
        let prove_start = std::time::Instant::now();

        let root_proof_inner = prover_instance.root_prover.prove(
            stark_proof,
            &prover_instance.root_engine,
            MAX_ROOT_TRACEGEN_RETRIES,
            |p| wrap_vm_stark_proof(&internal_recursive_prover, proof_has_deferral, p),
        )?;
        let prove_time_ms = prove_start.elapsed().as_millis() as u64;
        let sub_metrics = telemetry::span_timing::drain_span_timings();

        let typed = proof::RootProof(root_proof_inner);
        Ok(RootProofState {
            proof: Some(proof::encode_root_proof(&typed)?),
            prove_time_ms,
            sub_metrics,
        })
    }

    /// Replicates `AggProver::wrap_proof` (sdk/src/prover/agg.rs:329) — wraps a
    /// `VmStarkProof.inner` once through the recursive internal prover so the
    /// next root tracegen attempt sees a taller proof. `metadata` bookkeeping
    /// in the SDK is only used for tracing spans; we drop it here since the
    /// worker doesn't propagate `InternalLayerMetadata` across the wire.
    ///
    /// When THIS proof ran the tail merge, the proof entering root has
    /// `proofs_type = Combined` after `prove_mixed` (see
    /// `agg.rs::prove_mixed` setting `metadata.proofs_type = Combined`
    /// at line 328), so a retry wrap must also use `Combined`. A proof that
    /// did not defer (including a no-deferral proof on a deferral deployment)
    /// keeps `proofs_type = Vm`, so its retry wrap uses `Vm`.
    fn wrap_vm_stark_proof(
        internal_recursive_prover: &InternalProver,
        proof_has_deferral: bool,
        mut proof: VmStarkProof,
    ) -> Result<VmStarkProof> {
        let proofs_type = if proof_has_deferral {
            ProofsType::Combined
        } else {
            ProofsType::Vm
        };
        info!(
            "Root tracegen returned None; wrapping VmStarkProof once more (proofs_type={:?})",
            match proofs_type {
                ProofsType::Vm => "Vm",
                ProofsType::Deferral => "Deferral",
                ProofsType::Mix => "Mix",
                ProofsType::Combined => "Combined",
            }
        );
        proof.inner = internal_recursive_prover.agg_prove::<RecursionEngine>(
            &[proof.inner],
            ChildVkKind::RecursiveSelf,
            proofs_type,
            None,
        )?;
        Ok(proof)
    }
}

#[cfg(all(not(feature = "mock-provers"), feature = "evm-prove"))]
pub use real_impl::{prove_root_with_prover, RootProverInstance};
