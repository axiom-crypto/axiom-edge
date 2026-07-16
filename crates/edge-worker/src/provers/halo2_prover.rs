//! Halo2 Prover implementation (behind `evm-prove`).
//!
//! Wraps `sdk_v2::prover::Halo2Prover` and produces an EVM proof from a root
//! proof. Mirrors `EvmProver::prove_evm` /
//! `Halo2Prover::prove_for_evm(&Proof<RootSC>) -> EvmProof` in
//! `crates/sdk/src/prover/halo2.rs`.
//!
//! Mock mode emits a byte-vec `ProofResult::Evm` so the in-process EVM prove
//! is testable without real keys.

use eyre::Result;
#[cfg(feature = "mock-provers")]
use std::time::{Duration, Instant};
use tracing::{info, instrument};

#[cfg(all(not(feature = "mock-provers"), feature = "evm-prove"))]
use protocol::ProofResult;
#[cfg(feature = "mock-provers")]
use protocol::{EvmProof, EvmProofState, ProofResult};

use super::{Halo2ProverJob, ProverResult};

/// Execute halo2 proving on the root proof (mock path only; real builds drive
/// `prove_halo2_with_prover` from the worker pool).
#[cfg(feature = "mock-provers")]
#[instrument(skip_all, fields(
    proof_id = %job.context.proof_uuid,
))]
pub fn prove_halo2(job: Halo2ProverJob) -> ProverResult {
    info!(
        "Starting halo2 prove for proof {} (mock path)",
        job.context.proof_uuid
    );

    match prove_halo2_impl(job) {
        Ok(results) => ProverResult::Success(results),
        Err(e) => ProverResult::Error(format!("Halo2 prove failed: {}", e)),
    }
}

#[cfg(feature = "mock-provers")]
fn prove_halo2_impl(job: Halo2ProverJob) -> Result<Vec<ProofResult>> {
    let start = Instant::now();
    std::thread::sleep(Duration::from_millis(50));
    let prove_time_ms = start.elapsed().as_millis() as u64;

    let mock_proof = proof::EvmProof(vec![0u8; 4096]);
    let result = EvmProof {
        context: job.context,
        state: EvmProofState {
            proof: Some(proof::encode_evm_proof(&mock_proof)?),
            prove_time_ms,
            // Folded in by `run_evm_prove` from the root job's timing.
            root_prove_time_ms: 0,
            sub_metrics: std::collections::HashMap::new(),
        },
    };

    Ok(vec![ProofResult::Evm(result)])
}

// ============================================================================
// Real prover implementation (default, gated on `evm-prove`)
// ============================================================================

#[cfg(all(not(feature = "mock-provers"), feature = "evm-prove"))]
mod real_impl {
    use super::super::real_prover_types::Halo2Prover;
    use super::*;
    use crate::artifacts::ArtifactStore;
    use protocol::{EvmProof as ProtoEvmProof, EvmProofState};

    /// Reusable halo2 prover state, built once per halo2 worker thread.
    pub struct Halo2ProverInstance {
        pub prover: Halo2Prover,
    }

    impl Halo2ProverInstance {
        /// Construct from the global artifact store. Requires
        /// `EdgeArtifacts.evm` to be `Some(...)` (halo2_pk + SRS reader
        /// loaded from `--halo2-pk-path`).
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

            info!("Creating Halo2ProverInstance...");
            // sdk-v2 `Halo2Prover::new(&reader, halo2_pk)` reads `verifier_srs` /
            // `wrapper_srs` via the params reader using `k` baked into the pk.
            let prover = Halo2Prover::new(&*evm.halo2_params_reader, (*evm.halo2_pk).clone());
            info!("Halo2ProverInstance created successfully");

            Ok(Self { prover })
        }
    }

    /// Execute halo2 proving using a provided prover instance.
    #[instrument(skip_all, fields(
        proof_id = %job.context.proof_uuid,
    ))]
    pub fn prove_halo2_with_prover(
        job: Halo2ProverJob,
        prover_instance: &Halo2ProverInstance,
    ) -> ProverResult {
        info!(
            "Starting halo2 prove (with prover) for proof {}",
            job.context.proof_uuid
        );

        match prove_halo2_impl_with_prover(job, prover_instance) {
            Ok(results) => ProverResult::Success(results),
            Err(e) => ProverResult::Error(format!("Halo2 prove failed: {}", e)),
        }
    }

    fn prove_halo2_impl_with_prover(
        job: Halo2ProverJob,
        prover_instance: &Halo2ProverInstance,
    ) -> Result<Vec<ProofResult>> {
        let proof::RootProof(root_proof) = job.root_proof;

        let _ = telemetry::span_timing::drain_span_timings();
        let prove_start = std::time::Instant::now();
        let evm_proof_sdk = prover_instance.prover.prove_for_evm(&root_proof);
        let prove_time_ms = prove_start.elapsed().as_millis() as u64;
        let sub_metrics = telemetry::span_timing::drain_span_timings();

        let typed: proof::EvmProof = evm_proof_sdk;
        let result = ProtoEvmProof {
            context: job.context,
            state: EvmProofState {
                proof: Some(proof::encode_evm_proof(&typed)?),
                prove_time_ms,
                // Folded in by `run_evm_prove` from the root job's timing.
                root_prove_time_ms: 0,
                sub_metrics,
            },
        };

        Ok(vec![ProofResult::Evm(result)])
    }
}

#[cfg(all(not(feature = "mock-provers"), feature = "evm-prove"))]
pub use real_impl::{prove_halo2_with_prover, Halo2ProverInstance};
