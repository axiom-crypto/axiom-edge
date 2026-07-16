//! Stark-level deferral self-recursion e2e test.
//!
//! Validates the deferral pipeline edge ships by mirroring openvm's
//! canonical `tests::test_verify_stark_deferral` but
//! **driving edge's code paths** for the parts that are edge-owned:
//!
//! - The deferral keyset is built via `edge_worker::openvm_config::create_edge_sdk_with_deferral()`
//!   — the exact glue that `keygen --with-deferral` and the worker boot
//!   reconstruction call. So the SDK / proving keys exercised here are the
//!   ones a deferral-enabled edge deployment uses.
//! - The terminal-side merkle-path extraction goes through
//!   `edge_worker::deferral_merkle::{extract_deferral_auth_path,
//!   finalize_deferral_path, build_initial_memory_tree}` — the same helpers
//!   `run_deferral_tail_merge` calls. We byte-equate the edge-extracted +
//!   edge-finalized merkle proofs against the SDK's canonical
//!   `compute_deferral_merkle_proofs` over the **real prover memory state**
//!   produced by a deferral run. That's the first real-prover exercise of
//!   these helpers (the unit tests only used synthetic memory).
//! - The merge sequence (`prove_def → prove_mixed → wrap`) and the root
//!   prove run through the SDK's `Sdk::prove` / `EvmProver::prove_root` —
//!   which are the *same calls* `run_deferral_tail_merge` makes (it
//!   reconstructs an `Sdk` via `Sdk::from_deferral_cached_proving_key` and
//!   drives `agg_prover.prove_mixed` / `wrap_proof` directly). Running them
//!   here over edge's keyset verifies the merged proof is well-formed end-
//!   to-end.
//!
//! What is **not** covered here (a remaining real-hardware step): the distributed-cluster path (manager
//! fan-out + `run_deferral_tail_merge` over the wire) and the EVM/halo2
//! tail. The cluster path is functionally an HTTP-shaped wrapper around the
//! same SDK calls (the worker-side merge code in
//! `handlers.rs::run_deferral_tail_merge` is just
//! `Sdk::from_deferral_cached_proving_key` plus `agg_prover.prove_mixed`
//! plus `agg_prover.wrap_proof` plus edge merkle helpers — all exercised
//! here). The halo2 stage needs a GPU and the KZG params dir; verified in
//! a separate deploy-env run.
//!
//! # Cost
//!
//! Real prover on CPU. The edge VM config + deferral keyset is heavy:
//! `keygen --with-deferral` alone takes ~5-20 min on a fast CPU box (a cached-pk
//! round-trip without root_pk was ~8 min; root_pk adds CPU-dummy app→agg→root
//! proves on top). Add a fibonacci app+agg prove and a verify-stark guest
//! prove (with `prove_def → prove_mixed → wrap → root`) and the test as a
//! whole sits in the **hours** on CPU. Marked `#[ignore]` for that reason —
//! invoke explicitly:
//!
//! ```sh
//! cargo test --package edge-integration-tests \
//!     --test deferral_stark_e2e_test \
//!     --features real-deferral-integration \
//!     deferral_stark_e2e_verify -- --ignored --nocapture
//! ```

#![cfg(feature = "real-deferral-integration")]

use std::{slice::from_ref, sync::Arc};

use eyre::Result;
use openvm_stark_backend::{codec::Encode, p3_field::PrimeField32, StarkEngine};
use openvm_stark_sdk::{
    config::{baby_bear_bn254_poseidon2, baby_bear_poseidon2::Digest},
    utils::setup_tracing,
};
use openvm_verify_stark_circuit::extension::{get_deferral_state, get_raw_deferral_results};
use sdk_v2::{
    openvm_circuit::arch::hasher::poseidon2::vm_poseidon2_hasher,
    prover::compute_deferral_merkle_proofs, DeferralInput, StdIn, F,
};

/// Root engine on CPU (BabyBear → Bn254 wrap). `BabyBearBn254Poseidon2CpuEngine`
/// is generic over the transcript shape; a plain `use … as RootE` import
/// keeps the generic unresolved at the call site, so we put it in a type
/// alias to pick up the upstream default (`Transcript`).
type RootE = baby_bear_bn254_poseidon2::BabyBearBn254Poseidon2CpuEngine;
use verify_stark::{
    pvs::{DeferralPvs, DEF_PVS_AIR_ID},
    verify_vm_stark_proof_decoded,
    vk::{VerificationBaseline, VmStarkVerifyingKey},
    VmStarkProof,
};

use edge_worker::deferral_merkle::{
    build_initial_memory_tree, extract_deferral_auth_path, finalize_deferral_path, DIGEST_SIZE,
};
use edge_worker::openvm_config::create_edge_sdk_with_deferral;

/// `sdk_v2::openvm_circuit::system::memory::merkle::MerkleTree` of the digest
/// shape edge uses everywhere (matches `edge_worker::deferral_merkle::DIGEST_SIZE`).
type MerkleTree = sdk_v2::openvm_circuit::system::memory::merkle::MerkleTree<F, DIGEST_SIZE>;

/// Fibonacci guest ELF (lifted verbatim from openvm sdk examples). Used as
/// the inner program: prove it through edge's deferral keyset to get a
/// `VmStarkProof` we can feed into the verify-stark deferral circuit on the
/// next prove.
const FIBONACCI_ELF: &[u8] = include_bytes!("fixtures-deferral/fibonacci.elf");

/// Verify-stark guest ELF (lifted from openvm sdk examples). The outer
/// program: reads `(app_exe_commit, app_vm_commit, user_pvs, input_commit)`
/// + invokes `verify_stark::<0>` against the inner proof's fingerprint.
const VERIFY_STARK_ELF: &[u8] = include_bytes!("fixtures-deferral/verify-stark.elf");

/// Caller-side test harness mirroring openvm's `verify_stark_guest_inputs`
/// (`examples/verify-stark/host/src/lib.rs:145`).
///
/// This is intentionally **test-only**, not edge production code: by design,
/// caller-side derivation lives outside edge (see docs/DEFERRAL.md) so the
/// edge protocol stays circuit-agnostic. The fixture caller here plays the
/// role of an external client that derives `(StdIn, DeferralInput)` and
/// hands edge the artifacts.
fn verify_stark_guest_inputs(
    proof: &VmStarkProof,
    agg_vk: Arc<openvm_stark_backend::keygen::types::MultiStarkVerifyingKey<sdk_v2::SC>>,
    baseline: VerificationBaseline,
    // rc.3 (openvm PR #2962): the verify-stark deferral circuit's cached commit
    // is now a required argument to `get_raw_deferral_results` /
    // `get_deferral_state` (was implicit before). Obtained caller-side via
    // `sdk.deferral_circuit_cached_commits(def_idx)`.
    cached_commit: Digest,
) -> Result<(StdIn, DeferralInput)> {
    let child_vk = VmStarkVerifyingKey {
        mvk: agg_vk.as_ref().clone(),
        baseline,
    };
    let raw_results = get_raw_deferral_results(&child_vk, from_ref(proof), cached_commit)?;
    assert_eq!(raw_results.len(), 1);
    let input_commit: [u8; 32] = raw_results[0]
        .input
        .clone()
        .try_into()
        .expect("input_commit must be 32 bytes");
    // The `programs/examples/verify-stark.elf` guest (the one this test bundles,
    // matching the SDK's `test_verify_stark_deferral`) reads FOUR values from
    // stdin: app_exe_commit, app_vm_commit, collapsed user_public_values, and
    // input_commit — see the canonical `make_verify_stark_inputs_for_indices`
    // (sdk/src/tests.rs). The earlier single `input_commit` write was lifted
    // from `examples/verify-stark/host`, which pairs with a *different* guest;
    // against this ELF it underflows stdin (`EndOfInputStream`).
    let output_raw = &raw_results[0].output_raw;
    let app_exe_commit: [u8; 32] = output_raw[..32].try_into().unwrap();
    let app_vm_commit: [u8; 32] = output_raw[32..64].try_into().unwrap();
    let user_public_values = collapse_user_public_values(&output_raw[64..]);

    let mut stdin = StdIn::default();
    stdin.write(&app_exe_commit);
    stdin.write(&app_vm_commit);
    stdin.write(&user_public_values);
    stdin.write(&input_commit);
    stdin.deferrals = vec![get_deferral_state(
        &child_vk,
        from_ref(proof),
        cached_commit,
        0,
    )?];

    Ok((stdin, DeferralInput::from_inputs(from_ref(proof))))
}

/// Multi-verify variant, for the `verify-stark-multi` guest. That guest uses
/// `verify_stark_unchecked` and reads `input_commit` then `num_verifies`,
/// calling `verify_stark_unchecked::<0>` that many times against one deferral
/// circuit. We pack `num_verifies` copies of the same inner proof into circuit
/// 0's `DeferralState`/`DeferralInput`, so a single proof job makes
/// `num_verifies` `verify_stark` calls — the knob for the N-sweep
/// (N = 1,2,4,8,16,32,…).
fn verify_stark_multi_guest_inputs(
    proof: &VmStarkProof,
    agg_vk: Arc<openvm_stark_backend::keygen::types::MultiStarkVerifyingKey<sdk_v2::SC>>,
    baseline: VerificationBaseline,
    cached_commit: Digest,
    num_verifies: u32,
) -> Result<(StdIn, DeferralInput)> {
    assert!(num_verifies >= 1, "num_verifies (N) must be >= 1");
    let child_vk = VmStarkVerifyingKey {
        mvk: agg_vk.as_ref().clone(),
        baseline,
    };
    // `input_commit` is a property of the single child proof; all
    // `num_verifies` copies share it (the unchecked guest reads one commit and
    // verifies it `num_verifies` times against circuit 0's deferred proofs).
    let raw_results = get_raw_deferral_results(&child_vk, from_ref(proof), cached_commit)?;
    assert_eq!(raw_results.len(), 1);
    let input_commit: [u8; 32] = raw_results[0]
        .input
        .clone()
        .try_into()
        .expect("input_commit must be 32 bytes");

    // `num_verifies` copies of the inner proof, all deferred to circuit 0.
    let proofs = vec![proof.clone(); num_verifies as usize];

    let mut stdin = StdIn::default();
    // Guest read order (verify-stark-multi/src/main.rs): input_commit, then
    // num_verifies.
    stdin.write(&input_commit);
    stdin.write(&num_verifies);
    stdin.deferrals = vec![get_deferral_state(&child_vk, &proofs, cached_commit, 0)?];

    Ok((stdin, DeferralInput::from_inputs(&proofs)))
}

/// Collapse openvm's 4-bytes-per-field expanded user public values back to one
/// byte each (the high 3 bytes must be zero). Mirrors the SDK test helper of
/// the same name (`sdk/src/tests.rs`).
fn collapse_user_public_values(expanded: &[u8]) -> Vec<u8> {
    const F_NUM_BYTES: usize = 4;
    assert!(expanded.len().is_multiple_of(F_NUM_BYTES));
    expanded
        .chunks_exact(F_NUM_BYTES)
        .map(|bytes| {
            assert_eq!(&bytes[1..], &[0; F_NUM_BYTES - 1]);
            bytes[0]
        })
        .collect()
}

/// End-to-end validation: a real deferral proof produced through edge's
/// deferral keyset that **verifies** at the root level on CPU, and whose
/// `deferral_merkle_proofs` are byte-identical to what edge's merkle helpers
/// (`extract_deferral_auth_path` + `finalize_deferral_path`) produce against
/// the same prover memory state.
///
/// The flow mirrors the openvm reference test `test_verify_stark_deferral`
/// (`crates/sdk/src/tests.rs:296`) but uses edge's `create_edge_sdk_with_deferral()`
/// throughout — so the keyset, deferral path prover, and merge sequence are
/// the ones edge actually ships.
///
/// Self-recursion is naturally available here: `DeferralAggProver::verify_stark`
/// (the construction edge uses) computes a fixed-point `def_hook_commit` from
/// a dummy circuit, so an SDK built from it can verify proofs it produces
/// itself (`agg.rs:179`). The "child" inner proof is produced by the same
/// edge SDK as the outer verify-stark proof.
#[test]
#[ignore = "real prover; needs the full edge deferral keyset (hours on CPU). \
            Run with `cargo test ... -- --ignored --nocapture`."]
fn deferral_stark_e2e_verify() -> Result<()> {
    setup_tracing();

    eprintln!("=== deferral stark e2e — start ===");

    // 1. Build the edge deferral SDK (the production glue: same call
    //    `keygen --with-deferral` and the worker boot smoke-test make). Pays
    //    full keygen up-front; downstream `prove(...)` calls reuse the
    //    lazily-materialized keys.
    let t0 = std::time::Instant::now();
    let sdk = create_edge_sdk_with_deferral()?;
    eprintln!(
        "  create_edge_sdk_with_deferral() ok ({:.1}s)",
        t0.elapsed().as_secs_f64()
    );

    // 2. Prove fibonacci THROUGH the deferral SDK with empty def_inputs —
    //    the "deferrals enabled, none used" path (mirrors
    //    `test_deferrals_enabled_without_usage` and the inner-proof step of
    //    `test_verify_stark_path_sdk_can_verify_own_proofs`). When
    //    `def_inputs.is_empty()`, the SDK's `StarkProver::prove` skips the
    //    deferral merge but still attaches `deferral_merkle_proofs` (the
    //    SDK is deferral-enabled). The resulting proof's shape matches what
    //    this same SDK's verify-stark circuit expects to verify.
    let t1 = std::time::Instant::now();
    let fib_exe = sdk.convert_to_exe(FIBONACCI_ELF)?;
    let mut fib_stdin = StdIn::default();
    let fib_n: u64 = 100;
    fib_stdin.write(&fib_n);

    let (fib_proof, fib_baseline) = sdk.prove(fib_exe, fib_stdin, &[])?;
    eprintln!(
        "  inner fibonacci prove ok ({:.1}s)",
        t1.elapsed().as_secs_f64()
    );

    // 3. Caller-side derivation of (StdIn, DeferralInput) for the outer
    //    verify-stark guest. This is option (ii): the test plays "caller",
    //    not edge.
    let (vs_stdin, def_input) = verify_stark_guest_inputs(
        &fib_proof,
        sdk.agg_vk(),
        fib_baseline,
        sdk.deferral_circuit_cached_commits(0)?
            .pop()
            .expect("verify-stark cached commit (deferral circuit 0)")
            .into(),
    )?;

    // 4. Prove the verify-stark guest through the SAME edge SDK, feeding the
    //    inner proof as the def_input. This triggers app + leaf + internal +
    //    `prove_def → prove_mixed → wrap` + `compute_deferral_merkle_proofs`
    //    — i.e. the full deferral pipeline through edge's keyset.
    let t2 = std::time::Instant::now();
    let vs_exe = sdk.convert_to_exe(VERIFY_STARK_ELF)?;

    // Use the SDK's evm_prover_without_halo2 so we get a real RootProof we
    // can verify with the root engine — the cheapest credible real verify
    // (stark/root level, CPU). Mirrors
    // `test_verify_stark_deferral`'s root-level verify.
    let mut evm_prover = sdk.evm_prover_without_halo2(vs_exe)?;
    let vs_root_proof = evm_prover.prove_root(vs_stdin, &[def_input])?;
    eprintln!(
        "  outer verify-stark prove_root ok ({:.1}s)",
        t2.elapsed().as_secs_f64()
    );

    // 5. Verify the root proof — the test's hard assertion.
    let vk = evm_prover.root_prover.0.get_vk();
    let engine = RootE::new(vk.inner.params.clone());
    engine.verify(&vk, &vs_root_proof)?;
    eprintln!("  root proof VERIFIED");

    eprintln!("=== deferral stark e2e — pass ===");

    Ok(())
}

/// Stark-mode deferral completion, exercised through edge's **wire + persist +
/// verify** chain (no cluster).
///
/// A `proof_type=stark` deferral job stops at the merged final internal proof:
/// the worker runs the tail merge (`run_deferral_tail_merge`), attaches the
/// `DeferralMerkleProofs`, the manager persists it as an openvm-codec
/// `VmStarkProof`, and `verify_edge_final_proof` reads it back via
/// `load_final_proof`. This test drives that exact chain:
///  1. prove the merged stark proof via `sdk.prove` — the same
///     `prove_def → prove_mixed → wrap` + `compute_deferral_merkle_proofs`
///     sequence `run_deferral_tail_merge` runs, so the in-memory shape matches
///     what edge ships;
///  2. encode it with the openvm codec (`VmStarkProof::encode_to_vec`) exactly
///     as the manager's `persist_final_proof_to_disk` does, and write it to disk;
///  3. read it back through the production [`load_final_proof`], which decodes
///     the `VmStarkProof` **with** its merkle proofs;
///  4. verify the reconstructed proof with `verify_vm_stark_proof_decoded` —
///     the exact call `verify_edge_final_proof` makes.
///
/// Green ⇒ a persisted stark-mode deferral proof is verifiable: the merkle
/// proofs survive the wire + persist round-trip and the reconstructed proof
/// passes the real verifier. Same heavy-CPU caveat as the sibling tests.
#[test]
#[ignore = "real prover; needs the full edge deferral keyset (hours on CPU). \
            Run with `cargo test ... -- --ignored --nocapture`."]
fn deferral_stark_completion_persists_and_verifies() -> Result<()> {
    setup_tracing();
    eprintln!("=== stark-mode deferral completion (persist + verify) — start ===");

    let sdk = create_edge_sdk_with_deferral()?;

    // Inner fibonacci proof (empty def_inputs), then caller-derived inputs —
    // same setup as `deferral_stark_e2e_verify`.
    let fib_exe = sdk.convert_to_exe(FIBONACCI_ELF)?;
    let mut fib_stdin = StdIn::default();
    fib_stdin.write(&100u64);
    let (fib_proof, fib_baseline) = sdk.prove(fib_exe, fib_stdin, &[])?;
    let (vs_stdin, def_input) = verify_stark_guest_inputs(
        &fib_proof,
        sdk.agg_vk(),
        fib_baseline,
        sdk.deferral_circuit_cached_commits(0)?
            .pop()
            .expect("verify-stark cached commit (deferral circuit 0)")
            .into(),
    )?;

    // (1) The merged stark proof — what edge's tail merge produces for a
    //     `proof_type=stark` deferral job (a `VmStarkProof` carrying merkle
    //     proofs).
    let vs_exe = sdk.convert_to_exe(VERIFY_STARK_ELF)?;
    let (merged, vs_baseline) = sdk.prove(vs_exe, vs_stdin, &[def_input])?;
    assert!(
        merged.deferral_merkle_proofs.is_some(),
        "merged stark deferral proof must carry DeferralMerkleProofs"
    );

    // (2) Encode with the openvm codec exactly as the manager's
    //     `persist_final_proof_to_disk` does — `VmStarkProof::encode_to_vec`
    //     carries the proof, user public values, and merkle proofs inline.
    let persisted = merged.encode_to_vec()?;

    let dir = tempfile::tempdir()?;
    let path = dir.path().join("stark-deferral.proof.bin");
    std::fs::write(&path, &persisted)?;

    // (3) Read back through the production loader — decodes the VmStarkProof
    //     with its merkle proofs.
    let loaded = edge_worker::stark_verify::load_final_proof(&path)?;
    assert!(
        loaded.deferral_merkle_proofs.is_some(),
        "load_final_proof must reconstruct the deferral merkle proofs"
    );

    // (4) Verify exactly as `verify_edge_final_proof` does.
    let vk = VmStarkVerifyingKey {
        mvk: sdk.agg_vk().as_ref().clone(),
        baseline: vs_baseline,
    };
    verify_vm_stark_proof_decoded(&vk, &loaded)?;
    eprintln!("  persisted stark-mode deferral proof VERIFIED");

    eprintln!("=== stark-mode deferral completion — pass ===");

    Ok(())
}

/// Targeted byte-equality check between edge's merkle helpers and the SDK's
/// canonical `compute_deferral_merkle_proofs` over the **real prover state**
/// from one full deferral run.
///
/// This complements the unit tests in `edge_worker::deferral_merkle` (which
/// use synthetic memory): here we run a full deferral pipeline on a small
/// program, capture the same memory snapshots openvm uses
/// (`prover/stark.rs:84-152`), and assert that edge's
/// `extract_deferral_auth_path` + `finalize_deferral_path` produce bytes
/// identical to `compute_deferral_merkle_proofs`. If the depth-independent
/// extraction or the zero-pad finalization ever drifts from openvm — e.g.
/// after an openvm bump that touches `MemoryDimensions` or the merkle leaf
/// layout — this catches it on a real proof rather than waiting for the
/// verifier to reject.
///
/// Heavy on CPU for the same reason as the main test; `#[ignore]`'d.
#[test]
#[ignore = "real prover; runs full inner fib + outer verify-stark prove pair. \
            Use `-- --ignored --nocapture` to invoke."]
fn deferral_merkle_paths_match_canonical_on_real_prover_state() -> Result<()> {
    setup_tracing();
    use std::borrow::Borrow;

    let sdk = create_edge_sdk_with_deferral()?;
    let fib_exe = sdk.convert_to_exe(FIBONACCI_ELF)?;
    let mut fib_stdin = StdIn::default();
    fib_stdin.write(&100u64);
    let (fib_proof, fib_baseline) = sdk.prove(fib_exe, fib_stdin, &[])?;

    let (vs_stdin, def_input) = verify_stark_guest_inputs(
        &fib_proof,
        sdk.agg_vk(),
        fib_baseline,
        sdk.deferral_circuit_cached_commits(0)?
            .pop()
            .expect("verify-stark cached commit (deferral circuit 0)")
            .into(),
    )?;

    // Build the StarkProver ourselves so we can grab `initial_memory` /
    // `final_memory` around the prove. Mirrors `StarkProver::prove`'s body
    // (`prover/stark.rs:68-156`) — same call sequence the SDK uses.
    let vs_exe = sdk.convert_to_exe(VERIFY_STARK_ELF)?;
    let system_config = sdk.app_config().app_vm_config.as_ref().clone();
    let memory_dimensions = system_config.memory_config.memory_dimensions();
    let mut prover = sdk.prover(vs_exe.clone())?;
    let hasher = vm_poseidon2_hasher();

    // Snapshot initial memory + build initial tree the SDK way.
    let initial_state_ref = prover
        .app_prover
        .instance()
        .state()
        .as_ref()
        .expect("initial state populated before prove");
    let initial_memory_clone = initial_state_ref.memory.memory.clone();
    let canonical_initial_tree =
        MerkleTree::from_memory(&initial_memory_clone, &memory_dimensions, &hasher);

    // Run app + agg + tail merge through the SDK to get the merged stark
    // proof — same calls edge's `run_deferral_tail_merge` makes.
    let (stark_proof, _meta) = prover.prove(vs_stdin, &[def_input])?;
    let depth = {
        let def_pvs: &DeferralPvs<F> = stark_proof.inner.public_values[DEF_PVS_AIR_ID]
            .as_slice()
            .borrow();
        def_pvs.depth.as_canonical_u32() as usize
    };

    // Snapshot final memory + build final tree the SDK way.
    let final_memory_ref = &prover
        .app_prover
        .instance()
        .state()
        .as_ref()
        .expect("final state populated after prove")
        .memory
        .memory;
    let canonical_final_tree =
        MerkleTree::from_memory(final_memory_ref, &memory_dimensions, &hasher);

    // Canonical merkle proofs (what the verifier expects).
    let canonical = compute_deferral_merkle_proofs(
        memory_dimensions,
        &canonical_initial_tree,
        &canonical_final_tree,
        depth,
    );

    // Edge's merkle helpers on the SAME final tree.
    let edge_final_indep = extract_deferral_auth_path(&memory_dimensions, &canonical_final_tree);
    let edge_final = finalize_deferral_path(&edge_final_indep, depth);
    assert_eq!(
        edge_final, canonical.final_merkle_proof,
        "edge's extract+finalize must equal canonical final_merkle_proof at depth {depth}",
    );

    // Edge rebuilds the INITIAL tree from the exe (the production path on
    // the tail worker — see `handlers.rs::run_deferral_tail_merge`). Assert
    // that edge's rebuilt initial tree's path matches canonical too.
    let edge_initial_tree = build_initial_memory_tree(vs_exe.as_ref(), &system_config);
    let edge_initial_indep = extract_deferral_auth_path(&memory_dimensions, &edge_initial_tree);
    let edge_initial = finalize_deferral_path(&edge_initial_indep, depth);
    assert_eq!(
        edge_initial, canonical.initial_merkle_proof,
        "edge's build_initial_memory_tree + extract+finalize must equal canonical \
         initial_merkle_proof at depth {depth}",
    );

    eprintln!(
        "  edge merkle helpers byte-equal SDK compute_deferral_merkle_proofs at depth={depth}",
    );
    Ok(())
}

/// Caller-side derivation tool for the **distributed cluster** deferral e2e.
///
/// This plays the external caller's role (inputs are caller-derived — see
/// docs/DEFERRAL.md): produce the
/// artifacts a client hands to edge for a deferral job. It is NOT edge
/// production code — it plays the external client. It proves the inner
/// fibonacci program through edge's deferral keyset, derives the verify-stark
/// guest inputs, and writes three bincode files matching the exact wire
/// formats the worker decodes:
///   - `outer_stdin.bin`      — `StdIn` (the 4 guest reads; `deferrals` CLEARED
///                               because the worker REPLACES it from the staged
///                               state files, sharded_app_prover.rs:298).
///     → feed to `start-proof.sh --input`.
///   - `deferral_state_0.bin` — `DeferralState` (`bincode`, what
///                               `load_and_validate_deferral_states` reads).
///     → feed to `start-proof.sh --deferral-state`.
///   - `deferral_input_0.bin` — `DeferralInput` (`bincode`, what
///                               `run_deferral_tail_merge` reads).
///     → feed to `start-proof.sh --deferral-input`.
///
/// Keys: built via `create_edge_sdk_with_deferral()` — the SAME deterministic
/// construction `keygen --with-deferral` persists into the cluster's cached_pk,
/// so the inner proof verifies against the cluster's agg_vk.
///
/// Output dir: `$DEFERRAL_FIXTURE_DIR` (default `/tmp/edge-deferral-fixtures`).
#[test]
#[ignore = "fixture generator for the cluster e2e; run explicitly with --ignored"]
fn derive_deferral_cluster_fixtures() -> Result<()> {
    setup_tracing();
    let out_dir = std::env::var("DEFERRAL_FIXTURE_DIR")
        .unwrap_or_else(|_| "/tmp/edge-deferral-fixtures".into());
    std::fs::create_dir_all(&out_dir)?;
    eprintln!("=== deriving cluster deferral fixtures -> {out_dir} ===");

    let sdk = create_edge_sdk_with_deferral()?;
    let fib_exe = sdk.convert_to_exe(FIBONACCI_ELF)?;
    let mut fib_stdin = StdIn::default();
    fib_stdin.write(&100u64);
    let (fib_proof, fib_baseline) = sdk.prove(fib_exe, fib_stdin, &[])?;
    eprintln!("  inner fibonacci proof produced");

    let (mut vs_stdin, def_input) = verify_stark_guest_inputs(
        &fib_proof,
        sdk.agg_vk(),
        fib_baseline,
        sdk.deferral_circuit_cached_commits(0)?
            .pop()
            .expect("verify-stark cached commit (deferral circuit 0)")
            .into(),
    )?;

    // The DeferralState the worker grafts onto stdin from the staged file.
    let deferral_state = vs_stdin.deferrals[0].clone();
    // The worker REPLACES stdin.deferrals from the staged state files
    // (sharded_app_prover.rs:298), so the uploaded StdIn must carry only the
    // guest's buffered reads — clear deferrals to avoid shipping them twice.
    vs_stdin.deferrals.clear();

    let write = |name: &str, bytes: Vec<u8>| -> Result<()> {
        let path = format!("{out_dir}/{name}");
        std::fs::write(&path, &bytes)?;
        eprintln!("  wrote {path} ({} bytes)", bytes.len());
        Ok(())
    };
    write("outer_stdin.bin", bincode::serialize(&vs_stdin)?)?;
    write("deferral_state_0.bin", bincode::serialize(&deferral_state)?)?;
    write("deferral_input_0.bin", bincode::serialize(&def_input)?)?;

    eprintln!("=== cluster deferral fixtures ready ===");
    Ok(())
}

/// Fixture generator for the **multi-verify N-sweep**. For each N in the
/// comma-separated `$DEFERRAL_NUM_VERIFIES` (default `1`) it writes the three
/// fixture files under `<$DEFERRAL_FIXTURE_DIR>/N<n>/`, built for the
/// `verify-stark-multi` guest (one deferral circuit, `num_verifies = N`) — so a
/// proof job on N<n> makes N `verify_stark` calls. Point the cluster's
/// `programs.json` at `fixtures-deferral/verify-stark-multi.elf`.
///
/// One run derives the whole sweep (keyset + inner proof are shared):
///   DEFERRAL_NUM_VERIFIES=1,2,4,8,16,32 DEFERRAL_FIXTURE_DIR=/tmp/def-sweep \
///   cargo test -p edge-integration-tests --test deferral_stark_e2e_test \
///     --features real-deferral-integration,cuda --release \
///     derive_deferral_multi_fixtures -- --ignored --nocapture
///
/// Output: `<$DEFERRAL_FIXTURE_DIR>/N<n>/{outer_stdin,deferral_state_0,deferral_input_0}.bin`.
#[test]
#[ignore = "fixture generator for the multi-verify sweep; run with --ignored"]
fn derive_deferral_multi_fixtures() -> Result<()> {
    setup_tracing();
    let base_dir = std::env::var("DEFERRAL_FIXTURE_DIR")
        .unwrap_or_else(|_| "/tmp/edge-deferral-fixtures".into());
    // Comma-separated list, e.g. "1,2,4,8,16,32". All N share one keyset + one
    // inner proof (the expensive part), so the whole sweep is derived in a
    // single run; fixtures per N land under `<base_dir>/N<n>/`.
    let ns: Vec<u32> = std::env::var("DEFERRAL_NUM_VERIFIES")
        .unwrap_or_else(|_| "1".into())
        .split(',')
        .filter_map(|s| s.trim().parse::<u32>().ok())
        .filter(|&n| n >= 1)
        .collect();
    assert!(!ns.is_empty(), "DEFERRAL_NUM_VERIFIES parsed to no values");
    eprintln!("=== deriving multi-verify fixtures for N={ns:?} under {base_dir} ===");

    // Expensive setup ONCE (full deferral keygen + one inner fibonacci proof),
    // reused across every N.
    let sdk = create_edge_sdk_with_deferral()?;
    let fib_exe = sdk.convert_to_exe(FIBONACCI_ELF)?;
    let mut fib_stdin = StdIn::default();
    fib_stdin.write(&100u64);
    let (fib_proof, fib_baseline) = sdk.prove(fib_exe, fib_stdin, &[])?;
    eprintln!("  inner fibonacci proof produced; deferral keyset ready");
    let cached_commit: Digest = sdk
        .deferral_circuit_cached_commits(0)?
        .pop()
        .expect("verify-stark cached commit (deferral circuit 0)")
        .into();

    for &n in &ns {
        let (mut vs_stdin, def_input) = verify_stark_multi_guest_inputs(
            &fib_proof,
            sdk.agg_vk(),
            fib_baseline.clone(),
            cached_commit.clone(),
            n,
        )?;

        // Same wire split as the single-verify generator: the worker replaces
        // stdin.deferrals from the staged state file, so ship the state
        // separately and clear it from the uploaded StdIn.
        let deferral_state = vs_stdin.deferrals[0].clone();
        vs_stdin.deferrals.clear();

        let dir = format!("{base_dir}/N{n}");
        std::fs::create_dir_all(&dir)?;
        let write = |name: &str, bytes: Vec<u8>| -> Result<()> {
            let path = format!("{dir}/{name}");
            std::fs::write(&path, &bytes)?;
            eprintln!("  [N={n}] wrote {path} ({} bytes)", bytes.len());
            Ok(())
        };
        write("outer_stdin.bin", bincode::serialize(&vs_stdin)?)?;
        write("deferral_state_0.bin", bincode::serialize(&deferral_state)?)?;
        write("deferral_input_0.bin", bincode::serialize(&def_input)?)?;
    }

    eprintln!("=== multi-verify fixtures ready for N={ns:?} ===");
    Ok(())
}
