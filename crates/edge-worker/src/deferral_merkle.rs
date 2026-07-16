//! Deferral merkle proof helpers.
//!
//! Two paths from the `(DEFERRAL_AS, 0)` leaf of the VM memory tree — one
//! over the INITIAL memory image, one over the FINAL — finalized with
//! `depth` from `DeferralPvs` to make the `DeferralMerkleProofs` that the
//! verifier expects (`openvm/crates/verify/src/deferral.rs`). The openvm
//! SDK builds both around `app_prover.prove` in
//! `crates/sdk/src/prover/stark.rs:80-156`; edge splits the work across
//! stages:
//!
//! - **Terminal app worker** has `final_memory` in hand after the last
//!   segment proves (`sharded_app_prover.rs`); it builds the final memory
//!   tree and extracts the **depth-independent** `(DEFERRAL_AS, 0)` path
//!   here (`extract_deferral_auth_path`).
//! - **Tail worker** (`handlers.rs::run_deferral_tail_merge`) recomputes
//!   the initial path locally from the exe (`build_initial_memory_tree` +
//!   `extract_deferral_auth_path`), finalizes both with `depth` from the
//!   merged proof's `DeferralPvs` (`finalize_deferral_path`), and attaches
//!   them to the `VmStarkProof` before root.
//!
//! Why split? `depth` only exists after `prove_mixed` runs on the tail,
//! but the path's depth-dependent prefix is just a zero-pad — the
//! depth-independent siblings can ship early. Only the final-side path
//! travels (the initial side is deterministic from the exe, so the tail
//! reconstructs it locally; manager-buffered transport carries the final
//! side only).
//!
//! Mirrors the private `deferral_merkle_proof_from_tree` in openvm-sdk
//! (`crates/sdk/src/prover/deferral/merkle.rs:34-65`). Unit tests below
//! assert byte-equality against openvm's `compute_deferral_merkle_proofs`
//! over the same `(memory_dimensions, initial_tree, final_tree, depth)`.

use openvm_stark_backend::p3_field::PrimeCharacteristicRing;
use proof::F;
use sdk_v2::openvm_circuit::{
    arch::{
        hasher::poseidon2::{vm_poseidon2_hasher, Poseidon2Hasher},
        instructions::{exe::VmExe, DEFERRAL_AS},
        SystemConfig, VmState,
    },
    system::memory::{dimensions::MemoryDimensions, merkle::MerkleTree, AddressMap, CHUNK},
};

/// Length of one digest in field elements (BabyBear). Equals openvm's
/// `DIGEST_SIZE` / `CHUNK`. Re-exported so callers can spell
/// `[F; DIGEST_SIZE]` without re-imports.
pub const DIGEST_SIZE: usize = CHUNK;

/// Extract the depth-independent `(DEFERRAL_AS, 0)` authentication path
/// from a memory merkle tree.
///
/// Returns a vector of `overall_height()` digests, the sibling chain from
/// the leaf upward. This is the `depth == 0` form of
/// `deferral_merkle_proof_from_tree` (openvm
/// `crates/sdk/src/prover/deferral/merkle.rs:34-65`): every sibling at
/// index `i >= 1` is `get_node((leaf_idx >> i) ^ 1)` regardless of
/// `depth`, and the entry at index 0 is the leaf-level sibling
/// `get_node(leaf_idx)`. So finalization for any `depth` is just
/// "zero-pad the first `depth` entries" — see `finalize_deferral_path`.
pub fn extract_deferral_auth_path(
    memory_dimensions: &MemoryDimensions,
    merkle_tree: &MerkleTree<F, DIGEST_SIZE>,
) -> Vec<[F; DIGEST_SIZE]> {
    let overall_height = memory_dimensions.overall_height();
    let leaf_idx = (1u64 << overall_height) + memory_dimensions.label_to_index((DEFERRAL_AS, 0));
    debug_assert_eq!(leaf_idx % 2, 0);

    let mut node_idx = leaf_idx + 1;
    let mut proof = Vec::with_capacity(overall_height);
    while node_idx > 1 {
        let sibling_idx = node_idx ^ 1;
        proof.push(merkle_tree.get_node(sibling_idx));
        node_idx >>= 1;
    }
    debug_assert_eq!(proof.len(), overall_height);
    proof
}

/// Finalize a depth-independent authentication path for a given `depth`.
///
/// Zero-pads the first `depth` entries (the levels covered by the
/// deferral subtree). The remaining entries are siblings from the tree,
/// identical to those captured in the depth-independent path because at
/// index `i >= depth >= 1` both reduce to `get_node((leaf_idx >> i) ^ 1)`.
/// Mirrors the suffix produced by `deferral_merkle_proof_from_tree`
/// (openvm `merkle.rs:47-61`).
///
/// Panics if `depth > path.len()` — the verifier already enforces
/// `depth <= memory_dimensions.address_height`
/// (`verify/src/deferral.rs:68-73`), so the bound is structural.
pub fn finalize_deferral_path(path: &[[F; DIGEST_SIZE]], depth: usize) -> Vec<[F; DIGEST_SIZE]> {
    assert!(
        depth <= path.len(),
        "deferral depth {} exceeds path length {}",
        depth,
        path.len(),
    );
    let mut out = Vec::with_capacity(path.len());
    for _ in 0..depth {
        out.push([F::ZERO; DIGEST_SIZE]);
    }
    out.extend_from_slice(&path[depth..]);
    out
}

/// Build the initial memory merkle tree for `exe` — the tree rooted at
/// the program's static memory image before any execution.
///
/// `stdin` is fed via the hint stream and is NOT pre-loaded into
/// addressable memory (the initial memory tree is free and deterministic
/// from the exe), so the initial memory image (and its
/// merkle root) is fully determined by `exe.init_memory` and the system
/// config — no executor state needed.
///
/// Equivalent to openvm `stark.rs:82-96`'s pre-`prove` initial-tree path,
/// but reachable without `app_prover.instance().state()` (which the tail
/// worker no longer holds — the deferral-SDK reconstruction in
/// `run_deferral_tail_merge` builds and discards its own AppProver).
pub fn build_initial_memory_tree(
    exe: &VmExe<F>,
    system_config: &SystemConfig,
) -> MerkleTree<F, DIGEST_SIZE> {
    let memory_dimensions = system_config.memory_config.memory_dimensions();
    let initial_state = VmState::<F, _>::initial(
        system_config,
        &exe.init_memory,
        exe.pc_start,
        Vec::<Vec<F>>::new(),
    );
    let hasher: Poseidon2Hasher<F> = vm_poseidon2_hasher();
    build_memory_tree(&initial_state.memory.memory, &memory_dimensions, &hasher)
}

/// Thin wrapper over `MerkleTree::from_memory` — exists so callers don't
/// need to spell out the hasher type (it's used by both the terminal
/// worker's final-tree build and the tail's initial-tree build).
pub fn build_memory_tree(
    memory: &AddressMap,
    memory_dimensions: &MemoryDimensions,
    hasher: &Poseidon2Hasher<F>,
) -> MerkleTree<F, DIGEST_SIZE> {
    MerkleTree::from_memory(memory, memory_dimensions, hasher)
}

/// Build the COMPLETE `DeferralMerkleProofs` for a proof that made no
/// deferred calls (`depth == 0`), running on a deferral deployment.
///
/// A deferral-configured verifying key requires *every* proof — even one
/// with an empty deferral accumulator — to carry `DeferralMerkleProofs`
/// (`openvm/crates/verify/src/lib.rs:329` → `MissingDeferralMerkleProofs`).
/// For a real deferral proof edge splits this build across the terminal app
/// worker (final path) and the tail worker (initial path + `depth`
/// finalization). A no-deferral proof has no tail worker, so the terminal
/// app worker — the only stage holding BOTH the exe (initial memory image)
/// and the post-execution final memory — builds the whole thing here.
///
/// At `depth == 0`, `finalize_deferral_path` is the identity (nothing is
/// zero-padded), so this is just the initial + final `(DEFERRAL_AS, 0)` auth
/// paths. Correctness: the verifier requires `initial_merkle_proof[i] ==
/// final_merkle_proof[i]` for `i in 0..address_height` (`deferral.rs:75`); a
/// no-deferral program never writes `DEFERRAL_AS`, so that subtree is
/// identical in the initial and final images and the within-address
/// siblings match.
pub fn depth0_deferral_merkle_proofs(
    exe: &VmExe<F>,
    system_config: &SystemConfig,
    final_memory: &AddressMap,
    hasher: &Poseidon2Hasher<F>,
) -> verify_stark::deferral::DeferralMerkleProofs<F> {
    let memory_dimensions = system_config.memory_config.memory_dimensions();
    let initial_tree = build_initial_memory_tree(exe, system_config);
    let final_tree = build_memory_tree(final_memory, &memory_dimensions, hasher);
    let initial_path = extract_deferral_auth_path(&memory_dimensions, &initial_tree);
    let final_path = extract_deferral_auth_path(&memory_dimensions, &final_tree);
    verify_stark::deferral::DeferralMerkleProofs {
        initial_merkle_proof: finalize_deferral_path(&initial_path, 0),
        final_merkle_proof: finalize_deferral_path(&final_path, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sdk_v2::openvm_circuit::arch::MemoryConfig;
    use sdk_v2::openvm_circuit::system::memory::AddressMap;
    use sdk_v2::prover::compute_deferral_merkle_proofs;
    use std::collections::BTreeMap;

    /// Build a deterministic SparseMemoryImage that touches a handful of
    /// cells across the first few addressable spaces; `set_from_sparse`
    /// loads them into the `AddressMap`. The seed varies the cell values
    /// so initial vs final trees disagree in non-trivial places.
    fn make_memory(seed: u64) -> (MemoryConfig, AddressMap, Poseidon2Hasher<F>) {
        let memory_config = MemoryConfig::default();
        let mut memory = AddressMap::from_mem_config(&memory_config);

        // Touch a handful of cells in each non-empty addr space so the
        // tree has non-trivial nodes. Stay well within each space's
        // `num_cells` (some defaults are as small as 32) and use a
        // deterministic seed so initial/final trees reproduce.
        let mut sparse: BTreeMap<(u32, u32), u8> = BTreeMap::new();
        for (as_idx, cfg) in memory_config.addr_spaces.iter().enumerate() {
            if cfg.num_cells == 0 {
                continue;
            }
            let n = cfg.num_cells.min(8) as u32;
            for offset in 0..n {
                let v = ((seed
                    .wrapping_mul(0x9E3779B97F4A7C15)
                    .wrapping_add(as_idx as u64 * 131)
                    .wrapping_add(offset as u64))
                    & 0xff) as u8;
                sparse.insert((as_idx as u32, offset), v);
            }
        }
        memory.set_from_sparse(&sparse);

        let hasher = vm_poseidon2_hasher();
        (memory_config, memory, hasher)
    }

    /// The depth-independent path edge extracts equals what openvm's
    /// `compute_deferral_merkle_proofs` produces at `depth == 0` for the
    /// same final tree. This pins the leaf-side of the merkle math
    /// independently of any path-suffix games.
    #[test]
    fn extract_depth_independent_matches_compute_at_depth_zero() {
        let (memory_config, final_memory, hasher) = make_memory(0xa5a5_a5a5);
        let memory_dimensions = memory_config.memory_dimensions();
        let final_tree = MerkleTree::from_memory(&final_memory, &memory_dimensions, &hasher);

        // An (arbitrary, distinct) initial tree — used only to satisfy
        // `compute_deferral_merkle_proofs`'s signature; we only assert on
        // the final-side path here.
        let (_, initial_memory, _) = make_memory(0);
        let initial_tree = MerkleTree::from_memory(&initial_memory, &memory_dimensions, &hasher);

        let edge_path = extract_deferral_auth_path(&memory_dimensions, &final_tree);
        let canonical =
            compute_deferral_merkle_proofs(memory_dimensions, &initial_tree, &final_tree, 0);

        assert_eq!(
            edge_path, canonical.final_merkle_proof,
            "edge depth-independent extract must equal compute_deferral_merkle_proofs at depth=0",
        );
        assert_eq!(edge_path.len(), memory_dimensions.overall_height());
    }

    /// For every supported `depth`, `finalize_deferral_path` of the
    /// depth-independent path must equal what `compute_deferral_merkle_proofs`
    /// produces directly at that `depth` — for both the initial and the
    /// final sides. This checks the merkle math is exact, not just a
    /// type-check.
    #[test]
    fn finalize_matches_compute_at_every_supported_depth() {
        let (memory_config, final_memory, hasher) = make_memory(0xc0ffee);
        let memory_dimensions = memory_config.memory_dimensions();
        let (_, initial_memory, _) = make_memory(0xbeef);
        let final_tree = MerkleTree::from_memory(&final_memory, &memory_dimensions, &hasher);
        let initial_tree = MerkleTree::from_memory(&initial_memory, &memory_dimensions, &hasher);

        let edge_final_path = extract_deferral_auth_path(&memory_dimensions, &final_tree);
        let edge_initial_path = extract_deferral_auth_path(&memory_dimensions, &initial_tree);

        // depth is bounded by `address_height` (verifier enforces this).
        for depth in 0..=memory_dimensions.address_height {
            let canonical = compute_deferral_merkle_proofs(
                memory_dimensions,
                &initial_tree,
                &final_tree,
                depth,
            );
            let edge_final_finalized = finalize_deferral_path(&edge_final_path, depth);
            let edge_initial_finalized = finalize_deferral_path(&edge_initial_path, depth);

            assert_eq!(
                edge_final_finalized, canonical.final_merkle_proof,
                "final path mismatch at depth {depth}",
            );
            assert_eq!(
                edge_initial_finalized, canonical.initial_merkle_proof,
                "initial path mismatch at depth {depth}",
            );
        }
    }

    /// The siblings beyond the leaf level (indices >= 1) are the same
    /// regardless of `depth`, because for any depth `d <= i` they both
    /// reduce to `get_node((leaf_idx >> i) ^ 1)`. This is the structural
    /// fact that lets the terminal worker ship a single depth-independent
    /// path. Asserted directly here for clarity (the test above already
    /// covers it transitively).
    #[test]
    fn siblings_above_leaf_are_depth_invariant() {
        let (memory_config, memory, hasher) = make_memory(0x1234_5678);
        let memory_dimensions = memory_config.memory_dimensions();
        let tree = MerkleTree::from_memory(&memory, &memory_dimensions, &hasher);
        let path = extract_deferral_auth_path(&memory_dimensions, &tree);

        for depth in 1..=memory_dimensions.address_height {
            let canonical = compute_deferral_merkle_proofs(memory_dimensions, &tree, &tree, depth);
            // The canonical path has zeros at indices [0..depth) and the
            // tree siblings at [depth..overall_height). Each index
            // `i >= depth` must equal the depth-independent sibling.
            for (i, (canonical_sibling, indep_sibling)) in canonical
                .final_merkle_proof
                .iter()
                .zip(path.iter())
                .enumerate()
                .skip(depth)
            {
                assert_eq!(
                    canonical_sibling, indep_sibling,
                    "sibling at index {i} (depth {depth}) must equal depth-0 sibling",
                );
            }
        }
    }
}
