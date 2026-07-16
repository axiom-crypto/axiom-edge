//! Pure tree math for the recursion plan.
//!
//! Given the leaf arity (app proofs per leaf), the internal arity (children
//! per internal proof), and a leaf count, these functions describe the
//! shape of the recursion tree: how many internal layers it has, how many
//! proofs sit at each layer, and how proofs map to segment ranges. None of
//! them touch [`super::ProofState`] — they're plain arithmetic, callable
//! from anywhere and trivially unit-testable in isolation.

/// Number of internal layers needed to fold `num_leaf_proofs` into a single
/// final proof, given the internal-circuit fan-in.
pub fn num_internal_layers_for_leaf_count(num_leaf_proofs: usize, internal_arity: usize) -> usize {
    if num_leaf_proofs <= 1 {
        return 1;
    }
    let mut nodes = num_leaf_proofs;
    let mut layers = 0;
    while nodes > 1 {
        nodes = nodes.div_ceil(internal_arity);
        layers += 1;
    }
    layers
}

/// Number of internal proofs at `layer_idx` given `num_leaf_proofs` leaves
/// and the internal-circuit fan-in.
pub fn num_proofs_at_internal_layer_for_leaf_count(
    num_leaf_proofs: usize,
    layer_idx: usize,
    internal_arity: usize,
) -> usize {
    let mut ret = num_leaf_proofs;
    for _ in 0..=layer_idx {
        if ret == 1 {
            return 0;
        }
        ret = ret.div_ceil(internal_arity);
    }
    ret
}

/// Segment-start index for the internal proof at (`layer_idx`, `idx`),
/// using `leaf_arity` as the app-to-leaf fan-in and `internal_arity` as the
/// child-to-internal fan-in.
pub fn segment_start_of_internal_proof_for_leaf_count(
    leaf_arity: usize,
    internal_arity: usize,
    layer_idx: usize,
    idx: usize,
) -> usize {
    let mut base = internal_arity;
    for _ in 0..layer_idx {
        base *= internal_arity;
    }
    idx * base * leaf_arity
}

/// Convert a `segment_start` back to its internal-proof index at `layer_idx`.
pub fn segment_start_to_internal_idx_with_batch(
    segment_start: usize,
    layer_idx: usize,
    leaf_arity: usize,
    internal_arity: usize,
) -> usize {
    let mut base = internal_arity * leaf_arity;
    for _ in 0..layer_idx {
        base *= internal_arity;
    }
    segment_start / base
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_internal_layers_calculation() {
        // 1 leaf proof -> 1 layer
        assert_eq!(num_internal_layers_for_leaf_count(1, 3), 1);
        // 2 leaf proofs -> 1 layer
        assert_eq!(num_internal_layers_for_leaf_count(2, 3), 1);
        // 3 leaf proofs -> 1 layer
        assert_eq!(num_internal_layers_for_leaf_count(3, 3), 1);
        // 4 leaf proofs -> 2 layers (3+1 -> 2 -> 1)
        assert_eq!(num_internal_layers_for_leaf_count(4, 3), 2);
        // 9 leaf proofs -> 2 layers (3+3+3 -> 3 -> 1)
        assert_eq!(num_internal_layers_for_leaf_count(9, 3), 2);
        // 10 leaf proofs -> 3 layers (3+3+3+1 -> 3+1 -> 2 -> 1)
        assert_eq!(num_internal_layers_for_leaf_count(10, 3), 3);
    }

    // Bounded ranges chosen to stay far inside what real deployments use
    // (SDK MAX_NUM_CHILDREN_* caps arity in single digits; even reth blocks
    // produce well under 1e4 leaf proofs).
    const ARITY_RANGE: std::ops::RangeInclusive<usize> = 2..=8;
    const LEAF_COUNT_RANGE: std::ops::RangeInclusive<usize> = 1..=10_000;

    proptest! {
        /// Tree always terminates: one leaf needs no internal proof, while a
        /// larger tree has exactly one proof in its final internal layer.
        #[test]
        fn prop_tree_terminates_at_single_root(
            num_leaves in LEAF_COUNT_RANGE,
            internal_arity in ARITY_RANGE,
        ) {
            let layers = num_internal_layers_for_leaf_count(num_leaves, internal_arity);
            prop_assert!(layers >= 1, "tree must have ≥1 layer (got {layers})");

            let root_count = num_proofs_at_internal_layer_for_leaf_count(
                num_leaves, layers - 1, internal_arity,
            );
            let expected_root_count = usize::from(num_leaves > 1);
            prop_assert_eq!(root_count, expected_root_count);
        }

        /// Layer count is monotone non-decreasing in leaf count. More leaves
        /// can never require fewer recursion layers.
        #[test]
        fn prop_layers_monotone_in_leaf_count(
            a in LEAF_COUNT_RANGE,
            b in LEAF_COUNT_RANGE,
            internal_arity in ARITY_RANGE,
        ) {
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            let lo_layers = num_internal_layers_for_leaf_count(lo, internal_arity);
            let hi_layers = num_internal_layers_for_leaf_count(hi, internal_arity);
            prop_assert!(hi_layers >= lo_layers);
        }

        /// Each valid layer matches the closed-form geometric fold. A single
        /// leaf needs no internal proof; larger trees use ceiling division.
        #[test]
        fn prop_layer_counts_match_geometric_fold(
            num_leaves in LEAF_COUNT_RANGE,
            internal_arity in ARITY_RANGE,
            layer_idx in 0usize..20,
        ) {
            let total_layers = num_internal_layers_for_leaf_count(num_leaves, internal_arity);
            prop_assume!(layer_idx < total_layers);

            let count = num_proofs_at_internal_layer_for_leaf_count(
                num_leaves, layer_idx, internal_arity,
            );
            let exponent = u32::try_from(layer_idx + 1).expect("layer index fits in u32");
            let divisor = internal_arity.pow(exponent);
            let expected_count = if num_leaves == 1 {
                0
            } else {
                num_leaves.div_ceil(divisor)
            };
            prop_assert_eq!(count, expected_count);
        }

        /// `segment_start_to_internal_idx_with_batch` is a left-inverse of
        /// `segment_start_of_internal_proof_for_leaf_count` for valid indices.
        /// This is the load-bearing invariant for tail-proof scheduling.
        #[test]
        fn prop_segment_start_idx_roundtrip(
            leaf_arity in ARITY_RANGE,
            internal_arity in ARITY_RANGE,
            layer_idx in 0usize..6,
            idx in 0usize..100,
        ) {
            let segment_start = segment_start_of_internal_proof_for_leaf_count(
                leaf_arity, internal_arity, layer_idx, idx,
            );
            let recovered = segment_start_to_internal_idx_with_batch(
                segment_start, layer_idx, leaf_arity, internal_arity,
            );
            prop_assert_eq!(recovered, idx);
        }
    }
}
