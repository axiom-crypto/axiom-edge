//! Step enum for proof stages.

use serde::{Deserialize, Serialize};

/// Proof step types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    /// Sharded app prove: each worker runs the executor and proves the segments
    /// where `segment_idx % num_workers == prover_id`. Combines execution + app
    /// proving for the worker's shard, in parallel with other workers.
    ShardedAppProve,
    /// Leaf proof aggregating app proofs.
    LeafProve,
    /// Internal proof in the recursion tree.
    InternalProve,
    /// Root verifier circuit proof.
    RootProve,
    /// Halo2 proof wrapping the root proof for EVM verification.
    Halo2Prove,
    /// The EVM step (root → halo2) run as one dispatched step on the
    /// `EvmDedicated` worker in dedicated-halo2 mode. Unlike [`Step::RootProve`]
    /// / [`Step::Halo2Prove`] (which are never dispatched — a `Full` worker runs
    /// them in-process), this is a first-class scheduler step: the manager
    /// hands the finished (post-tail-merge) internal proof to the dedicated
    /// worker, which runs root → halo2 and posts the `Evm` result.
    EvmProve,
}

impl Step {
    pub fn as_str(&self) -> &'static str {
        match self {
            Step::ShardedAppProve => "sharded_app_prove",
            Step::LeafProve => "leaf_prove",
            Step::InternalProve => "internal_prove",
            Step::RootProve => "root_prove",
            Step::Halo2Prove => "halo2_prove",
            Step::EvmProve => "evm_prove",
        }
    }
}

impl std::fmt::Display for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
