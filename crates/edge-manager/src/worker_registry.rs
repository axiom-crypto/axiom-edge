//! Edge Worker Registry.
//!
//! Manages worker registration and readiness checking. Worker capacity
//! parameters live in [`ManagerConfig::provers`]; workers report their own
//! configured values at registration time and the manager rejects drift.
//! Total worker count lives in [`ServerConfig::num_workers`]; workers do not
//! self-declare it.

use dashmap::DashMap;
use eyre::{bail, Result};
use protocol::WorkerRole;
use serde::Serialize;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::{debug, info};

use crate::config::ProversConfig;

/// A registered Edge worker.
#[derive(Clone, Debug, Serialize)]
pub struct RegisteredWorker {
    pub worker_url: String,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    /// Deployment role this worker reported at registration. Stored so the
    /// manager can resolve the dedicated worker and the normal-worker set for
    /// normal-set sharding and EVM-step dispatch.
    pub worker_role: WorkerRole,
}

/// Registry for Edge workers.
///
/// Workers register themselves before proofs can be started. Workers must
/// supply their exact deterministic `worker_id`; the manager validates the
/// mapping and refuses remaps for an existing URL. Workers must also
/// supply their configured `[provers]` capacities; the manager validates
/// these against its own [`ProversConfig`] and rejects mismatches.
pub struct EdgeWorkerRegistry {
    next_worker_id: AtomicUsize,
    expected_num_workers: usize,
    expected_provers: ProversConfig,
    workers: DashMap<usize, RegisteredWorker>,
    url_to_id: DashMap<String, usize>,
}

impl EdgeWorkerRegistry {
    pub fn new(expected_num_workers: usize, expected_provers: ProversConfig) -> Self {
        Self {
            next_worker_id: AtomicUsize::new(0),
            expected_num_workers,
            expected_provers,
            workers: DashMap::new(),
            url_to_id: DashMap::new(),
        }
    }

    fn bump_next_worker_id(&self, min_next: usize) {
        loop {
            let current = self.next_worker_id.load(Ordering::SeqCst);
            if current >= min_next {
                break;
            }
            if self
                .next_worker_id
                .compare_exchange_weak(current, min_next, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                break;
            }
        }
    }

    pub fn expected_worker_count(&self) -> usize {
        self.expected_num_workers
    }

    /// Validate a worker's reported `[provers]` capacity against what its role
    /// is expected to provide.
    fn validate_provers(&self, reported: &ProversConfig, role: WorkerRole) -> Result<()> {
        match role {
            WorkerRole::Full | WorkerRole::StarkOnly => {
                if reported != &self.expected_provers {
                    bail!(
                        "worker provers config does not match manager config: \
                         worker reported {:?}, manager expects {:?}",
                        reported,
                        self.expected_provers
                    );
                }
            }
            WorkerRole::EvmDedicated => {
                if reported.max_app_provers != 0
                    || reported.max_leaf_provers != 0
                    || reported.max_internal_provers != 0
                {
                    bail!(
                        "EvmDedicated worker must report zero app/leaf/internal capacity \
                         (it runs only the EVM step), but reported {:?}",
                        reported
                    );
                }
            }
        }
        Ok(())
    }

    /// Register a worker with the manager.
    ///
    /// `worker_id` is treated as the exact deterministic ID expected for this
    /// URL. The manager validates the mapping and rejects attempts to remap
    /// an already-known URL to a different ID. The worker's reported
    /// `provers_config` must match what its `worker_role` is expected to
    /// provide (see [`Self::validate_provers`]).
    ///
    /// Returns the confirmed worker ID.
    pub fn register(
        &self,
        worker_url: &str,
        worker_id: usize,
        provers_config: ProversConfig,
        worker_role: WorkerRole,
    ) -> Result<usize> {
        self.validate_provers(&provers_config, worker_role)?;

        if worker_id >= self.expected_num_workers {
            bail!(
                "worker_id {} >= server.num_workers {}",
                worker_id,
                self.expected_num_workers
            );
        }

        let now = chrono::Utc::now();

        // Check if this worker URL is already registered.
        if let Some(existing_id) = self.url_to_id.get(worker_url) {
            let existing_worker_id = *existing_id;
            if worker_id != existing_worker_id {
                bail!(
                    "worker URL {} already bound to worker_id {} but requested worker_id {}",
                    worker_url,
                    existing_worker_id,
                    worker_id
                );
            }
            // Update last seen time (and refresh the reported role, which is
            // static in practice but cheap to keep current).
            if let Some(mut worker) = self.workers.get_mut(&existing_worker_id) {
                worker.last_seen = now;
                worker.worker_role = worker_role;
            }
            debug!(
                "Worker {} re-registered at {}",
                existing_worker_id, worker_url
            );
            return Ok(existing_worker_id);
        }

        if let Some(existing_worker) = self.workers.get(&worker_id) {
            if existing_worker.worker_url != worker_url {
                bail!(
                    "worker_id {} already bound to {} (requested by {})",
                    worker_id,
                    existing_worker.worker_url,
                    worker_url
                );
            }
        }
        self.bump_next_worker_id(worker_id + 1);

        let worker = RegisteredWorker {
            worker_url: worker_url.to_string(),
            last_seen: now,
            worker_role,
        };

        self.workers.insert(worker_id, worker);
        self.url_to_id.insert(worker_url.to_string(), worker_id);

        debug!("Registered new worker {} at {}", worker_id, worker_url);

        Ok(worker_id)
    }

    /// Get all registered workers.
    ///
    /// Returns an error if registration is incomplete (fewer registered
    /// workers than `server.num_workers`, or missing IDs).
    pub fn ready_workers(&self) -> Result<Vec<(usize, RegisteredWorker)>> {
        if self.workers.is_empty() {
            bail!("No Edge workers have registered yet");
        }

        let mut workers: Vec<_> = self
            .workers
            .iter()
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect();

        workers.sort_by_key(|(id, _)| *id);

        let expected = self.expected_num_workers;
        if workers.len() != expected {
            bail!(
                "Only {}/{} Edge workers have registered with manager",
                workers.len(),
                expected
            );
        }

        let missing_ids: Vec<_> = (0..expected)
            .filter(|expected_id| {
                workers
                    .iter()
                    .all(|(worker_id, _)| worker_id != expected_id)
            })
            .collect();
        if !missing_ids.is_empty() {
            bail!(
                "Edge workers missing registrations for worker IDs {:?}",
                missing_ids
            );
        }

        // Enforce the app-sharding index-space invariant: the app-eligible
        // (STARK-proving) subset must be the contiguous prefix `0..M-1`, so the
        // `segment % num_provers == prover_id` shard residues cover exactly
        // those workers. Since the full set is already contiguous `0..expected-1`
        // and id-sorted, this holds iff every `EvmDedicated` (non-STARK) worker
        // sits at a top id — equivalently, the i-th app-eligible worker has id
        // `i`. A violation (a dedicated worker not at the top) would orphan a
        // modulo shard; reject it here (surfaced via `/readyz` and every
        // `start_proof`) rather than silently mis-route work. See
        // [`app_eligible_workers`].
        let app_ids: Vec<usize> = workers
            .iter()
            .filter(|(_, w)| w.worker_role.runs_stark_proving())
            .map(|(id, _)| *id)
            .collect();
        if let Some((i, id)) = app_ids
            .iter()
            .enumerate()
            .find(|(i, id)| **id != *i)
            .map(|(i, id)| (i, *id))
        {
            bail!(
                "App-eligible (STARK-proving) worker IDs must be the contiguous range 0..{} for \
                 modulo sharding to cover them; worker at position {} has id {} (got {:?}). \
                 Assign EvmDedicated worker(s) the top worker IDs.",
                app_ids.len(),
                i,
                id,
                app_ids
            );
        }

        info!(
            "ready_workers: returning {} workers sorted by ID: {:?}",
            workers.len(),
            workers
                .iter()
                .map(|(id, w)| (*id, &w.worker_url))
                .collect::<Vec<_>>()
        );

        Ok(workers)
    }

    /// Get number of registered workers.
    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    /// Get current registry status.
    pub fn get_status(&self) -> EdgeRegistryStatus {
        let mut workers: Vec<_> = self
            .workers
            .iter()
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect();
        workers.sort_by_key(|(id, _)| *id);

        EdgeRegistryStatus {
            num_workers: workers.len(),
            expected_num_workers: self.expected_num_workers,
            workers,
        }
    }
}

/// The **app-eligible (stark) worker set** for app sharding.
///
/// Returns every registered worker whose role runs STARK proving
/// (app + leaf + internal) — i.e. all workers except `EvmDedicated` ones —
/// preserving the input order (callers pass the id-sorted `ready_workers`).
///
/// This set — **not** `workers.len()` — drives `num_provers`, the per-segment
/// `prover_id`/shard assignment, the proof-state app-proof count, and
/// scheduler init. The `EvmDedicated` worker therefore owns no modulo shard
/// and receives no `sharded_app_prove`.
///
/// **Default-mode invariance.** With no `EvmDedicated` worker (the default —
/// every worker is `Full`) this is the identity on the input: same workers,
/// same ids, same order. So `num_provers`, shard indices, and the app-proof
/// count are bit-identical to today's routing over the full set.
///
/// **Index-space invariant.** Sharding is `segment % num_provers ==
/// prover_id` with `prover_id == worker_id` (unchanged from today). For the
/// residues `0..num_provers-1` to cover exactly the returned workers, their
/// ids must be the contiguous range `0..M-1` (`M` = returned count). The
/// dedicated-halo2 deploy guarantees this by assigning the top id(s) to the
/// `EvmDedicated` worker(s), so a normal set is always the low ids `0..M-1`.
/// A non-contiguous set (a dedicated worker not at the top id) would orphan a
/// modulo shard; [`EdgeWorkerRegistry::ready_workers`] rejects that arrangement at
/// the readiness gate, so callers here always receive a valid contiguous set.
pub fn app_eligible_workers(
    workers: &[(usize, RegisteredWorker)],
) -> Vec<(usize, RegisteredWorker)> {
    workers
        .iter()
        .filter(|(_, w)| w.worker_role.runs_stark_proving())
        .cloned()
        .collect()
}

/// Current status of the worker registry.
#[derive(Debug, Clone, Serialize)]
pub struct EdgeRegistryStatus {
    pub num_workers: usize,
    pub expected_num_workers: usize,
    pub workers: Vec<(usize, RegisteredWorker)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_provers() -> ProversConfig {
        ProversConfig {
            max_app_provers: 2,
            max_leaf_provers: 2,
            max_internal_provers: 1,
        }
    }

    #[test]
    fn test_register_workers() {
        let registry = EdgeWorkerRegistry::new(2, test_provers());

        let id0 = registry
            .register("http://worker-0:8001", 0, test_provers(), WorkerRole::Full)
            .unwrap();
        assert_eq!(id0, 0);

        let id1 = registry
            .register("http://worker-1:8001", 1, test_provers(), WorkerRole::Full)
            .unwrap();
        assert_eq!(id1, 1);

        let workers = registry.ready_workers().unwrap();
        assert_eq!(workers.len(), 2);
        assert_eq!(workers[0].0, 0);
        assert_eq!(workers[1].0, 1);
    }

    #[test]
    fn test_re_register_same_worker() {
        let registry = EdgeWorkerRegistry::new(1, test_provers());

        let id0 = registry
            .register("http://worker-0:8001", 0, test_provers(), WorkerRole::Full)
            .unwrap();
        assert_eq!(id0, 0);

        // Re-register same worker should return same ID.
        let id0_again = registry
            .register("http://worker-0:8001", 0, test_provers(), WorkerRole::Full)
            .unwrap();
        assert_eq!(id0_again, 0);

        assert_eq!(registry.worker_count(), 1);
    }

    #[test]
    fn test_register_with_exact_worker_id() {
        let registry = EdgeWorkerRegistry::new(5, test_provers());

        let id4 = registry
            .register("http://worker-4:8001", 4, test_provers(), WorkerRole::Full)
            .unwrap();
        assert_eq!(id4, 4);

        let id2 = registry
            .register("http://worker-2:8001", 2, test_provers(), WorkerRole::Full)
            .unwrap();
        assert_eq!(id2, 2);
    }

    #[test]
    fn test_worker_id_conflict() {
        let registry = EdgeWorkerRegistry::new(4, test_provers());
        registry
            .register("http://worker-a:8001", 3, test_provers(), WorkerRole::Full)
            .unwrap();

        let err = registry
            .register("http://worker-b:8001", 3, test_provers(), WorkerRole::Full)
            .unwrap_err();
        assert!(
            err.to_string().contains("worker_id 3 already bound"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_re_register_same_url_with_different_worker_id_is_rejected() {
        let registry = EdgeWorkerRegistry::new(2, test_provers());
        registry
            .register("http://worker-0:8001", 0, test_provers(), WorkerRole::Full)
            .unwrap();

        let err = registry
            .register("http://worker-0:8001", 1, test_provers(), WorkerRole::Full)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("already bound to worker_id 0 but requested worker_id 1"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_ready_workers_requires_full_registration() {
        let registry = EdgeWorkerRegistry::new(2, test_provers());
        registry
            .register("http://worker-0:8001", 0, test_provers(), WorkerRole::Full)
            .unwrap();

        let err = registry.ready_workers().unwrap_err();
        assert!(
            err.to_string()
                .contains("Only 1/2 Edge workers have registered"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_register_rejects_mismatched_provers_config() {
        let registry = EdgeWorkerRegistry::new(2, test_provers());

        let mut wrong = test_provers();
        wrong.max_leaf_provers = 4;

        let err = registry
            .register("http://worker-0:8001", 0, wrong, WorkerRole::Full)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("worker provers config does not match manager config"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_register_rejects_worker_id_above_num_workers() {
        let registry = EdgeWorkerRegistry::new(2, test_provers());
        let err = registry
            .register("http://worker-2:8001", 2, test_provers(), WorkerRole::Full)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("worker_id 2 >= server.num_workers 2"),
            "unexpected error: {err}"
        );
    }

    /// A dedicated worker reports zero app/leaf/internal capacity (its
    /// root/halo2 capacity is not part of the registration payload).
    fn dedicated_provers() -> ProversConfig {
        ProversConfig {
            max_app_provers: 0,
            max_leaf_provers: 0,
            max_internal_provers: 0,
        }
    }

    #[test]
    fn test_register_normal_worker_matches_expected_config() {
        // A StarkOnly worker runs app/leaf/internal at the uniform expected
        // capacity, so it registers cleanly (same expectation as Full).
        let registry = EdgeWorkerRegistry::new(2, test_provers());
        let id0 = registry
            .register(
                "http://worker-0:8001",
                0,
                test_provers(),
                WorkerRole::StarkOnly,
            )
            .unwrap();
        assert_eq!(id0, 0);

        let workers = registry.get_status().workers;
        assert_eq!(workers[0].1.worker_role, WorkerRole::StarkOnly);
    }

    #[test]
    fn test_register_evm_dedicated_worker_with_zero_stark_capacity() {
        // An honest EvmDedicated worker reports zero app/leaf/internal capacity
        // and must register cleanly instead of being rejected against the
        // uniform expected config.
        let registry = EdgeWorkerRegistry::new(2, test_provers());
        let id1 = registry
            .register(
                "http://worker-1:8001",
                1,
                dedicated_provers(),
                WorkerRole::EvmDedicated,
            )
            .unwrap();
        assert_eq!(id1, 1);

        let status = registry.get_status();
        let (_, worker) = status
            .workers
            .iter()
            .find(|(id, _)| *id == 1)
            .expect("worker 1 registered");
        assert_eq!(worker.worker_role, WorkerRole::EvmDedicated);
    }

    #[test]
    fn test_ready_workers_accepts_dedicated_at_top_id() {
        // The supported dedicated-halo2 layout: the EvmDedicated worker takes
        // the top id, so the app-eligible (STARK) set is the contiguous prefix
        // `0..M-1`. `ready_workers` must accept it.
        let registry = EdgeWorkerRegistry::new(2, test_provers());
        registry
            .register("http://worker-0:8001", 0, test_provers(), WorkerRole::Full)
            .unwrap();
        registry
            .register(
                "http://worker-1:8001",
                1,
                dedicated_provers(),
                WorkerRole::EvmDedicated,
            )
            .unwrap();

        let workers = registry.ready_workers().unwrap();
        assert_eq!(workers.len(), 2);
        // App-eligible set is the contiguous prefix [0].
        let app = app_eligible_workers(&workers);
        assert_eq!(app.iter().map(|(id, _)| *id).collect::<Vec<_>>(), vec![0]);
    }

    #[test]
    fn test_ready_workers_rejects_dedicated_not_at_top_id() {
        // A dedicated worker at a low id (0) leaves the app-eligible set as the
        // non-contiguous {1}, which would orphan modulo shard 0. `ready_workers`
        // must reject this at the readiness gate rather than silently mis-route.
        let registry = EdgeWorkerRegistry::new(2, test_provers());
        registry
            .register(
                "http://worker-0:8001",
                0,
                dedicated_provers(),
                WorkerRole::EvmDedicated,
            )
            .unwrap();
        registry
            .register("http://worker-1:8001", 1, test_provers(), WorkerRole::Full)
            .unwrap();

        let err = registry.ready_workers().unwrap_err();
        assert!(
            err.to_string()
                .contains("must be the contiguous range 0..1"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_register_rejects_evm_dedicated_claiming_stark_capacity() {
        // A dedicated worker that advertises app/leaf/internal capacity is
        // genuinely misconfigured — reject it.
        let registry = EdgeWorkerRegistry::new(2, test_provers());
        let err = registry
            .register(
                "http://worker-1:8001",
                1,
                test_provers(),
                WorkerRole::EvmDedicated,
            )
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("EvmDedicated worker must report zero app/leaf/internal capacity"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_register_rejects_normal_worker_with_wrong_config() {
        // Role-aware validation still rejects a genuinely wrong StarkOnly config.
        let registry = EdgeWorkerRegistry::new(2, test_provers());
        let mut wrong = test_provers();
        wrong.max_app_provers = 8;

        let err = registry
            .register("http://worker-0:8001", 0, wrong, WorkerRole::StarkOnly)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("worker provers config does not match manager config"),
            "unexpected error: {err}"
        );
    }

    // ------------------------------------------------------------------
    // app_eligible_workers (normal-set sharding)
    // ------------------------------------------------------------------

    fn worker(id: usize, role: WorkerRole) -> (usize, RegisteredWorker) {
        (
            id,
            RegisteredWorker {
                worker_url: format!("http://worker-{id}:8001"),
                last_seen: chrono::Utc::now(),
                worker_role: role,
            },
        )
    }

    /// (a) No dedicated worker ⇒ the app-eligible set is all N workers with
    /// the same ids `0..N-1`, in order — bit-identical to routing over the
    /// full set (default mode).
    #[test]
    fn test_app_eligible_no_dedicated_is_identity() {
        let workers = vec![
            worker(0, WorkerRole::Full),
            worker(1, WorkerRole::Full),
            worker(2, WorkerRole::Full),
            worker(3, WorkerRole::Full),
        ];

        let app = app_eligible_workers(&workers);

        assert_eq!(app.len(), workers.len(), "num_provers == N");
        let ids: Vec<usize> = app.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, vec![0, 1, 2, 3], "prover_id indices 0..N-1 as today");
    }

    /// A `StarkOnly`-only fleet (dedicated-halo2 mode, but no dedicated worker in
    /// this slice) is likewise the identity — `StarkOnly` runs STARK proving.
    #[test]
    fn test_app_eligible_normal_workers_included() {
        let workers = vec![
            worker(0, WorkerRole::StarkOnly),
            worker(1, WorkerRole::StarkOnly),
        ];
        let app = app_eligible_workers(&workers);
        assert_eq!(app.len(), 2);
        assert_eq!(
            app.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            vec![0, 1]
        );
    }

    /// (b) One dedicated worker at the last (top) id ⇒ N-1 provers; shards map
    /// only to the normal workers `0..N-2`; the dedicated worker is excluded
    /// entirely (owns no modulo shard).
    #[test]
    fn test_app_eligible_one_dedicated_last_excluded() {
        let workers = vec![
            worker(0, WorkerRole::StarkOnly),
            worker(1, WorkerRole::StarkOnly),
            worker(2, WorkerRole::StarkOnly),
            worker(3, WorkerRole::EvmDedicated),
        ];

        let app = app_eligible_workers(&workers);

        assert_eq!(app.len(), 3, "N-1 provers");
        let ids: Vec<usize> = app.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, vec![0, 1, 2], "contiguous normal-set ids 0..M-1");
        assert!(
            !app.iter().any(|(id, _)| *id == 3),
            "dedicated worker gets no shard"
        );

        // Every residue class mod num_provers maps to exactly one normal
        // worker (no orphaned shard).
        let num_provers = app.len();
        for seg in 0..12usize {
            let owner = seg % num_provers;
            assert!(
                ids.contains(&owner),
                "segment {seg} residue {owner} owned by a normal worker"
            );
        }
    }

    /// (c) The expected app-proof count (the value fed to `num_provers` /
    /// `ProofState::num_workers`) equals the app-eligible set size, not the
    /// registered worker count.
    #[test]
    fn test_app_eligible_count_matches_set_size() {
        let workers = vec![
            worker(0, WorkerRole::Full),
            worker(1, WorkerRole::Full),
            worker(2, WorkerRole::EvmDedicated),
        ];
        assert_eq!(workers.len(), 3, "three workers registered");
        assert_eq!(
            app_eligible_workers(&workers).len(),
            2,
            "expected app-proof count is the normal-set size (2), not 3"
        );
    }
}
