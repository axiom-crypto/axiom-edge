//! Lock-free priority queue for Edge work items.
//!
//! Prioritizes work in order: Leaf proofs > Internal layer 0 > Internal layer 1 > ...

use crossbeam::queue::SegQueue;

use protocol::{GeneralProveRequest, MessageEnvelope, Step};

/// A work item in the queue.
#[derive(Clone)]
pub struct EdgeWorkItem {
    pub envelope: MessageEnvelope<GeneralProveRequest>,
    pub step: Step,
}

/// Lock-free priority queue for Edge work items.
///
/// Uses separate queues for different priority levels:
/// - Highest: Leaf proofs
/// - Then: Internal proofs by layer (layer 0, 1, 2, ...)
/// - Lowest: Other request types
pub struct PriorityWorkQueue {
    /// Highest priority: leaf proofs
    leaf_queue: SegQueue<EdgeWorkItem>,
    /// Internal proof queues indexed by layer (layer_queues[0] = layer 0, etc.)
    layer_queues: Vec<SegQueue<EdgeWorkItem>>,
    /// Fallback queue for other request types
    other_queue: SegQueue<EdgeWorkItem>,
}

impl Default for PriorityWorkQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl PriorityWorkQueue {
    /// Create a new priority work queue.
    pub fn new() -> Self {
        // Pre-allocate queues for common layer counts (can grow dynamically)
        let max_layers = 10; // Most proofs won't exceed this
        Self {
            leaf_queue: SegQueue::new(),
            layer_queues: (0..max_layers).map(|_| SegQueue::new()).collect(),
            other_queue: SegQueue::new(),
        }
    }

    /// Push a work item to the appropriate priority queue.
    pub fn push(&self, item: EdgeWorkItem) {
        match &item.envelope.message {
            GeneralProveRequest::LeafProve(_) => {
                self.leaf_queue.push(item);
            }
            GeneralProveRequest::InternalProve(req) => {
                let layer_idx = req.layer_idx;
                if layer_idx < self.layer_queues.len() {
                    self.layer_queues[layer_idx].push(item);
                } else {
                    // Rare case: layer exceeds pre-allocated queues, use last queue
                    self.layer_queues.last().unwrap().push(item);
                }
            }
            // The EVM step (dedicated-halo2 mode) is the lowest-priority class:
            // it only fires after the whole recursion tree is done, and the
            // dedicated worker serves nothing else. The `other_queue` gives it a
            // FIFO home so a busy dedicated worker queues (single slot) instead
            // of erroring.
            GeneralProveRequest::EvmProve(_) => {
                self.other_queue.push(item);
            }
        }
    }

    /// Pop the highest priority work item.
    pub fn pop(&self) -> Option<EdgeWorkItem> {
        // Check leaf queue first (highest priority)
        if let Some(item) = self.leaf_queue.pop() {
            return Some(item);
        }

        // Then check internal layers in order (0, 1, 2, ...)
        for queue in &self.layer_queues {
            if let Some(item) = queue.pop() {
                return Some(item);
            }
        }

        // Finally check other queue
        self.other_queue.pop()
    }

    /// Re-enqueue a work item that could not be dispatched (no free worker, or
    /// a failed send), returning it to its priority class.
    ///
    /// FIFO within a class: the item goes to the **back** of its class queue,
    /// the same as [`push`](Self::push) — `SegQueue` is a lock-free FIFO with
    /// no head-insertion, so a retried item does **not** jump ahead of other
    /// same-class work already queued. Cross-class priority is still honored by
    /// [`pop`](Self::pop) (leaf > internal layer 0 > layer 1 > ...).
    ///
    /// Retry ordering *within* a class is not significant for correctness here
    /// (one active proof at a time; the item is still retried promptly), so we
    /// keep the queue lock-free rather than switching to a `Mutex<VecDeque>`
    /// per class just to gain head-insertion.
    pub fn requeue(&self, item: EdgeWorkItem) {
        self.push(item);
    }

    /// Check if all queues are empty.
    pub fn is_empty(&self) -> bool {
        self.leaf_queue.is_empty()
            && self.layer_queues.iter().all(|q| q.is_empty())
            && self.other_queue.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::{InternalProveRequest, LeafProveRequest, ProgramRef, ProofContext};

    fn make_context() -> ProofContext {
        ProofContext::new(
            "test-proof".to_string(),
            ProgramRef::new("test-program", 1),
            Default::default(),
        )
    }

    #[test]
    fn test_priority_ordering() {
        let queue = PriorityWorkQueue::new();

        // Push internal layer 1
        queue.push(EdgeWorkItem {
            envelope: MessageEnvelope::with_metadata(GeneralProveRequest::InternalProve(
                InternalProveRequest {
                    context: make_context(),
                    child_proofs: vec![],
                    layer_idx: 1,
                    segment_start: 0,
                    segment_end: 3,
                    is_final_proof: false,
                    deferral_tail: None,
                    deferral_merkle_proofs_bytes: None,
                },
            )),
            step: Step::InternalProve,
        });

        // Push leaf
        queue.push(EdgeWorkItem {
            envelope: MessageEnvelope::with_metadata(GeneralProveRequest::LeafProve(
                LeafProveRequest {
                    context: make_context(),
                    app_proofs: vec![],
                    segment_start: 0,
                    segment_end: 0,
                },
            )),
            step: Step::LeafProve,
        });

        // Push internal layer 0
        queue.push(EdgeWorkItem {
            envelope: MessageEnvelope::with_metadata(GeneralProveRequest::InternalProve(
                InternalProveRequest {
                    context: make_context(),
                    child_proofs: vec![],
                    layer_idx: 0,
                    segment_start: 0,
                    segment_end: 1,
                    is_final_proof: false,
                    deferral_tail: None,
                    deferral_merkle_proofs_bytes: None,
                },
            )),
            step: Step::InternalProve,
        });

        // Pop should return leaf first
        let item = queue.pop().unwrap();
        assert_eq!(item.step, Step::LeafProve);

        // Then internal layer 0
        let item = queue.pop().unwrap();
        if let GeneralProveRequest::InternalProve(req) = &item.envelope.message {
            assert_eq!(req.layer_idx, 0);
        } else {
            panic!("Expected InternalProve");
        }

        // Then internal layer 1
        let item = queue.pop().unwrap();
        if let GeneralProveRequest::InternalProve(req) = &item.envelope.message {
            assert_eq!(req.layer_idx, 1);
        } else {
            panic!("Expected InternalProve");
        }

        // Queue should be empty
        assert!(queue.pop().is_none());
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let queue = Arc::new(PriorityWorkQueue::new());
        let mut handles = vec![];

        // Spawn 10 threads pushing
        for i in 0..10 {
            let q = queue.clone();
            handles.push(thread::spawn(move || {
                for j in 0..100 {
                    q.push(EdgeWorkItem {
                        envelope: MessageEnvelope::with_metadata(GeneralProveRequest::LeafProve(
                            LeafProveRequest {
                                context: make_context(),
                                app_proofs: vec![],
                                segment_start: i * 100 + j,
                                segment_end: i * 100 + j,
                            },
                        )),
                        step: Step::LeafProve,
                    });
                }
            }));
        }

        // Spawn 5 threads popping
        for _ in 0..5 {
            let q = queue.clone();
            handles.push(thread::spawn(move || {
                let mut count = 0;
                while count < 200 {
                    if q.pop().is_some() {
                        count += 1;
                    }
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // All items should be consumed
        assert!(queue.is_empty());
    }
}
