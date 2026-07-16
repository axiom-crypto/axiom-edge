//! Integration tests for the Axiom Edge manager and worker.
//!
//! # Test matrix
//!
//! | Test file                    | Feature gate                | Runs in CI? | Why                                                                                                            |
//! |------------------------------|-----------------------------|-------------|----------------------------------------------------------------------------------------------------------------|
//! | `mock_e2e_test.rs`           | `mock-provers`              | yes         | Self-contained: boots one manager + one worker in-process on kernel-assigned ports; no GPU, no real artifacts. |
//! | `deferral_stark_e2e_test.rs` | `real-deferral-integration` | no          | Real-prover deferral (verify-stark) e2e; heavy, needs locally derived fixtures — see `docs/DEFERRAL.md`.       |
//!
//! Control-plane behaviors covered in CI by `mock_e2e_test.rs` (no GPU): proof
//! completion, multi-program loadout, unknown-program 409, the single-active-proof
//! gate (a second proof while one is active → 409), duplicate-uuid rejection, and
//! `/cancel_proof` (endpoint contract + proof terminalizes).
//!
//! Not covered by these suites: genuine multi-worker proving over the network
//! and the `/upload_input*` HTTP path (the mock harness uses
//! `input_already_uploaded`, so the upload path isn't driven; the proof-uuid
//! allowlist itself is unit-tested in `edge-worker`).
