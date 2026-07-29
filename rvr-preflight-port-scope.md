# Porting axiom-edge to openvm `feat/rvr-preflight` — scope

**Status:** blocked on an openvm-side change. Not an edge-only port.

- openvm branch: `feat/rvr-preflight` @ `97195d8a56cb27ec38298a5f8d70c44d1c7b166c` (based on `develop-v2.1.0`; retains recompute-touched-pages + rvr `!= 0` fixes).
- edge file in scope: `crates/edge-worker/src/provers/sharded_app_prover.rs`.
- Compile failure that triggered this: 4× `E0599` — `metered_segment_rvr_instance` and `vm.prove` no longer exist.

---

## Bottom line

`feat/rvr-preflight` is a large preflight/postflight execution refactor (~30 commits). It **removed the public per-segment prove primitive** (`VirtualMachine::prove`) and moved GPU per-segment proving into a **private** driver. The only public proving entry point is now a **whole-program, sequential** continuation driver that **reuses the preflight transcript between consecutive segments**.

The edge's sharded prover proves a **non-consecutive subset** of segments per worker, out of order, via snapshot + interpreter fast-forward (no transcript reuse). That model has **no public integration point** on this branch. So porting requires openvm to first re-expose a public per-segment prove.

---

## Why it's blocked (evidence)

On `develop-v2.1.0` the edge calls one public generic method per segment:

```rust
// crates/vm/src/arch/vm.rs:1195 (develop) — PUBLIC
app_prover.vm.prove(&mut interpreter, vm_state, Some(num_insns), &trace_heights)
    -> Result<(Proof, Option<GuestMemory>)>
// internally: transport_init_memory_to_device -> execute_preflight_inner
//             -> generate_proving_ctx -> engine.prove
```

On `feat/rvr-preflight`:

- `VirtualMachine::prove` — **removed**. No inherent `prove` on `VirtualMachine`.
- The individual CPU/GPU building blocks in `crates/vm/src/arch/vm.rs` have mixed visibility:

  | method | vis | notes |
  |---|---|---|
  | `preflight_interpreter` (1037) | `pub` | build the interpreter (VmInstance no longer holds it eagerly) |
  | `execute_preflight_for` (1066) | `pub` | `(&interp, state, num_insns) -> PreflightOutput`; **no `trace_heights`**, `&` not `&mut` |
  | `transport_init_memory_to_device` (1226) | `pub` | |
  | `memory_top_tree` (1233) | `pub` | |
  | `postflight_history` (1447) | `pub` | GPU postflight |
  | `generate_preflight_proving_ctx` (1525) | `pub` | GPU tracegen |
  | `generate_proving_ctx_from_postflight` (1115) | **`pub(crate)`** | CPU tracegen — not callable externally |
  | `override_system_trace_heights` (2030) | `pub` | force heights (old `trace_heights` role) |

- **The actual GPU+rvr per-segment pipeline is private** — `crates/sdk-config/src/preflight_driver.rs`:
  - `struct PreparedPreflight` (48) — **private**
  - `fn prove` (134), `fn prove_inner` (150) — **private**
  - Only `SdkVmGpuBuilder::continuation_prover()` is exposed (via `ContinuationProverBuilder`), returning a boxed **whole-program** `ContinuationProverFn` (`FnMut(&mut VmInstance, Streams) -> ContinuationVmProof`).
  - Inside `prove_inner`, the rvr GPU path uses `prepared.preflight.execute_segment(state, limits)` / `execute_segment_reusing(...)` with `PreflightLimits` + `num_preflight_residuals` + `CHECKPOINT_INTERVAL`, and reuses the transcript across consecutive segments. This is **not** the generic public `execute_preflight_for` path.

So even though several `vm.rs` GPU primitives are `pub`, the real rvr-GPU per-segment execution the edge needs (`PreparedPreflight::execute_segment`) is private, and there is no public "prove one arbitrary segment on GPU" call.

The edge uses the GPU engine: `ProverType = VmInstance<RecursionEngine, SdkVmBuilder>` (`sharded_app_prover.rs:457`), built via `new_local_prover::<RecursionEngine, _>` ("GPU, temporary").

---

## Part A — required openvm change (branch author)

Expose a **public per-segment GPU prove** on `feat/rvr-preflight`. Cleanest: re-add, matching `develop`'s shape/semantics:

```rust
impl<E, VB> VirtualMachine<E, VB> {
    /// Prove exactly `num_insns` instructions from `state`. Returns the segment
    /// proof and, on successful termination, the final memory.
    pub fn prove(
        &mut self,
        interpreter: &PreflightInterpretedInstance2<Val<E::SC>, VB::VmConfig>,
        state: VmState<GuestMemory>,
        num_insns: Option<u64>,
        trace_heights: &[u32],
    ) -> Result<(Proof<E::SC>, Option<GuestMemory>), VirtualMachineError>;
}
```

It should wrap the GPU sequence that `preflight_driver::prove_inner` currently inlines, for **one** segment:

1. `transport_init_memory_to_device(&state.memory)`
2. rvr GPU preflight for exactly `num_insns` (the `PreparedPreflight::execute_segment` path — **no transcript reuse required** for a standalone segment)
3. `postflight_history(...)` → `(GpuPostflightTranscript, GpuPostflightPlan)`
4. mark touched pages on the end state
5. `generate_preflight_proving_ctx(...)` (optionally `override_system_trace_heights(trace_heights)`)
6. `engine.prove(pk(), ctx)`
7. `final_memory = (exit_code == Success).then_some(end_state.memory)`

Notes for the author:
- The edge needs the **GPU** path (`RecursionEngine`). A generic `impl<E, VB>` (like develop's `prove`) that dispatches CPU/GPU is ideal.
- `trace_heights` may be droppable — the branch derives heights from the postflight. If kept, apply via `override_system_trace_heights`.
- **Do not** require sequential/transcript-reuse semantics: the edge proves segments out of order, one at a time, from a fast-forwarded start state.

Alternative (more invasive on the edge): make `generate_proving_ctx_from_postflight` + the sdk-config per-segment pieces `pub` and let the edge assemble the sequence. Not recommended — spreads private GPU-preflight internals across the crate boundary.

---

## Part B — edge changes (mechanical, once Part A lands)

In `crates/edge-worker/src/provers/sharded_app_prover.rs`:

1. **Rename** the metered instance constructor (line ~824):
   `executor_keepalive.metered_segment_rvr_instance(exe, &idx, num_airs, None)`
   → `executor_keepalive.metered_segment_instance(exe, &idx, num_airs, None)` (args identical).
   `MeteredInstanceType = RvrMeteredSegmentInstance` and `PureInstanceType = InterpretedInstance<ExecutionCtx>` are unchanged.

2. **Interpreter** (`VmInstance.interpreter` is now `Option<..>`, left `None`): build it explicitly once and pass a shared ref.
   `let interpreter = app_prover.vm.preflight_interpreter(exe)?;` then pass `&interpreter` (not `&mut app_prover.interpreter`).

3. **3 prove sites** (lines ~1085, ~1302, ~1667):
   - Keep `vm_state.memory.memory.recompute_touched_pages();` immediately before (fast-forwarded start state still needs it for the initial-memory transport).
   - Call the re-added `app_prover.vm.prove(&interpreter, vm_state, Some(num_insns), &trace_heights)` → `(proof, Option<final_memory>)`. Terminal-segment `final_memory` handling (user public values, `memory_top_tree`, deferral paths) is unchanged.
   - If Part A drops `trace_heights`, remove that argument at all 3 sites.

No changes expected to the metered segmentation loop (`MeteredDriver`), `fast_forward`, or snapshot/`+2`-lookahead logic.

---

## Part C — validate

1. `scripts/dev/start-provers.py N --total-provers N --programs ./scripts/dev/eth-v2.1-programs.json --regenerate` (cuda+rvr build + keygen).
2. `scripts/ops/start-proof.sh --input <v2.1 eth input>`.
3. Confirm all segments prove to `completed` (watch for LogUp/memory errors — verifies the fast-forward + new postflight touched-pages interplay).

---

## Effort

| part | who | effort |
|---|---|---|
| A — re-expose per-segment GPU prove | openvm branch author | small–moderate (they own the rvr-GPU internals) |
| B — edge port | edge | ~half a day + compile iteration |
| C — validate | edge | one build + prove (~30–45 min) |

**Recommendation:** hand Part A to the branch author. The edge cannot build against `feat/rvr-preflight` until a public per-segment prove exists; do not attempt to reproduce the private GPU-preflight pipeline in the edge.

---

## Appendix — old→new API reference

### `metered_segment_*_instance` (rename only, same args)
- develop `VmExecutor::metered_segment_rvr_instance` `vm.rs:446`
- branch `VmExecutor::metered_segment_instance` `vm.rs:543`
- signature (both): `(&self, exe: &VmExe<F>, executor_idx_to_air_idx: &[usize], num_airs: usize, guest_debug_map: Option<&GuestDebugMap>) -> Result<RvrMeteredSegmentInstance<'_>, StaticProgramError>`
- VirtualMachine wrapper: develop `get_metered_segment_rvr_instance` `vm.rs:808` → branch `metered_segment_instance` `vm.rs:917`.

### `PreflightOutput` (branch) — `crates/vm/src/arch/preflight.rs:35`
```rust
pub struct PreflightOutput {
    pub history: PreflightHistory,     // { program: Vec<PreflightProgramEvent>, memory: PreflightMemoryLog }
    pub state: VmState<GuestMemory>,   // architectural end state
    pub exit_code: Option<u32>,        // Some(..) only on the terminating segment
}
```

### Interpreter type
- `PreflightInterpretedInstance2<F, VC>` typedef is unchanged between branches.
- `PreflightInterpretedInstance::new`: develop = 3 args `(&program, inventory, executor_idx_to_air_idx)`; branch = 2 args `(exe, inventory)`. `VirtualMachine::preflight_interpreter` handles this.
- Passed by `&` on the branch (append-only), `&mut` on develop.

### Continuation driver (branch, `crates/vm/src/arch/vm.rs`)
- `ContinuationVmProof<SC> { per_segment: Vec<Proof<SC>>, user_public_values }` (1632)
- `ContinuationProverFn<E, VB> = Box<dyn FnMut(&mut VmInstance<E,VB>, Streams) -> Result<ContinuationVmProof<..>>>` (1637)
- `ContinuationVmProver::prove(&mut self, impl Into<Streams>)` (1646)
- `ContinuationProverBuilder::continuation_prover() -> ContinuationProverFn` (1657)
- `VmInstance { vm, interpreter: Option<..>, program_commitment, exe, state: Option<..> }` (1668)
- `prove_continuations` (1750, `pub(crate)`) — the whole-program per-segment loop.
- CPU driver wiring: `crates/sdk-config/src/lib.rs:436`; GPU: `:508` → `preflight_driver::continuation_prover()`.
