# Deferrals

...standalone deferral circuits. For example, verifying a STARK proof recursively is implemented using deferrals, as directly running verification in the guest would require substantial VM execution.

[Deferrals](https://docs.openvm.dev/book/acceleration-using-extensions/deferral)
enable the guest program to offload expensive computations to standalone deferral
circuits. For example, verifying a STARK proof recursively is implemented using deferrals, 
as directly running verification in the guest would require substantial VM execution. 
Edge runs the deferral part (`prove_def → prove_mixed → wrap`) on the tail worker, merging it 
into the VM tree's final internal proof. A `proof_type=stark` job stops there — the merged proof
is the deliverable; a `proof_type=evm` job continues that merged proof into root → halo2.

Deferrals require a different proving key, so it's a deployment parameter to support it or not.
An Edge deployment with deferrals can prove deferral or non-deferral jobs. 

Note that `verify_stark` is currently the only supported deferral circuit.
The example below is **self-recursion**: prove `fibonacci`, then prove a `verify-stark`
guest that verifies that fibonacci proof, end-to-end through the cluster.

## How inputs work (caller-derived)

Edge stays circuit-agnostic. The **caller** derives, per deferral circuit:

- a `DeferralState` (small) — populates `StdIn.deferrals[i]` during app execution;
- a `DeferralInput` (the encoded child proof) — consumed by the tail worker's `prove_def`.

See OpenVM [example](https://github.com/openvm-org/openvm/blob/b820b25baab6c5d9b055f64e0286b6b1058e707c/examples/verify-stark/host/src/lib.rs#L216)
for how to derive these.
Edge relays both opaquely. `verify-stark` uses exactly **one** deferral circuit. The
derivation logic is caller-side; the `derive_deferral_cluster_fixtures` test (the prepare
step below) is the reference implementation.

## Data flow: caller → edge

The caller starts with the **child proof to verify** and turns it into **three bincode
objects**, then submits them with a single `POST /start_proof`. The derivation is *cheap*:
it decodes the proof and reads its public values (`verify_stark_deferral_fn`) — it does
**not** re-verify the proof. The actual verification is the deferral circuit's job during
proving.

```text
CALLER
──────
  child proof P  (+ agg_vk, baseline)          ← must already exist; can't defer-verify nothing
        │
        ▼  verify_stark_guest_inputs(P, agg_vk, baseline)
        │     cheap: decode P + read its public values (NOT a re-verify)
        │
        ├──► outer StdIn      ──bincode──►  outer_stdin.bin        (guest reads: exe/vm/pvs/input_commit)
        ├──► DeferralState    ──bincode──►  deferral_state_0.bin   (extracted outputs, keyed by input commit)
        └──► DeferralInput    ──bincode──►  deferral_input_0.bin   (the encoded proof P, to be verified)

  upload the 3 .bin files to the manager in ONE multipart request, then make
  ONE more call to start — everything else is internal to edge:

  POST /upload_input/{proof_uuid}   →   MANAGER   (multipart/form-data)
      input             = outer_stdin.bin        (the outer StdIn)
      deferral_state_0  = deferral_state_0.bin
      deferral_input_0  = deferral_input_0.bin

  POST /start_proof   →   MANAGER          (JSON body — no paths, no counts)
    {
      "proof_uuid": "...",
      "program": { "name": "verify-stark", "version": 1 },
      "proof_type": "evm"                      // or "stark" — see below
    }
    // deferral is INFERRED from the uploaded artifacts; input_already_uploaded
    // defaults to false (manager-staged).

EDGE
────
  MANAGER  (fans the staged bytes out; retains each DeferralInput)
      ├─ POST /upload_input          → every app worker   (outer StdIn)
      ├─ POST /upload_deferral_state → every app worker   (all DeferralStates, one bundle)
      └─ POST /upload_deferral_input → the tail worker     (DeferralInput → prove_def, just-in-time)
      │
      ▼
  app → leaf → internal → tail merge (prove_def → prove_mixed → wrap) ─┬─ root → halo2 → completed   (proof_type=evm)
      ▲                                                                └─ completed                    (proof_type=stark)
      └── caller polls  GET /proof_state/{proof_uuid}  for status
```

(The diagram shows `proof_type=evm`. A `proof_type=stark` job follows the identical
path up to and including the tail merge, then completes — the merged internal proof,
carrying its `DeferralMerkleProofs`, is the final artifact; no root/halo2.)

**HTTP, in two calls:** the caller uploads everything to the **manager** in one
multipart `POST /upload_input/{proof_uuid}` (an `input` part plus a
`deferral_state_{i}`/`deferral_input_{i}` part per circuit), then `POST /start_proof`
(JSON). The worker-side `/upload_input` / `/upload_deferral_state` /
`/upload_deferral_input` calls are the **manager fanning out to workers**, not
something the caller does. Deferral is manager-staged only — the Flow-1
`input_already_uploaded: true` path (a producer pushing compact input straight
to every worker) does **not** support deferral. `start-proof.sh` picks the
transport for you: its default direct path is Flow 1, and any `--deferral-*`
flag forces the manager path. See [CONCEPTS](../CONCEPTS.md) for flow 1 vs flow 2 input handling.

**Which object goes where:** `outer StdIn` + `DeferralState` → **app workers** (app
execution — `DeferralState` becomes `StdIn.deferrals[0]`); `DeferralInput` → the **tail
worker** (`prove_def`, where the proof is actually verified). See the same split under
[How inputs work](#how-inputs-work-caller-derived) above.

## Prerequisites

- NVIDIA GPU(s) + the standard edge setup (see the [main README](../README.md)).
- A `programs.json` pointing at the bundled deferral guest:

  ```jsonc
  [ { "name": "verify-stark", "version": 1,
      "path": "crates/edge-integration-tests/tests/fixtures-deferral/verify-stark.elf" } ]
  ```

- **halo2 only:** KZG SRS files (`kzg_bn254_<k>.srs`) in `<SRS_DIR>`.

Both quick starts run the self-recursion demo end-to-end. `<uuid>` in the verify step is the
`proof_uuid` printed by `start-proof.sh`.

## Quick start — without halo2 (`proof_type=stark`)

```sh
# 1. prepare: proves fibonacci in-process, writes the 3 caller inputs to
#    /tmp/edge-deferral-fixtures/{outer_stdin,deferral_state_0,deferral_input_0}.bin
cargo test -p edge-integration-tests --test deferral_stark_e2e_test \
    --features real-deferral-integration,cuda --release \
    derive_deferral_cluster_fixtures -- --ignored --nocapture

# 2. start provers (auto-runs keygen --with-deferral; STARK-only, no halo2 key)
./scripts/dev/start-provers.py 4 --halo2 none --with-deferral --regenerate \
    --persist-final-proofs-dir /tmp/edge-final-proofs --programs programs.json

# 3. start proof
./scripts/ops/start-proof.sh --program verify-stark --version 1 --proof-type stark \
    --input          /tmp/edge-deferral-fixtures/outer_stdin.bin \
    --deferral-state /tmp/edge-deferral-fixtures/deferral_state_0.bin \
    --deferral-input /tmp/edge-deferral-fixtures/deferral_input_0.bin

# 4. verify (stark-only build; rebuilds the deferral VK from the keyset)
cargo build --release -p edge-worker --bin verify_edge_final_proof
./target/release/verify_edge_final_proof \
    --proof /tmp/edge-final-proofs/<uuid>.proof.bin \
    --program-name verify-stark --program-version 1 --deferral
```

## Quick start — with halo2 (`proof_type=evm`)

```sh
# 1. prepare: same as above — writes the 3 caller inputs
cargo test -p edge-integration-tests --test deferral_stark_e2e_test \
    --features real-deferral-integration,cuda --release \
    derive_deferral_cluster_fixtures -- --ignored --nocapture

# 2. halo2 keygen — deferral-shaped wrapper (>10 GB) → <HALO2_PK_DIR>
cargo build --release -p edge-worker --features evm-prove --bin halo2-keygen
./target/release/halo2-keygen --with-deferral \
    --kzg-params-dir <SRS_DIR> --output-dir <HALO2_PK_DIR>

# 3. start provers (halo2 on every worker)
./scripts/dev/start-provers.py 4 --halo2 full --with-deferral \
    --halo2-pk-path <HALO2_PK_DIR> --regenerate \
    --persist-final-proofs-dir /tmp/edge-final-proofs --programs programs.json

# 4. start proof
./scripts/ops/start-proof.sh --program verify-stark --version 1 --proof-type evm \
    --input          /tmp/edge-deferral-fixtures/outer_stdin.bin \
    --deferral-state /tmp/edge-deferral-fixtures/deferral_state_0.bin \
    --deferral-input /tmp/edge-deferral-fixtures/deferral_input_0.bin

# 5. verify
cargo build --release -p edge-worker --features evm-prove --bin verify_edge_final_proof
./target/release/verify_edge_final_proof \
    --proof /tmp/edge-final-proofs/<uuid>.proof.bin \
    --program-name verify-stark --program-version 1 --deferral
```

## Testing multiple verifications (N-sweep)

Sweep the number of `verify_stark` calls one proof makes (N) and plot STARK vs
halo2 time. Uses the `verify-stark-multi` guest + `programs-deferral-multi.json`.

```sh
# 1. fixtures for all N (one keygen) → /tmp/def-sweep/N<n>/
DEFERRAL_NUM_VERIFIES=1,2,4,8,16,32 DEFERRAL_FIXTURE_DIR=/tmp/def-sweep \
cargo test -p edge-integration-tests --test deferral_stark_e2e_test \
    --features real-deferral-integration,cuda --release \
    derive_deferral_multi_fixtures -- --ignored --nocapture

# 2. deploy: deferral + halo2, multi guest (needs a deferral halo2 key, §1 above)
./scripts/dev/start-provers.py 4 --halo2 full --with-deferral \
    --halo2-pk-path <HALO2_PK_DIR> --regenerate \
    --persist-final-proofs-dir /tmp/edge-final-proofs \
    --programs scripts/dev/programs-deferral-multi.json

# 3. sweep → ~/deferral-sweep-logs/<tag>.csv
./scripts/dev/deferral-sweep.sh --fixture-dir /tmp/def-sweep \
    --n-values 1,2,4,8,16,32 --tag defsweep
```

STARK-only (no halo2 key): deploy `--halo2 none --with-deferral` — the halo2
columns read 0.

