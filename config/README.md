# axiom-edge/config

TOML configs for the manager and workers. There are two runtime entry points (production via `start-provers.py`, and tests/dev via `cargo` or the mock docker-compose), so the same kind of config exists in two variants.

## Which configs are used, by which flow

### Flow 1: `scripts/dev/start-provers.py` (production GPU deploy)

The script renders configs at startup into `config/generated/` and those are mounted into the containers.

- `config/generated/manager.toml` — written if the host is primary (not `--worker-only`)
- `config/generated/worker-{0..N-1}.toml` — one per GPU worker

Do not edit the generated files; they are overwritten on every run.

To change values in this flow:
- **Defaults**: edit [`config/defaults.toml`](defaults.toml). It is the single source of truth for tunable defaults (prover pool sizes, VPMM tuning, metrics endpoint, etc.).
- **Per-deploy override**: pass a CLI flag to `start-provers.py` (e.g. `--app-provers`, `--vpmm-page-size`, `--metrics-endpoint`). The flag wins over `defaults.toml` for that run.
- **Layout/structure changes**: edit `config/templates/manager.toml.j2` or `config/templates/worker.toml.j2`.

Environment variables are intentionally **not** read for tunable values — they would change behavior silently. `start-provers.py` reads `defaults.toml` + CLI flags only. (Deployment-specific secrets — e.g. a reporter's API key — live with that external integration, not in the edge.)

### Flow 2: tests / dev (`cargo run`, Rust integration tests, mock docker-compose)

All consumers of the test/dev path read from `config/testing/`:

- `testing/manager.toml`, `testing/worker.toml` — defaults for `edge-manager` / `edge-worker` when no `--config` is passed (`cargo run` convenience).
- `testing/docker-manager.toml`, `testing/docker-worker-{0..3}.toml` — used by `docker/docker-compose.mock.yml`. Baked into the mock image via `COPY config/ ./config/` in `Dockerfile.mock` and referenced as `/app/config/testing/…`.

(`docker/docker-compose.yml` is a fragment composed by Flow 1 with the generated `docker-compose.provers.yml`; on its own it has no workers and is not a runnable flow.)

## Where to change specific values

For Flow 1: edit [`config/defaults.toml`](defaults.toml) for persistent changes, or pass a CLI flag for one-off overrides. The table below lists where each value lives across both flows.

| Value | TOML section / key | Where it lives |
|---|---|---|
| Worker pool sizes | `[provers] max_app_provers`, `max_leaf_provers`, `max_internal_provers` | `defaults.toml` (Flow 1) / `testing/worker.toml` / `testing/docker-worker-*.toml` (Flow 2) |
| VM segmentation defaults | `[provers] default_segment_memory` | `defaults.toml` (commented; uncomment to enable) / `testing/worker.toml` |
| CUDA VPMM tuning | `[cuda] vpmm_page_size`, `vpmm_pages` | `defaults.toml` (Flow 1; rendered to container env, not read by the worker). Flow 2 does not set VPMM. |
| Leaf packing / recursion arity | `[proof] leaf_pack_threshold`, `leaf_arity`, `internal_arity` | `defaults.toml` (Flow 1) / `testing/manager.toml` / `testing/docker-manager.toml` |
| Metrics endpoint / output dir | `[metrics] endpoint`, `output_dir` | `defaults.toml` (Flow 1) / `testing/manager.toml` / `testing/docker-manager.toml` |
| Proof lifecycle webhook | `[lifecycle] webhook_url` | `start-provers.py --webhook-url` (Flow 1) / TOML (Flow 2) |
| OpenVM VM config (extensions) | — | `start-provers.py --openvm-config-file` (Flow 1; default: built-in standard config) |
| Cargo features, CUDA arch, build flags | `[build]` section | `defaults.toml` / `scripts/dev/start-provers.py` CLI flags |

## Reproducibility guarantee

The worker and manager Rust code do not read any environment variable that affects proving behavior. Given the same TOML, they behave identically on any host. `scripts/dev/start-provers.py` reads `defaults.toml` and CLI flags only — not host env — so the rendered TOML is reproducible from those inputs alone, and is the single runtime source of truth.

Exception: `openvm-cuda-common` (upstream dependency) still reads `VPMM_PAGE_SIZE` / `VPMM_PAGES` from the environment. The worker binary does not read or set them — `start-provers` reads `[cuda]` from `defaults.toml` and renders them as container env vars (via `templates/docker-compose.provers.yml.j2`) before the worker starts, so you only set them in `defaults.toml` (or `--vpmm-page-size` / `--vpmm-pages`).

