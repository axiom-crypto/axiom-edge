//! `emit_manifest` — a keygen host reports the keyset commits it derived.
//!
//! Reads the on-disk keyset a worker boots from (`<artifacts>/deferral/cached_pk`
//! plus one `programs/{name}/{version}/program.vmexe` per loadout entry),
//! reconstructs the deployment SDK exactly the way the worker does at boot
//! (`Sdk::from_deferral_cached_proving_key`), derives the family commits, and
//! writes them next to the artifacts as `edge-manifest.json`
//! ([`edge_worker::keyset_manifest`]).
//!
//! This is the axiom-edge side of milestone M3: a proving client needs each
//! child program's vk (already served by the manager at `GET /vk/{name}`), and
//! an L1-verifier deploy needs the top program's `app_exe_commit` plus the
//! shared `app_vm_commit` *before* any proof is produced. Those commits exist on
//! the host after keygen but were never exposed; this binary exposes them.
//!
//! It does NOT run or change keygen and does not touch how proofs are produced —
//! it only reads already-generated artifacts and reports derived values. Run it
//! on the host that holds the keyset, after keygen/provisioning has populated
//! the artifacts dir.
//!
//! ## Commit derivation (mirrors lighter's `regen-agg-commits` exporter)
//!
//! - `app_exe_commit` (per program): `sdk.prover(exe).generate_baseline().app_exe_commit`
//! - `app_vm_commit` (shared): `sdk.prover(exe).app_vm_commit()` — exe-independent,
//!   so it is read once from the first program.
//! - `def_hook_commit`: `sdk.def_hook_commit()`
//! - `deferral_cached_commit`: `sdk.deferral_circuit_cached_commits(0)` (single circuit)
//!
//! Every commit is emitted as raw little-endian limb-digest hex
//! (`keyset_manifest::digest_to_bytes`). See the module docs for why that
//! encoding is load-bearing.
//!
//! Reconstruction uses [`sdk_v2::CpuSdk`] regardless of the build's `cuda`
//! feature: the commits are pure field-element hashes, independent of the
//! proving engine, so deriving them on CPU is both correct and avoids coupling
//! this offline reporting step to a GPU.

#[cfg(not(feature = "mock-provers"))]
mod emit {
    use std::path::PathBuf;
    use std::sync::Arc;

    use clap::Parser;
    use eyre::{ensure, eyre, Result, WrapErr};

    use edge_worker::keyset_manifest::{
        digest_to_bytes, CommitInputs, Halo2Meta, ProgramRole, RawProgram,
        KEYSET_MANIFEST_FILE_NAME,
    };
    use openvm_sdk_config::SdkVmConfig;
    use openvm_stark_backend::Val;
    use protocol::{parse_programs_env, parse_programs_str, ProgramRef};
    use sdk_v2::fs::read_object_from_file;
    use sdk_v2::keygen::SdkCachedProvingKey;
    use sdk_v2::openvm_circuit::arch::instructions::exe::VmExe;
    use sdk_v2::{CpuSdk, SC};

    /// A pre-transpiled program executable, as loaded from `program.vmexe`.
    type Exe = VmExe<Val<SC>>;

    /// Index of the single deferral circuit the deployment registers (mirrors
    /// lighter's `DEFERRAL_DEF_IDX` and `create_edge_sdk_with_deferral`, which
    /// registers exactly `[SupportedDeferral::VerifyStark]`).
    const DEFERRAL_DEF_IDX: usize = 0;

    #[derive(Parser, Debug)]
    #[command(
        author,
        version,
        about = "Emit the keyset commits (edge-manifest.json) derived from an on-disk axiom-edge keyset"
    )]
    struct Args {
        /// Base artifacts dir: holds `deferral/cached_pk` and
        /// `programs/{name}/{version}/program.vmexe`. The manifest is written
        /// here unless `--output` overrides it.
        #[clap(long, default_value = "/data/artifacts")]
        artifacts_dir: PathBuf,

        /// Output path for the manifest. Defaults to
        /// `<artifacts_dir>/edge-manifest.json`.
        #[clap(long)]
        output: Option<PathBuf>,

        /// Loadout as a JSON array of `{name, version}` (same shape as
        /// `EDGE_PROGRAMS`). When omitted, `EDGE_PROGRAMS` is read from the
        /// environment. Program order is preserved and is part of the keyset
        /// epoch.
        #[clap(long)]
        programs: Option<String>,

        /// Name of the terminal (`role = top`) program; every other program is
        /// a `child`. When omitted, roles are derived from vk-blob presence:
        /// a program with `vk/{name}.app_vm_vk.bin` in the artifacts dir is a
        /// child, one without is the top (the export's own convention). Exactly
        /// one program must resolve to `top` either way.
        #[clap(long)]
        top: Option<String>,

        /// Directory holding `halo2_pk` (and its SRS files) — the worker's
        /// `halo2_pk_path`. Required to report `evm_ready = true`: the manifest
        /// is EVM-ready only when the cached_pk carries a root_pk AND this dir
        /// has a `halo2_pk`. Ignored unless built with `--features evm-prove`.
        #[clap(long)]
        halo2_pk_path: Option<PathBuf>,
    }

    pub fn main() -> Result<()> {
        let args = Args::parse();

        // Loadout: explicit `--programs`, else EDGE_PROGRAMS. Order preserved.
        let programs: Vec<ProgramRef> = match &args.programs {
            Some(json) => {
                parse_programs_str(json).map_err(|e| eyre!("failed to parse --programs: {e}"))?
            }
            None => parse_programs_env().map_err(|e| eyre!("no --programs given and {e}"))?,
        };

        // Validate an explicit `--top` names a program actually in the loadout,
        // so a typo fails loudly here rather than silently producing zero tops.
        if let Some(top) = &args.top {
            ensure!(
                programs.iter().any(|p| &p.name == top),
                "--top {top:?} is not in the loadout ({:?})",
                programs.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            );
        }

        // Reconstruct the deployment SDK from the cached pk — the same
        // reconstruction the worker performs at boot, so the commits derived
        // here match what the worker proves against.
        let cached_pk_path = args.artifacts_dir.join("deferral").join("cached_pk");
        println!(
            "Loading deferral cached_pk from {}",
            cached_pk_path.display()
        );
        let cached_pk: SdkCachedProvingKey<SdkVmConfig> = read_object_from_file(&cached_pk_path)
            .wrap_err_with(|| {
                format!(
                    "read {} — is this an artifacts dir produced by `keygen --with-deferral` / a \
                     lighter Edge export?",
                    cached_pk_path.display()
                )
            })?;

        // Whether the cached pk carries the root proving key (half of EVM
        // readiness). Captured before `cached_pk` is moved into the SDK.
        #[cfg(feature = "evm-prove")]
        let has_root_pk = cached_pk.root_pk.is_some();

        let sdk = CpuSdk::from_deferral_cached_proving_key(cached_pk).map_err(|e| {
            eyre!(
                "reconstruct deferral SDK from {}: {e}",
                cached_pk_path.display()
            )
        })?;

        // Deferral-path commits (require an active deferral prover, which the
        // reconstruction provides when cached_pk carried deferral keys).
        let def_hook_commit = digest_to_bytes(sdk.def_hook_commit().ok_or_else(|| {
            eyre!(
                "reconstructed SDK exposes no def_hook_commit — {} is not a deferral keyset \
                 (was it generated with `keygen --with-deferral`?)",
                cached_pk_path.display()
            )
        })?);
        let deferral_cached_commit = {
            let mut commits = sdk
                .deferral_circuit_cached_commits(DEFERRAL_DEF_IDX)
                .map_err(|e| eyre!("deferral_circuit_cached_commits({DEFERRAL_DEF_IDX}): {e}"))?;
            ensure!(
                commits.len() == 1,
                "expected exactly one deferral cached commit at index {DEFERRAL_DEF_IDX}, got {}",
                commits.len(),
            );
            *commits.pop().expect("length checked == 1").as_slice()
        };

        // Per-program exe commits + the shared vm commit (read once).
        let mut app_vm_commit: Option<[u8; 32]> = None;
        let mut raw_programs = Vec::with_capacity(programs.len());
        for program in &programs {
            let vmexe_path = args
                .artifacts_dir
                .join("programs")
                .join(&program.name)
                .join(program.version.to_string())
                .join("program.vmexe");
            println!(
                "Deriving commits for {program} from {}",
                vmexe_path.display()
            );
            let exe: Exe = read_object_from_file(&vmexe_path)
                .wrap_err_with(|| format!("read {}", vmexe_path.display()))?;
            let prover = sdk
                .prover(Arc::new(exe))
                .map_err(|e| eyre!("build prover for {program}: {e}"))?;
            if app_vm_commit.is_none() {
                app_vm_commit = Some(digest_to_bytes(prover.app_vm_commit()));
            }
            let app_exe_commit = digest_to_bytes(prover.generate_baseline().app_exe_commit);
            let role = role_for(&program.name, &args);
            raw_programs.push(RawProgram {
                name: program.name.clone(),
                version: program.version,
                app_exe_commit,
                role,
            });
        }
        let app_vm_commit =
            app_vm_commit.ok_or_else(|| eyre!("loadout resolved to zero programs"))?;

        // EVM readiness + halo2 sizes. EVM-ready requires BOTH a root_pk in the
        // cached pk AND a halo2_pk on disk; only then are the k sizes read (the
        // one field that needs the >10GB pk loaded). A stark-only build can
        // never be EVM-ready.
        #[cfg(feature = "evm-prove")]
        let (evm_ready, halo2) = evm_readiness(has_root_pk, args.halo2_pk_path.as_deref())?;
        #[cfg(not(feature = "evm-prove"))]
        let (evm_ready, halo2): (bool, Option<Halo2Meta>) = {
            if args.halo2_pk_path.is_some() {
                eprintln!(
                    "warning: --halo2-pk-path given but this binary was built without \
                     --features evm-prove; emitting evm_ready=false"
                );
            }
            (false, None)
        };

        let manifest = CommitInputs {
            programs: raw_programs,
            app_vm_commit,
            def_hook_commit,
            deferral_cached_commit,
            evm_ready,
            halo2,
        }
        .into_manifest();

        // Fail loudly on an inconsistent loadout (e.g. no single top) rather
        // than writing a manifest a downstream consumer will reject.
        manifest
            .validate()
            .map_err(|e| eyre!("assembled manifest failed validation: {e}"))?;

        let output = args
            .output
            .unwrap_or_else(|| args.artifacts_dir.join(KEYSET_MANIFEST_FILE_NAME));
        std::fs::write(&output, manifest.to_json()?)
            .wrap_err_with(|| format!("write {}", output.display()))?;

        println!("\n=== keyset manifest emitted ===");
        println!("  path:         {}", output.display());
        println!("  keyset_epoch: {}", manifest.keyset_epoch);
        println!("  evm_ready:    {}", manifest.evm_ready);
        Ok(())
    }

    /// Resolve a program's role. With `--top`, that program is `top` and every
    /// other is `child`. Without it, role follows the export convention: a
    /// child has a `vk/{name}.app_vm_vk.bin` blob, the top has none.
    fn role_for(name: &str, args: &Args) -> ProgramRole {
        match &args.top {
            Some(top) if top == name => ProgramRole::Top,
            Some(_) => ProgramRole::Child,
            None => {
                let vk = args.artifacts_dir.join(format!("vk/{name}.app_vm_vk.bin"));
                if vk.is_file() {
                    ProgramRole::Child
                } else {
                    ProgramRole::Top
                }
            }
        }
    }

    /// EVM readiness and halo2 SRS sizes. Ready iff the cached pk carried a
    /// root_pk and a `halo2_pk` file is present; the SRS `k` sizes are then read
    /// from the halo2 pk. Any other combination is stark-only.
    #[cfg(feature = "evm-prove")]
    fn evm_readiness(
        has_root_pk: bool,
        halo2_pk_path: Option<&std::path::Path>,
    ) -> Result<(bool, Option<Halo2Meta>)> {
        let halo2_pk_file = halo2_pk_path.map(|d| d.join("halo2_pk"));
        let halo2_present = halo2_pk_file.as_ref().map(|p| p.is_file()).unwrap_or(false);
        if !(has_root_pk && halo2_present) {
            if halo2_pk_path.is_some() || has_root_pk {
                eprintln!(
                    "note: not EVM-ready (cached_pk root_pk present: {has_root_pk}, \
                     halo2_pk present: {halo2_present}); emitting evm_ready=false"
                );
            }
            return Ok((false, None));
        }
        let halo2_pk_file = halo2_pk_file.expect("halo2_present implies Some");
        println!("Reading halo2 SRS sizes from {}", halo2_pk_file.display());
        let meta = load_halo2_meta(&halo2_pk_file)?;
        Ok((true, Some(meta)))
    }

    /// Read the halo2 verifier/wrapper `k` sizes from the proving key. Mirrors
    /// `artifacts::try_load_evm`'s field access; this loads the (large) pk.
    #[cfg(feature = "evm-prove")]
    fn load_halo2_meta(path: &std::path::Path) -> Result<Halo2Meta> {
        use sdk_v2::fs::read_halo2_pk_from_file;
        let pk =
            read_halo2_pk_from_file(path).wrap_err_with(|| format!("read {}", path.display()))?;
        Ok(Halo2Meta {
            verifier_k: pk.verifier.pinning.metadata.config_params.k,
            wrapper_k: pk.wrapper.pinning.metadata.config_params.k,
        })
    }
}

#[cfg(not(feature = "mock-provers"))]
fn main() -> eyre::Result<()> {
    emit::main()
}

#[cfg(feature = "mock-provers")]
fn main() {
    eprintln!("Error: emit_manifest requires real prover dependencies (not mock-provers)");
    std::process::exit(1);
}
