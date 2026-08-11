//! `emit_manifest` — a keygen host reports its deployment loadout and keyset epoch.
//!
//! Reads the on-disk keyset a worker boots from (`<artifacts>/deferral/cached_pk`
//! plus one `programs/{name}/{version}/program.vmexe` per loadout entry),
//! reconstructs the deployment SDK exactly the way the worker does at boot
//! (`Sdk::from_deferral_cached_proving_key`), derives each program's
//! `app_exe_commit`, and writes the loadout roster + `keyset_epoch` next to the
//! artifacts as `keyset-manifest.json` ([`edge_worker::keyset_manifest`]).
//!
//! ## Why this is all it emits
//!
//! Everything else a consumer needs is already an openvm type and already
//! served. `GET /vk/{name}` returns a `VmStarkVerifyingKey` whose
//! `VerificationBaseline` carries each child program's `app_exe_commit`,
//! `expected_def_hook_commit`, the `*_vk_commit`s, `memory_dimensions`, and
//! `num_user_pvs`; the shared `app_vm_commit` is *derivable* from that baseline
//! (`poseidon2_hash_slice` over the app/leaf/internal-for-leaf vk commits), so it
//! is re-emitted nowhere. What has no openvm type — the loadout roster and a
//! single-value `keyset_epoch` drift check — is what this binary produces. See
//! the [`edge_worker::keyset_manifest`] module docs for the full rationale.
//!
//! The one commit this binary genuinely surfaces is the **top** program's
//! `app_exe_commit`: the exporter writes a vk blob for `role = child` programs
//! only, so `GET /vk/{top}` is a 404 and the top's exe commit has no other
//! source. It is carried on every roster entry (uniformly with children) so the
//! roster is self-describing and the epoch is a pure function of the file.
//!
//! It does NOT run or change keygen and does not touch how proofs are produced —
//! it only reads already-generated artifacts and reports derived values. Run it
//! on the host that holds the keyset, after keygen/provisioning has populated
//! the artifacts dir.
//!
//! Reconstruction uses [`sdk_v2::CpuSdk`] regardless of the build's `cuda`
//! feature: `app_exe_commit` is a pure field-element hash of the program
//! executable, independent of the proving engine, so deriving it on CPU is both
//! correct and avoids coupling this offline reporting step to a GPU.

#[cfg(not(feature = "mock-provers"))]
mod emit {
    use std::path::PathBuf;
    use std::sync::Arc;

    use clap::Parser;
    use eyre::{ensure, eyre, Result, WrapErr};

    use continuations_v2::CommitBytes;
    use edge_worker::keyset_manifest::{
        KeysetManifest, ManifestProgram, ProgramRole, KEYSET_MANIFEST_FILE_NAME,
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

    #[derive(Parser, Debug)]
    #[command(
        author,
        version,
        about = "Emit keyset-manifest.json (loadout roster + keyset epoch) from an on-disk axiom-edge keyset"
    )]
    struct Args {
        /// Base artifacts dir: holds `deferral/cached_pk` and
        /// `programs/{name}/{version}/program.vmexe`. The manifest is written
        /// here unless `--output` overrides it.
        #[clap(long, default_value = "/data/artifacts")]
        artifacts_dir: PathBuf,

        /// Output path for the manifest. Defaults to
        /// `<artifacts_dir>/keyset-manifest.json`.
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

        let sdk = CpuSdk::from_deferral_cached_proving_key(cached_pk).map_err(|e| {
            eyre!(
                "reconstruct deferral SDK from {}: {e}",
                cached_pk_path.display()
            )
        })?;

        // Per-program app_exe_commit, in loadout order. `app_exe_commit` is a
        // hash of the program executable only; the reconstructed SDK is used
        // solely to build the prover that exposes it.
        let mut manifest_programs = Vec::with_capacity(programs.len());
        for program in &programs {
            let vmexe_path = args
                .artifacts_dir
                .join("programs")
                .join(&program.name)
                .join(program.version.to_string())
                .join("program.vmexe");
            println!(
                "Deriving app_exe_commit for {program} from {}",
                vmexe_path.display()
            );
            let exe: Exe = read_object_from_file(&vmexe_path)
                .wrap_err_with(|| format!("read {}", vmexe_path.display()))?;
            let prover = sdk
                .prover(Arc::new(exe))
                .map_err(|e| eyre!("build prover for {program}: {e}"))?;
            let app_exe_commit = CommitBytes::from(prover.generate_baseline().app_exe_commit);
            let role = role_for(&program.name, &args);
            manifest_programs.push(ManifestProgram {
                program: program.clone(),
                role,
                app_exe_commit,
            });
        }

        let manifest = KeysetManifest::new(manifest_programs);

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
        println!("  programs:     {}", manifest.programs.len());
        println!("  keyset_epoch: {}", manifest.keyset_epoch);
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
