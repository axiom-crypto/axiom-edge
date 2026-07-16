#[cfg(not(feature = "mock-provers"))]
mod verify {
    use clap::Parser;
    use color_eyre::eyre::{Result, WrapErr};
    use edge_worker::artifacts::EdgeArtifacts;
    use edge_worker::openvm_config::create_edge_sdk;
    use edge_worker::stark_verify::load_final_proof;
    use sdk_v2::Sdk;
    use std::{env, path::PathBuf};
    use verify_stark::{
        verify_vm_stark_proof_decoded,
        vk::{read_vk_from_file, write_vk_to_file, VmStarkVerifyingKey},
    };

    #[derive(Parser, Debug)]
    #[command(
        author,
        version,
        about = "Verify a copied Edge final proof against the local Edge artifact set"
    )]
    struct Args {
        /// Path to the copied final proof file created by the Edge manager.
        #[arg(long)]
        proof: PathBuf,

        /// Base artifacts path. Layout: app_pk, agg_stark_pk at top level;
        /// per-program vmexes at programs/{name}/{version}/program.vmexe.
        #[arg(long, default_value_os_t = default_artifacts_path())]
        artifacts_path: PathBuf,

        /// Program name to verify against.
        #[arg(long, default_value = "test-program")]
        program_name: String,

        /// Program version to verify against.
        #[arg(long, default_value_t = 1)]
        program_version: u32,

        /// Optional path to a cached VM verifying key bundle.
        /// If the file exists it will be reused; otherwise it will be generated and written there.
        #[arg(long)]
        vm_vk: Option<PathBuf>,

        /// Verify against the deferral-aware keyset (VK carries the deferral
        /// hook commit). Required for any proof produced on a deferral
        /// deployment — including a non-deferral proof, which still carries a
        /// depth-0 `DeferralMerkleProofs` and an expected_def_hook_commit VK.
        #[arg(long, default_value_t = false)]
        deferral: bool,
    }

    fn default_artifacts_path() -> PathBuf {
        env::var_os("ARTIFACTS_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp/edge-test-artifacts"))
    }

    fn load_or_create_vm_vk(args: &Args) -> Result<VmStarkVerifyingKey> {
        if let Some(path) = &args.vm_vk {
            if path.exists() {
                println!("Using cached VM verifying key: {}", path.display());
                return read_vk_from_file(path).wrap_err_with(|| {
                    format!("Failed to read VM verifying key {}", path.display())
                });
            }
        }

        let program = protocol::ProgramRef::new(&args.program_name, args.program_version);
        let artifacts = EdgeArtifacts::load_from_disk(
            &args.artifacts_path,
            std::slice::from_ref(&program),
            #[cfg(feature = "evm-prove")]
            None,
            // Load the deferral cached_pk when verifying a deferral-keyset
            // proof, so we can rebuild the deferral-aware VK from it directly
            // (fast, no keygen). Off otherwise (today's non-deferral path).
            args.deferral,
        )
        .wrap_err("Failed to load Edge artifacts")?;

        let exe = artifacts
            .programs
            .get(&program)
            .cloned()
            .ok_or_else(|| color_eyre::eyre::eyre!("vmexe missing for {program}"))?;

        // A proof produced on a deferral deployment must be verified against
        // the deferral-aware VK (its baseline carries `expected_def_hook_commit`
        // and the proof carries `DeferralMerkleProofs`). Non-deferral proofs on
        // a deferral deployment are no exception — they still carry a depth-0
        // `DeferralMerkleProofs`. Rebuild that VK from the on-disk cached_pk
        // (`Sdk::from_deferral_cached_proving_key`, fast — no keygen), the same
        // reconstruction the tail worker does; NOT `create_edge_sdk_with_deferral`
        // which re-runs the full deferral keygen.
        let sdk = if args.deferral {
            // Deferral is STARK-level, so reconstructing the deferral-aware VK
            // from the on-disk cached_pk needs no `evm-prove` — the tail worker
            // does the identical reconstruction in a stark-only build, and a
            // stark-only cached_pk (no `root_pk`) reconstructs fine. Fast: reads
            // the pk, no keygen.
            let deferral = artifacts.deferral.as_ref().ok_or_else(|| {
                color_eyre::eyre::eyre!(
                    "--deferral set but no deferral cached_pk under {}/deferral/cached_pk",
                    args.artifacts_path.display()
                )
            })?;
            Sdk::from_deferral_cached_proving_key((*deferral.cached_pk).clone())
                .wrap_err("Sdk::from_deferral_cached_proving_key failed")?
        } else {
            create_edge_sdk()?
        };
        let prover = sdk
            .prover((*exe).clone())
            .wrap_err("Failed to construct Edge prover for baseline generation")?;
        let vk = VmStarkVerifyingKey {
            mvk: (*sdk.agg_vk()).clone(),
            baseline: prover.generate_baseline(),
        };

        if let Some(path) = &args.vm_vk {
            write_vk_to_file(path, &vk)
                .wrap_err_with(|| format!("Failed to write VM verifying key {}", path.display()))?;
            println!("Wrote VM verifying key: {}", path.display());
        }

        Ok(vk)
    }

    pub fn main() -> Result<()> {
        color_eyre::install()?;

        let args = Args::parse();
        let proof = load_final_proof(&args.proof)?;
        let vk = load_or_create_vm_vk(&args)?;

        verify_vm_stark_proof_decoded(&vk, &proof).wrap_err("OpenVM STARK verification failed")?;

        println!("Proof verified successfully: {}", args.proof.display());
        Ok(())
    }
}

#[cfg(not(feature = "mock-provers"))]
fn main() -> color_eyre::eyre::Result<()> {
    verify::main()
}

#[cfg(feature = "mock-provers")]
fn main() {
    eprintln!("Error: verify_edge_final_proof requires real prover dependencies");
    std::process::exit(1);
}
