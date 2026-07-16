//! halo2-keygen — offline generator for the EVM (halo2) proving key.
//!
//! Produces the constant `halo2_pk` plus the two KZG SRS files (`kzg_bn254_<k>.srs`)
//! that `Halo2Prover::new` reads at worker boot. Runs once, host-side; output is
//! constant for a given OpenVM config + KZG SRS, and the serialized `halo2_pk` is
//! over 10GB (per upstream comment), so this is intentionally kept out of the
//! routine regenerate path.
//!
//! Inputs:
//!
//! ```text
//! --kzg-params-dir <DIR>   Directory holding `kzg_bn254_<k>.srs` files.
//!                          Trusted-setup SRS; provisioned out-of-band.
//! --output-dir     <DIR>   Output dir for `halo2_pk` + the two needed SRS
//!                          files. Workers mount this dir as `halo2_pk_path`.
//! ```
//!
//! `EDGE_OPENVM_CONFIG` is honored the same way as `keygen` — the OpenVM config
//! baked into `halo2_pk` must match the one used for `keygen`/`app_pk` or the
//! at-runtime worker will fail to wire up the verifier.
//!
//! This binary is only available under `--features evm-prove`; the
//! mock-provers build emits a stub error.

#[cfg(all(not(feature = "mock-provers"), feature = "evm-prove"))]
mod halo2_keygen {
    use clap::Parser;
    use eyre::{Context, Result};

    use edge_worker::openvm_config::{
        create_edge_sdk_for_halo2, create_edge_sdk_with_deferral_for_halo2,
    };
    use sdk_v2::fs::write_halo2_pk_to_file;
    use std::{fs, path::PathBuf};

    #[derive(Parser, Debug)]
    #[command(
        author,
        version,
        about = "Generate the EVM halo2 proving key (+ SRS files) for axiom-edge"
    )]
    struct Args {
        /// Directory holding the KZG SRS files (`kzg_bn254_<k>.srs`).
        #[clap(long)]
        kzg_params_dir: PathBuf,
        /// Output directory for `halo2_pk` + the two SRS files needed at runtime.
        #[clap(long, default_value = "output")]
        output_dir: PathBuf,
        #[clap(long)]
        with_deferral: bool,
    }

    pub fn main() -> Result<()> {
        let args = Args::parse();

        println!("=== axiom-edge halo2-keygen ===");
        println!("  KZG params dir: {}", args.kzg_params_dir.display());
        println!("  Output dir:     {}", args.output_dir.display());

        if !args.kzg_params_dir.is_dir() {
            eyre::bail!(
                "--kzg-params-dir {} does not exist or is not a directory",
                args.kzg_params_dir.display()
            );
        }
        fs::create_dir_all(&args.output_dir)?;

        let sdk = if args.with_deferral {
            println!("  Creating DEFERRAL-enabled SDK (verify-stark) + halo2 params reader...");
            create_edge_sdk_with_deferral_for_halo2(&args.kzg_params_dir)?
        } else {
            println!("  Creating SDK (axiom-edge VM config + halo2 params reader)...");
            create_edge_sdk_for_halo2(&args.kzg_params_dir)?
        };

        println!("  Generating halo2 proving key (this is expensive; serialized size is >10GB)...");
        let halo2_pk = sdk.halo2_pk();

        // The `k` baked into each pinning is what `Halo2Prover::new` reads from
        // the params reader at runtime — copy those SRS files alongside the pk
        // so the worker only needs to mount one directory.
        let verifier_k = halo2_pk.verifier.pinning.metadata.config_params.k;
        let wrapper_k = halo2_pk.wrapper.pinning.metadata.config_params.k;
        println!("  verifier_k={verifier_k}, wrapper_k={wrapper_k}");

        let halo2_pk_path = args.output_dir.join("halo2_pk");
        write_halo2_pk_to_file(&halo2_pk_path, &halo2_pk)?;
        println!("  Wrote {}", halo2_pk_path.display());

        let copy_srs = |k: usize| -> Result<PathBuf> {
            let name = format!("kzg_bn254_{k}.srs");
            let src = args.kzg_params_dir.join(&name);
            let dst = args.output_dir.join(&name);
            if dst == src {
                return Ok(dst);
            }
            fs::copy(&src, &dst).with_context(|| {
                format!("failed to copy {} -> {}", src.display(), dst.display())
            })?;
            println!("  Wrote {}", dst.display());
            Ok(dst)
        };
        let verifier_srs_path = copy_srs(verifier_k)?;
        let wrapper_srs_path = if wrapper_k == verifier_k {
            verifier_srs_path.clone()
        } else {
            copy_srs(wrapper_k)?
        };

        println!("\n=== halo2-keygen complete ===");
        println!("  halo2_pk:    {}", halo2_pk_path.display());
        println!("  verifier_srs: {}", verifier_srs_path.display());
        println!("  wrapper_srs:  {}", wrapper_srs_path.display());

        Ok(())
    }
}

#[cfg(all(not(feature = "mock-provers"), feature = "evm-prove"))]
fn main() -> eyre::Result<()> {
    halo2_keygen::main()
}
