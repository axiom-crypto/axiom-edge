#[cfg(not(feature = "mock-provers"))]
mod keygen {
    use clap::Parser;
    use eyre::Result;

    use edge_worker::openvm_config::{create_edge_sdk, create_edge_sdk_with_deferral};
    use sdk_v2::fs::write_object_to_file;
    use std::{fs, path::PathBuf};

    #[derive(Parser, Debug)]
    #[command(
        author,
        version,
        about = "Generate proving keys for axiom-edge (app_pk + agg_stark_pk; root_pk when built with --features evm-prove)"
    )]
    struct Args {
        /// Output directory for the generated keys
        #[clap(long, default_value = "output")]
        output_dir: PathBuf,
        /// Also generate deferral-aware proving keys (verify-stark deferral
        /// circuit). Persists a `SdkCachedProvingKey` artifact under
        /// `<output_dir>/deferral/` alongside the non-deferral keys. The
        /// deferral keyset is STARK-level and needs no `evm-prove`; under
        /// `--features evm-prove` the cached_pk additionally carries a `root_pk`
        /// for the `proof_type=evm` tail.
        #[clap(long)]
        with_deferral: bool,
    }

    pub fn main() -> Result<()> {
        let args = Args::parse();

        println!("=== axiom-edge keygen ===");
        println!("  Output dir: {}", args.output_dir.display());

        fs::create_dir_all(&args.output_dir)?;

        let app_pk_path = args.output_dir.join("app_pk");
        let agg_pk_path = args.output_dir.join("agg_stark_pk");

        println!("  Creating SDK (axiom-edge VM config)...");
        let sdk = create_edge_sdk()?;

        // Generate app proving key
        println!("  Generating app proving key...");
        let (app_pk, _app_vk) = sdk.app_keygen();
        write_object_to_file(&app_pk_path, &app_pk)?;
        println!("  Wrote {}", app_pk_path.display());

        // Generate aggregation proving key
        println!("  Generating aggregation proving key...");
        let agg_pk = sdk.agg_pk();
        write_object_to_file(&agg_pk_path, &agg_pk)?;
        println!("  Wrote {}", agg_pk_path.display());

        // Generate root proving key (only under `evm-prove`).
        // `sdk.root_pk()` lazily initializes the root prover, which runs a CPU
        // dummy proof through app→agg→root to record trace heights — no KZG /
        // trusted setup involved.
        #[cfg(feature = "evm-prove")]
        let root_pk_path = {
            let root_pk_path = args.output_dir.join("root_pk");
            println!("  Generating root proving key (CPU dummy proof, no KZG)...");
            let root_pk = sdk.root_pk();
            write_object_to_file(&root_pk_path, &root_pk)?;
            println!("  Wrote {}", root_pk_path.display());
            root_pk_path
        };

        // Deferral keygen — additive to the non-deferral
        // path above. Mirrors openvm `examples/verify-stark/host/src/lib.rs`:
        // build a deferral-enabled SDK with `DeferralAggProver::verify_stark`,
        // materialize app + agg + deferral keys, and persist them via
        // `SdkCachedProvingKey`
        let deferral_dir = if args.with_deferral {
            let deferral_dir = args.output_dir.join("deferral");
            fs::create_dir_all(&deferral_dir)?;
            let cached_pk_path = deferral_dir.join("cached_pk");

            println!("\n  === deferral keygen ===");
            println!("  Creating deferral-enabled SDK (verify-stark)...");
            let deferral_sdk = create_edge_sdk_with_deferral()?;

            println!("  Generating deferral app_pk...");
            let _ = deferral_sdk.app_keygen();
            println!("  Generating deferral agg_pk...");
            let _ = deferral_sdk.agg_pk();
            // root_pk only exists (and is only needed) under `evm-prove`.
            #[cfg(feature = "evm-prove")]
            {
                println!("  Generating deferral root_pk (CPU dummy proof)...");
                let _ = deferral_sdk.root_pk();
            }

            println!("  Materializing SdkCachedProvingKey...");
            let cached_pk = deferral_sdk.cached_proving_key()?;
            write_object_to_file(&cached_pk_path, &cached_pk)?;
            println!("  Wrote {}", cached_pk_path.display());
            Some(deferral_dir)
        } else {
            None
        };

        println!("\n=== keygen complete ===");
        println!("  app_pk:       {}", app_pk_path.display());
        println!("  agg_stark_pk: {}", agg_pk_path.display());
        #[cfg(feature = "evm-prove")]
        println!("  root_pk:      {}", root_pk_path.display());
        if let Some(deferral_dir) = deferral_dir {
            println!("  deferral:     {}", deferral_dir.display());
        }

        Ok(())
    }
}

#[cfg(not(feature = "mock-provers"))]
fn main() -> eyre::Result<()> {
    keygen::main()
}

#[cfg(feature = "mock-provers")]
fn main() {
    eprintln!("Error: keygen requires real prover dependencies");
    std::process::exit(1);
}
