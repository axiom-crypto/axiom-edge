#[cfg(not(feature = "mock-provers"))]
mod generate_vm_vk {
    use clap::Parser;
    use color_eyre::eyre::{Result, WrapErr};
    use edge_worker::openvm_config::create_edge_sdk;
    use edge_worker::stark_verify::build_vm_vk_from_elf_with_sdk;
    use sdk_v2::Sdk;
    use std::path::{Path, PathBuf};
    use verify_stark::vk::write_vk_to_file;

    #[derive(Parser, Debug)]
    #[command(
        author,
        version,
        about = "Generate an Edge VM verifying key bundle from an ELF"
    )]
    struct Args {
        /// Path to the input ELF file.
        #[arg(long)]
        elf: PathBuf,

        /// Output path for the generated VM verifying key bundle.
        #[arg(long, default_value = "reth.vm.vk")]
        output: PathBuf,

        /// Optional path to a deferral `SdkCachedProvingKey` (produced by
        /// `keygen --with-deferral`). When set, the vk is built with the
        /// deferral-enabled SDK, which adds the `DeferralTranspilerExtension`.
        /// Required for a deferral guest such as the final aggregation program:
        /// its custom opcodes are owned by the deferral extension, which the
        /// standard config's transpiler lacks ("couldn't parse the next
        /// instruction"). Mirrors `convert_fixtures --deferral-cached-pk` so a
        /// program's vk uses the same VM config — hence transpiler — as its
        /// `program.vmexe`.
        #[arg(long)]
        deferral_cached_pk: Option<PathBuf>,
    }

    pub fn main() -> Result<()> {
        color_eyre::install()?;

        let args = Args::parse();
        let sdk = build_sdk(args.deferral_cached_pk.as_deref())?;
        let vk = build_vm_vk_from_elf_with_sdk(&sdk, &args.elf)?;
        write_vk_to_file(&args.output, &vk).wrap_err_with(|| {
            format!("Failed to write VM verifying key {}", args.output.display())
        })?;

        println!("VM verifying key written to {}", args.output.display());
        Ok(())
    }

    /// Select the SDK the vk is built with: the deferral-enabled SDK when a
    /// `--deferral-cached-pk` is supplied, else the standard edge SDK. This is
    /// the same standard-vs-deferral split `convert_fixtures::convert_elf_to_vmexe`
    /// makes, so the vk uses the same transpiler as the program's vmexe.
    fn build_sdk(deferral_cached_pk: Option<&Path>) -> Result<Sdk> {
        let Some(pk_path) = deferral_cached_pk else {
            return create_edge_sdk();
        };
        #[cfg(feature = "evm-prove")]
        {
            use color_eyre::eyre::eyre;
            use openvm_sdk_config::SdkVmConfig;
            use sdk_v2::fs::read_object_from_file;
            use sdk_v2::keygen::SdkCachedProvingKey;
            println!(
                "Using deferral-enabled SDK (cached_pk: {})",
                pk_path.display()
            );
            let cached_pk: SdkCachedProvingKey<SdkVmConfig> = read_object_from_file(pk_path)
                .wrap_err_with(|| {
                    format!("Failed to read deferral cached_pk: {}", pk_path.display())
                })?;
            Sdk::from_deferral_cached_proving_key(cached_pk)
                .map_err(|e| eyre!("Failed to reconstruct deferral SDK from cached_pk: {e}"))
        }
        #[cfg(not(feature = "evm-prove"))]
        {
            // The deferral keyset is STARK-level; the vk only depends on the
            // deferral VM *config* (the transpiler + agg vk), not the cached
            // proving key, so a stark-only (`--halo2 none`) deferral deployment
            // rebuilds that config with the same non-evm constructor
            // `keygen --with-deferral` used. Mirrors `convert_fixtures`.
            use edge_worker::openvm_config::create_edge_sdk_with_deferral;
            let _ = pk_path;
            println!("Using deferral-enabled SDK (stark-only; VM config only)");
            create_edge_sdk_with_deferral()
        }
    }
}

#[cfg(not(feature = "mock-provers"))]
fn main() -> color_eyre::eyre::Result<()> {
    generate_vm_vk::main()
}

#[cfg(feature = "mock-provers")]
fn main() {
    eprintln!("Error: generate_edge_vm_vk requires real prover dependencies");
    std::process::exit(1);
}
