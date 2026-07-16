#[cfg(not(feature = "mock-provers"))]
mod generate_vm_vk {
    use clap::Parser;
    use color_eyre::eyre::{Result, WrapErr};
    use edge_worker::stark_verify::build_vm_vk_from_elf;
    use std::path::PathBuf;
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
    }

    pub fn main() -> Result<()> {
        color_eyre::install()?;

        let args = Args::parse();
        let vk = build_vm_vk_from_elf(&args.elf)?;
        write_vk_to_file(&args.output, &vk).wrap_err_with(|| {
            format!("Failed to write VM verifying key {}", args.output.display())
        })?;

        println!("VM verifying key written to {}", args.output.display());
        Ok(())
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
