//! Edge Worker - Proof generation service for Edge mode.
//!
//! This worker handles proof generation for individual segments,
//! leaf proofs, and internal proofs in the recursion tree.

use clap::Parser;
use color_eyre::eyre::Result;
use std::path::PathBuf;

use edge_worker::{config::WorkerConfig, server::run_server};
use telemetry::{init_telemetry, shutdown_telemetry, TelemetryConfig};

#[derive(Parser)]
#[command(name = "edge-worker")]
#[command(about = "Edge proof generation worker")]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "config/testing/worker.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let args = Args::parse();
    let config = WorkerConfig::load(&args.config)?;

    // Initialize telemetry
    let telemetry_config = TelemetryConfig {
        log_level: config.telemetry.log_level.clone(),
        otlp_endpoint: config.telemetry.otlp_endpoint.clone(),
        service_name: format!("edge-worker-{}", config.worker.prover_id),
    };
    init_telemetry(&telemetry_config)?;

    tracing::info!(
        "Starting Edge worker {} on {}",
        config.worker.prover_id,
        config.server.listen_addr
    );

    // Run the server
    let result = run_server(config).await;

    // Cleanup
    shutdown_telemetry();

    result
}
