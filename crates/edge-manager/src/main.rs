//! Edge Manager - Proof orchestration service for Edge mode.
//!
//! This manager coordinates proof generation across multiple workers,
//! managing work assignment, result collection, and recursion tree building.

use clap::Parser;
use color_eyre::eyre::Result;
use std::path::PathBuf;

use edge_manager::{config::ManagerConfig, otel_metrics, server::run_server};
use telemetry::{init_telemetry, shutdown_telemetry, TelemetryConfig};

#[derive(Parser)]
#[command(name = "edge-manager")]
#[command(about = "Edge proof orchestration manager")]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "config/testing/manager.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let args = Args::parse();
    let config = ManagerConfig::load(&args.config)?;

    // Initialize telemetry
    let telemetry_config = TelemetryConfig {
        log_level: config.telemetry.log_level.clone(),
        otlp_endpoint: config.telemetry.otlp_endpoint.clone(),
        service_name: "edge-manager".to_string(),
    };
    init_telemetry(&telemetry_config)?;

    // Initialize OTEL metrics export (endpoint/api_key come from manager config).
    let _meter_provider = otel_metrics::init_metrics(&config.metrics)?;

    tracing::info!("Starting Edge Manager on {}", config.server.listen_addr);

    // Run the server
    let result = run_server(config).await;

    // Cleanup: flush metrics before shutting down
    if let Some(ref provider) = _meter_provider {
        if let Err(e) = provider.shutdown() {
            tracing::warn!("Failed to shutdown meter provider: {:?}", e);
        }
    }
    shutdown_telemetry();

    result
}
