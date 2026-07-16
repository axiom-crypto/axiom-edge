//! Tracing and OpenTelemetry setup for Axiom Edge.
//!
//! Internal crate — manager and worker binaries depend on this for telemetry
//! initialization, span timing capture, and HTTP trace context propagation.

pub mod span_timing;

use eyre::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::span_timing::SpanTimingLayer;

/// Telemetry configuration.
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    /// Log level filter (e.g., "info", "debug", "trace")
    pub log_level: String,
    /// Optional OTLP endpoint for traces
    pub otlp_endpoint: Option<String>,
    /// Service name for traces
    pub service_name: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            log_level: "info".to_string(),
            otlp_endpoint: None,
            service_name: "axiom-edge".to_string(),
        }
    }
}

/// Initialize telemetry with the given configuration.
pub fn init_telemetry(config: &TelemetryConfig) -> Result<()> {
    // Build the env filter
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    // Create the fmt layer for console output
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false);

    // Apply the filter at the registry level so disabled trace/debug events never
    // reach SpanTimingLayer or other layers in hot execution loops.
    let registry = tracing_subscriber::registry()
        .with(env_filter)
        .with(SpanTimingLayer)
        .with(fmt_layer);

    // Note: OTLP tracing is disabled for now due to API compatibility issues.
    // When needed, use opentelemetry 0.27+ with compatible APIs.
    if config.otlp_endpoint.is_some() {
        tracing::warn!("OTLP endpoint configured but OTLP tracing is not yet implemented");
    }

    registry.init();

    Ok(())
}

/// Shutdown telemetry (flush pending traces).
pub fn shutdown_telemetry() {
    // No-op for now since we don't have OTLP enabled
    tracing::info!("Telemetry shutdown requested");
}

/// Inject trace context headers into an HTTP request.
pub fn inject_trace_headers(
    headers: &mut reqwest::header::HeaderMap,
    _parent_span: Option<&tracing::Span>,
) {
    use opentelemetry::propagation::TextMapPropagator;
    use opentelemetry_sdk::propagation::TraceContextPropagator;

    struct HeaderInjector<'a>(&'a mut reqwest::header::HeaderMap);

    impl opentelemetry::propagation::Injector for HeaderInjector<'_> {
        fn set(&mut self, key: &str, value: String) {
            if let Ok(name) = reqwest::header::HeaderName::try_from(key) {
                if let Ok(val) = reqwest::header::HeaderValue::try_from(&value) {
                    self.0.insert(name, val);
                }
            }
        }
    }

    let propagator = TraceContextPropagator::new();
    let cx = opentelemetry::Context::current();
    propagator.inject_context(&cx, &mut HeaderInjector(headers));
}

/// Extract trace context from HTTP request headers.
pub fn extract_trace_context(headers: &axum::http::HeaderMap) -> opentelemetry::Context {
    use opentelemetry::propagation::TextMapPropagator;
    use opentelemetry_sdk::propagation::TraceContextPropagator;

    struct HeaderExtractor<'a>(&'a axum::http::HeaderMap);

    impl opentelemetry::propagation::Extractor for HeaderExtractor<'_> {
        fn get(&self, key: &str) -> Option<&str> {
            self.0.get(key).and_then(|v| v.to_str().ok())
        }

        fn keys(&self) -> Vec<&str> {
            self.0.keys().map(|k| k.as_str()).collect()
        }
    }

    let propagator = TraceContextPropagator::new();
    propagator.extract(&HeaderExtractor(headers))
}
