//! OTEL metrics bridge for edge-manager.
//!
//! Bridges the `metrics` crate (used by proof_state.rs) to OpenTelemetry,
//! exporting via OTLP HTTP to metrics-api → VictoriaMetrics.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use eyre::Result;
use metrics::{Key, KeyName, Recorder, SharedString, Unit};
use opentelemetry::global;
use opentelemetry::KeyValue;
use opentelemetry_otlp::MetricExporter;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_otlp::WithHttpConfig;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider, Temporality};
use opentelemetry_sdk::Resource;
use tracing::info;

/// Metrics recorder that bridges `metrics` crate → OTEL gauges/counters/histograms.
pub struct OtelMetricRecorder {
    meter: opentelemetry::metrics::Meter,
}

struct OtelCounter {
    counter: opentelemetry::metrics::Counter<u64>,
    gauge: opentelemetry::metrics::Gauge<f64>,
    labels: Vec<KeyValue>,
}

impl metrics::CounterFn for OtelCounter {
    fn increment(&self, value: u64) {
        self.counter.add(value, &self.labels);
    }
    fn absolute(&self, value: u64) {
        self.gauge.record(value as f64, &self.labels);
    }
}

struct OtelGauge {
    gauge: opentelemetry::metrics::Gauge<f64>,
    labels: Vec<KeyValue>,
}

impl metrics::GaugeFn for OtelGauge {
    fn increment(&self, value: f64) {
        self.gauge.record(value, &self.labels);
    }
    fn decrement(&self, value: f64) {
        self.gauge.record(-value, &self.labels);
    }
    fn set(&self, value: f64) {
        self.gauge.record(value, &self.labels);
    }
}

struct OtelHistogram {
    histogram: opentelemetry::metrics::Histogram<f64>,
    labels: Vec<KeyValue>,
}

impl metrics::HistogramFn for OtelHistogram {
    fn record(&self, value: f64) {
        self.histogram.record(value, &self.labels);
    }
}

impl OtelMetricRecorder {
    pub fn new(meter_name: &'static str) -> Self {
        let meter = global::meter(meter_name);
        Self { meter }
    }

    fn get_labels(key: &Key) -> Vec<KeyValue> {
        key.labels()
            .map(|label| KeyValue::new(label.key().to_string(), label.value().to_string()))
            .collect()
    }
}

impl Recorder for OtelMetricRecorder {
    fn describe_counter(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}
    fn describe_gauge(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}
    fn describe_histogram(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn register_counter(&self, key: &Key, _metadata: &metrics::Metadata<'_>) -> metrics::Counter {
        let name = key.name().to_string();
        let counter = self.meter.u64_counter(name.clone()).build();
        let gauge = self.meter.f64_gauge(name).build();
        let labels = Self::get_labels(key);
        metrics::Counter::from_arc(Arc::new(OtelCounter {
            counter,
            gauge,
            labels,
        }))
    }

    fn register_gauge(&self, key: &Key, _metadata: &metrics::Metadata<'_>) -> metrics::Gauge {
        let name = key.name().to_string();
        let gauge = self.meter.f64_gauge(name).build();
        let labels = Self::get_labels(key);
        metrics::Gauge::from_arc(Arc::new(OtelGauge { gauge, labels }))
    }

    fn register_histogram(
        &self,
        key: &Key,
        _metadata: &metrics::Metadata<'_>,
    ) -> metrics::Histogram {
        let name = key.name().to_string();
        let histogram = self.meter.f64_histogram(name).build();
        let labels = Self::get_labels(key);
        metrics::Histogram::from_arc(Arc::new(OtelHistogram { histogram, labels }))
    }
}

/// Initialize the OTEL metrics pipeline and install the global recorder.
///
/// If `config.endpoint` is `None`, metrics export is disabled (no-op recorder).
pub fn init_metrics(config: &crate::config::MetricsConfig) -> Result<Option<SdkMeterProvider>> {
    let Some(endpoint) = config.endpoint.as_deref() else {
        info!("metrics.endpoint not set, metrics export disabled");
        return Ok(None);
    };

    info!("Initializing OTEL metrics export to {}", endpoint);

    // Build custom headers for X-API-Key auth
    let mut headers = HashMap::new();
    if let Some(api_key) = config.api_key.as_ref() {
        if !api_key.is_empty() {
            headers.insert("X-API-Key".to_string(), api_key.clone());
        }
    }

    // Create OTLP HTTP exporter with Delta temporality
    let exporter = MetricExporter::builder()
        .with_http()
        .with_endpoint(endpoint)
        .with_headers(headers)
        .with_timeout(Duration::from_secs(10))
        .with_temporality(Temporality::Delta)
        .build()?;

    // Periodic reader exports every 5 seconds
    let reader = PeriodicReader::builder(exporter)
        .with_interval(Duration::from_secs(5))
        .build();

    let provider = SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(
            Resource::builder()
                .with_attributes(vec![KeyValue::new("service.name", "edge-manager")])
                .build(),
        )
        .build();

    global::set_meter_provider(provider.clone());

    // Install the metrics crate → OTEL bridge recorder
    let static_name: &'static str = "edge-manager";
    let recorder = OtelMetricRecorder::new(static_name);
    if let Err(e) = metrics::set_global_recorder(recorder) {
        tracing::warn!("Failed to set global metrics recorder: {}", e);
    }

    info!("OTEL metrics initialized (export every 5s to {})", endpoint);
    Ok(Some(provider))
}
