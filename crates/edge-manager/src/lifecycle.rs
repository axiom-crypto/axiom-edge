//! Generic proof-lifecycle webhook.
//!
//! When `[lifecycle].webhook_url` is set, the manager POSTs a small JSON
//! event on each proof transition — `queued`, `proving`, `completed`. The
//! payload is destination-agnostic; external integrations (e.g. a reporter
//! sidecar) consume these and translate to their own APIs. The
//! manager knows nothing about any specific downstream.
//!
//! Delivery is best-effort: failures are retried a few times then logged and
//! dropped. The proving pipeline never blocks on the webhook.
//!
//! The `completed` event carries the deployment-defined `labels` plus proving
//! time + cycle count, and the on-disk path to the persisted final proof
//! (`proof_path`), so a co-located consumer can read the proof bytes without
//! the manager inlining a multi-MB payload. `proof_path` is only present when
//! `[proof].persist_final_proofs_dir` is configured.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use eyre::{eyre, Result};
use serde_json::{json, Value};
use tracing::{info, warn};

use crate::config::LifecycleConfig;

const LIFECYCLE_MAX_ATTEMPTS: u32 = 3;
const LIFECYCLE_RETRY_BACKOFF: Duration = Duration::from_millis(500);

pub struct LifecycleReporter {
    webhook_url: String,
    timeout: Duration,
    client: reqwest::Client,
}

impl LifecycleReporter {
    /// Build a reporter from config. Returns `None` when no webhook URL is
    /// configured (lifecycle reporting disabled).
    pub fn from_config(config: &LifecycleConfig) -> Option<Self> {
        let url = config.webhook_url.as_ref()?.trim().to_string();
        if url.is_empty() {
            return None;
        }
        Some(Self {
            webhook_url: url,
            timeout: Duration::from_millis(config.timeout_ms),
            client: reqwest::Client::new(),
        })
    }

    /// Fire-and-forget a `queued` event.
    pub fn report_queued(&self, proof_uuid: &str, labels: &BTreeMap<String, String>) {
        self.spawn_event(json!({
            "event": "queued",
            "proof_uuid": proof_uuid,
            "labels": labels,
        }));
    }

    /// Fire-and-forget a `proving` event.
    pub fn report_proving(&self, proof_uuid: &str, labels: &BTreeMap<String, String>) {
        self.spawn_event(json!({
            "event": "proving",
            "proof_uuid": proof_uuid,
            "labels": labels,
        }));
    }

    /// Fire-and-forget a `completed` event. `proof_path` is the on-disk path
    /// to the persisted final proof, if persistence is enabled.
    pub fn report_completed(
        &self,
        proof_uuid: &str,
        labels: &BTreeMap<String, String>,
        proving_time_ms: Option<u64>,
        proving_cycles: Option<u64>,
        proof_path: Option<&Path>,
    ) {
        self.spawn_event(json!({
            "event": "completed",
            "proof_uuid": proof_uuid,
            "labels": labels,
            "proving_time_ms": proving_time_ms,
            "proving_cycles": proving_cycles,
            "proof_path": proof_path.map(|p| p.to_string_lossy().into_owned()),
        }));
    }

    /// Spawn a background task that POSTs `payload` with bounded retries.
    fn spawn_event(&self, payload: Value) {
        let client = self.client.clone();
        let url = self.webhook_url.clone();
        let timeout = self.timeout;
        let event = payload
            .get("event")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let proof_uuid = payload
            .get("proof_uuid")
            .and_then(Value::as_str)
            .unwrap_or("?")
            .to_string();

        tokio::spawn(async move {
            match post_with_retry(&client, &url, timeout, &payload).await {
                Ok(()) => info!(
                    "Posted lifecycle event '{}' for proof {}",
                    event, proof_uuid
                ),
                Err(e) => warn!(
                    "Failed to post lifecycle event '{}' for proof {}: {}",
                    event, proof_uuid, e
                ),
            }
        });
    }
}

async fn post_with_retry(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
    payload: &Value,
) -> Result<()> {
    let mut last_err: Option<eyre::Report> = None;

    for attempt in 1..=LIFECYCLE_MAX_ATTEMPTS {
        match client.post(url).timeout(timeout).json(payload).send().await {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    return Ok(());
                }
                let body = response.text().await.unwrap_or_default();
                let err = eyre!("HTTP {} from {}: {}", status, url, body);
                // Retry 5xx / 429; 4xx won't recover.
                let retriable = status.is_server_error() || status.as_u16() == 429;
                if !retriable || attempt == LIFECYCLE_MAX_ATTEMPTS {
                    return Err(err);
                }
                last_err = Some(err);
            }
            Err(e) => {
                let err = eyre::Report::new(e);
                if attempt == LIFECYCLE_MAX_ATTEMPTS {
                    return Err(err);
                }
                last_err = Some(err);
            }
        }
        tokio::time::sleep(LIFECYCLE_RETRY_BACKOFF * attempt).await;
    }

    Err(last_err.unwrap_or_else(|| eyre!("lifecycle webhook failed without captured error")))
}
