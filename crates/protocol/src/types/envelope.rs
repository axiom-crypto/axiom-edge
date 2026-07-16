//! Message envelope for HTTP communication.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::current_timestamp;

/// Message envelope with metadata (timestamp and message_id).
/// Used for idempotent message delivery.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MessageEnvelope<T> {
    pub timestamp: u64,
    pub message_id: String,
    pub message: T,
}

impl<T> MessageEnvelope<T> {
    /// Create a new envelope with auto-generated metadata.
    pub fn with_metadata(message: T) -> Self {
        Self {
            timestamp: current_timestamp(),
            message_id: Uuid::new_v4().to_string(),
            message,
        }
    }

    /// Create an envelope with a custom message_id (useful for testing).
    pub fn new(message: T, message_id: &str) -> Self {
        Self {
            timestamp: current_timestamp(),
            message_id: message_id.to_string(),
            message,
        }
    }
}

impl<T> From<T> for MessageEnvelope<T> {
    fn from(message: T) -> Self {
        Self::with_metadata(message)
    }
}
