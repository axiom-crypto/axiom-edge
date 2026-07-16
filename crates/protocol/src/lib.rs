//! Wire protocol types and status enums for the Axiom Edge manager ↔ worker
//! protocol. This is the public API surface — external integrators depend on
//! this crate to talk to an Axiom Edge deployment.
//!
//! # What's in this crate
//!
//! - Request types: [`StartProofRequest`], [`RegisterWorkerRequest`],
//!   [`ShardedAppProveRequest`], [`LeafProveRequest`], [`InternalProveRequest`],
//!   [`GeneralProveRequest`].
//! - Result types: [`ProofResult`], [`AppProof`], [`LeafProof`],
//!   [`InternalProof`], [`ExecuteE2Result`], [`ErrorResult`],
//!   [`ResultPayload`].
//! - Shared types: [`ProofContext`], [`MessageEnvelope`], [`Step`].
//! - [`PROTOCOL_VERSION`] tagging the wire format (informational; see
//!   *Transports and compatibility* below).
//!
//! Dependencies are deliberately small: serde, serde_json, uuid. This crate
//! does **not** pull in OpenVM or the rest of the prover stack — a
//! non-proving consumer (orchestrator, monitor, archival service) can talk
//! to the protocol with a fast compile.
//!
//! # Proof and segment payloads on the wire
//!
//! Fields that carry proof or segment data are typed [`ProofBytes`] /
//! [`SegmentBytes`] (both `Vec<u8>`). The bytes are bincode-encoded
//! `proof::ProofWithPublicValue<F>` / `proof::Segment` values produced by
//! the [`proof`] crate's `encode_proof` / `encode_segment` helpers.
//!
//! Most consumers can treat these bytes as opaque — submit a proof, poll
//! status, forward or archive the resulting bytes — and never depend on
//! `proof` at all. Consumers that need to inspect proof contents (verify,
//! extract public values, re-aggregate) add `proof` alongside `protocol`
//! and call `proof::decode_proof` / `proof::decode_segment`.
//!
//! ```text
//! [dependencies]
//! protocol = { ... }
//! proof    = { ... }   # only if you need typed access
//! ```
//!
//! ```ignore
//! use protocol::{AppProof, ProofResult};
//!
//! fn handle_app_proof(app: &AppProof) -> eyre::Result<()> {
//!     if let Some(bytes) = &app.state.proof {
//!         // Typed access — requires the `proof` crate.
//!         let typed = proof::decode_proof(bytes)?;
//!         // typed.proof: openvm_stark_backend::proof::Proof<SC>
//!         // typed.user_public_values: Option<UserPublicValuesProof<...>>
//!     }
//!     Ok(())
//! }
//! ```
//!
//! Producers do the reverse: build a typed `proof::ProofWithPublicValue<F>`,
//! call `proof::encode_proof(&typed)?`, and place the resulting bytes in the
//! protocol type's `proof` field.
//!
//! # Transports and compatibility
//!
//! Two serialization formats are in play, with very different evolution
//! properties:
//!
//! - **JSON** — the caller-facing and control endpoints: `/start_proof`
//!   ([`StartProofRequest`]), `/register_worker` ([`RegisterWorkerRequest`]),
//!   `/sharded_app_prove` ([`ShardedAppProveRequest`]), and all query
//!   endpoints. JSON is self-describing, so `#[serde(default)]` fields can be
//!   added and payloads from older builds keep deserializing.
//! - **bincode** — the high-volume internal paths: worker results
//!   (`/proof_result`, [`ResultPayload`]) and recursion work dispatch
//!   (`/recursion_prove`, `MessageEnvelope<GeneralProveRequest>`). bincode is
//!   positional and **not** self-describing: `#[serde(default)]` never fires
//!   (a missing trailing field is a decode error, not a default), adding a
//!   field changes the byte stream even when it is `None`, and inserting an
//!   enum variant renumbers every later variant's tag.
//!
//! Consequently, the compatibility unit is the **build**: deploy the manager
//! and all workers from the same commit/tag. `#[serde(default)]` attributes
//! on bincode-transported types make in-memory construction and JSON-based
//! tooling ergonomic — they do not provide cross-version wire tolerance.
//!
//! [`proof`]: https://crates.io/

pub mod types;

pub use types::*;

/// Wire protocol version. Bumped on any breaking format change.
///
/// Currently **informational only** — nothing checks it at registration or
/// on either transport. The compatibility unit is the build: deploy the
/// manager and all workers from the same commit/tag (see the crate-level
/// *Transports and compatibility* notes).
pub const PROTOCOL_VERSION: u32 = 1;

/// Current Unix timestamp in milliseconds.
pub fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
