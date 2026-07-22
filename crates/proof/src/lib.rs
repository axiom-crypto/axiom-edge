//! Typed proof access for the wire payloads carried in the [`protocol`] crate.
//!
//! The `protocol` crate defines axiom-edge's wire format; proof and segment
//! fields there are opaque `Vec<u8>`. This crate provides:
//!
//! - The typed structures those bytes encode: [`ProofWithPublicValue`],
//!   [`F`], [`SC`], [`Segment`], [`UserPublicValuesProof`].
//! - Encode/decode helpers: [`encode_proof`], [`decode_proof`],
//!   [`encode_segment`], [`decode_segment`], plus the lower-level
//!   [`encode`] / [`decode`] over any serde-compatible value.
//!
//! Under `feature = "mock-provers"` the typed structures are replaced with
//! minimal stubs so test builds don't pull the OpenVM dependency tree.
//!
//! # When to depend on this crate
//!
//! - You're writing a manager, worker, or anything else that constructs
//!   `protocol` payloads from real proofs.
//! - You're verifying or inspecting proofs received from an axiom-edge
//!   deployment.
//!
//! Consumers that only route or store proof bytes (orchestrators, archival
//! services, monitoring) should depend on `protocol` alone.
//!
//! # Decoding example
//!
//! ```ignore
//! use protocol::AppProof;
//!
//! fn inspect(app: &AppProof) -> eyre::Result<()> {
//!     if let Some(bytes) = &app.state.proof {
//!         let typed = proof::decode_proof(bytes)?;
//!         // typed.proof / typed.user_public_values are accessible here.
//!     }
//!     Ok(())
//! }
//! ```
//!
//! [`protocol`]: https://crates.io/

use eyre::{Result, WrapErr};
use serde::{de::DeserializeOwned, Serialize};

// Conditional compilation for proof types based on features.
// Real provers are the default; mock-provers is opt-in for testing.
#[cfg(not(feature = "mock-provers"))]
mod real_types {
    use openvm_stark_backend::proof::Proof;
    use openvm_stark_backend::Val;
    // openvm develop-v2.1.0 removed `system::memory::CHUNK`; the memory merkle
    // digest width is now `VM_DIGEST_WIDTH` (still 8). Alias it to `CHUNK` so
    // the const-generic uses below read the same.
    use sdk_v2::openvm_circuit::arch::instructions::VM_DIGEST_WIDTH as CHUNK;

    /// The field type used for proofs (BabyBear).
    pub type F = Val<sdk_v2::SC>;

    /// The stark config type.
    pub type SC = sdk_v2::SC;

    /// Memory chunk size constant (re-exported for convenience).
    pub const MEMORY_CHUNK: usize = CHUNK;

    /// User public values proof type.
    pub type UserPublicValuesProof =
        sdk_v2::openvm_circuit::system::memory::merkle::public_values::UserPublicValuesProof<
            CHUNK,
            F,
        >;

    /// Segment type used by metered execution.
    pub type Segment = sdk_v2::openvm_circuit::arch::execution_mode::metered::segment_ctx::Segment;

    /// Proof with optional public values.
    /// The proof field uses `openvm_stark_backend::proof::Proof` which is the type
    /// expected by the continuations-v2 aggregation provers.
    #[derive(Clone, serde::Serialize, serde::Deserialize)]
    pub struct ProofWithPublicValue<Field> {
        pub proof: Proof<SC>,
        pub user_public_values: Option<
            sdk_v2::openvm_circuit::system::memory::merkle::public_values::UserPublicValuesProof<
                CHUNK,
                Field,
            >,
        >,
    }

    impl<Field> std::fmt::Debug for ProofWithPublicValue<Field> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ProofWithPublicValue")
                .field("has_proof", &true)
                .field("has_user_public_values", &self.user_public_values.is_some())
                .finish()
        }
    }

    /// Root verifier circuit proof.
    #[cfg(feature = "evm-prove")]
    #[derive(Clone, serde::Serialize, serde::Deserialize)]
    pub struct RootProof(pub Proof<continuations_v2::RootSC>);

    #[cfg(feature = "evm-prove")]
    impl std::fmt::Debug for RootProof {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_tuple("RootProof").field(&"Proof<RootSC>").finish()
        }
    }

    /// SDK EVM proof type.
    #[cfg(feature = "evm-prove")]
    pub type EvmProof = sdk_v2::types::EvmProof;

    /// One digest entry on a deferral merkle authentication path.
    /// `MEMORY_CHUNK == DIGEST_SIZE` for the BabyBear+Poseidon2 config
    /// edge uses (both 8); the SDK's `MerkleTree<F, CHUNK>` and the
    /// verifier's `DeferralMerkleProofs<F>` agree on this length.
    pub type DeferralPathDigest = [F; MEMORY_CHUNK];
}

#[cfg(not(feature = "mock-provers"))]
pub use real_types::*;

// Mock types for testing without real provers.
#[cfg(feature = "mock-provers")]
mod mock_types {
    use serde::{Deserialize, Serialize};

    /// Mock field type for testing.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
    pub struct F(pub u64);

    impl F {
        pub const ZERO: Self = F(0);
        pub const ONE: Self = F(1);
    }

    /// Mock stark config placeholder.
    pub struct SC;

    /// Mock segment type for testing.
    pub type Segment = Vec<u8>;

    /// Mock proof with public values for testing.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ProofWithPublicValue<Field> {
        /// Raw proof bytes (mock).
        pub proof: Vec<u8>,
        /// Mock public values.
        pub public_values: Vec<Field>,
    }

    impl<Field: Default + Clone> Default for ProofWithPublicValue<Field> {
        fn default() -> Self {
            Self {
                proof: vec![0u8; 256],
                public_values: vec![],
            }
        }
    }

    /// Mock root proof bytes.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct RootProof(pub Vec<u8>);

    /// Mock EVM proof bytes.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct EvmProof(pub Vec<u8>);
}

#[cfg(feature = "mock-provers")]
pub use mock_types::*;

/// Bincode-encode a value (proof or segment) for transport on the wire.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    bincode::serialize(value).wrap_err("failed to bincode-encode wire payload")
}

/// Bincode-decode a value (proof or segment) received from the wire.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    bincode::deserialize(bytes).wrap_err("failed to bincode-decode wire payload")
}

/// Encode a `ProofWithPublicValue<F>` for wire transport.
pub fn encode_proof(proof: &ProofWithPublicValue<F>) -> Result<Vec<u8>> {
    encode(proof)
}

/// Decode a wire-form proof into `ProofWithPublicValue<F>`.
pub fn decode_proof(bytes: &[u8]) -> Result<ProofWithPublicValue<F>> {
    decode(bytes)
}

/// Encode a root proof for wire transport.
#[cfg(any(feature = "evm-prove", feature = "mock-provers"))]
pub fn encode_root_proof(proof: &RootProof) -> Result<Vec<u8>> {
    encode(proof)
}

/// Decode a wire-form root proof.
#[cfg(any(feature = "evm-prove", feature = "mock-provers"))]
pub fn decode_root_proof(bytes: &[u8]) -> Result<RootProof> {
    decode(bytes)
}

#[cfg(all(not(feature = "mock-provers"), feature = "evm-prove"))]
#[derive(serde::Serialize, serde::Deserialize)]
struct EvmProofWire {
    version: String,
    app_exe_commit: Vec<u8>,
    app_vm_commit: Vec<u8>,
    user_public_values: Vec<u8>,
    accumulator: Vec<u8>,
    proof: Vec<u8>,
}

#[cfg(all(not(feature = "mock-provers"), feature = "evm-prove"))]
impl From<&EvmProof> for EvmProofWire {
    fn from(proof: &EvmProof) -> Self {
        Self {
            version: proof.version.clone(),
            app_exe_commit: proof.app_commit.app_exe_commit.as_slice().to_vec(),
            app_vm_commit: proof.app_commit.app_vm_commit.as_slice().to_vec(),
            user_public_values: proof.user_public_values.clone(),
            accumulator: proof.proof_data.accumulator.clone(),
            proof: proof.proof_data.proof.clone(),
        }
    }
}

#[cfg(all(not(feature = "mock-provers"), feature = "evm-prove"))]
impl TryFrom<EvmProofWire> for EvmProof {
    type Error = eyre::Report;

    fn try_from(wire: EvmProofWire) -> Result<Self> {
        use continuations_v2::CommitBytes;
        use sdk_v2::types::{AppExecutionCommit, ProofData};

        fn commit_bytes(bytes: Vec<u8>, field: &str) -> Result<CommitBytes> {
            let len = bytes.len();
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| eyre::eyre!("{field} must be 32 bytes, got {len}"))?;
            std::panic::catch_unwind(|| CommitBytes::new(bytes))
                .map_err(|_| eyre::eyre!("{field} is not canonical CommitBytes"))
        }

        Ok(Self {
            version: wire.version,
            app_commit: AppExecutionCommit {
                app_exe_commit: commit_bytes(wire.app_exe_commit, "app_exe_commit")?,
                app_vm_commit: commit_bytes(wire.app_vm_commit, "app_vm_commit")?,
            },
            user_public_values: wire.user_public_values,
            proof_data: ProofData {
                accumulator: wire.accumulator,
                proof: wire.proof,
            },
        })
    }
}

/// Encode an EVM proof for wire transport.
#[cfg(all(not(feature = "mock-provers"), feature = "evm-prove"))]
pub fn encode_evm_proof(proof: &EvmProof) -> Result<Vec<u8>> {
    encode(&EvmProofWire::from(proof))
}

/// Decode a wire-form EVM proof.
#[cfg(all(not(feature = "mock-provers"), feature = "evm-prove"))]
pub fn decode_evm_proof(bytes: &[u8]) -> Result<EvmProof> {
    let wire: EvmProofWire = decode(bytes)?;
    wire.try_into()
}

/// Encode a mock EVM proof for wire transport.
#[cfg(feature = "mock-provers")]
pub fn encode_evm_proof(proof: &EvmProof) -> Result<Vec<u8>> {
    encode(proof)
}

/// Decode a mock wire-form EVM proof.
#[cfg(feature = "mock-provers")]
pub fn decode_evm_proof(bytes: &[u8]) -> Result<EvmProof> {
    decode(bytes)
}

/// Encode a `Segment` for wire transport.
pub fn encode_segment(segment: &Segment) -> Result<Vec<u8>> {
    encode(segment)
}

/// Encode a deferral merkle authentication path (length-prefixed slice
/// of `DIGEST_SIZE` digests) for wire transport.
///
/// Uses the stark-backend's canonical digest codec (the same one
/// `DeferralMerkleProofs::encode` uses on the verifier side
/// `openvm/crates/verify/src/deferral.rs:24-28`), so the bytes the
/// terminal worker ships can be fed straight into the verifier types
/// after decoding on the tail.
#[cfg(not(feature = "mock-provers"))]
pub fn encode_deferral_auth_path(path: &[DeferralPathDigest]) -> Result<Vec<u8>> {
    use openvm_stark_backend::codec::EncodableConfig;
    let mut buf = Vec::new();
    SC::encode_digest_slice(path, &mut buf)
        .map_err(|e| eyre::eyre!("failed to encode deferral auth path: {}", e))?;
    Ok(buf)
}

/// Decode a deferral merkle authentication path produced by
/// `encode_deferral_auth_path`.
#[cfg(not(feature = "mock-provers"))]
pub fn decode_deferral_auth_path(bytes: &[u8]) -> Result<Vec<DeferralPathDigest>> {
    use openvm_stark_backend::codec::DecodableConfig;
    let mut reader = std::io::Cursor::new(bytes);
    SC::decode_digest_vec(&mut reader)
        .map_err(|e| eyre::eyre!("failed to decode deferral auth path: {}", e))
}

/// Mock encoder for the deferral auth path — bincode pass-through over
/// `Vec<Vec<u64>>` so the wire format roundtrips for tests without
/// pulling the OpenVM dependency tree.
#[cfg(feature = "mock-provers")]
pub fn encode_deferral_auth_path(path: &[Vec<u64>]) -> Result<Vec<u8>> {
    encode(&path.to_vec())
}

/// Mock decoder pair for `encode_deferral_auth_path`.
#[cfg(feature = "mock-provers")]
pub fn decode_deferral_auth_path(bytes: &[u8]) -> Result<Vec<Vec<u64>>> {
    decode(bytes)
}

/// Decode a wire-form segment into `Segment`.
pub fn decode_segment(bytes: &[u8]) -> Result<Segment> {
    decode(bytes)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "mock-provers")]
    use super::{decode_evm_proof, decode_root_proof, encode_evm_proof, encode_root_proof};
    #[cfg(feature = "mock-provers")]
    use super::{EvmProof, RootProof};

    #[cfg(feature = "mock-provers")]
    #[test]
    fn mock_root_and_evm_proofs_roundtrip() {
        let root = RootProof(vec![1, 2, 3, 4]);
        let encoded_root = encode_root_proof(&root).unwrap();
        let decoded_root = decode_root_proof(&encoded_root).unwrap();
        assert_eq!(decoded_root, root);

        let evm = EvmProof(vec![5, 6, 7, 8]);
        let encoded_evm = encode_evm_proof(&evm).unwrap();
        let decoded_evm = decode_evm_proof(&encoded_evm).unwrap();
        assert_eq!(decoded_evm, evm);
    }

    #[cfg(all(not(feature = "mock-provers"), feature = "evm-prove"))]
    #[test]
    fn evm_proof_roundtrip_real_type() {
        use super::{decode_evm_proof, encode_evm_proof, EvmProof};
        use continuations_v2::CommitBytes;
        use sdk_v2::types::{AppExecutionCommit, ProofData};

        let proof = EvmProof {
            version: "v2.0".to_string(),
            app_commit: AppExecutionCommit {
                app_exe_commit: CommitBytes::new([0u8; 32]),
                app_vm_commit: CommitBytes::new([0u8; 32]),
            },
            user_public_values: vec![1, 2, 3],
            proof_data: ProofData {
                accumulator: vec![4, 5, 6],
                proof: vec![7, 8, 9],
            },
        };

        let encoded = encode_evm_proof(&proof).unwrap();
        let decoded = decode_evm_proof(&encoded).unwrap();

        assert_eq!(decoded.version, proof.version);
        assert_eq!(
            decoded.app_commit.app_exe_commit.as_slice(),
            proof.app_commit.app_exe_commit.as_slice()
        );
        assert_eq!(
            decoded.app_commit.app_vm_commit.as_slice(),
            proof.app_commit.app_vm_commit.as_slice()
        );
        assert_eq!(decoded.user_public_values, proof.user_public_values);
        assert_eq!(decoded.proof_data.accumulator, proof.proof_data.accumulator);
        assert_eq!(decoded.proof_data.proof, proof.proof_data.proof);
    }

    #[cfg(all(not(feature = "mock-provers"), feature = "evm-prove"))]
    #[test]
    fn root_proof_helpers_are_available_in_evm_mode() {
        use super::{decode_root_proof, encode_root_proof, RootProof};

        fn assert_helpers(
            _encode: fn(&RootProof) -> eyre::Result<Vec<u8>>,
            _decode: fn(&[u8]) -> eyre::Result<RootProof>,
        ) {
        }

        assert_helpers(encode_root_proof, decode_root_proof);
    }

    /// Decoding an `EvmProof` whose `app_exe_commit` or `app_vm_commit` is not
    /// a valid `CommitBytes` (wrong length, or non-canonical 32B) must surface
    /// a clear error instead of panicking inside `CommitBytes::new`. Drives
    /// the `commit_bytes` helper in `lib.rs::EvmProofWire::try_from` (~line
    /// 229).
    #[cfg(all(not(feature = "mock-provers"), feature = "evm-prove"))]
    #[test]
    fn evm_proof_decode_rejects_wrong_length_commit() {
        use super::{decode_evm_proof, EvmProofWire};

        // 31 bytes, one short of the required 32.
        let wire = EvmProofWire {
            version: "v2.0".to_string(),
            app_exe_commit: vec![0u8; 31],
            app_vm_commit: vec![0u8; 32],
            user_public_values: vec![],
            accumulator: vec![],
            proof: vec![],
        };
        let bytes = bincode::serialize(&wire).expect("bincode encodes");
        let err = decode_evm_proof(&bytes).expect_err("wrong-length commit must error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("app_exe_commit") && msg.contains("32 bytes") && msg.contains("31"),
            "expected length-mismatch diagnostic for app_exe_commit, got {msg}",
        );

        // Same shape, but exe_commit is fine and vm_commit is the bad one —
        // confirms the field name in the error reflects the actually-failing field.
        let wire = EvmProofWire {
            version: "v2.0".to_string(),
            app_exe_commit: vec![0u8; 32],
            app_vm_commit: vec![0u8; 1],
            user_public_values: vec![],
            accumulator: vec![],
            proof: vec![],
        };
        let bytes = bincode::serialize(&wire).expect("bincode encodes");
        let err = decode_evm_proof(&bytes).expect_err("wrong-length commit must error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("app_vm_commit") && msg.contains("32 bytes"),
            "expected length-mismatch diagnostic for app_vm_commit, got {msg}",
        );
    }

    /// Negative test for the non-canonical (panic-from-`CommitBytes::new`)
    /// branch of the `commit_bytes` helper. `CommitBytes` is the BN254
    /// scalar wrapper used to commit to app code + VM; non-canonical
    /// representations (above the field modulus) panic on construction.
    /// We catch that panic with `catch_unwind` and surface a typed error.
    #[cfg(all(not(feature = "mock-provers"), feature = "evm-prove"))]
    #[test]
    fn evm_proof_decode_rejects_noncanonical_commit() {
        use super::{decode_evm_proof, EvmProofWire};

        // All-0xFF is above the BN254 scalar modulus → non-canonical.
        // CommitBytes::new(...) panics; the decoder catch_unwinds and
        // returns a typed error.
        let wire = EvmProofWire {
            version: "v2.0".to_string(),
            app_exe_commit: vec![0xFFu8; 32],
            app_vm_commit: vec![0u8; 32],
            user_public_values: vec![],
            accumulator: vec![],
            proof: vec![],
        };
        let bytes = bincode::serialize(&wire).expect("bincode encodes");
        let err = decode_evm_proof(&bytes).expect_err("non-canonical commit bytes must error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("app_exe_commit") && msg.contains("canonical"),
            "expected non-canonical diagnostic for app_exe_commit, got {msg}",
        );
    }
}
