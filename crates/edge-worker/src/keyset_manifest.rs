//! The keyset manifest a keygen host emits to report what it derived.
//!
//! After a host loads (or generates) the deployment keyset, it can derive the
//! family commits that a control plane needs *before* any proof is produced:
//! per-program `app_exe_commit`s, the shared `app_vm_commit`, the deferral
//! `def_hook_commit` and `deferral_cached_commit`, a `keyset_epoch` that hashes
//! over all of them, and whether the deployment is `evm_ready`. Nothing else in
//! axiom-edge exposes these — today they appear only inside a produced EVM proof
//! (`crates/proof/src/lib.rs`), which is far too late for a verifier deploy.
//!
//! This module is the pure, prover-free half: the serializable shape, the
//! commit encoding, and the epoch hash. The `emit_manifest` binary is the thin
//! host-side driver that reconstructs the SDK from the on-disk keyset, derives
//! the raw commit digests, and calls [`CommitInputs::into_manifest`] here. The
//! split keeps every byte-level decision (field order, hex encoding, epoch
//! algorithm) unit-testable without a multi-minute keygen.
//!
//! # Cross-repo contract — the encoding is load-bearing
//!
//! The shape and encoding intentionally match lighter's `EdgeManifest`
//! (`~/lighter-evm-backend/crates/regen-agg-commits/src/manifest.rs`) field for
//! field, so this file is a drop-in for anything that reads that manifest. The
//! one decision that must not drift: **commits are the raw little-endian
//! limb-digest hex** ([`digest_to_bytes`] — each BabyBear limb as a
//! little-endian `u32`). The L1-verifier deploy step consumes this file and
//! re-composes the canonical big-endian `CommitBytes` itself
//! (`le_limbs_to_be` in lighter's `scripts/ci-devnet.sh`). Emitting big-endian
//! here would pin the verifier contract to the wrong commit — a silent failure
//! that only surfaces as a rejected proof at the end of a long CI job.
//!
//! # Reproducibility
//!
//! Every field is a deterministic function of the on-disk keyset bytes (the
//! `deferral/cached_pk` and the `program.vmexe` files) computed with pure field
//! arithmetic and SHA-256. Two hosts that load the *same* keyset bundle derive
//! byte-identical commits and therefore an identical [`KeysetManifest::keyset_epoch`].

use serde::{Deserialize, Serialize};

/// The manifest schema version. Matches lighter's `MANIFEST_SCHEMA_VERSION`;
/// bump in lockstep on any shape change.
pub const MANIFEST_SCHEMA_VERSION: u32 = 3;

/// The conventional filename for the emitted manifest, written next to the
/// artifacts. Deliberately *not* `manifest.json`: a keyset bundle produced by
/// lighter's exporter already carries its own private `manifest.json`, and this
/// host-emitted file must never collide with or clobber it.
pub const KEYSET_MANIFEST_FILE_NAME: &str = "edge-manifest.json";

/// Explicit program role — nothing reading the manifest should have to infer
/// which program is the terminal one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramRole {
    /// A program that can appear as a deferral child of an aggregation program;
    /// its app-VM vk is exported at `vk/{name}.app_vm_vk.bin` and served by the
    /// manager at `GET /vk/{name}`.
    Child,
    /// The terminal (final-agg) program — no vk blob. A planned L1-verifier
    /// deploy reads this program's `app_exe_commit` (plus the shared
    /// `app_vm_commit`) to pin the verifier contract.
    Top,
}

/// One program in the deployment loadout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestProgram {
    /// Loadout name; also the `programs/{name}/{version}/` path component and
    /// (for children) the `vk/{name}.app_vm_vk.bin` filename.
    pub name: String,
    pub version: u32,
    /// This program's exe commit, as the raw little-endian limb-digest hex
    /// ([`digest_to_bytes`] then [`hex0x`]).
    pub app_exe_commit: String,
    pub role: ProgramRole,
}

/// KZG SRS sizes for an EVM-ready keyset. Present iff `evm_ready`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Halo2Meta {
    pub verifier_k: usize,
    pub wrapper_k: usize,
}

/// The emitted `edge-manifest.json`, typed. Field order here is the serialized
/// field order — kept identical to lighter's `EdgeManifest` so the two producers
/// agree byte-for-byte.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeysetManifest {
    /// [`MANIFEST_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The loadout, in the canonical order the keyset epoch hashes over
    /// (declaration order of `EDGE_PROGRAMS`).
    pub programs: Vec<ManifestProgram>,
    /// The shared app-VM commit for the whole program family, as the raw
    /// little-endian limb-digest hex.
    pub app_vm_commit: String,
    /// The deferral path's `def_hook_commit`, raw little-endian limb-digest hex.
    pub def_hook_commit: String,
    /// The family-wide deferral cached commit, raw little-endian limb-digest
    /// hex. Recorded for bookkeeping only — the Edge client independently
    /// re-derives it from the vk it downloads.
    pub deferral_cached_commit: String,
    /// SHA-256 over every commit above (see [`compute_keyset_epoch`]) — the
    /// keyset's identity for operator bookkeeping and rollout comparison.
    pub keyset_epoch: String,
    /// Whether root + halo2 material is present, i.e. the deployment can serve
    /// `proof_type=evm`.
    pub evm_ready: bool,
    /// Present iff `evm_ready`: the KZG SRS sizes the deployment host must
    /// provision (`kzg_bn254_<k>.srs`) alongside `halo2/halo2_pk`.
    pub halo2: Option<Halo2Meta>,
}

/// One program's raw (pre-hex) commit inputs.
#[derive(Debug, Clone)]
pub struct RawProgram {
    pub name: String,
    pub version: u32,
    /// Raw little-endian limb-digest bytes ([`digest_to_bytes`]).
    pub app_exe_commit: [u8; 32],
    pub role: ProgramRole,
}

/// The raw commit digests a host derives from its keyset, before hex encoding
/// and epoch hashing. [`Self::into_manifest`] is the single place that turns
/// these into the serialized [`KeysetManifest`], so the epoch is always
/// computed the one canonical way.
#[derive(Debug, Clone)]
pub struct CommitInputs {
    pub programs: Vec<RawProgram>,
    pub app_vm_commit: [u8; 32],
    pub def_hook_commit: [u8; 32],
    pub deferral_cached_commit: [u8; 32],
    pub evm_ready: bool,
    pub halo2: Option<Halo2Meta>,
}

impl CommitInputs {
    /// Assemble the serialized manifest, computing `keyset_epoch` from the raw
    /// commit bytes. The epoch hashes over the same bytes the hex strings
    /// encode, so it is independent of the hex formatting.
    pub fn into_manifest(self) -> KeysetManifest {
        let epoch = compute_keyset_epoch(
            self.programs.iter().map(|p| &p.app_exe_commit),
            &self.app_vm_commit,
            &self.def_hook_commit,
            &self.deferral_cached_commit,
        );
        KeysetManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            programs: self
                .programs
                .into_iter()
                .map(|p| ManifestProgram {
                    name: p.name,
                    version: p.version,
                    app_exe_commit: hex0x(&p.app_exe_commit),
                    role: p.role,
                })
                .collect(),
            app_vm_commit: hex0x(&self.app_vm_commit),
            def_hook_commit: hex0x(&self.def_hook_commit),
            deferral_cached_commit: hex0x(&self.deferral_cached_commit),
            keyset_epoch: hex0x(&epoch),
            evm_ready: self.evm_ready,
            halo2: self.halo2,
        }
    }
}

impl KeysetManifest {
    /// Serialize in the canonical on-disk form (pretty + trailing newline).
    pub fn to_json(&self) -> serde_json::Result<String> {
        Ok(serde_json::to_string_pretty(self)? + "\n")
    }

    /// Internal-consistency checks mirroring lighter's `EdgeManifest::validate`:
    /// a non-empty loadout, exactly one `role = top` program, and
    /// `evm_ready ↔ halo2` agreement.
    pub fn validate(&self) -> Result<(), String> {
        if self.programs.is_empty() {
            return Err("manifest has no programs".to_string());
        }
        let tops = self
            .programs
            .iter()
            .filter(|p| p.role == ProgramRole::Top)
            .count();
        if tops != 1 {
            return Err(format!(
                "manifest must have exactly one role=top program, got {tops}"
            ));
        }
        if self.evm_ready != self.halo2.is_some() {
            return Err(format!(
                "evm_ready = {} but halo2 meta is {}",
                self.evm_ready,
                if self.halo2.is_some() {
                    "present"
                } else {
                    "absent"
                },
            ));
        }
        Ok(())
    }
}

/// SHA-256 over every program's `app_exe_commit` (in loadout order), then
/// `app_vm_commit`, `def_hook_commit`, and `deferral_cached_commit` — the raw
/// 32-byte little-endian limb bytes of each, concatenated. Identical to
/// lighter's `EdgeManifest::compute_keyset_epoch`.
pub fn compute_keyset_epoch<'a>(
    program_exe_commits: impl Iterator<Item = &'a [u8; 32]>,
    app_vm_commit: &[u8; 32],
    def_hook_commit: &[u8; 32],
    deferral_cached_commit: &[u8; 32],
) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    for commit in program_exe_commits {
        h.update(commit);
    }
    h.update(app_vm_commit);
    h.update(def_hook_commit);
    h.update(deferral_cached_commit);
    h.finalize().into()
}

/// `0x`-prefixed lowercase hex. Matches lighter's `hex0x`.
pub fn hex0x(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        write!(s, "{b:02x}").expect("writing to a String cannot fail");
    }
    s
}

/// Encode a digest into 32 bytes as the deferral framework's raw layout: each
/// of the 8 BabyBear limbs written as a little-endian `u32`. Byte-for-byte
/// identical to lighter's `lighter_agg_sdk::digest_to_bytes` and to what
/// `verify_stark_unchecked` returns. **This is the load-bearing encoding** the
/// L1-verifier consumer re-composes to big-endian; do not change it.
pub fn digest_to_bytes(digest: openvm_stark_sdk::config::baby_bear_poseidon2::Digest) -> [u8; 32] {
    use openvm_stark_backend::p3_field::PrimeField32;
    let mut out = [0u8; 32];
    for (i, v) in digest.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&v.as_canonical_u32().to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lighter `EdgeManifest` fixture, copied verbatim. It is the
    /// byte-for-byte target: our serialization and epoch must reproduce it, so
    /// any drift from lighter's producer shape shows up here.
    const FIXTURE: &str = include_str!("fixtures/edge-manifest.json");

    fn decode32(hex: &str) -> [u8; 32] {
        let raw = hex.strip_prefix("0x").expect("0x prefix");
        let bytes = hex::decode(raw).expect("valid hex");
        bytes.try_into().expect("32 bytes")
    }

    fn fixture() -> KeysetManifest {
        serde_json::from_str(FIXTURE).expect("fixture parses")
    }

    /// Parse → re-serialize reproduces the fixture bytes exactly. This pins the
    /// field order, the `snake_case` role encoding, the 2-space pretty
    /// indentation, and the trailing newline — i.e. that our shape is a
    /// byte-for-byte match for lighter's `EdgeManifest`.
    #[test]
    fn fixture_round_trips_byte_identically() {
        let manifest = fixture();
        assert_eq!(manifest.to_json().expect("serializes"), FIXTURE);
    }

    /// Assembling from the fixture's raw commit bytes reproduces the fixture's
    /// `keyset_epoch` and the entire fixture byte stream. This is the core
    /// cross-check: our `CommitInputs::into_manifest` + `compute_keyset_epoch`
    /// exactly reproduce lighter's producer for a real, pinned keyset.
    #[test]
    fn assembling_from_raw_commits_reproduces_the_fixture() {
        let f = fixture();
        let inputs = CommitInputs {
            programs: f
                .programs
                .iter()
                .map(|p| RawProgram {
                    name: p.name.clone(),
                    version: p.version,
                    app_exe_commit: decode32(&p.app_exe_commit),
                    role: p.role,
                })
                .collect(),
            app_vm_commit: decode32(&f.app_vm_commit),
            def_hook_commit: decode32(&f.def_hook_commit),
            deferral_cached_commit: decode32(&f.deferral_cached_commit),
            evm_ready: f.evm_ready,
            halo2: f.halo2,
        };
        let assembled = inputs.into_manifest();
        assert_eq!(
            assembled.keyset_epoch, f.keyset_epoch,
            "recomputed epoch must match the fixture's recorded epoch",
        );
        assert_eq!(
            assembled.to_json().expect("serializes"),
            FIXTURE,
            "assembled manifest must be byte-identical to the fixture",
        );
    }

    /// The epoch is a pure function of the commit bytes: reordering programs, or
    /// changing any commit, changes the epoch; the identical inputs reproduce it.
    #[test]
    fn keyset_epoch_is_deterministic_and_order_sensitive() {
        let f = fixture();
        let exe: Vec<[u8; 32]> = f
            .programs
            .iter()
            .map(|p| decode32(&p.app_exe_commit))
            .collect();
        let app_vm = decode32(&f.app_vm_commit);
        let def_hook = decode32(&f.def_hook_commit);
        let deferral = decode32(&f.deferral_cached_commit);

        let epoch_a = compute_keyset_epoch(exe.iter(), &app_vm, &def_hook, &deferral);
        let epoch_b = compute_keyset_epoch(exe.iter(), &app_vm, &def_hook, &deferral);
        assert_eq!(epoch_a, epoch_b, "same inputs → same epoch");
        assert_eq!(hex0x(&epoch_a), f.keyset_epoch);

        // Swapping two programs changes the epoch (order is part of the identity).
        let mut swapped = exe.clone();
        swapped.swap(0, 2);
        let epoch_swapped = compute_keyset_epoch(swapped.iter(), &app_vm, &def_hook, &deferral);
        assert_ne!(
            epoch_a, epoch_swapped,
            "program order must affect the epoch"
        );
    }

    #[test]
    fn validate_accepts_the_fixture() {
        fixture().validate().expect("fixture validates");
    }

    #[test]
    fn validate_rejects_zero_or_two_top_programs() {
        let mut m = fixture();
        m.programs[2].role = ProgramRole::Child; // now zero tops
        assert!(m.validate().unwrap_err().contains("exactly one role=top"));

        let mut m = fixture();
        m.programs[0].role = ProgramRole::Top; // now two tops
        assert!(m.validate().unwrap_err().contains("exactly one role=top"));
    }

    #[test]
    fn validate_rejects_evm_ready_halo2_disagreement() {
        let mut m = fixture();
        m.halo2 = None; // evm_ready still true
        assert!(m.validate().unwrap_err().contains("evm_ready"));
    }

    #[test]
    fn hex0x_is_lowercase_0x_prefixed() {
        assert_eq!(hex0x(&[0x00, 0xab, 0xff]), "0x00abff");
        assert_eq!(hex0x(&[0u8; 0]), "0x");
    }
}
