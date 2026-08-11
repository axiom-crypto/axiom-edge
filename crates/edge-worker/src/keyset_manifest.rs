//! The keyset manifest a keygen host emits: the deployment loadout roster plus
//! a single `keyset_epoch` drift value.
//!
//! # What this emits, and what it deliberately does not
//!
//! After a host loads (or generates) the deployment keyset, almost everything a
//! consumer needs is *already an openvm type and already served*: `GET /vk/{name}`
//! returns a [`VmStarkVerifyingKey`] whose [`VerificationBaseline`] carries, per
//! child program, `app_exe_commit`, `expected_def_hook_commit`, the four
//! `*_vk_commit`s, `memory_dimensions`, and `num_user_pvs`. The shared
//! `app_vm_commit` is *derivable* from that baseline (it is
//! `poseidon2_hash_slice` over the `app_vk_commit` / `leaf_vk_commit` /
//! `internal_for_leaf_vk_commit` components — see the crate `openvm-sdk`
//! `AggProver::vm_or_hook_commit`), so nothing needs to re-emit it either.
//!
//! Two things have no openvm type and are served nowhere, so this manifest emits
//! exactly them:
//!
//! 1. **The loadout roster** — which programs are deployed together, their
//!    versions, and which one is the terminal `top`. This is a deployment
//!    concept; openvm has no type for it. Each entry reuses axiom-edge's own
//!    [`ProgramRef`] for `(name, version)`.
//! 2. **`keyset_epoch`** — a single-value identity for the whole keyset, for
//!    cross-cluster drift checks (milestone M5). Defined in axiom-edge's own
//!    terms (see [`compute_keyset_epoch`]); it is not lighter's algorithm and
//!    nothing requires the two to agree.
//!
//! Each roster entry also carries its `app_exe_commit`. For a `child` program
//! this value is redundant with the served vk, but for the `top` program it is
//! carried *nowhere else*: the exporter writes a `vk/{name}.app_vm_vk.bin` blob
//! only for `child` programs, so `GET /vk/{top}` is a 404 and the top's
//! `app_exe_commit` — which an L1-verifier deploy must pin alongside the shared
//! `app_vm_commit` — has no other source. Keeping it on every entry (rather than
//! only the top) makes the roster self-describing and makes `keyset_epoch` a
//! pure function of the emitted file, recomputable without any vk download.
//!
//! # Encoding
//!
//! Every commit is emitted as [`continuations_v2::CommitBytes`] via that type's
//! own serialization: the **canonical** big-endian 32-byte form an L1 verifier
//! pins. This is the form `EvmProof.app_commit` and `AppExecutionCommit` use.
//! There is intentionally no little-endian limb form anywhere — emitting
//! canonical bytes removes the `le_limbs_to_be` re-composition (and its silent
//! wrong-endianness failure mode) from every consumer.
//!
//! # Reproducibility
//!
//! `app_exe_commit` is a pure function of a program's `program.vmexe` (a hash of
//! the program commit, initial memory root, and initial pc). Two hosts that load
//! the *same* keyset bundle therefore derive byte-identical roster commits and an
//! identical [`KeysetManifest::keyset_epoch`].
//!
//! [`VmStarkVerifyingKey`]: verify_stark::vk::VmStarkVerifyingKey
//! [`VerificationBaseline`]: verify_stark::vk::VerificationBaseline

use std::fmt;

use continuations_v2::CommitBytes;
use protocol::ProgramRef;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The conventional filename for the emitted manifest, written next to the
/// artifacts. Deliberately *not* `manifest.json`: a keyset bundle produced by
/// lighter's exporter carries its own private `manifest.json` with a different
/// (larger) shape, and this host-emitted file must never collide with it.
pub const KEYSET_MANIFEST_FILE_NAME: &str = "keyset-manifest.json";

/// Domain-separation tag folded into every [`compute_keyset_epoch`] hash. Names
/// the algorithm as axiom-edge's own (v1) so a future shape change is
/// distinguishable and can never collide with another producer's hash.
pub const KEYSET_EPOCH_DOMAIN: &[u8] = b"axiom-edge/keyset-epoch/v1";

/// Explicit program role — nothing reading the manifest should have to infer
/// which program is the terminal one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramRole {
    /// A program that appears as a deferral child of an aggregation program; its
    /// app-VM vk is exported at `vk/{name}.app_vm_vk.bin` and served by the
    /// manager at `GET /vk/{name}`.
    Child,
    /// The terminal (final-agg) program — no vk blob, so `GET /vk/{name}` 404s.
    /// An L1-verifier deploy reads this program's `app_exe_commit` (plus the
    /// shared, derivable `app_vm_commit`) to pin the verifier contract.
    Top,
}

impl ProgramRole {
    /// Stable one-byte tag folded into the keyset epoch. Distinct from the
    /// `serde` rename so the on-disk JSON spelling and the hash tag can evolve
    /// independently.
    fn epoch_tag(self) -> u8 {
        match self {
            ProgramRole::Child => 0,
            ProgramRole::Top => 1,
        }
    }
}

/// One program in the deployment loadout: its `(name, version)` identity (reused
/// from axiom-edge's [`ProgramRef`]), its role, and its exe commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestProgram {
    /// Loadout identity — `name` is also the `programs/{name}/{version}/` path
    /// component and (for children) the `vk/{name}.app_vm_vk.bin` filename.
    /// Flattened so the JSON carries `name` and `version` at the entry's top
    /// level.
    #[serde(flatten)]
    pub program: ProgramRef,
    pub role: ProgramRole,
    /// This program's app-exe commit, as canonical big-endian [`CommitBytes`].
    /// The only source for the `top` program's value (it has no served vk).
    pub app_exe_commit: CommitBytes,
}

/// The emitted `keyset-manifest.json`, typed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeysetManifest {
    /// The loadout, in the order the epoch hashes over (declaration order of
    /// `EDGE_PROGRAMS`).
    pub programs: Vec<ManifestProgram>,
    /// A single-value identity for the whole keyset (see
    /// [`compute_keyset_epoch`]) — used for cross-cluster drift checks.
    pub keyset_epoch: KeysetEpoch,
}

impl KeysetManifest {
    /// Assemble a manifest from an assembled roster, computing its
    /// `keyset_epoch`. This is the single place the epoch is produced, so it is
    /// always the one canonical function of the roster.
    pub fn new(programs: Vec<ManifestProgram>) -> Self {
        let keyset_epoch = compute_keyset_epoch(&programs);
        Self {
            programs,
            keyset_epoch,
        }
    }

    /// Serialize in the canonical on-disk form (pretty + trailing newline).
    pub fn to_json(&self) -> serde_json::Result<String> {
        Ok(serde_json::to_string_pretty(self)? + "\n")
    }

    /// Internal-consistency checks: a non-empty loadout, and exactly one
    /// `role = top` program (the L1-verifier deploy selects that single entry).
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
        Ok(())
    }
}

/// axiom-edge's keyset identity: `sha256` over a domain tag ([`KEYSET_EPOCH_DOMAIN`])
/// followed by, for each program **in loadout order**, its length-prefixed name,
/// its version (`u32` little-endian), its role tag (one byte), and its
/// `app_exe_commit` (canonical 32 bytes). The length prefix makes the encoding
/// unambiguous, and the order-sensitivity means any change to loadout
/// membership, ordering, versions, roles, or any program's exe commit changes
/// the epoch.
///
/// It is deliberately a pure function of the emitted roster: a consumer
/// recomputes it from the file alone, with no vk download and no openvm hashing
/// primitive. `app_vm_commit` is *not* folded in — it is derivable and not
/// emitted, and the aggregation programs' exe commits already transitively
/// encode the child vk commits, so the roster's exe commits are a sufficient
/// keyset identity for drift detection.
pub fn compute_keyset_epoch(programs: &[ManifestProgram]) -> KeysetEpoch {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    h.update(KEYSET_EPOCH_DOMAIN);
    for p in programs {
        h.update((p.program.name.len() as u32).to_le_bytes());
        h.update(p.program.name.as_bytes());
        h.update(p.program.version.to_le_bytes());
        h.update([p.role.epoch_tag()]);
        h.update(p.app_exe_commit.as_slice());
    }
    KeysetEpoch(h.finalize().into())
}

/// A keyset epoch: a raw 32-byte SHA-256 digest (not a BabyBear field digest, so
/// not a [`CommitBytes`]). Serializes as a `0x`-prefixed lowercase hex string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeysetEpoch([u8; 32]);

impl KeysetEpoch {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for KeysetEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl Serialize for KeysetEpoch {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for KeysetEpoch {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let hex_str = s.strip_prefix("0x").unwrap_or(&s);
        let bytes: [u8; 32] = hex::decode(hex_str)
            .map_err(serde::de::Error::custom)?
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))?;
        Ok(KeysetEpoch(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid canonical [`CommitBytes`] from small BabyBear limbs. `CommitBytes`
    /// enforces canonicity, so this exercises the real encoding without a keygen.
    fn commit(seed: u32) -> CommitBytes {
        CommitBytes::from([seed, seed + 1, seed + 2, seed + 3, 4, 5, 6, 7])
    }

    fn program(name: &str, version: u32, role: ProgramRole, seed: u32) -> ManifestProgram {
        ManifestProgram {
            program: ProgramRef::new(name, version),
            role,
            app_exe_commit: commit(seed),
        }
    }

    fn sample() -> KeysetManifest {
        KeysetManifest::new(vec![
            program("evm-leaf", 1, ProgramRole::Child, 10),
            program("evm-agg", 1, ProgramRole::Child, 20),
            program("final-agg", 1, ProgramRole::Top, 30),
        ])
    }

    /// The roster serializes to `{name, version, role, app_exe_commit}` per
    /// entry, and the whole manifest round-trips byte-identically.
    #[test]
    fn manifest_round_trips_and_has_expected_shape() {
        let manifest = sample();
        let json = manifest.to_json().expect("serializes");

        // Flattened ProgramRef → name/version at the entry top level; role is
        // snake_case; commits are canonical 0x hex.
        assert!(json.contains("\"name\": \"final-agg\""));
        assert!(json.contains("\"version\": 1"));
        assert!(json.contains("\"role\": \"top\""));
        assert!(json.contains("\"role\": \"child\""));
        assert!(json.contains("\"app_exe_commit\": \"0x"));
        assert!(json.contains("\"keyset_epoch\": \"0x"));

        let parsed: KeysetManifest = serde_json::from_str(&json).expect("parses");
        assert_eq!(parsed, manifest);
        assert_eq!(parsed.to_json().expect("re-serializes"), json);
    }

    /// `app_exe_commit` is the canonical big-endian `CommitBytes` form, *not* the
    /// little-endian limb layout the previous revision emitted. This pins the
    /// encoding switch: the JSON hex must equal `CommitBytes` serialization and
    /// must differ from the LE-limb bytes (for a non-palindromic digest).
    #[test]
    fn app_exe_commit_is_canonical_not_le_limbs() {
        let c = commit(10);
        let canonical = c.as_slice();
        let le_limbs = c.to_field_le_bytes();
        assert_ne!(
            canonical, &le_limbs,
            "canonical BE and LE-limb forms must differ for this digest, else the test proves nothing",
        );

        // The serialized field is the canonical form.
        let p = program("evm-leaf", 1, ProgramRole::Child, 10);
        let json = serde_json::to_string(&p).expect("serializes");
        assert!(json.contains(&format!("0x{}", hex::encode(canonical))));
        assert!(!json.contains(&hex::encode(le_limbs)));
    }

    /// The epoch is deterministic and sensitive to every part of the roster.
    #[test]
    fn keyset_epoch_is_deterministic_and_sensitive() {
        let a = sample();
        let b = sample();
        assert_eq!(a.keyset_epoch, b.keyset_epoch, "same roster → same epoch");

        // Reordering programs changes the epoch (order is part of the identity).
        let mut reordered = a.programs.clone();
        reordered.swap(0, 2);
        assert_ne!(
            KeysetManifest::new(reordered).keyset_epoch,
            a.keyset_epoch,
            "program order must affect the epoch",
        );

        // Changing a single exe commit changes the epoch.
        let mut diff_commit = a.programs.clone();
        diff_commit[1].app_exe_commit = commit(99);
        assert_ne!(
            KeysetManifest::new(diff_commit).keyset_epoch,
            a.keyset_epoch
        );

        // Changing a role changes the epoch.
        let mut diff_role = a.programs.clone();
        diff_role[0].role = ProgramRole::Top;
        assert_ne!(KeysetManifest::new(diff_role).keyset_epoch, a.keyset_epoch);

        // Changing a version changes the epoch.
        let mut diff_version = a.programs.clone();
        diff_version[0].program.version = 2;
        assert_ne!(
            KeysetManifest::new(diff_version).keyset_epoch,
            a.keyset_epoch
        );
    }

    #[test]
    fn validate_accepts_exactly_one_top() {
        sample().validate().expect("sample validates");
    }

    #[test]
    fn validate_rejects_zero_or_two_tops() {
        let mut zero = sample();
        zero.programs[2].role = ProgramRole::Child; // now zero tops
        assert!(zero
            .validate()
            .unwrap_err()
            .contains("exactly one role=top"));

        let mut two = sample();
        two.programs[0].role = ProgramRole::Top; // now two tops
        assert!(two.validate().unwrap_err().contains("exactly one role=top"));
    }

    #[test]
    fn validate_rejects_empty_loadout() {
        let empty = KeysetManifest::new(vec![]);
        assert!(empty.validate().unwrap_err().contains("no programs"));
    }

    #[test]
    fn keyset_epoch_hex_round_trips() {
        let epoch = sample().keyset_epoch;
        let json = serde_json::to_string(&epoch).expect("serializes");
        assert!(json.starts_with("\"0x"));
        let parsed: KeysetEpoch = serde_json::from_str(&json).expect("parses");
        assert_eq!(parsed, epoch);
    }
}
