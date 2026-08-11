use std::{fs, path::Path};

use bitcode::{deserialize, serialize};
use color_eyre::eyre::{Result, WrapErr};
use openvm_stark_backend::{codec::Decode, Val};
use sdk_v2::{openvm_circuit::arch::instructions::exe::VmExe, types::ExecutableFormat, Sdk, SC};
use verify_stark::{vk::VmStarkVerifyingKey, VmStarkProof};

use crate::openvm_config::create_edge_sdk;

const ZSTD_FRAME_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// Build a VM verifying key bundle from an ELF using the standard edge SDK.
///
/// This handles any program the standard transpiler can parse. A deferral guest
/// (e.g. the final aggregation program) carries custom opcodes owned by the
/// deferral extension, which the standard config's transpiler lacks — build the
/// deferral-enabled SDK and call [`build_vm_vk_from_elf_with_sdk`] instead. That
/// is the same standard-vs-deferral split `convert_fixtures` makes when
/// transpiling the matching `program.vmexe`, so the vk stays consistent with it.
pub fn build_vm_vk_from_elf<P: AsRef<Path>>(elf_path: P) -> Result<VmStarkVerifyingKey> {
    let sdk = create_edge_sdk()?;
    build_vm_vk_from_elf_with_sdk(&sdk, elf_path)
}

/// Build a VM verifying key bundle from an ELF with a caller-provided SDK.
///
/// The SDK fixes the transpiler and aggregation config, so the returned vk
/// (`mvk` from `sdk.agg_vk()`, baseline from the transpiled exe) matches a vmexe
/// transpiled from the SAME SDK. Pass a deferral-enabled SDK to build the vk for
/// a deferral guest; pass [`create_edge_sdk`] (via [`build_vm_vk_from_elf`]) for
/// a standard program.
pub fn build_vm_vk_from_elf_with_sdk<P: AsRef<Path>>(
    sdk: &Sdk,
    elf_path: P,
) -> Result<VmStarkVerifyingKey> {
    let elf_path = elf_path.as_ref();
    let elf_bytes = fs::read(elf_path)
        .wrap_err_with(|| format!("Failed to read ELF file {}", elf_path.display()))?;

    let executable: ExecutableFormat = elf_bytes.as_slice().into();
    let exe = sdk
        .convert_to_exe(executable)
        .wrap_err_with(|| format!("Failed to convert ELF {} to VmExe", elf_path.display()))?;
    // Match the artifact-backed path by normalizing through the same bitcode encoding
    // used for program.vmexe on disk before generating the verification baseline.
    let exe_bytes = serialize(exe.as_ref())
        .wrap_err("Failed to bitcode-serialize VmExe while building VM verifying key")?;
    let exe: VmExe<Val<SC>> = deserialize(&exe_bytes)
        .wrap_err("Failed to bitcode-deserialize VmExe while building VM verifying key")?;
    let prover = sdk
        .prover(exe)
        .wrap_err("Failed to construct Edge prover for baseline generation")?;

    Ok(VmStarkVerifyingKey {
        mvk: (*sdk.agg_vk()).clone(),
        baseline: prover.generate_baseline(),
    })
}

fn decode_persisted_final_proof_bytes(path: &Path, proof_bytes: Vec<u8>) -> Result<Vec<u8>> {
    if proof_bytes.starts_with(&ZSTD_FRAME_MAGIC) {
        return zstd::decode_all(&proof_bytes[..]).wrap_err_with(|| {
            format!(
                "Failed to zstd-decompress persisted Edge final proof {}",
                path.display()
            )
        });
    }

    Ok(proof_bytes)
}

pub fn load_final_proof<P: AsRef<Path>>(path: P) -> Result<VmStarkProof> {
    let path = path.as_ref();
    let proof_bytes = fs::read(path)
        .wrap_err_with(|| format!("Failed to read final proof {}", path.display()))?;
    let proof_bytes = decode_persisted_final_proof_bytes(path, proof_bytes)?;

    // Final stark proofs persist as a `VmStarkProof` encoded with the openvm
    // codec (the manager's `persist_final_proof_to_disk` reconstructs it from
    // the proof + user public values + any deferral merkle proofs). The codec
    // carries the `DeferralMerkleProofs` inline, so a `proof_type=stark`
    // deferral proof round-trips with its merkle proofs (needed to verify;
    // they bind the deferral accumulator hashes to the initial/final memory
    // roots). Non-deferral proofs decode with `deferral_merkle_proofs = None`.
    VmStarkProof::decode_from_bytes(&proof_bytes).wrap_err_with(|| {
        format!(
            "Failed to decode Edge final proof (VmStarkProof) {}",
            path.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::decode_persisted_final_proof_bytes;

    #[test]
    fn test_decode_persisted_final_proof_bytes_accepts_raw_bytes() {
        let path = std::path::Path::new("/tmp/test.proof.bin");
        let raw = b"raw-proof-bytes".to_vec();

        let decoded = decode_persisted_final_proof_bytes(path, raw.clone()).unwrap();

        assert_eq!(decoded, raw);
    }

    #[test]
    fn test_decode_persisted_final_proof_bytes_decompresses_zstd() {
        let path = std::path::Path::new("/tmp/test.proof.bin");
        let raw = b"compressed-proof-bytes".to_vec();
        let compressed = zstd::encode_all(&raw[..], 19).unwrap();

        let decoded = decode_persisted_final_proof_bytes(path, compressed).unwrap();

        assert_eq!(decoded, raw);
    }
}
