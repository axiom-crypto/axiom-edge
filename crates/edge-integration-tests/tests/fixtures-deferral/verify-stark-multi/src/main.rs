// Verify-stark guest that makes a configurable number of `verify_stark` calls
// against a single deferral circuit.
//
// stdin protocol (via `openvm::io::read`):
//   input_commit : Commit   — the child proof's input commitment
//   num_verifies : u32       — how many times to verify it (all at circuit 0)
//
// Each `verify_stark_unchecked::<0>` call defers one verification of the child
// proof; the outer proof only generates if every deferred verification passes.
// So a proof job makes `num_verifies` verify_stark calls and succeeds iff all
// pass. Edge supports one deferral circuit, so this uses circuit 0 only.
#![cfg_attr(target_os = "zkvm", no_main)]
#![cfg_attr(target_os = "zkvm", no_std)]

extern crate alloc;

use openvm::io::read;
use openvm_deferral_guest::Commit;
use openvm_verify_stark_guest::verify_stark_unchecked;

openvm::entry!(main);

pub fn main() {
    let input_commit: Commit = read();
    let num_verifies: u32 = read();
    for _ in 0..num_verifies {
        let _ = verify_stark_unchecked::<0>(&input_commit);
    }
}
