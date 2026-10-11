#![forbid(unsafe_code)]
//! Regenerates the contract-basis golden binary fixture after an intentional
//! registry-digest migration (writes `tests/fixtures/contract_basis_v2.bin`
//! and prints the canonical + freeze digests to pin in `contract_basis.rs`
//! and `contract_basis_contract.rs`). Deliberately manual: fixture bytes are
//! reviewable binary artifacts, and regenerating them is a deliberate act,
//! never an incidental test side effect.

use std::error::Error;
use std::path::PathBuf;

use fss_core::ContentDigest;
use fss_core::contract_basis::{encode_canonical_binary, reference_contract_basis};

fn main() -> Result<(), Box<dyn Error>> {
    let basis = reference_contract_basis();
    let binary = encode_canonical_binary(&basis)?;
    let canonical = basis.basis_digest();
    let freeze = ContentDigest::sha256(&binary);
    println!("canonical basis digest: {}", canonical.to_text());
    println!("binary freeze digest: {}", freeze.to_text());

    let out = PathBuf::from("tests/fixtures/contract_basis_v2.bin");
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&out, &binary)?;
    println!("wrote {} ({} bytes)", out.display(), binary.len());
    Ok(())
}
