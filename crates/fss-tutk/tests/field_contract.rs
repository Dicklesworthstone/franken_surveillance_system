#![forbid(unsafe_code)]
//! Field-operation contract tests for the X25519 gf arithmetic, using
//! vectors computed by the oracle-verified Python clone (LAB-2026-10-07).

use fss_tutk::x25519::{x25519, x25519_base};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn gf_field_ops_match_python_clone() {
    let x = unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    let y = unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6c0ab1c4c");
    let mut xb = [0u8; 32];
    xb.copy_from_slice(&x);
    let mut yb = [0u8; 32];
    yb.copy_from_slice(&y);
    // these vectors come straight from the python clone's internal gf functions
    assert_eq!(
        hex(&x25519(&xb, &yb)),
        "b5c498fec0a7e948f8c91cb9a551ee4c217e6d579e024ffda37abb467f222345",
        "X25519(v1)"
    );
}

#[test]
fn v2_and_base_vectors() {
    let n2 = unhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
    let u2 = unhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
    let mut n2b = [0u8; 32];
    n2b.copy_from_slice(&n2);
    let mut u2b = [0u8; 32];
    u2b.copy_from_slice(&u2);
    assert_eq!(
        hex(&x25519(&n2b, &u2b)),
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
        "X25519(v2)"
    );
    let a = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let mut ab = [0u8; 32];
    ab.copy_from_slice(&a);
    assert_eq!(
        hex(&x25519_base(&ab)),
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        "X25519_base(alice)"
    );
    let b = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let mut bb = [0u8; 32];
    bb.copy_from_slice(&b);
    assert_eq!(
        hex(&x25519_base(&bb)),
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        "X25519_base(bob)"
    );
}
