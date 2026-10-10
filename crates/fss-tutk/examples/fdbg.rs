#![forbid(unsafe_code)]
// Field-op level differential: gf mul/sqr/inv/pack vs python-computed vectors.
// (uses only the crate's public x25519 path; prints for manual comparison)

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

fn main() {
    let x = unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    let y = unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6c0ab1c4c");
    let mut xb = [0u8; 32];
    xb.copy_from_slice(&x);
    let mut yb = [0u8; 32];
    yb.copy_from_slice(&y);
    println!("x25519(x,y): {}", hex(&x25519(&xb, &yb)));
    println!("oracle     : b5c498fec0a7e948f8c91cb9a551ee4c217e6d579e024ffda37abb467f222345");
    // oracle's X25519 with x as scalar against base point? not needed here
    let a = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let mut ab = [0u8; 32];
    ab.copy_from_slice(&a);
    println!("base(a)    : {}", hex(&x25519_base(&ab)));
    println!("oracle     : 8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
}
