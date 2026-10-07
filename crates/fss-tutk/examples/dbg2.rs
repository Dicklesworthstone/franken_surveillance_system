// Debug harness for field ops, chacha block, and poly1305 against known answers.
use fss_tutk::chacha::{chacha20_xor, poly1305};
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
    // --- x25519 ---
    let n = unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    let u = unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6c0ab1c4c");
    let mut nb = [0u8; 32];
    nb.copy_from_slice(&n);
    let mut ub = [0u8; 32];
    ub.copy_from_slice(&u);
    println!("x25519(v1): {}", hex(&x25519(&nb, &ub)));
    println!("oracle    : b5c498fec0a7e948f8c91cb9a551ee4c217e6d579e024ffda37abb467f222345");

    // --- chacha block for stream params ---
    let key: [u8; 32] = std::array::from_fn(|i| i as u8);
    let nonce: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0];
    let mut zeros = vec![0u8; 64];
    chacha20_xor(&key, 1, &nonce, &mut zeros);
    println!("ks[:16]   : {}", hex(&zeros[..16]));
    // expected keystream prefix (block 1): compute from canonical ct xor pt:
    // 6e2e359a2568f98041ba0728dd0d6981 XOR "Ladies and Gentl" = ...
    let pt = b"Ladies and Gentl";
    let want_ct = unhex("6e2e359a2568f98041ba0728dd0d6981");
    let ks: Vec<u8> = want_ct.iter().zip(pt.iter()).map(|(a, b)| a ^ b).collect();
    println!("ks oracle : {}", hex(&ks));

    // --- poly1305 ---
    let pkey = unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pkey);
    println!("poly      : {}", hex(&poly1305(&pk, b"Cryptographic Forum Research Group")));
    println!("poly want : a8061dc1305136c6c22b8baf0c0127a9");

    // --- x25519 base ---
    let a = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let mut ab = [0u8; 32];
    ab.copy_from_slice(&a);
    println!("base      : {}", hex(&x25519_base(&ab)));
    println!("base want : 8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
}
