#![forbid(unsafe_code)]
use fss_tutk::chacha::chacha20_xor;
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
    let key: [u8; 32] = std::array::from_fn(|i| i as u8);
    let nonce: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0];
    let pt = b"Ladies and Gentlemen of the class of \x27\x39\x39\x3a\x20If I could offer you only one tip for the future, sunscreen would be it.";
    let mut data = pt.to_vec();
    chacha20_xor(&key, 1, &nonce, &mut data);
    println!("stream[:16]: {}", hex(&data[..16]));
    println!("expect     : 6e2e359a2568f98041ba0728dd0d6981");

    let n2 = unhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
    let u2 = unhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
    let mut n = [0u8; 32];
    n.copy_from_slice(&n2);
    let mut u = [0u8; 32];
    u.copy_from_slice(&u2);
    println!("x25519(v2) : {}", hex(&x25519(&n, &u)));
    println!("expect     : 95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
    let a = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let mut ab = [0u8; 32];
    ab.copy_from_slice(&a);
    println!("base(alice): {}", hex(&x25519_base(&ab)));
    println!("expect     : 8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
}
