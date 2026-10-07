//! Known-answer tests for the first-party digest module (FIPS + RFC 2104 vectors).

use fss_tutk::digest::{hmac_sha1, hmac_sha256, Sha1, Sha256};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn sha1_known_answers() {
    assert_eq!(hex(&Sha1::digest(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
    assert_eq!(
        hex(&Sha1::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
        "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
    );
    // streaming in odd-size chunks must equal one-shot
    let msg = vec![0x61u8; 1000];
    let mut h = Sha1::new();
    for chunk in msg.chunks(7) {
        h.update(chunk);
    }
    assert_eq!(hex(&h.finish()), hex(&Sha1::digest(&msg)));
}

#[test]
fn sha256_known_answers() {
    assert_eq!(
        hex(&Sha256::digest(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex(&Sha256::digest(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    let msg = vec![0x42u8; 1000];
    let mut h = Sha256::new();
    for chunk in msg.chunks(13) {
        h.update(chunk);
    }
    assert_eq!(hex(&h.finish()), hex(&Sha256::digest(&msg)));
}

#[test]
fn hmac_sha1_rfc2202() {
    // RFC 2202 case 1
    assert_eq!(
        hex(&hmac_sha1(&[0x0b; 20], b"Hi There")),
        "b617318655057264e28bc0b6fb378c8ef146be00"
    );
    // case 2
    assert_eq!(
        hex(&hmac_sha1(b"Jefe", b"what do ya want for nothing?")),
        "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
    );
    // case 3 (20 x 0xaa key, 50 x 0xdd data)
    assert_eq!(
        hex(&hmac_sha1(&[0xaa; 20], &[0xdd; 50])),
        "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
    );
}

#[test]
fn hmac_sha256_rfc4231() {
    // RFC 4231 case 1
    assert_eq!(
        hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    // case 2
    assert_eq!(
        hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    // case 6 (long key, pre-hashed path)
    assert_eq!(
        hex(&hmac_sha256(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        )),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
}
