//! Known-answer contract tests for the first-party AES-128 / GCM / HMAC
//! core. Vectors: FIPS-197 Appendix C.1 (AES), McGrew–Viega/NIST GCM cases
//! verified against pyca/cryptography (lab oracle), RFC 4231 (HMAC-SHA256),
//! plus ECB-PKCS7 round-trips and tamper rejection.

use fss_tuya::crypto::{
    Aes128, aes128_ecb_decrypt_pkcs7, aes128_ecb_decrypt_raw, aes128_ecb_encrypt_pkcs7,
    aes128_ecb_encrypt_raw, aes128_gcm_decrypt, aes128_gcm_encrypt, hmac_sha256,
};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .unwrap_or_default()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn aes128_fips197_appendix_c1() {
    let key: [u8; 16] = unhex("000102030405060708090a0b0c0d0e0f").try_into().unwrap_or([0; 16]);
    let pt: [u8; 16] = unhex("00112233445566778899aabbccddeeff")
        .try_into()
        .unwrap_or([0; 16]);
    let cipher = Aes128::new(&key);
    let ct = cipher.encrypt_block(&pt);
    assert_eq!(hex(&ct), "69c4e0d86a7b0430d8cdb78070b4c55a");
    assert_eq!(cipher.decrypt_block(&ct), pt, "decrypt inverts encrypt");
}

#[test]
fn gcm_case1_empty() {
    // NIST GCM case 1: zero key, zero IV, empty plaintext/AAD → tag only.
    let out = aes128_gcm_encrypt(&[0u8; 16], &[0u8; 12], b"", b"");
    assert_eq!(hex(&out), "58e2fccefa7e3061367f1d57a4e7455a");
    let pt = aes128_gcm_decrypt(&[0u8; 16], &[0u8; 12], b"", &out);
    assert_eq!(pt, Some(Vec::new()));
}

#[test]
fn gcm_case2_single_zero_block() {
    let out = aes128_gcm_encrypt(&[0u8; 16], &[0u8; 12], b"", &[0u8; 16]);
    assert_eq!(
        hex(&out),
        "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"
    );
}

#[test]
fn gcm_case3_four_blocks_no_aad() {
    let key: [u8; 16] = unhex("feffe9928665731c6d6a8f9467308308")
        .try_into()
        .unwrap_or([0; 16]);
    let iv: [u8; 12] = unhex("cafebabefacedbaddecaf888")
        .try_into()
        .unwrap_or([0; 12]);
    let pt = unhex(concat!(
        "d9313225f88406e5a55909c5aff5269a",
        "86a7a9531534f7da2e4c303d8a318a72",
        "1c3c0c95956809532fcf0e2449a6b525",
        "b16aedf5aa0de657ba637b391aafd255"
    ));
    let out = aes128_gcm_encrypt(&key, &iv, b"", &pt);
    assert_eq!(
        hex(&out),
        concat!(
            "42831ec2217774244b7221b784d0d49c",
            "e3aa212f2c02a4e035c17e2329aca12e",
            "21d514b25466931c7d8f6a5aac84aa05",
            "1ba30b396a0aac973d58e091473f5985",
            "4d5c2af327cd64a62cf35abd2ba6fab4"
        )
    );
    assert_eq!(aes128_gcm_decrypt(&key, &iv, b"", &out), Some(pt));
}

#[test]
fn gcm_case4_with_aad() {
    let key: [u8; 16] = unhex("feffe9928665731c6d6a8f9467308308")
        .try_into()
        .unwrap_or([0; 16]);
    let iv: [u8; 12] = unhex("cafebabefacedbaddecaf888")
        .try_into()
        .unwrap_or([0; 12]);
    let pt = unhex(concat!(
        "d9313225f88406e5a55909c5aff5269a",
        "86a7a9531534f7da2e4c303d8a318a72",
        "1c3c0c95956809532fcf0e2449a6b525",
        "b16aedf5aa0de657ba637b391aafd255"
    ));
    let aad = unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    let out = aes128_gcm_encrypt(&key, &iv, &aad, &pt);
    // Same ciphertext as case 3, AAD-dependent tag (oracle-verified).
    assert_eq!(
        hex(&out),
        concat!(
            "42831ec2217774244b7221b784d0d49c",
            "e3aa212f2c02a4e035c17e2329aca12e",
            "21d514b25466931c7d8f6a5aac84aa05",
            "1ba30b396a0aac973d58e091473f5985",
            "da80ce830cfda02da2a218a1744f4c76"
        )
    );
    assert_eq!(aes128_gcm_decrypt(&key, &iv, &aad, &out), Some(pt.clone()));
    // Wrong AAD must fail the tag.
    assert_eq!(aes128_gcm_decrypt(&key, &iv, b"wrong", &out), None);
}

#[test]
fn gcm_odd_length_and_tamper() {
    // 20-byte plaintext (non-block-aligned) with AAD, oracle-verified.
    let key: [u8; 16] = unhex("feffe9928665731c6d6a8f9467308308")
        .try_into()
        .unwrap_or([0; 16]);
    let iv: [u8; 12] = unhex("cafebabefacedbaddecaf888")
        .try_into()
        .unwrap_or([0; 12]);
    let aad = unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    let pt = b"hello tuya lan world";
    let out = aes128_gcm_encrypt(&key, &iv, &aad, pt);
    assert_eq!(
        hex(&out),
        "f3d7408bb6d306b4974a081e4a4bd2710a7fe418e2f2f00d8f75e180e9dd0d1d4848d0ed"
    );
    assert_eq!(aes128_gcm_decrypt(&key, &iv, &aad, &out).as_deref(), Some(&pt[..]));
    // One-bit tamper anywhere in ct or tag must be rejected.
    for idx in [0, 7, out.len() - 1] {
        let mut bad = out.clone();
        if let Some(b) = bad.get_mut(idx) {
            *b ^= 0x01;
        }
        assert_eq!(aes128_gcm_decrypt(&key, &iv, &aad, &bad), None, "idx {idx}");
    }
    // Wrong key must be rejected.
    assert_eq!(aes128_gcm_decrypt(&[0xAA; 16], &iv, &aad, &out), None);
}

#[test]
fn ecb_pkcs7_vector_and_roundtrip() {
    let key = *b"0123456789abcdef";
    let pt = b"hello tuya!";
    let ct = aes128_ecb_encrypt_pkcs7(&key, pt);
    assert_eq!(hex(&ct), "9c6354a09f9d2db63b27273e6f5b4dc9");
    assert_eq!(aes128_ecb_decrypt_pkcs7(&key, &ct).as_deref(), Some(&pt[..]));
    // Raw path requires alignment.
    assert_eq!(aes128_ecb_encrypt_raw(&key, b"not aligned"), None);
    assert_eq!(aes128_ecb_decrypt_raw(&key, b"not aligned"), None);
    // Empty plaintext pads to a full block and round-trips.
    let ct_empty = aes128_ecb_encrypt_pkcs7(&key, b"");
    assert_eq!(ct_empty.len(), 16);
    assert_eq!(aes128_ecb_decrypt_pkcs7(&key, &ct_empty), Some(Vec::new()));
}

#[test]
fn hmac_sha256_rfc4231_case1() {
    let key = [0x0bu8; 20];
    let mac = hmac_sha256(&key, b"Hi There");
    assert_eq!(
        hex(&mac),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
}

#[test]
fn hmac_sha256_rfc4231_long_key() {
    // Key longer than the 64-byte block size exercises the hash-key path.
    let key = [0xAAu8; 131];
    let mac = hmac_sha256(&key, b"Test Using Larger Than Block-Size Key - Hash Key First");
    assert_eq!(
        hex(&mac),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
}
