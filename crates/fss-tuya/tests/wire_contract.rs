//! Wire-framing contract tests: CRC32 known vector, 55AA round-trips
//! (CRC + HMAC trailers), the oracle-verified 6699 golden frame, retcode
//! heuristics, and both session-key derivations.

use fss_tuya::wire::{
    self, RetcodeMode, WireError, cmd, crc32_ieee, derive_session_key_34, derive_session_key_35,
    pack_55aa, pack_6699, parse_header, unpack_55aa, unpack_6699, unpack_6699_mode,
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
fn crc32_known_vector() {
    assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
}

#[test]
fn frame_55aa_crc_roundtrip() {
    let payload = b"{\"dps\":{\"1\":true}}";
    let frame = pack_55aa(42, cmd::DP_QUERY, Some(0), payload, None);
    let h = parse_header(&frame);
    let h = match h {
        Ok(h) => h,
        Err(e) => panic!("header: {e}"),
    };
    assert_eq!(h.prefix, wire::PREFIX_55AA);
    assert_eq!(h.seqno, 42);
    assert_eq!(h.cmd, cmd::DP_QUERY);
    assert_eq!(h.total, frame.len());
    let msg = unpack_55aa(&frame, None, false);
    let msg = match msg {
        Ok(m) => m,
        Err(e) => panic!("unpack: {e}"),
    };
    assert_eq!(msg.payload, payload);
    assert_eq!(msg.retcode, Some(0));
}

#[test]
fn frame_55aa_hmac_golden() {
    // Oracle-generated (tinytuya semantics): seq 9, STATUS, retcode 0,
    // payload {"dps":{"20":false}}, HMAC key "0123456789abcdef".
    let golden = unhex(concat!(
        "000055aa00000009000000080000003c00000000",
        "7b22647073223a7b223230223a66616c73657d7d",
        "d3722ff93f7fabc43c1404f23d4b6ef15d44621b1c2803a293bfbfd89df5bd83",
        "0000aa55"
    ));
    let key = *b"0123456789abcdef";
    let ours = pack_55aa(9, cmd::STATUS, Some(0), b"{\"dps\":{\"20\":false}}", Some(&key));
    assert_eq!(hex(&ours), hex(&golden), "byte-exact vs oracle");
    let msg = match unpack_55aa(&golden, Some(&key), false) {
        Ok(m) => m,
        Err(e) => panic!("unpack golden: {e}"),
    };
    assert_eq!(msg.payload, b"{\"dps\":{\"20\":false}}");
    // Wrong HMAC key must fail integrity.
    let bad = unpack_55aa(&golden, Some(b"9999999999999999"), false);
    assert_eq!(bad, Err(WireError::Integrity));
}

#[test]
fn frame_6699_golden() {
    // Oracle-generated (tinytuya semantics): seq 7, DP_QUERY, retcode 0,
    // payload {"dps":{"1":true}}, key "0123456789abcdef",
    // iv 000102030405060708090a0b.
    let golden = unhex(
        "0000669900000000000000070000000a00000032000102030405060708090a0bfd3fc41d65565f469b043d61e2aa921774a5229f7ace0a2e102475fe6af5ba5ef6523e9feeb000009966",
    );
    let key = *b"0123456789abcdef";
    let iv: [u8; 12] = unhex("000102030405060708090a0b")
        .try_into()
        .unwrap_or([0; 12]);
    let ours = pack_6699(7, cmd::DP_QUERY, Some(0), b"{\"dps\":{\"1\":true}}", &key, iv);
    assert_eq!(hex(&ours), hex(&golden), "byte-exact vs oracle");
    let msg = match unpack_6699(&golden, &key) {
        Ok(m) => m,
        Err(e) => panic!("unpack golden: {e}"),
    };
    assert_eq!(msg.payload, b"{\"dps\":{\"1\":true}}");
    assert_eq!(msg.retcode, Some(0));
    assert_eq!(msg.iv, Some(iv));
}

#[test]
fn frame_6699_no_retcode_roundtrip() {
    // Client→device negotiation shape: raw binary payload, no retcode.
    let key = *b"0123456789abcdef";
    let nonce = *b"fedcba9876543210";
    let iv: [u8; 12] = *b"0123456789ab";
    let frame = pack_6699(1, cmd::SESS_KEY_NEG_START, None, &nonce, &key, iv);
    let msg = match unpack_6699_mode(&frame, &key, RetcodeMode::Absent) {
        Ok(m) => m,
        Err(e) => panic!("unpack: {e}"),
    };
    assert_eq!(msg.payload, nonce);
    assert_eq!(msg.retcode, None);
    // Auto heuristic on binary payloads keeps the payload whole when
    // byte 4 is not '{' (mirrors the laboratory oracle).
    let auto = match unpack_6699(&frame, &key) {
        Ok(m) => m,
        Err(e) => panic!("unpack auto: {e}"),
    };
    assert_eq!(auto.payload, nonce);
}

#[test]
fn frame_bad_inputs_are_typed_errors() {
    assert_eq!(parse_header(b"\x00\x01"), Err(WireError::ShortHeader));
    let bad_prefix = unhex("00001234000000000000000000000000");
    assert_eq!(
        parse_header(&bad_prefix),
        Err(WireError::BadPrefix(0x1234))
    );
    let mut frame = pack_55aa(1, cmd::HEART_BEAT, Some(0), b"", None);
    frame.truncate(frame.len() - 2);
    let e = parse_header(&frame);
    assert!(matches!(e, Err(WireError::Truncated { .. })), "{e:?}");
    // Corrupt CRC → Integrity, never silent.
    let mut frame = pack_55aa(1, cmd::HEART_BEAT, Some(0), b"", None);
    let idx = frame.len() - 5;
    if let Some(b) = frame.get_mut(idx) {
        *b ^= 0x01;
    }
    assert_eq!(unpack_55aa(&frame, None, false), Err(WireError::Integrity));
    // Corrupt suffix → Integrity.
    let mut frame = pack_55aa(1, cmd::HEART_BEAT, Some(0), b"", None);
    let idx = frame.len() - 1;
    if let Some(b) = frame.get_mut(idx) {
        *b ^= 0xFF;
    }
    assert_eq!(unpack_55aa(&frame, None, false), Err(WireError::Integrity));
    // 6699 with wrong key → GcmAuth.
    let key = *b"0123456789abcdef";
    let f = pack_6699(1, cmd::STATUS, Some(0), b"{}", &key, [0u8; 12]);
    assert_eq!(
        unpack_6699(&f, b"9999999999999999"),
        Err(WireError::GcmAuth)
    );
}

#[test]
fn session_key_derivation_vectors() {
    // Oracle-derived (pyca): key "0123456789abcdef",
    // client nonce "0123456789abcdef", device nonce "fedcba9876543210".
    let key = *b"0123456789abcdef";
    let cn = *b"0123456789abcdef";
    let dn = *b"fedcba9876543210";
    let k35 = derive_session_key_35(&key, &cn, &dn);
    assert_eq!(hex(&k35), "34165bab783422860c0c23b2d48cf7a5");
    let k34 = derive_session_key_34(&key, &cn, &dn);
    assert_eq!(k34.map(|k| hex(&k)).as_deref(), Some("6575cf6b37479d9215337ff9767fe786"));
}
