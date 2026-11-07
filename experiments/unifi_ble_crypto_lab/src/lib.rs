#![forbid(unsafe_code)]
//! Experimental, offline UniFi BLE cryptographic interoperability laboratory.
//!
//! This is not an admitted cryptographic provider. It does not authenticate a
//! camera, own entropy or secrets, perform I/O, or implement provisioning.
//! It exists to compare the reverse-engineered wire primitives with an
//! independent implementation using synthetic keys and messages only.

#[path = "../../../crates/fss-tutk/src/chacha.rs"]
mod existing_poly1305;
#[path = "../../../crates/fss-tutk/src/x25519.rs"]
mod existing_x25519;

const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

fn word(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn salsa_rounds(x: &mut [u32; 16]) {
    for _ in 0..10 {
        x[4] ^= x[0].wrapping_add(x[12]).rotate_left(7);
        x[8] ^= x[4].wrapping_add(x[0]).rotate_left(9);
        x[12] ^= x[8].wrapping_add(x[4]).rotate_left(13);
        x[0] ^= x[12].wrapping_add(x[8]).rotate_left(18);
        x[9] ^= x[5].wrapping_add(x[1]).rotate_left(7);
        x[13] ^= x[9].wrapping_add(x[5]).rotate_left(9);
        x[1] ^= x[13].wrapping_add(x[9]).rotate_left(13);
        x[5] ^= x[1].wrapping_add(x[13]).rotate_left(18);
        x[14] ^= x[10].wrapping_add(x[6]).rotate_left(7);
        x[2] ^= x[14].wrapping_add(x[10]).rotate_left(9);
        x[6] ^= x[2].wrapping_add(x[14]).rotate_left(13);
        x[10] ^= x[6].wrapping_add(x[2]).rotate_left(18);
        x[3] ^= x[15].wrapping_add(x[11]).rotate_left(7);
        x[7] ^= x[3].wrapping_add(x[15]).rotate_left(9);
        x[11] ^= x[7].wrapping_add(x[3]).rotate_left(13);
        x[15] ^= x[11].wrapping_add(x[7]).rotate_left(18);
        x[1] ^= x[0].wrapping_add(x[3]).rotate_left(7);
        x[2] ^= x[1].wrapping_add(x[0]).rotate_left(9);
        x[3] ^= x[2].wrapping_add(x[1]).rotate_left(13);
        x[0] ^= x[3].wrapping_add(x[2]).rotate_left(18);
        x[6] ^= x[5].wrapping_add(x[4]).rotate_left(7);
        x[7] ^= x[6].wrapping_add(x[5]).rotate_left(9);
        x[4] ^= x[7].wrapping_add(x[6]).rotate_left(13);
        x[5] ^= x[4].wrapping_add(x[7]).rotate_left(18);
        x[11] ^= x[10].wrapping_add(x[9]).rotate_left(7);
        x[8] ^= x[11].wrapping_add(x[10]).rotate_left(9);
        x[9] ^= x[8].wrapping_add(x[11]).rotate_left(13);
        x[10] ^= x[9].wrapping_add(x[8]).rotate_left(18);
        x[12] ^= x[15].wrapping_add(x[14]).rotate_left(7);
        x[13] ^= x[12].wrapping_add(x[15]).rotate_left(9);
        x[14] ^= x[13].wrapping_add(x[12]).rotate_left(13);
        x[15] ^= x[14].wrapping_add(x[13]).rotate_left(18);
    }
}

fn state(key: &[u8; 32], input: &[u8; 16]) -> [u32; 16] {
    [
        SIGMA[0],
        word(&key[0..]),
        word(&key[4..]),
        word(&key[8..]),
        word(&key[12..]),
        SIGMA[1],
        word(&input[0..]),
        word(&input[4..]),
        word(&input[8..]),
        word(&input[12..]),
        SIGMA[2],
        word(&key[16..]),
        word(&key[20..]),
        word(&key[24..]),
        word(&key[28..]),
        SIGMA[3],
    ]
}

fn subkey(key: &[u8; 32], nonce: &[u8; 24]) -> [u8; 32] {
    let mut input = [0; 16];
    input.copy_from_slice(&nonce[..16]);
    let mut x = state(key, &input);
    salsa_rounds(&mut x);
    let mut out = [0; 32];
    for (dst, i) in out.chunks_exact_mut(4).zip([0, 5, 10, 15, 6, 7, 8, 9]) {
        dst.copy_from_slice(&x[i].to_le_bytes());
    }
    out
}

fn stream(key: &[u8; 32], nonce: &[u8; 24], length: usize) -> Option<Vec<u8>> {
    // A BLE packet is u16-length-framed. Bound before allocating and generating.
    if length > usize::from(u16::MAX) {
        return None;
    }
    let key = subkey(key, nonce);
    let mut out = Vec::new();
    out.try_reserve_exact(length).ok()?;
    for counter in 0..length.div_ceil(64) {
        let mut input = [0; 16];
        input[..8].copy_from_slice(&nonce[16..]);
        input[8..].copy_from_slice(&(counter as u64).to_le_bytes());
        let original = state(&key, &input);
        let mut x = original;
        salsa_rounds(&mut x);
        for (a, b) in x.into_iter().zip(original) {
            let bytes = a.wrapping_add(b).to_le_bytes();
            let n = (length - out.len()).min(4);
            out.extend_from_slice(&bytes[..n]);
        }
    }
    Some(out)
}

/// Seal synthetic data using the NaCl secretbox wire layout (tag then ciphertext).
pub fn seal(key: &[u8; 32], nonce: &[u8; 24], message: &[u8]) -> Option<Vec<u8>> {
    let total = message.len().checked_add(32)?;
    let stream = stream(key, nonce, total)?;
    let mut poly_key = [0; 32];
    poly_key.copy_from_slice(&stream[..32]);
    let mut out = Vec::new();
    out.try_reserve_exact(message.len().checked_add(16)?).ok()?;
    out.resize(16, 0);
    out.extend(message.iter().zip(&stream[32..]).map(|(a, b)| a ^ b));
    let tag = existing_poly1305::poly1305(&poly_key, &out[16..]);
    out[..16].copy_from_slice(&tag);
    Some(out)
}

/// Verify before exposing any plaintext; this is not a constant-time assurance.
pub fn open(key: &[u8; 32], nonce: &[u8; 24], boxed: &[u8]) -> Option<Vec<u8>> {
    if boxed.len() < 16 {
        return None;
    }
    let stream = stream(key, nonce, boxed.len().checked_sub(16)?.checked_add(32)?)?;
    let mut poly_key = [0; 32];
    poly_key.copy_from_slice(&stream[..32]);
    let tag = existing_poly1305::poly1305(&poly_key, &boxed[16..]);
    let diff = tag
        .iter()
        .zip(&boxed[..16])
        .fold(0u8, |d, (a, b)| d | (a ^ b));
    if diff != 0 {
        return None;
    }
    Some(
        boxed[16..]
            .iter()
            .zip(&stream[32..])
            .map(|(a, b)| a ^ b)
            .collect(),
    )
}

/// Encode one synthetic packet. The caller owns sequence use and all I/O.
pub fn pack_packet(key: &[u8; 32], sequence: u16, protocol: u8, data: &[u8]) -> Option<Vec<u8>> {
    let frame_len = data.len().checked_add(21)?;
    let frame_len = u16::try_from(frame_len).ok()?;
    let mut plain = Vec::new();
    plain.try_reserve_exact(data.len().checked_add(3)?).ok()?;
    plain.extend_from_slice(&sequence.to_be_bytes());
    plain.push(protocol);
    plain.extend_from_slice(data);
    let mut nonce = [0; 24];
    nonce[..2].copy_from_slice(&sequence.to_be_bytes());
    let sealed = seal(key, &nonce, &plain)?;
    let mut frame = Vec::new();
    frame.try_reserve_exact(usize::from(frame_len)).ok()?;
    frame.extend_from_slice(&frame_len.to_be_bytes());
    frame.extend_from_slice(&sealed);
    Some(frame)
}

/// Verify an entire packet and its inner sequence and protocol, without accepting trailing bytes.
pub fn open_packet(
    key: &[u8; 32],
    expected_sequence: u16,
    expected_protocol: u8,
    frame: &[u8],
) -> Option<Vec<u8>> {
    if frame.len() < 21 || usize::from(u16::from_be_bytes([frame[0], frame[1]])) != frame.len() {
        return None;
    }
    let mut nonce = [0; 24];
    nonce[..2].copy_from_slice(&expected_sequence.to_be_bytes());
    let plain = open(key, &nonce, &frame[2..])?;
    if plain.len() < 3
        || u16::from_be_bytes([plain[0], plain[1]]) != expected_sequence
        || plain[2] != expected_protocol
    {
        return None;
    }
    Some(plain[3..].to_vec())
}

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];
const PERM: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

fn mix(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}
fn compress(h: &mut [u64; 8], bytes: &[u8], count: u128, last: bool) {
    let mut block = [0u8; 128];
    block[..bytes.len()].copy_from_slice(bytes);
    let mut m = [0u64; 16];
    for (dst, chunk) in m.iter_mut().zip(block.chunks_exact(8)) {
        let mut b = [0; 8];
        b.copy_from_slice(chunk);
        *dst = u64::from_le_bytes(b);
    }
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= count as u64;
    v[13] ^= (count >> 64) as u64;
    if last {
        v[14] = !v[14];
    }
    for s in PERM {
        mix(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        mix(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        mix(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        mix(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        mix(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        mix(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        mix(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        mix(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// BLAKE2b with a 32-byte output for synthetic interoperability checks.
pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut h = IV;
    h[0] ^= 0x0101_0020;
    let mut offset = 0usize;
    while data.len() - offset > 128 {
        offset += 128;
        compress(&mut h, &data[offset - 128..offset], offset as u128, false);
    }
    compress(&mut h, &data[offset..], data.len() as u128, true);
    let mut out = [0u8; 32];
    for (dst, word) in out.chunks_exact_mut(8).zip(h) {
        dst.copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// Reproduce the reference's DH key mixing; reject an all-zero shared secret.
/// This is unauthenticated unless an independently verified peer key is bound.
pub fn derive_key(
    private: &[u8; 32],
    peer_public: &[u8; 32],
    auth_key: Option<&[u8]>,
) -> Option<[u8; 32]> {
    if auth_key.is_some_and(|k| k.len() > 1024) {
        return None;
    }
    let public = existing_x25519::x25519_base(private);
    let shared = existing_x25519::x25519(private, peer_public);
    if shared.iter().fold(0u8, |a, b| a | b) == 0 {
        return None;
    }
    let mut material = Vec::with_capacity(96 + auth_key.map_or(0, <[u8]>::len));
    material.extend_from_slice(&shared);
    material.extend_from_slice(&public);
    material.extend_from_slice(peer_public);
    if let Some(k) = auth_key {
        material.extend_from_slice(k);
    }
    Some(blake2b_256(&material))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn secretbox_matches_independent_pynacl_at_block_boundaries() -> Result<(), &'static str> {
        let key = std::array::from_fn(|i| i as u8);
        let nonce = std::array::from_fn(|i| i as u8);
        for (len, expected) in [
            (0, "28fd82cd7386c5471a24d8ad2a525b6e"),
            (
                43,
                "ea3144b6612efebfafeda3c96b52f8785efe3a4cc3cfa417b33585356482449842b454cc983029f80fbb7d8f49dabffea3fad7f66195d32591a4ca",
            ),
            (
                129,
                "7820170511c8ca8a686beec9087966ef5efe3a4cc3cfa417b33585356482449842b454cc983029f80fbb7d8f49dabffea3fad7f66195d32591a4cab2564b856c13705aacc7a2ea7884261d86265ca9ca9cc1bd5a41538faa5cbbcb9a863ec6cda68280a8c64b78afc161c4517e66b9f1e13b66e53be7340f4703bb24f492316753bd50eea657e81ee5bb60fa01b42ac41b",
            ),
        ] {
            let msg: Vec<u8> = (0..len).map(|n| n as u8).collect();
            let boxed = seal(&key, &nonce, &msg).ok_or("seal")?;
            assert_eq!(hex(&boxed), expected);
            assert_eq!(open(&key, &nonce, &boxed), Some(msg));
            for i in 0..boxed.len() {
                let mut altered = boxed.clone();
                altered[i] ^= 1;
                assert_eq!(open(&key, &nonce, &altered), None);
            }
        }
        Ok(())
    }

    #[test]
    fn blake2b_matches_independent_hashlib_final_blocks() {
        for (len, expected) in [
            (
                0,
                "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
            ),
            (
                128,
                "c3582f71ebb2be66fa5dd750f80baae97554f3b015663c8be377cfcb2488c1d1",
            ),
            (
                129,
                "f7f3c46ba2564ff4c4c162da1f5b605f9f1c4aa6a20652a9f9a337c1a2f5b9c9",
            ),
        ] {
            let msg: Vec<u8> = (0..len).map(|n| n as u8).collect();
            assert_eq!(hex(&blake2b_256(&msg)), expected);
        }
    }

    #[test]
    fn dh_mixing_matches_pynacl_and_rejects_low_order() -> Result<(), &'static str> {
        let private = std::array::from_fn(|i| i as u8);
        let peer_private = std::array::from_fn(|i| (i + 32) as u8);
        let peer = existing_x25519::x25519_base(&peer_private);
        assert_eq!(
            hex(&peer),
            "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"
        );
        assert_eq!(
            hex(&derive_key(&private, &peer, None).ok_or("derive")?),
            "a874b380504a27e664722e83a9e0e01dd9cd6fb193f3c3610ca490f2c2fa2b36"
        );
        assert_eq!(derive_key(&private, &[0; 32], None), None);
        assert_eq!(derive_key(&private, &peer, Some(&[0; 1025])), None);
        Ok(())
    }

    #[test]
    fn rejects_truncation_wrong_key_nonce_and_oversized_input() -> Result<(), &'static str> {
        let boxed = seal(&[1; 32], &[2; 24], b"fixture").ok_or("seal")?;
        assert_eq!(open(&[1; 32], &[2; 24], &boxed[..15]), None);
        assert_eq!(open(&[3; 32], &[2; 24], &boxed), None);
        assert_eq!(open(&[1; 32], &[3; 24], &boxed), None);
        assert_eq!(seal(&[1; 32], &[2; 24], &vec![0; 65504]), None);
        Ok(())
    }

    #[test]
    fn rejects_authenticated_packets_with_inconsistent_inner_sequence_or_length()
    -> Result<(), &'static str> {
        let key = [1; 32];
        let nonce = [0; 24];
        // Authenticated with nonce zero, but claims inner sequence one.
        let cipher = seal(&key, &nonce, &[0, 1, 3, 42]).ok_or("seal")?;
        assert_eq!(open(&key, &nonce, &cipher), Some(vec![0, 1, 3, 42]));
        let mut frame = Vec::from([0, 22]);
        frame.extend_from_slice(&cipher);
        assert_eq!(open_packet(&key, 0, 3, &frame), None);
        frame[1] -= 1;
        assert_eq!(open_packet(&key, 0, 3, &frame), None);
        assert_eq!(open_packet(&key, 0, 3, &[0, 2]), None);
        Ok(())
    }

    #[test]
    fn synthetic_handshake_and_api_packets_match_pynacl_msgpack_reference()
    -> Result<(), &'static str> {
        // This is the published protocol default, not a credential or device identity.
        let key = [
            0xa7, 0x81, 0xf8, 0xa4, 0xa6, 0x27, 0x37, 0x3b, 0x70, 0x74, 0x57, 0x38, 0xcd, 0xff,
            0xdd, 0x1d, 0xe9, 0xae, 0x35, 0x25, 0x17, 0xc3, 0x74, 0xca, 0x9a, 0xfc, 0x21, 0x5c,
            0x39, 0xc6, 0x26, 0x37,
        ];
        let private = std::array::from_fn(|i| i as u8);
        let peer_private = std::array::from_fn(|i| (i + 32) as u8);
        let client = existing_x25519::x25519_base(&private);
        let peer = existing_x25519::x25519_base(&peer_private);
        let mut host_msg = vec![0x93, 0xa4, b'D', b'H', b'P', b'K', 0xc2, 0xc4, 0x20];
        host_msg.extend_from_slice(&client);
        let mut peer_msg = vec![0x93, 0xa4, b'D', b'H', b'P', b'K', 0xc3, 0xc4, 0x20];
        peer_msg.extend_from_slice(&peer);
        let auth = [0x92, 0xa4, b'A', b'U', b'T', b'H', 0xa2, b'D', b'H'];
        for (seq, protocol, msg, expected) in [
            (
                0,
                0,
                host_msg.as_slice(),
                "003e4e95e6b90ee828d1c417fc03c78a3142c830c5e8b6b487b37433f1dc35db56cc5957aaf3aa32a7d8c10965883f6e3d678a599cf70bc2a3e4c04ebdaf",
            ),
            (
                0,
                0,
                peer_msg.as_slice(),
                "003ed885a85aaedb0eca92f43fc1140e7d97c830c5e8b6b487b37432f1dc8f1be1b7d9800f404e3d2756f4ee3edece7252db15acf998331d1c082c60f7a4",
            ),
            (
                1,
                0,
                auth.as_slice(),
                "001ea9f8d0fae89980d5e2b2197f684085e840a219f803f07a7ed1e20ca4",
            ),
        ] {
            let frame = pack_packet(&key, seq, protocol, msg).ok_or("pack")?;
            assert_eq!(hex(&frame), expected);
            assert_eq!(open_packet(&key, seq, protocol, &frame), Some(msg.to_vec()));
            assert_eq!(open_packet(&key, seq + 1, protocol, &frame), None);
            assert_eq!(open_packet(&key, seq, protocol + 1, &frame), None);
            let mut trailing = frame.clone();
            trailing.push(0);
            assert_eq!(open_packet(&key, seq, protocol, &trailing), None);
        }
        let derived = derive_key(&private, &peer, None).ok_or("derive")?;
        let api = pack_packet(&derived, 2, 3, b"synthetic").ok_or("API packet")?;
        assert_eq!(
            hex(&api),
            "001e2f7bdd0bf21fecde1e19e32419a7f6b37c23ad7cbe66c1a2db3a31ae"
        );
        assert_eq!(
            open_packet(&derived, 2, 3, &api),
            Some(b"synthetic".to_vec())
        );
        assert_eq!(open_packet(&key, 2, 3, &api), None);
        Ok(())
    }
}
