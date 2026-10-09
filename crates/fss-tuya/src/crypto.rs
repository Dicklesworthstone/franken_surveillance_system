//! First-party AES-128 (ECB raw/PKCS7 and GCM) plus HMAC-SHA256 over
//! `fss_core::sha256`. The AES core is the same table-based safe-Rust cipher
//! already qualified in `fss-reference`'s Tuya beacon decoder (FIPS-197
//! Appendix vectors in `tests/crypto_contract.rs`); the forward direction and
//! GCM (NIST SP 800-38D, 96-bit nonces — the only size Tuya uses) are added
//! here. No constant-time guarantees are claimed: this is a lab-qualified
//! interoperable implementation for owner devices on owner LANs, not a
//! side-channel-hardened library.

/// AES-128 cipher with precomputed round keys.
pub struct Aes128 {
    rk: [[u32; 4]; 11],
}

impl Aes128 {
    /// Expands a 16-byte key (FIPS-197 §5.2).
    #[must_use]
    pub fn new(key: &[u8; 16]) -> Self {
        Self { rk: expand_key(key) }
    }

    /// Encrypts one 16-byte block.
    #[must_use]
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut s = load_state(block);
        add_round_key(&mut s, &self.rk[0]);
        for rk in &self.rk[1..10] {
            sub_bytes(&mut s);
            shift_rows(&mut s);
            mix_columns(&mut s);
            add_round_key(&mut s, rk);
        }
        sub_bytes(&mut s);
        shift_rows(&mut s);
        add_round_key(&mut s, &self.rk[10]);
        store_state(&s)
    }

    /// Decrypts one 16-byte block (direct inverse cipher).
    #[must_use]
    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut s = load_state(block);
        add_round_key(&mut s, &self.rk[10]);
        for round in (1..10).rev() {
            inv_shift_rows(&mut s);
            inv_sub_bytes(&mut s);
            add_round_key(&mut s, &self.rk[round]);
            inv_mix_columns(&mut s);
        }
        inv_shift_rows(&mut s);
        inv_sub_bytes(&mut s);
        add_round_key(&mut s, &self.rk[0]);
        store_state(&s)
    }
}

fn load_state(block: &[u8; 16]) -> [[u8; 4]; 4] {
    let mut s = [[0u8; 4]; 4];
    for c in 0..4 {
        for r in 0..4 {
            s[r][c] = block[c * 4 + r];
        }
    }
    s
}

fn store_state(s: &[[u8; 4]; 4]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for c in 0..4 {
        for r in 0..4 {
            out[c * 4 + r] = s[r][c];
        }
    }
    out
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    p
}

fn expand_key(key: &[u8; 16]) -> [[u32; 4]; 11] {
    const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];
    let mut w = [[0u32; 4]; 11];
    for i in 0..4 {
        w[0][i] = u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    for round in 1..11 {
        let prev = w[round - 1];
        let mut temp = prev[3];
        temp = sub_word(temp.rotate_left(8));
        temp ^= u32::from(RCON[round - 1]) << 24;
        let mut cur = [temp ^ prev[0], 0, 0, 0];
        for i in 1..4 {
            cur[i] = cur[i - 1] ^ prev[i];
        }
        w[round] = cur;
    }
    w
}

fn sub_word(x: u32) -> u32 {
    u32::from_be_bytes([
        SBOX[((x >> 24) & 0xFF) as usize],
        SBOX[((x >> 16) & 0xFF) as usize],
        SBOX[((x >> 8) & 0xFF) as usize],
        SBOX[(x & 0xFF) as usize],
    ])
}

fn add_round_key(s: &mut [[u8; 4]; 4], rk: &[u32; 4]) {
    for c in 0..4 {
        let w = rk[c].to_be_bytes();
        for r in 0..4 {
            s[r][c] ^= w[r];
        }
    }
}

fn sub_bytes(s: &mut [[u8; 4]; 4]) {
    for r in 0..4 {
        for c in 0..4 {
            s[r][c] = SBOX[s[r][c] as usize];
        }
    }
}

fn inv_sub_bytes(s: &mut [[u8; 4]; 4]) {
    for r in 0..4 {
        for c in 0..4 {
            s[r][c] = INV_SBOX[s[r][c] as usize];
        }
    }
}

/// Forward cipher: row r cyclically shifts LEFT by r (FIPS-197 §5.1.2).
fn shift_rows(s: &mut [[u8; 4]; 4]) {
    for r in 1..4 {
        let row = s[r];
        for c in 0..4 {
            s[r][c] = row[(c + r) % 4];
        }
    }
}

/// Inverse cipher: row r cyclically shifts RIGHT by r (FIPS-197 §5.3.2).
fn inv_shift_rows(s: &mut [[u8; 4]; 4]) {
    for r in 1..4 {
        let row = s[r];
        for c in 0..4 {
            s[r][c] = row[(c + 4 - r) % 4];
        }
    }
}

fn mix_columns(s: &mut [[u8; 4]; 4]) {
    for c in 0..4 {
        let a0 = s[0][c];
        let a1 = s[1][c];
        let a2 = s[2][c];
        let a3 = s[3][c];
        s[0][c] = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3;
        s[1][c] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3;
        s[2][c] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3);
        s[3][c] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2);
    }
}

fn inv_mix_columns(s: &mut [[u8; 4]; 4]) {
    for c in 0..4 {
        let a0 = s[0][c];
        let a1 = s[1][c];
        let a2 = s[2][c];
        let a3 = s[3][c];
        s[0][c] = gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9);
        s[1][c] = gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13);
        s[2][c] = gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11);
        s[3][c] = gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14);
    }
}

/// AES-128-ECB encrypt of a multiple-of-16 input (no padding added).
/// Returns `None` when the input is not block-aligned.
#[must_use]
pub fn aes128_ecb_encrypt_raw(key: &[u8; 16], data: &[u8]) -> Option<Vec<u8>> {
    if !data.len().is_multiple_of(16) {
        return None;
    }
    let cipher = Aes128::new(key);
    let mut out = Vec::with_capacity(data.len().max(16));
    for block in data.chunks(16) {
        let mut b = [0u8; 16];
        b.copy_from_slice(block);
        out.extend_from_slice(&cipher.encrypt_block(&b));
    }
    Some(out)
}

/// AES-128-ECB decrypt with no padding verification (Tuya broadcast
/// semantics: trailing bytes after the JSON terminator are noise).
#[must_use]
pub fn aes128_ecb_decrypt_raw(key: &[u8; 16], data: &[u8]) -> Option<Vec<u8>> {
    if !data.len().is_multiple_of(16) || data.is_empty() {
        return None;
    }
    let cipher = Aes128::new(key);
    let mut out = Vec::with_capacity(data.len());
    for block in data.chunks(16) {
        let mut b = [0u8; 16];
        b.copy_from_slice(block);
        out.extend_from_slice(&cipher.decrypt_block(&b));
    }
    Some(out)
}

/// PKCS7 padding per RFC 5652 §6.3 (always adds 1..=16 bytes).
#[must_use]
pub fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
    let padnum = 16 - (data.len() % 16);
    let mut out = Vec::with_capacity(data.len() + padnum);
    out.extend_from_slice(data);
    out.extend(std::iter::repeat_n(padnum as u8, padnum));
    out
}

/// PKCS7 unpad; `None` when the padding is structurally invalid.
#[must_use]
pub fn pkcs7_unpad(data: &[u8]) -> Option<&[u8]> {
    let &last = data.last()?;
    let padlen = usize::from(last);
    if !(1..=16).contains(&padlen) || padlen > data.len() {
        return None;
    }
    Some(&data[..data.len() - padlen])
}

/// AES-128-ECB encrypt with PKCS7 padding (the 3.1/3.3 payload shape).
#[must_use]
pub fn aes128_ecb_encrypt_pkcs7(key: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let padded = pkcs7_pad(data);
    // padded is always block-aligned, so this never falls back.
    aes128_ecb_encrypt_raw(key, &padded).unwrap_or_default()
}

/// AES-128-ECB decrypt with PKCS7 unpadding (structural validation only).
#[must_use]
pub fn aes128_ecb_decrypt_pkcs7(key: &[u8; 16], data: &[u8]) -> Option<Vec<u8>> {
    let raw = aes128_ecb_decrypt_raw(key, data)?;
    Some(pkcs7_unpad(&raw)?.to_vec())
}

// ---- AES-128-GCM (NIST SP 800-38D; 96-bit nonces only) -------------------

const GCM_R: u128 = 0xE100_0000_0000_0000_0000_0000_0000_0000;

/// GF(2^128) multiplication, SP 800-38D §6.3 Algorithm 1.
fn gf128_mul(x: u128, y: u128) -> u128 {
    let mut z = 0u128;
    let mut v = y;
    for i in 0..128 {
        if (x >> (127 - i)) & 1 == 1 {
            z ^= v;
        }
        v = if v & 1 == 0 { v >> 1 } else { (v >> 1) ^ GCM_R };
    }
    z
}

fn ghash(h: u128, aad: &[u8], ciphertext: &[u8]) -> u128 {
    let mut x = 0u128;
    let mut feed = |block: &[u8]| {
        let mut b = [0u8; 16];
        b[..block.len()].copy_from_slice(block);
        x = gf128_mul(x ^ u128::from_be_bytes(b), h);
    };
    for block in aad.chunks(16) {
        feed(block);
    }
    for block in ciphertext.chunks(16) {
        feed(block);
    }
    let lens = ((aad.len() as u64) * 8).to_be_bytes();
    let lenc = ((ciphertext.len() as u64) * 8).to_be_bytes();
    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&lens);
    len_block[8..].copy_from_slice(&lenc);
    feed(&len_block);
    x
}

/// Increments the rightmost 32 bits of the counter block (SP 800-38D §6.2).
fn inc32(counter: &mut [u8; 16]) {
    let mut n = u32::from_be_bytes([counter[12], counter[13], counter[14], counter[15]]);
    n = n.wrapping_add(1);
    counter[12..].copy_from_slice(&n.to_be_bytes());
}

fn gctr(cipher: &Aes128, icb: [u8; 16], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut counter = icb;
    for block in data.chunks(16) {
        let ks = cipher.encrypt_block(&counter);
        for (i, &b) in block.iter().enumerate() {
            out.push(b ^ ks[i]);
        }
        inc32(&mut counter);
    }
    out
}

/// AES-128-GCM encrypt: returns `ciphertext || tag(16)` (the caller prepends
/// the 12-byte nonce on the wire, per Tuya 6699 framing).
#[must_use]
pub fn aes128_gcm_encrypt(key: &[u8; 16], iv: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(key);
    let h = u128::from_be_bytes(cipher.encrypt_block(&[0u8; 16]));
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(iv);
    j0[15] = 1;
    let mut ctr = j0;
    inc32(&mut ctr);
    let ciphertext = gctr(&cipher, ctr, plaintext);
    let s = ghash(h, aad, &ciphertext);
    let tag_full = gctr(&cipher, j0, &s.to_be_bytes());
    let mut out = ciphertext;
    out.extend_from_slice(&tag_full[..16]);
    out
}

/// AES-128-GCM decrypt over `ciphertext || tag(16)`; `None` on tag mismatch.
/// The tag comparison is branch-free (accumulated XOR) though the AES core
/// itself is table-based; see the module-level caveat.
#[must_use]
pub fn aes128_gcm_decrypt(
    key: &[u8; 16],
    iv: &[u8; 12],
    aad: &[u8],
    ct_and_tag: &[u8],
) -> Option<Vec<u8>> {
    if ct_and_tag.len() < 16 {
        return None;
    }
    let (ciphertext, tag) = ct_and_tag.split_at(ct_and_tag.len() - 16);
    let cipher = Aes128::new(key);
    let h = u128::from_be_bytes(cipher.encrypt_block(&[0u8; 16]));
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(iv);
    j0[15] = 1;
    let s = ghash(h, aad, ciphertext);
    let tag_full = gctr(&cipher, j0, &s.to_be_bytes());
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= tag[i] ^ tag_full[i];
    }
    if diff != 0 {
        return None;
    }
    let mut ctr = j0;
    inc32(&mut ctr);
    Some(gctr(&cipher, ctr, ciphertext))
}

// ---- HMAC-SHA256 (RFC 2104 over fss-core's qualified SHA-256) ------------

/// HMAC-SHA256 (RFC 2104, 64-byte block size).
#[must_use]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let h = fss_core::sha256(key);
        k[..32].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + data.len());
    inner.extend(k.iter().map(|b| b ^ 0x36));
    inner.extend_from_slice(data);
    let inner_hash = fss_core::sha256(&inner);
    let mut outer = Vec::with_capacity(96);
    outer.extend(k.iter().map(|b| b ^ 0x5C));
    outer.extend_from_slice(&inner_hash);
    fss_core::sha256(&outer)
}

#[rustfmt::skip]
const SBOX: [u8; 256] = [
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16,
];

#[rustfmt::skip]
const INV_SBOX: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        t[SBOX[i] as usize] = i as u8;
        i += 1;
    }
    t
};
