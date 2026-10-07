//! ChaCha20 and Poly1305 with AEAD composition (RFC 8439), first-party.
//!
//! ChaCha20 block/stream from RFC 8439 §2.3/§2.4; Poly1305 from §2.5 using
//! the public-domain poly1305-donna 26-bit-limb design; AEAD from §2.8.
//! Verified against the RFC's published test vectors in this crate's tests.

// ---------------------------------------------------------------------------
// ChaCha20
// ---------------------------------------------------------------------------

#[inline]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[0] = 0x6170_7865;
    state[1] = 0x3320_646e;
    state[2] = 0x7962_2d32;
    state[3] = 0x6b20_6574;
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    state[12] = counter;
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes([nonce[4 * i], nonce[4 * i + 1], nonce[4 * i + 2], nonce[4 * i + 3]]);
    }
    let initial = state;
    for _ in 0..10 {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        let v = state[i].wrapping_add(initial[i]);
        out[4 * i..4 * i + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

/// ChaCha20 stream cipher: XOR `data` with the keystream starting at
/// block `counter` (RFC 8439 §2.4).
pub fn chacha20_xor(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    let mut ctr = counter;
    for chunk in data.chunks_mut(64) {
        let stream = chacha20_block(key, ctr, nonce);
        ctr = ctr.wrapping_add(1);
        for (i, b) in chunk.iter_mut().enumerate() {
            *b ^= stream[i];
        }
    }
}

// ---------------------------------------------------------------------------
// Poly1305 (poly1305-donna-32 style, 26-bit limbs)
// ---------------------------------------------------------------------------

struct Poly1305 {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
    leftover: usize,
    buffer: [u8; 16],
    final_: bool,
}

impl Poly1305 {
    fn new(key: &[u8; 32]) -> Self {
        let mut r = [0u32; 5];
        r[0] = (u32::from_le_bytes([key[0], key[1], key[2], key[3]])) & 0x3ff_ffff;
        r[1] = (u32::from_le_bytes([key[3], key[4], key[5], key[6]]) >> 2) & 0x3ff_ff03;
        r[2] = (u32::from_le_bytes([key[6], key[7], key[8], key[9]]) >> 4) & 0x3ff_c0ff;
        r[3] = (u32::from_le_bytes([key[9], key[10], key[11], key[12]]) >> 6) & 0x3f0_3fff;
        r[4] = (u32::from_le_bytes([key[12], key[13], key[14], key[15]]) >> 8) & 0x00f_ffff;
        // pad = key[16..32] as four LE u32 (the "+" half of the one-time key)
        let pad = [
            u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
            u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
            u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
            u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
        ];
        Self {
            r,
            h: [0; 5],
            pad,
            leftover: 0,
            buffer: [0; 16],
            final_: false,
        }
    }

    fn block(&mut self, m: &[u8], last: bool) {
        let hibit: u32 = if last { 0 } else { 1 << 24 };
        let r = self.r;
        let s = [r[1] * 5, r[2] * 5, r[3] * 5, r[4] * 5];
        let mut h = self.h;
        h[0] += (u32::from_le_bytes([m[0], m[1], m[2], m[3]])) & 0x3ff_ffff;
        h[1] += (u32::from_le_bytes([m[3], m[4], m[5], m[6]]) >> 2) & 0x3ff_ffff;
        h[2] += (u32::from_le_bytes([m[6], m[7], m[8], m[9]]) >> 4) & 0x3ff_ffff;
        h[3] += (u32::from_le_bytes([m[9], m[10], m[11], m[12]]) >> 6) & 0x3ff_ffff;
        h[4] += (u32::from_le_bytes([m[12], m[13], m[14], m[15]]) >> 8) | hibit;
        let d0 = h[0] as u64 * r[0] as u64
            + h[1] as u64 * s[3] as u64
            + h[2] as u64 * s[2] as u64
            + h[3] as u64 * s[1] as u64
            + h[4] as u64 * s[0] as u64;
        let mut d1 = h[0] as u64 * r[1] as u64
            + h[1] as u64 * r[0] as u64
            + h[2] as u64 * s[3] as u64
            + h[3] as u64 * s[2] as u64
            + h[4] as u64 * s[1] as u64;
        let mut d2 = h[0] as u64 * r[2] as u64
            + h[1] as u64 * r[1] as u64
            + h[2] as u64 * r[0] as u64
            + h[3] as u64 * s[3] as u64
            + h[4] as u64 * s[2] as u64;
        let mut d3 = h[0] as u64 * r[3] as u64
            + h[1] as u64 * r[2] as u64
            + h[2] as u64 * r[1] as u64
            + h[3] as u64 * r[0] as u64
            + h[4] as u64 * s[3] as u64;
        let mut d4 = h[0] as u64 * r[4] as u64
            + h[1] as u64 * r[3] as u64
            + h[2] as u64 * r[2] as u64
            + h[3] as u64 * r[1] as u64
            + h[4] as u64 * r[0] as u64;
        let mut c = (d0 >> 26) as u32;
        h[0] = (d0 & 0x3ff_ffff) as u32;
        d1 += c as u64;
        c = (d1 >> 26) as u32;
        h[1] = (d1 & 0x3ff_ffff) as u32;
        d2 += c as u64;
        c = (d2 >> 26) as u32;
        h[2] = (d2 & 0x3ff_ffff) as u32;
        d3 += c as u64;
        c = (d3 >> 26) as u32;
        h[3] = (d3 & 0x3ff_ffff) as u32;
        d4 += c as u64;
        c = (d4 >> 26) as u32;
        h[4] = (d4 & 0x3ff_ffff) as u32;
        h[0] += c * 5;
        c = h[0] >> 26;
        h[0] &= 0x3ff_ffff;
        h[1] += c;
        self.h = h;
    }

    fn update(&mut self, mut data: &[u8]) {
        if self.leftover > 0 {
            let take = (16 - self.leftover).min(data.len());
            self.buffer[self.leftover..self.leftover + take].copy_from_slice(&data[..take]);
            self.leftover += take;
            data = &data[take..];
            if self.leftover == 16 {
                let m = self.buffer;
                self.block(&m, false);
                self.leftover = 0;
            }
        }
        while data.len() >= 16 {
            let (block, rest) = data.split_at(16);
            let mut m = [0u8; 16];
            m.copy_from_slice(block);
            self.block(&m, false);
            data = rest;
        }
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.leftover = data.len();
        }
    }

    fn finish(mut self) -> [u8; 16] {
        if self.leftover > 0 {
            let i = self.leftover;
            self.buffer[i] = 1;
            for b in self.buffer[i + 1..16].iter_mut() {
                *b = 0;
            }
            self.final_ = true;
            let m = self.buffer;
            self.block(&m, true);
        }
        // full carry
        let mut h = self.h;
        let mut c = h[1] >> 26;
        h[1] &= 0x3ff_ffff;
        h[2] += c;
        c = h[2] >> 26;
        h[2] &= 0x3ff_ffff;
        h[3] += c;
        c = h[3] >> 26;
        h[3] &= 0x3ff_ffff;
        h[4] += c;
        c = h[4] >> 26;
        h[4] &= 0x3ff_ffff;
        h[0] += c * 5;
        c = h[0] >> 26;
        h[0] &= 0x3ff_ffff;
        h[1] += c;
        // compute h + -p = h + 5 - 2^130 (poly1305-donna form)
        let mut g = [0u32; 5];
        g[0] = h[0].wrapping_add(5);
        let mut c = g[0] >> 26;
        g[0] &= 0x3ff_ffff;
        for i in 1..4 {
            g[i] = h[i].wrapping_add(c);
            c = g[i] >> 26;
            g[i] &= 0x3ff_ffff;
        }
        g[4] = h[4].wrapping_add(c).wrapping_sub(1 << 26);
        // select h if h < p, else g: g[4] underflowed (bit 31 set) iff h < p
        let mask = (g[4] >> 31).wrapping_sub(1); // 0 if h < p, 0xFFFF_FFFF if h >= p
        for i in 0..5 {
            h[i] = (h[i] & !mask) | (g[i] & mask);
        }
        // h % 2^128
        let h0 = h[0] | (h[1] << 26);
        let h1 = (h[1] >> 6) | (h[2] << 20);
        let h2 = (h[2] >> 12) | (h[3] << 14);
        let h3 = (h[3] >> 18) | (h[4] << 8);
        let mut out = [0u8; 16];
        // (h + pad) mod 2^128: 64-bit intermediates to propagate carries
        let f0 = h0 as u64 + self.pad[0] as u64;
        let f1 = h1 as u64 + self.pad[1] as u64 + (f0 >> 32);
        let f2 = h2 as u64 + self.pad[2] as u64 + (f1 >> 32);
        let f3 = h3 as u64 + self.pad[3] as u64 + (f2 >> 32);
        let words = [f0 as u32, f1 as u32, f2 as u32, f3 as u32];
        for i in 0..4 {
            out[4 * i..4 * i + 4].copy_from_slice(&words[i].to_le_bytes());
        }
        out
    }
}

/// One-shot Poly1305 MAC (RFC 8439 §2.5).
#[must_use]
pub fn poly1305(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    let mut p = Poly1305::new(key);
    p.update(data);
    p.finish()
}

// ---------------------------------------------------------------------------
// AEAD_CHACHA20_POLY1305 (RFC 8439 §2.8)
// ---------------------------------------------------------------------------

fn poly_key(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let block = chacha20_block(key, 0, nonce);
    let mut k = [0u8; 32];
    k.copy_from_slice(&block[..32]);
    k
}

fn mac_data(aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut d = Vec::with_capacity(aad.len() + 16 + ciphertext.len() + 16);
    d.extend_from_slice(aad);
    while d.len() % 16 != 0 {
        d.push(0);
    }
    d.extend_from_slice(ciphertext);
    while d.len() % 16 != 0 {
        d.push(0);
    }
    d.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    d.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    d
}

/// AEAD encrypt: returns (ciphertext, tag) (RFC 8439 §2.8.1).
#[must_use]
pub fn aead_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    let mut ct = plaintext.to_vec();
    chacha20_xor(key, 1, nonce, &mut ct);
    let pkey = poly_key(key, nonce);
    let tag = poly1305(&pkey, &mac_data(aad, &ct));
    (ct, tag)
}

/// AEAD decrypt: verifies tag, returns plaintext or `None` (RFC 8439 §2.8.2).
#[must_use]
pub fn aead_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Option<Vec<u8>> {
    let pkey = poly_key(key, nonce);
    let want = poly1305(&pkey, &mac_data(aad, ciphertext));
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= want[i] ^ tag[i];
    }
    if diff != 0 {
        return None;
    }
    let mut pt = ciphertext.to_vec();
    chacha20_xor(key, 1, nonce, &mut pt);
    Some(pt)
}
