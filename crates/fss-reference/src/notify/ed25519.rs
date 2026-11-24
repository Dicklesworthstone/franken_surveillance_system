#![forbid(unsafe_code)]
//! First-party pure-Rust FIPS 180-4 SHA-512 and RFC 8032 Ed25519 keygen, signing, and verification.
//!
//! Used for TLS 1.3 `CertificateVerify`, X.509 certificate signature verification, and
//! deterministic loopback test CA/leaf certificate generation. Secret seeds are wrapped in
//! [`Zeroizing`] and never formatted in `Debug` or `Display`.

use core::fmt;

use fss_vault::EntropySource;
use zeroize::Zeroizing;

use super::x25519::Fe;

/// Ed25519 subgroup order `L = 2^252 + 27742317777372353535851937790883648493` in 4x64 LE limbs.
const L_LIMBS: [u64; 4] = [
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0x0000_0000_0000_0000,
    0x1000_0000_0000_0000,
];

/// Square root of `-1` modulo `2^255 - 19` (`2^((p - 1) / 4) mod p`) in 32-byte LE form.
const SQRT_M1_BYTES: [u8; 32] = [
    0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
    0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
];

/// Ed25519 basepoint `B` compressed encoding (`y = 4/5 mod p`, even `x`).
const BASEPOINT_BYTES: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// FIPS 180-4 SHA-512 initial state constants.
const SHA512_IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

/// FIPS 180-4 SHA-512 round constants.
const SHA512_K: [u64; 80] = [
    0x428a_2f98_d728_ae22,
    0x7137_4491_23ef_65cd,
    0xb5c0_fbcf_ec4d_3b2f,
    0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538,
    0x59f1_11f1_b605_d019,
    0x923f_82a4_af19_4f9b,
    0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242,
    0x1283_5b01_4570_6fbe,
    0x2431_85be_4ee4_b28c,
    0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f,
    0x80de_b1fe_3b16_96b1,
    0x9bdc_06a7_25c7_1235,
    0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2,
    0xefbe_4786_384f_25e3,
    0x0fc1_9dc6_8b8c_d5b5,
    0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275,
    0x4a74_84aa_6ea6_e483,
    0x5cb0_a9dc_bd41_fbd4,
    0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab,
    0xa831_c66d_2db4_3210,
    0xb003_27c8_98fb_213f,
    0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2,
    0xd5a7_9147_930a_a725,
    0x06ca_6351_e003_826f,
    0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc,
    0x2e1b_2138_5c26_c926,
    0x4d2c_6dfc_5ac4_2aed,
    0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de,
    0x766a_0abb_3c77_b2a8,
    0x81c2_c92e_47ed_aee6,
    0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364,
    0xa81a_664b_bc42_3001,
    0xc24b_8b70_d0f8_9791,
    0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218,
    0xd699_0624_5565_a910,
    0xf40e_3585_5771_202a,
    0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8,
    0x1e37_6c08_5141_ab53,
    0x2748_774c_df8e_eb99,
    0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63,
    0x4ed8_aa4a_e341_8acb,
    0x5b9c_ca4f_7763_e373,
    0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc,
    0x78a5_636f_4317_2f60,
    0x84c8_7814_a1f0_ab72,
    0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28,
    0xa450_6ceb_de82_bde9,
    0xbef9_a3f7_b2c6_7915,
    0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c,
    0xd186_b8c7_21c0_c207,
    0xeada_7dd6_cde0_eb1e,
    0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba,
    0x0a63_7dc5_a2c8_98a6,
    0x113f_9804_bef9_0dae,
    0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84,
    0x32ca_ab7b_40c7_2493,
    0x3c9e_be0a_15c9_bebc,
    0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6,
    0x597f_299c_fc65_7e2a,
    0x5fcb_6fab_3ad6_faec,
    0x6c44_198c_4a47_5817,
];

/// Errors returned by Ed25519 key generation or signature verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ed25519Error {
    /// Explicit entropy source failed to supply random bytes.
    EntropyFailed,
    /// Encoded public key is non-canonical or does not lie on Edwards25519.
    InvalidPublicKey,
    /// Encoded signature is malformed, non-canonical (`S >= L`), or invalid.
    InvalidSignature,
}

impl fmt::Display for Ed25519Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EntropyFailed => f.write_str("Ed25519 entropy generation failed"),
            Self::InvalidPublicKey => f.write_str("invalid Ed25519 public key encoding"),
            Self::InvalidSignature => f.write_str("Ed25519 signature verification failed"),
        }
    }
}

impl std::error::Error for Ed25519Error {}

/// Pure-Rust FIPS 180-4 SHA-512 streaming hasher.
#[derive(Clone)]
pub struct Sha512Hasher {
    state: [u64; 8],
    buffer: [u8; 128],
    buffer_len: usize,
    total_len: u128,
}

impl Default for Sha512Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha512Hasher {
    /// Initializes a new FIPS 180-4 SHA-512 hasher.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: SHA512_IV,
            buffer: [0_u8; 128],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Absorbs input bytes into the SHA-512 state.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.saturating_add(data.len() as u128);
        if self.buffer_len > 0 {
            let need = 128 - self.buffer_len;
            if data.len() < need {
                self.buffer[self.buffer_len..self.buffer_len + data.len()].copy_from_slice(data);
                self.buffer_len += data.len();
                return;
            }
            self.buffer[self.buffer_len..128].copy_from_slice(&data[..need]);
            sha512_compress(&mut self.state, &self.buffer);
            self.buffer_len = 0;
            data = &data[need..];
        }
        let (blocks, rem) = data.as_chunks::<128>();
        for block in blocks {
            sha512_compress(&mut self.state, block);
        }
        if !rem.is_empty() {
            self.buffer[..rem.len()].copy_from_slice(rem);
            self.buffer_len = rem.len();
        }
    }

    /// Finalizes the hash and returns the 64-byte SHA-512 digest.
    #[must_use]
    pub fn finalize(mut self) -> [u8; 64] {
        let bit_len = self.total_len.wrapping_mul(8);
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        if self.buffer_len > 112 {
            self.buffer[self.buffer_len..128].fill(0);
            sha512_compress(&mut self.state, &self.buffer);
            self.buffer = [0_u8; 128];
            self.buffer_len = 0;
        }
        self.buffer[self.buffer_len..112].fill(0);
        self.buffer[112..128].copy_from_slice(&bit_len.to_be_bytes());
        sha512_compress(&mut self.state, &self.buffer);

        let mut out = [0_u8; 64];
        for (idx, word) in self.state.iter().enumerate() {
            out[idx * 8..idx * 8 + 8].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// One-shot SHA-512 over `input`.
    #[must_use]
    pub fn digest(input: &[u8]) -> [u8; 64] {
        let mut h = Self::new();
        h.update(input);
        h.finalize()
    }
}

fn sha512_compress(state: &mut [u64; 8], block: &[u8; 128]) {
    let mut w = [0_u64; 80];
    let (chunks, _) = block.as_chunks::<8>();
    for (slot, chunk) in w.iter_mut().take(16).zip(chunks) {
        *slot = u64::from_be_bytes(*chunk);
    }
    for i in 16..80 {
        let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
        let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..80 {
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA512_K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// RFC 8032 Ed25519 private signing key with zeroized seed and redacted formatting.
#[derive(Clone)]
pub struct Ed25519SigningKey {
    seed: Zeroizing<[u8; 32]>,
    public_bytes: [u8; 32],
}

impl Ed25519SigningKey {
    /// Generates a fresh Ed25519 signing key using an explicit [`EntropySource`].
    pub fn generate(entropy: &mut dyn EntropySource) -> Result<Self, Ed25519Error> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        entropy
            .fill_bytes(&mut *seed)
            .map_err(|_| Ed25519Error::EntropyFailed)?;
        Ok(Self::from_seed(*seed))
    }

    /// Constructs a signing key deterministically from a 32-byte RFC 8032 seed.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let expanded = Zeroizing::new(Sha512Hasher::digest(&seed));
        let mut a = Zeroizing::new([0_u8; 32]);
        a.copy_from_slice(&expanded[0..32]);
        clamp_ed25519_scalar(&mut a);
        let public_bytes = basepoint().scalar_mul(&a).to_bytes();
        Self {
            seed: Zeroizing::new(seed),
            public_bytes,
        }
    }

    /// Returns the paired 32-byte Ed25519 verifying key.
    #[must_use]
    pub const fn verifying_key(&self) -> Ed25519VerifyingKey {
        Ed25519VerifyingKey(self.public_bytes)
    }

    /// Computes a deterministic 64-byte RFC 8032 Ed25519 signature over `message`.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let expanded = Zeroizing::new(Sha512Hasher::digest(&*self.seed));
        let mut a_bytes = Zeroizing::new([0_u8; 32]);
        a_bytes.copy_from_slice(&expanded[0..32]);
        clamp_ed25519_scalar(&mut a_bytes);
        let prefix = &expanded[32..64];

        let mut r_hasher = Sha512Hasher::new();
        r_hasher.update(prefix);
        r_hasher.update(message);
        let r_digest = Zeroizing::new(r_hasher.finalize());
        let r_scalar = Zeroizing::new(reduce_512_mod_l(&r_digest));
        let r_bytes = basepoint().scalar_mul(&r_scalar).to_bytes();

        let mut k_hasher = Sha512Hasher::new();
        k_hasher.update(&r_bytes);
        k_hasher.update(&self.public_bytes);
        k_hasher.update(message);
        let k_scalar = reduce_512_mod_l(&k_hasher.finalize());

        let s_bytes = mul_add_mod_l(&k_scalar, &a_bytes, &r_scalar);

        let mut sig = [0_u8; 64];
        sig[0..32].copy_from_slice(&r_bytes);
        sig[32..64].copy_from_slice(&s_bytes);
        sig
    }
}

impl fmt::Debug for Ed25519SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519SigningKey")
            .field("public_key", &self.public_bytes)
            .field("seed", &"[REDACTED]")
            .finish()
    }
}

/// 32-byte compressed RFC 8032 Ed25519 public verifying key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ed25519VerifyingKey(pub [u8; 32]);

impl Ed25519VerifyingKey {
    /// Parses and validates a 32-byte compressed Ed25519 public key.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, Ed25519Error> {
        let _ = ExtPoint::from_bytes(&bytes).ok_or(Ed25519Error::InvalidPublicKey)?;
        Ok(Self(bytes))
    }

    /// Returns the raw 32-byte compressed public key.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Verifies a 64-byte RFC 8032 Ed25519 signature strictly (rejecting non-canonical `S >= L`).
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Ed25519Error> {
        if signature.len() != 64 {
            return Err(Ed25519Error::InvalidSignature);
        }
        let mut r_bytes = [0_u8; 32];
        let mut s_bytes = [0_u8; 32];
        r_bytes.copy_from_slice(&signature[0..32]);
        s_bytes.copy_from_slice(&signature[32..64]);

        if !scalar_is_canonical(&s_bytes) {
            return Err(Ed25519Error::InvalidSignature);
        }
        let a_point = ExtPoint::from_bytes(&self.0).ok_or(Ed25519Error::InvalidPublicKey)?;
        let r_point = ExtPoint::from_bytes(&r_bytes).ok_or(Ed25519Error::InvalidSignature)?;

        let mut k_hasher = Sha512Hasher::new();
        k_hasher.update(&r_bytes);
        k_hasher.update(&self.0);
        k_hasher.update(message);
        let k_scalar = reduce_512_mod_l(&k_hasher.finalize());

        let lhs = basepoint().scalar_mul(&s_bytes);
        let rhs = r_point.add(&a_point.scalar_mul(&k_scalar));
        if fss_vault::constant_time_eq(&lhs.to_bytes(), &rhs.to_bytes()) {
            Ok(())
        } else {
            Err(Ed25519Error::InvalidSignature)
        }
    }
}

fn clamp_ed25519_scalar(bytes: &mut [u8; 32]) {
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
}

/// Extended twisted Edwards point `(X : Y : Z : T)` on `-x^2 + y^2 = 1 + d*x^2*y^2`.
#[derive(Clone, Copy)]
struct ExtPoint {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

fn edwards_d() -> Fe {
    Fe::from_u64(121_665)
        .neg()
        .mul(&Fe::from_u64(121_666).invert())
}

fn basepoint() -> ExtPoint {
    ExtPoint::from_bytes(&BASEPOINT_BYTES).unwrap_or(ExtPoint::IDENTITY)
}

impl ExtPoint {
    const IDENTITY: Self = Self {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        if !Fe::is_canonical_field_bytes(bytes) {
            return None;
        }
        let sign = (bytes[31] >> 7) & 1;
        let y = Fe::from_bytes_masked(bytes);
        let y2 = y.square();
        let u = y2.sub(&Fe::ONE);
        let d = edwards_d();
        let v = d.mul(&y2).add(&Fe::ONE);
        let v3 = v.square().mul(&v);
        let v7 = v3.square().mul(&v);
        let mut x = u.mul(&v3).mul(&u.mul(&v7).pow_252_3());

        let vx2 = v.mul(&x.square());
        if !vx2.ct_eq(&u) {
            if vx2.ct_eq(&u.neg()) {
                let sqrt_m1 = Fe::from_bytes_masked(&SQRT_M1_BYTES);
                x = x.mul(&sqrt_m1);
            } else {
                return None;
            }
        }
        let x_bytes = x.to_bytes();
        if x_bytes == [0_u8; 32] && sign == 1 {
            return None;
        }
        if (x_bytes[0] & 1) != sign {
            x = x.neg();
        }
        Some(Self {
            x,
            y,
            z: Fe::ONE,
            t: x.mul(&y),
        })
    }

    fn to_bytes(self) -> [u8; 32] {
        let recip = self.z.invert();
        let x = self.x.mul(&recip);
        let y = self.y.mul(&recip);
        let mut out = y.to_bytes();
        out[31] |= (x.to_bytes()[0] & 1) << 7;
        out
    }

    /// Unified complete addition (RFC 8032 §5.1.4); handles doubling and identity uniformly.
    fn add(&self, other: &Self) -> Self {
        let two_d = edwards_d().add(&edwards_d());
        let a = self.y.sub(&self.x).mul(&other.y.sub(&other.x));
        let b = self.y.add(&self.x).mul(&other.y.add(&other.x));
        let c = self.t.mul(&two_d).mul(&other.t);
        let d = self.z.add(&self.z).mul(&other.z);
        let e = b.sub(&a);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);
        Self {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    fn scalar_mul(&self, scalar_le: &[u8; 32]) -> Self {
        let mut acc = Self::IDENTITY;
        let mut base = *self;
        for byte in scalar_le {
            for bit in 0..8 {
                let sum = acc.add(&base);
                let select = u64::from((byte >> bit) & 1);
                acc = Self::cselect(select, &acc, &sum);
                base = base.add(&base);
            }
        }
        acc
    }

    fn cselect(choice: u64, if_zero: &Self, if_one: &Self) -> Self {
        let mut out = *if_zero;
        let mut alt = *if_one;
        Fe::cswap(choice, &mut out.x, &mut alt.x);
        Fe::cswap(choice, &mut out.y, &mut alt.y);
        Fe::cswap(choice, &mut out.z, &mut alt.z);
        Fe::cswap(choice, &mut out.t, &mut alt.t);
        out
    }
}

fn scalar_is_canonical(s_le: &[u8; 32]) -> bool {
    let limbs = bytes_to_u64x4_le(s_le);
    for i in (0..4).rev() {
        if limbs[i] < L_LIMBS[i] {
            return true;
        }
        if limbs[i] > L_LIMBS[i] {
            return false;
        }
    }
    false
}

/// Reduces a 512-bit little-endian integer modulo `L` into 32 canonical LE bytes.
fn reduce_512_mod_l(input: &[u8; 64]) -> [u8; 32] {
    let mut rem = [0_u64; 5];
    for byte_idx in (0..64).rev() {
        let byte = input[byte_idx];
        for bit_idx in (0..8).rev() {
            let bit = u64::from((byte >> bit_idx) & 1);
            shift_left_1_with_bit(&mut rem, bit);
            if gte_l(&rem) {
                sub_l(&mut rem);
            }
        }
    }
    u64x4_to_bytes_le([rem[0], rem[1], rem[2], rem[3]])
}

/// Computes `(k * a + r) mod L` for 256-bit little-endian scalars.
fn mul_add_mod_l(k_le: &[u8; 32], a_le: &[u8; 32], r_le: &[u8; 32]) -> [u8; 32] {
    let k = bytes_to_u64x4_le(k_le);
    let a = bytes_to_u64x4_le(a_le);
    let r = bytes_to_u64x4_le(r_le);
    let mut prod = [0_u64; 8];

    for i in 0..4 {
        let mut carry = 0_u128;
        for j in 0..4 {
            let acc = u128::from(prod[i + j]) + u128::from(k[i]) * u128::from(a[j]) + carry;
            prod[i + j] = acc as u64;
            carry = acc >> 64;
        }
        prod[i + 4] = prod[i + 4].wrapping_add(carry as u64);
    }

    let mut carry = 0_u128;
    for i in 0..8 {
        let rhs = if i < 4 { u128::from(r[i]) } else { 0 };
        let sum = u128::from(prod[i]) + rhs + carry;
        prod[i] = sum as u64;
        carry = sum >> 64;
    }

    let mut wide = Zeroizing::new([0_u8; 64]);
    for (idx, word) in prod.iter().enumerate() {
        wide[idx * 8..idx * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    reduce_512_mod_l(&wide)
}

fn shift_left_1_with_bit(limbs: &mut [u64; 5], low_bit: u64) {
    let mut carry = low_bit & 1;
    for limb in limbs.iter_mut() {
        let next_carry = *limb >> 63;
        *limb = (*limb << 1) | carry;
        carry = next_carry;
    }
}

fn gte_l(rem: &[u64; 5]) -> bool {
    if rem[4] > 0 {
        return true;
    }
    for i in (0..4).rev() {
        if rem[i] > L_LIMBS[i] {
            return true;
        }
        if rem[i] < L_LIMBS[i] {
            return false;
        }
    }
    true
}

fn sub_l(rem: &mut [u64; 5]) {
    let mut borrow = 0_u128;
    for i in 0..4 {
        let lhs = u128::from(rem[i]);
        let rhs = u128::from(L_LIMBS[i]) + borrow;
        if lhs >= rhs {
            rem[i] = (lhs - rhs) as u64;
            borrow = 0;
        } else {
            rem[i] = ((1_u128 << 64) + lhs - rhs) as u64;
            borrow = 1;
        }
    }
    rem[4] = rem[4].wrapping_sub(borrow as u64);
}

fn bytes_to_u64x4_le(bytes: &[u8; 32]) -> [u64; 4] {
    let mut out = [0_u64; 4];
    for (idx, chunk) in bytes.as_chunks::<8>().0.iter().enumerate() {
        out[idx] = u64::from_le_bytes(*chunk);
    }
    out
}

fn u64x4_to_bytes_le(limbs: [u64; 4]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    for (idx, word) in limbs.iter().enumerate() {
        out[idx * 8..idx * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    out
}
