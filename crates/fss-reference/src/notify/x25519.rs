#![forbid(unsafe_code)]
//! First-party pure-Rust RFC 7748 X25519 key agreement and $GF(2^{255}-19)$ field arithmetic.
//!
//! Zero external crates beyond `zeroize` and `fss_vault::EntropySource`. All ephemeral
//! private scalars are wrapped in [`Zeroizing`] and never formatted in `Debug` or `Display`.

use core::fmt;

use fss_vault::EntropySource;
use zeroize::Zeroizing;

/// Bitmask for a 51-bit field limb (`2^51 - 1`).
const MASK51: u64 = (1_u64 << 51) - 1;

/// Montgomery curve constant `(A - 2) / 4 = (486662 - 2) / 4 = 121665` (RFC 7748 §5).
const A24: u64 = 121_665;

/// Standard Curve25519 basepoint `u = 9` in 32-byte little-endian encoding (RFC 7748 §4.1).
pub const X25519_BASEPOINT: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Errors returned by X25519 key generation or shared-secret derivation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum X25519Error {
    /// Explicit entropy source failed to supply random bytes.
    EntropyFailed,
    /// Derived shared secret was the all-zero low-order point (RFC 7748 §6.1).
    LowOrderPoint,
}

impl fmt::Display for X25519Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EntropyFailed => f.write_str("X25519 entropy generation failed"),
            Self::LowOrderPoint => f.write_str("X25519 derived low-order all-zero shared secret"),
        }
    }
}

impl std::error::Error for X25519Error {}

/// Ephemeral X25519 secret scalar wrapped in [`Zeroizing`] with redacted formatting.
#[derive(Clone)]
pub struct X25519SecretKey {
    bytes: Zeroizing<[u8; 32]>,
}

impl X25519SecretKey {
    /// Generates a fresh X25519 secret scalar using an explicit [`EntropySource`].
    pub fn generate(entropy: &mut dyn EntropySource) -> Result<Self, X25519Error> {
        let mut raw = Zeroizing::new([0_u8; 32]);
        entropy
            .fill_bytes(&mut *raw)
            .map_err(|_| X25519Error::EntropyFailed)?;
        Ok(Self::from_bytes(*raw))
    }

    /// Constructs a secret key from 32 bytes (RFC 7748 clamping is applied on use).
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    /// Derives the corresponding 32-byte X25519 public key (`u = X25519(sk, 9)`).
    #[must_use]
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey(x25519_raw(&self.bytes, &X25519_BASEPOINT))
    }

    /// Computes the X25519 shared secret with `peer_public`, refusing all-zero outputs.
    pub fn diffie_hellman(
        &self,
        peer_public: &X25519PublicKey,
    ) -> Result<Zeroizing<[u8; 32]>, X25519Error> {
        let shared = Zeroizing::new(x25519_raw(&self.bytes, &peer_public.0));
        let mut or_acc = 0_u8;
        for &byte in shared.iter() {
            or_acc |= byte;
        }
        if or_acc == 0 {
            return Err(X25519Error::LowOrderPoint);
        }
        Ok(shared)
    }
}

impl fmt::Debug for X25519SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("X25519SecretKey([REDACTED])")
    }
}

/// 32-byte X25519 public u-coordinate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X25519PublicKey(pub [u8; 32]);

impl X25519PublicKey {
    /// Returns the raw 32-byte little-endian Montgomery u-coordinate.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Pure-Rust RFC 7748 §5 X25519 scalar multiplication `X25519(k, u)`.
#[must_use]
pub fn x25519_raw(scalar: &[u8; 32], u_coord: &[u8; 32]) -> [u8; 32] {
    let mut k = Zeroizing::new(*scalar);
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;

    let x_1 = Fe::from_bytes_masked(u_coord);
    let mut x_2 = Fe::ONE;
    let mut z_2 = Fe::ZERO;
    let mut x_3 = x_1;
    let mut z_3 = Fe::ONE;
    let mut swap = 0_u64;

    for t in (0_usize..255).rev() {
        let k_t = u64::from((k[t >> 3] >> (t & 7)) & 1);
        swap ^= k_t;
        Fe::cswap(swap, &mut x_2, &mut x_3);
        Fe::cswap(swap, &mut z_2, &mut z_3);
        swap = k_t;

        let a = x_2.add(&z_2);
        let aa = a.square();
        let b = x_2.sub(&z_2);
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x_3.add(&z_3);
        let d = x_3.sub(&z_3);
        let da = d.mul(&a);
        let cb = c.mul(&b);
        x_3 = da.add(&cb).square();
        z_3 = x_1.mul(&da.sub(&cb).square());
        x_2 = aa.mul(&bb);
        z_2 = e.mul(&aa.add(&e.mul_small(A24)));
    }

    Fe::cswap(swap, &mut x_2, &mut x_3);
    Fe::cswap(swap, &mut z_2, &mut z_3);

    x_2.mul(&z_2.invert()).to_bytes()
}

/// Element of the prime field $GF(2^{255}-19)$ represented in five 51-bit limbs.
///
/// Shared internally by both `x25519` and `ed25519`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Fe(pub(crate) [u64; 5]);

impl Fe {
    pub(crate) const ZERO: Self = Self([0, 0, 0, 0, 0]);
    pub(crate) const ONE: Self = Self([1, 0, 0, 0, 0]);

    #[must_use]
    pub(crate) const fn from_u64(value: u64) -> Self {
        Self([value & MASK51, value >> 51, 0, 0, 0])
    }

    /// Loads 32 little-endian bytes, masking off bit 255 as required by RFC 7748 & RFC 8032.
    #[must_use]
    pub(crate) fn from_bytes_masked(bytes: &[u8; 32]) -> Self {
        let l0 = load_u64_le(&bytes[0..8]) & MASK51;
        let l1 = (load_u64_le(&bytes[6..14]) >> 3) & MASK51;
        let l2 = (load_u64_le(&bytes[12..20]) >> 6) & MASK51;
        let l3 = (load_u64_le(&bytes[19..27]) >> 1) & MASK51;
        let l4 = (load_u64_le(&bytes[24..32]) >> 12) & MASK51;
        Self([l0, l1, l2, l3, l4])
    }

    /// Returns `true` iff the 255-bit value (with bit 255 cleared) is strictly `< 2^255 - 19`.
    #[must_use]
    pub(crate) fn is_canonical_field_bytes(bytes: &[u8; 32]) -> bool {
        if (bytes[31] & 0x7f) != 0x7f {
            return true;
        }
        if bytes[1..31].iter().any(|&b| b != 0xff) {
            return true;
        }
        bytes[0] < 0xed
    }

    /// Constant-time canonical 32-byte little-endian serialization modulo `2^255 - 19`.
    #[must_use]
    pub(crate) fn to_bytes(self) -> [u8; 32] {
        let mut r = self.reduce_limbs().0;
        let mut q = (r[0] + 19) >> 51;
        q = (r[1] + q) >> 51;
        q = (r[2] + q) >> 51;
        q = (r[3] + q) >> 51;
        q = (r[4] + q) >> 51;

        r[0] += 19 * q;
        r[1] += r[0] >> 51;
        r[0] &= MASK51;
        r[2] += r[1] >> 51;
        r[1] &= MASK51;
        r[3] += r[2] >> 51;
        r[2] &= MASK51;
        r[4] += r[3] >> 51;
        r[3] &= MASK51;
        r[4] &= MASK51;

        let mut out = [0_u8; 32];
        out[0..8].copy_from_slice(&(r[0] | (r[1] << 51)).to_le_bytes());
        out[8..16].copy_from_slice(&((r[1] >> 13) | (r[2] << 38)).to_le_bytes());
        out[16..24].copy_from_slice(&((r[2] >> 26) | (r[3] << 25)).to_le_bytes());
        out[24..32].copy_from_slice(&((r[3] >> 39) | (r[4] << 12)).to_le_bytes());
        out
    }

    #[must_use]
    fn reduce_limbs(self) -> Self {
        let mut r = self.0;
        let c0 = r[0] >> 51;
        r[0] &= MASK51;
        r[1] += c0;
        let c1 = r[1] >> 51;
        r[1] &= MASK51;
        r[2] += c1;
        let c2 = r[2] >> 51;
        r[2] &= MASK51;
        r[3] += c2;
        let c3 = r[3] >> 51;
        r[3] &= MASK51;
        r[4] += c3;
        let c4 = r[4] >> 51;
        r[4] &= MASK51;
        r[0] += c4 * 19;
        let c0b = r[0] >> 51;
        r[0] &= MASK51;
        r[1] += c0b;
        Self(r)
    }

    #[must_use]
    pub(crate) fn add(&self, other: &Self) -> Self {
        Self([
            self.0[0] + other.0[0],
            self.0[1] + other.0[1],
            self.0[2] + other.0[2],
            self.0[3] + other.0[3],
            self.0[4] + other.0[4],
        ])
        .reduce_limbs()
    }

    #[must_use]
    pub(crate) fn sub(&self, other: &Self) -> Self {
        const TWO_P0: u64 = (1_u64 << 52) - 38;
        const TWO_PN: u64 = (1_u64 << 52) - 2;
        Self([
            (self.0[0] + TWO_P0) - other.0[0],
            (self.0[1] + TWO_PN) - other.0[1],
            (self.0[2] + TWO_PN) - other.0[2],
            (self.0[3] + TWO_PN) - other.0[3],
            (self.0[4] + TWO_PN) - other.0[4],
        ])
        .reduce_limbs()
    }

    #[must_use]
    pub(crate) fn neg(&self) -> Self {
        Self::ZERO.sub(self)
    }

    #[must_use]
    pub(crate) fn mul_small(&self, scalar: u64) -> Self {
        let s = u128::from(scalar);
        let mut t0 = u128::from(self.0[0]) * s;
        let mut t1 = u128::from(self.0[1]) * s;
        let mut t2 = u128::from(self.0[2]) * s;
        let mut t3 = u128::from(self.0[3]) * s;
        let mut t4 = u128::from(self.0[4]) * s;

        t1 += t0 >> 51;
        let r0 = (t0 as u64) & MASK51;
        t2 += t1 >> 51;
        let r1 = (t1 as u64) & MASK51;
        t3 += t2 >> 51;
        let r2 = (t2 as u64) & MASK51;
        t4 += t3 >> 51;
        let r3 = (t3 as u64) & MASK51;
        t0 = u128::from(r0) + (t4 >> 51) * 19;
        let r4 = (t4 as u64) & MASK51;
        let r0 = (t0 as u64) & MASK51;
        let r1 = r1 + ((t0 >> 51) as u64);
        Self([r0, r1, r2, r3, r4]).reduce_limbs()
    }

    #[must_use]
    pub(crate) fn mul(&self, other: &Self) -> Self {
        let a0 = u128::from(self.0[0]);
        let a1 = u128::from(self.0[1]);
        let a2 = u128::from(self.0[2]);
        let a3 = u128::from(self.0[3]);
        let a4 = u128::from(self.0[4]);

        let b0 = u128::from(other.0[0]);
        let b1 = u128::from(other.0[1]);
        let b2 = u128::from(other.0[2]);
        let b3 = u128::from(other.0[3]);
        let b4 = u128::from(other.0[4]);

        let b1_19 = b1 * 19;
        let b2_19 = b2 * 19;
        let b3_19 = b3 * 19;
        let b4_19 = b4 * 19;

        let t0 = a0 * b0 + a1 * b4_19 + a2 * b3_19 + a3 * b2_19 + a4 * b1_19;
        let mut t1 = a0 * b1 + a1 * b0 + a2 * b4_19 + a3 * b3_19 + a4 * b2_19;
        let mut t2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * b4_19 + a4 * b3_19;
        let mut t3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * b4_19;
        let mut t4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;

        t1 += t0 >> 51;
        let r0 = (t0 as u64) & MASK51;
        t2 += t1 >> 51;
        let mut r1 = (t1 as u64) & MASK51;
        t3 += t2 >> 51;
        let mut r2 = (t2 as u64) & MASK51;
        t4 += t3 >> 51;
        let r3 = (t3 as u64) & MASK51;
        let c = u128::from(r0) + (t4 >> 51) * 19;
        let r4 = (t4 as u64) & MASK51;
        let r0 = (c as u64) & MASK51;
        r1 += (c >> 51) as u64;
        r2 += r1 >> 51;
        r1 &= MASK51;

        Self([r0, r1, r2, r3, r4]).reduce_limbs()
    }

    #[must_use]
    pub(crate) fn square(&self) -> Self {
        self.mul(self)
    }

    #[must_use]
    pub(crate) fn pow_squares(&self, count: usize) -> Self {
        let mut acc = *self;
        for _ in 0..count {
            acc = acc.square();
        }
        acc
    }

    /// Computes `self^(2^252 - 3) mod p`, used for both inversion and square roots.
    #[must_use]
    pub(crate) fn pow_252_3(&self) -> Self {
        let t0 = self.square();
        let t1 = t0.pow_squares(2);
        let t2 = self.mul(&t1);
        let t3 = t0.mul(&t2);
        let t4 = t3.square();
        let t5 = t2.mul(&t4);
        let t6 = t5.pow_squares(5);
        let t7 = t6.mul(&t5);
        let t8 = t7.pow_squares(10);
        let t9 = t8.mul(&t7);
        let t10 = t9.pow_squares(20);
        let t11 = t10.mul(&t9);
        let t12 = t11.pow_squares(10);
        let t13 = t12.mul(&t7);
        let t14 = t13.pow_squares(50);
        let t15 = t14.mul(&t13);
        let t16 = t15.pow_squares(100);
        let t17 = t16.mul(&t15);
        let t18 = t17.pow_squares(50);
        let t19 = t18.mul(&t13);
        let t20 = t19.pow_squares(2);
        t20.mul(self)
    }

    /// Computes multiplicative inverse `self^(p - 2) = self^(2^255 - 21) mod p`.
    #[must_use]
    pub(crate) fn invert(&self) -> Self {
        let t0 = self.square();
        let t1 = t0.pow_squares(2);
        let t2 = self.mul(&t1);
        let t3 = t0.mul(&t2);
        let t4 = t3.square();
        let t5 = t2.mul(&t4);
        let t6 = t5.pow_squares(5);
        let t7 = t6.mul(&t5);
        let t8 = t7.pow_squares(10);
        let t9 = t8.mul(&t7);
        let t10 = t9.pow_squares(20);
        let t11 = t10.mul(&t9);
        let t12 = t11.pow_squares(10);
        let t13 = t12.mul(&t7);
        let t14 = t13.pow_squares(50);
        let t15 = t14.mul(&t13);
        let t16 = t15.pow_squares(100);
        let t17 = t16.mul(&t15);
        let t18 = t17.pow_squares(50);
        let t19 = t18.mul(&t13);
        let t20 = t19.pow_squares(5);
        t20.mul(&t3)
    }

    /// Constant-time conditional swap when `choice == 1` (no-op when `choice == 0`).
    pub(crate) fn cswap(choice: u64, a: &mut Self, b: &mut Self) {
        let mask = 0_u64.wrapping_sub(choice & 1);
        for i in 0..5 {
            let diff = mask & (a.0[i] ^ b.0[i]);
            a.0[i] ^= diff;
            b.0[i] ^= diff;
        }
    }

    /// Constant-time canonical equality modulo `p`.
    #[must_use]
    pub(crate) fn ct_eq(&self, other: &Self) -> bool {
        fss_vault::constant_time_eq(&self.to_bytes(), &other.to_bytes())
    }
}

#[inline]
fn load_u64_le(slice: &[u8]) -> u64 {
    let mut buf = [0_u8; 8];
    buf.copy_from_slice(slice);
    u64::from_le_bytes(buf)
}
