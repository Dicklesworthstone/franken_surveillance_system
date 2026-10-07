//! XXTEA (corrected Block TEA) for the K-command challenge-response
//! (reference doc §15.1; byte-differential-verified against the live-proven
//! Python port and the mrlt8 `tutk_protocol.py` reference).

const DELTA: u32 = 0x9E37_79B9;

/// Errors from XXTEA input validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XxteaError {
    /// Key must be exactly 16 bytes.
    BadKeyLength(usize),
    /// Data must be at least 8 bytes and a multiple of 4.
    BadDataLength(usize),
}

impl core::fmt::Display for XxteaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadKeyLength(n) => write!(f, "XXTEA key must be 16 bytes, got {n}"),
            Self::BadDataLength(n) => {
                write!(f, "XXTEA data must be >= 8 bytes and multiple of 4, got {n}")
            }
        }
    }
}

impl std::error::Error for XxteaError {}

#[inline]
fn mx(sum: u32, y: u32, z: u32, p: usize, e: u32, k: &[u32; 4]) -> u32 {
    let a = (z >> 5) ^ (y << 2);
    let b = (y >> 3) ^ (z << 4);
    let c = (sum ^ y).wrapping_add(k[(p & 3) ^ e as usize] ^ z);
    (a.wrapping_add(b)) ^ c
}

fn to_words(data: &[u8]) -> Vec<u32> {
    data.chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

fn to_bytes(v: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 4);
    for w in v {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}

fn check(data: &[u8], key: &[u8]) -> Result<[u32; 4], XxteaError> {
    if key.len() != 16 {
        return Err(XxteaError::BadKeyLength(key.len()));
    }
    if data.len() < 8 || data.len() % 4 != 0 {
        return Err(XxteaError::BadDataLength(data.len()));
    }
    let kw = to_words(key);
    Ok([kw[0], kw[1], kw[2], kw[3]])
}

/// Decrypt per doc §15.1 (no length prefix, no padding — the TUTK usage).
pub fn decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, XxteaError> {
    let k = check(data, key)?;
    let mut v = to_words(data);
    let n = v.len();
    let mut rounds = 6 + 52 / n as u32;
    let mut sum = rounds.wrapping_mul(DELTA);
    let mut y = v[0];
    while rounds > 0 {
        let e = (sum >> 2) & 3;
        for p in (1..n).rev() {
            let z = v[p - 1];
            v[p] = v[p].wrapping_sub(mx(sum, y, z, p, e, &k));
            y = v[p];
        }
        let z = v[n - 1];
        v[0] = v[0].wrapping_sub(mx(sum, y, z, 0, e, &k));
        y = v[0];
        sum = sum.wrapping_sub(DELTA);
        rounds -= 1;
    }
    Ok(to_bytes(&v))
}

/// Encrypt (inverse of [`decrypt`]; used for self-tests and simulators).
pub fn encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, XxteaError> {
    let k = check(data, key)?;
    let mut v = to_words(data);
    let n = v.len();
    let rounds = 6 + 52 / n as u32;
    let mut sum = 0u32;
    let mut z = v[n - 1];
    for _ in 0..rounds {
        sum = sum.wrapping_add(DELTA);
        let e = (sum >> 2) & 3;
        for p in 0..n - 1 {
            let y = v[p + 1];
            v[p] = v[p].wrapping_add(mx(sum, y, z, p, e, &k));
            z = v[p];
        }
        let y = v[0];
        v[n - 1] = v[n - 1].wrapping_add(mx(sum, y, z, n - 1, e, &k));
        z = v[n - 1];
    }
    Ok(to_bytes(&v))
}

/// K10001 challenge-response key modes (reference doc §7 Layer 3; order
/// verified against the mrlt8 reference implementation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeKey {
    /// status 1: default key 16 x 0xFF
    Default,
    /// status 3: ENR[0:16]
    Enr,
    /// status 6: double decrypt — first ENR[0:16], then ENR[16:32]
    EnrDouble,
}

/// Decrypt the 16-byte K10001 challenge per the camera's selected mode.
pub fn challenge_response(
    mode: ChallengeKey,
    challenge: &[u8],
    enr: &str,
) -> Result<Vec<u8>, XxteaError> {
    if challenge.len() != 16 {
        return Err(XxteaError::BadDataLength(challenge.len()));
    }
    let enr_b = enr.as_bytes();
    match mode {
        ChallengeKey::Default => decrypt(challenge, b"FFFFFFFFFFFFFFFF"),
        ChallengeKey::Enr => {
            if enr_b.len() < 16 {
                return Err(XxteaError::BadKeyLength(enr_b.len()));
            }
            decrypt(challenge, &enr_b[..16])
        }
        ChallengeKey::EnrDouble => {
            if enr_b.len() < 32 {
                return Err(XxteaError::BadKeyLength(enr_b.len()));
            }
            let stage1 = decrypt(challenge, &enr_b[..16])?;
            decrypt(&stage1, &enr_b[16..32])
        }
    }
}
