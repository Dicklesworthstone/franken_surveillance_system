#![forbid(unsafe_code)]
//! Pure-Rust Castagnoli CRC32C checksum implementation with zero external dependencies.
//!
//! Uses the reflected Castagnoli polynomial `0x82F6_3B78` (RFC 3720 / iSCSI) with a
//! compile-time generated slicing-by-4 table for fast verification of packfile records,
//! catalog journal frames, and media chunk tables.

/// Reflected Castagnoli polynomial (`x^32 + x^28 + x^27 + x^26 + x^25 + x^23 + ... + 1`).
const CRC32C_POLY_REFLECTED: u32 = 0x82F6_3B78;

/// Precomputed slicing-by-4 lookup tables generated at compile time.
const TABLES: [[u32; 256]; 4] = build_tables();

const fn build_tables() -> [[u32; 256]; 4] {
    let mut tables = [[0_u32; 256]; 4];

    let mut i = 0_usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ CRC32C_POLY_REFLECTED;
            } else {
                crc >>= 1;
            }
            bit += 1;
        }
        tables[0][i] = crc;
        i += 1;
    }

    let mut t = 1_usize;
    while t < 4 {
        let mut j = 0_usize;
        while j < 256 {
            let prev = tables[t - 1][j];
            tables[t][j] = (prev >> 8) ^ tables[0][(prev & 0xFF) as usize];
            j += 1;
        }
        t += 1;
    }

    tables
}

/// Incremental streaming CRC32C (Castagnoli) checksum hasher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Crc32cHasher {
    state: u32,
}

impl Default for Crc32cHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32cHasher {
    /// Creates a new CRC32C hasher initialized to standard `0xFFFF_FFFF` state.
    #[must_use]
    pub const fn new() -> Self {
        Self { state: 0xFFFF_FFFF }
    }

    /// Feeds bytes into the running CRC32C state.
    pub fn update(&mut self, bytes: &[u8]) {
        let mut crc = self.state;
        let (chunks, remainder) = bytes.as_chunks::<4>();
        for chunk in chunks {
            let word = u32::from_le_bytes(*chunk) ^ crc;
            crc = TABLES[3][(word & 0xFF) as usize]
                ^ TABLES[2][((word >> 8) & 0xFF) as usize]
                ^ TABLES[1][((word >> 16) & 0xFF) as usize]
                ^ TABLES[0][((word >> 24) & 0xFF) as usize];
        }
        for &byte in remainder {
            crc = (crc >> 8) ^ TABLES[0][((crc ^ u32::from(byte)) & 0xFF) as usize];
        }
        self.state = crc;
    }

    /// Finalizes and returns the 32-bit Castagnoli CRC32C checksum.
    #[must_use]
    pub const fn finalize(self) -> u32 {
        !self.state
    }
}

/// Computes the Castagnoli CRC32C checksum of `bytes` in one shot.
#[must_use]
pub fn crc32c(bytes: &[u8]) -> u32 {
    let mut hasher = Crc32cHasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::{Crc32cHasher, crc32c};

    #[test]
    fn matches_rfc3720_standard_vectors() {
        assert_eq!(crc32c(b""), 0x0000_0000);
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);

        let zeros = [0_u8; 32];
        assert_eq!(crc32c(&zeros), 0x8A91_36AA);

        let ones = [0xFF_u8; 32];
        assert_eq!(crc32c(&ones), 0x62A8_AB43);

        let mut ascending = [0_u8; 32];
        for (idx, slot) in ascending.iter_mut().enumerate() {
            *slot = idx as u8;
        }
        assert_eq!(crc32c(&ascending), 0x46DD_794E);

        let mut descending = [0_u8; 32];
        for (idx, slot) in descending.iter_mut().enumerate() {
            *slot = (31 - idx) as u8;
        }
        assert_eq!(crc32c(&descending), 0x113F_DB5C);
    }

    #[test]
    fn streaming_matches_one_shot_across_arbitrary_splits() {
        let payload: Vec<u8> = (0_u32..517)
            .map(|v| (v.wrapping_mul(37) & 0xFF) as u8)
            .collect();
        let expected = crc32c(&payload);

        for chunk_size in [1_usize, 2, 3, 4, 5, 7, 13, 64] {
            let mut hasher = Crc32cHasher::new();
            for chunk in payload.chunks(chunk_size) {
                hasher.update(chunk);
            }
            assert_eq!(hasher.finalize(), expected);
        }
    }
}
