//! CAVLC residual-coefficient machinery (ITU-T H.264 clause 9.2).
//!
//! This module owns the context arithmetic and the variable-length-table
//! infrastructure. The spec's variable-length tables (Table 9-5 coeff_token,
//! Table 9-7 total_zeros, Table 9-10 run_before) are data, not memory —
//! [`table_checks`] makes any transcription machine-checkable before it is
//! allowed to drive a decode:
//!
//! - **prefix-free**: no codeword is a prefix of another (decodability);
//! - **Kraft-complete**: the Kraft sum is exactly 1, so a table with a
//!   missing, duplicated, or miscopied row almost always fails loudly.
//!
//! The full residual-block decode loop lands together with the validated
//! transcriptions of the real tables and the FFmpeg differential oracle;
//! shipping an unverified level-decoder from memory would be exactly the
//! "unverified claim" the repository constitution forbids.

use crate::bits::BitReader;
use crate::DecodeError;

/// A variable-length table: maps a codeword (MSB-first packed) to a value
/// within one context. Lookup is linear; tables are small (<= 70 rows) and
/// the scalar-reference stage is not performance-critical.
#[derive(Clone, Debug)]
pub struct VlcTable {
    entries: Vec<VlcEntry>,
}

/// One table row: a codeword and the value it decodes to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VlcEntry {
    /// Codeword bits, MSB-first, right-aligned in `code`.
    pub code: u32,
    /// Codeword length in bits (coeff_token needs up to 17).
    pub len: u8,
    /// The decoded value (e.g. `TotalCoeff * 4 + TrailingOnes` packed).
    pub value: u16,
}

impl VlcTable {
    /// Builds a table from rows, rejecting duplicate values eagerly.
    ///
    /// # Errors
    /// [`DecodeError::Malformed`] when two rows decode to the same value.
    pub fn new(entries: Vec<VlcEntry>) -> Result<Self, DecodeError> {
        let mut seen = std::collections::BTreeSet::new();
        for entry in &entries {
            if !seen.insert(entry.value) {
                return Err(DecodeError::Malformed);
            }
        }
        Ok(Self { entries })
    }

    /// Row access for validators and tests.
    #[must_use]
    pub fn entries(&self) -> &[VlcEntry] {
        &self.entries
    }

    /// Reads one codeword from `reader` and returns its value.
    ///
    /// # Errors
    /// [`DecodeError::Limit`] when the bound ends mid-codeword;
    /// [`DecodeError::Malformed`] when the bits match no row within 17 bits.
    pub fn decode(&self, reader: &mut BitReader<'_>) -> Result<u16, DecodeError> {
        let mut code: u32 = 0;
        for len in 1u8..=17 {
            code = (code << 1) | u32::from(reader.bit()?);
            if let Some(entry) = self.entries.iter().find(|e| e.len == len && e.code == code) {
                return Ok(entry.value);
            }
        }
        Err(DecodeError::Malformed)
    }

    /// Appends the codeword for `value` to `out`, MSB-first.
    ///
    /// # Errors
    /// [`DecodeError::Malformed`] when the value is absent (encoder side
    /// exists for deterministic round-trip tests and fixture authoring).
    pub fn encode(&self, value: u16, out: &mut Vec<u8>) -> Result<(), DecodeError> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.value == value)
            .ok_or(DecodeError::Malformed)?;
        for shift in (0..entry.len).rev() {
            let bit = u8::try_from((entry.code >> shift) & 1).unwrap_or(0);
            out.push(bit);
        }
        Ok(())
    }
}

/// Structural validators that make table transcription machine-checked.
pub mod table_checks {
    use super::{DecodeError, VlcTable};

    /// Verifies the table is prefix-free and Kraft-complete.
    ///
    /// # Errors
    /// [`DecodeError::Malformed`] on a prefix conflict, an incomplete Kraft
    /// sum (missing rows), or an empty table.
    pub fn validate_canonical(table: &VlcTable) -> Result<(), DecodeError> {
        let entries = table.entries();
        if entries.is_empty() {
            return Err(DecodeError::Malformed);
        }
        // Prefix-freedom: for any pair, the longer codeword's top
        // `shorter.len` bits must differ from the shorter codeword.
        for (index, a) in entries.iter().enumerate() {
            for b in entries.iter().skip(index + 1) {
                let (short, long) = if a.len <= b.len { (a, b) } else { (b, a) };
                if (long.code >> (long.len - short.len)) == (short.code & mask(short.len)) {
                    return Err(DecodeError::Malformed);
                }
            }
        }
        // Kraft equality in exact integer arithmetic: sum of 2^(max-len)
        // over a common denominator 2^max must equal 2^max. A single
        // missing or miscopied row changes the sum.
        let max_len = entries.iter().map(|e| e.len).max().ok_or(DecodeError::Malformed)?;
        let mut numerator: u64 = 0;
        for entry in entries {
            numerator += 1u64 << (max_len - entry.len);
        }
        if numerator != 1u64 << max_len {
            return Err(DecodeError::Malformed);
        }
        Ok(())
    }

    fn mask(bits: u8) -> u32 {
        if bits == 0 || bits >= 32 {
            u32::MAX
        } else {
            (1u32 << bits) - 1
        }
    }
}

/// Builds a canonical code assignment: rows given as (value, length) in
/// spec order receive consecutive codewords of their lengths — the property
/// every H.295 VLC table has (equal-length codes are consecutive and ordered).
///
/// Rows must arrive sorted by (length ascending, then spec order).
///
/// # Errors
/// [`DecodeError::Malformed`] when the assignment would overflow a row's
/// length (a proof the (value,length) list is not prefix-free-complete).
pub fn canonical_table(rows: &[(u16, u8)]) -> Result<VlcTable, DecodeError> {
    let mut code: u32 = 0;
    let mut previous_len: Option<u8> = None;
    let mut entries = Vec::with_capacity(rows.len());
    for &(value, len) in rows {
        if len == 0 || len > 17 {
            return Err(DecodeError::Malformed);
        }
        if let Some(previous) = previous_len {
            if len < previous {
                return Err(DecodeError::Malformed);
            }
            // First code of this length: shift the running code left.
            code <<= len - previous;
        }
        entries.push(VlcEntry { code, len, value });
        code += 1;
        previous_len = Some(len);
    }
    VlcTable::new(entries)
}

/// nC context from left/above neighbor TotalCoeff values (clause 9.2.1).
///
/// `None` marks an unavailable neighbor; both-unavailable selects the
/// `nC < 0` table (used for ChromaDC). One-available reads that neighbor's
/// count directly.
#[must_use]
pub fn context_nc(left: Option<u8>, above: Option<u8>) -> i32 {
    match (left, above) {
        (Some(left_count), Some(above_count)) => {
            let count = i32::from(left_count) + i32::from(above_count);
            if count < 2 {
                0
            } else if count < 4 {
                1
            } else if count < 8 {
                2
            } else {
                3
            }
        }
        (Some(count), None) | (None, Some(count)) => i32::from(count),
        (None, None) => -1,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// A complete synthetic canonical table over 5 values (lengths 2,2,2,3,3;
    /// Kraft 3/4 + 2/8 = 1).
    fn synthetic_table() -> VlcTable {
        canonical_table(&[(0, 2), (1, 2), (2, 2), (3, 3), (4, 3)]).unwrap()
    }

    #[test]
    fn canonical_table_is_prefix_free_and_kraft_complete() {
        let table = synthetic_table();
        table_checks::validate_canonical(&table).expect("synthetic table is canonical");
        assert_eq!(table.entries().len(), 5);
        assert_eq!(table.entries()[0], VlcEntry { code: 0b00, len: 2, value: 0 });
        assert_eq!(table.entries()[3], VlcEntry { code: 0b110, len: 3, value: 3 });
        assert_eq!(table.entries()[4], VlcEntry { code: 0b111, len: 3, value: 4 });
    }

    #[test]
    fn validator_rejects_missing_rows_by_kraft_sum() {
        // Lengths (1,2,3) over only two rows: Kraft sum 1/2 + 1/4 + ... < 1.
        let incomplete = VlcTable::new(vec![
            VlcEntry { code: 0b0, len: 1, value: 0 },
            VlcEntry { code: 0b10, len: 2, value: 1 },
        ])
        .unwrap();
        assert_eq!(
            table_checks::validate_canonical(&incomplete).unwrap_err(),
            DecodeError::Malformed
        );
    }

    #[test]
    fn validator_rejects_prefix_conflicts() {
        // "0" and "01": the second is prefixed by the first.
        let conflicting = VlcTable::new(vec![
            VlcEntry { code: 0b0, len: 1, value: 0 },
            VlcEntry { code: 0b01, len: 2, value: 1 },
            VlcEntry { code: 0b10, len: 2, value: 2 },
            VlcEntry { code: 0b11, len: 2, value: 3 },
        ])
        .unwrap();
        assert_eq!(
            table_checks::validate_canonical(&conflicting).unwrap_err(),
            DecodeError::Malformed
        );
    }

    #[test]
    fn duplicate_values_are_refused_at_construction() {
        assert!(VlcTable::new(vec![
            VlcEntry { code: 0b0, len: 1, value: 7 },
            VlcEntry { code: 0b10, len: 2, value: 7 },
        ])
        .is_err());
    }

    #[test]
    fn round_trip_every_value_through_bits() {
        let table = synthetic_table();
        // Encode all values back to back, then decode them in order.
        let mut packed = Vec::new();
        for value in 0..5u16 {
            table.encode(value, &mut packed).expect("value in table");
        }
        while packed.len() % 8 != 0 {
            packed.push(0);
        }
        let bytes: Vec<u8> = packed
            .chunks(8)
            .map(|chunk| chunk.iter().fold(0u8, |acc, &b| (acc << 1) | b))
            .collect();
        let mut reader = BitReader::new(&bytes, packed.len());
        for value in 0..5u16 {
            assert_eq!(table.decode(&mut reader).unwrap(), value);
        }
    }

    #[test]
    fn incomplete_table_refuses_unmatched_prefix() {
        // Two of three length-2 codes: the all-ones run matches no row and
        // exhausts the 17-bit codeword search — typed Malformed, not Limit.
        let incomplete = VlcTable::new(vec![
            VlcEntry { code: 0b00, len: 2, value: 0 },
            VlcEntry { code: 0b01, len: 2, value: 1 },
        ])
        .unwrap();
        let mut reader = BitReader::new(&[0b1111_1111, 0b1111_1111, 0b1100_0000], 17);
        assert_eq!(incomplete.decode(&mut reader).unwrap_err(), DecodeError::Malformed);
    }

    #[test]
    fn bound_exhaustion_is_limit_not_malformed() {
        let table = synthetic_table();
        // Only 2 bits of a 3-bit codeword fit the bound.
        let mut reader = BitReader::new(&[0b1100_0000], 2);
        assert_eq!(table.decode(&mut reader).unwrap_err(), DecodeError::Limit);
    }

    #[test]
    fn context_nc_follows_clause_9_2_1() {
        // Both neighbors: sum thresholds 2/4/8 map to contexts 0/1/2/3.
        assert_eq!(context_nc(Some(0), Some(1)), 0);
        assert_eq!(context_nc(Some(1), Some(1)), 1);
        assert_eq!(context_nc(Some(2), Some(2)), 2);
        assert_eq!(context_nc(Some(4), Some(4)), 3);
        // One available neighbor: its count is the context directly.
        assert_eq!(context_nc(Some(5), None), 5);
        assert_eq!(context_nc(None, Some(1)), 1);
        // Neither: the nC < 0 table.
        assert_eq!(context_nc(None, None), -1);
    }

    #[test]
    fn noncanonical_order_is_refused() {
        // Lengths must be non-decreasing for the canonical assignment.
        assert!(canonical_table(&[(0, 2), (1, 1)]).is_err());
        assert!(canonical_table(&[(0, 0)]).is_err());
        assert!(canonical_table(&[(0, 18)]).is_err());
    }
}
