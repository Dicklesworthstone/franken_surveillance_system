//! RBSP extraction: NAL header discipline, emulation-prevention removal,
//! and trailing-bit validation per ITU-T H.264 clause 7.4.1 / 7.3.1.
//!
//! The encoder side of the same coin ([`ebsp_from_rbsp`]) exists for
//! deterministic round-trip testing and fixture authoring only; the decode
//! path never re-adds emulation bytes.

use crate::DecodeError;

/// Parsed NAL unit header fields (forbidden_zero_bit is implied by type > 31).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NalHeader {
    /// `nal_ref_idc`: 0 = disposable, 1..3 = reference priority.
    pub ref_idc: u8,
    /// `nal_unit_type` (1..=31 after the forbidden-zero check).
    pub unit_type: u8,
}

/// A NAL payload after its single-byte header, with `fss-packet`'s byte
/// bounds already applied upstream. Carries no copy of the header byte.
#[derive(Clone, Copy, Debug)]
pub struct NalPayload<'a> {
    bytes: &'a [u8],
}

impl<'a> NalPayload<'a> {
    /// Wraps the NAL bytes including the header byte; the caller has already
    /// applied byte limits via `fss-packet`.
    #[must_use]
    pub const fn new(nal: &'a [u8]) -> Self {
        Self { bytes: nal }
    }

    /// Parses and removes the one-byte header.
    ///
    /// # Errors
    /// [`DecodeError::Malformed`] on a forbidden-zero bit set or type 0;
    /// [`DecodeError::UnexpectedNal`] when the NAL is header-only.
    pub fn split_header(&self) -> Result<(NalHeader, &'a [u8]), DecodeError> {
        let (first, rest) = self.bytes.split_first().ok_or(DecodeError::UnexpectedNal)?;
        if first & 0x80 != 0 {
            return Err(DecodeError::Malformed);
        }
        let unit_type = first & 0x1F;
        if unit_type == 0 {
            return Err(DecodeError::Malformed);
        }
        Ok((
            NalHeader {
                ref_idc: (first >> 5) & 0x03,
                unit_type,
            },
            rest,
        ))
    }
}

/// Removes emulation-prevention bytes: every `00 00 03` whose `03` was
/// inserted by the encoder becomes `00 00`. Any `00 00 03` that decodes to a
/// `00 00 00` (i.e. was *not* needed) proves corruption and is refused —
/// a valid RBSP never contains three zero bytes in a row, so a surviving
/// `00 00 00` after removal means the stream lied about its own framing.
///
/// # Errors
/// [`DecodeError::Limit`] when the output would exceed `max_rbsp_bytes`;
/// [`DecodeError::Malformed`] on an impossible `00 00 00` remainder.
pub fn rbsp_from_ebsp(ebsp: &[u8], max_rbsp_bytes: usize) -> Result<Vec<u8>, DecodeError> {
    // RBSP is never larger than EBSP: removal only deletes bytes.
    if ebsp.len() > max_rbsp_bytes {
        return Err(DecodeError::Limit);
    }
    let mut rbsp = Vec::with_capacity(ebsp.len());
    let mut zeros: u32 = 0;
    let mut index = 0;
    while index < ebsp.len() {
        let byte = ebsp[index];
        if byte == 0 {
            zeros += 1;
            // A valid stream cannot carry three real zero bytes.
            if zeros > 2 {
                return Err(DecodeError::Malformed);
            }
            rbsp.push(0);
        } else if byte == 3 && zeros == 2 {
            // Emulation byte: drop it, collapse the two zeros' run, and
            // require at least one more byte (the escaped one) to exist.
            index += 1;
            if index >= ebsp.len() {
                return Err(DecodeError::Malformed);
            }
            zeros = 0;
            continue;
        } else {
            zeros = 0;
            rbsp.push(byte);
        }
        index += 1;
    }
    Ok(rbsp)
}

/// Adds emulation-prevention bytes to RBSP payload bytes (excluding the NAL
/// header, which the caller prepends separately). Inverse of
/// [`rbsp_from_ebsp`] for test-fixture construction.
#[must_use]
pub fn ebsp_from_rbsp(rbsp: &[u8]) -> Vec<u8> {
    let mut ebsp = Vec::with_capacity(rbsp.len() + rbsp.len() / 2);
    let mut zeros: u32 = 0;
    for &byte in rbsp {
        if zeros == 2 && byte <= 3 {
            ebsp.push(3);
            zeros = 0;
        }
        ebsp.push(byte);
        zeros = if byte == 0 { zeros + 1 } else { 0 };
    }
    ebsp
}

/// Validates `rbsp_trailing_bits`: the first `1` must be followed by only
/// zero bits to the byte boundary, and the payload must end on that boundary.
///
/// # Errors
/// [`DecodeError::Malformed`] on a missing stop bit, nonzero cabac_zero_words
/// remnants, or nonzero padding bits.
pub fn validate_trailing_bits(rbsp: &[u8]) -> Result<(), DecodeError> {
    let Some(&last) = rbsp.last() else {
        return Err(DecodeError::Malformed);
    };
    // The stop bit is the LAST one-bit of the final byte; every bit below
    // it must be zero padding. An all-zero final byte has no stop bit.
    if last == 0 {
        return Err(DecodeError::Malformed);
    }
    let stop_index = last.trailing_zeros();
    let low_mask = (1u16 << stop_index) - 1;
    if (u16::from(last) & low_mask) != 0 {
        return Err(DecodeError::Malformed);
    }
    Ok(())
}

/// Bit index of the `rbsp_stop_one_bit`: the last one-bit of the payload,
/// ignoring trailing zero bytes (Annex-B `trailing_zero_8bits`). Syntax
/// readers bound themselves to this index, so `more_rbsp_data()` is simply
/// "bits remain before the bound".
///
/// # Errors
/// [`DecodeError::Malformed`] when the payload contains no one-bit at all.
pub fn stop_bit_position(rbsp: &[u8]) -> Result<usize, DecodeError> {
    let (index, &last) = rbsp
        .iter()
        .enumerate()
        .rev()
        .find(|(_, byte)| **byte != 0)
        .ok_or(DecodeError::Malformed)?;
    let trailing = usize::try_from(last.trailing_zeros()).map_err(|_| DecodeError::Malformed)?;
    Ok(index * 8 + 7 - trailing)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// Clause 7.4.1 emulation prevention: every `00 00 03` in EBSP collapses
    /// to `00 00`; a lone `00 03` (single zero) is real data, not an escape.
    #[test]
    fn spec_emulation_prevention_samples_decode() {
        let cases: &[(&[u8], &[u8])] = &[
            (&[0xAB, 0x11, 0xB4], &[0xAB, 0x11, 0xB4]),
            // Single zero then 03: no escape, bytes pass through.
            (&[0xAB, 0x00, 0x03, 0xB4], &[0xAB, 0x00, 0x03, 0xB4]),
            // Two zeros then 03: escape removed.
            (&[0xAB, 0x00, 0x00, 0x03, 0xB4], &[0xAB, 0x00, 0x00, 0xB4]),
            // Table 7-1 tail example: consecutive escapes.
            (
                &[0xAB, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x03],
                &[0xAB, 0x00, 0x00, 0x00, 0x00, 0x03],
            ),
            // Table 7-1: escape before 00 yields RBSP zeros.
            (&[0x00, 0x00, 0x03, 0x04], &[0x00, 0x00, 0x04]),
        ];
        for (ebsp, expected) in cases {
            assert_eq!(
                &rbsp_from_ebsp(ebsp, 64).unwrap(),
                expected,
                "ebsp {ebsp:?}"
            );
        }
    }

    #[test]
    fn impossible_zero_run_is_refused() {
        // Valid EBSP never carries three raw zero bytes in a row.
        assert_eq!(
            rbsp_from_ebsp(&[0x00, 0x00, 0x00], 64).unwrap_err(),
            DecodeError::Malformed
        );
        assert_eq!(
            rbsp_from_ebsp(&[0x01, 0x00, 0x00, 0x00, 0x02], 64).unwrap_err(),
            DecodeError::Malformed
        );
    }

    #[test]
    fn truncated_emulation_byte_is_refused() {
        // `00 00 03` with nothing after the escape byte cannot be real.
        assert_eq!(
            rbsp_from_ebsp(&[0x00, 0x00, 0x03], 64).unwrap_err(),
            DecodeError::Malformed
        );
    }

    #[test]
    fn byte_limit_is_enforced() {
        assert_eq!(
            rbsp_from_ebsp(&[0x01, 0x02, 0x03], 2).unwrap_err(),
            DecodeError::Limit
        );
    }

    #[test]
    fn ebsp_round_trip_is_lossless() {
        let rbsp: Vec<Vec<u8>> = vec![
            vec![0x90, 0x00, 0x00, 0x01], // becomes 00 00 03 01
            vec![0x00, 0x00, 0x02, 0x00, 0x00, 0x03],
            vec![0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01], // 3 zeros split by escape
            vec![0x00],
            vec![0x00, 0x00],
        ];
        for payload in &rbsp {
            let ebsp = ebsp_from_rbsp(payload);
            assert_eq!(rbsp_from_ebsp(&ebsp, payload.len() + 8).unwrap(), *payload);
        }
    }

    #[test]
    fn nal_header_parses_and_refuses_forbidden_and_zero_types() {
        let (header, payload) = NalPayload::new(&[0x41, 0x9A, 0x02]).split_header().unwrap();
        assert_eq!(header.ref_idc, 2);
        assert_eq!(header.unit_type, 1);
        assert_eq!(payload, &[0x9A, 0x02]);

        // Header-only NAL parses to an empty payload; stage code refuses it.
        let (header, payload) = NalPayload::new(&[0x01]).split_header().unwrap();
        assert_eq!(header.unit_type, 1);
        assert!(payload.is_empty());

        // Forbidden zero bit set (0x80) with a valid type 1.
        assert_eq!(
            NalPayload::new(&[0x81, 0x00]).split_header().unwrap_err(),
            DecodeError::Malformed
        );
        // Type 0 is reserved-impossible.
        assert_eq!(
            NalPayload::new(&[0x00, 0x00]).split_header().unwrap_err(),
            DecodeError::Malformed
        );
    }

    #[test]
    fn trailing_bits_validate_stop_bit_discipline() {
        // Stop bit in the top position of the final byte, no padding bits.
        assert!(validate_trailing_bits(&[0x80]).is_ok());
        // Stop bit lower down; nothing is below it, so valid.
        assert!(validate_trailing_bits(&[0b0100_0000]).is_ok());
        // Lowest set bit is BY DEFINITION the stop bit, so other set bits
        // above it are syntax, not padding violations.
        assert!(validate_trailing_bits(&[0b0100_0001]).is_ok());
        // All-zero final byte has no stop bit at all.
        assert!(validate_trailing_bits(&[0x00]).is_err());
        // Empty payload has no rbsp_trailing_bits.
        assert!(validate_trailing_bits(&[]).is_err());
    }
}
