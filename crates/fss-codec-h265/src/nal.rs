//! NAL unit header (ITU-T H.265 clause 7.3.1.2), emulation-prevention
//! removal (clause 7.4.2) and the `rbsp_stop_one_bit` search.

use crate::DecodeError;

/// NAL unit types this decoder distinguishes (Table 7-1).
pub mod unit_type {
    /// Trailing picture, sub-layer non-reference.
    pub const TRAIL_N: u8 = 0;
    /// Last VCL type of the leading/trailing range (`RSV_VCL_R15`).
    pub const RSV_VCL_R15: u8 = 15;
    /// Broken-link access picture (first IRAP type).
    pub const BLA_W_LP: u8 = 16;
    /// BLA with RADL pictures.
    pub const BLA_W_RADL: u8 = 17;
    /// BLA without leading pictures.
    pub const BLA_N_LP: u8 = 18;
    /// IDR that may have RADL pictures.
    pub const IDR_W_RADL: u8 = 19;
    /// IDR without leading pictures.
    pub const IDR_N_LP: u8 = 20;
    /// Clean random access picture.
    pub const CRA_NUT: u8 = 21;
    /// Last reserved IRAP type.
    pub const RSV_IRAP_VCL23: u8 = 23;
    /// Video parameter set.
    pub const VPS: u8 = 32;
    /// Sequence parameter set.
    pub const SPS: u8 = 33;
    /// Picture parameter set.
    pub const PPS: u8 = 34;
    /// End of sequence.
    pub const EOS: u8 = 36;
    /// End of bitstream.
    pub const EOB: u8 = 37;
}

/// Parsed two-byte NAL unit header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NalHeader {
    /// `nal_unit_type`, 0..=63.
    pub unit_type: u8,
    /// `nuh_layer_id`, 0..=63.
    pub layer_id: u8,
    /// `TemporalId` (`nuh_temporal_id_plus1 - 1`).
    pub temporal_id: u8,
}

impl NalHeader {
    /// Splits a NAL unit (header included, no start code) into its header
    /// and escaped payload.
    ///
    /// # Errors
    /// [`DecodeError::Malformed`] on a set forbidden bit, a zero
    /// `nuh_temporal_id_plus1`, or fewer than two bytes.
    pub fn split(nal: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let [first, second, payload @ ..] = nal else {
            return Err(DecodeError::Malformed);
        };
        if first & 0x80 != 0 {
            return Err(DecodeError::Malformed);
        }
        let temporal_plus1 = second & 7;
        if temporal_plus1 == 0 {
            return Err(DecodeError::Malformed);
        }
        Ok((
            Self {
                unit_type: (first >> 1) & 0x3F,
                layer_id: ((first & 1) << 5) | (second >> 3),
                temporal_id: temporal_plus1 - 1,
            },
            payload,
        ))
    }

    /// True for coded slice segment NAL units (types 0..=31 hold VCL,
    /// of which 0..=9 and 16..=21 are defined).
    #[must_use]
    pub const fn is_vcl(self) -> bool {
        self.unit_type < 32
    }

    /// Intra random access point picture (BLA, IDR, CRA).
    #[must_use]
    pub const fn is_irap(self) -> bool {
        self.unit_type >= unit_type::BLA_W_LP && self.unit_type <= unit_type::RSV_IRAP_VCL23
    }

    /// Instantaneous decoding refresh picture.
    #[must_use]
    pub const fn is_idr(self) -> bool {
        self.unit_type == unit_type::IDR_W_RADL || self.unit_type == unit_type::IDR_N_LP
    }

    /// Broken link access picture.
    #[must_use]
    pub const fn is_bla(self) -> bool {
        self.unit_type >= unit_type::BLA_W_LP && self.unit_type <= unit_type::BLA_N_LP
    }

    /// Random access skipped leading picture (RASL_N / RASL_R).
    #[must_use]
    pub const fn is_rasl(self) -> bool {
        self.unit_type == 8 || self.unit_type == 9
    }

    /// Sub-layer non-reference picture (even types below 16, Table 7-1).
    #[must_use]
    pub const fn is_sub_layer_non_reference(self) -> bool {
        self.unit_type <= 14 && self.unit_type.is_multiple_of(2)
    }
}

/// Removes emulation-prevention bytes: every `00 00 03` whose `03` was
/// inserted by the encoder becomes `00 00`. A surviving `00 00 00` or
/// `00 00 01` inside a NAL proves corrupt framing and is refused.
///
/// # Errors
/// [`DecodeError::Limit`] when the payload exceeds `max_bytes`;
/// [`DecodeError::Malformed`] on an impossible zero run.
pub fn rbsp_from_ebsp(ebsp: &[u8], max_bytes: usize) -> Result<Vec<u8>, DecodeError> {
    if ebsp.len() > max_bytes {
        return Err(DecodeError::Limit);
    }
    let mut rbsp = Vec::new();
    rbsp.try_reserve_exact(ebsp.len())
        .map_err(|_| DecodeError::Limit)?;
    let mut zeros = 0u32;
    let mut index = 0;
    while index < ebsp.len() {
        let byte = ebsp[index];
        if zeros == 2 && byte < 3 {
            return Err(DecodeError::Malformed);
        }
        if zeros == 2 && byte == 3 {
            zeros = 0;
            index += 1;
            // The escaped byte must exist and be 0..=3.
            match ebsp.get(index) {
                Some(&next) if next <= 3 => {}
                // `00 00 03` as the final bytes is allowed only for a
                // trailing cabac_zero_word; tolerate it.
                None => break,
                Some(_) => return Err(DecodeError::Malformed),
            }
            continue;
        }
        zeros = if byte == 0 { zeros + 1 } else { 0 };
        rbsp.push(byte);
        index += 1;
    }
    Ok(rbsp)
}

/// Bit index of the `rbsp_stop_one_bit`: the last one-bit of the payload,
/// ignoring trailing zero bytes (`cabac_zero_word`s and Annex-B padding).
///
/// # Errors
/// [`DecodeError::Malformed`] when the payload holds no one-bit.
pub fn stop_bit_position(rbsp: &[u8]) -> Result<usize, DecodeError> {
    let (index, &last) = rbsp
        .iter()
        .enumerate()
        .rev()
        .find(|(_, byte)| **byte != 0)
        .ok_or(DecodeError::Malformed)?;
    Ok(index * 8 + 7 - last.trailing_zeros() as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Clause 7.3.1.2 layout: forbidden(1) type(6) layer(6) tid+1(3).
    /// 0x40 0x01 is a VPS, layer 0, TemporalId 0; 0x26 0x01 is an
    /// IDR_W_RADL; 0x02 0x01 a TRAIL_R.
    #[test]
    fn header_fields_by_hand() -> Result<(), DecodeError> {
        let (vps, payload) = NalHeader::split(&[0x40, 0x01, 0x0C])?;
        assert_eq!(
            vps,
            NalHeader {
                unit_type: 32,
                layer_id: 0,
                temporal_id: 0
            }
        );
        assert_eq!(payload, &[0x0C]);
        let (idr, _) = NalHeader::split(&[0x26, 0x01])?;
        assert!(idr.is_idr() && idr.is_irap() && idr.is_vcl());
        let (trail, _) = NalHeader::split(&[0x02, 0x01])?;
        assert_eq!(trail.unit_type, 1);
        assert!(!trail.is_irap() && !trail.is_sub_layer_non_reference());
        // Layer id straddles the two bytes: 0x41 0x09 -> layer 33, tid 0.
        let (layered, _) = NalHeader::split(&[0x41, 0x09])?;
        assert_eq!((layered.unit_type, layered.layer_id), (32, 33));
        assert!(NalHeader::split(&[0xC0, 0x01]).is_err());
        assert!(NalHeader::split(&[0x40, 0x00]).is_err());
        assert!(NalHeader::split(&[0x40]).is_err());
        Ok(())
    }

    #[test]
    fn emulation_prevention_is_removed_and_policed() {
        assert_eq!(
            rbsp_from_ebsp(&[0xAB, 0x00, 0x00, 0x03, 0x01], 16),
            Ok(vec![0xAB, 0x00, 0x00, 0x01])
        );
        assert_eq!(
            rbsp_from_ebsp(&[0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x03], 16),
            Ok(vec![0x00, 0x00, 0x00, 0x00, 0x03])
        );
        assert_eq!(
            rbsp_from_ebsp(&[0x00, 0x03, 0x00], 16),
            Ok(vec![0x00, 0x03, 0x00])
        );
        assert!(rbsp_from_ebsp(&[0x01, 0x00, 0x00, 0x00], 16).is_err());
        assert!(rbsp_from_ebsp(&[0x00, 0x00, 0x01], 16).is_err());
        assert!(rbsp_from_ebsp(&[0x00, 0x00, 0x03, 0x04], 16).is_err());
        assert_eq!(rbsp_from_ebsp(&[1, 2, 3], 2), Err(DecodeError::Limit));
    }

    #[test]
    fn stop_bit_is_the_last_one_bit() {
        assert_eq!(stop_bit_position(&[0x80]), Ok(0));
        assert_eq!(stop_bit_position(&[0xFF, 0x40, 0x00, 0x00]), Ok(9));
        assert!(stop_bit_position(&[0x00, 0x00]).is_err());
    }
}
