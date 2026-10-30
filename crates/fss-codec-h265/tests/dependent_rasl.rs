#![forbid(unsafe_code)]
//! Skipped RASL pictures retain bounded header inheritance, never pixel authority.
//! The IDR seed is oracle-backed. Leading-picture payloads deliberately contain
//! headers only because the RASL omission path must not decode their entropy.

use fss_codec_h265::{DecodeError, Decoder, DecoderLimits, Picture, annex_b_nal_units};
use std::error::Error;

type Test<T = ()> = Result<T, Box<dyn Error>>;
const SEED: &[u8] = include_bytes!("fixtures/decode/dependent_context_chain.h265");
const CHANGED: &[u8] = include_bytes!("fixtures/decode/dependent_qp_carry.h265");

#[derive(Default)]
struct Bits {
    bytes: Vec<u8>,
    position: usize,
}
impl Bits {
    fn bit(&mut self, value: bool) {
        if self.position.is_multiple_of(8) {
            self.bytes.push(0);
        }
        if value {
            let index = self.bytes.len() - 1;
            self.bytes[index] |= 1 << (7 - self.position % 8);
        }
        self.position += 1;
    }
    fn uint(&mut self, count: u32, value: u32) {
        for shift in (0..count).rev() {
            self.bit(value & (1 << shift) != 0);
        }
    }
    fn ue(&mut self, value: u32) {
        let coded = value + 1;
        let length = 32 - coded.leading_zeros();
        self.uint(length - 1, 0);
        self.uint(length, coded);
    }
    fn aligned_one(&mut self) {
        self.bit(true);
        while !self.position.is_multiple_of(8) {
            self.bit(false);
        }
    }
    fn nal(mut self) -> Vec<u8> {
        self.aligned_one(); // header byte_alignment()
        self.aligned_one(); // rbsp_stop_one_bit after the complete header
        let mut nal = vec![8 << 1, 1]; // RASL_N, base layer, TemporalId 0
        let mut zeros = 0;
        for byte in self.bytes {
            if zeros == 2 && byte <= 3 {
                nal.push(3);
                zeros = 0;
            }
            nal.push(byte);
            zeros = if byte == 0 { zeros + 1 } else { 0 };
        }
        nal
    }
}

fn independent_rasl(first: bool, address: u32, poc: u32) -> Vec<u8> {
    let mut bits = Bits::default();
    bits.bit(first); // RASL has no IRAP prior-output flag
    bits.ue(0); // PPS 0
    if !first {
        bits.bit(false);
        bits.uint(2, address);
    }
    bits.ue(2); // I slice, matching the seed SPS's one-picture DPB
    bits.uint(8, poc);
    bits.bit(false); // explicit empty short-term RPS
    bits.ue(0);
    bits.ue(0);
    bits.ue(0); // slice_qp_delta = 0
    // No MVP, SAO, slice deblock override, WPP or extension in this fixture.
    bits.nal()
}

fn dependent_rasl(address: u32) -> Vec<u8> {
    let mut bits = Bits::default();
    bits.bit(false);
    bits.ue(0);
    bits.bit(true);
    bits.uint(2, address); // four CTBs in the retained 64x16 seed
    bits.nal()
}

fn complete_seed(decoder: &mut Decoder) -> Test<Picture> {
    let mut pictures = decoder.decode_annex_b(SEED)?;
    pictures.extend(decoder.finish()?);
    assert_eq!(pictures.len(), 1);
    let picture = pictures.remove(0);
    assert_eq!((picture.width(), picture.height()), (64, 16));
    Ok(picture)
}

fn opened(limits: DecoderLimits) -> Test<(Decoder, Picture)> {
    let mut decoder = Decoder::new(limits)?;
    let seed = complete_seed(&mut decoder)?;
    assert_eq!(decoder.pictures_decoded(), 1);
    assert!(
        decoder
            .decode_nal(&independent_rasl(true, 0, 255))?
            .is_none()
    );
    assert!(decoder.next_output().is_none());
    Ok((decoder, seed))
}

fn recover(decoder: &mut Decoder, seed: &Picture) -> Test {
    let picture = complete_seed(decoder)?;
    assert_eq!(picture.to_i420(), seed.to_i420());
    assert_eq!(picture.decode_index(), 1);
    assert_eq!(decoder.pictures_decoded(), 2);
    Ok(())
}

#[test]
fn skipped_dependent_headers_do_not_decode_entropy_or_publish_pixels() -> Test {
    let (mut decoder, _) = opened(DecoderLimits::default())?;
    for address in 1..=3 {
        assert!(decoder.decode_nal(&dependent_rasl(address))?.is_none());
        assert!(decoder.next_output().is_none());
        assert_eq!(decoder.pictures_decoded(), 1);
    }
    assert!(decoder.finish()?.is_empty());
    assert_eq!(decoder.pictures_decoded(), 1);
    Ok(())
}

#[test]
fn finish_eos_and_eob_clear_skipped_header_inheritance() -> Test {
    for terminator in [None, Some(36), Some(37)] {
        let (mut decoder, seed) = opened(DecoderLimits::default())?;
        assert!(decoder.decode_nal(&dependent_rasl(1))?.is_none());
        if let Some(kind) = terminator {
            assert!(decoder.decode_nal(&[kind << 1, 1, 0x80])?.is_none());
        } else {
            assert!(decoder.finish()?.is_empty());
        }
        assert_eq!(
            decoder.decode_nal(&dependent_rasl(2)).err(),
            Some(DecodeError::IncompletePicture)
        );
        recover(&mut decoder, &seed)?;
    }
    Ok(())
}

#[test]
fn skipped_segments_share_one_bounded_picture_allowance() -> Test {
    let exact = DecoderLimits {
        max_slices_per_picture: 4,
        ..DecoderLimits::default()
    };
    let (mut decoder, _) = opened(exact)?;
    for address in 1..=3 {
        assert!(decoder.decode_nal(&dependent_rasl(address))?.is_none());
    }
    assert!(decoder.finish()?.is_empty());
    let below = DecoderLimits {
        max_slices_per_picture: 3,
        ..exact
    };
    let (mut decoder, seed) = opened(below)?;
    for address in 1..=2 {
        assert!(decoder.decode_nal(&dependent_rasl(address))?.is_none());
    }
    assert_eq!(
        decoder.decode_nal(&dependent_rasl(3)).err(),
        Some(DecodeError::Limit)
    );
    assert_eq!(
        decoder.decode_nal(&dependent_rasl(1)).err(),
        Some(DecodeError::IncompletePicture)
    );
    recover(&mut decoder, &seed)
}

#[test]
fn skipped_corrupt_headers_and_overlap_discard_inheritance_before_idr_recovery() -> Test {
    let mut wrong_temporal = dependent_rasl(2);
    wrong_temporal[1] = 2;
    for bad in [Vec::new(), vec![8 << 1], dependent_rasl(1), wrong_temporal] {
        let (mut decoder, seed) = opened(DecoderLimits::default())?;
        assert!(decoder.decode_nal(&dependent_rasl(1))?.is_none());
        assert!(decoder.decode_nal(&bad).is_err());
        assert!(decoder.next_output().is_none());
        assert_eq!(
            decoder.decode_nal(&dependent_rasl(2)).err(),
            Some(DecodeError::IncompletePicture)
        );
        recover(&mut decoder, &seed)?;
    }
    Ok(())
}

#[test]
fn skipped_picture_parameter_fence_accepts_retransmission_and_refuses_redefinition() -> Test {
    let original: Vec<_> = annex_b_nal_units(SEED).collect();
    let changed: Vec<_> = annex_b_nal_units(CHANGED).collect();
    let (mut decoder, _) = opened(DecoderLimits::default())?;
    for parameter in &original[1..3] {
        assert!(decoder.decode_nal(parameter)?.is_none());
    }
    assert!(decoder.decode_nal(&dependent_rasl(1))?.is_none());
    assert!(decoder.finish()?.is_empty());

    let mut disabled = original[2].to_vec();
    assert_ne!(disabled[2] & 0x20, 0);
    disabled[2] &= !0x20;
    for replacement in [changed[1], changed[2], disabled.as_slice()] {
        let (mut decoder, seed) = opened(DecoderLimits::default())?;
        assert!(decoder.decode_nal(replacement)?.is_none());
        assert!(decoder.decode_nal(&dependent_rasl(1)).is_err());
        assert!(decoder.next_output().is_none());
        assert_eq!(decoder.pictures_decoded(), 1);
        recover(&mut decoder, &seed)?;
    }
    Ok(())
}

#[test]
fn skipped_independent_headers_must_keep_the_same_picture_identity() -> Test {
    let (mut decoder, _) = opened(DecoderLimits::default())?;
    assert!(
        decoder
            .decode_nal(&independent_rasl(false, 1, 255))?
            .is_none()
    );
    assert!(decoder.decode_nal(&dependent_rasl(2))?.is_none());
    assert!(decoder.finish()?.is_empty());

    let (mut decoder, seed) = opened(DecoderLimits::default())?;
    assert_eq!(
        decoder.decode_nal(&independent_rasl(false, 1, 254)).err(),
        Some(DecodeError::Malformed)
    );
    assert_eq!(
        decoder.decode_nal(&dependent_rasl(2)).err(),
        Some(DecodeError::IncompletePicture)
    );
    recover(&mut decoder, &seed)
}
