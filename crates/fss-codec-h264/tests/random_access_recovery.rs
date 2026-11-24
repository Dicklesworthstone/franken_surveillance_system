#![forbid(unsafe_code)]
//! Real NAL decoding across IDR output resets and rejected multi-slice pictures.
//! I_PCM samples identify every picture independently of prediction or an encoder.

use std::error::Error;

use fss_codec_h264::rbsp::ebsp_from_rbsp;
use fss_codec_h264::{DecodeError, Decoder, DecoderLimits, Picture, UnsupportedFeature};

type Test = Result<(), Box<dyn Error>>;

#[derive(Default)]
struct Bits(Vec<u8>);

impl Bits {
    fn u(&mut self, width: u32, value: u64) -> &mut Self {
        for shift in (0..width).rev() {
            self.0.push(((value >> shift) & 1) as u8);
        }
        self
    }

    fn ue(&mut self, value: u64) -> &mut Self {
        let code = value + 1;
        let width = 64 - code.leading_zeros();
        self.u(width - 1, 0).u(width, code)
    }

    fn se(&mut self, value: i64) -> &mut Self {
        self.ue(if value > 0 { 2 * value - 1 } else { -2 * value } as u64)
    }

    fn align(&mut self) {
        while !self.0.len().is_multiple_of(8) {
            self.0.push(0);
        }
    }

    fn nal(mut self, header: u8) -> Vec<u8> {
        self.0.push(1);
        self.align();
        let rbsp: Vec<u8> = self
            .0
            .as_chunks::<8>()
            .0
            .iter()
            .map(|bits| bits.iter().fold(0, |value, bit| (value << 1) | bit))
            .collect();
        let mut nal = vec![header];
        nal.extend(ebsp_from_rbsp(&rbsp));
        nal
    }
}

fn sps(reorder: u64) -> Vec<u8> {
    let mut w = Bits::default();
    w.u(8, 77).u(8, 0).u(8, 30).ue(0); // Main profile; SPS 0.
    w.ue(0).ue(0).ue(0); // Four-bit frame_num and POC LSB; POC type 0.
    w.ue(4).u(1, 0).ue(1).ue(0); // Four references; no gaps; 32x16.
    w.u(1, 1).u(1, 1).u(1, 0); // Progressive, direct inference, no crop.
    w.u(1, 1).u(8, 0); // VUI, with only bitstream restrictions present.
    w.u(1, 1).u(1, 1); // Restriction; motion over picture boundaries.
    w.ue(0).ue(0).ue(16).ue(16).ue(reorder).ue(4);
    w.nal(0x67)
}

#[derive(Clone, Copy, Default)]
struct Pps {
    id: u64,
    sps_id: u64,
    qp_delta: i64,
    constrained_intra: bool,
}

impl Pps {
    fn nal(self) -> Vec<u8> {
        let mut w = Bits::default();
        w.ue(self.id).ue(self.sps_id).u(1, 0).u(1, 0).ue(0);
        w.ue(0).ue(0).u(1, 0).u(2, 0);
        w.se(self.qp_delta).se(0).se(0);
        w.u(1, 1).u(1, u64::from(self.constrained_intra)).u(1, 0);
        w.nal(0x68)
    }
}

#[derive(Clone, Copy)]
struct Frame {
    number: u64,
    poc: u64,
    pixel: u8,
    idr: bool,
    reference: bool,
    discard_prior: bool,
    pps_id: u64,
}

impl Frame {
    fn reference(number: u64, poc: u64, pixel: u8) -> Self {
        Self {
            number,
            poc,
            pixel,
            idr: false,
            reference: true,
            discard_prior: false,
            pps_id: 0,
        }
    }

    fn idr(pixel: u8, discard_prior: bool) -> Self {
        Self {
            idr: true,
            discard_prior,
            ..Self::reference(0, 0, pixel)
        }
    }

    fn slice(self, first_mb: u64, count: u64) -> Vec<u8> {
        let mut w = Bits::default();
        w.ue(first_mb).ue(7).ue(self.pps_id).u(4, self.number);
        if self.idr {
            w.ue(0);
        }
        w.u(4, self.poc);
        if self.reference {
            if self.idr {
                w.u(1, u64::from(self.discard_prior)).u(1, 0);
            } else {
                w.u(1, 0); // Sliding-window reference marking.
            }
        }
        w.se(0).ue(1); // Constant QP; no deblocking of the identifying samples.
        for _ in 0..count {
            w.ue(25); // I_PCM.
            w.align();
            for _ in 0..256 {
                w.u(8, u64::from(self.pixel));
            }
            for _ in 0..128 {
                w.u(8, 128);
            }
        }
        w.nal(if self.idr {
            0x65
        } else if self.reference {
            0x41
        } else {
            0x01
        })
    }

    fn nal(self) -> Vec<u8> {
        self.slice(0, 2)
    }
}

fn decoder(reorder: u64) -> Result<Decoder, DecodeError> {
    let mut decoder = Decoder::new(DecoderLimits {
        max_nal_bytes: 1024,
        ..DecoderLimits::default()
    })?;
    assert!(decoder.decode_nal(&sps(reorder))?.is_none());
    assert!(decoder.decode_nal(&Pps::default().nal())?.is_none());
    Ok(decoder)
}

fn feed(decoder: &mut Decoder, nal: &[u8]) -> Result<Vec<Picture>, DecodeError> {
    let mut pictures = Vec::new();
    if let Some(picture) = decoder.decode_nal(nal)? {
        pictures.push(picture);
    }
    pictures.extend(std::iter::from_fn(|| decoder.next_output()));
    Ok(pictures)
}

fn assert_pictures(pictures: &[Picture], expected: &[(u64, i32, u8)]) {
    assert_eq!(pictures.len(), expected.len());
    for (picture, &(index, poc, pixel)) in pictures.iter().zip(expected) {
        assert_eq!(picture.decode_index(), index);
        assert_eq!(picture.poc(), poc);
        assert_eq!((picture.width(), picture.height()), (32, 16));
        assert!(picture.luma().iter().all(|&sample| sample == pixel));
        assert!(
            picture
                .cb()
                .iter()
                .chain(picture.cr())
                .all(|&sample| sample == 128)
        );
    }
}

#[test]
fn idr_discards_only_waiting_pictures_when_explicitly_requested() -> Test {
    for discard_prior in [false, true] {
        let mut decoder = decoder(2)?;
        let mut pictures = Vec::new();
        for frame in [
            Frame::idr(10, false),
            Frame::reference(1, 6, 60),
            Frame {
                reference: false,
                ..Frame::reference(2, 2, 20)
            },
            Frame {
                reference: false,
                ..Frame::reference(2, 4, 40)
            },
        ] {
            pictures.extend(feed(&mut decoder, &frame.nal())?);
        }
        assert_pictures(&pictures, &[(0, 0, 10), (2, 2, 20)]);
        pictures.extend(feed(&mut decoder, &Frame::idr(90, discard_prior).nal())?);
        pictures.extend(decoder.finish()?);
        assert_eq!(decoder.pictures_decoded(), 5);
        if discard_prior {
            assert_pictures(&pictures, &[(0, 0, 10), (2, 2, 20), (4, 0, 90)]);
        } else {
            assert_pictures(
                &pictures,
                &[(0, 0, 10), (2, 2, 20), (3, 4, 40), (1, 6, 60), (4, 0, 90)],
            );
        }
    }
    Ok(())
}

#[test]
fn idr_discard_preserves_pictures_already_released_to_the_output_queue() -> Test {
    let mut decoder = decoder(2)?;
    assert!(decoder.decode_nal(&Frame::idr(10, false).nal())?.is_none());
    assert!(
        decoder
            .decode_nal(&Frame::reference(1, 6, 60).nal())?
            .is_none()
    );
    let first = feed(
        &mut decoder,
        &Frame {
            reference: false,
            ..Frame::reference(2, 2, 20)
        }
        .nal(),
    )?;
    assert_pictures(&first, &[(0, 0, 10)]);

    // This IDR releases both waiting old pictures, returning one and queuing the other.
    let released: Vec<_> = decoder
        .decode_nal(&Frame::idr(80, false).nal())?
        .into_iter()
        .collect();
    assert_pictures(&released, &[(2, 2, 20)]);
    // The next IDR discards the waiting 80 picture, not the already-released 60 picture.
    let queued = feed(&mut decoder, &Frame::idr(90, true).nal())?;
    assert_pictures(&queued, &[(1, 6, 60)]);
    assert_pictures(&decoder.finish()?, &[(4, 0, 90)]);
    Ok(())
}

#[test]
fn every_rejected_nal_quarantines_the_partial_picture_and_requires_idr() -> Test {
    let cases = [
        ("size", vec![0; 1025], DecodeError::Limit),
        ("empty", vec![], DecodeError::UnexpectedNal),
        ("header", vec![0xe5, 0x80], DecodeError::Malformed),
        (
            "unsupported SPS",
            vec![0x67, 0],
            DecodeError::Unsupported(UnsupportedFeature::Profile),
        ),
        (
            "truncated SPS",
            vec![0x67, 77, 0, 30],
            DecodeError::Malformed,
        ),
        ("pps", vec![0x68, 0], DecodeError::Malformed),
        (
            "unknown SPS",
            Pps {
                sps_id: 1,
                ..Pps::default()
            }
            .nal(),
            DecodeError::MissingParameterSet,
        ),
        (
            "partition",
            vec![0x42, 0x80],
            DecodeError::Unsupported(UnsupportedFeature::DataPartitioning),
        ),
        ("slice", vec![0x41, 0], DecodeError::Malformed),
    ];
    for (case, rejected, expected) in cases {
        let mut decoder = decoder(0)?;
        assert_pictures(
            &feed(&mut decoder, &Frame::idr(10, false).nal())?,
            &[(0, 0, 10)],
        );
        let partial = Frame::reference(1, 2, 20);
        assert!(decoder.decode_nal(&partial.slice(0, 1))?.is_none());
        assert!(decoder.has_incomplete_picture());
        assert_eq!(
            decoder.decode_nal(&rejected).err(),
            Some(expected),
            "{case}"
        );
        assert!(!decoder.has_incomplete_picture(), "{case}");
        assert!(decoder.decode_nal(&partial.slice(1, 1)).is_err(), "{case}");
        assert_eq!(
            decoder.decode_nal(&partial.nal()).err(),
            Some(DecodeError::MissingReference),
            "{case}"
        );
        assert!(decoder.next_output().is_none(), "{case}");
        assert_eq!(decoder.pictures_decoded(), 1, "{case}");
        assert_pictures(
            &feed(&mut decoder, &Frame::idr(90, false).nal())?,
            &[(1, 0, 90)],
        );
        assert!(decoder.finish()?.is_empty());
    }
    Ok(())
}

#[test]
fn rejection_between_complete_pictures_also_requires_a_new_idr() -> Test {
    let mut decoder = decoder(0)?;
    assert_pictures(
        &feed(&mut decoder, &Frame::idr(10, false).nal())?,
        &[(0, 0, 10)],
    );
    assert!(!decoder.has_incomplete_picture());
    assert_eq!(
        decoder.decode_nal(&[0xe5, 0x80]).err(),
        Some(DecodeError::Malformed)
    );
    assert_eq!(
        decoder.decode_nal(&Frame::reference(1, 2, 20).nal()).err(),
        Some(DecodeError::MissingReference)
    );
    assert_pictures(
        &feed(&mut decoder, &Frame::idr(90, false).nal())?,
        &[(1, 0, 90)],
    );
    Ok(())
}

#[test]
fn identical_and_unrelated_parameter_set_repeats_preserve_multislice_pixels() -> Test {
    let mut decoder = decoder(0)?;
    let frame = Frame::idr(30, false);
    assert!(decoder.decode_nal(&frame.slice(0, 1))?.is_none());
    assert!(decoder.decode_nal(&sps(0))?.is_none());
    assert!(decoder.decode_nal(&Pps::default().nal())?.is_none());
    assert!(
        decoder
            .decode_nal(
                &Pps {
                    id: 1,
                    qp_delta: 3,
                    ..Pps::default()
                }
                .nal()
            )?
            .is_none()
    );
    assert!(decoder.has_incomplete_picture());
    assert_pictures(&feed(&mut decoder, &frame.slice(1, 1))?, &[(0, 0, 30)]);
    assert!(!decoder.has_incomplete_picture());
    Ok(())
}

#[test]
fn changed_pps_content_or_identity_cannot_complete_a_picture() -> Test {
    let changes = [
        Pps {
            qp_delta: 1,
            ..Pps::default()
        },
        Pps {
            constrained_intra: true,
            ..Pps::default()
        },
        Pps {
            id: 1,
            ..Pps::default()
        },
    ];
    for changed in changes {
        let mut decoder = decoder(0)?;
        let frame = Frame::idr(30, false);
        assert!(decoder.decode_nal(&frame.slice(0, 1))?.is_none());
        assert!(decoder.decode_nal(&changed.nal())?.is_none());
        let continuation = Frame {
            pps_id: changed.id,
            ..frame
        };
        assert_eq!(
            decoder.decode_nal(&continuation.slice(1, 1)).err(),
            Some(DecodeError::Malformed)
        );
        assert!(!decoder.has_incomplete_picture());
        assert_eq!(decoder.pictures_decoded(), 0);
        assert!(decoder.next_output().is_none());
        assert_eq!(
            decoder.decode_nal(&Frame::reference(1, 2, 20).nal()).err(),
            Some(DecodeError::MissingReference)
        );
        // Restore the original PPS; the actual recovery still requires a new IDR.
        assert!(decoder.decode_nal(&Pps::default().nal())?.is_none());
        assert_pictures(
            &feed(&mut decoder, &Frame::idr(90, false).nal())?,
            &[(0, 0, 90)],
        );
        assert!(decoder.finish()?.is_empty());
    }
    Ok(())
}

#[test]
fn pps_changes_between_complete_pictures_remain_admitted() -> Test {
    let mut decoder = decoder(0)?;
    assert_pictures(
        &feed(&mut decoder, &Frame::idr(10, false).nal())?,
        &[(0, 0, 10)],
    );
    assert!(
        decoder
            .decode_nal(
                &Pps {
                    qp_delta: 1,
                    ..Pps::default()
                }
                .nal()
            )?
            .is_none()
    );
    assert_pictures(
        &feed(&mut decoder, &Frame::reference(1, 2, 20).nal())?,
        &[(1, 2, 20)],
    );
    Ok(())
}
