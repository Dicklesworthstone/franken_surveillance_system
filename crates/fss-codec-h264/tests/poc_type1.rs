#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Progressive POC type 1 through real SPS, PPS and I_PCM decoding. Expected
//! orders and pixel values are independently hand-computed from H.264 8.2.1.2;
//! the encoded I_PCM payload makes each picture's identity directly observable.

use fss_codec_h264::params::parse_sps;
use fss_codec_h264::rbsp::{ebsp_from_rbsp, rbsp_from_ebsp};
use fss_codec_h264::{DecodeError, Decoder, DecoderLimits, Picture};

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
            .chunks(8)
            .map(|bits| bits.iter().fold(0, |value, bit| (value << 1) | bit))
            .collect();
        let mut nal = vec![header];
        nal.extend(ebsp_from_rbsp(&rbsp));
        nal
    }
}

#[derive(Clone)]
struct Sequence {
    cycle: Vec<i64>,
    non_reference: i64,
    bottom_offset: i64,
    zero_deltas: bool,
    bottom_delta_present: bool,
    width_mbs: u64,
}

impl Default for Sequence {
    fn default() -> Self {
        Self {
            cycle: vec![2],
            non_reference: -1,
            bottom_offset: 0,
            zero_deltas: true,
            bottom_delta_present: false,
            width_mbs: 1,
        }
    }
}

impl Sequence {
    fn sps(&self) -> Vec<u8> {
        let mut w = Bits::default();
        w.u(8, 66).u(8, 0).u(8, 30).ue(0);
        w.ue(0).ue(1).u(1, u64::from(self.zero_deltas));
        w.se(self.non_reference)
            .se(self.bottom_offset)
            .ue(self.cycle.len() as u64);
        for offset in &self.cycle {
            w.se(*offset);
        }
        // Four-bit frame_num; two retained reference frames; no gap concealment.
        w.ue(2).u(1, 0).ue(self.width_mbs - 1).ue(0);
        w.u(1, 1).u(1, 1).u(1, 0).u(1, 0); // progressive, inference, no crop/VUI
        w.nal(0x67)
    }
    fn pps(&self) -> Vec<u8> {
        let mut w = Bits::default();
        w.ue(0)
            .ue(0)
            .u(1, 0)
            .u(1, u64::from(self.bottom_delta_present))
            .ue(0);
        w.ue(0).ue(0).u(1, 0).u(2, 0).se(0).se(0).se(0);
        w.u(1, 1).u(1, 0).u(1, 0);
        w.nal(0x68)
    }
    fn picture(&self, frame: Frame) -> Vec<u8> {
        self.slice(frame, 0, self.width_mbs)
    }
    fn slice(&self, frame: Frame, first_mb: u64, count: u64) -> Vec<u8> {
        let mut w = Bits::default();
        w.ue(first_mb).ue(7).ue(0).u(4, frame.number);
        if frame.idr {
            w.ue(0);
        }
        if !self.zero_deltas {
            w.se(frame.deltas[0]);
            if self.bottom_delta_present {
                w.se(frame.deltas[1]);
            }
        }
        if frame.reference {
            if frame.idr {
                w.u(1, 0).u(1, 0);
            } else if frame.reset {
                w.u(1, 1).ue(5).ue(0);
            } else {
                w.u(1, 0);
            }
        }
        w.se(0).ue(1); // constant QP; deblocking disabled to preserve PCM samples.
        for _ in 0..count {
            w.ue(25); // I_PCM
            w.align();
            for _ in 0..256 {
                w.u(8, u64::from(frame.pixel));
            }
            for _ in 0..128 {
                w.u(8, 128);
            }
        }
        w.nal(if frame.idr {
            0x65
        } else if frame.reference {
            0x41
        } else {
            0x01
        })
    }
    fn prefix(&self) -> Vec<Vec<u8>> {
        vec![self.sps(), self.pps()]
    }
}

#[derive(Clone, Copy)]
struct Frame {
    idr: bool,
    reference: bool,
    reset: bool,
    number: u64,
    deltas: [i64; 2],
    pixel: u8,
}

impl Frame {
    fn reference(number: u64, pixel: u8) -> Self {
        Self {
            idr: false,
            reference: true,
            reset: false,
            number,
            deltas: [0; 2],
            pixel,
        }
    }
    fn idr(pixel: u8) -> Self {
        Self {
            idr: true,
            ..Self::reference(0, pixel)
        }
    }
    fn disposable(number: u64, pixel: u8) -> Self {
        Self {
            reference: false,
            ..Self::reference(number, pixel)
        }
    }
}

fn feed(decoder: &mut Decoder, units: &[Vec<u8>]) -> Result<Vec<Picture>, DecodeError> {
    let mut output = Vec::new();
    for unit in units {
        if let Some(picture) = decoder.decode_nal(unit)? {
            output.push(picture);
        }
        while let Some(picture) = decoder.next_output() {
            output.push(picture);
        }
    }
    Ok(output)
}

fn decode(sequence: &Sequence, frames: &[Frame]) -> Vec<Picture> {
    let mut units = sequence.prefix();
    units.extend(frames.iter().map(|frame| sequence.picture(*frame)));
    let mut decoder = Decoder::new(DecoderLimits::default()).unwrap();
    let mut output = feed(&mut decoder, &units).unwrap();
    output.extend(decoder.finish().unwrap());
    output
}

fn assert_pictures(pictures: &[Picture], expected: &[(i32, u8)]) {
    assert_eq!(pictures.len(), expected.len());
    for (picture, (poc, pixel)) in pictures.iter().zip(expected) {
        assert_eq!(picture.poc(), *poc);
        assert!(picture.luma().iter().all(|value| value == pixel));
        assert!(
            picture
                .cb()
                .iter()
                .chain(picture.cr())
                .all(|value| *value == 128)
        );
    }
}

#[test]
fn actual_pixels_follow_reference_and_disposable_picture_order() {
    let sequence = Sequence::default();
    let pictures = decode(
        &sequence,
        &[
            Frame::idr(10),
            Frame::reference(1, 30),
            Frame::disposable(2, 20),
            Frame::reference(2, 50),
            Frame::disposable(3, 40),
        ],
    );
    assert_pictures(&pictures, &[(0, 10), (1, 20), (2, 30), (3, 40), (4, 50)]);
    assert_eq!(
        pictures
            .iter()
            .map(Picture::decode_index)
            .collect::<Vec<_>>(),
        vec![0, 2, 1, 4, 3]
    );
}

#[test]
fn signed_deltas_order_multiple_nonreference_pictures_with_one_frame_number() {
    let sequence = Sequence {
        cycle: vec![4],
        non_reference: -3,
        zero_deltas: false,
        ..Sequence::default()
    };
    let pictures = decode(
        &sequence,
        &[
            Frame::idr(10),
            Frame::reference(1, 50),
            Frame::disposable(2, 20),
            Frame {
                deltas: [1, 0],
                ..Frame::disposable(2, 30)
            },
            Frame {
                deltas: [2, 0],
                ..Frame::disposable(2, 40)
            },
        ],
    );
    assert_pictures(&pictures, &[(0, 10), (1, 20), (2, 30), (3, 40), (4, 50)]);
    assert_eq!(
        pictures
            .iter()
            .map(Picture::decode_index)
            .collect::<Vec<_>>(),
        vec![0, 2, 3, 4, 1]
    );
}

#[test]
fn frame_number_wrap_counts_previous_picture_including_nonreferences() {
    let sequence = Sequence::default();
    let mut frames = vec![Frame::idr(10)];
    frames.extend((1..16).map(|number| Frame::reference(number, 10 + number as u8)));
    frames.push(Frame::disposable(0, 90)); // wraps once; displayed between POC28 and30.
    frames.push(Frame::reference(0, 91)); // same frame_num must not wrap a second time.
    let pictures = decode(&sequence, &frames);
    let mut expected: Vec<_> = (0..15)
        .map(|number| (2 * number, 10 + number as u8))
        .collect();
    expected.extend([(29, 90), (30, 25), (32, 91)]);
    assert_pictures(&pictures, &expected);
}

#[test]
fn periodic_offsets_use_the_whole_cycle_and_allow_signed_entries() {
    let sequence = Sequence {
        cycle: vec![4, -2, 4],
        ..Sequence::default()
    };
    let frames = [
        Frame::idr(10),
        Frame::reference(1, 20),
        Frame::reference(2, 30),
        Frame::reference(3, 40),
        Frame::reference(4, 50),
        Frame::reference(5, 60),
        Frame::reference(6, 70),
    ];
    // Reference offsets prefix 4,2,6; complete cycles advance by6.
    assert_pictures(
        &decode(&sequence, &frames),
        &[
            (0, 10),
            (2, 30),
            (4, 20),
            (6, 40),
            (8, 60),
            (10, 50),
            (12, 70),
        ],
    );
}

#[test]
fn both_field_deltas_participate_in_the_frame_minimum() {
    let sequence = Sequence {
        cycle: vec![4],
        bottom_offset: 2,
        zero_deltas: false,
        bottom_delta_present: true,
        ..Sequence::default()
    };
    let frames = [
        Frame {
            deltas: [0, -2],
            ..Frame::idr(10)
        },
        Frame {
            deltas: [1, -4],
            ..Frame::reference(1, 20)
        },
        Frame {
            deltas: [-1, 1],
            ..Frame::reference(2, 30)
        },
    ];
    assert_pictures(&decode(&sequence, &frames), &[(0, 10), (3, 20), (7, 30)]);
    let absent = Sequence {
        bottom_delta_present: false,
        ..sequence
    };
    assert_pictures(
        &decode(
            &absent,
            &[
                Frame::idr(10),
                Frame {
                    deltas: [1, 0],
                    ..Frame::reference(1, 20)
                },
            ],
        ),
        &[(0, 10), (5, 20)],
    );
}

#[test]
fn always_zero_deltas_override_pps_presence_and_empty_cycle_still_applies_nonref_offset() {
    let implicit = Sequence {
        bottom_delta_present: true,
        ..Sequence::default()
    };
    assert_pictures(
        &decode(&implicit, &[Frame::idr(10), Frame::reference(1, 20)]),
        &[(0, 10), (2, 20)],
    );
    let empty = Sequence {
        cycle: vec![],
        non_reference: 3,
        zero_deltas: false,
        ..Sequence::default()
    };
    assert_pictures(
        &decode(
            &empty,
            &[
                Frame::idr(10),
                Frame {
                    deltas: [6, 0],
                    ..Frame::reference(1, 30)
                },
                Frame {
                    deltas: [1, 0],
                    ..Frame::disposable(2, 20)
                },
            ],
        ),
        &[(0, 10), (4, 20), (6, 30)],
    );
}

#[test]
fn mmco5_and_new_idr_reset_frame_offset_and_output_epoch() {
    let sequence = Sequence::default();
    let mut frames = vec![Frame::idr(10)];
    frames.extend((1..16).map(|number| Frame::reference(number, 10 + number as u8)));
    frames.extend([
        Frame {
            reset: true,
            ..Frame::reference(0, 40)
        },
        Frame::reference(1, 41),
        Frame::reference(2, 42),
        Frame::idr(50),
        Frame::reference(1, 51),
    ]);
    let mut expected: Vec<_> = (0..16)
        .map(|number| (2 * number, 10 + number as u8))
        .collect();
    expected.extend([(0, 40), (2, 41), (4, 42), (0, 50), (2, 51)]);
    assert_pictures(&decode(&sequence, &frames), &expected);
}

#[test]
fn mismatched_slice_deltas_refuse_without_partial_picture_and_require_idr() {
    let sequence = Sequence {
        width_mbs: 2,
        zero_deltas: false,
        bottom_delta_present: true,
        ..Sequence::default()
    };
    for deltas in [[1, 0], [0, 1]] {
        let mut decoder = Decoder::new(DecoderLimits::default()).unwrap();
        feed(&mut decoder, &sequence.prefix()).unwrap();
        assert!(
            decoder
                .decode_nal(&sequence.slice(Frame::idr(10), 0, 1))
                .unwrap()
                .is_none()
        );
        let wrong = sequence.slice(
            Frame {
                deltas,
                ..Frame::idr(10)
            },
            1,
            1,
        );
        assert_eq!(
            decoder.decode_nal(&wrong).unwrap_err(),
            DecodeError::Malformed
        );
        assert!(decoder.next_output().is_none());
        assert_eq!(
            decoder
                .decode_nal(&sequence.picture(Frame::reference(1, 20)))
                .unwrap_err(),
            DecodeError::MissingReference
        );
        let mut recovered = feed(&mut decoder, &[sequence.picture(Frame::idr(30))]).unwrap();
        recovered.extend(decoder.finish().unwrap());
        assert_pictures(&recovered, &[(0, 30)]);
    }
}

#[test]
fn both_field_counts_are_checked_even_when_the_minimum_would_fit() {
    for (bottom_offset, delta0, idr_delta1) in [(1, 0, 0), (-2, 1, 2)] {
        let sequence = Sequence {
            cycle: vec![i64::from(i32::MAX)],
            bottom_offset,
            zero_deltas: false,
            bottom_delta_present: true,
            ..Sequence::default()
        };
        let mut decoder = Decoder::new(DecoderLimits::default()).unwrap();
        let mut prefix = sequence.prefix();
        prefix.push(sequence.picture(Frame {
            deltas: [0, idr_delta1],
            ..Frame::idr(10)
        }));
        feed(&mut decoder, &prefix).unwrap();
        assert_eq!(
            decoder
                .decode_nal(&sequence.picture(Frame {
                    deltas: [delta0, 0],
                    ..Frame::reference(1, 20)
                }))
                .unwrap_err(),
            DecodeError::Limit
        );
        assert!(decoder.next_output().is_none());
    }
}

#[test]
fn full_signed_sps_range_is_preserved_and_cycle_and_truncation_bounds_refuse() {
    let bounded = Sequence {
        cycle: vec![i64::from(i32::MAX); 255],
        non_reference: i64::from(i32::MIN + 1),
        bottom_offset: i64::from(i32::MAX),
        ..Sequence::default()
    };
    let nal = bounded.sps();
    let rbsp = rbsp_from_ebsp(&nal[1..], 4096).unwrap();
    let parsed = parse_sps(&rbsp).unwrap();
    assert_eq!(parsed.offset_for_ref_frame, vec![i32::MAX; 255]);
    assert_eq!(parsed.offset_for_non_ref_pic, i32::MIN + 1);
    assert_eq!(parsed.offset_for_top_to_bottom_field, i32::MAX);
    for sequence in [
        Sequence {
            cycle: vec![2; 256],
            ..Sequence::default()
        },
        Sequence {
            non_reference: i64::from(i32::MIN),
            ..Sequence::default()
        },
    ] {
        assert!(
            Decoder::new(DecoderLimits::default())
                .unwrap()
                .decode_nal(&sequence.sps())
                .is_err()
        );
    }
    let short = Sequence::default().sps();
    for length in 0..short.len() {
        assert!(
            Decoder::new(DecoderLimits::default())
                .unwrap()
                .decode_nal(&short[..length])
                .is_err()
        );
    }
}

#[test]
fn invalid_idr_order_and_existing_picture_budgets_are_not_weakened() {
    let sequence = Sequence {
        zero_deltas: false,
        ..Sequence::default()
    };
    let mut decoder = Decoder::new(DecoderLimits::default()).unwrap();
    feed(&mut decoder, &sequence.prefix()).unwrap();
    assert_eq!(
        decoder
            .decode_nal(&sequence.picture(Frame {
                deltas: [1, 0],
                ..Frame::idr(10)
            }))
            .unwrap_err(),
        DecodeError::Malformed
    );
    let limits = DecoderLimits {
        max_pictures: 1,
        ..DecoderLimits::default()
    };
    let mut decoder = Decoder::new(limits).unwrap();
    let mut prefix = sequence.prefix();
    prefix.push(sequence.picture(Frame::idr(10)));
    feed(&mut decoder, &prefix).unwrap();
    assert_eq!(
        decoder
            .decode_nal(&sequence.picture(Frame::reference(1, 20)))
            .unwrap_err(),
        DecodeError::Limit
    );
}
