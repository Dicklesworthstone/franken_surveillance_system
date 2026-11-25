#![forbid(unsafe_code)]
//! Source, time, and archive-order regressions through the actual packet and AVC codecs.

use std::error::Error;

use fss_codec_h264::rbsp::ebsp_from_rbsp;
use fss_packet::access_unit::{AccessUnit, AccessUnitAssembler, AccessUnitLimits};
use fss_packet::avc::{
    AvcAssembler, AvcAssemblyLimits, AvcAssemblyPoll, AvcAssemblyRetirement, AvcSyntaxLimits,
    parse_pps, parse_sps,
};
use fss_packet::{H264Depacketizer, H264Limits, H264Mode, PacketLimits, RtpPacket, StreamKey};

use super::*;

mod network;

type Test = Result<(), Box<dyn Error>>;

const B_PICTURES: &[u8] =
    include_bytes!("../../../../fss-codec-h264/tests/fixtures/decode/m_b_pyramid_ref3.h264");
const MULTISLICE: &[u8] =
    include_bytes!("../../../../fss-codec-h264/tests/fixtures/decode/ip_qcif_slices3.h264");

struct Groups {
    key: StreamKey,
    sequence: u64,
    assembler: AvcAssembler,
    depacketizer: H264Depacketizer,
}

impl Groups {
    fn new(sps: &[u8], pps: &[u8]) -> Result<Self, Box<dyn Error>> {
        let key = StreamKey {
            ingress: 17,
            generation: 1,
            ssrc: 7,
        };
        let syntax = AvcSyntaxLimits::default();
        let sps = parse_sps(sps, syntax)?;
        let pps = parse_pps(pps, &sps, syntax)?;
        Ok(Self {
            key,
            sequence: 0,
            assembler: AvcAssembler::new(key, sps, pps, syntax, AvcAssemblyLimits::default())?,
            depacketizer: H264Depacketizer::new(
                key,
                96,
                H264Mode::NonInterleaved,
                H264Limits::default(),
            )?,
        })
    }

    fn fixture(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        let sps = annex_b_nal_units(bytes)
            .find(|nal| nal[0] & 31 == 7)
            .ok_or("fixture SPS")?;
        let pps = annex_b_nal_units(bytes)
            .find(|nal| nal[0] & 31 == 8)
            .ok_or("fixture PPS")?;
        Self::new(sps, pps)
    }

    fn push(
        &mut self,
        nals: &[Vec<u8>],
        timestamp: u32,
        marker: bool,
    ) -> Result<Option<AvcPictureGroup>, Box<dyn Error>> {
        let mut group = None;
        for (offset, nal) in nals.iter().enumerate() {
            self.sequence += 1;
            let marked = marker && offset + 1 == nals.len();
            let mut wire = vec![0x80, 96 | (u8::from(marked) << 7)];
            wire.extend_from_slice(&(self.sequence as u16).to_be_bytes());
            wire.extend_from_slice(&timestamp.to_be_bytes());
            wire.extend_from_slice(&self.key.ssrc.to_be_bytes());
            wire.extend_from_slice(nal);
            let packet = RtpPacket::parse(&wire, PacketLimits::default())?;
            let output = self
                .depacketizer
                .push(self.key, self.sequence, packet, self.sequence)?;
            assert!(!output.gap_before);
            assert!(output.discarded.is_none());
            for nal in output.nals {
                collect_avc_media(
                    AvcReceivePoll::Assembly(self.assembler.push(nal, self.sequence)),
                    &mut group,
                )?;
            }
        }
        if marker && group.is_none() {
            match self.assembler.poll(self.sequence)? {
                AvcAssemblyPoll::Picture(picture) => group = Some(picture),
                AvcAssemblyPoll::Pending { .. } => {}
                event => {
                    return Err(format!("unexpected fixture assembly output: {event:?}").into());
                }
            }
        }
        Ok(group)
    }

    fn picture(
        &mut self,
        nals: &[Vec<u8>],
        timestamp: u32,
    ) -> Result<AvcPictureGroup, Box<dyn Error>> {
        self.push(nals, timestamp, true)?
            .ok_or_else(|| "fixture did not produce a picture".into())
    }
}

fn access_units(bytes: &[u8]) -> Result<Vec<AccessUnit>, Box<dyn Error>> {
    let mut assembler = AccessUnitAssembler::new(AccessUnitLimits::default())?;
    let mut units = Vec::new();
    for nal in annex_b_nal_units(bytes) {
        if let Some(unit) = assembler.push(nal)? {
            units.push(unit);
        }
    }
    units.extend(assembler.flush());
    units.retain(|unit| unit.nals.iter().any(|nal| matches!(nal[0] & 31, 1 | 5)));
    Ok(units)
}

fn drain(decoder: &mut AvcSourceDecoder, output: &mut Vec<DecodedSource>) {
    output.extend(std::iter::from_fn(|| decoder.take_ready()));
}

#[test]
fn b_pictures_keep_original_pixels_pts_source_and_decodable_archive_order() -> Test {
    let mut oracle = Decoder::new(DecoderLimits::default())?;
    let mut expected = oracle.decode_annex_b(B_PICTURES)?;
    expected.extend(oracle.finish()?);
    assert!(
        expected
            .windows(2)
            .any(|pair| pair[0].decode_index() > pair[1].decode_index()),
        "the real fixture must exercise display/decode reordering"
    );
    let expected: BTreeMap<_, _> = expected
        .into_iter()
        .map(|picture| (picture.decode_index(), picture.i420_sha256()))
        .collect();

    let mut groups = Groups::fixture(B_PICTURES)?;
    let mut decoder = AvcSourceDecoder::new()?;
    let units = access_units(B_PICTURES)?;
    assert_eq!(units.len(), expected.len());
    let mut output = Vec::new();
    for (index, unit) in units.iter().enumerate() {
        // Deliberately nonmonotonic presentation times, with monotonic source receipt.
        let timestamp = 90_000 + ((index * 7) % units.len()) as u32 * 3_000;
        let group = groups.picture(&unit.nals, timestamp)?;
        decoder.push(&group, 1_000_000 + index as i128 * 10_000)?;
        drain(&mut decoder, &mut output);
    }
    assert!(
        output.len() < expected.len(),
        "EOF must release delayed pixels"
    );
    decoder.finish()?;
    drain(&mut decoder, &mut output);
    assert_eq!(output.len(), expected.len());
    assert!(decoder.sources.is_empty());
    assert!(decoder.pictures.is_empty());
    assert_eq!(decoder.pending_bytes, 0);

    let mut archive = Vec::new();
    for (index, (decoded, original)) in output.iter().zip(&units).enumerate() {
        assert_eq!(decoded.picture.decode_index(), index as u64);
        assert_eq!(decoded.picture.i420_sha256(), expected[&(index as u64)]);
        let timestamp = 90_000 + ((index * 7) % units.len()) as u32 * 3_000;
        assert_eq!(
            decoded.source.media_pts_ns,
            i128::from(timestamp) * 1_000_000_000 / 90_000
        );
        assert_eq!(
            decoded.source.host_receive_ns,
            1_000_000 + index as i128 * 10_000
        );
        assert_eq!(
            decoded.source.digest,
            ContentDigest::sha256(&decoded.source.encoded)
        );
        let parameter_prefix = usize::from(index == 0 || original.contains_idr) * 2;
        let retained: Vec<_> = annex_b_nal_units(&decoded.source.encoded)
            .skip(parameter_prefix)
            .collect();
        let original: Vec<_> = original.nals.iter().map(Vec::as_slice).collect();
        assert_eq!(retained, original);
        archive.extend_from_slice(&decoded.source.encoded);
    }
    // Storage concatenates frames in driver emission order. The retained bytes must
    // independently reconstruct every pixel, including references and B pictures.
    let mut replay = Decoder::new(DecoderLimits::default())?;
    let mut replayed = replay.decode_annex_b(&archive)?;
    replayed.extend(replay.finish()?);
    let replayed: BTreeMap<_, _> = replayed
        .into_iter()
        .map(|picture| (picture.decode_index(), picture.i420_sha256()))
        .collect();
    assert_eq!(replayed, expected);
    Ok(())
}

#[test]
fn rtp_timestamp_wrap_preserves_reordered_presentation_times_and_source_order() -> Test {
    let mut groups = Groups::fixture(B_PICTURES)?;
    let mut decoder = AvcSourceDecoder::new()?;
    let units = access_units(B_PICTURES)?;
    assert!(
        units.len() >= 3,
        "fixture must cover both directions of wrap"
    );
    let origin = i128::from(u32::MAX) - 4_500;
    let mut output = Vec::new();
    let mut expected_ticks = Vec::new();
    for (index, unit) in units.iter().enumerate() {
        // Exercise both directions across the wire wrap while preserving real B pictures.
        let presentation_index = match index {
            1 => 2,
            2 => 1,
            _ => index,
        };
        let ticks = origin + presentation_index as i128 * 3_000;
        let group = groups.picture(&unit.nals, ticks as u32)?;
        decoder.push(&group, 1_000_000 + index as i128 * 10_000)?;
        expected_ticks.push(ticks);
        drain(&mut decoder, &mut output);
    }
    assert!(
        expected_ticks
            .iter()
            .any(|ticks| *ticks > i128::from(u32::MAX))
    );
    assert!(expected_ticks.windows(2).any(|pair| pair[0] > pair[1]));
    decoder.finish()?;
    drain(&mut decoder, &mut output);
    assert_eq!(output.len(), units.len());

    let mut archive = Vec::new();
    for (index, (decoded, ticks)) in output.iter().zip(expected_ticks).enumerate() {
        assert_eq!(decoded.picture.decode_index(), index as u64);
        assert_eq!(decoded.source.media_pts_ns, ticks * 1_000_000_000 / 90_000);
        assert_eq!(
            decoded.source.host_receive_ns,
            1_000_000 + index as i128 * 10_000
        );
        assert_eq!(
            decoded.source.digest,
            ContentDigest::sha256(&decoded.source.encoded)
        );
        archive.extend_from_slice(&decoded.source.encoded);
    }
    let mut replay = Decoder::new(DecoderLimits::default())?;
    let mut replayed = replay.decode_annex_b(&archive)?;
    replayed.extend(replay.finish()?);
    let replayed: BTreeMap<_, _> = replayed
        .into_iter()
        .map(|picture| (picture.decode_index(), picture.i420_sha256()))
        .collect();
    let original: BTreeMap<_, _> = output
        .into_iter()
        .map(|decoded| {
            (
                decoded.picture.decode_index(),
                decoded.picture.i420_sha256(),
            )
        })
        .collect();
    assert_eq!(replayed, original);
    Ok(())
}

#[test]
fn ambiguous_rtp_epoch_refuses_and_a_new_decoder_starts_its_own_clock() -> Test {
    for (timestamp, receive_ns) in [
        (90_000_u32.wrapping_add(0x8000_0000), 101),
        (93_000, 100 + RTP_HALF_CYCLE_NS),
        (93_000, i128::MAX),
    ] {
        let mut groups = Groups::new(&sps(2), &Pps::default().nal())?;
        let first = groups.picture(&[Frame::idr(10, false).nal()], 90_000)?;
        let second = groups.picture(&[Frame::reference(1, 2, 20).nal()], timestamp)?;
        let mut decoder = AvcSourceDecoder::new()?;
        decoder.push(&first, 100)?;
        assert_eq!(
            decoder.push(&second, receive_ns),
            Err("AVC source timestamp epoch is ambiguous; new generation required")
        );
        assert!(decoder.take_ready().is_none());
        assert!(decoder.push(&second, receive_ns).is_err());
        assert!(decoder.finish().is_err());

        let mut fresh_groups = Groups::new(&sps(0), &Pps::default().nal())?;
        let idr = fresh_groups.picture(&[Frame::idr(30, false).nal()], 123)?;
        let mut fresh = AvcSourceDecoder::new()?;
        fresh.push(&idr, receive_ns)?;
        fresh.finish()?;
        let decoded = fresh.take_ready().ok_or("new generation picture missing")?;
        assert_eq!(decoded.source.media_pts_ns, 123 * 1_000_000_000 / 90_000);
        assert_eq!(decoded.picture.decode_index(), 0);
    }
    Ok(())
}

#[test]
fn marked_partial_multislice_picture_closes_decoder_without_emitting_pixels() -> Test {
    let units = access_units(MULTISLICE)?;
    let first = units.first().ok_or("multislice fixture is empty")?;
    assert!(first.nals.iter().filter(|nal| nal[0] & 31 == 5).count() > 1);
    let mut partial = first.nals.clone();
    let last_slice = partial
        .iter()
        .rposition(|nal| nal[0] & 31 == 5)
        .ok_or("multislice fixture lacks IDR")?;
    partial.remove(last_slice);
    let mut groups = Groups::fixture(MULTISLICE)?;
    let group = groups.picture(&partial, 90_000)?;
    let mut decoder = AvcSourceDecoder::new()?;
    assert!(decoder.push(&group, 100).is_err());
    assert!(decoder.take_ready().is_none());
    assert!(decoder.finish().is_err());
    assert!(decoder.push(&group, 200).is_err());

    // A new generation, with all slices present, is independently decodable.
    let mut fresh_groups = Groups::fixture(MULTISLICE)?;
    let complete = fresh_groups.picture(&first.nals, 90_000)?;
    let mut fresh_decoder = AvcSourceDecoder::new()?;
    fresh_decoder.push(&complete, 300)?;
    fresh_decoder.finish()?;
    assert_eq!(
        fresh_decoder
            .take_ready()
            .ok_or("complete picture missing")?
            .picture
            .decode_index(),
        0
    );
    Ok(())
}

#[test]
fn idr_discard_reports_unrecoverable_source_gap_instead_of_blocking_or_mislabeling() -> Test {
    for discard_prior in [false, true] {
        let mut groups = Groups::new(&sps(2), &Pps::default().nal())?;
        let mut decoder = AvcSourceDecoder::new()?;
        let mut output = Vec::new();
        let frames = [
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
        ];
        for (index, frame) in frames.into_iter().enumerate() {
            let group = groups.picture(&[frame.nal()], 90_000 + index as u32 * 3_000)?;
            decoder.push(&group, index as i128)?;
            drain(&mut decoder, &mut output);
        }
        assert_eq!(output.len(), 1, "decode-order reference is still pending");
        let idr = groups.picture(&[Frame::idr(90, discard_prior).nal()], 102_000)?;
        let result = decoder.push(&idr, 4);
        if discard_prior {
            assert_eq!(
                result,
                Err("AVC random-access reset discarded pending source pictures")
            );
            assert!(decoder.take_ready().is_none());
            assert!(decoder.push(&idr, 5).is_err());
            assert!(decoder.finish().is_err());
        } else {
            result?;
            decoder.finish()?;
            drain(&mut decoder, &mut output);
            assert_eq!(output.len(), 5);
            for (index, (decoded, pixel)) in output.iter().zip([10, 60, 20, 40, 90]).enumerate() {
                assert_eq!(decoded.picture.decode_index(), index as u64);
                assert!(decoded.picture.luma().iter().all(|value| *value == pixel));
                assert_eq!(decoded.source.host_receive_ns, index as i128);
            }
        }
    }
    Ok(())
}

#[test]
fn eof_tail_is_decoded_only_after_native_completeness_verification() -> Test {
    for complete in [true, false] {
        let mut groups = Groups::new(&sps(2), &Pps::default().nal())?;
        let frame = Frame::idr(37, false);
        let nals = [frame.slice(0, if complete { 2 } else { 1 })];
        assert!(groups.push(&nals, 90_000, false)?.is_none());
        let tail = groups.assembler.finish(groups.sequence)?;
        let mut group = None;
        assert!(collect_avc_media(
            AvcReceivePoll::Ended {
                fragment: None,
                interrupted_picture: None,
                tail: Some(tail),
            },
            &mut group,
        )?);
        let group = group.ok_or("EOF lost its accepted picture group")?;
        let mut decoder = AvcSourceDecoder::new()?;
        if complete {
            decoder.push(&group, 10)?;
            assert!(decoder.take_ready().is_none());
            decoder.finish()?;
            let output = decoder.take_ready().ok_or("EOF lost delayed picture")?;
            assert!(output.picture.luma().iter().all(|value| *value == 37));
            assert_eq!(output.source.host_receive_ns, 10);
        } else {
            assert!(decoder.push(&group, 10).is_err());
            assert!(decoder.take_ready().is_none());
        }
    }
    Ok(())
}

#[test]
fn picture_loss_is_explicit_but_parameter_only_retirement_has_no_decode_index() -> Test {
    let mut group = None;
    for reason in [
        AvcRetirementReason::InputDiscontinuity,
        AvcRetirementReason::Deadline,
        AvcRetirementReason::Limit,
        AvcRetirementReason::InvalidInput,
        AvcRetirementReason::ConfigurationChanged,
    ] {
        let retired = AvcAssemblyRetirement {
            key: StreamKey {
                ingress: 17,
                generation: 1,
                ssrc: 7,
            },
            reason,
            nals: 1,
            bytes: 10,
            first_sequence: Some(1),
            last_sequence: Some(1),
        };
        assert!(collect_avc_media(AvcReceivePoll::PictureRetired(retired), &mut group).is_err());
        assert!(group.is_none());
    }
    let mut groups = Groups::new(&sps(0), &Pps::default().nal())?;
    assert!(
        groups
            .push(&[sps(0), Pps::default().nal()], 90_000, false)?
            .is_none()
    );
    let tail = groups.assembler.finish(groups.sequence)?;
    assert_eq!(
        tail.retired.as_ref().map(|retired| retired.reason),
        Some(AvcRetirementReason::NoPrimaryPicture)
    );
    assert!(collect_avc_media(
        AvcReceivePoll::Ended {
            fragment: None,
            interrupted_picture: None,
            tail: Some(tail),
        },
        &mut group,
    )?);
    assert!(group.is_none());
    let mut decoder = AvcSourceDecoder::new()?;
    decoder.finish()?;
    assert_eq!(decoder.decoder.pictures_decoded(), 0);
    assert!(decoder.take_ready().is_none());
    Ok(())
}

#[test]
fn source_window_exhaustion_and_clock_reversal_fail_closed() -> Test {
    let mut groups = Groups::new(&sps(2), &Pps::default().nal())?;
    let first = groups.picture(&[Frame::idr(10, false).nal()], 90_000)?;
    let second = groups.picture(&[Frame::reference(1, 2, 20).nal()], 93_000)?;
    let mut decoder = AvcSourceDecoder::new()?;
    decoder.push(&first, 100)?;
    assert_eq!(
        decoder.push(&second, 99),
        Err("AVC source receive time moved backwards")
    );
    assert!(decoder.take_ready().is_none());

    let mut decoder = AvcSourceDecoder::new()?;
    // Exercise admission at the byte ceiling without allocating 128 MiB in the test.
    decoder.pending_bytes = MAX_PENDING_BYTES;
    assert_eq!(
        decoder.push(&first, 100),
        Err("AVC source reorder window exceeded its byte bound")
    );
    assert!(decoder.take_ready().is_none());
    assert_eq!(decoder.pending_bytes, 0);
    Ok(())
}

// Small exact I_PCM fixtures also exercise the codec's explicit IDR discard flag.
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
