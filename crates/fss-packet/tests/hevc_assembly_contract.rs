#![forbid(unsafe_code)]
//! Real source-linked NAL fixtures; no decoder or parameter-set compatibility claims.

use fss_packet::{H265Depacketizer, H265Limits, H265NalUnit, PacketLimits, RtpPacket, StreamKey};
use fss_packet::hevc::{
    HevcAssembler, HevcAssemblyError as E, HevcAssemblyLimits as Limits,
    HevcAssemblyOutput as Output, HevcAssemblyRefusal, HevcAssemblyStep as Step,
    HevcBoundary as B, HevcPrefixError as S, HevcRetirementReason as R, parse_slice_prefix,
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
const KEY: StreamKey = StreamKey { ingress: 1, generation: 1, ssrc: 7 };

fn slice(kind: u8, first: bool, pps: u8, tid: u8, no_output: bool) -> Vec<u8> {
    let mut bits = vec![u8::from(first)];
    if (16..=21).contains(&kind) { bits.push(u8::from(no_output)); }
    let value = u16::from(pps) + 1;
    let width = 16 - value.leading_zeros();
    bits.extend(std::iter::repeat_n(0, (width - 1) as usize));
    for shift in (0..width).rev() { bits.push(((value >> shift) & 1) as u8); }
    bits.push(1); // Opaque fixture suffix, not a complete slice body.
    while bits.len() % 8 != 0 { bits.push(0); }
    let mut nal = vec![kind << 1, tid];
    for byte in bits.chunks_exact(8) {
        nal.push(byte.iter().fold(0, |v, bit| v * 2 + bit));
    }
    nal
}
fn wire(key: StreamKey, seq: u64, ts: u32, payload: &[u8], marker: bool) -> Vec<u8> {
    let mut bytes = vec![0x80, 98 | if marker { 128 } else { 0 }];
    bytes.extend_from_slice(&(seq as u16).to_be_bytes());
    bytes.extend_from_slice(&ts.to_be_bytes());
    bytes.extend_from_slice(&key.ssrc.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}
fn nal(key: StreamKey, seq: u64, ts: u32, payload: &[u8], marker: bool)
    -> Result<H265NalUnit, Box<dyn std::error::Error>>
{
    let mut receiver = H265Depacketizer::new(key, 98, 0, H265Limits::default())?;
    let bytes = wire(key, seq, ts, payload, marker);
    let mut result = receiver.push(key, seq, RtpPacket::parse(&bytes, PacketLimits::default())?, 0)?;
    result.nals.pop().ok_or_else(|| "fixture did not produce a NAL".into())
}
fn accepted(step: Step) -> Result<Output, Box<dyn std::error::Error>> {
    match step {
        Step::Accepted(output) => Ok(output),
        Step::Refused(refusal) => Err(format!("unexpected refusal: {:?}", refusal.reason).into()),
    }
}
fn refused(step: Step) -> Result<HevcAssemblyRefusal, Box<dyn std::error::Error>> {
    match step {
        Step::Refused(refusal) => Ok(refusal),
        Step::Accepted(_) => Err("invalid input was accepted".into()),
    }
}
fn push(a: &mut HevcAssembler, seq: u64, ts: u32, bytes: &[u8], now: u64)
    -> Result<Output, Box<dyn std::error::Error>>
{
    accepted(a.push(nal(KEY, seq, ts, bytes, false)?, now))
}

#[test]
fn every_admitted_pps_temporal_and_first_flag_prefix_round_trips() -> TestResult {
    for kind in (0..=9).chain(16..=21) {
        for pps in 0..=63 {
            for tid in 1..=7 {
                for first in [false, true] {
                    for no_output in [false, true] {
                        let bytes = slice(kind, first, pps, tid, no_output);
                        let parsed = parse_slice_prefix(&bytes, 1024)?;
                        assert_eq!(parsed.first_slice, first);
                        assert_eq!(parsed.pps_id, pps);
                        assert_eq!(parsed.nal_type, kind);
                        assert_eq!(parsed.temporal_id_plus_one, tid);
                        assert_eq!(parsed.no_output_of_prior_pics, if kind >= 16 { Some(no_output) } else { None });
                    }
                }
            }
        }
    }
    Ok(())
}

#[test]
fn prefix_parser_refuses_truncation_corruption_reserved_values_and_other_layers() -> TestResult {
    for bytes in [vec![], vec![2], vec![2, 1]] {
        assert_eq!(parse_slice_prefix(&bytes, 1024), Err(S::Truncated));
    }
    assert_eq!(parse_slice_prefix(&[0x82, 1, 0xc0], 1024), Err(S::Corrupt));
    assert_eq!(parse_slice_prefix(&[2, 0, 0xc0], 1024), Err(S::Malformed));
    assert_eq!(parse_slice_prefix(&[3, 1, 0xc0], 1024), Err(S::UnsupportedLayer));
    assert_eq!(parse_slice_prefix(&[2, 9, 0xc0], 1024), Err(S::UnsupportedLayer));
    for kind in (10..=15).chain(22..=63) {
        assert_eq!(parse_slice_prefix(&[kind << 1, 1, 0xc0], 1024), Err(S::UnsupportedNal));
    }
    for pps in [64, 127, 255] {
        assert_eq!(parse_slice_prefix(&slice(1, true, pps, 1, false), 1024), Err(S::Malformed));
    }
    assert_eq!(parse_slice_prefix(&[2, 1, 0], 1024), Err(S::Malformed));
    assert_eq!(parse_slice_prefix(&[2, 1, 0xc0, 0], 3), Err(S::Limit));
    assert_eq!(parse_slice_prefix(&[2, 1, 0xc0], 0), Err(S::Limit));
    Ok(())
}

#[test]
fn rtp_marker_does_not_split_multislice_picture_and_next_first_slice_does() -> TestResult {
    let mut a = HevcAssembler::new(KEY, Limits::default())?;
    let first = slice(19, true, 0, 1, false);
    let next = slice(19, false, 0, 1, false);
    assert!(accepted(a.push(nal(KEY, 1, 100, &first, true)?, 0))?.picture.is_none());
    assert!(accepted(a.push(nal(KEY, 2, 100, &next, true)?, 1))?.picture.is_none());
    let picture = push(&mut a, 3, 200, &first, 2)?.picture.ok_or("missing first-slice boundary")?;
    assert_eq!(picture.boundary(), B::NextFirstSlice);
    assert_eq!(picture.timestamp(), 100);
    assert_eq!(picture.slice_count(), 2);
    assert_eq!(picture.prefix().nal_type, 19);
    assert_eq!(picture.nals()[0].bytes(), first);
    assert_eq!(picture.nals()[1].bytes(), next);
    assert!(picture.nals().iter().all(|n| n.marker()));
    assert!(!picture.discontinuity_before());
    assert_eq!(picture.byte_len(), first.len() + next.len());
    assert_eq!(picture.source_span_count(), 2);
    assert_eq!(picture.key(), KEY);
    assert!(a.pending_bytes() > 0);
    Ok(())
}

#[test]
fn leading_and_suffix_metadata_are_preserved_in_the_correct_group() -> TestResult {
    let mut a = HevcAssembler::new(KEY, Limits::default())?;
    let mut seq = 0;
    for bytes in [vec![64, 1, 0x80], vec![66, 1, 0x80], vec![68, 1, 0x80],
        vec![78, 1, 0x80], slice(1, true, 3, 2, false), vec![80, 1, 0x80], vec![76, 1, 0xff, 0x80]] {
        seq += 1;
        assert!(push(&mut a, seq, 100, &bytes, seq)?.picture.is_none());
    }
    let output = push(&mut a, 8, 200, &[64, 1, 0x80], 8)?;
    let picture = output.picture.ok_or("prefix failed to delimit previous picture")?;
    assert_eq!(picture.boundary(), B::NextAccessUnitPrefix);
    assert_eq!(picture.nals().iter().map(|n| n.nal_type()).collect::<Vec<_>>(), vec![32, 33, 34, 39, 1, 40, 38]);
    assert_eq!(picture.slice_count(), 1);
    assert_eq!(picture.prefix().pps_id, 3);
    push(&mut a, 9, 200, &slice(1, true, 4, 2, false), 9)?;
    let tail = a.finish(10)?.picture.ok_or("tail missing")?;
    assert_eq!(tail.nals().len(), 2);
    assert_eq!(tail.nals()[0].sources()[0].sequence, 8);
    assert_eq!(tail.boundary(), B::EndOfInputUnverified);
    Ok(())
}

#[test]
fn aud_and_end_markers_have_validated_trailing_bits_and_explicit_ownership() -> TestResult {
    for (kind, boundary) in [(36, B::EndOfSequence), (37, B::EndOfBitstream)] {
        let mut a = HevcAssembler::new(KEY, Limits::default())?;
        let standalone = push(&mut a, 1, 10, &[kind << 1, 1, 0x80], 0)?;
        assert_eq!(standalone.standalone.ok_or("unattached end marker vanished")?.bytes(), [kind << 1, 1, 0x80]);
        if kind == 37 {
            assert_eq!(refused(a.push(nal(KEY, 2, 100, &slice(1, true, 0, 1, false), false)?, 1))?.reason, E::Closed);
        }
        let mut a = HevcAssembler::new(KEY, Limits::default())?;
        push(&mut a, 2, 100, &slice(1, true, 0, 1, false), 1)?;
        let old = push(&mut a, 3, 200, &[70, 1, 0x50], 2)?.picture.ok_or("AUD did not delimit")?;
        assert_eq!(old.boundary(), B::AccessUnitDelimiter);
        push(&mut a, 4, 200, &slice(1, true, 0, 1, false), 3)?;
        let ended = push(&mut a, 5, 200, &[kind << 1, 1, 0x80], 4)?.picture.ok_or("end marker lost picture")?;
        assert_eq!(ended.boundary(), boundary);
        assert_eq!(ended.nals().first().ok_or("no AUD")?.nal_type(), 35);
        assert_eq!(ended.nals().last().ok_or("no terminator")?.nal_type(), kind);
        assert_eq!(a.pending_bytes(), 0);
    }
    for invalid in [vec![70, 1, 0x70], vec![70, 1, 0x11], vec![72, 1, 0], vec![74, 1, 0x80, 0], vec![76, 1, 0, 0x80]] {
        let mut a = HevcAssembler::new(KEY, Limits::default())?;
        assert_eq!(refused(a.push(nal(KEY, 1, 0, &invalid, false)?, 0))?.reason, E::Syntax(S::Malformed));
    }
    Ok(())
}

#[test]
fn missing_first_slice_and_suffix_without_picture_never_become_output() -> TestResult {
    for invalid in [slice(1, false, 0, 1, false), vec![80, 1, 0x80], vec![76, 1, 0x80]] {
        let mut a = HevcAssembler::new(KEY, Limits::default())?;
        push(&mut a, 1, 100, &[64, 1, 0x80], 0)?;
        let failure = refused(a.push(nal(KEY, 2, 100, &invalid, false)?, 1))?;
        assert_eq!(failure.reason, E::MissingFirstSlice);
        assert_eq!(failure.nal.bytes(), invalid);
        assert_eq!(failure.retired.ok_or("metadata retirement missing")?.nals, 1);
        assert_eq!(a.pending_bytes(), 0);
    }
    Ok(())
}

#[test]
fn conflicting_slice_identity_timestamp_and_post_suffix_vcl_fail_closed() -> TestResult {
    for (bytes, timestamp, expected) in [
        (slice(19, false, 1, 1, false), 100, E::PictureMismatch),
        (slice(20, false, 0, 1, false), 100, E::PictureMismatch),
        (slice(19, false, 0, 2, false), 100, E::PictureMismatch),
        (slice(19, false, 0, 1, true), 100, E::PictureMismatch),
        (slice(19, false, 0, 1, false), 200, E::TimestampMismatch),
        (slice(19, true, 0, 1, false), 100, E::TimestampMismatch),
        (vec![72, 1, 0x80], 200, E::TimestampMismatch),
        (vec![74, 1, 0x80], 200, E::TimestampMismatch),
    ] {
        let mut a = HevcAssembler::new(KEY, Limits::default())?;
        push(&mut a, 1, 100, &slice(19, true, 0, 1, false), 0)?;
        let refused = refused(a.push(nal(KEY, 2, timestamp, &bytes, false)?, 1))?;
        assert_eq!(refused.reason, expected);
        assert_eq!(refused.retired.ok_or("inconsistent group was not retired")?.reason, R::InvalidInput);
        assert_eq!(a.pending_bytes(), 0);
    }
    let mut a = HevcAssembler::new(KEY, Limits::default())?;
    push(&mut a, 1, 100, &slice(1, true, 0, 1, false), 0)?;
    push(&mut a, 2, 100, &[80, 1, 0x80], 1)?;
    assert_eq!(refused(a.push(nal(KEY, 3, 100, &slice(1, false, 0, 1, false), false)?, 2))?.reason, E::Ordering);
    Ok(())
}

#[test]
fn expiry_is_fixed_at_first_prefix_and_cannot_be_erased_by_a_late_boundary() -> TestResult {
    let mut a = HevcAssembler::new(KEY, Limits { max_age_ns: 10, ..Limits::default() })?;
    push(&mut a, 1, 100, &[64, 1, 0x80], 0)?;
    push(&mut a, 2, 100, &slice(1, true, 0, 1, false), 9)?;
    assert_eq!(a.next_wake_ns(), Some(10));
    let out = push(&mut a, 3, 200, &slice(1, true, 0, 1, false), 10)?;
    assert!(out.picture.is_none());
    let retirement = out.retired.ok_or("expired prefix was published")?;
    assert_eq!(retirement.reason, R::Deadline);
    assert_eq!(retirement.nals, 2);
    assert_eq!(retirement.first_sequence, 1);
    assert_eq!(retirement.last_sequence, 2);
    let picture = push(&mut a, 4, 300, &slice(1, true, 0, 1, false), 11)?.picture.ok_or("new picture missing")?;
    assert!(picture.discontinuity_before());
    let following = push(&mut a, 5, 400, &slice(1, true, 0, 1, false), 12)?.picture.ok_or("following picture missing")?;
    assert!(!following.discontinuity_before());
    assert_eq!(a.expire(22)?.ok_or("silent timeout missing")?.reason, R::Deadline);
    assert!(a.expire(23)?.is_none());
    Ok(())
}

#[test]
fn automatic_sequence_gap_and_owner_declared_loss_invalidate_pending_pictures() -> TestResult {
    for explicit in [false, true] {
        let mut a = HevcAssembler::new(KEY, Limits::default())?;
        push(&mut a, 1, 100, &slice(1, true, 0, 1, false), 0)?;
        if explicit {
            assert_eq!(a.discontinuity(KEY, 1)?.ok_or("missing discontinuity")?.reason, R::InputDiscontinuity);
        }
        let out = push(&mut a, 3, 200, &slice(1, true, 0, 1, false), 2)?;
        assert!(out.picture.is_none());
        if !explicit { assert_eq!(out.retired.ok_or("implicit gap ignored")?.reason, R::InputDiscontinuity); }
        let picture = a.finish(3)?.picture.ok_or("new tail missing")?;
        assert!(picture.discontinuity_before());
        assert_eq!(picture.timestamp(), 200);
        assert_eq!(picture.boundary(), B::EndOfInputUnverified);
    }
    Ok(())
}

#[test]
fn duplicate_and_reversed_source_spans_refuse_but_adjacent_ap_members_bind() -> TestResult {
    let mut a = HevcAssembler::new(KEY, Limits::default())?;
    let first = slice(1, true, 0, 1, false);
    push(&mut a, 1, 100, &first, 0)?;
    let error = refused(a.push(nal(KEY, 1, 100, &first, false)?, 1))?;
    assert_eq!(error.reason, E::SourceOrder);
    assert!(error.retired.is_some());
    let next = slice(1, false, 0, 1, false);
    let mut ap = vec![96, 1];
    for bytes in [&first, &next] { ap.extend_from_slice(&(bytes.len() as u16).to_be_bytes()); ap.extend_from_slice(bytes); }
    let bytes = wire(KEY, 2, 200, &ap, true);
    let mut d = H265Depacketizer::new(KEY, 98, 0, H265Limits::default())?;
    let result = d.push(KEY, 2, RtpPacket::parse(&bytes, PacketLimits::default())?, 0)?;
    for nal in result.nals { accepted(a.push(nal, 2))?; }
    let picture = a.finish(3)?.picture.ok_or("AP picture missing")?;
    assert_eq!(picture.nals().len(), 2);
    let left = &picture.nals()[0].sources()[0];
    let right = &picture.nals()[1].sources()[0];
    assert_eq!(left.sequence, right.sequence);
    assert!(left.wire_range.end < right.wire_range.start);
    assert!(picture.discontinuity_before());
    Ok(())
}

#[test]
fn wrong_owner_and_reversed_clock_leave_pending_bytes_and_source_watermark_unchanged() -> TestResult {
    let mut a = HevcAssembler::new(KEY, Limits::default())?;
    let first = slice(1, true, 0, 1, false);
    push(&mut a, 1, 100, &first, 10)?;
    for wrong in [StreamKey { generation: 2, ..KEY }, StreamKey { ssrc: 9, ..KEY }, StreamKey { ingress: 2, ..KEY }] {
        let refusal = refused(a.push(nal(wrong, 2, 200, &first, false)?, 20))?;
        assert_eq!(refusal.reason, E::StreamMismatch);
        assert!(refusal.retired.is_none());
    }
    assert_eq!(refused(a.push(nal(KEY, 2, 200, &first, false)?, 9))?.reason, E::ClockReversed);
    assert_eq!(a.pending_bytes(), first.len());
    assert_eq!(push(&mut a, 2, 200, &first, 11)?.picture.ok_or("valid retry failed")?.timestamp(), 100);
    Ok(())
}

#[test]
fn byte_nal_span_and_deadline_limits_retire_before_silently_partial_output() -> TestResult {
    let first = slice(1, true, 0, 1, false);
    for limits in [
        Limits { max_nals: 1, ..Limits::default() },
        Limits { max_bytes: first.len(), ..Limits::default() },
        Limits { max_source_spans: 1, ..Limits::default() },
    ] {
        let mut a = HevcAssembler::new(KEY, limits)?;
        push(&mut a, 1, 100, &first, 0)?;
        let continuation = slice(1, false, 0, 1, false);
        let refusal = refused(a.push(nal(KEY, 2, 100, &continuation, false)?, 1))?;
        assert_eq!(refusal.reason, E::Limit);
        assert_eq!(refusal.nal.bytes(), continuation);
        assert_eq!(refusal.retired.ok_or("limit retirement missing")?.reason, R::Limit);
        assert_eq!(a.pending_bytes(), 0);
    }
    let mut a = HevcAssembler::new(KEY, Limits::default())?;
    assert_eq!(refused(a.push(nal(KEY, 1, 100, &first, false)?, u64::MAX))?.reason, E::Limit);
    assert_eq!(a.next_wake_ns(), None);
    Ok(())
}

#[test]
fn metadata_only_eof_repeated_aud_and_cancellation_have_exact_retirement() -> TestResult {
    let mut a = HevcAssembler::new(KEY, Limits::default())?;
    push(&mut a, 1, 100, &[70, 1, 0x10], 0)?;
    let replaced = push(&mut a, 2, 200, &[70, 1, 0x10], 1)?;
    assert_eq!(replaced.retired.ok_or("old empty AU vanished")?.reason, R::NoPicture);
    let out = a.finish(2)?;
    assert!(out.picture.is_none());
    assert_eq!(out.retired.ok_or("metadata EOF missing")?.first_sequence, 2);
    assert!(a.finish(3)?.retired.is_none());
    assert_eq!(refused(a.push(nal(KEY, 3, 300, &slice(1, true, 0, 1, false), false)?, 3))?.reason, E::Closed);
    let mut a = HevcAssembler::new(KEY, Limits::default())?;
    push(&mut a, 1, 100, &slice(1, true, 0, 1, false), 0)?;
    assert_eq!(a.cancel().ok_or("cancel receipt missing")?.reason, R::Cancelled);
    assert!(a.cancel().is_none());
    assert!(a.finish(1)?.picture.is_none());
    Ok(())
}

#[test]
fn finished_timestamp_cannot_be_reopened_by_a_repeated_first_slice() -> TestResult {
    let mut a = HevcAssembler::new(KEY, Limits::default())?;
    let first = slice(1, true, 0, 1, false);
    push(&mut a, 1, 100, &first, 0)?;
    push(&mut a, 2, 100, &[72, 1, 0x80], 1)?;
    assert_eq!(refused(a.push(nal(KEY, 3, 100, &first, false)?, 2))?.reason, E::TimestampMismatch);
    // Timestamp wrap or B-frame ordering is not interpreted as a wall-clock reversal.
    push(&mut a, 4, u32::MAX, &first, 3)?;
    push(&mut a, 5, 0, &first, 4)?;
    Ok(())
}

#[test]
fn limits_and_payload_free_debug_are_public_contracts() -> TestResult {
    for limits in [
        Limits { max_nals: 0, ..Limits::default() },
        Limits { max_bytes: 2, ..Limits::default() },
        Limits { max_source_spans: 0, ..Limits::default() },
        Limits { max_age_ns: 0, ..Limits::default() },
        Limits { max_nals: 4097, ..Limits::default() },
        Limits { max_bytes: 64 * 1_024 * 1_024 + 1, ..Limits::default() },
        Limits { max_source_spans: 262_145, ..Limits::default() },
        Limits { max_age_ns: 60_000_000_001, ..Limits::default() },
    ] { assert_eq!(HevcAssembler::new(KEY, limits).err(), Some(E::Configuration)); }
    let mut a = HevcAssembler::new(KEY, Limits::default())?;
    let mut bytes = slice(1, true, 0, 1, false);
    bytes.extend_from_slice(b"PRIVATE_MEDIA");
    push(&mut a, 1, 100, &bytes, 0)?;
    assert!(!format!("{a:?}").contains("PRIVATE_MEDIA"));
    let out = a.finish(1)?;
    assert!(!format!("{out:?}").contains("PRIVATE_MEDIA"));
    assert!(!format!("{out:?}").contains(&format!("{bytes:?}")));
    Ok(())
}
