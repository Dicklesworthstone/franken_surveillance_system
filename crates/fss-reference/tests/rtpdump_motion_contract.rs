#![forbid(unsafe_code)]
//! Native source -> custody/receipt -> shared pixel-change kernel, without mock frames.
mod rtpdump_support;

use fss_codec_h264::{Decoder, DecoderLimits, Picture};
use fss_core::{CanonicalEncode, ContentDigest, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::pixel_change::rtp::*;
use fss_reference::ingest::pixel_change::{PixelChangeConfig, PixelChangeError, PixelChangeReset};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::rtpdump::import::{
    RtpImportLimits, RtpImportScope, prepare_rtp_import, publish_rtp_import,
};
use fss_reference::ingest::rtpdump::recovery::checked_decode::receipt::ReceiptedRtpDecodeStep;
use fss_reference::ingest::rtpdump::recovery::decode::RetainedRtpDecodeRequest;
use fss_reference::ingest::rtpdump::recovery::{RtpRecoveryPolicy, inspect_rtp_import};
use fss_reference::{ReferenceDeployment, ReplayCx};
use rtpdump_support::*;
use std::path::PathBuf;

fn setup(
    label: &str,
    bytes: &[u8],
    cx: &ReplayCx,
) -> Result<(ReferenceDeployment, ContentDigest, PathBuf), Error> {
    let base = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(base)?;
    for i in 0..1000 {
        let path = base.join(format!("rtp-motion-{label}-{}-{i}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => {
                let mut dep = ReferenceDeployment::open(&path, "site:rtp-motion", cx)?;
                let plan = prepare_rtp_import(
                    bytes,
                    RtpImportScope {
                        sensor: SensorId::parse("sensor:rtp-motion")?,
                        stream: StreamId::parse("stream:rtp-motion")?,
                        receive_time: TimestampNs(2_000_000_000),
                    },
                    config_for(7),
                    RtpImportLimits::default(),
                    cx,
                )?;
                let root = publish_rtp_import(plan, cx, &mut dep)?.root();
                return Ok((dep, root, path));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    Err("temporary directory bound".into())
}
fn request(all: &[&[u8]]) -> Result<RtpMotionRequest, Error> {
    let sps = all.iter().find(|n| n[0] & 31 == 7).ok_or("SPS")?;
    let pps = all.iter().find(|n| n[0] & 31 == 8).ok_or("PPS")?;
    Ok(RtpMotionRequest::new(
        RetainedRtpDecodeRequest::new([ContentDigest::sha256(sps), ContentDigest::sha256(pps)]),
        PixelChangeConfig {
            minimum_delta: 20,
            minimum_changed_pixels: 2,
            minimum_changed_fraction_ppm: 500,
        },
        64_000_000,
    ))
}
fn native(all: &[&[u8]]) -> Result<Vec<Picture>, Error> {
    let mut decoder = Decoder::new(DecoderLimits::default())?;
    let mut frames = Vec::new();
    for nal in all {
        if let Some(p) = decoder.decode_nal(nal)? {
            frames.push(p);
        }
        while let Some(p) = decoder.next_output() {
            frames.push(p);
        }
    }
    frames.extend(decoder.finish()?);
    Ok(frames)
}
fn collect(
    a: &mut RtpMotionAnalyzer<'_>,
    dep: &ReferenceDeployment,
    cx: &ReplayCx,
) -> Result<Vec<RtpPixelChangeObservation>, Error> {
    let mut out = Vec::new();
    for _ in 0..20_000 {
        match a.step(dep, cx)? {
            RtpMotionStep::Observation(o) => out.push(o),
            RtpMotionStep::Ended(_) => return Ok(out),
            RtpMotionStep::Progress { .. } => {}
        }
    }
    Err("motion did not terminate".into())
}
fn next(
    a: &mut RtpMotionAnalyzer<'_>,
    dep: &ReferenceDeployment,
    cx: &ReplayCx,
) -> Result<RtpPixelChangeObservation, Error> {
    for _ in 0..20_000 {
        match a.step(dep, cx)? {
            RtpMotionStep::Observation(o) => return Ok(o),
            RtpMotionStep::Ended(_) => return Err("expected observation".into()),
            RtpMotionStep::Progress { .. } => {}
        }
    }
    Err("observation progress bound".into())
}
fn assert_native(
    observations: &[RtpPixelChangeObservation],
    frames: &[Picture],
    r: RtpMotionRequest,
) {
    assert_eq!(observations.len(), frames.len());
    assert!(observations[0].statistics.is_none());
    assert!(
        observations[0]
            .reset_reasons
            .contains(&PixelChangeReset::NoPredecessor)
    );
    assert_eq!(observations[0].predecessor_receipt, None);
    for (index, (o, pair)) in observations[1..].iter().zip(frames.windows(2)).enumerate() {
        let s = o.statistics.as_ref().expect("comparable pair");
        let diff: Vec<_> = pair[0]
            .luma()
            .iter()
            .zip(pair[1].luma())
            .map(|(a, b)| a.abs_diff(*b))
            .collect();
        let changed = diff
            .iter()
            .filter(|d| **d >= r.thresholds.minimum_delta)
            .count() as u64;
        let count = diff.len() as u64;
        assert_eq!(s.compared_pixels, count);
        assert_eq!(s.changed_pixels, changed);
        assert_eq!(
            s.absolute_difference_sum,
            diff.iter().map(|d| u64::from(*d)).sum::<u64>()
        );
        assert_eq!(s.maximum_difference, *diff.iter().max().expect("pixels"));
        assert_eq!(
            s.candidate,
            changed >= r.thresholds.minimum_changed_pixels
                && changed * 1_000_000
                    >= count * u64::from(r.thresholds.minimum_changed_fraction_ppm)
        );
        assert_eq!(
            o.predecessor_receipt,
            Some(observations[index].frame_receipt)
        );
        assert_eq!(o.output_index, index as u64 + 1);
        assert!(o.reset_reasons.is_empty());
    }
}

#[test]
fn single_and_fragmented_sources_measure_exact_native_pixels_without_writes() -> TestResult {
    for fragmented in [false, true] {
        let cx = cx()?;
        let (dep, root, _) = setup("scalar", &real_dump(fragmented), &cx)?;
        let anchor = dep.current_anchor().clone();
        let retained = inspect_rtp_import(root, 1, RtpRecoveryPolicy::default(), &cx, &dep)?;
        let r = request(&nals())?;
        let mut a = RtpMotionAnalyzer::open(&retained, r, &dep, &cx)?;
        let out = collect(&mut a, &dep, &cx)?;
        assert_native(&out, &native(&nals())?, r);
        assert_eq!(a.stats().observations, 4);
        assert_eq!(a.stats().measured_pairs, 3);
        assert_eq!(a.stats().resets, 1);
        assert!(a.stats().complete());
        assert!(
            a.stats().comparisons > 0
                && a.stats().custody_read_bytes > 0
                && a.stats().receipt_bytes > 0
        );
        assert_eq!(dep.current_anchor(), &anchor);
    }
    Ok(())
}

#[test]
fn cold_open_and_new_ingress_reproduce_observations_and_exact_frame_receipts() -> TestResult {
    let cx = cx()?;
    let (dep, root, path) = setup("cold", &real_dump(true), &cx)?;
    let retained = inspect_rtp_import(root, 1, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let r = request(&nals())?;
    let mut a = RtpMotionAnalyzer::open(&retained, r, &dep, &cx)?;
    let first = collect(&mut a, &dep, &cx)?;
    drop(a);
    drop(retained);
    drop(dep);
    let dep = ReferenceDeployment::reopen(&path, "site:rtp-motion", &cx)?;
    let retained = inspect_rtp_import(root, u128::MAX, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let mut a = RtpMotionAnalyzer::open(&retained, r, &dep, &cx)?;
    let second = collect(&mut a, &dep, &cx)?;
    assert_eq!(first, second);
    for (a, b) in first.iter().zip(&second) {
        assert_eq!(a.try_canonical_bytes()?, b.try_canonical_bytes()?);
        assert_eq!(a.digest(), b.digest());
        assert_eq!(a.capture.earliest, TimestampNs(0));
        assert_eq!(a.capture.latest, TimestampNs(2_000_000_000));
    }
    let mut d = retained.decode_h264_receipted(r.decode, r.custody, r.receipts, &dep, &cx)?;
    let mut identities = Vec::new();
    for _ in 0..20_000 {
        match d.step(&dep, &cx)? {
            ReceiptedRtpDecodeStep::Frame { receipt, .. } => identities.push(receipt.digest()),
            ReceiptedRtpDecodeStep::Ended(_) => break,
            _ => {}
        }
    }
    assert_eq!(
        identities,
        second.iter().map(|o| o.frame_receipt).collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn changed_thresholds_change_observation_identity_not_native_frame_identity() -> TestResult {
    let cx = cx()?;
    let (dep, root, _) = setup("thresholds", &real_dump(false), &cx)?;
    let retained = inspect_rtp_import(root, 1, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let r = request(&nals())?;
    let mut a = RtpMotionAnalyzer::open(&retained, r, &dep, &cx)?;
    let first = collect(&mut a, &dep, &cx)?;
    let mut other = r;
    other.thresholds.minimum_delta = 1;
    let mut b = RtpMotionAnalyzer::open(&retained, other, &dep, &cx)?;
    let second = collect(&mut b, &dep, &cx)?;
    for (a, b) in first.iter().zip(second) {
        assert_eq!(a.frame_receipt, b.frame_receipt);
        assert_ne!(a.configuration_digest, b.configuration_digest);
        assert_ne!(a.digest(), b.digest());
    }
    Ok(())
}
fn full_mask(dep: &mut ReferenceDeployment, cx: &ReplayCx) -> TestResult {
    let frames = native(&nals())?;
    let [w, h] = [frames[0].width(), frames[0].height()];
    let p = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:rtp-motion")?,
        [w, h],
        &[[0, 0, w, h]],
    )?;
    let approval = preview_mask(dep, &p)?.approval;
    declare_mask(dep, &p, approval, cx)?;
    Ok(())
}

#[test]
fn privacy_mask_is_applied_before_comparison_and_kept_in_lineage() -> TestResult {
    let cx = cx()?;
    let (mut dep, root, _) = setup("masked", &real_dump(false), &cx)?;
    full_mask(&mut dep, &cx)?;
    let retained = inspect_rtp_import(root, 1, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let mut a = RtpMotionAnalyzer::open(&retained, request(&nals())?, &dep, &cx)?;
    let out = collect(&mut a, &dep, &cx)?;
    assert!(a.stats().complete());
    assert_eq!(a.stats().candidate_pairs, 0);
    for o in &out[1..] {
        let s = o.statistics.as_ref().ok_or("masked measurement")?;
        assert_eq!(s.absolute_difference_sum, 0);
        assert_eq!(s.changed_pixels, 0);
        assert_eq!(s.changed_bounds, None);
        assert!(!s.candidate);
    }
    Ok(())
}

#[test]
fn gap_recovery_emits_an_unmeasured_baseline_and_never_hides_partial_history() -> TestResult {
    let cx = cx()?;
    let mut planned = packetize(3, 10000, 100, 7, 0, 0);
    let remove = planned
        .iter()
        .enumerate()
        .filter(|(_, p)| p.vcl)
        .nth(5)
        .ok_or("VCL")?
        .0;
    planned.remove(remove);
    let (dep, root, _) = setup("gap", &dump_planned(&planned), &cx)?;
    let retained = inspect_rtp_import(root, 1, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let mut a = RtpMotionAnalyzer::open(&retained, request(&nals())?, &dep, &cx)?;
    let out = collect(&mut a, &dep, &cx)?;
    assert!(
        out.iter()
            .any(|o| o.decoder_epoch == 0 && o.statistics.is_some())
    );
    let recovered = out
        .iter()
        .find(|o| o.decoder_epoch > 0)
        .ok_or("recovery observation")?;
    assert!(
        recovered
            .reset_reasons
            .contains(&PixelChangeReset::SourceGap)
    );
    assert!(recovered.statistics.is_none() && recovered.predecessor_receipt.is_none());
    assert!(a.stats().decode.refusals > 0 && a.stats().resets >= 2);
    assert!(!a.stats().complete());
    assert_eq!(
        a.stats().comparisons,
        out.iter()
            .filter_map(|o| o.statistics.as_ref())
            .map(|s| s.compared_pixels)
            .sum()
    );
    Ok(())
}

#[test]
fn comparison_limit_is_terminal_and_failed_measurement_is_not_delivered() -> TestResult {
    let cx = cx()?;
    let (dep, root, _) = setup("budget", &real_dump(false), &cx)?;
    let retained = inspect_rtp_import(root, 1, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let mut r = request(&nals())?;
    r.max_comparisons = 0;
    let mut a = RtpMotionAnalyzer::open(&retained, r, &dep, &cx)?;
    next(&mut a, &dep, &cx)?;
    let mut refused = false;
    for _ in 0..20_000 {
        match a.step(&dep, &cx) {
            Err(RtpMotionError::Pixel(PixelChangeError::BudgetExceeded)) => {
                refused = true;
                break;
            }
            Err(e) => return Err(e.into()),
            Ok(RtpMotionStep::Observation(_)) => return Err("over-budget comparison".into()),
            _ => {}
        }
    }
    assert!(refused && !a.stats().complete() && a.stats().ended);
    assert_eq!(a.stats().observations, 1);
    assert_eq!(a.stats().comparisons, 0);
    assert_eq!(a.stats().failures, 1);
    assert!(matches!(a.step(&dep, &cx)?, RtpMotionStep::Ended(_)));
    Ok(())
}

#[test]
fn cancellation_after_a_baseline_prevents_future_measurements() -> TestResult {
    let cx = cx()?;
    let (dep, root, _) = setup("cancel", &real_dump(false), &cx)?;
    let retained = inspect_rtp_import(root, 1, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let mut a = RtpMotionAnalyzer::open(&retained, request(&nals())?, &dep, &cx)?;
    next(&mut a, &dep, &cx)?;
    cx.request_cancellation();
    assert!(matches!(
        a.step(&dep, &cx),
        Err(RtpMotionError::Pixel(PixelChangeError::Cancelled))
    ));
    assert_eq!(a.stats().observations, 1);
    assert!(!a.stats().complete());
    assert!(matches!(a.step(&dep, &cx)?, RtpMotionStep::Ended(_)));
    Ok(())
}

#[test]
fn lost_custody_cannot_be_hidden_by_a_cached_baseline() -> TestResult {
    let cx = cx()?;
    let (dep, root, _) = setup("loss", &real_dump(false), &cx)?;
    let retained = inspect_rtp_import(root, 1, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let mut a = RtpMotionAnalyzer::open(&retained, request(&nals())?, &dep, &cx)?;
    next(&mut a, &dep, &cx)?;
    let d = retained.report().chunk_digests()[0];
    std::fs::remove_file(dep.publisher().spool().object_path(d))?;
    let mut refused = false;
    for _ in 0..20_000 {
        match a.step(&dep, &cx) {
            Err(RtpMotionError::Decode(_)) => {
                refused = true;
                break;
            }
            Err(e) => return Err(e.into()),
            Ok(RtpMotionStep::Observation(_)) => return Err("uncustodied measurement".into()),
            _ => {}
        }
    }
    assert!(refused && !a.stats().complete());
    assert_eq!(a.stats().observations, 1);
    Ok(())
}

#[test]
fn policy_change_fences_the_attempt_and_new_admission_uses_masked_pixels() -> TestResult {
    let cx = cx()?;
    let (mut dep, root, _) = setup("drift", &real_dump(false), &cx)?;
    let retained = inspect_rtp_import(root, 1, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let mut a = RtpMotionAnalyzer::open(&retained, request(&nals())?, &dep, &cx)?;
    next(&mut a, &dep, &cx)?;
    full_mask(&mut dep, &cx)?;
    assert!(matches!(a.step(&dep, &cx), Err(RtpMotionError::Decode(_))));
    assert_eq!(a.stats().observations, 1);
    let fresh = inspect_rtp_import(root, 2, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let mut b = RtpMotionAnalyzer::open(&fresh, request(&nals())?, &dep, &cx)?;
    let out = collect(&mut b, &dep, &cx)?;
    assert_eq!(out.len(), 4);
    assert!(b.stats().complete());
    assert_eq!(b.stats().candidate_pairs, 0);
    Ok(())
}

#[test]
fn malformed_tail_and_receipt_limit_cannot_be_reported_as_complete_motion() -> TestResult {
    let cx = cx()?;
    let mut bytes = real_dump(false);
    bytes.extend_from_slice(&[0, 10, 0]);
    let (dep, root, _) = setup("tail", &bytes, &cx)?;
    let retained = inspect_rtp_import(root, 1, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let r = request(&nals())?;
    let mut a = RtpMotionAnalyzer::open(&retained, r, &dep, &cx)?;
    collect(&mut a, &dep, &cx)?;
    assert!(!a.stats().complete() && a.stats().decode.refusals > 0);
    let mut r = r;
    r.receipts.max_receipt_bytes = 1;
    let mut b = RtpMotionAnalyzer::open(&retained, r, &dep, &cx)?;
    assert!(collect(&mut b, &dep, &cx).is_err());
    assert_eq!(b.stats().observations, 0);
    assert!(!b.stats().complete());
    Ok(())
}

// Fixture-only packetizer for the independently committed Main-profile B-picture corpus.
fn b_nals() -> Vec<&'static [u8]> {
    let bytes: &'static [u8] =
        include_bytes!("../../fss-codec-h264/tests/fixtures/decode/m_b_cavlc.h264");
    let mut starts = Vec::new();
    let mut at = 0;
    while at + 3 <= bytes.len() {
        let len = if bytes.get(at..at + 4) == Some(&[0, 0, 0, 1]) {
            4
        } else if bytes[at..at + 3] == [0, 0, 1] {
            3
        } else {
            0
        };
        if len > 0 {
            starts.push((at, at + len));
            at += len;
        } else {
            at += 1;
        }
    }
    starts
        .iter()
        .enumerate()
        .map(|(i, (_, s))| {
            let mut e = starts.get(i + 1).map_or(bytes.len(), |n| n.0);
            while e > *s && bytes[e - 1] == 0 {
                e -= 1;
            }
            &bytes[*s..e]
        })
        .collect()
}
#[test]
fn b_picture_display_reordering_is_comparable_without_fabricated_source_gaps() -> TestResult {
    let cx = cx()?;
    let all = b_nals();
    let frames = native(&all)?;
    let mut bytes = header();
    let p = rtp(0, false, &[9, 0xf0]);
    record(&mut bytes, &p, p.len() as u16, 0);
    for (i, nal) in all.iter().enumerate() {
        let p = rtp((i + 1) as u16, matches!(nal[0] & 31, 1 | 5), nal);
        record(&mut bytes, &p, p.len() as u16, i as u32);
    }
    let (dep, root, _) = setup("b-display", &bytes, &cx)?;
    let retained = inspect_rtp_import(root, 1, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let r = request(&all)?;
    let mut a = RtpMotionAnalyzer::open(&retained, r, &dep, &cx)?;
    let out = collect(&mut a, &dep, &cx)?;
    assert!(a.stats().complete(), "{:?}", a.stats());
    assert!(
        out.windows(2)
            .any(|pair| pair[1].source_group < pair[0].source_group)
    );
    assert_native(&out, &frames, r);
    Ok(())
}
