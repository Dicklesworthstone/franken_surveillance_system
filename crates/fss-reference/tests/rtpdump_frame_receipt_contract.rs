#![forbid(unsafe_code)]
//! Reproduce portable receipts from real decoded pixels without restoring process authority.
mod rtpdump_support;

use fss_core::{ContentDigest, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::privacy_mask::{
    MASK_FILL_CHROMA, MASK_FILL_LUMA, PrivacyMaskPolicy, declare_mask, preview_mask,
};
use fss_reference::ingest::rtpdump::import::{
    RtpImportLimits, RtpImportScope, prepare_rtp_import, publish_rtp_import,
};
use fss_reference::ingest::rtpdump::recovery::checked_decode::RtpCustodyDecodeLimits;
use fss_reference::ingest::rtpdump::recovery::checked_decode::receipt::{
    ReceiptedRtpDecodeStep, RetainedRtpFrameReceipt, RtpFrameReceiptError, RtpFrameReceiptLimits,
};
use fss_reference::ingest::rtpdump::recovery::decode::RetainedRtpDecodeRequest;
use fss_reference::ingest::rtpdump::recovery::{RtpRecoveryPolicy, inspect_rtp_import};
use fss_reference::{ReferenceDeployment, ReplayCx};
use rtpdump_support::*;

fn setup(
    label: &str,
    bytes: &[u8],
    cx: &ReplayCx,
) -> Result<(ReferenceDeployment, ContentDigest), Error> {
    let base = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(base)?;
    for i in 0..1000 {
        let path = base.join(format!("rtp-receipt-{label}-{}-{i}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => {
                let mut dep = ReferenceDeployment::open(&path, "site:rtp-receipts", cx)?;
                let plan = prepare_rtp_import(
                    bytes,
                    RtpImportScope {
                        sensor: SensorId::parse("sensor:rtp-receipts")?,
                        stream: StreamId::parse("stream:rtp-receipts")?,
                        receive_time: TimestampNs(1_000_000_000),
                    },
                    config_for(7),
                    RtpImportLimits::default(),
                    cx,
                )?;
                let root = publish_rtp_import(plan, cx, &mut dep)?.root();
                return Ok((dep, root));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    Err("temporary directory bound".into())
}
fn request() -> Result<RetainedRtpDecodeRequest, Error> {
    let all = nals();
    let sps = all.iter().find(|n| n[0] & 31 == 7).ok_or("SPS")?;
    let pps = all.iter().find(|n| n[0] & 31 == 8).ok_or("PPS")?;
    Ok(RetainedRtpDecodeRequest::new([
        ContentDigest::sha256(sps),
        ContentDigest::sha256(pps),
    ]))
}
fn receipts(
    dep: &ReferenceDeployment,
    root: ContentDigest,
    ingress: u128,
    request: RetainedRtpDecodeRequest,
    cx: &ReplayCx,
) -> Result<Vec<RetainedRtpFrameReceipt>, Error> {
    let retained = inspect_rtp_import(root, ingress, RtpRecoveryPolicy::default(), cx, dep)?;
    let mut decoder = retained.decode_h264_receipted(
        request,
        RtpCustodyDecodeLimits::default(),
        RtpFrameReceiptLimits::default(),
        dep,
        cx,
    )?;
    let mut out = Vec::new();
    for _ in 0..10_000 {
        match decoder.step(dep, cx)? {
            ReceiptedRtpDecodeStep::Frame { frame, receipt } => {
                assert_eq!(frame.source().key.ingress, ingress);
                assert_eq!(receipt.digest(), ContentDigest::sha256(receipt.bytes()));
                assert_eq!(
                    receipt.plane_digests(),
                    [
                        ContentDigest::sha256(frame.pixels()),
                        ContentDigest::sha256(frame.cb()),
                        ContentDigest::sha256(frame.cr()),
                        ContentDigest::sha256(&[frame.pixels(), frame.cb(), frame.cr()].concat()),
                    ]
                );
                out.push(receipt);
            }
            ReceiptedRtpDecodeStep::Progress { .. } => {}
            ReceiptedRtpDecodeStep::Ended(stats) => {
                assert!(stats.complete());
                assert_eq!(
                    decoder.receipt_bytes(),
                    out.iter().map(|r| r.bytes().len() as u64).sum::<u64>()
                );
                assert_eq!(out.len(), 4);
                return Ok(out);
            }
        }
    }
    Err("receipt progress bound".into())
}

#[test]
fn canonical_receipts_reproduce_across_fresh_ingress_handles_with_exact_masked_pixels() -> TestResult
{
    let cx = cx()?;
    let (dep, root) = setup("reproduce", &real_dump(true), &cx)?;
    let before = dep.current_anchor().clone();
    let a = receipts(&dep, root, 1, request()?, &cx)?;
    let b = receipts(&dep, root, u128::MAX, request()?, &cx)?;
    assert_eq!(a, b);
    assert_eq!(dep.current_anchor(), &before);
    Ok(())
}

#[test]
fn changed_receiver_or_decoder_recipe_cannot_reuse_the_same_frame_receipt() -> TestResult {
    let cx = cx()?;
    let (dep, root) = setup("recipe", &real_dump(false), &cx)?;
    let a = receipts(&dep, root, 1, request()?, &cx)?;
    let mut changed = request()?;
    changed.receiver.reorder.max_delay_ns += 1;
    let b = receipts(&dep, root, 1, changed, &cx)?;
    let mut changed = request()?;
    changed.decode.max_decode_calls -= 1;
    let c = receipts(&dep, root, 1, changed, &cx)?;
    for (index, original) in a.iter().enumerate() {
        for alternate in [&b[index], &c[index]] {
            assert_eq!(original.plane_digests(), alternate.plane_digests());
            assert_ne!(original.recipe(), alternate.recipe());
            assert_ne!(original.digest(), alternate.digest());
        }
    }
    Ok(())
}

#[test]
fn tampered_rehashed_truncated_or_substituted_saved_receipts_fail_reproduction() -> TestResult {
    let cx = cx()?;
    let (dep, root) = setup("tamper", &real_dump(false), &cx)?;
    let all = receipts(&dep, root, 1, request()?, &cx)?;
    let first = &all[0];
    first.verify_saved(first.bytes(), first.digest())?;
    let mut tampered = first.bytes().to_vec();
    tampered[0] ^= 1;
    assert!(first.verify_saved(&tampered, first.digest()).is_err());
    assert!(
        first
            .verify_saved(&tampered, ContentDigest::sha256(&tampered))
            .is_err()
    );
    assert!(
        first
            .verify_saved(&first.bytes()[..first.bytes().len() - 1], first.digest())
            .is_err()
    );
    assert!(first.verify_saved(first.bytes(), all[1].digest()).is_err());
    assert!(first.verify_saved(all[1].bytes(), all[1].digest()).is_err());
    Ok(())
}

#[test]
fn privacy_changes_produce_new_receipts_over_only_masked_y_cb_cr_planes() -> TestResult {
    let cx = cx()?;
    let (mut dep, root) = setup("privacy", &real_dump(false), &cx)?;
    let before = receipts(&dep, root, 1, request()?, &cx)?;
    let retained = inspect_rtp_import(root, 1, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let mut decoder = retained.decode_h264_receipted(
        request()?,
        RtpCustodyDecodeLimits::default(),
        RtpFrameReceiptLimits::default(),
        &dep,
        &cx,
    )?;
    let mut dimensions = None;
    for _ in 0..10_000 {
        if let ReceiptedRtpDecodeStep::Frame { frame, .. } = decoder.step(&dep, &cx)? {
            dimensions = Some(frame.dimensions());
            break;
        }
    }
    let dimensions = dimensions.ok_or("frame dimensions")?;
    drop(decoder);
    let policy = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:rtp-receipts")?,
        dimensions,
        &[[0, 0, dimensions[0], dimensions[1]]],
    )?;
    let approval = preview_mask(&dep, &policy)?.approval;
    declare_mask(&mut dep, &policy, approval, &cx)?;
    let after = receipts(&dep, root, 2, request()?, &cx)?;
    let [w, h] = dimensions;
    let masked_y = ContentDigest::sha256(&vec![MASK_FILL_LUMA; (w * h) as usize]);
    let masked_c = ContentDigest::sha256(&vec![
        MASK_FILL_CHROMA;
        (w.div_ceil(2) * h.div_ceil(2)) as usize
    ]);
    for (old, new) in before.iter().zip(after) {
        assert_eq!(old.recipe(), new.recipe());
        assert_ne!(old.digest(), new.digest());
        assert_eq!(new.plane_digests()[0], masked_y);
        assert_eq!(new.plane_digests()[1], masked_c);
        assert_eq!(new.plane_digests()[2], masked_c);
    }
    Ok(())
}

#[test]
fn receipt_budget_is_cumulative_and_failed_pair_delivery_is_not_a_served_frame() -> TestResult {
    let cx = cx()?;
    let (dep, root) = setup("budget", &real_dump(false), &cx)?;
    let all = receipts(&dep, root, 1, request()?, &cx)?;
    let allowance = all[0].bytes().len() as u64;
    let retained = inspect_rtp_import(root, 1, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let mut decoder = retained.decode_h264_receipted(
        request()?,
        RtpCustodyDecodeLimits::default(),
        RtpFrameReceiptLimits {
            max_total_bytes: allowance,
            ..RtpFrameReceiptLimits::default()
        },
        &dep,
        &cx,
    )?;
    let mut served = 0;
    let mut refused = false;
    for _ in 0..10_000 {
        match decoder.step(&dep, &cx) {
            Ok(ReceiptedRtpDecodeStep::Frame { .. }) => served += 1,
            Err(RtpFrameReceiptError::Limit) => {
                refused = true;
                break;
            }
            Err(e) => return Err(e.into()),
            Ok(ReceiptedRtpDecodeStep::Ended(_)) => break,
            _ => {}
        }
    }
    assert!(refused);
    assert_eq!(served, 1);
    assert_eq!(decoder.stats().frames, 1);
    assert!(decoder.stats().ended && !decoder.stats().complete());
    assert_eq!(decoder.receipt_bytes(), allowance);
    assert!(matches!(
        decoder.step(&dep, &cx)?,
        ReceiptedRtpDecodeStep::Ended(_)
    ));
    Ok(())
}

#[test]
fn per_receipt_limit_refuses_before_pixel_digesting_or_joint_delivery() -> TestResult {
    let cx = cx()?;
    let (dep, root) = setup("single-bound", &real_dump(false), &cx)?;
    let retained = inspect_rtp_import(root, 1, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let mut decoder = retained.decode_h264_receipted(
        request()?,
        RtpCustodyDecodeLimits::default(),
        RtpFrameReceiptLimits {
            max_receipt_bytes: 1,
            ..RtpFrameReceiptLimits::default()
        },
        &dep,
        &cx,
    )?;
    let mut refused = false;
    for _ in 0..10_000 {
        match decoder.step(&dep, &cx) {
            Err(RtpFrameReceiptError::Limit) => {
                refused = true;
                break;
            }
            Err(e) => return Err(e.into()),
            Ok(ReceiptedRtpDecodeStep::Frame { .. }) => {
                return Err("unreceipted frame escaped".into());
            }
            _ => {}
        }
    }
    assert!(refused);
    assert_eq!(decoder.receipt_bytes(), 0);
    assert_eq!(decoder.stats().frames, 0);
    Ok(())
}

#[test]
fn cancellation_before_receipt_delivery_is_terminal_and_has_no_frame_output() -> TestResult {
    let cx = cx()?;
    let (dep, root) = setup("cancel", &real_dump(false), &cx)?;
    let retained = inspect_rtp_import(root, 1, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let mut decoder = retained.decode_h264_receipted(
        request()?,
        RtpCustodyDecodeLimits::default(),
        RtpFrameReceiptLimits::default(),
        &dep,
        &cx,
    )?;
    cx.request_cancellation();
    assert!(matches!(
        decoder.step(&dep, &cx),
        Err(RtpFrameReceiptError::Cancelled)
    ));
    assert_eq!(decoder.stats().frames, 0);
    assert_eq!(decoder.receipt_bytes(), 0);
    assert!(matches!(
        decoder.step(&dep, &cx)?,
        ReceiptedRtpDecodeStep::Ended(_)
    ));
    Ok(())
}

#[test]
fn successful_idr_recovery_receipts_do_not_erase_the_incomplete_decode_history() -> TestResult {
    let cx = cx()?;
    let mut planned = packetize(2, 100, 65534, 7, 90000, 0);
    let missing = planned.iter().position(|p| p.vcl).ok_or("IDR packet")?;
    planned.remove(missing);
    let (dep, root) = setup("recovery", &dump_planned(&planned), &cx)?;
    let retained = inspect_rtp_import(root, 1, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let mut decoder = retained.decode_h264_receipted(
        request()?,
        RtpCustodyDecodeLimits::default(),
        RtpFrameReceiptLimits::default(),
        &dep,
        &cx,
    )?;
    let mut recovered = false;
    for _ in 0..10_000 {
        match decoder.step(&dep, &cx)? {
            ReceiptedRtpDecodeStep::Frame { frame, receipt } => {
                recovered |= frame.source().decoder_epoch > 0;
                receipt.verify_saved(receipt.bytes(), receipt.digest())?;
            }
            ReceiptedRtpDecodeStep::Ended(stats) => {
                assert!(recovered && stats.frames > 0 && stats.refusals > 0);
                assert!(stats.skipped_groups > 0 && stats.native_finished && !stats.complete());
                return Ok(());
            }
            _ => {}
        }
    }
    Err("recovered receipt progress bound".into())
}
