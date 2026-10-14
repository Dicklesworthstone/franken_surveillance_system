#![forbid(unsafe_code)]
//! Current-custody delivery over the retained RTP decoder, including queued output failures.
mod rtpdump_support;
use fss_codec_h264::{Decoder, DecoderLimits, Picture};
use fss_core::{CanonicalEncode, CaptureInterval, ContentDigest, SensorId, StreamId, TimestampNs};
use fss_publication::SlotName;
use fss_reference::ingest::privacy_mask::{
    MASK_FILL_CHROMA, MASK_FILL_LUMA, PrivacyMaskPolicy, declare_mask, preview_mask,
};
use fss_reference::ingest::rtpdump::import::{
    RtpImportLimits, RtpImportScope, prepare_rtp_import, publish_rtp_import,
};
use fss_reference::ingest::rtpdump::recovery::checked_decode::{
    CheckedRetainedRtpH264Decoder, CheckedRtpDecodeError, RtpCustodyDecodeLimits,
};
use fss_reference::ingest::rtpdump::recovery::decode::{
    RetainedRtpDecodeError, RetainedRtpDecodeRequest, RetainedRtpDecodeStep,
};
use fss_reference::ingest::rtpdump::recovery::{RtpRecoveryPolicy, inspect_rtp_import};
use fss_reference::{ReferenceDeployment, ReplayCx};
use rtpdump_support::*;

fn scope() -> Result<RtpImportScope, Error> {
    Ok(RtpImportScope {
        sensor: SensorId::parse("sensor:retained-rtp-decode")?,
        stream: StreamId::parse("stream:retained-rtp-decode")?,
        receive_time: TimestampNs(1_000_000_000),
    })
}
fn directory(label: &str) -> Result<std::path::PathBuf, Error> {
    let base = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(base)?;
    for index in 0..1000 {
        let path = base.join(format!(
            "rtp-custody-decode-{label}-{}-{index}",
            std::process::id()
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err("directory bound".into())
}
fn publish(
    bytes: &[u8],
    dep: &mut ReferenceDeployment,
    cx: &ReplayCx,
) -> Result<ContentDigest, Error> {
    Ok(publish_rtp_import(
        prepare_rtp_import(
            bytes,
            scope()?,
            config_for(7),
            RtpImportLimits::default(),
            cx,
        )?,
        cx,
        dep,
    )?
    .root())
}
fn selection() -> Result<RetainedRtpDecodeRequest, Error> {
    let all = nals();
    let sps = all.iter().find(|nal| nal[0] & 31 == 7).ok_or("SPS")?;
    let pps = all.iter().find(|nal| nal[0] & 31 == 8).ok_or("PPS")?;
    Ok(RetainedRtpDecodeRequest::new([
        ContentDigest::sha256(sps),
        ContentDigest::sha256(pps),
    ]))
}
fn oracle() -> Result<Vec<Picture>, Error> {
    let mut decoder = Decoder::new(DecoderLimits::default())?;
    let mut frames = Vec::new();
    for nal in nals() {
        if let Some(frame) = decoder.decode_nal(nal)? {
            frames.push(frame);
        }
        while let Some(frame) = decoder.next_output() {
            frames.push(frame);
        }
    }
    frames.extend(decoder.finish()?);
    assert_eq!(frames.len(), 4);
    Ok(frames)
}
fn dimensions() -> Result<[u32; 2], Error> {
    let frames = oracle()?;
    let first = frames.first().ok_or("oracle frame")?;
    Ok([first.width(), first.height()])
}
fn mask(
    dep: &mut ReferenceDeployment,
    dimensions: [u32; 2],
    cx: &ReplayCx,
) -> Result<ContentDigest, Error> {
    let policy = PrivacyMaskPolicy::new(
        scope()?.sensor,
        dimensions,
        &[[0, 0, dimensions[0], dimensions[1]]],
    )?;
    let preview = preview_mask(dep, &policy)?;
    declare_mask(dep, &policy, preview.approval, cx)?;
    Ok(policy.digest())
}
fn until_queued(
    reader: &mut CheckedRetainedRtpH264Decoder<'_>,
    dep: &ReferenceDeployment,
    cx: &ReplayCx,
) -> TestResult {
    for _ in 0..10_000 {
        if reader.queued_pictures() > 0 {
            return Ok(());
        }
        assert!(!matches!(
            reader.step(dep, cx)?,
            RetainedRtpDecodeStep::Ended(_)
        ));
    }
    Err("no queued picture within bound".into())
}

#[test]
fn cold_root_decode_matches_native_pixels_without_original_file_or_new_authority() -> TestResult {
    let dir = directory("cold")?;
    let cx = cx()?;
    let mut dep = ReferenceDeployment::open(&dir, "site:retained-rtp", &cx)?;
    let root = publish(&real_dump(true), &mut dep, &cx)?;
    drop(dep);
    let dep = ReferenceDeployment::reopen(&dir, "site:retained-rtp", &cx)?;
    let before = dep.current_anchor().clone();
    let recovered = inspect_rtp_import(root, 901, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let mut reader = recovered.decode_h264_checked(
        selection()?,
        RtpCustodyDecodeLimits::default(),
        &dep,
        &cx,
    )?;
    let mut found = Vec::new();
    for _ in 0..10_000 {
        match reader.step(&dep, &cx)? {
            RetainedRtpDecodeStep::Frame(frame) => {
                assert_eq!(frame.root(), root);
                assert_eq!(frame.mask().policy_digest(), None);
                assert_eq!(frame.source().recording, recovered.report().input_digest());
                assert_eq!(frame.source().key.ingress, 901);
                found.push(ContentDigest::sha256(
                    &[frame.pixels(), frame.cb(), frame.cr()].concat(),
                ));
            }
            RetainedRtpDecodeStep::Ended(_) => break,
            RetainedRtpDecodeStep::Progress { .. } => {}
        }
    }
    let expected: Vec<_> = oracle()?
        .iter()
        .map(|frame| ContentDigest::sha256(&[frame.luma(), frame.cb(), frame.cr()].concat()))
        .collect();
    assert_eq!(found, expected);
    let summary = reader.stats();
    assert!(summary.ended && summary.input_ended && summary.native_finished);
    assert_eq!(summary.records, recovered.report().records().len());
    assert_eq!(summary.frames, 4);
    assert_eq!(summary.refusals, 0);
    assert_eq!(summary.skipped_groups, 0);
    assert!(reader.read_bytes() > 0);
    assert_eq!(dep.current_anchor(), &before);
    Ok(())
}

#[test]
fn retained_mask_is_applied_to_luma_and_both_chroma_planes_before_digesting() -> TestResult {
    let dir = directory("masked")?;
    let cx = cx()?;
    let mut dep = ReferenceDeployment::open(&dir, "site:retained-mask", &cx)?;
    let root = publish(&real_dump(true), &mut dep, &cx)?;
    let policy = mask(&mut dep, dimensions()?, &cx)?;
    let recovered = inspect_rtp_import(root, 902, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let mut reader = recovered.decode_h264_checked(
        selection()?,
        RtpCustodyDecodeLimits::default(),
        &dep,
        &cx,
    )?;
    let mut count = 0;
    for _ in 0..10_000 {
        match reader.step(&dep, &cx)? {
            RetainedRtpDecodeStep::Frame(frame) => {
                assert_eq!(frame.mask().policy_digest(), Some(policy));
                assert_eq!(frame.mask().generation(), Some(1));
                assert!(frame.pixels().iter().all(|v| *v == MASK_FILL_LUMA));
                assert!(frame.cb().iter().all(|v| *v == MASK_FILL_CHROMA));
                assert!(frame.cr().iter().all(|v| *v == MASK_FILL_CHROMA));
                assert!(
                    !frame.pixels().is_empty() && !frame.cb().is_empty() && !frame.cr().is_empty()
                );
                count += 1;
            }
            RetainedRtpDecodeStep::Ended(_) => break,
            RetainedRtpDecodeStep::Progress { .. } => {}
        }
    }
    assert!(reader.stats().ended);
    assert_eq!(count, 4);
    Ok(())
}

#[test]
fn policy_change_fences_already_queued_raw_pixels_and_requires_reinspection() -> TestResult {
    let dir = directory("policy-change")?;
    let cx = cx()?;
    let mut dep = ReferenceDeployment::open(&dir, "site:retained-policy-change", &cx)?;
    let root = publish(&real_dump(false), &mut dep, &cx)?;
    let recovered = inspect_rtp_import(root, 903, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let mut reader = recovered.decode_h264_checked(
        selection()?,
        RtpCustodyDecodeLimits::default(),
        &dep,
        &cx,
    )?;
    until_queued(&mut reader, &dep, &cx)?;
    assert_eq!(reader.stats().frames, 0);
    mask(&mut dep, dimensions()?, &cx)?;
    assert!(matches!(
        reader.step(&dep, &cx),
        Err(CheckedRtpDecodeError::StaleBasis)
    ));
    assert_eq!(reader.queued_pictures(), 0);
    assert_eq!(reader.stats().frames, 0);
    assert!(reader.stats().ended);
    assert!(matches!(
        reader.step(&dep, &cx)?,
        RetainedRtpDecodeStep::Ended(_)
    ));
    assert!(matches!(
        recovered.decode_h264_checked(selection()?, RtpCustodyDecodeLimits::default(), &dep, &cx),
        Err(CheckedRtpDecodeError::StaleBasis),
    ));
    // Recovery is an explicit new admission under the new policy, never an in-place rebase.
    let refreshed = inspect_rtp_import(root, 913, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let mut next = refreshed.decode_h264_checked(
        selection()?,
        RtpCustodyDecodeLimits::default(),
        &dep,
        &cx,
    )?;
    until_queued(&mut next, &dep, &cx)?;
    let RetainedRtpDecodeStep::Frame(frame) = next.step(&dep, &cx)? else {
        return Err("newly admitted masked frame missing".into());
    };
    assert_eq!(frame.root(), root);
    assert!(frame.mask().policy_digest().is_some());
    assert!(frame.pixels().iter().all(|v| *v == MASK_FILL_LUMA));
    assert!(frame.cb().iter().all(|v| *v == MASK_FILL_CHROMA));
    assert!(frame.cr().iter().all(|v| *v == MASK_FILL_CHROMA));
    Ok(())
}

#[test]
fn missing_original_chunk_cannot_be_hidden_by_cached_source_or_queued_pixels() -> TestResult {
    let dir = directory("missing-source")?;
    let cx = cx()?;
    let mut dep = ReferenceDeployment::open(&dir, "site:retained-missing", &cx)?;
    let root = publish(&real_dump(false), &mut dep, &cx)?;
    let recovered = inspect_rtp_import(root, 904, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let mut reader = recovered.decode_h264_checked(
        selection()?,
        RtpCustodyDecodeLimits::default(),
        &dep,
        &cx,
    )?;
    until_queued(&mut reader, &dep, &cx)?;
    let digest = *recovered.report().chunk_digests().first().ok_or("chunk")?;
    std::fs::remove_file(dep.publisher().spool().object_path(digest))?;
    assert!(matches!(
        reader.step(&dep, &cx),
        Err(CheckedRtpDecodeError::Custody)
    ));
    assert_eq!(reader.stats().frames, 0);
    assert_eq!(reader.queued_pictures(), 0);
    assert!(reader.stats().ended);
    Ok(())
}

#[test]
fn cancelled_delivery_discards_queued_pixels_without_serving_a_frame() -> TestResult {
    let dir = directory("cancelled")?;
    let cx = cx()?;
    let mut dep = ReferenceDeployment::open(&dir, "site:retained-cancelled", &cx)?;
    let root = publish(&real_dump(false), &mut dep, &cx)?;
    let recovered = inspect_rtp_import(root, 905, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let mut reader = recovered.decode_h264_checked(
        selection()?,
        RtpCustodyDecodeLimits::default(),
        &dep,
        &cx,
    )?;
    until_queued(&mut reader, &dep, &cx)?;
    cx.request_cancellation();
    assert!(matches!(
        reader.step(&dep, &cx),
        Err(CheckedRtpDecodeError::Cancelled)
    ));
    assert_eq!(reader.stats().frames, 0);
    assert_eq!(reader.queued_pictures(), 0);
    assert!(reader.stats().ended);
    assert!(matches!(
        reader.step(&dep, &cx)?,
        RetainedRtpDecodeStep::Ended(_)
    ));
    Ok(())
}

#[test]
fn exact_parameter_types_and_independent_source_read_and_step_limits_are_enforced() -> TestResult {
    let dir = directory("limits")?;
    let cx = cx()?;
    let mut dep = ReferenceDeployment::open(&dir, "site:retained-limits", &cx)?;
    let root = publish(&real_dump(false), &mut dep, &cx)?;
    let recovered = inspect_rtp_import(root, 906, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let selected = selection()?;
    for invalid in [
        RetainedRtpDecodeRequest::new([selected.parameters[1], selected.parameters[0]]),
        RetainedRtpDecodeRequest::new([
            ContentDigest::sha256(b"absent SPS"),
            selected.parameters[1],
        ]),
    ] {
        assert!(matches!(
            recovered.decode_h264_checked(invalid, RtpCustodyDecodeLimits::default(), &dep, &cx),
            Err(CheckedRtpDecodeError::Native(error))
                if matches!(*error, RetainedRtpDecodeError::ParametersUnavailable)
        ));
    }
    for limits in [
        RtpCustodyDecodeLimits {
            max_source_bytes: 1,
            ..RtpCustodyDecodeLimits::default()
        },
        RtpCustodyDecodeLimits {
            max_records: 1,
            ..RtpCustodyDecodeLimits::default()
        },
        RtpCustodyDecodeLimits {
            max_read_bytes: dep.publisher().spool().limits().max_object_bytes as u64,
            ..RtpCustodyDecodeLimits::default()
        },
    ] {
        assert!(matches!(
            recovered.decode_h264_checked(selected, limits, &dep, &cx),
            Err(CheckedRtpDecodeError::Limit),
        ));
    }
    let mut reader = recovered.decode_h264_checked(
        selected,
        RtpCustodyDecodeLimits {
            max_steps: 1,
            ..RtpCustodyDecodeLimits::default()
        },
        &dep,
        &cx,
    )?;
    let _ = reader.step(&dep, &cx)?;
    assert!(matches!(
        reader.step(&dep, &cx),
        Err(CheckedRtpDecodeError::Limit)
    ));
    assert_eq!(reader.steps(), 1);
    assert_eq!(reader.stats().frames, 0);
    Ok(())
}

#[test]
fn wrong_mask_resolution_refuses_instead_of_returning_unmasked_native_pixels() -> TestResult {
    let dir = directory("resolution")?;
    let cx = cx()?;
    let mut dep = ReferenceDeployment::open(&dir, "site:retained-resolution", &cx)?;
    let root = publish(&real_dump(false), &mut dep, &cx)?;
    assert_ne!(dimensions()?, [1, 1]);
    mask(&mut dep, [1, 1], &cx)?;
    let recovered = inspect_rtp_import(root, 907, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let mut reader = recovered.decode_h264_checked(
        selection()?,
        RtpCustodyDecodeLimits::default(),
        &dep,
        &cx,
    )?;
    until_queued(&mut reader, &dep, &cx)?;
    assert!(matches!(
        reader.step(&dep, &cx),
        Err(CheckedRtpDecodeError::Native(error))
            if matches!(*error, RetainedRtpDecodeError::Privacy(_))
    ));
    assert_eq!(reader.stats().frames, 0);
    assert_eq!(reader.queued_pictures(), 0);
    Ok(())
}

#[test]
fn root_only_publication_cannot_be_used_as_a_completed_decode_import() -> TestResult {
    let dir = directory("pending")?;
    let cx = cx()?;
    let mut dep = ReferenceDeployment::open(&dir, "site:retained-pending", &cx)?;
    let bytes = real_dump(false);
    let plan = prepare_rtp_import(
        &bytes,
        scope()?,
        config_for(7),
        RtpImportLimits::default(),
        &cx,
    )?;
    for chunk in bytes.chunks(RtpImportLimits::default().chunk_bytes) {
        dep.stage_payload(chunk)?;
    }
    for nal in nals() {
        dep.stage_payload(nal)?;
    }
    for unit in plan.report().access_units() {
        dep.stage_payload(&bytes[unit.source.clone()])?;
        dep.stage_payload(&unit.capsule.try_canonical_bytes()?)?;
    }
    dep.stage_payload(plan.report_bytes())?;
    let root = plan.manifest().root();
    let hex: String = root
        .bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let slot = SlotName::parse(&format!("rtp-{hex}"))?;
    dep.publisher_mut().stage_manifest(&slot, plan.manifest())?;
    dep.publish_and_commit(
        &slot,
        plan.manifest(),
        CaptureInterval::new(TimestampNs(0), scope()?.receive_time)?,
        &cx,
    )?;
    let recovered = inspect_rtp_import(root, 908, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let before = dep.current_anchor().clone();
    assert!(matches!(
        recovered.decode_h264_checked(selection()?, RtpCustodyDecodeLimits::default(), &dep, &cx),
        Err(CheckedRtpDecodeError::Native(error))
            if matches!(*error, RetainedRtpDecodeError::ImportPending)
    ));
    assert_eq!(dep.current_anchor(), &before);
    Ok(())
}

#[test]
fn recovered_decode_retains_refusal_and_skip_history_after_a_successful_flush() -> TestResult {
    let dir = directory("recovered")?;
    let cx = cx()?;
    let mut dep = ReferenceDeployment::open(&dir, "site:retained-recovered", &cx)?;
    let mut packets = packetize(2, 100, 65534, 7, 90000, 0);
    let missing = packets
        .iter()
        .position(|packet| packet.vcl)
        .ok_or("first IDR")?;
    packets.remove(missing);
    let root = publish(&dump_planned(&packets), &mut dep, &cx)?;
    let recovered = inspect_rtp_import(root, 909, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let mut reader = recovered.decode_h264_checked(
        selection()?,
        RtpCustodyDecodeLimits::default(),
        &dep,
        &cx,
    )?;
    for _ in 0..10_000 {
        if matches!(reader.step(&dep, &cx)?, RetainedRtpDecodeStep::Ended(_)) {
            break;
        }
    }
    let summary = reader.stats();
    assert!(summary.ended && summary.input_ended && summary.native_finished);
    assert!(summary.frames > 0);
    assert!(summary.refusals > 0 && summary.skipped_groups > 0);
    assert_eq!(summary.records, packets.len());
    Ok(())
}

#[test]
fn malformed_source_tail_never_becomes_clean_decode_completion() -> TestResult {
    let dir = directory("bad-tail")?;
    let cx = cx()?;
    let mut dep = ReferenceDeployment::open(&dir, "site:retained-tail", &cx)?;
    let mut bytes = real_dump(false);
    bytes.extend_from_slice(&[0, 10, 0]);
    let root = publish(&bytes, &mut dep, &cx)?;
    let recovered = inspect_rtp_import(root, 910, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let mut reader = recovered.decode_h264_checked(
        selection()?,
        RtpCustodyDecodeLimits::default(),
        &dep,
        &cx,
    )?;
    for _ in 0..10_000 {
        if matches!(reader.step(&dep, &cx)?, RetainedRtpDecodeStep::Ended(_)) {
            break;
        }
    }
    let summary = reader.stats();
    assert!(summary.ended);
    assert!(!summary.input_ended && !summary.native_finished);
    assert!(summary.refusals > 0);
    Ok(())
}

#[test]
fn unreadable_deletion_authority_fails_closed_even_with_all_media_bytes_present() -> TestResult {
    use fss_reference::deletion::{commit_deletion, plan_deletion};
    use fss_reference::{FileIngestAdapter, FileIngestRequest};
    let dir = directory("deletion-authority")?;
    let cx = cx()?;
    let mut dep = ReferenceDeployment::open(&dir, "site:retained-deletion", &cx)?;
    // Create genuine deletion authority through its sole permitted owner. Corrupt its
    // retained plan afterwards, without manufacturing a reserved-family ledger row.
    let jpeg = include_bytes!("../../../tests/fixtures/media/jpeg/gray_16x16_flat.jpg");
    let source = dir.join("delete-source.mjpeg");
    std::fs::write(&source, jpeg.repeat(2))?;
    let imported = FileIngestAdapter::ingest(
        FileIngestRequest::new(
            source,
            SensorId::parse("sensor:delete-fixture")?,
            StreamId::parse("stream:delete-fixture")?,
        )
        .with_receive_time(TimestampNs(1_000_000_000)),
        &cx,
        &mut dep,
    )?;
    let plan = plan_deletion(&dep, imported.import_identity, &cx)?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    let plan_digest = plan.digest()?;
    let principal = "operator:rtp-deletion-fixture";
    commit_deletion(
        &mut dep,
        plan_digest,
        plan.approval_digest(principal)?,
        principal,
        &cx,
    )?;
    let root = publish(&real_dump(false), &mut dep, &cx)?;
    let recovered = inspect_rtp_import(root, 911, RtpRecoveryPolicy::default(), &cx, &dep)?;
    std::fs::remove_file(dep.publisher().spool().object_path(plan_digest))?;
    // New source admissions now verify canonical denial before disclosing original bytes.
    assert!(inspect_rtp_import(root, 912, RtpRecoveryPolicy::default(), &cx, &dep).is_err());
    assert!(matches!(
        recovered.decode_h264_checked(selection()?, RtpCustodyDecodeLimits::default(), &dep, &cx),
        Err(CheckedRtpDecodeError::Custody),
    ));
    Ok(())
}

#[test]
fn a_missing_noncurrent_chunk_invalidates_the_complete_recording_dependency_closure() -> TestResult
{
    let dir = directory("reference-closure")?;
    let cx = cx()?;
    let mut dep = ReferenceDeployment::open(&dir, "site:retained-reference-closure", &cx)?;
    let bytes = real_dump(false);
    let plan = prepare_rtp_import(
        &bytes,
        scope()?,
        config_for(7),
        RtpImportLimits {
            chunk_bytes: 512,
            ..RtpImportLimits::default()
        },
        &cx,
    )?;
    let root = publish_rtp_import(plan, &cx, &mut dep)?.root();
    let recovered = inspect_rtp_import(root, 912, RtpRecoveryPolicy::default(), &cx, &dep)?;
    assert!(recovered.report().chunk_digests().len() > 1);
    let mut reader = recovered.decode_h264_checked(
        selection()?,
        RtpCustodyDecodeLimits::default(),
        &dep,
        &cx,
    )?;
    until_queued(&mut reader, &dep, &cx)?;
    let last = *recovered
        .report()
        .chunk_digests()
        .last()
        .ok_or("last chunk")?;
    std::fs::remove_file(dep.publisher().spool().object_path(last))?;
    assert!(matches!(
        reader.step(&dep, &cx),
        Err(CheckedRtpDecodeError::Custody)
    ));
    assert_eq!(reader.stats().frames, 0);
    assert_eq!(reader.queued_pictures(), 0);
    Ok(())
}

#[test]
fn custody_read_allowance_is_cumulative_across_delivered_frames() -> TestResult {
    let dir = directory("cumulative-reads")?;
    let cx = cx()?;
    let mut dep = ReferenceDeployment::open(&dir, "site:retained-cumulative-reads", &cx)?;
    let root = publish(&real_dump(false), &mut dep, &cx)?;
    let recovered = inspect_rtp_import(root, 914, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let mut baseline = recovered.decode_h264_checked(
        selection()?,
        RtpCustodyDecodeLimits::default(),
        &dep,
        &cx,
    )?;
    until_queued(&mut baseline, &dep, &cx)?;
    assert!(matches!(
        baseline.step(&dep, &cx)?,
        RetainedRtpDecodeStep::Frame(_)
    ));
    let one_frame_cost = baseline.read_bytes();
    let object_ceiling = dep.publisher().spool().limits().max_object_bytes;
    let limits = RtpCustodyDecodeLimits {
        max_object_bytes: object_ceiling,
        max_read_bytes: one_frame_cost + object_ceiling as u64,
        ..RtpCustodyDecodeLimits::default()
    };
    drop(baseline);
    let mut reader = recovered.decode_h264_checked(selection()?, limits, &dep, &cx)?;
    until_queued(&mut reader, &dep, &cx)?;
    assert!(matches!(
        reader.step(&dep, &cx)?,
        RetainedRtpDecodeStep::Frame(_)
    ));
    assert_eq!(reader.read_bytes(), one_frame_cost);
    until_queued(&mut reader, &dep, &cx)?;
    assert!(matches!(
        reader.step(&dep, &cx),
        Err(CheckedRtpDecodeError::Limit)
    ));
    assert_eq!(reader.stats().frames, 1);
    assert!(reader.read_bytes() <= limits.max_read_bytes);
    assert!(reader.stats().ended);
    assert_eq!(reader.queued_pictures(), 0);
    Ok(())
}
