#![forbid(unsafe_code)]
//! Cold source custody to native, privacy-projected pixels without import rewrites.
mod rtpdump_support;
use fss_codec_h264::{Decoder, DecoderLimits, Picture};
use fss_core::{CanonicalEncode, CaptureInterval, ContentDigest, SensorId, StreamId, TimestampNs};
use fss_publication::SlotName;
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::rtpdump::decode::{RtpDecodeEffect, RtpDecodeLimits};
use fss_reference::ingest::rtpdump::import::*;
use fss_reference::ingest::rtpdump::recovery::decode::*;
use fss_reference::ingest::rtpdump::recovery::*;
use fss_reference::{ReferenceDeployment, ReplayCx};
use rtpdump_support::*;

fn directory(label: &str) -> Result<std::path::PathBuf, Error> {
    let base = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(base)?;
    for attempt in 0..1000 {
        let path = base.join(format!(
            "rtp-retained-{label}-{}-{attempt}",
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
fn scope() -> Result<RtpImportScope, Error> {
    Ok(RtpImportScope {
        sensor: SensorId::parse("sensor:retained-rtp")?,
        stream: StreamId::parse("stream:retained-rtp")?,
        receive_time: TimestampNs(1_000_000_000),
    })
}
fn publish(
    bytes: &[u8],
    dep: &mut ReferenceDeployment,
    cx: &ReplayCx,
) -> Result<ContentDigest, Error> {
    let plan = prepare_rtp_import(
        bytes,
        scope()?,
        config_for(7),
        RtpImportLimits::default(),
        cx,
    )?;
    Ok(publish_rtp_import(plan, cx, dep)?.root())
}
fn recover(
    root: ContentDigest,
    dep: &ReferenceDeployment,
    cx: &ReplayCx,
) -> Result<RecoveredRtpImport, Error> {
    Ok(inspect_rtp_import(
        root,
        999,
        RtpRecoveryPolicy::default(),
        cx,
        dep,
    )?)
}
fn request(
    retained: &RecoveredRtpImport,
    cx: &ReplayCx,
) -> Result<RetainedRtpDecodeRequest, Error> {
    let candidates = retained.h264_parameters(cx)?;
    let pair = candidates.unique_pair().ok_or("ambiguous parameters")?;
    Ok(RetainedRtpDecodeRequest::new(pair))
}
fn native() -> Result<Vec<Picture>, Error> {
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
fn mask_all(dep: &mut ReferenceDeployment, cx: &ReplayCx) -> Result<ContentDigest, Error> {
    let frames = native()?;
    let dimensions = [frames[0].width(), frames[0].height()];
    let policy = PrivacyMaskPolicy::new(
        scope()?.sensor,
        dimensions,
        &[[0, 0, dimensions[0], dimensions[1]]],
    )?;
    let approval = preview_mask(dep, &policy)?.approval;
    Ok(declare_mask(dep, &policy, approval, cx)?.policy_digest)
}
fn collect(
    decoder: &mut RetainedRtpH264Decoder<'_>,
    dep: &ReferenceDeployment,
    cx: &ReplayCx,
) -> Result<(Vec<RetainedRtpH264Frame>, RetainedRtpDecodeStats), Error> {
    let mut frames = Vec::new();
    for _ in 0..20_000 {
        match decoder.step(dep, cx)? {
            RetainedRtpDecodeStep::Frame(frame) => frames.push(frame),
            RetainedRtpDecodeStep::Ended(stats) => return Ok((frames, stats)),
            RetainedRtpDecodeStep::Progress { .. } => {}
        }
    }
    Err("decode did not terminate within its fixture step bound".into())
}
fn wait_for_queue(
    decoder: &mut RetainedRtpH264Decoder<'_>,
    dep: &ReferenceDeployment,
    cx: &ReplayCx,
) -> TestResult {
    for _ in 0..20_000 {
        let _ = decoder.step(dep, cx)?;
        if decoder.queued_pictures() > 0 {
            return Ok(());
        }
    }
    Err("fixture never queued native output".into())
}

#[test]
fn cold_completed_root_decodes_exact_native_pixels_without_originals_or_authority_writes()
-> TestResult {
    for fragmented in [false, true] {
        let dir = directory(if fragmented { "cold-fu" } else { "cold-single" })?;
        let cx = cx()?;
        let mut dep = ReferenceDeployment::open(&dir, "site:retained-rtp", &cx)?;
        let root = publish(&real_dump(fragmented), &mut dep, &cx)?;
        drop(dep);
        // No source path or in-memory import receipt survives this reopen.
        let dep = ReferenceDeployment::reopen(&dir, "site:retained-rtp", &cx)?;
        let before = dep.current_anchor().clone();
        let objects = dep.publisher().spool().object_count();
        let retained = recover(root, &dep, &cx)?;
        let mut decoder = retained.decode_h264(request(&retained, &cx)?, &dep, &cx)?;
        let (frames, stats) = collect(&mut decoder, &dep, &cx)?;
        assert!(stats.complete());
        assert_eq!(stats.records, retained.report().records().len());
        assert_eq!(stats.frames, 4);
        for (actual, expected) in frames.iter().zip(native()?) {
            assert_eq!(actual.root(), root);
            assert_eq!(actual.sensor(), &scope()?.sensor);
            assert_eq!(actual.stream(), &scope()?.stream);
            assert_eq!(
                actual.capture(),
                CaptureInterval::new(TimestampNs(0), scope()?.receive_time)?
            );
            assert_eq!(actual.source().key.ingress, 999);
            assert_eq!(actual.source().key.generation, 1);
            assert_eq!(actual.source().recording, retained.report().input_digest());
            assert_eq!(actual.mask().policy_digest(), None);
            assert_eq!(actual.pixels(), expected.luma());
            assert_eq!(actual.cb(), expected.cb());
            assert_eq!(actual.cr(), expected.cr());
        }
        assert_eq!(dep.current_anchor(), &before);
        assert_eq!(dep.publisher().spool().object_count(), objects);
        assert!(matches!(decoder.step(&dep, &cx)?, RetainedRtpDecodeStep::Ended(s) if s == stats));
    }
    Ok(())
}

#[test]
fn every_served_plane_uses_the_restored_sensors_current_mask() -> TestResult {
    let dir = directory("masked")?;
    let cx = cx()?;
    let mut dep = ReferenceDeployment::open(&dir, "site:retained-rtp", &cx)?;
    let root = publish(&real_dump(true), &mut dep, &cx)?;
    let policy = mask_all(&mut dep, &cx)?;
    drop(dep);
    let dep = ReferenceDeployment::reopen(&dir, "site:retained-rtp", &cx)?;
    let before = dep.current_anchor().clone();
    let retained = recover(root, &dep, &cx)?;
    let mut decoder = retained.decode_h264(request(&retained, &cx)?, &dep, &cx)?;
    let (frames, stats) = collect(&mut decoder, &dep, &cx)?;
    assert!(stats.complete());
    assert_eq!(frames.len(), 4);
    for frame in frames {
        assert_eq!(frame.mask().policy_digest(), Some(policy));
        assert!(frame.pixels().iter().all(|v| *v == 16));
        assert!(frame.cb().iter().all(|v| *v == 128));
        assert!(frame.cr().iter().all(|v| *v == 128));
    }
    assert_eq!(dep.current_anchor(), &before);
    Ok(())
}

#[test]
fn privacy_change_fences_queued_pixels_and_fresh_inspection_uses_the_new_policy() -> TestResult {
    let dir = directory("privacy-drift")?;
    let cx = cx()?;
    let mut dep = ReferenceDeployment::open(&dir, "site:retained-rtp", &cx)?;
    let root = publish(&real_dump(false), &mut dep, &cx)?;
    let retained = recover(root, &dep, &cx)?;
    let mut decoder = retained.decode_h264(request(&retained, &cx)?, &dep, &cx)?;
    wait_for_queue(&mut decoder, &dep, &cx)?;
    let served = decoder.stats().frames;
    let policy = mask_all(&mut dep, &cx)?;
    assert!(matches!(
        decoder.step(&dep, &cx),
        Err(RetainedRtpDecodeError::Source(_))
    ));
    assert_eq!(decoder.queued_pictures(), 0);
    assert_eq!(decoder.stats().frames, served);
    assert!(!decoder.stats().complete());
    assert!(matches!(
        decoder.step(&dep, &cx)?,
        RetainedRtpDecodeStep::Ended(_)
    ));
    assert!(matches!(
        retained.decode_h264(request(&retained, &cx)?, &dep, &cx),
        Err(RetainedRtpDecodeError::Source(_))
    ));
    let fresh = recover(root, &dep, &cx)?;
    let mut decoder = fresh.decode_h264(request(&fresh, &cx)?, &dep, &cx)?;
    let (frames, stats) = collect(&mut decoder, &dep, &cx)?;
    assert!(stats.complete());
    assert!(
        frames.iter().all(
            |f| f.mask().policy_digest() == Some(policy) && f.pixels().iter().all(|v| *v == 16)
        )
    );
    Ok(())
}

#[test]
fn unselected_or_swapped_parameters_cannot_be_substituted_from_loose_objects() -> TestResult {
    let dir = directory("parameters")?;
    let cx = cx()?;
    let mut dep = ReferenceDeployment::open(&dir, "site:retained-rtp", &cx)?;
    let root = publish(&real_dump(false), &mut dep, &cx)?;
    let loose = dep.stage_payload(b"not part of the selected source graph")?;
    let retained = recover(root, &dep, &cx)?;
    let base = request(&retained, &cx)?;
    let before = dep.current_anchor().clone();
    for parameters in [
        [loose, base.parameters[1]],
        [base.parameters[1], base.parameters[0]],
    ] {
        assert!(matches!(
            retained.decode_h264(RetainedRtpDecodeRequest { parameters, ..base }, &dep, &cx),
            Err(RetainedRtpDecodeError::ParametersUnavailable)
        ));
    }
    assert_eq!(dep.current_anchor(), &before);
    Ok(())
}

#[test]
fn output_limit_keeps_source_accounting_but_never_reports_complete_or_serves_pixels() -> TestResult
{
    let dir = directory("output-limit")?;
    let cx = cx()?;
    let mut dep = ReferenceDeployment::open(&dir, "site:retained-rtp", &cx)?;
    let root = publish(&real_dump(false), &mut dep, &cx)?;
    let retained = recover(root, &dep, &cx)?;
    let mut req = request(&retained, &cx)?;
    req.decode = RtpDecodeLimits {
        max_output_bytes: 1,
        ..req.decode
    };
    let mut decoder = retained.decode_h264(req, &dep, &cx)?;
    let (frames, stats) = collect(&mut decoder, &dep, &cx)?;
    assert!(frames.is_empty());
    assert!(stats.refusals > 0);
    assert!(!stats.complete());
    assert_eq!(stats.records, retained.report().records().len());
    Ok(())
}

#[test]
fn cancellation_retires_queued_raw_output_without_disclosing_it() -> TestResult {
    let dir = directory("cancel")?;
    let cx = cx()?;
    let mut dep = ReferenceDeployment::open(&dir, "site:retained-rtp", &cx)?;
    let root = publish(&real_dump(false), &mut dep, &cx)?;
    let retained = recover(root, &dep, &cx)?;
    let mut decoder = retained.decode_h264(request(&retained, &cx)?, &dep, &cx)?;
    wait_for_queue(&mut decoder, &dep, &cx)?;
    let served = decoder.stats().frames;
    cx.request_cancellation();
    assert!(matches!(
        decoder.step(&dep, &cx),
        Err(RetainedRtpDecodeError::Cancelled)
    ));
    assert_eq!(decoder.queued_pictures(), 0);
    assert_eq!(decoder.stats().frames, served);
    assert!(!decoder.stats().complete());
    assert!(cx.is_drain_completed());
    Ok(())
}

#[test]
fn malformed_retained_tail_remains_incomplete_even_when_valid_prefix_pixels_exist() -> TestResult {
    let dir = directory("bad-tail")?;
    let cx = cx()?;
    let mut dep = ReferenceDeployment::open(&dir, "site:retained-rtp", &cx)?;
    let mut bytes = real_dump(false);
    bytes.extend_from_slice(&[0, 10, 0]);
    let root = publish(&bytes, &mut dep, &cx)?;
    let retained = recover(root, &dep, &cx)?;
    let mut decoder = retained.decode_h264(request(&retained, &cx)?, &dep, &cx)?;
    let (frames, stats) = collect(&mut decoder, &dep, &cx)?;
    assert!(!frames.is_empty());
    assert!(stats.refusals > 0);
    assert!(!stats.input_ended);
    assert!(!stats.complete());
    Ok(())
}

#[test]
fn root_only_publication_cannot_implicitly_finish_import_or_start_pixel_decode() -> TestResult {
    let dir = directory("pending")?;
    let cx = cx()?;
    let bytes = real_dump(false);
    let mut dep = ReferenceDeployment::open(&dir, "site:retained-rtp", &cx)?;
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
    let hex: String = root.bytes().iter().map(|b| format!("{b:02x}")).collect();
    let slot = SlotName::parse(&format!("rtp-{hex}"))?;
    dep.publisher_mut().stage_manifest(&slot, plan.manifest())?;
    dep.publish_and_commit(
        &slot,
        plan.manifest(),
        CaptureInterval::new(TimestampNs(0), scope()?.receive_time)?,
        &cx,
    )?;
    let before = dep.current_anchor().clone();
    let retained = recover(root, &dep, &cx)?;
    assert!(matches!(
        retained.state(),
        RtpRecoveryState::LedgerPending { .. }
    ));
    assert!(matches!(
        retained.decode_h264(request(&retained, &cx)?, &dep, &cx),
        Err(RetainedRtpDecodeError::ImportPending)
    ));
    assert_eq!(dep.current_anchor(), &before);
    Ok(())
}

#[test]
fn fresh_decode_refuses_damaged_current_privacy_custody_instead_of_using_no_policy() -> TestResult {
    use std::io::Write;
    let dir = directory("damaged-mask")?;
    let cx = cx()?;
    let mut dep = ReferenceDeployment::open(&dir, "site:retained-rtp", &cx)?;
    let root = publish(&real_dump(false), &mut dep, &cx)?;
    let policy = mask_all(&mut dep, &cx)?;
    let retained = recover(root, &dep, &cx)?;
    let path = dep.publisher().spool().object_path(policy);
    let mut file = std::fs::OpenOptions::new().append(true).open(path)?;
    file.write_all(&[0xff])?;
    file.sync_all()?;
    assert!(matches!(
        retained.decode_h264(request(&retained, &cx)?, &dep, &cx),
        Err(RetainedRtpDecodeError::Privacy(_))
    ));
    Ok(())
}

#[test]
fn recovered_pixels_do_not_erase_prior_refusals_from_terminal_statistics() -> TestResult {
    let dir = directory("recovery")?;
    let cx = cx()?;
    let mut dep = ReferenceDeployment::open(&dir, "site:retained-rtp", &cx)?;
    let mut planned = packetize(2, 100, 65534, 7, 90000, 0);
    let missing = planned.iter().position(|p| p.vcl).ok_or("IDR packet")?;
    planned.remove(missing);
    let root = publish(&dump_planned(&planned), &mut dep, &cx)?;
    let retained = recover(root, &dep, &cx)?;
    let mut decoder = retained.decode_h264(request(&retained, &cx)?, &dep, &cx)?;
    let mut recovered = false;
    let mut ended = false;
    for _ in 0..20_000 {
        match decoder.step(&dep, &cx)? {
            RetainedRtpDecodeStep::Progress {
                effect:
                    RtpDecodeEffect::Refused {
                        awaiting_idr: true, ..
                    },
                ..
            } => recovered = true,
            RetainedRtpDecodeStep::Frame(frame) => {
                assert!(recovered);
                assert!(frame.source().decoder_epoch > 0);
            }
            RetainedRtpDecodeStep::Ended(stats) => {
                assert!(stats.frames > 0 && stats.refusals > 0 && stats.skipped_groups > 0);
                assert!(!stats.complete());
                assert_eq!(stats.records, planned.len());
                ended = true;
                break;
            }
            _ => {}
        }
    }
    assert!(ended && recovered);
    Ok(())
}
