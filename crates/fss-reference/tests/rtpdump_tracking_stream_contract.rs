#![forbid(unsafe_code)]
//! Real retained H.264 and the checked-in neural package; no caller-injected tracks.
mod rtpdump_support;

use std::io::{self, Cursor, Read, Write};
use std::path::PathBuf;

use fss_core::{ContentDigest, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::ingest::rtpdump::detect::RtpDetectionRequest;
use fss_reference::ingest::rtpdump::import::{
    RtpImportLimits, RtpImportScope, prepare_rtp_import, publish_rtp_import,
};
use fss_reference::ingest::rtpdump::recovery::decode::RetainedRtpDecodeRequest;
use fss_reference::ingest::rtpdump::recovery::{
    RecoveredRtpImport, RtpRecoveryPolicy, inspect_rtp_import,
};
use fss_reference::ingest::rtpdump::track::{RtpTrackingLimits, RtpTrackingRequest};
use fss_reference::ingest::rtpdump::track_stream::*;
use fss_reference::ingest::tracker::TrackerConfig;
use fss_reference::{ReferenceDeployment, ReplayCx, ScalarExecCx};
use rtpdump_support::*;

const PACKAGE: &[u8] = include_bytes!("../../../models/yolox-nano/yolox_nano.fmpk");
const PACKAGE_SHA: &str = "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";
const SITE: &str = "site:rtp-trajectory-stream";
const SENSOR: &str = "sensor:rtp-trajectory-stream";

struct Fixture {
    dep: ReferenceDeployment,
    root: ContentDigest,
    package: RgbDetectorPackage,
    cx: ReplayCx,
    scalar: ScalarExecCx,
    dir: PathBuf,
}
impl Fixture {
    fn new(label: &str, bytes: &[u8]) -> Result<Self, Error> {
        let base = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
        std::fs::create_dir_all(base)?;
        for attempt in 0..1000 {
            let dir = base.join(format!(
                "rtp-track-stream-{label}-{}-{attempt}",
                std::process::id()
            ));
            match std::fs::create_dir(&dir) {
                Ok(()) => {
                    let cx = cx()?;
                    let scalar = ScalarExecCx::new();
                    let mut dep = ReferenceDeployment::open(&dir, SITE, &cx)?;
                    let plan = prepare_rtp_import(
                        bytes,
                        RtpImportScope {
                            sensor: SensorId::parse(SENSOR)?,
                            stream: StreamId::parse("stream:rtp-trajectory-stream")?,
                            receive_time: TimestampNs(1_000_000_000),
                        },
                        config_for(7),
                        RtpImportLimits::default(),
                        &cx,
                    )?;
                    let root = publish_rtp_import(plan, &cx, &mut dep)?.root();
                    drop(dep);
                    let dep = ReferenceDeployment::reopen(&dir, SITE, &cx)?;
                    let package = RgbDetectorPackage::load(
                        PACKAGE,
                        PACKAGE_SHA.parse()?,
                        1 << 40,
                        &cx,
                        &scalar,
                    )?;
                    return Ok(Self {
                        dep,
                        root,
                        package,
                        cx,
                        scalar,
                        dir,
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("fixture directory reservation exhausted".into())
    }
    fn retained(&self, ingress: u128) -> Result<RecoveredRtpImport, Error> {
        Ok(inspect_rtp_import(
            self.root,
            ingress,
            RtpRecoveryPolicy::default(),
            &self.cx,
            &self.dep,
        )?)
    }
    fn request(&self, retained: &RecoveredRtpImport) -> Result<RtpTrackStreamRequest, Error> {
        let parameters = retained
            .h264_parameters(&self.cx)?
            .unique_pair()
            .ok_or("parameters")?;
        Ok(RtpTrackStreamRequest::new(RtpTrackingRequest {
            detection: RtpDetectionRequest::new(RetainedRtpDecodeRequest::new(parameters)),
            class_index: 0,
            tracker: TrackerConfig {
                min_hits: 2,
                max_misses: 2,
                iou_threshold: 0.1,
                process_noise: 1.0,
                measurement_noise: 1.0,
            },
            limits: RtpTrackingLimits::default(),
        }))
    }
    fn write(
        &self,
        r: &RecoveredRtpImport,
        request: RtpTrackStreamRequest,
        writer: &mut impl Write,
    ) -> Result<RtpTrackStreamSummary, RtpTrackStreamError> {
        write_tracking_stream(
            r,
            &self.package,
            request,
            writer,
            &self.dep,
            &self.cx,
            &self.scalar,
        )
    }
    fn verify(
        &self,
        r: &RecoveredRtpImport,
        request: RtpTrackStreamRequest,
        saved: &mut impl Read,
        digest: ContentDigest,
    ) -> Result<RtpTrackStreamSummary, RtpTrackStreamError> {
        verify_tracking_stream(
            r,
            &self.package,
            request,
            saved,
            digest,
            &self.dep,
            &self.cx,
            &self.scalar,
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn cold_native_transcript_reproduces_every_byte_without_source_writes() -> TestResult {
    let f = Fixture::new("cold", &real_dump(true))?;
    let retained = f.retained(11)?;
    let request = f.request(&retained)?;
    let anchor = f.dep.current_anchor().clone();
    let mut saved = Vec::new();
    let summary = f.write(&retained, request.clone(), &mut saved)?;
    assert_eq!(summary.stats.frames, 4);
    assert!(summary.stats.complete());
    assert_eq!(summary.digest, ContentDigest::sha256(&saved));
    assert_eq!(summary.bytes, saved.len() as u64);
    assert!(summary.records > summary.stats.frames as u64 + 2);
    assert!(summary.stats.detection.execution_macs > 0);
    assert!(summary.stats.detection.receipt_bytes > 0);
    // Ingress belongs to this read operation, never the durable transcript identity.
    let cold = f.retained(999)?;
    let mut replay = Cursor::new(&saved);
    let checked = f.verify(&cold, request, &mut replay, summary.digest)?;
    assert_eq!(checked.digest, summary.digest);
    assert_eq!(checked.last_frame, summary.last_frame);
    assert_eq!(checked.native_recipe, summary.native_recipe);
    assert_eq!(checked.observations, summary.observations);
    assert_eq!(replay.position(), saved.len() as u64);
    assert_eq!(f.dep.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn recomputed_attacker_hash_cannot_bless_modified_truncated_or_extended_results() -> TestResult {
    let f = Fixture::new("tamper", &real_dump(false))?;
    let r = f.retained(1)?;
    let req = f.request(&r)?;
    let mut original = Vec::new();
    f.write(&r, req.clone(), &mut original)?;
    let mut modified = original.clone();
    let middle = modified.len() / 2;
    modified[middle] ^= 1;
    let mut trailing = original.clone();
    trailing.push(0);
    let mut malformed_length = original.clone();
    malformed_length[8..16].fill(255);
    for bytes in [
        modified,
        trailing,
        malformed_length,
        original[..original.len() - 1].to_vec(),
    ] {
        let expected = ContentDigest::sha256(&bytes);
        assert!(matches!(
            f.verify(&r, req.clone(), &mut Cursor::new(bytes), expected),
            Err(RtpTrackStreamError::Mismatch)
        ));
    }
    Ok(())
}

#[test]
fn independent_digest_and_exact_requested_admissions_are_both_required() -> TestResult {
    let f = Fixture::new("recipe", &real_dump(false))?;
    let r = f.retained(1)?;
    let req = f.request(&r)?;
    let mut bytes = Vec::new();
    let summary = f.write(&r, req.clone(), &mut bytes)?;
    assert!(matches!(
        f.verify(
            &r,
            req.clone(),
            &mut Cursor::new(&bytes),
            ContentDigest::sha256(b"wrong")
        ),
        Err(RtpTrackStreamError::Mismatch)
    ));
    let mut changes = Vec::new();
    let mut class = req.clone();
    class.tracking.class_index = 1;
    changes.push(class);
    let mut numerical = req.clone();
    numerical.tracking.tracker.min_hits += 1;
    changes.push(numerical);
    let mut budget = req.clone();
    budget.tracking.detection.analysis.max_execution_macs += 1;
    changes.push(budget);
    let mut output = req.clone();
    output.max_stream_bytes += 1;
    changes.push(output);
    let mut completion = req;
    completion.completion = RtpTrackStreamCompletion::SourceDiagnostics;
    changes.push(completion);
    for changed in changes {
        assert!(matches!(
            f.verify(&r, changed, &mut Cursor::new(&bytes), summary.digest),
            Err(RtpTrackStreamError::Mismatch)
        ));
    }
    Ok(())
}

#[test]
fn source_gaps_need_explicit_diagnostic_policy_and_remain_incomplete_after_verification()
-> TestResult {
    let mut packets = packetize(2, 100, 65534, 7, 90000, 0);
    let missing = packets.iter().position(|packet| packet.vcl).ok_or("IDR")?;
    packets.remove(missing);
    let f = Fixture::new("gap", &dump_planned(&packets))?;
    let r = f.retained(1)?;
    let mut req = f.request(&r)?;
    assert!(matches!(
        f.write(&r, req.clone(), &mut Vec::new()),
        Err(RtpTrackStreamError::Incomplete(_))
    ));
    req.completion = RtpTrackStreamCompletion::SourceDiagnostics;
    let mut saved = Vec::new();
    let summary = f.write(&r, req.clone(), &mut saved)?;
    assert!(summary.stats.frames > 0);
    assert!(summary.stats.detection.native.refusals > 0);
    assert!(!summary.stats.complete());
    let checked = f.verify(&r, req, &mut Cursor::new(&saved), summary.digest)?;
    assert!(!checked.stats.complete());
    assert_eq!(
        checked.stats.detection.native,
        summary.stats.detection.native
    );
    Ok(())
}

#[test]
fn independent_output_record_and_frame_bounds_never_certify_a_prefix() -> TestResult {
    let f = Fixture::new("bounds", &real_dump(false))?;
    let r = f.retained(1)?;
    let req = f.request(&r)?;
    let mut limits = Vec::new();
    let mut bytes = req.clone();
    bytes.max_stream_bytes = 1;
    limits.push(bytes);
    let mut records = req.clone();
    records.max_records = 3;
    limits.push(records);
    let mut frame = req;
    frame.max_frame_bytes = 1;
    limits.push(frame);
    for limited in limits {
        let mut saved = Vec::new();
        assert!(matches!(
            f.write(&r, limited, &mut saved),
            Err(RtpTrackStreamError::Limit)
        ));
    }
    Ok(())
}

#[test]
fn diagnostics_do_not_waive_inference_or_tracking_allowances() -> TestResult {
    let f = Fixture::new("analysis-limit", &real_dump(true))?;
    let r = f.retained(1)?;
    for detector in [false, true] {
        let mut request = f.request(&r)?;
        request.completion = RtpTrackStreamCompletion::SourceDiagnostics;
        if detector {
            request.tracking.detection.analysis.max_frames = 1;
        } else {
            request.tracking.limits.max_frames = 1;
        }
        assert!(matches!(
            f.write(&r, request, &mut Vec::new()),
            Err(RtpTrackStreamError::Tracking(_))
        ));
    }
    Ok(())
}

#[test]
fn wrong_source_custody_fails_even_with_saved_verified_bytes() -> TestResult {
    let f = Fixture::new("custody", &real_dump(false))?;
    let r = f.retained(1)?;
    let req = f.request(&r)?;
    let mut saved = Vec::new();
    let summary = f.write(&r, req.clone(), &mut saved)?;
    let chunk = *r.report().chunk_digests().first().ok_or("source chunk")?;
    std::fs::remove_file(f.dep.publisher().spool().object_path(chunk))?;
    assert!(matches!(
        f.verify(&r, req, &mut Cursor::new(&saved), summary.digest),
        Err(RtpTrackStreamError::Tracking(_))
    ));
    Ok(())
}

#[test]
fn fresh_privacy_cannot_reproduce_an_old_unmasked_transcript() -> TestResult {
    let mut f = Fixture::new("privacy", &real_dump(false))?;
    let r = f.retained(1)?;
    let req = f.request(&r)?;
    let mut saved = Vec::new();
    let summary = f.write(&r, req.clone(), &mut saved)?;
    // Exercise a valid changed privacy projection, not a geometry admission failure.
    // Derive the actual grid from native source decoding; do not bake fixture dimensions in.
    let dimensions = {
        let mut decoder = r.decode_h264(req.tracking.detection.decode, &f.dep, &f.cx)?;
        let mut dimensions = None;
        for _ in 0..20_000 {
            match decoder.step(&f.dep, &f.cx)? {
                fss_reference::ingest::rtpdump::recovery::decode::RetainedRtpDecodeStep::Frame(
                    frame,
                ) => {
                    dimensions = Some(frame.dimensions());
                    break;
                }
                fss_reference::ingest::rtpdump::recovery::decode::RetainedRtpDecodeStep::Ended(
                    _,
                ) => break,
                _ => {}
            }
        }
        dimensions.ok_or("native privacy-test dimensions missing")?
    };
    let mask = PrivacyMaskPolicy::new(
        SensorId::parse(SENSOR)?,
        dimensions,
        &[[0, 0, dimensions[0], dimensions[1]]],
    )?;
    let approval = preview_mask(&f.dep, &mask)?.approval;
    declare_mask(&mut f.dep, &mask, approval, &f.cx)?;
    assert!(
        f.verify(&r, req.clone(), &mut Cursor::new(&saved), summary.digest)
            .is_err()
    );
    let current = f.retained(2)?;
    assert!(matches!(
        f.verify(&current, req, &mut Cursor::new(&saved), summary.digest),
        Err(RtpTrackStreamError::Mismatch)
    ));
    Ok(())
}

#[test]
fn incompatible_privacy_grid_remains_a_native_refusal_not_a_replay_match() -> TestResult {
    let mut f = Fixture::new("privacy-grid", &real_dump(false))?;
    let retained = f.retained(1)?;
    let request = f.request(&retained)?;
    let mut saved = Vec::new();
    let summary = f.write(&retained, request.clone(), &mut saved)?;
    let mask = PrivacyMaskPolicy::new(SensorId::parse(SENSOR)?, [1, 1], &[[0, 0, 1, 1]])?;
    let approval = preview_mask(&f.dep, &mask)?.approval;
    declare_mask(&mut f.dep, &mask, approval, &f.cx)?;
    let current = f.retained(2)?;
    // A policy that cannot project onto the source grid is not a valid alternative replay.
    // Keep that failure typed; never coerce it to Mismatch merely to satisfy the old test.
    assert!(matches!(
        f.verify(&current, request, &mut Cursor::new(&saved), summary.digest),
        Err(RtpTrackStreamError::Tracking(_))
    ));
    Ok(())
}

#[test]
fn sink_failure_stops_before_the_first_neural_attempt() -> TestResult {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let f = Fixture::new("sink", &real_dump(false))?;
    let r = f.retained(1)?;
    let req = f.request(&r)?;
    f.cx.set_cancel_at_checkpoint("rtp_detect:inference");
    assert!(matches!(
        f.write(&r, req, &mut Broken),
        Err(RtpTrackStreamError::Io(io::ErrorKind::BrokenPipe))
    ));
    assert!(!f.cx.is_cancelled());
    Ok(())
}

#[test]
fn cancellation_during_delivery_drains_both_owners_and_stops_the_sink() -> TestResult {
    struct CancelSink<'a> {
        scalar: &'a ScalarExecCx,
        calls: usize,
    }
    impl Write for CancelSink<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            self.scalar.request_cancellation();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let f = Fixture::new("cancel", &real_dump(false))?;
    let r = f.retained(1)?;
    let req = f.request(&r)?;
    let mut sink = CancelSink {
        scalar: &f.scalar,
        calls: 0,
    };
    assert!(matches!(
        f.write(&r, req, &mut sink),
        Err(RtpTrackStreamError::Cancelled)
    ));
    assert_eq!(sink.calls, 1);
    assert!(f.cx.is_drain_completed() && f.scalar.is_drain_completed());
    Ok(())
}

#[test]
fn interruption_retries_are_bounded_and_short_io_reproduces_exactly() -> TestResult {
    struct Interrupted {
        calls: usize,
    }
    impl Write for Interrupted {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            Err(io::ErrorKind::Interrupted.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    struct Short<T>(T);
    impl<T: Write> Write for Short<T> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.write(&bytes[..bytes.len().min(7)])
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }
    impl<T: Read> Read for Short<T> {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            let length = bytes.len().min(3);
            self.0.read(&mut bytes[..length])
        }
    }
    let f = Fixture::new("io", &real_dump(false))?;
    let r = f.retained(1)?;
    let req = f.request(&r)?;
    let mut interrupted = Interrupted { calls: 0 };
    assert!(matches!(
        f.write(&r, req.clone(), &mut interrupted),
        Err(RtpTrackStreamError::Io(io::ErrorKind::Interrupted))
    ));
    assert_eq!(interrupted.calls, 8);
    let mut short = Short(Vec::new());
    let summary = f.write(&r, req.clone(), &mut short)?;
    assert_eq!(summary.digest, ContentDigest::sha256(&short.0));
    let checked = f.verify(&r, req, &mut Short(Cursor::new(&short.0)), summary.digest)?;
    assert_eq!(checked.digest, summary.digest);
    Ok(())
}

#[test]
fn invalid_stream_admission_precedes_source_readback() -> TestResult {
    let f = Fixture::new("invalid", &real_dump(false))?;
    let r = f.retained(1)?;
    let mut req = f.request(&r)?;
    req.max_records = 0;
    let chunk = *r.report().chunk_digests().first().ok_or("source chunk")?;
    std::fs::remove_file(f.dep.publisher().spool().object_path(chunk))?;
    let mut saved = Vec::new();
    assert!(matches!(
        f.write(&r, req, &mut saved),
        Err(RtpTrackStreamError::Limit)
    ));
    assert!(saved.is_empty());
    Ok(())
}
