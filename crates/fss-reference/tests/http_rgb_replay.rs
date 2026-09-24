#![forbid(unsafe_code)]
//! Actual cold source replay through native JPEG/convolution/detection/zone engines.
#[allow(dead_code)]
mod http_rgb_support;
mod rgb_zone_support;
use fixture::{Test, WORK};
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget};
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_object::SpoolLimits;
use fss_publication::{
    LocalPublicationLimits, LocalRootPublisher, NeverCancel, PublishCancellation, PublishCutPoint,
};
use fss_reference::ScalarExecCx;
use fss_reference::ingest::http_archive::*;
use fss_reference::ingest::http_camera::HttpCameraStep;
use fss_reference::ingest::http_camera::rgb::custody::HttpRgbCustody;
use fss_reference::ingest::http_camera::rgb::{
    HttpRgbBudgets, HttpRgbContext, HttpRgbReceipt, HttpRgbStep, http_rgb_exposure,
};
use fss_reference::ingest::http_replay::rgb::*;
use fss_reference::ingest::http_replay::*;
use fss_reference::ingest::rgb_detections::{RgbDetectionBudget, RgbDetectionContract};
use fss_reference::ingest::rgb_inference::RgbInferenceModel;
use fss_reference::ingest::rgb_tracking::pipeline::{RgbJpegZonePipeline, RgbZonePhase};
use fss_reference::ingest::rgb_tracking::{RgbFrameAdmission, RgbZoneTracker};
use fss_twin::image_tracking::TrackingAvailability;
use http_rgb_support as live;
use rgb_zone_support as fixture;
use std::cell::Cell;
use std::path::PathBuf;

const STORAGE_WORK: u64 = 100_000_000_000;
const MASK: [u8; 512] = [1; 512];
struct Directory(PathBuf);
impl Directory {
    fn new() -> Test<Self> {
        for attempt in 0..64 {
            let path = std::env::temp_dir()
                .join(format!("fss-rgb-replay-{}-{attempt}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("fixture directory attempts exhausted".into())
    }
    fn open(&self) -> Test<LocalRootPublisher> {
        Ok(LocalRootPublisher::open(
            &self.0,
            LocalPublicationLimits::new(
                512,
                16,
                128,
                4096,
                SpoolLimits::new(4096, 16 * 1024 * 1024, 65536, 4096),
            ),
        )?)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn work() -> WorkBudget<'static> {
    WorkBudget::new(STORAGE_WORK)
}
fn framing() -> DecodeBudget<'static> {
    DecodeBudget::new(WORK)
}
fn limits() -> HttpArchiveLimits {
    HttpArchiveLimits {
        maximum_reads: 256,
        maximum_bytes: 1024 * 1024,
        maximum_scan_roots: 1024,
        maximum_spool_object_bytes: 65536,
    }
}
fn access<'a, 'cx>(
    p: &'a LocalRootPublisher,
    cancel: &'a dyn PublishCancellation,
    work: &'a mut WorkBudget<'cx>,
    framing: &'a mut DecodeBudget<'cx>,
) -> HttpReplayAccess<'a, 'cx> {
    HttpReplayAccess {
        publisher: p,
        cancellation: cancel,
        work,
        framing,
    }
}
fn acquire(
    p: &mut LocalRootPublisher,
    chunked: bool,
) -> Test<(HttpWireScope, HttpWirePin, Vec<HttpRgbReceipt>)> {
    let model = fixture::model(1)?;
    let head = fixture::head(&model)?;
    let mut owner = fixture::tracker(&head, fixture::tracking_policy())?;
    let (mut capture, auth, mut server) = live::session(
        &model,
        &head,
        &mut owner,
        live::response(&[fixture::jpeg(16), fixture::jpeg(240)], chunked),
        257,
    )?;
    let scope = HttpWireScope {
        stream: capture.camera().route().basis(),
        receive_clock: [21; 32],
        retention_evidence: [22; 32],
    };
    let mut archive = HttpWireArchive::new(scope, limits())?;
    let mut original = Vec::new();
    let mut framing = framing();
    let mut work = work();
    for _ in 0..50000 {
        match live::pump(&mut capture, &auth, &mut server, &mut framing)? {
            HttpRgbStep::Source(HttpCameraStep::WireReady(_)) => {
                let plan = capture.prepare_wire_custody(&archive, live::NOW, &auth, &mut work)?;
                let commit = capture.retain_wire(
                    plan,
                    live::NOW,
                    &auth,
                    HttpRgbCustody {
                        archive: &mut archive,
                        publisher: p,
                        cancellation: &NeverCancel,
                        work: &mut work,
                    },
                )?;
                commit.acknowledgement()?;
            }
            HttpRgbStep::AwaitingContext => {
                let receipt = live::complete(&mut capture, &auth, original.len() as u8 + 1)?;
                let output = capture.take_result(receipt, live::NOW, &auth)?;
                if original.len() == 1 {
                    assert!(!output.analysis().temporal().events().is_empty());
                }
                original.push(receipt);
            }
            HttpRgbStep::Source(HttpCameraStep::Complete) => {
                return Ok((scope, archive.pin(), original));
            }
            HttpRgbStep::Source(HttpCameraStep::Advanced | HttpCameraStep::Pending) => {
                std::thread::yield_now()
            }
            _ => return Err("unexpected live source phase".into()),
        }
    }
    Err("live capture step bound".into())
}
fn restored(
    p: &LocalRootPublisher,
    scope: HttpWireScope,
    pin: HttpWirePin,
) -> Test<HttpWireArchive> {
    Ok(HttpWireArchive::load(
        p,
        scope,
        pin,
        limits(),
        &NeverCancel,
        &mut work(),
    )?)
}
fn attach<'a, 'm, 't>(
    a: &'a HttpWireArchive,
    model: &'m RgbInferenceModel,
    head: &'m RgbDetectionContract,
    owner: &'t mut RgbZoneTracker,
    read_bytes: usize,
) -> Test<HttpRgbReplay<'a, 'm, 't>> {
    let source = HttpWireReplay::new(
        a,
        a.pin(),
        HttpReplayLimits {
            read_bytes,
            ..HttpReplayLimits::default()
        },
    )?;
    let processor = RgbJpegZonePipeline::new(model, head, owner)?;
    HttpRgbReplay::attach(source, processor)
        .map_err(|_| "fresh RGB replay attachment refused".into())
}
fn next(r: &mut HttpRgbReplay<'_, '_, '_>, p: &LocalRootPublisher) -> Test<HttpRgbReplayStep> {
    Ok(r.step(access(p, &NeverCancel, &mut work(), &mut framing()))?)
}
fn to_frame(r: &mut HttpRgbReplay<'_, '_, '_>, p: &LocalRootPublisher) -> Test {
    for _ in 0..50000 {
        match next(r, p)? {
            HttpRgbReplayStep::AwaitingContext => return Ok(()),
            HttpRgbReplayStep::Source(
                HttpReplayStep::PrefixVerified
                | HttpReplayStep::WireLoaded { .. }
                | HttpReplayStep::Advanced,
            ) => {}
            _ => return Err("unexpected replay phase before frame".into()),
        }
    }
    Err("replay step bound".into())
}
fn context(r: &HttpRgbReplay<'_, '_, '_>, n: u8) -> Test<HttpRgbContext<'static>> {
    let f = r.source().pending_frame().ok_or("missing original frame")?;
    let mut source = fixture::source(f.part().bytes(), &MASK, n);
    source.exposure = http_rgb_exposure(f, &mut work())?;
    Ok(HttpRgbContext {
        expected_head: f.head(),
        ordinal: f.part().receipt().ordinal,
        interpretation: ComponentInterpretation::YCbCr,
        allowed: &MASK,
        admission: RgbFrameAdmission::new(
            source,
            TrackingAvailability::Available,
            ContentDigest::sha256(b"independent test capture and availability"),
        )?,
    })
}
fn analyze(
    r: &mut HttpRgbReplay<'_, '_, '_>,
    context: HttpRgbContext<'_>,
    p: &LocalRootPublisher,
    cancel: &dyn PublishCancellation,
    projection: &mut RgbDetectionBudget,
) -> Result<HttpRgbReplayStep, HttpRgbReplayError> {
    r.analyze(
        context,
        fixture::limits(),
        access(p, cancel, &mut work(), &mut framing()),
        HttpRgbBudgets {
            decoder: &mut framing(),
            projection,
            temporal: &mut work(),
            linking: &mut work(),
        },
        &ScalarExecCx::new(),
    )
}
fn complete(
    r: &mut HttpRgbReplay<'_, '_, '_>,
    p: &LocalRootPublisher,
    n: u8,
) -> Test<HttpRgbReplayReceipt> {
    let context = context(r, n)?;
    match analyze(r, context, p, &NeverCancel, &mut fixture::post())? {
        HttpRgbReplayStep::ResultReady(receipt) => Ok(*receipt),
        _ => Err("RGB replay incomplete".into()),
    }
}
fn same(replayed: HttpRgbReplayReceipt, original: HttpRgbReceipt) {
    assert_eq!(replayed.exposure(), original.exposure());
    assert_eq!(replayed.ordinal(), original.ordinal());
    assert_eq!(replayed.encoded_sha256(), original.encoded_sha256());
    assert_eq!(replayed.inference(), original.inference());
    assert_eq!(replayed.detections(), original.detections());
    assert_eq!(replayed.tracking(), original.tracking());
    assert_eq!(replayed.zones(), original.zones());
}
#[test]
fn cold_originals_reproduce_actual_neural_tracking_and_zone_results() -> Test {
    for chunked in [false, true] {
        let d = Directory::new()?;
        let mut p = d.open()?;
        let (scope, pin, original) = acquire(&mut p, chunked)?;
        assert_eq!(original.len(), 2);
        drop(p); // All original source, model, detector and temporal owners are gone.
        let p = d.open()?;
        let a = restored(&p, scope, pin)?;
        for read_bytes in [17, 65536] {
            let model = fixture::model(1)?;
            let head = fixture::head(&model)?;
            let mut owner = fixture::tracker(&head, fixture::tracking_policy())?;
            let mut replay = attach(&a, &model, &head, &mut owner, read_bytes)?;
            for (i, native) in original.iter().enumerate() {
                to_frame(&mut replay, &p)?;
                let before = replay.source().position();
                let receipt = complete(&mut replay, &p, i as u8 + 1)?;
                same(receipt, *native);
                assert_eq!(receipt.pin(), pin);
                for _ in 0..3 {
                    assert_eq!(
                        next(&mut replay, &p)?,
                        HttpRgbReplayStep::ResultReady(Box::new(receipt))
                    );
                }
                assert_eq!(replay.source().position(), before);
                let output = replay.take_result(
                    receipt,
                    access(&p, &NeverCancel, &mut work(), &mut framing()),
                )?;
                assert_eq!(output.receipt(), receipt);
                assert_eq!(
                    ContentDigest::sha256(output.frame().part().bytes()).bytes(),
                    native.encoded_sha256()
                );
                if i == 1 {
                    assert!(!output.analysis().temporal().events().is_empty());
                }
                assert_eq!(replay.last_taken(), Some(receipt));
                assert!(replay.analysis().is_none());
            }
            let mut done = false;
            for _ in 0..50000 {
                match next(&mut replay, &p)? {
                    HttpRgbReplayStep::Source(HttpReplayStep::Complete) => {
                        done = true;
                        break;
                    }
                    HttpRgbReplayStep::Source(
                        HttpReplayStep::Advanced | HttpReplayStep::WireLoaded { .. },
                    ) => {}
                    _ => return Err("unexpected final replay classification".into()),
                }
            }
            assert!(done);
            assert_eq!(replay.source().position().transferred_frames, 2);
        }
    }
    Ok(())
}
#[test]
fn mismatched_context_and_mask_leave_original_frame_correctable() -> Test {
    let d = Directory::new()?;
    let mut p = d.open()?;
    let (scope, pin, _) = acquire(&mut p, false)?;
    let a = restored(&p, scope, pin)?;
    let model = fixture::model(1)?;
    let head = fixture::head(&model)?;
    let mut owner = fixture::tracker(&head, fixture::tracking_policy())?;
    let mut r = attach(&a, &model, &head, &mut owner, 65536)?;
    to_frame(&mut r, &p)?;
    let good = context(&r, 1)?;
    let before = r.source().position();
    let bad = HttpRgbContext {
        ordinal: good.ordinal + 1,
        ..good
    };
    assert_eq!(
        analyze(&mut r, bad, &p, &NeverCancel, &mut fixture::post()),
        Err(HttpRgbReplayError::FrameMismatch)
    );
    let mut changed = good.admission.source();
    changed.exposure = [88; 32];
    let bad = HttpRgbContext {
        admission: fixture::admission(changed, TrackingAvailability::Available)?,
        ..good
    };
    assert_eq!(
        analyze(&mut r, bad, &p, &NeverCancel, &mut fixture::post()),
        Err(HttpRgbReplayError::FrameMismatch)
    );
    let bad = HttpRgbContext {
        allowed: &[0; 512],
        ..good
    };
    assert!(matches!(
        analyze(&mut r, bad, &p, &NeverCancel, &mut fixture::post())?,
        HttpRgbReplayStep::AnalysisRefused(RgbZonePhase::Ready)
    ));
    assert!(r.analysis().is_none());
    assert_eq!(r.source().position(), before);
    assert!(matches!(
        analyze(&mut r, good, &p, &NeverCancel, &mut fixture::post())?,
        HttpRgbReplayStep::ResultReady(_)
    ));
    Ok(())
}
#[test]
fn accepted_projection_resumes_without_redecoding_or_replacing_context() -> Test {
    let d = Directory::new()?;
    let mut p = d.open()?;
    let (scope, pin, native) = acquire(&mut p, false)?;
    let a = restored(&p, scope, pin)?;
    let model = fixture::model(1)?;
    let head = fixture::head(&model)?;
    let mut owner = fixture::tracker(&head, fixture::tracking_policy())?;
    let mut r = attach(&a, &model, &head, &mut owner, 65536)?;
    to_frame(&mut r, &p)?;
    let input = context(&r, 1)?;
    assert!(matches!(
        analyze(
            &mut r,
            input,
            &p,
            &NeverCancel,
            &mut RgbDetectionBudget::new(0, 32 * 1024 * 1024)
        )?,
        HttpRgbReplayStep::AnalysisPending(RgbZonePhase::Projection)
    ));
    assert!(
        r.analysis()
            .ok_or("accepted analysis lost")?
            .pending_inference()
            .is_some()
    );
    assert_eq!(
        analyze(&mut r, input, &p, &NeverCancel, &mut fixture::post()),
        Err(HttpRgbReplayError::AlreadyAccepted)
    );
    let step = r.resume(
        access(&p, &NeverCancel, &mut work(), &mut DecodeBudget::new(0)),
        &mut fixture::post(),
        &mut work(),
        &ScalarExecCx::new(),
    )?;
    let HttpRgbReplayStep::ResultReady(receipt) = step else {
        return Err("projection resume incomplete".into());
    };
    same(*receipt, native[0]);
    assert_eq!(r.source().position().transferred_frames, 0);
    Ok(())
}
struct Stop;
impl PublishCancellation for Stop {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        true
    }
}
#[test]
fn disclosure_denial_and_storage_budget_refuse_before_neural_acceptance() -> Test {
    let d = Directory::new()?;
    let mut p = d.open()?;
    let (scope, pin, _) = acquire(&mut p, false)?;
    let a = restored(&p, scope, pin)?;
    let model = fixture::model(1)?;
    let head = fixture::head(&model)?;
    let mut owner = fixture::tracker(&head, fixture::tracking_policy())?;
    let mut r = attach(&a, &model, &head, &mut owner, 65536)?;
    to_frame(&mut r, &p)?;
    let input = context(&r, 1)?;
    let before = r.source().position();
    assert_eq!(
        analyze(&mut r, input, &p, &Stop, &mut fixture::post()),
        Err(HttpRgbReplayError::Source(HttpReplayError::Cancelled))
    );
    let refused = r.analyze(
        input,
        fixture::limits(),
        access(&p, &NeverCancel, &mut WorkBudget::new(0), &mut framing()),
        HttpRgbBudgets {
            decoder: &mut framing(),
            projection: &mut fixture::post(),
            temporal: &mut work(),
            linking: &mut work(),
        },
        &ScalarExecCx::new(),
    );
    assert!(matches!(
        refused,
        Err(HttpRgbReplayError::Source(HttpReplayError::Archive(_)))
    ));
    assert!(r.analysis().is_none());
    assert!(r.processing_result().is_none());
    assert_eq!(r.source().position(), before);
    assert_eq!(r.phase(), RgbZonePhase::Ready);
    Ok(())
}
#[test]
fn corrupt_originals_cannot_release_or_discard_completed_native_analysis() -> Test {
    let d = Directory::new()?;
    let mut p = d.open()?;
    let (scope, pin, _) = acquire(&mut p, false)?;
    let a = restored(&p, scope, pin)?;
    let model = fixture::model(1)?;
    let head = fixture::head(&model)?;
    let mut owner = fixture::tracker(&head, fixture::tracking_policy())?;
    let mut r = attach(&a, &model, &head, &mut owner, 65536)?;
    to_frame(&mut r, &p)?;
    let receipt = complete(&mut r, &p, 1)?;
    let span = r
        .source()
        .pending_frame()
        .ok_or("original missing")?
        .source_spans()[0];
    let (_, raw) = a
        .reads()
        .find(|(_, raw)| raw.range[0] <= span.wire_range[0] && raw.range[1] > span.wire_range[0])
        .ok_or("source run missing")?;
    let name: String = raw.sha256.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(
        p.root_dir().join("spool/objects").join(name),
        b"corrupt source",
    )?;
    assert!(matches!(
        r.take_result(
            receipt,
            access(&p, &NeverCancel, &mut work(), &mut framing())
        ),
        Err(HttpRgbReplayError::Source(HttpReplayError::Archive(_)))
    ));
    assert_eq!(r.phase(), RgbZonePhase::Complete);
    assert_eq!(r.completion(), Some(receipt));
    assert!(r.completed().is_some());
    assert_eq!(r.source().position().transferred_frames, 0);
    let retired = r.retire();
    assert!(retired.source.frame.is_some());
    assert!(retired.held.is_some());
    assert!(retired.processor.complete.is_none());
    assert_eq!(retired.complete, Some(receipt));
    Ok(())
}
struct Probe {
    seen: Cell<usize>,
    stop: Option<usize>,
}
impl PublishCancellation for Probe {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        let n = self.seen.get() + 1;
        self.seen.set(n);
        self.stop == Some(n)
    }
}
#[test]
fn late_analysis_cancellation_preserves_success_without_reexecuting_it() -> Test {
    let d = Directory::new()?;
    let mut p = d.open()?;
    let (scope, pin, native) = acquire(&mut p, false)?;
    let a = restored(&p, scope, pin)?;
    let model = fixture::model(1)?;
    let head = fixture::head(&model)?;
    let calls = {
        let mut owner = fixture::tracker(&head, fixture::tracking_policy())?;
        let mut r = attach(&a, &model, &head, &mut owner, 65536)?;
        to_frame(&mut r, &p)?;
        let probe = Probe {
            seen: Cell::new(0),
            stop: None,
        };
        let input = context(&r, 1)?;
        assert!(matches!(
            analyze(&mut r, input, &p, &probe, &mut fixture::post())?,
            HttpRgbReplayStep::ResultReady(_)
        ));
        probe.seen.get()
    };
    let mut owner = fixture::tracker(&head, fixture::tracking_policy())?;
    let mut r = attach(&a, &model, &head, &mut owner, 65536)?;
    to_frame(&mut r, &p)?;
    let probe = Probe {
        seen: Cell::new(0),
        stop: Some(calls),
    };
    let input = context(&r, 1)?;
    assert_eq!(
        analyze(&mut r, input, &p, &probe, &mut fixture::post()),
        Err(HttpRgbReplayError::Source(HttpReplayError::Cancelled))
    );
    let receipt = r.completion().ok_or("late refusal lost complete result")?;
    same(receipt, native[0]);
    assert!(r.processing_result().ok_or("native success lost")?.is_ok());
    assert_eq!(
        r.resume(
            access(&p, &NeverCancel, &mut work(), &mut framing()),
            &mut RgbDetectionBudget::new(0, 0),
            &mut WorkBudget::new(0),
            &ScalarExecCx::new()
        )?,
        HttpRgbReplayStep::ResultReady(Box::new(receipt))
    );
    r.take_result(
        receipt,
        access(&p, &NeverCancel, &mut work(), &mut framing()),
    )?;
    assert_eq!(r.source().position().transferred_frames, 1);
    Ok(())
}
#[test]
fn prior_result_key_cannot_release_a_later_complete_source() -> Test {
    let d = Directory::new()?;
    let mut p = d.open()?;
    let (scope, pin, _) = acquire(&mut p, false)?;
    let a = restored(&p, scope, pin)?;
    let model = fixture::model(1)?;
    let head = fixture::head(&model)?;
    let mut owner = fixture::tracker(&head, fixture::tracking_policy())?;
    let mut r = attach(&a, &model, &head, &mut owner, 65536)?;
    to_frame(&mut r, &p)?;
    let old = complete(&mut r, &p, 1)?;
    r.take_result(old, access(&p, &NeverCancel, &mut work(), &mut framing()))?;
    to_frame(&mut r, &p)?;
    let current = complete(&mut r, &p, 2)?;
    assert!(matches!(
        r.take_result(old, access(&p, &NeverCancel, &mut work(), &mut framing())),
        Err(HttpRgbReplayError::ReceiptMismatch)
    ));
    assert_eq!(r.completion(), Some(current));
    assert_eq!(r.source().position().transferred_frames, 1);
    r.take_result(
        current,
        access(&p, &NeverCancel, &mut work(), &mut framing()),
    )?;
    assert_eq!(r.source().position().transferred_frames, 2);
    Ok(())
}
#[test]
fn rejected_attachment_returns_advanced_source_without_losing_original_bytes() -> Test {
    let d = Directory::new()?;
    let mut p = d.open()?;
    let (scope, pin, _) = acquire(&mut p, false)?;
    let a = restored(&p, scope, pin)?;
    let model = fixture::model(1)?;
    let head = fixture::head(&model)?;
    let mut owner = fixture::tracker(&head, fixture::tracking_policy())?;
    let mut source = HttpWireReplay::new(&a, pin, HttpReplayLimits::default())?;
    assert_eq!(
        source.step(access(&p, &NeverCancel, &mut work(), &mut framing()))?,
        HttpReplayStep::PrefixVerified
    );
    assert!(matches!(
        source.step(access(&p, &NeverCancel, &mut work(), &mut framing()))?,
        HttpReplayStep::WireLoaded { .. }
    ));
    let position = source.position();
    let processor = RgbJpegZonePipeline::new(&model, &head, &mut owner)?;
    let rejected = match HttpRgbReplay::attach(source, processor) {
        Ok(_) => return Err("advanced source attachment unexpectedly accepted".into()),
        Err(owners) => owners,
    };
    assert_eq!(rejected.source.position(), position);
    assert!(
        !rejected
            .source
            .pending_wire()
            .ok_or("rejected attachment lost originals")?
            .bytes
            .is_empty()
    );
    assert_eq!(rejected.processor.phase(), RgbZonePhase::Ready);
    Ok(())
}
#[test]
fn deleted_originals_block_pending_stage_resumption_without_erasing_tensors() -> Test {
    let d = Directory::new()?;
    let mut p = d.open()?;
    let (scope, pin, _) = acquire(&mut p, false)?;
    let a = restored(&p, scope, pin)?;
    let model = fixture::model(1)?;
    let head = fixture::head(&model)?;
    let mut owner = fixture::tracker(&head, fixture::tracking_policy())?;
    let mut r = attach(&a, &model, &head, &mut owner, 65536)?;
    to_frame(&mut r, &p)?;
    let input = context(&r, 1)?;
    assert!(matches!(
        analyze(
            &mut r,
            input,
            &p,
            &NeverCancel,
            &mut RgbDetectionBudget::new(0, 32 * 1024 * 1024)
        )?,
        HttpRgbReplayStep::AnalysisPending(RgbZonePhase::Projection)
    ));
    let span = r
        .source()
        .pending_frame()
        .ok_or("original missing")?
        .source_spans()[0];
    let (_, raw) = a
        .reads()
        .find(|(_, raw)| raw.range[0] <= span.wire_range[0] && raw.range[1] > span.wire_range[0])
        .ok_or("source run missing")?;
    let name: String = raw.sha256.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::remove_file(p.root_dir().join("spool/objects").join(name))?;
    assert!(matches!(
        r.resume(
            access(&p, &NeverCancel, &mut work(), &mut framing()),
            &mut fixture::post(),
            &mut work(),
            &ScalarExecCx::new()
        ),
        Err(HttpRgbReplayError::Source(HttpReplayError::Archive(_)))
    ));
    assert_eq!(r.phase(), RgbZonePhase::Projection);
    assert_eq!(r.source().position().transferred_frames, 0);
    let retired = r.retire();
    assert!(retired.processor.inference.is_some());
    assert!(retired.source.frame.is_some());
    assert!(retired.complete.is_none());
    Ok(())
}
