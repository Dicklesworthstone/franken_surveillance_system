#![forbid(unsafe_code)]
#![allow(dead_code)]
//! Real loopback, native import/inference and durable storage fixture adapters.
use crate::http_rgb_recording_support::{Authority, Server};
use crate::rgb_evidence_support as fixture;
use crate::rgb_zone_support::{Test, WORK};
use fss_codec_mjpeg::DecodeBudget;
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_publication::{LocalRootPublisher, NeverCancel};
use fss_reference::ingest::http_archive::HttpArchiveLimits;
use fss_reference::ingest::http_rgb_evidence::*;
use fss_reference::ingest::http_rgb_recording::HttpRgbRecordingStep;
use fss_reference::ingest::http_camera::rgb::{HttpRgbBudgets, HttpRgbReceipt, HttpRgbStep};
use fss_reference::ingest::model_import::{ImportBudget, ImportLimits, WeightFloatPolicy};
use fss_reference::ingest::model_import::rgb::{ImportedRgbModel, RgbModelImportRequest};
use fss_reference::ingest::privacy_mask::live::SensorMask;
use fss_reference::ingest::rgb_archive::*;
use fss_reference::ingest::rgb_detections::*;
use fss_reference::ingest::rgb_evidence::*;
use fss_reference::ingest::rgb_inference::{RgbInferenceModel, RgbModelSpec};
use fss_reference::preprocess::{ResizeAspect, ResizeFilter};
use fss_reference::{ChannelTransform, PreprocessProgram, ReplayCx, ScalarExecCx};
use fss_twin::image_tracking::TrackingAvailability;
use std::cell::Cell;
use std::collections::BTreeMap;

pub struct Budgets {
    pub copy: RgbEvidenceBudget,
    pub work: WorkBudget<'static>,
    pub import: ImportBudget,
    pub decoder: DecodeBudget<'static>,
    pub head: RgbDetectionBudget,
    pub temporal: WorkBudget<'static>,
    pub linking: WorkBudget<'static>,
}
impl Budgets {
    pub fn new() -> Self {
        Self {
            copy: RgbEvidenceBudget::new(WORK), work: WorkBudget::new(100_000_000_000),
            import: ImportBudget::new(WORK), decoder: DecodeBudget::new(WORK),
            head: RgbDetectionBudget::new(WORK, 32 * 1024 * 1024),
            temporal: WorkBudget::new(WORK), linking: WorkBudget::new(WORK),
        }
    }
}
pub fn imported<'a>(graph: &'a [u8], weights: &'a [u8], cx: &ReplayCx, b: &mut Budgets) -> Test<ImportedRgbModel<'a>> {
    let request = RgbModelImportRequest {
        graph, graph_digest: ContentDigest::sha256(graph),
        weights, weights_digest: ContentDigest::sha256(weights),
        spec: RgbModelSpec {
            image_input: "image".into(),
            preprocess: PreprocessProgram::new(8, 8, ChannelTransform::Rgb, true),
            filter: ResizeFilter::Bilinear, aspect: ResizeAspect::Letterbox(114), masked_rgb: [0; 3],
        },
        float_policy: WeightFloatPolicy::F32Only, bindings: BTreeMap::new(),
    };
    Ok(ImportedRgbModel::build(&request, ImportLimits::default(), &mut b.import, cx, &ScalarExecCx::new())?)
}
pub fn head(model: &RgbInferenceModel) -> Test<RgbDetectionContract> {
    Ok(RgbDetectionContract::new(RgbDetectionSpec {
        model: model.digest(), output_port: "head".into(), labels: vec!["numeric-red".into(), "numeric-green".into()],
        layout: HeadLayout::Channels, boxes: HeadBoxes::PixelCorners, class_score: HeadScore::Probability,
        objectness: None, classes: HeadClasses::Best, minimum_score_ppm: 500_000,
        nms_iou_ppm: 500_000, maximum_rows: 8, maximum_candidates: 8, maximum_detections: 8,
    })?)
}
pub fn limits() -> HttpRgbEvidenceLimits {
    HttpRgbEvidenceLimits {
        source: HttpArchiveLimits {
            maximum_reads: 128, maximum_bytes: 65536,
            maximum_scan_roots: 1024, maximum_spool_object_bytes: 65536,
        },
        archive: RgbArchiveLimits::default(),
    }
}
pub fn retention() -> ContentDigest { ContentDigest::sha256(b"explicit original/model custody test authority") }
pub struct ArchiveAuthority { pub reads: Cell<bool>, pub writes: Cell<bool> }
impl ArchiveAuthority {
    pub fn new() -> Self { Self { reads: Cell::new(true), writes: Cell::new(true) } }
    pub fn access<'a>(&'a self, camera: &'a Authority) -> HttpRgbEvidenceAccess<'a> {
        HttpRgbEvidenceAccess { source: camera.access(&NeverCancel), archive: self }
    }
}
impl RgbArchiveAuthority for ArchiveAuthority {
    fn permits(&self, operation: RgbArchiveOperation, scope: ContentDigest, _: ContentDigest) -> bool {
        scope == retention() && match operation {
            RgbArchiveOperation::RetainOriginals => self.writes.get(),
            RgbArchiveOperation::ReadOriginals => self.reads.get(),
        }
    }
}
pub fn next(
    r: &mut HttpRgbEvidenceRecording<'_, '_>, publisher: &mut LocalRootPublisher,
    a: &Authority, server: &mut Server,
) -> Test<HttpRgbRecordingStep> {
    for _ in 0..50000 {
        server.poll()?;
        match r.poll(a.access(&NeverCancel))? {
            HttpRgbRecordingStep::Advanced | HttpRgbRecordingStep::Pending => std::thread::yield_now(),
            HttpRgbRecordingStep::WirePrepared(plan) => { r.commit_wire(plan, publisher, a.access(&NeverCancel))?.acknowledgement()?; }
            barrier => return Ok(barrier),
        }
    }
    Err("bounded loopback recording did not reach a barrier".into())
}
pub fn analyze(
    r: &mut HttpRgbEvidenceRecording<'_, '_>, publisher: &LocalRootPublisher,
    a: &Authority, n: u8, privacy: SensorMask<'_>, b: &mut Budgets,
) -> Test<HttpRgbReceipt> {
    let context = crate::http_rgb_support::context(r.recording().capture(), &[1; 512], n, TrackingAvailability::Available, privacy)?;
    match r.analyze(context, fixture::limits().run, publisher, a.access(&NeverCancel), HttpRgbBudgets {
        decoder: &mut b.decoder, projection: &mut b.head, temporal: &mut b.temporal, linking: &mut b.linking,
    }, &ScalarExecCx::new())? {
        HttpRgbStep::ResultReady(receipt) => Ok(receipt),
        _ => Err("native numerical fixture failed to complete".into()),
    }
}
pub fn evidence(
    r: &HttpRgbEvidenceRecording<'_, '_>, imported: &ImportedRgbModel<'_>, head: &RgbDetectionContract,
    privacy: SensorMask<'_>, b: &mut Budgets, cx: &ReplayCx,
) -> Test<(RgbEvidence, ReplayedRgbEvidence)> {
    let c = r.recording().capture();
    let evidence = RgbEvidence::capture(
        imported, head, c.frame().ok_or("held source missing")?.part().bytes(),
        c.completed().ok_or("held native output missing")?.detection_run(),
        r.accepted_admission().ok_or("accepted admission missing")?,
        RgbEvidenceLimits::default(), &mut b.copy, cx,
    )?;
    let replay = evidence.replay(privacy, fixture::limits(), &mut b.copy, &mut b.import, &mut b.decoder, &mut b.head, cx, &ScalarExecCx::new())?;
    Ok((evidence, replay))
}
