#![forbid(unsafe_code)]
#![allow(dead_code)]
//! Actual first-party RTP → native recording/catalog publication, shared with operator tests.

#[path = "../hevc_recording_support/mod.rs"]
mod hevc_recording_support;
#[path = "../recording_support/mod.rs"]
mod recording_support;

use std::fs;
use std::path::{Path, PathBuf};

use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, TimestampNs};
use fss_geometry::WorkBudget;
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel, SlotName};
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchOptions, WatchTrackerConfig, WatchZone,
};
use fss_reference::ingest::rtsp_import::catalog::{
    MAX_FRAMES, MAX_MEDIA_BYTES, MAX_ORIGINAL_BYTES, MAX_WINDOWS, RtspCatalogImportRequest,
};
use fss_reference::ingest::rtsp_import::pages::{RtspCatalogPage, RtspCatalogPagesImportRequest};
use fss_reference::ingest::rtsp_import::{RtspCaptureOrigin, RtspImportCodec, RtspImportRequest};
use fss_reference::ingest::rtsp_selected_watch::{
    RtspSelectedWatchAuthority, RtspSelectedWatchLimits, RtspSelectedWatchPlan,
    RtspSelectedWatchReport, RtspWatchSelection, process_rtsp_selections,
};
use fss_reference::rtsp::recording::PreparedRecording;
use fss_reference::rtsp::recording::local::{RecordingProgress, RecordingPublication};
use fss_reference::rtsp::recording_catalog::local::{CatalogProgress, CatalogPublication};
use fss_reference::rtsp::recording_catalog::{
    CatalogScope, CatalogWindow, RecordingCatalog, prepare_catalog,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

pub type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub const SITE: &str = "site:rtsp-selected-watch";
pub const PRINCIPAL: &str = "principal:rtsp-selected-watch";
pub const WORK: u64 = 2 * 1024 * 1024 * 1024;

pub struct Directory(pub PathBuf);
impl Directory {
    pub fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-rtsp-selected-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("fixture directory bound".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:rtsp-selected-watch".into(),
        operation_id: OperationId::parse("operation:rtsp-selected-watch")?,
        principal: PRINCIPAL.into(),
        capabilities: vec![
            "ADP-REPLAY-001".into(),
            "CAP-READ-MEDIA-001".into(),
            "CAP-OBJECT-STAGE-001".into(),
            "CAP-OBJECT-PUBLISH-001".into(),
            "CAP-RETENTION-COMMIT-001".into(),
        ],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(WORK).build()?,
        privacy_scope: "privacy:fixture".into(),
        retention_scope: "retention:fixture".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}
pub fn archive_limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        32,
        512,
        32,
        512,
        SpoolLimits::new(512, 256 * 1024 * 1024, 32 * 1024 * 1024, 512),
    )
}
pub struct Owner(pub bool);
impl RtspSelectedWatchAuthority for Owner {
    fn permit(&self, _: &RtspSelectedWatchPlan, destination: &ReferenceDeployment) -> bool {
        self.0 && destination.site_lineage() == SITE
    }
}

fn publish_window(
    source: &mut LocalRootPublisher,
    plan: &PreparedRecording,
    name: &str,
) -> Test<SlotName> {
    let slot = SlotName::parse(name)?;
    let mut publication =
        RecordingPublication::new(plan, source, slot.clone(), plan.byte_len(), 100)?;
    for now in 0..5 {
        if matches!(
            publication.step(now, &NeverCancel)?,
            RecordingProgress::Published(_)
        ) {
            return Ok(slot);
        }
    }
    Err("native window publication incomplete".into())
}
fn publish_catalog(
    source: &mut LocalRootPublisher,
    page: &RecordingCatalog,
    name: &str,
) -> Test<RtspCatalogPage> {
    let slot = SlotName::parse(name)?;
    let mut publication =
        CatalogPublication::new(page, source, slot.clone(), page.byte_len(), 100)?;
    for now in 0..page.entries().len() as u64 + 2 {
        if matches!(
            publication.step(now, &NeverCancel)?,
            CatalogProgress::Published(_)
        ) {
            return Ok(RtspCatalogPage {
                slot,
                root: page.manifest().root(),
            });
        }
    }
    Err("native catalog publication incomplete".into())
}
fn origin() -> Option<RtspCaptureOrigin> {
    Some(RtspCaptureOrigin {
        start_ns: TimestampNs(1_000_000_000),
        uncertainty_ns: 10,
    })
}
fn window_request(
    codec: RtspImportCodec,
    slot: SlotName,
    plan: &PreparedRecording,
) -> RtspImportRequest {
    RtspImportRequest {
        codec,
        slot,
        root: plan.manifest().root(),
        source: plan.summary().scope.clone(),
        receive_time: TimestampNs(1_000_000_000_000),
        capture_origin: origin(),
        max_frames: 256,
        max_original_bytes: 32 * 1024 * 1024,
        max_media_bytes: 32 * 1024 * 1024,
    }
}

pub struct Fixture {
    pub directory: Directory,
    pub source: Option<LocalRootPublisher>,
    pub target: Option<ReferenceDeployment>,
    pub cx: ReplayCx,
    pub plan: RtspSelectedWatchPlan,
    pub limits: RtspSelectedWatchLimits,
    pub original: ContentDigest,
}
impl Fixture {
    /// Window AVC, two-window catalog AVC, two whole pages AVC, then independent HEVC window.
    pub fn new(label: &str, per_catalog_window: usize) -> Test<Self> {
        let directory = Directory::new(label)?;
        let mut source = LocalRootPublisher::open(directory.0.join("archive"), archive_limits())?;
        let first = recording_support::repeated(701, 2, 1, 0)?.prepare()?;
        let first_slot = publish_window(&mut source, &first, "selected-window-avc")?;
        let original = ContentDigest::sha256(first.objects().source);
        let mut selections = vec![RtspWatchSelection::Window(window_request(
            RtspImportCodec::Avc,
            first_slot,
            &first,
        ))];

        let a = recording_support::repeated(702, per_catalog_window, 2000, 0)?.prepare_at(0)?;
        let start = per_catalog_window as u64 * 3600;
        let b = recording_support::repeated(703, per_catalog_window, 4000, start as u32)?
            .prepare_at(start)?;
        let a_slot = publish_window(&mut source, &a, "selected-catalog-window-a")?;
        let b_slot = publish_window(&mut source, &b, "selected-catalog-window-b")?;
        let scope = CatalogScope {
            recording: a.summary().scope.clone(),
            decode_clock: ContentDigest::sha256(b"selected-catalog-decode-clock"),
            time_scale: 90_000,
        };
        let catalog = prepare_catalog(
            scope.clone(),
            &[
                CatalogWindow {
                    slot: &a_slot,
                    recording: &a,
                },
                CatalogWindow {
                    slot: &b_slot,
                    recording: &b,
                },
            ],
        )?;
        let catalog_pin = publish_catalog(&mut source, &catalog, "selected-catalog")?;
        let catalog_request = RtspCatalogImportRequest {
            codec: RtspImportCodec::Avc,
            slot: catalog_pin.slot,
            root: catalog_pin.root,
            scope,
            receive_time: TimestampNs(1_000_000_000_000),
            capture_origin: origin(),
            max_windows: MAX_WINDOWS,
            max_frames: MAX_FRAMES,
            max_original_bytes: MAX_ORIGINAL_BYTES,
            max_media_bytes: MAX_MEDIA_BYTES,
        };
        selections.push(RtspWatchSelection::Catalog(catalog_request));

        let c = recording_support::repeated(704, 3, 6000, 0)?.prepare_at(0)?;
        let d = recording_support::repeated(705, 3, 8000, 10_800)?.prepare_at(10_800)?;
        let c_slot = publish_window(&mut source, &c, "selected-page-window-a")?;
        let d_slot = publish_window(&mut source, &d, "selected-page-window-b")?;
        let scope = CatalogScope {
            recording: c.summary().scope.clone(),
            decode_clock: ContentDigest::sha256(b"selected-pages-decode-clock"),
            time_scale: 90_000,
        };
        let page_a = prepare_catalog(
            scope.clone(),
            &[CatalogWindow {
                slot: &c_slot,
                recording: &c,
            }],
        )?;
        let page_b = prepare_catalog(
            scope.clone(),
            &[CatalogWindow {
                slot: &d_slot,
                recording: &d,
            }],
        )?;
        let page_a = publish_catalog(&mut source, &page_a, "selected-page-a")?;
        let page_b = publish_catalog(&mut source, &page_b, "selected-page-b")?;
        selections.push(RtspWatchSelection::Pages(RtspCatalogPagesImportRequest {
            codec: RtspImportCodec::Avc,
            pages: vec![page_a, page_b],
            scope,
            receive_time: TimestampNs(1_000_000_000_000),
            capture_origin: origin(),
            max_pages: 2,
            max_windows: MAX_WINDOWS,
            max_frames: MAX_FRAMES,
            max_original_bytes: MAX_ORIGINAL_BYTES,
            max_media_bytes: MAX_MEDIA_BYTES,
        }));

        let hevc = hevc_recording_support::fixture()?;
        let hevc = hevc.publication_plan();
        let hevc_slot = publish_window(&mut source, hevc, "selected-window-hevc")?;
        selections.push(RtspWatchSelection::Window(window_request(
            RtspImportCodec::Hevc,
            hevc_slot,
            hevc,
        )));
        let root = directory.0.join("destination");
        let cx = context(&root)?;
        let target = ReferenceDeployment::open(&root, SITE, &cx)?;
        let plan = RtspSelectedWatchPlan {
            selections,
            interpretation: ComponentInterpretation::YCbCr,
            zones: vec![WatchZone {
                zone_id: "fixture-zone".into(),
                x: 1,
                y: 1,
                width: 12,
                height: 12,
            }],
            detector: WatchDetectorConfig::default(),
            tracker: WatchTrackerConfig::default(),
            options: WatchOptions::default(),
            screened: false,
        };
        Ok(Self {
            directory,
            source: Some(source),
            target: Some(target),
            cx,
            plan,
            limits: RtspSelectedWatchLimits::default(),
            original,
        })
    }
    pub fn target(&self) -> &ReferenceDeployment {
        self.target.as_ref().expect("fixture target")
    }
    pub fn run(&mut self) -> Test<RtspSelectedWatchReport> {
        Ok(process_rtsp_selections(
            self.source.as_ref().ok_or("source closed")?,
            self.target.as_mut().ok_or("target closed")?,
            &self.plan,
            &self.limits,
            &Owner(true),
            &self.cx,
            &mut WorkBudget::new(WORK),
        )?)
    }
}
