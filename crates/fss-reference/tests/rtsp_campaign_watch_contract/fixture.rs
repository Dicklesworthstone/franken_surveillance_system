#![forbid(unsafe_code)]
#![allow(dead_code)]
//! Actual AVC pages and HEVC catalogs in independent archives, with native durable history.

#[path = "../hevc_recording_support/mod.rs"]
mod hevc;
#[path = "../rtsp_selected_watch_contract/fixture.rs"]
mod selected;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec, TimestampNs,
};
use fss_geometry::WorkBudget;
use fss_publication::{LocalRootPublisher, NeverCancel, SlotName};
use fss_reference::ingest::rtsp_campaign_watch::*;
use fss_reference::ingest::rtsp_import::catalog::{
    MAX_FRAMES, MAX_MEDIA_BYTES, MAX_ORIGINAL_BYTES, MAX_WINDOWS, RtspCatalogImportRequest,
};
use fss_reference::ingest::rtsp_import::{RtspCaptureOrigin, RtspImportCodec};
use fss_reference::ingest::rtsp_selected_watch::RtspWatchSelection;
use fss_reference::rtsp::archive_pins::ArchivePinAnchor;
use fss_reference::rtsp::campaign_history::*;
use fss_reference::rtsp::recording::hevc::prepare_hevc_recording;
use fss_reference::rtsp::recording::local::{RecordingProgress, RecordingPublication};
use fss_reference::rtsp::recording_archive::{ArchiveNamespace, hevc::HevcArchiveNamespace};
use fss_reference::rtsp::recording_catalog::CatalogScope;
use fss_reference::rtsp::recording_catalog::hevc::local::HevcCatalogPublication;
use fss_reference::rtsp::recording_catalog::hevc::{HevcCatalogWindow, prepare_hevc_catalog};
use fss_reference::rtsp::recording_catalog::local::CatalogProgress;
use fss_reference::{ReferenceDeployment, ReplayCx};

pub use selected::{Directory, PRINCIPAL, SITE, Test, archive_limits};
pub const WORK: u64 = 20_000_000_000;

pub fn digest(text: &str) -> ContentDigest {
    ContentDigest::sha256(text.as_bytes())
}
pub fn context(root: &Path, read_only: bool) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:rtsp-campaign-watch".into(),
        operation_id: OperationId::parse("operation:rtsp-campaign-watch")?,
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
        privacy_scope: "privacy:campaign-watch-fixture".into(),
        retention_scope: "retention:campaign-watch-fixture".into(),
        anchor_universe: digest(SITE),
        generation: 1,
    })?;
    Ok(if read_only {
        ReplayCx::from_context_authority_read_only(&authority, root.to_path_buf())?
    } else {
        ReplayCx::from_context_authority(&authority, root.to_path_buf())?
    })
}

pub struct Fault {
    pub after_sequence: u64,
    pub path: PathBuf,
    pub bytes: Option<Vec<u8>>,
}
pub struct Owner {
    pub campaign: CampaignPlan,
    pub enabled: AtomicBool,
    pub calls: AtomicUsize,
    pub fault: Mutex<Option<Fault>>,
}
impl Owner {
    fn new(campaign: CampaignPlan) -> Self {
        Self {
            campaign,
            enabled: AtomicBool::new(true),
            calls: AtomicUsize::new(0),
            fault: Mutex::new(None),
        }
    }
}
impl CampaignAuthority for Owner {
    fn permit(&self, _: CampaignOperation, plan: &CampaignPlan) -> bool {
        self.enabled.load(Ordering::Acquire) && plan == &self.campaign
    }
    fn permit_read(&self, pin: CampaignPin, root: &Path, principal: &str) -> bool {
        self.enabled.load(Ordering::Acquire)
            && pin.approval == self.campaign.approval
            && self
                .campaign
                .digest()
                .is_ok_and(|digest| pin.plan == digest)
            && root == Path::new(&self.campaign.history_path)
            && principal == PRINCIPAL
    }
}
impl RtspCampaignWatchAuthority for Owner {
    fn permit_watch(
        &self,
        plan: &RtspCampaignWatchPlan,
        destination: &ReferenceDeployment,
    ) -> bool {
        self.calls.fetch_add(1, Ordering::AcqRel);
        if let Ok(mut fault) = self.fault.lock()
            && fault.as_ref().is_some_and(|fault| {
                destination.current_anchor().commit_sequence > fault.after_sequence
            })
            && let Some(fault) = fault.take()
        {
            let result = if let Some(bytes) = fault.bytes {
                fs::write(&fault.path, bytes)
            } else {
                fs::remove_file(&fault.path)
            };
            if result.is_err() {
                return false;
            }
        }
        self.enabled.load(Ordering::Acquire)
            && plan.history.approval == self.campaign.approval
            && destination.site_lineage() == SITE
    }
}

pub struct Fixture {
    pub directory: Directory,
    retained_fixture: selected::Fixture,
    pub archives: Vec<Option<LocalRootPublisher>>,
    pub destination: Option<ReferenceDeployment>,
    pub cx: ReplayCx,
    pub history_cx: ReplayCx,
    pub owner: Owner,
    pub plan: RtspCampaignWatchPlan,
    pub limits: RtspCampaignWatchLimits,
    pub first_start: CampaignPin,
    pub source_objects: Vec<PathBuf>,
    pub history_object: PathBuf,
    pub writer: CampaignWriter,
}
impl Fixture {
    pub fn new(label: &str, first_recorded_pictures: u64) -> Test<Self> {
        let directory = Directory::new(label)?;
        let mut retained_fixture = selected::Fixture::new(&format!("{label}-avc"), 2)?;
        let avc = retained_fixture.plan.selections[2].clone();
        let RtspWatchSelection::Pages(avc_request) = &avc else {
            return Err("AVC pages".into());
        };
        let avc_namespace = ArchiveNamespace::new(avc_request.scope.clone())?.digest();
        let first_archive = retained_fixture.source.take().ok_or("AVC archive")?;
        let first_catalog_root = first_archive.spool().object_path(avc_request.pages[0].root);

        let mut second_archive =
            LocalRootPublisher::open(directory.0.join("archive-hevc"), archive_limits())?;
        let mut recording_scope = hevc::scope()?;
        recording_scope.generation = 2;
        let packets = hevc::packets()?;
        let recording = prepare_hevc_recording(
            recording_scope.clone(),
            &hevc::configuration()?,
            90_000,
            &hevc::timings(4),
            &hevc::borrowed(&packets),
        )?;
        let window_slot = SlotName::parse("campaign-hevc-window")?;
        let mut publication = RecordingPublication::new(
            recording.publication_plan(),
            &mut second_archive,
            window_slot.clone(),
            recording.publication_plan().byte_len(),
            100,
        )?;
        let mut published = false;
        for now in 0..5 {
            if matches!(
                publication.step(now, &NeverCancel)?,
                RecordingProgress::Published(_)
            ) {
                published = true;
                break;
            }
        }
        if !published {
            return Err("HEVC window publication".into());
        }
        drop(publication);
        let hevc_scope = CatalogScope {
            recording: recording_scope,
            decode_clock: digest("campaign HEVC decode"),
            time_scale: 90_000,
        };
        let catalog = prepare_hevc_catalog(
            hevc_scope.clone(),
            &[HevcCatalogWindow {
                slot: &window_slot,
                recording: &recording,
            }],
        )?;
        let catalog_slot = SlotName::parse("campaign-hevc-catalog")?;
        let mut publication = HevcCatalogPublication::new(
            &catalog,
            &mut second_archive,
            catalog_slot.clone(),
            catalog.byte_len(),
            100,
        )?;
        let mut published = false;
        for now in 0..5 {
            if matches!(
                publication.step(now, &NeverCancel)?,
                CatalogProgress::Published(_)
            ) {
                published = true;
                break;
            }
        }
        if !published {
            return Err("HEVC catalog publication".into());
        }
        drop(publication);
        let second_original = second_archive.spool().object_path(ContentDigest::sha256(
            recording.publication_plan().objects().source,
        ));
        let hevc = RtspWatchSelection::Catalog(RtspCatalogImportRequest {
            codec: RtspImportCodec::Hevc,
            slot: catalog_slot,
            root: catalog.manifest().root(),
            scope: hevc_scope.clone(),
            receive_time: TimestampNs(1_000_000_000_000),
            capture_origin: Some(RtspCaptureOrigin {
                start_ns: TimestampNs(1_000_000_000),
                uncertainty_ns: 10,
            }),
            max_windows: MAX_WINDOWS,
            max_frames: MAX_FRAMES,
            max_original_bytes: MAX_ORIGINAL_BYTES,
            max_media_bytes: MAX_MEDIA_BYTES,
        });
        let history_root = directory.0.join("history");
        let mut attempts = Vec::new();
        for ordinal in 1..=4 {
            attempts.push(CampaignAttempt {
                ordinal,
                child_approval: digest(&format!("{label} child {ordinal}")),
                generation: u64::from(ordinal),
                archive_namespace: match ordinal {
                    1 => avc_namespace,
                    2 => HevcArchiveNamespace::new(hevc_scope.clone())?.digest(),
                    _ => digest(&format!("{label} archive {ordinal}")),
                },
                journal_id: digest(&format!("{label} journal {ordinal}")),
                receive_clock: match ordinal {
                    1 => avc_request.scope.recording.receive_clock,
                    2 => hevc_scope.recording.receive_clock,
                    _ => digest("unknown receive clock"),
                },
                decode_clock: match ordinal {
                    1 => avc_request.scope.decode_clock,
                    2 => hevc_scope.decode_clock,
                    _ => digest("unknown decode clock"),
                },
                archive_path: match ordinal {
                    1 => first_archive.root_dir().to_path_buf(),
                    2 => second_archive.root_dir().to_path_buf(),
                    _ => directory.0.join(format!("missing-archive-{ordinal}")),
                }
                .to_string_lossy()
                .into_owned(),
                pins_path: directory
                    .0
                    .join(format!("pins-{ordinal}"))
                    .to_string_lossy()
                    .into_owned(),
                source: None,
                picture_ceiling: if ordinal == 2 { 4 } else { 10 },
            });
        }
        let campaign = CampaignPlan {
            approval: digest(&format!("{label} campaign")),
            principal: PRINCIPAL.into(),
            history_path: history_root.to_string_lossy().into_owned(),
            continue_after_success: true,
            retry_interrupted: false,
            progress_supervised: false,
            duration_limited: false,
            attempts,
        };
        let limits = RtspCampaignWatchLimits::default();
        let history_cx = context(&history_root, true)?;
        let owner = Owner::new(campaign.clone());
        let mut writer = CampaignWriter::new(campaign, limits.history)?;
        let mut publisher = LocalRootPublisher::open(&history_root, limits.history_publication)?;
        let mut work = WorkBudget::new(WORK);
        let first_start =
            writer.start_attempt(&mut publisher, 1, &owner, &history_cx, &mut work)?;
        let bindings = |selection: &RtspWatchSelection| match selection {
            RtspWatchSelection::Pages(request) => request
                .pages
                .iter()
                .map(|page| CampaignCatalogBinding {
                    slot: page.slot.as_str().into(),
                    root: page.root,
                })
                .collect(),
            RtspWatchSelection::Catalog(request) => vec![CampaignCatalogBinding {
                slot: request.slot.as_str().into(),
                root: request.root,
            }],
            _ => Vec::new(),
        };
        writer.finish_attempt(
            &mut publisher,
            1,
            CampaignFinish {
                native: Some(NativeAttemptObservation {
                    complete: false,
                    error_id: Some("ERR-CAPTURE-RTSP-SOURCE-001".into()),
                    retry: Some(CampaignRetryReason::SourceEnded),
                    durable_pictures: first_recorded_pictures,
                    recovery_required: false,
                    bindings: NativeBindings {
                        catalogs: bindings(&avc),
                        ..NativeBindings::default()
                    },
                }),
                controller_error: None,
                settled_success: false,
                next_attempt_planned: true,
            },
            &owner,
            &history_cx,
            &mut work,
        )?;
        writer.start_attempt(&mut publisher, 2, &owner, &history_cx, &mut work)?;
        writer.finish_attempt(
            &mut publisher,
            2,
            CampaignFinish {
                native: Some(NativeAttemptObservation {
                    complete: true,
                    error_id: None,
                    retry: Some(CampaignRetryReason::SettledSuccess),
                    durable_pictures: 4,
                    recovery_required: false,
                    bindings: NativeBindings {
                        snapshot_digest: Some(digest("snapshot HEVC")),
                        journal_anchor: Some(ArchivePinAnchor {
                            sequence: 2,
                            root: digest("journal HEVC"),
                        }),
                        catalogs: bindings(&hevc),
                        source_pin: None,
                    },
                }),
                controller_error: None,
                settled_success: true,
                next_attempt_planned: true,
            },
            &owner,
            &history_cx,
            &mut work,
        )?;
        writer.start_attempt(&mut publisher, 3, &owner, &history_cx, &mut work)?;
        writer.finish_attempt(
            &mut publisher,
            3,
            CampaignFinish {
                native: Some(NativeAttemptObservation {
                    complete: false,
                    error_id: Some("ERR-CAPTURE-RTSP-CONNECT-001".into()),
                    retry: Some(CampaignRetryReason::ConnectionUnavailable),
                    durable_pictures: 0,
                    recovery_required: false,
                    bindings: NativeBindings::default(),
                }),
                controller_error: None,
                settled_success: false,
                next_attempt_planned: true,
            },
            &owner,
            &history_cx,
            &mut work,
        )?;
        let history = writer.start_attempt(&mut publisher, 4, &owner, &history_cx, &mut work)?;
        let history_object = publisher.spool().object_path(history.root);
        drop(publisher);
        let root = directory.0.join("destination");
        let cx = context(&root, false)?;
        let destination = ReferenceDeployment::open(&root, SITE, &cx)?;
        let native = &retained_fixture.plan;
        let plan = RtspCampaignWatchPlan {
            history,
            history_root,
            bindings: vec![
                RtspCampaignWatchBinding {
                    ordinal: 1,
                    selection: Some(avc),
                },
                RtspCampaignWatchBinding {
                    ordinal: 2,
                    selection: Some(hevc),
                },
                RtspCampaignWatchBinding {
                    ordinal: 3,
                    selection: None,
                },
                RtspCampaignWatchBinding {
                    ordinal: 4,
                    selection: None,
                },
            ],
            interpretation: native.interpretation,
            zones: native.zones.clone(),
            detector: native.detector,
            tracker: native.tracker,
            options: native.options,
            screened: false,
        };
        Ok(Self {
            directory,
            retained_fixture,
            archives: vec![Some(first_archive), Some(second_archive), None, None],
            destination: Some(destination),
            cx,
            history_cx,
            owner,
            plan,
            limits,
            first_start,
            source_objects: vec![first_catalog_root, second_original],
            history_object,
            writer,
        })
    }
    pub fn target(&self) -> &ReferenceDeployment {
        self.destination.as_ref().expect("fixture target")
    }
    pub fn run(&mut self) -> Result<RtspCampaignWatchReport, RtspCampaignWatchError> {
        let sources: Vec<_> = self.archives.iter().map(Option::as_ref).collect();
        process_rtsp_campaign(
            &sources,
            self.destination.as_mut().expect("target"),
            &self.plan,
            &self.limits,
            &self.owner,
            &self.history_cx,
            &self.cx,
            &mut WorkBudget::new(WORK),
        )
    }
    pub fn inspect(&self) -> Test<VerifiedCampaignHistory> {
        Ok(VerifiedCampaignHistory::inspect(
            &self.plan.history_root,
            self.plan.history,
            self.limits.history,
            self.limits.history_publication,
            &self.owner,
            &self.history_cx,
            &mut WorkBudget::new(WORK),
        )?)
    }
    pub fn finish_fourth(&mut self, native: Option<NativeAttemptObservation>) -> Test {
        let mut publisher =
            LocalRootPublisher::open(&self.plan.history_root, self.limits.history_publication)?;
        self.plan.history = self.writer.finish_attempt(
            &mut publisher,
            4,
            CampaignFinish {
                native,
                controller_error: Some("ERR-CAPTURE-RTSP-OUTPUT-001".into()),
                settled_success: false,
                next_attempt_planned: false,
            },
            &self.owner,
            &self.history_cx,
            &mut WorkBudget::new(WORK),
        )?;
        self.history_object = publisher.spool().object_path(self.plan.history.root);
        Ok(())
    }
}
