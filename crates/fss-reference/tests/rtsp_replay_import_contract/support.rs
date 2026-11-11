#![forbid(unsafe_code)]
//! Native original and replay-receipt fixtures shared by the replay-import contracts.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, CanonicalEncode, ContentDigest, OperationId, TimestampNs};
use fss_geometry::WorkBudget;
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel, SlotName};
use fss_reference::ingest::rtsp_import::RtspImportCodec;
use fss_reference::ingest::rtsp_import::catalog::{
    MAX_FRAMES, MAX_MEDIA_BYTES, MAX_ORIGINAL_BYTES,
};
use fss_reference::ingest::rtsp_import::replay::{
    RtspReplayImportAuthority, RtspReplayImportReceipt, RtspReplayImportRequest, import_rtsp_replay,
};
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits};
use fss_reference::rtsp::client::replay::{ReplayAcceptance, ReplayWindow};
use fss_reference::rtsp::recording::PreparedRecording;
use fss_reference::rtsp::recording::hevc::PreparedHevcRecording;
use fss_reference::rtsp::recording::local::{RecordingProgress, RecordingPublication};
use fss_reference::rtsp::recording_archive::ArchiveNamespace;
use fss_reference::rtsp::recording_archive::hevc::HevcArchiveNamespace;
use fss_reference::rtsp::recording_catalog::CatalogScope;
use fss_reference::rtsp::recording_replay::{
    MAX_REPLAY_WINDOWS, OnvifReplaySource, ReplayReceipt, ReplayRequest, ReplayTermination,
    ReplayWindowProof, publish_replay_receipt,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::{hevc_recording_support, recording_support};

pub type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub const SITE: &str = "site:rtsp-replay-import";

pub struct Directory(pub PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-replay-import-{label}-{}-{attempt}",
                std::process::id(),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("temporary directory bound".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:replay-import".into(),
        operation_id: OperationId::parse("operation:replay-import")?,
        principal: "principal:replay-import".into(),
        capabilities: vec![
            "ADP-REPLAY-001".into(),
            "CAP-READ-MEDIA-001".into(),
            "CAP-OBJECT-STAGE-001".into(),
            "CAP-OBJECT-PUBLISH-001".into(),
            "CAP-RETENTION-COMMIT-001".into(),
            "CAP-DELETE-PREPARE-001".into(),
            "CAP-DELETE-COMMIT-001".into(),
        ],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(1024 * 1024 * 1024).build()?,
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
pub fn work() -> WorkBudget<'static> {
    WorkBudget::new(1024 * 1024 * 1024)
}
pub struct Owner(pub bool);
impl RtspReplayImportAuthority for Owner {
    fn permit(&self, _: &RtspReplayImportRequest, destination: &ReferenceDeployment) -> bool {
        self.0 && destination.site_lineage() == SITE
    }
}
fn archive_limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        16,
        512,
        16,
        256,
        SpoolLimits::new(256, 128 * 1024 * 1024, 32 * 1024 * 1024, 256),
    )
}

enum Original {
    Avc(PreparedRecording),
    Hevc(PreparedHevcRecording),
}
impl Original {
    fn plan(&self) -> &PreparedRecording {
        match self {
            Self::Avc(value) => value,
            Self::Hevc(value) => value.publication_plan(),
        }
    }
    fn proof(&self, slot: SlotName) -> Test<ReplayWindowProof> {
        Ok(match self {
            Self::Avc(value) => ReplayWindowProof::from_avc(slot, value)?,
            Self::Hevc(value) => ReplayWindowProof::from_hevc(slot, value)?,
        })
    }
}

pub struct Fixture {
    pub directory: Directory,
    pub source: Option<LocalRootPublisher>,
    pub target: Option<ReferenceDeployment>,
    pub cx: ReplayCx,
    pub request: RtspReplayImportRequest,
    pub receipt: ReplayReceipt,
    pub originals: BTreeMap<ContentDigest, Vec<u8>>,
    pub packet_packs: Vec<ContentDigest>,
    pub media: Vec<u8>,
    pub frames: usize,
}
impl Fixture {
    pub fn new(label: &str, codec: RtspImportCodec, gap: u64, onvif: bool) -> Test<Self> {
        let directory = Directory::new(label)?;
        let originals = match codec {
            RtspImportCodec::Avc => vec![
                Original::Avc(recording_support::repeated(751, 3, 1, 0)?.prepare_at(0)?),
                Original::Avc(
                    recording_support::repeated(752, 3, 2_000, (10_800 + gap) as u32)?
                        .prepare_at(10_800 + gap)?,
                ),
            ],
            RtspImportCodec::Hevc => {
                let first = hevc_recording_support::fixture()?;
                let mut packets = hevc_recording_support::packets()?;
                for packet in &mut packets {
                    packet.sequence += 32;
                    packet.received_ns += 32;
                    packet.bytes[2..4].copy_from_slice(&(packet.sequence as u16).to_be_bytes());
                    let time = u32::from_be_bytes(packet.bytes[4..8].try_into()?);
                    packet.bytes[4..8].copy_from_slice(&(time + 72_000 + gap as u32).to_be_bytes());
                }
                let mut timings = hevc_recording_support::timings(4);
                for timing in &mut timings {
                    timing.decode_time += 72_000 + gap;
                }
                // Native presentation reordering must survive the reconstructed movie.
                timings[1].composition_offset = 18_000;
                timings[2].composition_offset = -18_000;
                vec![
                    Original::Hevc(first),
                    Original::Hevc(hevc_recording_support::prepare(&packets, &timings)?),
                ]
            }
        };
        let source_scope = originals[0].plan().summary().scope.clone();
        let route = ContentDigest::sha256(b"approved exact credential-free historical route");
        let interval = ReplayWindow::from_timestamps("20261101T120000Z", "20261101T120500Z")?;
        let base_clock = ContentDigest::sha256(b"operator-selected base decode clock");
        let mut replay_request = match codec {
            RtspImportCodec::Avc => ReplayRequest::new(source_scope, route, interval, base_clock)?,
            RtspImportCodec::Hevc => {
                ReplayRequest::new_hevc(source_scope, route, interval, base_clock)?
            }
        };
        if onvif {
            replay_request = replay_request.with_onvif_source(OnvifReplaySource::new(
                ContentDigest::sha256(b"approved protected ONVIF discovery operation"),
                ContentDigest::sha256(b"complete protected handoff bytes"),
                ContentDigest::sha256(b"observed private input file"),
                ContentDigest::sha256(b"selected services"),
                ContentDigest::sha256(b"complete service observation"),
                ContentDigest::sha256(b"exact recording token"),
                ContentDigest::sha256(b"complete recording information"),
                ContentDigest::sha256(b"exact replay URI"),
                ContentDigest::sha256(b"complete replay URI observation"),
            )?)?;
        }
        let scope = CatalogScope {
            recording: replay_request.scope().clone(),
            decode_clock: replay_request.decode_clock(),
            time_scale: 90_000,
        };
        let mut source = LocalRootPublisher::open(directory.0.join("archive"), archive_limits())?;
        let mut payloads = BTreeMap::new();
        let mut packet_packs = Vec::new();
        let mut windows = Vec::new();
        let mut media = Vec::new();
        let mut frames = 0;
        for (ordinal, original) in originals.iter().enumerate() {
            let slot = match codec {
                RtspImportCodec::Avc => {
                    ArchiveNamespace::new(scope.clone())?.window_slot(ordinal)?
                }
                RtspImportCodec::Hevc => {
                    HevcArchiveNamespace::new(scope.clone())?.window_slot(ordinal)?
                }
            };
            let plan = original.plan();
            let mut publication =
                RecordingPublication::new(plan, &mut source, slot.clone(), plan.byte_len(), 100)?;
            for at in 0..4 {
                assert!(matches!(
                    publication.step(at, &NeverCancel)?,
                    RecordingProgress::ChildStaged { .. }
                ));
            }
            assert!(matches!(
                publication.step(4, &NeverCancel)?,
                RecordingProgress::Published(_)
            ));
            drop(publication);
            payloads.insert(plan.manifest().root(), plan.manifest().canonical_bytes());
            payloads.extend(
                plan.children()
                    .into_iter()
                    .map(|(_, digest, bytes)| (digest, bytes.to_vec())),
            );
            packet_packs.push(ContentDigest::sha256(plan.objects().source));
            windows.push(original.proof(slot)?);
            frames += plan.summary().samples;
            if ordinal == 0 {
                media.extend_from_slice(plan.objects().initialization);
            }
            let at = media.len();
            media.extend_from_slice(plan.objects().media);
            // Only mfhd.sequence_number differs from the exact original window fragments.
            assert_eq!(&media[at + 12..at + 16], b"mfhd");
            assert_eq!(&media[at + 20..at + 24], &1_u32.to_be_bytes());
            media[at + 20..at + 24].copy_from_slice(&(ordinal as u32 + 1).to_be_bytes());
        }
        let acceptance = ReplayAcceptance::new(
            9,
            interval,
            ReplayWindow::from_timestamps("20261101T120100Z", "20261101T120400Z")?,
        )?;
        let receipt = ReplayReceipt::prepare(
            replay_request,
            scope.clone(),
            ContentDigest::sha256(b"exact whole capture approval"),
            acceptance,
            windows,
            ReplayTermination::InputEnded,
            false,
        )?;
        publish_replay_receipt(&receipt, &mut source, &NeverCancel)?;
        payloads.insert(receipt.root(), receipt.manifest().canonical_bytes());
        payloads.insert(
            ContentDigest::sha256(receipt.metadata_bytes()),
            receipt.metadata_bytes().to_vec(),
        );
        let root = directory.0.join("destination");
        let cx = context(&root)?;
        let target = ReferenceDeployment::open(&root, SITE, &cx)?;
        let request = RtspReplayImportRequest {
            codec,
            receipt_root: receipt.root(),
            request_identity: receipt.request().digest(),
            scope,
            receive_time: TimestampNs(1_000_000_000_000),
            capture_origin: None,
            preserve_decode_gaps: false,
            max_windows: MAX_REPLAY_WINDOWS,
            max_frames: MAX_FRAMES,
            max_original_bytes: MAX_ORIGINAL_BYTES,
            max_media_bytes: MAX_MEDIA_BYTES,
        };
        Ok(Self {
            directory,
            source: Some(source),
            target: Some(target),
            cx,
            request,
            receipt,
            originals: payloads,
            packet_packs,
            media,
            frames,
        })
    }
    pub fn target(&self) -> Test<&ReferenceDeployment> {
        self.target.as_ref().ok_or_else(|| "target closed".into())
    }
    pub fn run(&mut self) -> Test<RtspReplayImportReceipt> {
        Ok(import_rtsp_replay(
            self.source.as_ref().ok_or("source closed")?,
            self.target.as_mut().ok_or("target closed")?,
            &self.request,
            &Owner(true),
            &self.cx,
            &mut work(),
        )?)
    }
    pub fn retained(&self, identity: ContentDigest) -> Test<RetainedFileImport> {
        Ok(RetainedFileImport::open(
            self.target()?,
            identity,
            RetainedReadLimits::default(),
            &self.cx,
        )?)
    }
    pub fn snapshot(&self) -> Test<(usize, usize, usize)> {
        let d = self.target()?;
        Ok((
            d.ledger().batches().len(),
            d.publisher().visible_roots().count(),
            d.publisher().spool().digests().count(),
        ))
    }
    pub fn assert_original_closure(&self) -> Test {
        for (digest, bytes) in &self.originals {
            assert_eq!(
                self.target()?.publisher().spool().read(*digest)?,
                *bytes,
                "original replay graph changed at {digest}"
            );
        }
        Ok(())
    }
    pub fn offline_archive_and_reopen(&mut self) -> Test {
        drop(self.source.take());
        fs::rename(
            self.directory.0.join("archive"),
            self.directory.0.join("offline-archive"),
        )?;
        drop(self.target.take());
        let root = self.directory.0.join("destination");
        self.cx = context(&root)?;
        self.target = Some(ReferenceDeployment::open(&root, SITE, &self.cx)?);
        Ok(())
    }
}
