#![forbid(unsafe_code)]
//! Immutable native video reads share custody and a nonrenewing allowance with active capture.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, SensorId, StreamId, TimestampNs};
use fss_reference::agent_orient::OrientLimits;
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_decode::h264::{
    DecoderLimits, RecordedH264Range, RecordedH264Request,
};
use fss_reference::ingest::video_publication::{
    NativeVideoFrame, PublishedVideoFrame, VideoPublicationLimits,
};
use fss_reference::ingest::{
    FileFormatHint, FileIngestAdapter, FileIngestRequest, RetainedReadLimits,
};
use fss_reference::retained_source::{
    ImmutableRetainedReadLimits, ImmutableRetainedSource, RetainedReadUsage,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:video-read-source";
const SENSOR: &str = "sensor:video-read-source";
const AVC: &[u8] =
    include_bytes!("../../fss-codec-h264/tests/fixtures/decode/p_qcif_ref3_p4x4.h264");

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-video-read-source-{label}-{}-{attempt}",
                std::process::id(),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("test directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn context(root: &Path, read_only: bool) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:video-read-source".into(),
        operation_id: OperationId::parse("operation:video-read-source")?,
        principal: "principal:video-read-source".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(256 * 1024 * 1024)
            .storage_operations(100_000)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(if read_only {
        ReplayCx::from_context_authority_read_only(&authority, root.to_path_buf())?
    } else {
        ReplayCx::from_context_authority(&authority, root.to_path_buf())?
    })
}
fn limits() -> ImmutableRetainedReadLimits {
    ImmutableRetainedReadLimits {
        snapshot: OrientLimits::default(),
        max_read_bytes: 256 * 1024 * 1024,
        max_read_objects: 100_000,
    }
}
struct Fixture {
    directory: Directory,
    root: PathBuf,
    cx: ReplayCx,
    deployment: ReferenceDeployment,
    saved: PublishedVideoFrame,
}
impl Fixture {
    fn new(label: &str) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let path = directory.0.join("input");
        fs::write(&path, AVC)?;
        let cx = context(&root, false)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut request = FileIngestRequest::new(
            path.clone(),
            SensorId::parse(SENSOR)?,
            StreamId::parse("stream:video-read-source")?,
        )
        .with_receive_time(TimestampNs(1_000_000_000));
        request.format_hint = Some(FileFormatHint::AnnexB);
        let import = FileIngestAdapter::ingest(request, &cx, &mut deployment)?;
        fs::remove_file(path)?;
        let mut range = RecordedH264Range::open(
            &deployment,
            RecordedH264Request {
                import_identity: import.import_identity,
                first_segment: 0,
                segment_count: 3,
                interpretation: ComponentInterpretation::YCbCr,
                read_limits: RetainedReadLimits::default(),
                decoder_limits: DecoderLimits {
                    max_width: 176,
                    max_height: 144,
                    max_macroblocks: 99,
                    ..DecoderLimits::default()
                },
            },
            &cx,
        )?;
        let frame = range
            .next_frame(&deployment, &cx)?
            .ok_or("native first frame")?;
        let saved = PublishedVideoFrame::publish(
            &mut deployment,
            NativeVideoFrame::H264(&frame),
            VideoPublicationLimits::default(),
            &cx,
        )?;
        Ok(Self {
            directory,
            root,
            cx,
            deployment,
            saved,
        })
    }
    fn object_path(&self, bytes: &[u8]) -> PathBuf {
        self.root.join("objects/spool/objects").join(
            ContentDigest::sha256(bytes)
                .bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        )
    }
}
fn inspect(
    fixture: &Fixture,
    cx: &ReplayCx,
    bounds: ImmutableRetainedReadLimits,
) -> Test<RetainedReadUsage> {
    let source = ImmutableRetainedSource::open(&fixture.root, bounds, cx)?;
    let frame = PublishedVideoFrame::open(
        &source,
        fixture.saved.publication_root(),
        VideoPublicationLimits::default(),
        cx,
    )?;
    assert_eq!(frame.i420(), fixture.saved.i420());
    assert_eq!(frame.codec_receipt(), fixture.saved.codec_receipt());
    assert_eq!(frame.authority_anchor(), fixture.saved.authority_anchor());
    source.revalidate_snapshot_metadata()?;
    source.revalidate()?;
    Ok(source.usage())
}

#[test]
fn immutable_video_read_succeeds_while_writer_remains_exclusive_and_requires_same_owner() -> Test {
    let fixture = Fixture::new("owner")?;
    let cx = context(&fixture.root, true)?;
    let ledger = fs::read(fixture.root.join("ledger/journal.fssj"))?;
    let effects = fs::read(fixture.root.join("effects/journal.fssj"))?;
    let usage = inspect(&fixture, &cx, limits())?;
    assert!(usage.read_bytes > fixture.saved.i420().len() as u64);
    assert!(ReferenceDeployment::open(&fixture.root, SITE, &cx).is_err());
    assert_eq!(fs::read(fixture.root.join("ledger/journal.fssj"))?, ledger);
    assert_eq!(
        fs::read(fixture.root.join("effects/journal.fssj"))?,
        effects
    );

    let other_root = fixture.directory.0.join("other-root");
    fs::create_dir(&other_root)?;
    let other = context(&other_root, true)?;
    let source = ImmutableRetainedSource::open(&fixture.root, limits(), &cx)?;
    let before = source.usage();
    for owner in [
        &source as &dyn fss_reference::RetainedSource,
        &fixture.deployment,
    ] {
        assert!(
            PublishedVideoFrame::open(
                owner,
                fixture.saved.publication_root(),
                VideoPublicationLimits::default(),
                &other,
            )
            .is_err()
        );
    }
    assert_eq!(
        source.usage(),
        before,
        "foreign owner was read before refusal"
    );
    Ok(())
}

#[test]
fn one_nonrenewing_allowance_covers_open_metadata_source_pixels_and_final_rereads() -> Test {
    let fixture = Fixture::new("allowance")?;
    let cx = context(&fixture.root, true)?;
    let used = inspect(&fixture, &cx, limits())?;
    let exact = ImmutableRetainedReadLimits {
        max_read_bytes: usize::try_from(used.read_bytes)?,
        max_read_objects: usize::try_from(used.read_objects)?,
        ..limits()
    };
    assert_eq!(inspect(&fixture, &cx, exact)?, used);
    for narrowed in [
        ImmutableRetainedReadLimits {
            max_read_bytes: exact.max_read_bytes - 1,
            ..exact
        },
        ImmutableRetainedReadLimits {
            max_read_objects: exact.max_read_objects - 1,
            ..exact
        },
    ] {
        let source = ImmutableRetainedSource::open(&fixture.root, narrowed, &cx)?;
        PublishedVideoFrame::open(
            &source,
            fixture.saved.publication_root(),
            VideoPublicationLimits::default(),
            &cx,
        )?;
        assert!(
            source
                .revalidate_snapshot_metadata()
                .and_then(|()| source.revalidate())
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn final_validation_refuses_late_pixel_and_source_damage_without_repair() -> Test {
    let fixture = Fixture::new("late-damage")?;
    let cx = context(&fixture.root, true)?;
    for bytes in [fixture.saved.i420(), AVC] {
        let source = ImmutableRetainedSource::open(&fixture.root, limits(), &cx)?;
        PublishedVideoFrame::open(
            &source,
            fixture.saved.publication_root(),
            VideoPublicationLimits::default(),
            &cx,
        )?;
        let path = fixture.object_path(bytes);
        let original = fs::read(&path)?;
        let mut damaged = original.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        fs::write(&path, &damaged)?;
        assert!(source.revalidate().is_err());
        assert_eq!(fs::read(&path)?, damaged);
        fs::write(path, original)?;
    }
    Ok(())
}

#[test]
fn final_validation_refuses_current_privacy_changes_and_late_cancellation() -> Test {
    let mut fixture = Fixture::new("late-privacy")?;
    let cx = context(&fixture.root, true)?;
    let cancelled = AtomicBool::new(false);
    let probe = || cancelled.load(Ordering::Acquire);
    let source = ImmutableRetainedSource::open_cancellable(&fixture.root, limits(), &cx, &probe)?;
    PublishedVideoFrame::open(
        &source,
        fixture.saved.publication_root(),
        VideoPublicationLimits::default(),
        &cx,
    )?;
    cancelled.store(true, Ordering::Release);
    assert!(source.revalidate().is_err());
    cancelled.store(false, Ordering::Release);
    let source = ImmutableRetainedSource::open(&fixture.root, limits(), &cx)?;
    PublishedVideoFrame::open(
        &source,
        fixture.saved.publication_root(),
        VideoPublicationLimits::default(),
        &cx,
    )?;
    let policy = PrivacyMaskPolicy::new(SensorId::parse(SENSOR)?, [176, 144], &[[0, 0, 176, 144]])?;
    let preview = preview_mask(&fixture.deployment, &policy)?;
    declare_mask(
        &mut fixture.deployment,
        &policy,
        preview.approval,
        &fixture.cx,
    )?;
    source.revalidate_snapshot_metadata()?;
    assert!(source.revalidate().is_err());
    let current = ImmutableRetainedSource::open(&fixture.root, limits(), &cx)?;
    assert!(
        PublishedVideoFrame::open(
            &current,
            fixture.saved.publication_root(),
            VideoPublicationLimits::default(),
            &cx,
        )
        .is_err()
    );
    Ok(())
}
