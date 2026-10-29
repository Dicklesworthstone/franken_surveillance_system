#![forbid(unsafe_code)]
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
//! Real process export of retained footage behind a native long-watch event. The `rtsp` target
//! name keeps this original-media boundary in the existing native capture regression lane.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use fss_container::TimedAvcPicture;
use fss_container::demux::{AvcMp4, DemuxLimits, VideoCodec, length_prefixed_nals};
use fss_packet::avc::{
    AvcAssemblyStep, AvcPictureGroup, AvcReceiveLimits, AvcReceivePoll, AvcReceiver, parse_pps,
    parse_sps,
};
use fss_packet::hevc::{HevcConfiguration, HevcConfigurationLimits};
use fss_packet::{H264Mode, StreamKey};
use fss_reference::ingest::rtsp_import::RtspImportCodec;
use fss_reference::rtsp::recording::hevc::{
    HevcRecordingTiming, PreparedHevcRecording, prepare_hevc_recording,
};
use fss_reference::rtsp::recording::{
    PreparedRecording, RecordingPacket, RecordingScope, prepare_recording,
};

use fss_cli::json_input::{Value, parse};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, ContentDigest, EventId, OperationId, SensorId, StreamId, TimestampNs,
};
use fss_geometry::WorkBudget;
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel, SlotName};
use fss_reference::ingest::long_dwell::LongDwellLimits;
use fss_reference::ingest::long_watch::LongWatchReport;
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchOptions, WatchPlan, WatchTrackerConfig, WatchZone,
};
use fss_reference::ingest::rtsp_import::{
    RtspCaptureOrigin, RtspImportAuthority, RtspImportRequest, import_rtsp,
};
use fss_reference::ingest::{
    CaptureHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest, RetainedFileImport,
    RetainedReadLimits,
};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::original_media_export::verify_original_media_export;
use fss_reference::rtsp::recording::local::{RecordingProgress, RecordingPublication};
use fss_reference::{
    ReferenceDeployment, ReferencePolicyAction, ReferencePolicyDecision, ReplayCx,
};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
#[path = "rtsp_event_media_export_cli/package.rs"]
mod package;
const SITE: &str = "site:original-media-export-cli";
const ACTOR: &str = "principal:original-media-export-cli";
const SENSOR: &str = "sensor:original-media-export-cli";
const RECIPIENT: &str = "recipient:owner-case-7";
const EXPIRY: &str = "2000000000000";
const NOW: &str = "1000000000001:1000000000010";
// Another fixture must not hold a briefly inherited deployment lock when a CLI child forks.
static SERIAL: Mutex<()> = Mutex::new(());

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-original-media-cli-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                    return Ok(Self(path));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
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

fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:original-media-export-cli-test".into(),
        operation_id: OperationId::parse("operation:original-media-export-cli-test")?,
        principal: ACTOR.into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(256 * 1024 * 1024)
            .storage_operations(131_072)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

fn scene() -> Test<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut bytes = Vec::new();
    for position in 0..12 {
        let mut pixels = vec![40_u8 + (position % 2) as u8 * 8; 48 * 32];
        if position >= 3 {
            for y in 8..24 {
                for x in 8..24 {
                    pixels[y * 48 + x] = 220;
                }
            }
        }
        bytes.extend(encode_jpeg(48, 32, &pixels, &config)?);
    }
    Ok(bytes)
}

struct Fixture {
    directory: Directory,
    root: PathBuf,
    output: PathBuf,
    source: Vec<u8>,
    source_chunk: PathBuf,
    identity: ContentDigest,
    import_root: ContentDigest,
    event_id: EventId,
    revision: ContentDigest,
}

struct ReviewWitness {
    revision: i128,
    event_revision: ContentDigest,
    event_root: ContentDigest,
    statement_digest: ContentDigest,
    statement_root: ContentDigest,
    disposition: String,
}

struct FixtureOwner;
impl RtspImportAuthority for FixtureOwner {
    fn permit(&self, request: &RtspImportRequest, deployment: &ReferenceDeployment) -> bool {
        deployment.site_lineage() == SITE
            && request.source.sensor.as_str() == SENSOR
            && request.source.anchor == ContentDigest::sha256(b"explicit native fixture owner")
    }
}

impl Fixture {
    fn new(label: &str) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let cx = context(&root)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let source = scene()?;
        let input = directory.0.join("private-camera.mjpeg");
        fs::write(&input, &source)?;
        let mut limits = FileIngestLimits::standard();
        limits.max_segments = 1024;
        limits.chunk_bytes = 4096;
        let request = FileIngestRequest::new(
            &input,
            SensorId::parse(SENSOR)?,
            StreamId::parse("stream:original-media-export-cli")?,
        )
        .with_limits(limits)
        .with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?)
        .with_receive_time(TimestampNs(1_000_000_000_000));
        let receipt = FileIngestAdapter::ingest(request, &cx, &mut deployment)?;
        fs::remove_file(input)?;
        let identity = receipt.import_identity;
        Self::from_import(
            directory,
            source,
            deployment,
            cx,
            identity,
            receipt.capsule_count,
            [48, 32],
            ComponentInterpretation::Grayscale,
        )
    }

    fn native(codec: RtspImportCodec) -> Test<Self> {
        let label = match codec {
            RtspImportCodec::Avc => "native-avc",
            RtspImportCodec::Hevc => "native-hevc",
        };
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let archive_path = directory.0.join("camera-archive");
        let prepared = native_plan(codec)?;
        let recording = prepared.plan();
        let objects = recording.objects();
        let source = [objects.initialization, objects.media].concat();
        let mut archive = LocalRootPublisher::open(
            &archive_path,
            LocalPublicationLimits::new(
                16,
                64,
                16,
                256,
                SpoolLimits::new(256, 128 * 1024 * 1024, 32 * 1024 * 1024, 256),
            ),
        )?;
        let slot = SlotName::parse("native-export-window")?;
        let mut publication = RecordingPublication::new(
            recording,
            &mut archive,
            slot.clone(),
            recording.byte_len(),
            100,
        )?;
        let mut published = false;
        for at in 0..5 {
            if let RecordingProgress::Published(receipt) = publication.step(at, &NeverCancel)? {
                assert_eq!(receipt.root, recording.manifest().root());
                published = true;
                break;
            }
        }
        assert!(published, "native recording publication did not finish");
        drop(publication);
        let cx = context(&root)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let request = RtspImportRequest {
            codec,
            slot,
            root: recording.manifest().root(),
            source: recording.summary().scope.clone(),
            receive_time: TimestampNs(1_000_000_000_000),
            capture_origin: Some(RtspCaptureOrigin {
                start_ns: TimestampNs(0),
                uncertainty_ns: 0,
            }),
            max_frames: 256,
            max_original_bytes: 32 * 1024 * 1024,
            max_media_bytes: 32 * 1024 * 1024,
        };
        let imported = import_rtsp(
            &archive,
            &mut deployment,
            &request,
            &FixtureOwner,
            &cx,
            &mut WorkBudget::new(512 * 1024 * 1024),
        )?;
        drop(archive);
        fs::rename(archive_path, directory.0.join("camera-archive-offline"))?;
        let size = match codec {
            RtspImportCodec::Avc => [48, 32],
            RtspImportCodec::Hevc => [96, 48],
        };
        Self::from_import(
            directory,
            source,
            deployment,
            cx,
            imported.import_identity,
            imported.frames,
            size,
            ComponentInterpretation::YCbCr,
        )
    }

    fn from_import(
        directory: Directory,
        source: Vec<u8>,
        mut deployment: ReferenceDeployment,
        cx: ReplayCx,
        identity: ContentDigest,
        count: usize,
        size: [u32; 2],
        interpretation: ComponentInterpretation,
    ) -> Test<Self> {
        let root = deployment.root().to_path_buf();
        let output = directory.0.join("owner's original footage");
        let retained =
            RetainedFileImport::open(&deployment, identity, RetainedReadLimits::default(), &cx)?;
        let import_root = retained.import_root();
        let chunk = retained
            .manifest()
            .ordered_chunks
            .first()
            .copied()
            .ok_or("retained fixture source chunk missing")?;
        let source_chunk = deployment.publisher().spool().object_path(chunk);
        let plan = WatchPlan {
            import_identity: identity,
            interpretation,
            first_segment: 0,
            segment_count: count,
            zones: vec![WatchZone {
                zone_id: "porch".into(),
                x: 0,
                y: 0,
                width: size[0],
                height: size[1],
            }],
            detector: WatchDetectorConfig {
                learning_rate_num: 0,
                ..WatchDetectorConfig::default()
            },
            tracker: WatchTrackerConfig::default(),
        };
        let mut report = LongWatchReport::analyze(
            &deployment,
            &plan,
            WatchOptions::default(),
            &LongDwellLimits::default(),
            &cx,
        )?;
        let candidate = report
            .candidates()
            .first()
            .ok_or("native watch event missing")?;
        let event_id = candidate.event().event_id.clone();
        let approval = candidate.proposal_digest();
        assert_eq!(
            report.publish(&mut deployment, &BTreeSet::from([approval]), &cx)?,
            1
        );
        let (event, _) = deployment.current_event_authority(&event_id)?;
        assert_eq!(event.revision, 1);
        let revision = event.revision_digest();
        drop(deployment);
        cx.drain_and_finalize();
        Ok(Self {
            directory,
            root,
            output,
            source,
            source_chunk,
            identity,
            import_root,
            event_id,
            revision,
        })
    }

    fn args(&self) -> Vec<OsString> {
        vec![
            "media".into(),
            "--root".into(),
            self.root.as_os_str().to_owned(),
            "--site".into(),
            SITE.into(),
            "--principal".into(),
            ACTOR.into(),
            "--event-id".into(),
            self.event_id.as_str().into(),
            "--expected-revision".into(),
            self.revision.to_text().into(),
            "--import-identity".into(),
            self.identity.to_text().into(),
            "--expected-import-root".into(),
            self.import_root.to_text().into(),
            "--recipient".into(),
            RECIPIENT.into(),
            "--purpose".into(),
            "Owner's incident review: \"porch\" footage".into(),
            "--expires-at-ns".into(),
            EXPIRY.into(),
            "--attested-now-ns".into(),
            NOW.into(),
            "--whole-source".into(),
            "yes".into(),
            "--max-source-bytes".into(),
            "1048576".into(),
            "--out".into(),
            self.output.as_os_str().to_owned(),
        ]
    }

    fn preview(&self) -> Test<Value> {
        let output = execute(&self.args())?;
        let report = success(&output)?;
        assert_eq!(text(&report, "status")?, "awaiting_approval");
        assert_eq!(field(&report, "published")?.boolean(), Some(false));
        assert!(
            !self.output.exists(),
            "preview must not create a destination"
        );
        Ok(report)
    }

    fn publish(&self) -> Test<Value> {
        let preview = self.preview()?;
        let output = execute(&approved(self.args(), text(&preview, "approval_digest")?))?;
        let report = success(&output)?;
        assert_eq!(text(&report, "status")?, "exported_original_media");
        assert_eq!(field(&report, "published")?.boolean(), Some(true));
        assert_eq!(
            field(&report, "export_root")?,
            field(&preview, "export_root")?
        );
        Ok(report)
    }

    fn verify_args(&self, export_root: &str) -> Vec<OsString> {
        vec![
            "media-verify".into(),
            "--input".into(),
            self.output.as_os_str().to_owned(),
            "--export-root".into(),
            export_root.into(),
            "--recipient".into(),
            RECIPIENT.into(),
            "--attested-now-ns".into(),
            "1000000000011:1000000000020".into(),
        ]
    }

    fn journals(&self) -> Test<(Vec<u8>, Vec<u8>)> {
        Ok((
            fs::read(self.root.join("ledger/journal.fssj"))?,
            fs::read(self.root.join("effects/journal.fssj"))?,
        ))
    }

    fn review_show(&self) -> Test<Value> {
        let report = success(&execute_binary(
            env!("CARGO_BIN_EXE_fss-review"),
            &[
                "show".into(),
                "--root".into(),
                self.root.as_os_str().to_owned(),
                "--site".into(),
                SITE.into(),
                "--event-id".into(),
                self.event_id.as_str().into(),
            ],
        )?)?;
        assert_eq!(text(field(&report, "result")?, "status")?, "read_verified");
        Ok(report)
    }

    fn review(&mut self, disposition: &str, reviewer: &str, reason: &str) -> Test<ReviewWitness> {
        let args = vec![
            disposition.into(),
            "--root".into(),
            self.root.as_os_str().to_owned(),
            "--site".into(),
            SITE.into(),
            "--event-id".into(),
            self.event_id.as_str().into(),
            "--expected-revision".into(),
            self.revision.to_text().into(),
            "--principal".into(),
            reviewer.into(),
            "--reason".into(),
            reason.into(),
        ];
        let before = self.journals()?;
        let preview = success(&execute_binary(env!("CARGO_BIN_EXE_fss-review"), &args)?)?;
        let proposed = field(&preview, "result")?;
        assert_eq!(text(proposed, "status")?, "proposed");
        assert_eq!(field(proposed, "published")?.boolean(), Some(false));
        assert_eq!(self.journals()?, before, "review preview must not publish");
        let committed = success(&execute_binary(
            env!("CARGO_BIN_EXE_fss-review"),
            &approved(args, text(proposed, "approval_digest")?),
        )?)?;
        let result = field(&committed, "result")?;
        assert_eq!(text(result, "status")?, "published");
        assert_eq!(field(result, "published")?.boolean(), Some(true));
        assert_eq!(
            field(result, "revision_digest")?,
            field(proposed, "revision_digest")?
        );
        assert_eq!(
            field(&committed, "effects_performed")?.boolean(),
            Some(false)
        );
        assert_eq!(self.journals()?.1, before.1);
        self.revision = ContentDigest::parse(text(result, "revision_digest")?)?;
        let shown = self.review_show()?;
        let current = field(&shown, "result")?;
        assert_eq!(text(current, "review_status")?, "verified_current_review");
        assert_eq!(text(current, "revision_digest")?, self.revision.to_text());
        let statement = field(result, "record")?;
        assert_eq!(text(statement, "principal")?, reviewer);
        assert_eq!(text(statement, "reason")?, reason);
        Ok(ReviewWitness {
            revision: field(field(result, "event")?, "revision")?
                .integer()
                .ok_or("review event revision missing")?,
            event_revision: self.revision,
            event_root: ContentDigest::parse(text(current, "event_root")?)?,
            statement_digest: ContentDigest::parse(text(statement, "record_digest")?)?,
            statement_root: ContentDigest::parse(text(result, "provenance_root")?)?,
            disposition: disposition.to_owned(),
        })
    }

    fn update(&self, action: impl FnOnce(&mut ReferenceDeployment, &ReplayCx) -> Test) -> Test {
        let cx = context(&self.root)?;
        let mut deployment = ReferenceDeployment::open(&self.root, SITE, &cx)?;
        let result = action(&mut deployment, &cx);
        drop(deployment);
        cx.drain_and_finalize();
        result
    }
}

// Each child has a deadline and is reaped on every exit, including an assertion/unwind. File
// capture prevents a full stdout/stderr pipe from blocking a child while its owner polls it.
struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn execute(args: &[OsString]) -> Test<Output> {
    execute_binary(env!("CARGO_BIN_EXE_fss-export"), args)
}

fn execute_binary(binary: &str, args: &[OsString]) -> Test<Output> {
    let capture = Directory::new("process")?;
    let stdout = capture.0.join("stdout");
    let stderr = capture.0.join("stderr");
    let mut child = OwnedChild(
        Command::new(binary)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::from(fs::File::create(&stdout)?))
            .stderr(Stdio::from(fs::File::create(&stderr)?))
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = child.0.try_wait()? {
            if fs::metadata(&stdout)?.len() > 1024 * 1024
                || fs::metadata(&stderr)?.len() > 1024 * 1024
            {
                return Err("CLI output exceeded test capture bound".into());
            }
            return Ok(Output {
                status,
                stdout: fs::read(&stdout)?,
                stderr: fs::read(&stderr)?,
            });
        }
        if Instant::now() >= deadline {
            return Err("CLI child exceeded 60-second deadline".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn field<'a>(value: &'a Value, key: &str) -> Test<&'a Value> {
    value
        .object()
        .and_then(|fields| fields.get(key))
        .ok_or_else(|| format!("missing JSON object field {key}").into())
}
fn text<'a>(value: &'a Value, key: &str) -> Test<&'a str> {
    field(value, key)?
        .text()
        .ok_or_else(|| format!("non-text JSON field {key}").into())
}
fn success(output: &Output) -> Test<Value> {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "successful command must not hide a warning"
    );
    Ok(parse(std::str::from_utf8(&output.stdout)?)?)
}
fn refused(output: &Output) {
    assert!(
        !output.status.success(),
        "unexpected successful output: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        output.stdout.is_empty(),
        "refusal must not emit a partial success record"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("ERR-"),
        "refusal needs a stable error identity: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn replace(args: &mut [OsString], key: &str, value: impl Into<OsString>) -> Test {
    let index = args
        .iter()
        .position(|arg| arg == key)
        .ok_or("option missing in fixture")?;
    let slot = args.get_mut(index + 1).ok_or("option has no value")?;
    *slot = value.into();
    Ok(())
}
fn approved(mut args: Vec<OsString>, approval: &str) -> Vec<OsString> {
    args.extend(["--approve".into(), approval.into()]);
    args
}
fn package_snapshot(path: &Path) -> Test<Vec<(OsString, Vec<u8>)>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        files.push((entry.file_name(), fs::read(entry.path())?));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

fn assert_reviewed_record(
    record: &Value,
    original: &Value,
    reviews: &[ReviewWitness],
    current_state: &str,
) -> Test {
    assert_eq!(text(record, "schema")?, "fss.original_media_export.v2");
    assert_eq!(
        text(record, "profile")?,
        "event-reviewed-original-media-whole-source-v2"
    );
    assert_eq!(field(record, "reviewed_event")?.boolean(), Some(true));
    assert_eq!(
        field(record, "native_origin_revision")?,
        field(original, "revision_digest")?
    );
    assert_eq!(
        field(record, "native_origin_event_root")?,
        field(original, "event_root")?
    );
    assert_eq!(
        field(record, "native_origin_authority_sequence")?.integer(),
        field(field(original, "event_anchor")?, "capsuleSequence")?.integer()
    );
    ContentDigest::parse(text(record, "native_origin_authority_anchor_digest")?)?;
    assert_eq!(
        field(record, "review_count")?.integer(),
        Some(reviews.len() as i128)
    );
    let chain = field(record, "review_chain")?
        .array()
        .ok_or("review chain must be an array")?;
    assert_eq!(chain.len(), reviews.len());
    for (entry, expected) in chain.iter().zip(reviews) {
        assert_eq!(field(entry, "revision")?.integer(), Some(expected.revision));
        assert_eq!(
            text(entry, "event_revision")?,
            expected.event_revision.to_text()
        );
        assert_eq!(text(entry, "event_root")?, expected.event_root.to_text());
        assert_eq!(
            text(entry, "statement_digest")?,
            expected.statement_digest.to_text()
        );
        assert_eq!(
            text(entry, "statement_root")?,
            expected.statement_root.to_text()
        );
        assert_eq!(text(entry, "disposition")?, expected.disposition);
        assert_eq!(text(entry, "assertion_class")?, "operator");
        assert_eq!(field(entry, "sensor_support_added")?.boolean(), Some(false));
    }
    for name in [
        "review_reasons_included",
        "reviewer_identity_included",
        "review_is_sensor_recomputation",
    ] {
        assert_eq!(field(record, name)?.boolean(), Some(false));
    }
    let summary = field(record, "event_summary")?;
    assert_eq!(text(summary, "state")?, current_state);
    assert_eq!(
        text(summary, "event_revision_digest")?,
        reviews
            .last()
            .ok_or("no expected reviews")?
            .event_revision
            .to_text()
    );
    Ok(())
}

#[test]
fn whole_source_export_is_explicit_private_exact_and_independently_verifiable() -> Test {
    let _guard = SERIAL.lock().map_err(|_| "test lock poisoned")?;
    let fixture = Fixture::new("roundtrip")?;
    let journals = fixture.journals()?;
    let preview = fixture.preview()?;
    assert_eq!(text(&preview, "media_filename")?, "source.mjpeg");
    assert_eq!(
        text(&preview, "media_digest")?,
        ContentDigest::sha256(&fixture.source).to_text()
    );
    assert_eq!(
        field(&preview, "media_bytes")?.integer(),
        Some(fixture.source.len() as i128)
    );
    let record = field(&preview, "record")?;
    assert_eq!(
        text(record, "source_import_identity")?,
        fixture.identity.to_text()
    );
    assert_eq!(
        text(record, "source_import_root")?,
        fixture.import_root.to_text()
    );
    assert_eq!(text(record, "event_profile")?, "long_watch");
    assert_eq!(text(record, "source_format")?, "mjpeg");
    assert_eq!(
        field(record, "whole_source_authorized")?.boolean(),
        Some(true)
    );
    assert_eq!(field(record, "frame_precise_trim")?.boolean(), Some(false));
    assert_eq!(
        field(record, "context_outside_event_may_be_included")?.boolean(),
        Some(true)
    );
    assert_eq!(field(record, "audio_included")?.boolean(), Some(false));
    assert_eq!(fixture.journals()?, journals);

    let args = approved(fixture.args(), text(&preview, "approval_digest")?);
    let published = success(&execute(&args)?)?;
    assert_eq!(text(&published, "status")?, "exported_original_media");
    assert_eq!(field(&published, "published")?.boolean(), Some(true));
    assert_eq!(
        field(&published, "export_root")?,
        field(&preview, "export_root")?
    );
    assert_eq!(
        fs::read(fixture.output.join("source.mjpeg"))?,
        fixture.source
    );
    assert_eq!(
        fs::metadata(&fixture.output)?.permissions().mode() & 0o777,
        0o700
    );
    let package = package_snapshot(&fixture.output)?;
    let names: Vec<_> = package.iter().map(|(name, _)| name.to_str()).collect();
    assert_eq!(
        names,
        vec![
            Some("COMPLETE.json"),
            Some("COMPLETE.json.pending"),
            Some("manifest.canonical"),
            Some("record.canonical"),
            Some("record.json"),
            Some("source.mjpeg")
        ]
    );
    for (name, _) in &package {
        let metadata = fs::symlink_metadata(fixture.output.join(name))?;
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }
    let root = ContentDigest::parse(text(&preview, "export_root")?)?;
    let verified = verify_original_media_export(
        &fs::read(fixture.output.join("manifest.canonical"))?,
        &fs::read(fixture.output.join("record.canonical"))?,
        &fixture.source,
        root,
    )?;
    assert_eq!(verified.request().import_identity, fixture.identity);
    assert_eq!(verified.request().event.expected_revision, fixture.revision);
    assert_eq!(verified.request().event.recipient, RECIPIENT);
    assert_eq!(
        verified.to_json().as_bytes(),
        fs::read(fixture.output.join("record.json"))?
    );
    let complete = parse(&fs::read_to_string(fixture.output.join("COMPLETE.json"))?)?;
    assert_eq!(text(&complete, "export_root")?, root.to_text());

    let retry = success(&execute(&args)?)?;
    assert_eq!(text(&retry, "status")?, "already_exported_original_media");
    assert_eq!(field(&retry, "published")?.boolean(), Some(false));
    assert_eq!(package_snapshot(&fixture.output)?, package);
    // The redundant staging link is not part of the portable five-file package. A complete
    // export remains an exact retry after it has been removed during an ordinary copy.
    fs::remove_file(fixture.output.join("COMPLETE.json.pending"))?;
    let copied_retry = success(&execute(&args)?)?;
    assert_eq!(
        text(&copied_retry, "status")?,
        "already_exported_original_media"
    );
    assert_eq!(fs::read_dir(&fixture.output)?.count(), 5);
    assert_eq!(
        fixture.journals()?,
        journals,
        "local export must not invent a delivery receipt"
    );

    // Independent verification must need neither the source path nor a deployment directory.
    fs::rename(
        &fixture.root,
        fixture.directory.0.join("deployment-offline"),
    )?;
    let report = success(&execute(&fixture.verify_args(&root.to_text()))?)?;
    assert_eq!(text(&report, "status")?, "verified_original_media");
    assert_eq!(
        field(&report, "current_deployment_state_checked")?.boolean(),
        Some(false)
    );
    assert_eq!(
        field(&report, "recipient_authenticated")?.boolean(),
        Some(false)
    );
    assert_eq!(field(&report, "delivery_proven")?.boolean(), Some(false));
    assert!(!fixture.root.exists());
    Ok(())
}

#[test]
fn approval_binds_disclosure_actor_destination_clocks_and_exact_source_pins() -> Test {
    let _guard = SERIAL.lock().map_err(|_| "test lock poisoned")?;
    let fixture = Fixture::new("approval")?;
    let journals = fixture.journals()?;
    let preview = fixture.preview()?;
    let approval = text(&preview, "approval_digest")?;
    for (key, value) in [
        ("--recipient", "recipient:substituted"),
        ("--purpose", "An unapproved disclosure purpose"),
        ("--principal", "principal:another-actor"),
        ("--expires-at-ns", "2000000000001"),
        ("--attested-now-ns", "1000000000002:1000000000010"),
        ("--max-source-bytes", "1048575"),
        ("--whole-source", "no"),
        ("--attested-now-ns", "2000000000000:2000000000000"),
        ("--attested-now-ns", "1999999999999:2000000000000"),
        ("--attested-now-ns", "1000000000011:1000000000010"),
        ("--max-source-bytes", "1"),
        ("--max-source-bytes", "67108865"),
    ] {
        let mut args = approved(fixture.args(), approval);
        replace(&mut args, key, value)?;
        refused(&execute(&args)?);
        assert!(
            !fixture.output.exists(),
            "refused {key} must not publish anything"
        );
    }
    let wrong = ContentDigest::sha256(b"not the approved source or event").to_text();
    for key in [
        "--expected-revision",
        "--import-identity",
        "--expected-import-root",
        "--approve",
    ] {
        let mut args = approved(fixture.args(), approval);
        replace(&mut args, key, &wrong)?;
        refused(&execute(&args)?);
        assert!(!fixture.output.exists());
    }
    let destination = fixture.directory.0.join("unapproved-copy");
    let mut substituted = approved(fixture.args(), approval);
    replace(&mut substituted, "--out", destination.as_os_str())?;
    refused(&execute(&substituted)?);
    assert!(!destination.exists());
    assert_eq!(fixture.journals()?, journals);
    // Refused attempts leave the exact original approval usable.
    assert_eq!(
        text(
            &success(&execute(&approved(fixture.args(), approval))?)?,
            "status"
        )?,
        "exported_original_media"
    );
    Ok(())
}

#[test]
fn native_avc_and_hevc_events_export_exact_video_after_the_camera_archive_goes_offline() -> Test {
    let _guard = SERIAL.lock().map_err(|_| "test lock poisoned")?;
    for (codec, format) in [
        (RtspImportCodec::Avc, "mp4avc"),
        (RtspImportCodec::Hevc, "mp4hevc"),
    ] {
        let fixture = Fixture::native(codec)?;
        assert!(!fixture.directory.0.join("camera-archive").exists());
        let journals = fixture.journals()?;
        let exported = fixture.publish()?;
        assert_eq!(text(&exported, "media_filename")?, "source.mp4");
        let record = field(&exported, "record")?;
        assert_eq!(text(record, "source_format")?, format);
        assert_eq!(text(record, "event_profile")?, "long_watch");
        assert_eq!(field(record, "audio_included")?.boolean(), Some(false));
        assert_eq!(fs::read(fixture.output.join("source.mp4"))?, fixture.source);
        assert_eq!(fixture.journals()?, journals);
        let expected = text(&exported, "export_root")?;
        fs::rename(
            &fixture.root,
            fixture.directory.0.join("deployment-offline"),
        )?;
        let verified = success(&execute(&fixture.verify_args(expected))?)?;
        assert_eq!(text(&verified, "status")?, "verified_original_media");
        assert_eq!(
            text(&verified, "media_digest")?,
            ContentDigest::sha256(&fixture.source).to_text()
        );
        assert!(!fixture.root.exists());
    }
    Ok(())
}

#[test]
fn reviewed_native_avc_and_hevc_exports_keep_original_video_and_operator_assertions_separate()
-> Test {
    let _guard = SERIAL.lock().map_err(|_| "test lock poisoned")?;
    const REVIEWER: &str = "principal:private-native-reviewer";
    const REASON: &str = "Private synthetic-case rationale excluded from the recipient package";
    for (codec, disposition, state) in [
        (RtspImportCodec::Avc, "investigate", "indeterminate"),
        (RtspImportCodec::Hevc, "reject", "rejected"),
    ] {
        let mut fixture = Fixture::native(codec)?;
        let original = fixture.review_show()?;
        let review = fixture.review(disposition, REVIEWER, REASON)?;
        let reviews = [review];
        let journals = fixture.journals()?;
        let exported = fixture.publish()?;
        assert_eq!(
            text(&exported, "profile")?,
            "event-reviewed-original-media-whole-source-v2"
        );
        assert_reviewed_record(
            field(&exported, "record")?,
            field(&original, "result")?,
            &reviews,
            state,
        )?;
        assert_eq!(fs::read(fixture.output.join("source.mp4"))?, fixture.source);
        for name in ["record.canonical", "record.json"] {
            let bytes = fs::read(fixture.output.join(name))?;
            for private in [REVIEWER, REASON] {
                assert!(
                    !bytes
                        .windows(private.len())
                        .any(|part| part == private.as_bytes()),
                    "recipient {name} must not disclose private review attribution or rationale"
                );
            }
        }

        // Source export may follow verified review lineage. Native replay must still refuse
        // to present the operator's successor as the original sensor computation.
        let native_read = execute_binary(
            env!("CARGO_BIN_EXE_fss-event"),
            &[
                "read".into(),
                "--root".into(),
                fixture.root.as_os_str().to_owned(),
                "--site".into(),
                SITE.into(),
                "--event-id".into(),
                fixture.event_id.as_str().into(),
            ],
        )?;
        refused(&native_read);
        assert!(
            String::from_utf8_lossy(&native_read.stderr)
                .contains("unsupported_long_event_replay_profile")
        );
        assert_eq!(fixture.journals()?, journals);
        let root = text(&exported, "export_root")?;
        fs::rename(
            &fixture.root,
            fixture.directory.0.join("reviewed-deployment-offline"),
        )?;
        let verified = success(&execute(&fixture.verify_args(root))?)?;
        assert_eq!(text(&verified, "status")?, "verified_original_media");
        assert_eq!(
            text(&verified, "profile")?,
            "event-reviewed-original-media-whole-source-v2"
        );
        assert_eq!(field(&verified, "record")?, field(&exported, "record")?);
        assert_eq!(
            text(&verified, "media_digest")?,
            ContentDigest::sha256(&fixture.source).to_text()
        );
        assert!(!fixture.root.exists());
    }
    Ok(())
}

#[test]
fn successive_operator_reviews_require_fresh_export_approval_and_preserve_the_complete_chain()
-> Test {
    let _guard = SERIAL.lock().map_err(|_| "test lock poisoned")?;
    let mut fixture = Fixture::new("review-chain")?;
    let original = fixture.review_show()?;
    let unreviewed_preview = fixture.preview()?;
    let before_review = approved(
        fixture.args(),
        text(&unreviewed_preview, "approval_digest")?,
    );
    let first = fixture.review(
        "investigate",
        "principal:first-private-reviewer",
        "Initial synthetic-case review remains unresolved",
    )?;
    let intermediate = fixture.preview()?;
    let before_resolution = approved(fixture.args(), text(&intermediate, "approval_digest")?);
    let second = fixture.review(
        "investigate",
        "principal:second-private-reviewer",
        "Independent operator investigation continues without new sensor support",
    )?;
    let third = fixture.review(
        "resolve",
        "principal:third-private-reviewer",
        "Owner closes the synthetic case without asserting scene truth",
    )?;
    let reviews = [first, second, third];
    let journals = fixture.journals()?;
    for obsolete in [before_review, before_resolution] {
        refused(&execute(&obsolete)?);
        assert!(!fixture.output.exists());
    }
    // Replacing the old command's revision with the current one cannot transfer its approval.
    refused(&execute(&approved(
        fixture.args(),
        text(&unreviewed_preview, "approval_digest")?,
    ))?);
    assert!(!fixture.output.exists());
    let preview = fixture.preview()?;
    assert_reviewed_record(
        field(&preview, "record")?,
        field(&original, "result")?,
        &reviews,
        "resolved",
    )?;
    let args = approved(fixture.args(), text(&preview, "approval_digest")?);
    let exported = success(&execute(&args)?)?;
    assert_eq!(text(&exported, "status")?, "exported_original_media");
    assert_eq!(
        field(&exported, "export_root")?,
        field(&preview, "export_root")?
    );
    assert_eq!(
        fs::read(fixture.output.join("source.mjpeg"))?,
        fixture.source
    );
    let package = package_snapshot(&fixture.output)?;
    assert_eq!(
        text(&success(&execute(&args)?)?, "status")?,
        "already_exported_original_media"
    );
    assert_eq!(package_snapshot(&fixture.output)?, package);
    assert_eq!(fixture.journals()?, journals);
    fs::rename(
        &fixture.root,
        fixture.directory.0.join("resolved-deployment-offline"),
    )?;
    let verified = success(&execute(
        &fixture.verify_args(text(&exported, "export_root")?),
    )?)?;
    assert_eq!(text(&verified, "status")?, "verified_original_media");
    assert_reviewed_record(
        field(&verified, "record")?,
        field(&original, "result")?,
        &reviews,
        "resolved",
    )?;
    Ok(())
}

#[test]
fn missing_or_corrupted_earlier_review_custody_refuses_export_without_repair_or_output() -> Test {
    let _guard = SERIAL.lock().map_err(|_| "test lock poisoned")?;
    let mut fixture = Fixture::new("review-custody")?;
    let first = fixture.review(
        "investigate",
        "principal:review-one",
        "First exact assertion",
    )?;
    let middle = fixture.review(
        "investigate",
        "principal:review-two",
        "Second exact assertion",
    )?;
    fixture.review("resolve", "principal:review-three", "Final exact assertion")?;
    let preview = fixture.preview()?;
    let approved_args = approved(fixture.args(), text(&preview, "approval_digest")?);
    let mut objects = Vec::new();
    fixture.update(|deployment, _| {
        for digest in [
            first.statement_digest,
            first.statement_root,
            middle.statement_digest,
            middle.statement_root,
        ] {
            objects.push(deployment.publisher().spool().object_path(digest));
        }
        Ok(())
    })?;
    let journals = fixture.journals()?;
    for path in objects {
        let original = fs::read(&path)?;
        let mut changed = original.clone();
        *changed.last_mut().ok_or("empty retained review object")? ^= 1;
        fs::write(&path, changed)?;
        for missing in [false, true] {
            if missing {
                fs::remove_file(&path)?;
            }
            refused(&execute(&approved_args)?);
            refused(&execute(&fixture.args())?);
            assert!(!fixture.output.exists());
            assert_eq!(fixture.journals()?, journals);
            if missing {
                assert!(
                    !path.exists(),
                    "failed export must not recreate missing review custody"
                );
            }
        }
        fs::write(&path, original)?;
        let restored = fixture.preview()?;
        assert_eq!(
            field(&restored, "approval_digest")?,
            field(&preview, "approval_digest")?
        );
    }
    let exported = success(&execute(&approved_args)?)?;
    assert_eq!(text(&exported, "status")?, "exported_original_media");
    assert_eq!(
        fs::read(fixture.output.join("source.mjpeg"))?,
        fixture.source
    );
    assert_eq!(fixture.journals()?, journals);
    Ok(())
}

#[test]
fn a_new_event_revision_invalidates_an_already_previewed_original_export() -> Test {
    let _guard = SERIAL.lock().map_err(|_| "test lock poisoned")?;
    let fixture = Fixture::new("revision")?;
    let preview = fixture.preview()?;
    fixture.update(|deployment, cx| {
        let (mut event, _) = deployment.current_event_authority(&fixture.event_id)?;
        event.supersedes = Some(event.revision_digest());
        event.revision = 2;
        deployment.publish_event(
            &ReferencePolicyDecision {
                event,
                action: ReferencePolicyAction::Hold,
            },
            cx,
        )?;
        Ok(())
    })?;
    let journals = fixture.journals()?;
    refused(&execute(&approved(
        fixture.args(),
        text(&preview, "approval_digest")?,
    ))?);
    refused(&execute(&fixture.args())?);
    assert!(!fixture.output.exists());
    assert_eq!(fixture.journals()?, journals);
    Ok(())
}

#[test]
fn a_valid_retained_source_from_another_camera_cannot_be_substituted_for_event_media() -> Test {
    let _guard = SERIAL.lock().map_err(|_| "test lock poisoned")?;
    let fixture = Fixture::new("unrelated-source")?;
    let mut unrelated = None;
    fixture.update(|deployment, cx| {
        let input = fixture.directory.0.join("another-camera.mjpeg");
        fs::write(&input, &fixture.source)?;
        let request = FileIngestRequest::new(
            &input,
            SensorId::parse("sensor:unrelated-original-media-camera")?,
            StreamId::parse("stream:unrelated-original-media-camera")?,
        )
        .with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?)
        .with_receive_time(TimestampNs(1_000_000_000_000));
        let imported = FileIngestAdapter::ingest(request, cx, deployment)?;
        fs::remove_file(input)?;
        let retained = RetainedFileImport::open(
            deployment,
            imported.import_identity,
            RetainedReadLimits::default(),
            cx,
        )?;
        unrelated = Some((retained.import_identity(), retained.import_root()));
        Ok(())
    })?;
    let (identity, import_root) = unrelated.ok_or("second real import missing")?;
    assert_ne!(identity, fixture.identity);
    let journals = fixture.journals()?;
    let preview = fixture.preview()?;
    let mut wrong_source = fixture.args();
    replace(&mut wrong_source, "--import-identity", identity.to_text())?;
    replace(
        &mut wrong_source,
        "--expected-import-root",
        import_root.to_text(),
    )?;
    refused(&execute(&wrong_source)?);
    refused(&execute(&approved(
        wrong_source,
        text(&preview, "approval_digest")?,
    ))?);
    assert!(!fixture.output.exists());
    assert_eq!(fixture.journals()?, journals);
    Ok(())
}

#[test]
fn a_mask_declared_after_preview_prevents_raw_export_even_with_old_approval() -> Test {
    let _guard = SERIAL.lock().map_err(|_| "test lock poisoned")?;
    let fixture = Fixture::new("mask")?;
    let preview = fixture.preview()?;
    fixture.update(|deployment, cx| {
        let policy = PrivacyMaskPolicy::new(SensorId::parse(SENSOR)?, [48, 32], &[[40, 0, 8, 32]])?;
        let approval = preview_mask(deployment, &policy)?.approval;
        declare_mask(deployment, &policy, approval, cx)?;
        Ok(())
    })?;
    let journals = fixture.journals()?;
    refused(&execute(&approved(
        fixture.args(),
        text(&preview, "approval_digest")?,
    ))?);
    refused(&execute(&fixture.args())?);
    assert!(!fixture.output.exists());
    assert_eq!(fixture.journals()?, journals);
    Ok(())
}

#[test]
fn corrupted_or_missing_retained_source_is_refused_before_output() -> Test {
    let _guard = SERIAL.lock().map_err(|_| "test lock poisoned")?;
    let fixture = Fixture::new("source-corruption")?;
    let preview = fixture.preview()?;
    let args = approved(fixture.args(), text(&preview, "approval_digest")?);
    let original = fs::read(&fixture.source_chunk)?;
    let mut altered = original.clone();
    let byte = altered.last_mut().ok_or("empty source chunk")?;
    *byte ^= 1;
    fs::write(&fixture.source_chunk, altered)?;
    let journals = fixture.journals()?;
    refused(&execute(&args)?);
    refused(&execute(&fixture.args())?);
    assert!(!fixture.output.exists());
    fs::remove_file(&fixture.source_chunk)?;
    refused(&execute(&args)?);
    assert!(!fixture.output.exists());
    assert_eq!(fixture.journals()?, journals);
    fs::write(&fixture.source_chunk, original)?;
    assert_eq!(
        text(&success(&execute(&args)?)?, "status")?,
        "exported_original_media"
    );
    Ok(())
}

#[test]
fn destination_parent_substitution_and_partial_packages_never_overwrite() -> Test {
    let _guard = SERIAL.lock().map_err(|_| "test lock poisoned")?;
    let mut fixture = Fixture::new("destination")?;
    let parent = fixture.directory.0.join("approved-parent");
    fs::create_dir(&parent)?;
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))?;
    fixture.output = parent.join("package");
    let preview = fixture.preview()?;
    let approved_args = approved(fixture.args(), text(&preview, "approval_digest")?);
    fs::rename(&parent, fixture.directory.0.join("original-parent"))?;
    fs::create_dir(&parent)?;
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))?;
    refused(&execute(&approved_args)?);
    assert!(
        !fixture.output.exists(),
        "same path on another parent inode is not approved"
    );

    let fresh = fixture.preview()?;
    let fresh_args = approved(fixture.args(), text(&fresh, "approval_digest")?);
    fs::create_dir(&fixture.output)?;
    fs::set_permissions(&fixture.output, fs::Permissions::from_mode(0o700))?;
    let sentinel = fixture.output.join("source.mjpeg");
    fs::write(&sentinel, b"preexisting private work")?;
    refused(&execute(&fresh_args)?);
    assert_eq!(fs::read(&sentinel)?, b"preexisting private work");
    assert!(!fixture.output.join("COMPLETE.json").exists());
    assert_eq!(fs::read_dir(&fixture.output)?.count(), 1);

    // A symlink cannot turn an already approved destination into another writable directory.
    fs::rename(&fixture.output, parent.join("preexisting-package"))?;
    let elsewhere = fixture.directory.0.join("unapproved-directory");
    fs::create_dir(&elsewhere)?;
    symlink(&elsewhere, &fixture.output)?;
    refused(&execute(&fresh_args)?);
    assert_eq!(fs::read_dir(elsewhere)?.count(), 0);
    Ok(())
}

#[test]
fn offline_verification_refuses_wrong_trust_recipient_expiry_or_changed_package_bytes() -> Test {
    let _guard = SERIAL.lock().map_err(|_| "test lock poisoned")?;
    let fixture = Fixture::new("offline-refusals")?;
    let exported = fixture.publish()?;
    let root = text(&exported, "export_root")?;
    let baseline = package_snapshot(&fixture.output)?;
    let original_args = fixture.verify_args(root);
    assert_eq!(
        text(&success(&execute(&original_args)?)?, "status")?,
        "verified_original_media"
    );
    let wrong = ContentDigest::sha256(b"untrusted replacement root").to_text();
    for (key, value) in [
        ("--export-root", wrong.as_str()),
        ("--recipient", "recipient:somebody-else"),
        ("--attested-now-ns", "2000000000000:2000000000000"),
        ("--attested-now-ns", "1999999999999:2000000000000"),
        ("--attested-now-ns", "1000000000021:1000000000020"),
    ] {
        let mut args = original_args.clone();
        replace(&mut args, key, value)?;
        refused(&execute(&args)?);
        assert_eq!(package_snapshot(&fixture.output)?, baseline);
    }
    for name in [
        "source.mjpeg",
        "record.canonical",
        "manifest.canonical",
        "record.json",
        "COMPLETE.json",
    ] {
        let path = fixture.output.join(name);
        let original = fs::read(&path)?;
        let mut changed = original.clone();
        let byte = changed.last_mut().ok_or("empty package child")?;
        *byte ^= 1;
        fs::write(&path, changed)?;
        refused(&execute(&original_args)?);
        let damaged = package_snapshot(&fixture.output)?;
        // A complete-looking but corrupt destination is not a valid idempotent retry either.
        refused(&execute(&approved(
            fixture.args(),
            text(&exported, "approval_digest")?,
        ))?);
        assert_eq!(package_snapshot(&fixture.output)?, damaged);
        fs::write(&path, original)?;
    }
    fs::remove_file(fixture.output.join("COMPLETE.json"))?;
    refused(&execute(&original_args)?);
    let incomplete = package_snapshot(&fixture.output)?;
    refused(&execute(&approved(
        fixture.args(),
        text(&exported, "approval_digest")?,
    ))?);
    assert_eq!(package_snapshot(&fixture.output)?, incomplete);
    Ok(())
}

enum NativePlan {
    Avc(PreparedRecording),
    Hevc(PreparedHevcRecording),
}
impl NativePlan {
    fn plan(&self) -> &PreparedRecording {
        match self {
            Self::Avc(plan) => plan,
            Self::Hevc(plan) => plan.publication_plan(),
        }
    }
}

struct NativePacket {
    sequence: u64,
    received_ns: u64,
    bytes: Vec<u8>,
}
fn native_packet(
    sequence: u16,
    pt: u8,
    timestamp: u32,
    marker: bool,
    payload: &[u8],
) -> NativePacket {
    let mut bytes = vec![0x80, pt | if marker { 128 } else { 0 }];
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&timestamp.to_be_bytes());
    bytes.extend_from_slice(&7_u32.to_be_bytes());
    bytes.extend_from_slice(payload);
    NativePacket {
        sequence: u64::from(sequence),
        received_ns: 100 + u64::from(sequence),
        bytes,
    }
}
fn native_scope() -> Test<RecordingScope> {
    Ok(RecordingScope {
        sensor: SensorId::parse(SENSOR)?,
        stream: StreamId::parse("stream:original-media-native-test")?,
        generation: 1,
        anchor: ContentDigest::sha256(b"explicit native fixture owner"),
        receive_clock: ContentDigest::sha256(b"explicit native fixture receive clock"),
    })
}
fn borrowed_native(packets: &[NativePacket]) -> Vec<RecordingPacket<'_>> {
    packets
        .iter()
        .map(|p| RecordingPacket {
            sequence: p.sequence,
            received_ns: p.received_ns,
            bytes: &p.bytes,
        })
        .collect()
}
fn rtp_timestamp(sample: &fss_container::demux::AvcSample, scale: u32) -> Test<u32> {
    let n = sample
        .presentation_time()
        .checked_mul(90_000)
        .ok_or("RTP overflow")?;
    if n < 0 || n % i128::from(scale) != 0 {
        return Err("fixture requires exact positive 90 kHz presentation ticks".into());
    }
    Ok(u32::try_from(n / i128::from(scale))?)
}
fn native_plan(codec: RtspImportCodec) -> Test<NativePlan> {
    let bytes: &[u8] = match codec {
        RtspImportCodec::Avc => {
            include_bytes!("../../fss-reference/tests/fixtures/long_dwell_h264/square_300.mp4")
        }
        RtspImportCodec::Hevc => {
            include_bytes!("../../fss-reference/tests/fixtures/hevc_ingest/watch_96x48_moving.mp4")
        }
    };
    let parsed = AvcMp4::parse(bytes, None, DemuxLimits::default())?;
    match codec {
        RtspImportCodec::Avc => {
            assert_eq!(parsed.codec(), VideoCodec::Avc);
            let limits = AvcReceiveLimits::default();
            let sets = parsed
                .parameter_sets()
                .iter()
                .map(|r| &bytes[r.clone()])
                .collect::<Vec<_>>();
            let sps_nal = sets
                .iter()
                .copied()
                .find(|n| n[0] & 31 == 7)
                .ok_or("AVC SPS")?;
            let pps_nal = sets
                .iter()
                .copied()
                .find(|n| n[0] & 31 == 8)
                .ok_or("AVC PPS")?;
            let sps = parse_sps(sps_nal, limits.syntax)?;
            let pps = parse_pps(pps_nal, &sps, limits.syntax)?;
            let key = StreamKey {
                ingress: 7001,
                generation: 1,
                ssrc: 7,
            };
            let mut receiver =
                AvcReceiver::new(key, 96, H264Mode::NonInterleaved, limits, (sps, pps))?;
            // 13 coding samples = IDR + four complete P/B/B groups. Native sample
            // composition offsets preserve the original display order (B frames present).
            let samples = &parsed.samples()[..13];
            let first_ts = rtp_timestamp(&samples[0], parsed.timescale())?;
            let probation = native_packet(0, 96, first_ts, false, sps_nal);
            receiver.ingest(key, &probation.bytes, probation.received_ns)?;
            let mut packets = Vec::new();
            let mut pictures = Vec::new();
            let mut seq = 1_u16;
            for nal in [sps_nal, pps_nal] {
                let p = native_packet(seq, 96, first_ts, false, nal);
                receiver.ingest(key, &p.bytes, p.received_ns)?;
                drain_native_avc(&mut receiver, p.received_ns, &mut pictures)?;
                packets.push(p);
                seq = seq.checked_add(1).ok_or("RTP sequence overflow")?;
            }
            for sample in samples {
                let payload = &bytes[sample.source.clone()];
                let nals = length_prefixed_nals(payload, parsed.nal_length_bytes())?;
                let ts = rtp_timestamp(sample, parsed.timescale())?;
                for (i, range) in nals.iter().enumerate() {
                    let p =
                        native_packet(seq, 96, ts, i + 1 == nals.len(), &payload[range.clone()]);
                    receiver.ingest(key, &p.bytes, p.received_ns)?;
                    drain_native_avc(&mut receiver, p.received_ns, &mut pictures)?;
                    packets.push(p);
                    seq = seq.checked_add(1).ok_or("RTP sequence overflow")?;
                }
            }
            assert_eq!(pictures.len(), samples.len());
            let timed = pictures
                .iter()
                .zip(samples)
                .map(|(picture, sample)| {
                    Ok(TimedAvcPicture {
                        picture,
                        decode_time: sample.decode_time,
                        duration: sample.duration,
                        composition_offset: i32::try_from(sample.composition_offset)?,
                    })
                })
                .collect::<Test<Vec<_>>>()?;
            Ok(NativePlan::Avc(prepare_recording(
                native_scope()?,
                parsed.timescale(),
                &timed,
                &borrowed_native(&packets),
            )?))
        }
        RtspImportCodec::Hevc => {
            assert_eq!(parsed.codec(), VideoCodec::Hevc);
            let sets = parsed
                .parameter_sets()
                .iter()
                .map(|r| &bytes[r.clone()])
                .collect::<Vec<_>>();
            let vps = sets
                .iter()
                .copied()
                .find(|n| (n[0] >> 1) & 63 == 32)
                .ok_or("HEVC VPS")?;
            let sps = sets
                .iter()
                .copied()
                .find(|n| (n[0] >> 1) & 63 == 33)
                .ok_or("HEVC SPS")?;
            let pps = sets
                .iter()
                .copied()
                .find(|n| (n[0] >> 1) & 63 == 34)
                .ok_or("HEVC PPS")?;
            let configuration =
                HevcConfiguration::parse(vps, sps, pps, HevcConfigurationLimits::default())?;
            let mut packets = Vec::new();
            let mut seq = 1_u16;
            let mut last_ts = 0_u32;
            // Configuration is supplied out of band and does not invent RTP spans;
            // in-band parameter sets, if present in fixture samples, remain original.
            for sample in parsed.samples() {
                let payload = &bytes[sample.source.clone()];
                let nals = length_prefixed_nals(payload, parsed.nal_length_bytes())?;
                last_ts = rtp_timestamp(sample, parsed.timescale())?;
                for (i, range) in nals.iter().enumerate() {
                    packets.push(native_packet(
                        seq,
                        98,
                        last_ts,
                        i + 1 == nals.len(),
                        &payload[range.clone()],
                    ));
                    seq = seq.checked_add(1).ok_or("RTP sequence overflow")?;
                }
            }
            // Explicit fixture sender EOS: observed original RTP boundary witness,
            // retained with source but not fabricated into exported media samples.
            packets.push(native_packet(seq, 98, last_ts, true, &[0x48, 1, 0x80]));
            let timings = parsed
                .samples()
                .iter()
                .map(|sample| {
                    Ok(HevcRecordingTiming {
                        decode_time: sample.decode_time,
                        duration: sample.duration,
                        composition_offset: i32::try_from(sample.composition_offset)?,
                    })
                })
                .collect::<Test<Vec<_>>>()?;
            assert_eq!(timings.len(), 14);
            Ok(NativePlan::Hevc(prepare_hevc_recording(
                native_scope()?,
                &configuration,
                parsed.timescale(),
                &timings,
                &borrowed_native(&packets),
            )?))
        }
    }
}
fn drain_native_avc(receiver: &mut AvcReceiver, now: u64, out: &mut Vec<AvcPictureGroup>) -> Test {
    for _ in 0..1024 {
        match receiver.poll(now)? {
            AvcReceivePoll::Source {
                gap_before: false,
                picture: None,
                fragment: None,
                ..
            } => {}
            AvcReceivePoll::Assembly(AvcAssemblyStep::Accepted(output)) => {
                if output.retired.is_some() {
                    return Err("native AVC fixture retired".into());
                }
                if let Some(p) = output.picture {
                    out.push(p);
                }
            }
            AvcReceivePoll::Picture(p) => out.push(p),
            AvcReceivePoll::Pending { .. } => return Ok(()),
            other => return Err(format!("native AVC fixture refusal: {other:?}").into()),
        }
    }
    Err("native AVC fixture poll bound".into())
}
