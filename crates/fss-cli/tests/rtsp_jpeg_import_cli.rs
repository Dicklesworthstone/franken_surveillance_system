#![forbid(unsafe_code)]
//! Actual RTP/JPEG source custody -> offline import -> retained native JPEG decode.
//! The checked-in image is a codec oracle, not camera/field-quality qualification.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_cli::json_input::{Value, parse};
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeLimits, decode_luma};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, SensorId};
use fss_geometry::WorkBudget;
use fss_object::SpoolLimits;
use fss_packet::StreamKey;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel};
use fss_reference::ingest::privacy_mask::{
    MASK_FILL_LUMA, PrivacyMaskPolicy, declare_mask, preview_mask,
};
use fss_reference::rtsp::datagram_archive::{
    DatagramArchive, DatagramArchiveLimits, DatagramPin, DatagramScope,
};
use fss_reference::rtsp::framed::RtspWireIntake;
use fss_reference::rtsp::tcp::{TcpBinding, TcpSecurityPolicy};
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:rtsp-jpeg-import-cli";
const JPEG: &[u8] =
    include_bytes!("../../fss-codec-mjpeg/tests/fixtures/rtp_jpeg/422_32x24_q50_rst0.jpg");

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..128 {
            let path = std::env::temp_dir().join(format!(
                "fss-jpeg-import-cli-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
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

fn scan() -> Test<&'static [u8]> {
    let mut at = 2;
    while at < JPEG.len() {
        let marker = JPEG.get(at..at + 4).ok_or("short fixture marker")?;
        let end = at + 2 + usize::from(u16::from_be_bytes([marker[2], marker[3]]));
        JPEG.get(at..end).ok_or("short fixture segment")?;
        if marker[1] == 0xda {
            return Ok(&JPEG[end..]);
        }
        at = end;
    }
    Err("fixture missing entropy scan".into())
}

fn packet(
    sequence: u16,
    timestamp: u32,
    range: std::ops::Range<usize>,
    marker: bool,
) -> Test<Vec<u8>> {
    let mut out = vec![0x80, 26 | if marker { 0x80 } else { 0 }];
    out.extend(sequence.to_be_bytes());
    out.extend(timestamp.to_be_bytes());
    out.extend(7_u32.to_be_bytes());
    out.extend([
        0,
        (range.start >> 16) as u8,
        (range.start >> 8) as u8,
        range.start as u8,
        0,
        50,
        4,
        3,
    ]);
    out.extend_from_slice(scan()?.get(range).ok_or("fixture scan range")?);
    Ok(out)
}

struct Fixture {
    directory: Directory,
    archive: PathBuf,
    root: PathBuf,
    scope: DatagramScope,
    pin: DatagramPin,
    original_payload: ContentDigest,
}
impl Fixture {
    fn new(label: &str, second_frame: bool, partial_tail: bool) -> Test<Self> {
        let directory = Directory::new(label)?;
        let archive = directory.0.join("source archive");
        let root = directory.0.join("destination");
        let scope = DatagramScope {
            binding: TcpBinding::new(
                StreamKey {
                    ingress: 11,
                    generation: 8,
                    ssrc: 7,
                },
                "127.0.0.1:8554".parse()?,
                "camera.test",
                TcpSecurityPolicy::OwnerApprovedPlaintext,
            )?,
            channels: (0, 1),
            receive_clock: ContentDigest::sha256(b"original parser receive clock"),
            retention_evidence: ContentDigest::sha256(b"original owner RTP and RTCP retention"),
        };
        let limits = DatagramArchiveLimits {
            max_datagrams: 32,
            max_payload_bytes: 1_048_576,
            max_scan_roots: 128,
            max_spool_object_bytes: 65_536,
        };
        let mut source = DatagramArchive::new(scope.clone(), limits)?;
        let mut publisher = LocalRootPublisher::open(
            &archive,
            LocalPublicationLimits::new(
                64,
                2,
                64,
                256,
                SpoolLimits::new(512, 8_388_608, 65_536, 512),
            ),
        )?;
        let size = scan()?.len();
        let first = packet(11, 90_000, 0..size / 2, false)?;
        let mut rtcp = vec![0x80, 201, 0, 1];
        rtcp.extend(7_u32.to_be_bytes());
        let mut originals = vec![
            (0, packet(10, 90_000, 0..size, true)?), // probation is still retained
            (0, first.clone()),
            (0, first), // duplicate is a separate source observation
            (1, rtcp),
            (0, packet(12, 90_000, size / 2..size, true)?),
        ];
        if second_frame {
            originals.push((0, packet(13, 180_000, 0..size, true)?));
        }
        if partial_tail {
            originals.push((
                0,
                packet(
                    if second_frame { 14 } else { 13 },
                    270_000,
                    0..size / 2,
                    false,
                )?,
            ));
        }
        let original_payload = ContentDigest::sha256(&originals[1].1);
        let mut work = WorkBudget::new(100_000_000);
        for (i, (channel, bytes)) in originals.iter().enumerate() {
            let mut wire = vec![b'$', *channel];
            wire.extend(u16::try_from(bytes.len())?.to_be_bytes());
            wire.extend_from_slice(bytes);
            let received = 1_000 + i as u64;
            let mut intake = RtspWireIntake::new();
            intake.ingest(&wire, received)?;
            let frame = intake
                .poll(received)?
                .ok_or("complete native interleaved frame")?;
            let prepared = source.prepare_frame(&frame, &mut work)?;
            source.publish(&prepared, &mut publisher, &NeverCancel, &mut work)?;
        }
        let pin = source.pin();
        drop(publisher);
        Ok(Self {
            directory,
            archive,
            root,
            scope,
            pin,
            original_payload,
        })
    }

    fn args(&self) -> Test<Vec<OsString>> {
        Ok([
            "jpeg",
            "--archive",
            self.archive.to_str().ok_or("UTF-8 archive")?,
            "--root",
            self.root.to_str().ok_or("UTF-8 root")?,
            "--site",
            SITE,
            "--peer",
            "127.0.0.1:8554",
            "--authority",
            "camera.test",
            "--ingress",
            "11",
            "--generation",
            "8",
            "--ssrc",
            "7",
            "--receive-clock",
            &self.scope.receive_clock.to_text(),
            "--retention-evidence",
            &self.scope.retention_evidence.to_text(),
            "--prefix-scope",
            &self.pin.scope.to_text(),
            "--prefix-head",
            &self.pin.head.to_text(),
            "--prefix-datagrams",
            &self.pin.datagrams.to_string(),
            "--prefix-bytes",
            &self.pin.payload_bytes.to_string(),
            "--configuration-evidence",
            &ContentDigest::sha256(b"exact negotiated JPEG configuration").to_text(),
            "--reduced-rtcp",
            "yes",
            "--sensor-id",
            "sensor:physical-jpeg-camera",
            "--stream-id",
            "stream:owner-camera-main",
            "--mapping-evidence",
            &ContentDigest::sha256(b"explicit owner physical camera mapping").to_text(),
            "--receive-time-ns",
            "5000000000",
            "--owner-authorized",
            "yes",
            "--read-originals",
            "yes",
            "--retain-originals",
            "yes",
            "--timeout-ms",
            "600000",
        ]
        .into_iter()
        .map(OsString::from)
        .collect())
    }

    fn journals(&self) -> Test<(Vec<u8>, Vec<u8>)> {
        Ok((
            fs::read(self.root.join("ledger/journal.fssj"))?,
            fs::read(self.root.join("effects/journal.fssj"))?,
        ))
    }
}

fn run(args: &[OsString]) -> Test<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-import-rtsp"))
        .args(args)
        .output()?)
}
fn good(output: Output) -> Test<String> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}
fn value<'a>(document: &'a Value, path: &[&str]) -> Test<&'a Value> {
    let mut at = document;
    for field in path {
        at = at
            .object()
            .and_then(|object| object.get(*field))
            .ok_or_else(|| format!("missing field {field}"))?;
    }
    Ok(at)
}
fn text<'a>(document: &'a Value, path: &[&str]) -> Test<&'a str> {
    value(document, path)?
        .text()
        .ok_or("text field expected".into())
}
fn set(args: &mut Vec<OsString>, key: &str, value: &str) {
    if let Some(index) = args.iter().position(|arg| arg == key) {
        args[index + 1] = value.into();
    } else {
        args.extend([key.into(), value.into()]);
    }
}
fn approved(args: &[OsString]) -> Test<(Vec<OsString>, String)> {
    let preview = good(run(args)?)?;
    let parsed = parse(&preview)?;
    let mut args = args.to_vec();
    args.extend([
        "--approve".into(),
        text(&parsed, &["approval_digest"])?.into(),
    ]);
    Ok((args, preview))
}
fn fixture_output(name: &str, bytes: &[u8]) -> Test {
    if let Some(path) = std::env::var_os("FSS_RTSP_JPEG_IMPORT_FIXTURE_DIR") {
        let directory = PathBuf::from(path);
        fs::create_dir_all(&directory)?;
        fs::write(directory.join(name), bytes)?;
    }
    Ok(())
}
fn file(root: &Path, command: &str, identity: &str) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fss-file"));
    cmd.arg(command)
        .arg("--root")
        .arg(root)
        .args(["--site", SITE, "--import-id", identity]);
    cmd
}

#[test]
fn complete_original_prefix_imports_retries_and_decodes_after_the_source_archive_is_offline() -> Test
{
    let fixture = Fixture::new("cold", true, false)?;
    let args = fixture.args()?;
    let (approved, preview) = approved(&args)?;
    assert!(
        !fixture.root.exists(),
        "pure preview initialized destination custody"
    );
    fixture_output("preview.json", preview.as_bytes())?;
    let mut wrong = args;
    set(
        &mut wrong,
        "--approve",
        &ContentDigest::sha256(b"not this plan").to_text(),
    );
    let refused = run(&wrong)?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("ERR-RTSP-JPEG-IMPORT-APPROVAL-001"));
    assert!(!fixture.root.exists());

    let imported = good(run(&approved)?)?;
    fixture_output("imported.json", imported.as_bytes())?;
    let report = parse(&imported)?;
    assert_eq!(value(&report, &["frames"])?.integer(), Some(2));
    assert_eq!(text(&report, &["capture_time_label"])?, "unknown");
    assert_eq!(value(&report, &["pixels_decoded"])?.boolean(), Some(false));
    assert_eq!(
        value(&report, &["entropy_validated"])?.boolean(),
        Some(false)
    );
    assert_eq!(
        value(&report, &["accounting", "rtp_datagrams"])?.integer(),
        Some(5)
    );
    assert_eq!(
        value(&report, &["accounting", "rtcp_datagrams"])?.integer(),
        Some(1)
    );
    assert_eq!(text(&report, &["ending"])?, "pinned_prefix");
    assert_eq!(
        value(&report, &["source_prefix_exhaustion_is_eof"])?.boolean(),
        Some(false)
    );
    let identity = text(&report, &["import_identity"])?;
    let before = fixture.journals()?;
    let retried = good(run(&approved)?)?;
    fixture_output("retried.json", retried.as_bytes())?;
    let retry = parse(&retried)?;
    assert_eq!(text(&retry, &["import_identity"])?, identity);
    assert_eq!(
        text(&retry, &["origin_proof"])?,
        text(&report, &["origin_proof"])?
    );
    assert_eq!(value(&retry, &["reused"])?.boolean(), Some(true));
    assert_eq!(
        fixture.journals()?,
        before,
        "retry changed canonical authority/effects"
    );

    fs::rename(
        &fixture.archive,
        fixture.directory.0.join("offline original archive"),
    )?;
    let verified = good(file(&fixture.root, "verify", identity).output()?)?;
    assert!(verified.contains("media_format=mjpeg"));
    assert!(verified.contains("segment_count=2"));
    assert!(verified.contains("capture_time_class=unknown"));
    assert!(verified.contains("absence_certifiable=false"));
    let decoded = good(
        file(&fixture.root, "decode", identity)
            .args(["--segment", "0", "--interpretation", "ycbcr"])
            .output()?,
    )?;
    let expected = decode_luma(
        JPEG,
        ContentDigest::sha256(JPEG).bytes(),
        ComponentInterpretation::YCbCr,
        DecodeLimits::default(),
        &mut DecodeBudget::new(20_000_000),
    )?;
    assert!(decoded.contains(&format!(
        "luma_sha256={}",
        ContentDigest::sha256(expected.pixels())
    )));
    assert!(decoded.contains("width=32\nheight=24"));
    assert!(decoded.contains("source_sensor_id=sensor:physical-jpeg-camera"));
    assert!(decoded.contains("source_stream_id=stream:owner-camera-main"));
    assert!(decoded.contains("capture_earliest_ns=0"));
    assert!(decoded.contains("capture_latest_ns=5000000000"));
    assert!(decoded.contains("decode_complete=true"));
    assert_eq!(
        fixture.journals()?.1,
        before.1,
        "offline decode dispatched a physical effect"
    );
    let cx = context(&fixture.root)?;
    let mut deployment = ReferenceDeployment::reopen(&fixture.root, SITE, &cx)?;
    let policy = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:physical-jpeg-camera")?,
        [32, 24],
        &[[0, 0, 32, 24]],
    )?;
    let approval = preview_mask(&deployment, &policy)?.approval;
    declare_mask(&mut deployment, &policy, approval, &cx)?;
    drop(deployment);
    cx.drain_and_finalize();
    let masked = good(
        file(&fixture.root, "decode", identity)
            .args(["--segment", "0", "--interpretation", "ycbcr"])
            .output()?,
    )?;
    assert!(masked.contains(&format!("privacy_mask_policy={}", policy.digest())));
    assert!(masked.contains(&format!(
        "luma_sha256={}",
        ContentDigest::sha256(&[MASK_FILL_LUMA; 32 * 24]),
    )));
    let missing = run(&approved)?;
    assert!(!missing.status.success());
    assert!(missing.stdout.is_empty());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("ERR-RTSP-JPEG-IMPORT-SOURCE-001"));
    assert!(
        !fixture.archive.exists(),
        "retry recreated missing original storage"
    );
    Ok(())
}

#[test]
fn partial_tail_is_retained_and_reported_without_inventing_an_extra_frame_or_eof() -> Test {
    let fixture = Fixture::new("tail", false, true)?;
    let (args, _) = approved(&fixture.args()?)?;
    let imported = good(run(&args)?)?;
    fixture_output("partial-tail.json", imported.as_bytes())?;
    let report = parse(&imported)?;
    assert_eq!(value(&report, &["frames"])?.integer(), Some(1));
    assert_eq!(value(&report, &["prefix", "datagrams"])?.integer(), Some(6));
    assert_eq!(
        value(&report, &["source_prefix_exhaustion_is_eof"])?.boolean(),
        Some(false)
    );
    assert!(
        value(&report, &["terminal", "fragment", "bytes"])?
            .integer()
            .is_some_and(|bytes| bytes > 0)
    );
    assert_eq!(
        value(&report, &["terminal", "fragment", "first_sequence"])?.integer(),
        Some(13)
    );
    assert_eq!(text(&report, &["capture_time_label"])?, "unknown");
    let verified = good(
        file(
            &fixture.root,
            "verify",
            text(&report, &["import_identity"])?,
        )
        .output()?,
    )?;
    assert!(verified.contains("segment_count=1"));
    Ok(())
}

#[test]
fn complete_selection_limits_refuse_instead_of_publishing_an_accepted_prefix() -> Test {
    let fixture = Fixture::new("limits", true, false)?;
    for (index, (key, bound)) in [
        ("--max-frames", "1"),
        ("--max-media-bytes", "1"),
        ("--max-original-bytes", "1"),
        ("--max-read-bytes", "1"),
        ("--max-steps", "1"),
        ("--max-work", "1"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut args = fixture.args()?;
        let root = fixture.directory.0.join(format!("limited-{index}"));
        set(
            &mut args,
            "--root",
            root.to_str().ok_or("UTF-8 fixture path")?,
        );
        set(&mut args, key, bound);
        let (args, _) = approved(&args)?;
        let refused = run(&args)?;
        assert!(!refused.status.success(), "{key} released a partial import");
        assert!(refused.stdout.is_empty(), "{key} released a success prefix");
        assert!(
            String::from_utf8_lossy(&refused.stderr).contains("ERR-RTSP-JPEG-IMPORT-"),
            "{key}"
        );
    }
    let (unlimited, _) = approved(&fixture.args()?)?;
    let successful = parse(&good(run(&unlimited)?)?)?;
    assert_eq!(value(&successful, &["frames"])?.integer(), Some(2));
    Ok(())
}

#[test]
fn missing_store_wrong_pin_and_nested_alias_never_become_a_successful_import() -> Test {
    let fixture = Fixture::new("source-refusals", false, false)?;
    let mut args = fixture.args()?;
    let missing = fixture.directory.0.join("absent archive");
    set(
        &mut args,
        "--archive",
        missing.to_str().ok_or("fixture path")?,
    );
    let (args, _) = approved(&args)?;
    let refused = run(&args)?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    assert!(!missing.exists());
    assert!(!fixture.root.exists());
    let mut args = fixture.args()?;
    set(
        &mut args,
        "--prefix-head",
        &ContentDigest::sha256(b"wrong prefix head").to_text(),
    );
    let (args, _) = approved(&args)?;
    let refused = run(&args)?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    #[cfg(unix)]
    {
        let alias = fixture.directory.0.join("archive alias");
        std::os::unix::fs::symlink(&fixture.archive, &alias)?;
        let nested = alias.join("destination");
        let mut args = fixture.args()?;
        set(&mut args, "--root", nested.to_str().ok_or("fixture path")?);
        let (args, _) = approved(&args)?;
        let refused = run(&args)?;
        assert!(!refused.status.success());
        assert!(
            String::from_utf8_lossy(&refused.stderr).contains("ERR-RTSP-JPEG-IMPORT-REQUEST-001")
        );
        assert!(!nested.exists());
    }
    Ok(())
}

fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:jpeg-import-custody-test".into(),
        operation_id: OperationId::parse("operation:jpeg-import-custody-test")?,
        principal: "principal:local-operator".into(),
        capabilities: vec![
            "ADP-REPLAY-001".into(),
            "CAP-READ-MEDIA-001".into(),
            "CAP-OBJECT-STAGE-001".into(),
            "CAP-OBJECT-PUBLISH-001".into(),
            "CAP-RETENTION-COMMIT-001".into(),
        ],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(512 * 1024 * 1024).build()?,
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

#[test]
fn intact_reconstructed_jpeg_cannot_replace_lost_retained_original_packets() -> Test {
    let fixture = Fixture::new("destination-custody", false, false)?;
    let (args, _) = approved(&fixture.args()?)?;
    let imported = parse(&good(run(&args)?)?)?;
    let identity = text(&imported, &["import_identity"])?;
    let cx = context(&fixture.root)?;
    let deployment = ReferenceDeployment::reopen(&fixture.root, SITE, &cx)?;
    let original_path = deployment
        .publisher()
        .spool()
        .object_path(fixture.original_payload);
    assert!(original_path.is_file());
    drop(deployment);
    cx.drain_and_finalize();
    fs::write(&original_path, b"damaged original RTP source")?;
    let before = fixture.journals()?;
    for action in ["verify", "decode"] {
        let mut command = file(&fixture.root, action, identity);
        if action == "decode" {
            command.args(["--segment", "0", "--interpretation", "ycbcr"]);
        }
        let refused = command.output()?;
        assert!(
            !refused.status.success(),
            "retained source loss was hidden by assembled JPEG"
        );
    }
    let retry = run(&args)?;
    assert!(!retry.status.success());
    assert!(retry.stdout.is_empty());
    assert_eq!(fixture.journals()?, before);
    assert_eq!(fs::read(original_path)?, b"damaged original RTP source");
    Ok(())
}
