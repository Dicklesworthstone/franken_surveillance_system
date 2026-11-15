#![forbid(unsafe_code)]
//! Explicit grammar, finite native dispatch and cold custody before successful output.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId};

use super::*;
use super::super::{Action as FileAction, Options, parse as parse_command, run as run_command};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn args(extra: &[&str]) -> Vec<OsString> {
    [
        "import-ts", "--root", "/unused", "--site", "site:ts-cli",
        "--input", "recording.ts", "--sensor", "sensor:ts-cli",
        "--stream", "stream:ts-cli", "--receive-time-ns", "10000000000",
    ]
    .into_iter()
    .chain(extra.iter().copied())
    .map(OsString::from)
    .collect()
}

fn parsed(argv: &[OsString]) -> Test<Options> {
    parse_command(argv)
        .map_err(|(id, reason)| io::Error::other(format!("{id}: {reason}")))?
        .ok_or_else(|| io::Error::other("expected parsed command").into())
}

fn parsed_action(options: Options) -> Test<Action> {
    match options.action {
        FileAction::ImportTs(action) => Ok(*action),
        _ => Err("import-ts reached another action".into()),
    }
}

#[test]
fn explicit_transport_parser_preserves_bindings_and_capture_assumptions() -> Test {
    let options = parsed(&args(&[]))?;
    assert_eq!(options.limits.max_source_bytes, MAX_SOURCE_BYTES);
    let action = parsed_action(options)?;
    let request = &action.request;
    assert_eq!(request.file.sensor_id.as_str(), "sensor:ts-cli");
    assert_eq!(request.file.stream_id.as_str(), "stream:ts-cli");
    assert_eq!(request.file.receive_time.map(|time| time.0), Some(10_000_000_000));
    assert!(request.file.format_hint.is_none());
    assert!(request.file.rtp_binding.is_none());
    assert!(request.file.capture_hint.is_none());
    assert_eq!(request.selection, TsSelection::default());
    assert_eq!(request.transport_limits.max_input_bytes as u64, MAX_BYTES);
    assert_eq!(request.transport_limits.max_elementary_bytes as u64, MAX_BYTES);
    assert_eq!(request.file.limits.annexb_limits.max_input_bytes as u64, MAX_BYTES);
    assert_eq!(action.work_units, DEFAULT_WORK_UNITS);

    let selected = parsed_action(parsed(&args(&[
        "--ts-program", "65535", "--ts-video-pid", "8190",
        "--max-source-bytes", "8192", "--max-elementary-bytes", "4096",
        "--max-ts-packets", "40", "--max-ts-psi-sections", "2",
        "--max-ts-pes", "1", "--max-ts-pes-bytes", "4096", "--max-ts-spans", "40",
        "--capture-start-ns", "1000000000", "--capture-uncertainty-ns", "1000",
        "--assumed-fps", "30", "--work-units", "4294967296",
    ]))?)?;
    assert_eq!(selected.request.selection, TsSelection { program: Some(65535), video_pid: Some(8190) });
    assert_eq!(selected.request.transport_limits.max_input_bytes, 8192);
    assert_eq!(selected.request.transport_limits.max_elementary_bytes, 4096);
    assert_eq!(selected.request.transport_limits.max_packets, 40);
    assert_eq!(selected.request.transport_limits.max_psi_sections, 2);
    assert_eq!(selected.request.transport_limits.max_pes, 1);
    assert_eq!(selected.request.transport_limits.max_pes_bytes, 4096);
    assert_eq!(selected.request.transport_limits.max_payload_spans, 40);
    assert_eq!(selected.request.file.limits.annexb_limits.max_input_bytes, 4096);
    let hint = selected.request.file.capture_hint.ok_or("capture hint")?;
    assert_eq!(hint.start_ns.0, 1_000_000_000);
    assert_eq!(hint.uncertainty_ns, 1000);
    assert_eq!(hint.assumed_fps, 30.0);
    assert_eq!(selected.work_units, MAX_WORK_UNITS);
    Ok(())
}

#[test]
fn transport_options_reject_cross_protocol_flags_invalid_scope_and_unbounded_work() {
    for (key, value) in [
        ("--media-format", "auto"), ("--media-format", "annexb"),
        ("--rtp-generation", "1"), ("--rtp-ssrc", "7"),
        ("--rtp-payload-type", "96"), ("--rtp-mode", "single-nal"),
        ("--import-id", "sha256:00"), ("--ts-program", "0"),
        ("--ts-program", "65536"), ("--ts-program", "+1"),
        ("--ts-video-pid", "0"), ("--ts-video-pid", "15"),
        ("--ts-video-pid", "8191"), ("--ts-video-pid", "65536"),
        ("--max-source-bytes", "0"), ("--max-source-bytes", "67108865"),
        ("--max-elementary-bytes", "0"), ("--max-elementary-bytes", "67108865"),
        ("--max-ts-packets", "0"), ("--max-ts-packets", "18446744073709551615"),
        ("--max-ts-psi-sections", "0"), ("--max-ts-psi-sections", "65537"),
        ("--max-ts-pes", "0"), ("--max-ts-pes", "65537"),
        ("--max-ts-pes-bytes", "8"), ("--max-ts-pes-bytes", "67108865"),
        ("--max-ts-spans", "0"), ("--max-ts-spans", "18446744073709551615"),
        ("--max-ts-spans", "1.5"), ("--max-ts-pes", " 1"),
        ("--work-units", "-1"), ("--work-units", "+1"),
        ("--work-units", "4294967297"), ("--work-units", "18446744073709551616"),
        ("--capture-start-ns", "0"),
    ] {
        assert!(parse_command(&args(&[key, value])).is_err(), "{key} {value}");
    }
    assert!(parse_command(&args(&["--ts-program", "1", "--ts-program", "2"])).is_err());
    assert!(parse_command(&args(&["--ts-program"])).is_err());
    let mut missing_time = args(&[]);
    missing_time.truncate(missing_time.len() - 2);
    assert!(parse_command(&missing_time).is_err());
    for (key, value) in [
        ("--ts-program", "1"), ("--ts-video-pid", "256"),
        ("--max-elementary-bytes", "1024"), ("--max-ts-pes", "1"),
    ] {
        let mut ordinary = args(&[key, value]);
        ordinary[0] = OsString::from("import");
        assert!(parse_command(&ordinary).is_err());
    }
    assert!(parse_command(&args(&["--work-units", "0"])).is_ok());
    assert!(parse_command(&args(&["--ts-video-pid", "16"])).is_ok());
}

#[cfg(unix)]
#[test]
fn transport_input_keeps_native_os_path_bytes() -> Test {
    use std::os::unix::ffi::OsStringExt;
    let mut arguments = args(&[]);
    let native = OsString::from_vec(b"camera-\xff.ts".to_vec());
    arguments[6] = native.clone();
    assert_eq!(parsed_action(parsed(&arguments)?)?.request.file.path.as_os_str(), native);
    Ok(())
}

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-ts-cli-{label}-{}-{attempt}", std::process::id(),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("temporary directory bound".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

// Independently framed PSI/PES packets; production import/extraction writes none of these bytes.
fn section(table: u8, extension: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![table, 0xb0, 0, (extension >> 8) as u8, extension as u8, 0xc1, 0, 0];
    bytes.extend_from_slice(body);
    let length = bytes.len() + 1;
    bytes[1] |= (length >> 8) as u8;
    bytes[2] = length as u8;
    let mut crc = u32::MAX;
    for byte in &bytes {
        crc ^= u32::from(*byte) << 24;
        for _ in 0..8 {
            crc = (crc << 1) ^ if crc & 0x8000_0000 != 0 { 0x04c1_1db7 } else { 0 };
        }
    }
    bytes.extend_from_slice(&crc.to_be_bytes());
    bytes
}
fn packet(pid: u16, first: bool, counter: u8, payload: &[u8]) -> Vec<u8> {
    assert!(!payload.is_empty() && payload.len() <= 184);
    let mut bytes = vec![0xff; 188];
    bytes[..4].copy_from_slice(&[
        0x47, (pid >> 8) as u8 | if first { 0x40 } else { 0 }, pid as u8,
        (if payload.len() == 184 { 0x10 } else { 0x30 }) | (counter & 15),
    ]);
    if payload.len() < 184 {
        bytes[4] = (183 - payload.len()) as u8;
        if bytes[4] > 0 { bytes[5] = 0; }
    }
    bytes[188 - payload.len()..].copy_from_slice(payload);
    bytes
}
fn recording(codec: VideoCodec) -> (Vec<u8>, Vec<u8>) {
    let one: &[u8] = match codec {
        VideoCodec::Avc => include_bytes!("../../../../../fss-codec-h264/tests/fixtures/baseline_i64.h264"),
        VideoCodec::Hevc => include_bytes!("../../../../../fss-codec-h265/tests/fixtures/decode/i_64x64_ctu32_qp30.h265"),
    };
    let media = [one, one].concat();
    let mut pat = vec![0];
    pat.extend(section(0, 1, &[0, 1, 0xf0, 0]));
    let mut pmt = vec![0];
    pmt.extend(section(2, 1, &[
        0xe1, 0, 0xf0, 0, if codec == VideoCodec::Avc { 0x1b } else { 0x24 },
        0xe1, 0, 0xf0, 0,
    ]));
    let mut transport = packet(0, true, 0, &pat);
    transport.extend(packet(0x1000, true, 0, &pmt));
    // Two syntax access units in one PES; a high PTS must never become UTC/capture time.
    let mut pes = vec![0, 0, 1, 0xe0, 0, 0, 0x80, 0x80, 5, 0x2f, 0xff, 0xff, 0xff, 0xff];
    pes.extend_from_slice(&media);
    for (index, body) in pes.chunks(184).enumerate() {
        transport.extend(packet(0x100, index == 0, index as u8, body));
    }
    (transport, media)
}
fn bound_args(root: &Path, input: &Path, extra: &[&str]) -> Vec<OsString> {
    let mut arguments = args(extra);
    arguments[2] = root.as_os_str().to_owned();
    arguments[6] = input.as_os_str().to_owned();
    arguments
}
fn execute(arguments: &[OsString]) -> Test<String> {
    let mut output = Vec::new();
    run_command(parsed(arguments)?, &mut output)?;
    Ok(String::from_utf8(output)?)
}
fn field<'a>(output: &'a str, key: &str) -> Test<&'a str> {
    output.lines().find_map(|line| {
        line.split_once('=').filter(|(name, _)| *name == key).map(|(_, value)| value)
    }).ok_or_else(|| format!("missing report field {key}").into())
}

#[test]
fn native_avc_and_hevc_dispatch_reopen_verified_custody_and_reuse_the_import() -> Test {
    for codec in [VideoCodec::Avc, VideoCodec::Hevc] {
        let directory = Directory::new(&format!("native-{codec:?}"))?;
        let root = directory.0.join("deployment");
        let input = directory.0.join("recording.ts");
        let (transport, elementary) = recording(codec);
        fs::write(&input, &transport)?;
        let arguments = bound_args(&root, &input, &["--ts-program", "1", "--ts-video-pid", "256"]);
        let report = execute(&arguments)?;
        assert_eq!(field(&report, "operation")?, "import-ts");
        assert_eq!(field(&report, "transport_container")?, "mpegts");
        assert_eq!(field(&report, "video_codec")?, if codec == VideoCodec::Avc { "h264" } else { "h265" });
        assert_eq!(field(&report, "ts_program")?, "1");
        assert_eq!(field(&report, "ts_video_pid")?, "256");
        assert_eq!(field(&report, "segment_count")?, "2");
        assert_eq!(field(&report, "segment_unit")?, "annexb_access_unit");
        assert_eq!(field(&report, "decoded_frames")?, "0");
        assert_eq!(field(&report, "capture_time_class")?, "unknown");
        assert_eq!(field(&report, "source_pts_is_utc")?, "false");
        assert_eq!(field(&report, "absence_certifiable")?, "false");
        assert_eq!(field(&report, "original_ts_sha256")?, ContentDigest::sha256(&transport).to_text());
        assert_eq!(field(&report, "verified_elementary_sha256")?, ContentDigest::sha256(&elementary).to_text());
        assert_eq!(field(&report, "reused")?, "false");
        assert!(field(&report, "import_work_units_used")?.parse::<u64>()? > transport.len() as u64);
        let identity = field(&report, "import_identity")?;
        let retry = execute(&arguments)?;
        assert_eq!(field(&retry, "import_identity")?, identity);
        assert_eq!(field(&retry, "import_root")?, field(&report, "import_root")?);
        assert_eq!(field(&retry, "reused")?, "true");

        fs::remove_file(&input)?;
        let verify = [
            OsString::from("verify"), OsString::from("--root"), root.as_os_str().to_owned(),
            OsString::from("--site"), OsString::from("site:ts-cli"),
            OsString::from("--import-id"), OsString::from(identity),
        ];
        let cold = execute(&verify)?;
        assert_eq!(field(&cold, "verified_source_sha256")?, ContentDigest::sha256(&elementary).to_text());
    }
    Ok(())
}

#[test]
fn exhausted_work_and_native_parser_ceilings_cannot_print_import_success() -> Test {
    let directory = Directory::new("bounded-dispatch")?;
    let input = directory.0.join("recording.ts");
    fs::write(&input, recording(VideoCodec::Avc).0)?;
    for (index, extra) in [
        vec!["--work-units", "0"],
        vec!["--work-units", "1"],
        vec!["--max-ts-packets", "1"],
        vec!["--max-elementary-bytes", "1"],
    ].into_iter().enumerate() {
        let root = directory.0.join(format!("deployment-{index}"));
        let options = parsed(&bound_args(&root, &input, &extra))?;
        let mut output = Vec::new();
        assert!(run_command(options, &mut output).is_err());
        assert!(output.is_empty());
        // Failed bounded work cannot poison a later, explicitly admitted import.
        let completed = execute(&bound_args(&root, &input, &[]))?;
        assert_eq!(field(&completed, "operation")?, "import-ts");
    }
    Ok(())
}

fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:ts-cli-verification".into(),
        operation_id: OperationId::parse("operation:ts-cli-verification")?,
        principal: "principal:local-operator".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(MAX_BYTES).build()?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(b"site:ts-cli"),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(&authority, root.to_path_buf())?)
}

#[test]
fn damaged_original_or_final_cancellation_withholds_report_and_manifest_export() -> Test {
    for cancelled in [false, true] {
        let directory = Directory::new(if cancelled { "cancelled-report" } else { "damaged-report" })?;
        let root = directory.0.join("deployment");
        let input = directory.0.join("recording.ts");
        let export = directory.0.join("manifest.fss");
        fs::write(&input, recording(VideoCodec::Avc).0)?;
        let action = parsed_action(parsed(&bound_args(&root, &input, &[]))?)?;
        let cx = context(&root)?;
        let mut deployment = ReferenceDeployment::open(&root, "site:ts-cli", &cx)?;
        let mut import_work = WorkBudget::new(DEFAULT_WORK_UNITS);
        let receipt = import_mpeg_ts_file(&mut deployment, &action.request, &cx, &mut import_work)?;
        if cancelled {
            cx.set_cancel_at_checkpoint("file_cli:mpegts_verified_output");
        } else {
            let original = deployment.publisher().spool().object_path(receipt.original_digest);
            fs::write(original, b"damaged retained transport")?;
        }
        let mut report = Vec::new();
        assert!(report_verified(
            &receipt, &deployment, RetainedReadLimits::default(), &root, Some(&export), &cx,
            &mut WorkBudget::new(DEFAULT_WORK_UNITS), DEFAULT_WORK_UNITS, &mut report,
        ).is_err());
        assert!(report.is_empty());
        assert!(!export.exists());
        cx.drain_and_finalize();
    }
    Ok(())
}
