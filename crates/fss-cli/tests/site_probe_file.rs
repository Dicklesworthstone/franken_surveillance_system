#![forbid(unsafe_code)]
//! Real CLI measurement of complete codec fixtures, then consumption by site planning.
//! These are offline protocol observations, not camera, custody, or pixel-decode claims.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use fss_cli::json_output::string;
use fss_core::ContentDigest;
use fss_core::json_input::{self, Value};
use fss_reference::site::{SiteProbeReceipt, parse_manifest, parse_probe_receipts};

type Test<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const MANIFEST: &[u8] = include_bytes!("../../../fixtures/site_probe/manifest.v1.json");
const AVC_RESPONSE: &[u8] = include_bytes!("../../../fixtures/site_probe/avc.describe.rtsp");
const AVC_DUMP: &[u8] = include_bytes!("../../../fixtures/site_probe/avc.rtpdump");
const HEVC_RESPONSE: &[u8] = include_bytes!("../../../fixtures/site_probe/hevc.describe.rtsp");
const HEVC_DUMP: &[u8] = include_bytes!("../../../fixtures/site_probe/hevc.rtpdump");
const JPEG_RESPONSE: &[u8] = include_bytes!("../../../fixtures/site_probe/jpeg.describe.rtsp");
const JPEG_DUMP: &[u8] = include_bytes!("../../../fixtures/site_probe/jpeg.rtpdump");
const SERVER_CANARY: &str = "fixture-private-server-canary";
const FIRST_TIMESTAMP: u32 = 0xffff_f000;
const MAX_CAPTURE_BYTES: u64 = 2 * 1024 * 1024 + 1024;
const PROCESS_TIMEOUT: Duration = Duration::from_secs(20);
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct Directory(PathBuf);

impl Directory {
    fn new(name: &str) -> Test<Self> {
        for _ in 0..128 {
            let serial = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "fss-site-probe-{name}-{}-{serial}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err("could not allocate isolated probe test directory".into())
    }

    fn write(&self, name: &str, bytes: impl AsRef<[u8]>) -> Test<PathBuf> {
        let path = self.0.join(name);
        fs::write(&path, bytes)?;
        Ok(path)
    }

    fn entries(&self) -> Test<Vec<OsString>> {
        let mut entries = fs::read_dir(&self.0)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort();
        Ok(entries)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn binary() -> Test<PathBuf> {
    std::env::var_os("FSS_BIN")
        .map(PathBuf::from)
        .or_else(|| option_env!("CARGO_BIN_EXE_fss").map(PathBuf::from))
        .ok_or_else(|| "fss binary unavailable; build it or set FSS_BIN".into())
}

fn read_output(input: impl Read) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    input.take(MAX_CAPTURE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CAPTURE_BYTES {
        return Err(io::Error::other("CLI output exceeded its test bound"));
    }
    Ok(bytes)
}

fn run(directory: &Path, arguments: &[OsString]) -> Test<Output> {
    let mut child = Command::new(binary()?)
        .args(arguments)
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().ok_or("missing stdout pipe")?;
    let stderr = child.stderr.take().ok_or("missing stderr pipe")?;
    std::thread::scope(|scope| {
        let stdout = scope.spawn(move || read_output(stdout));
        let stderr = scope.spawn(move || read_output(stderr));
        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if started.elapsed() < PROCESS_TIMEOUT => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("offline probe CLI did not finish within its test deadline".into());
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error.into());
                }
            }
        };
        let stdout = stdout
            .join()
            .map_err(|_| io::Error::other("stdout reader panicked"))??;
        let stderr = stderr
            .join()
            .map_err(|_| io::Error::other("stderr reader panicked"))??;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    })
}

fn good(output: &Output) -> Test<Value> {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    Ok(json_input::parse(std::str::from_utf8(&output.stdout)?)?)
}

fn field<'a>(value: &'a Value, name: &str) -> Test<&'a Value> {
    value
        .object()
        .and_then(|fields| fields.get(name))
        .ok_or_else(|| format!("missing field {name}").into())
}

fn text<'a>(value: &'a Value, name: &str) -> Test<&'a str> {
    field(value, name)?
        .text()
        .ok_or_else(|| format!("field {name} is not text").into())
}

fn number(value: &Value, name: &str) -> Test<u64> {
    field(value, name)?
        .integer()
        .and_then(|integer| u64::try_from(integer).ok())
        .ok_or_else(|| format!("field {name} is not an unsigned integer").into())
}

fn items<'a>(value: &'a Value, name: &str) -> Test<&'a [Value]> {
    field(value, name)?
        .array()
        .ok_or_else(|| format!("field {name} is not an array").into())
}

fn render(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.clone(),
        Value::Text(value) => string(value),
        Value::Array(values) => {
            format!(
                "[{}]",
                values.iter().map(render).collect::<Vec<_>>().join(",")
            )
        }
        Value::Object(fields) => format!(
            "{{{}}}",
            fields
                .iter()
                .map(|(key, value)| format!("{}:{}", string(key), render(value)))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

fn object_mut(value: &mut Value) -> Test<&mut BTreeMap<String, Value>> {
    match value {
        Value::Object(fields) => Ok(fields),
        _ => Err("expected fixture object".into()),
    }
}

fn source_mut(value: &mut Value) -> Test<&mut BTreeMap<String, Value>> {
    match object_mut(value)?.get_mut("sources") {
        Some(Value::Array(sources)) => {
            object_mut(sources.first_mut().ok_or("missing fixture source")?)
        }
        _ => Err("missing fixture sources".into()),
    }
}

fn replace_arg(args: &mut [OsString], flag: &str, value: impl Into<OsString>) -> Test {
    let index = args
        .iter()
        .position(|argument| argument == flag)
        .ok_or("missing fixture argument")?;
    *args.get_mut(index + 1).ok_or("missing argument value")? = value.into();
    Ok(())
}

fn no_effects(report: &Value) -> Test {
    for name in [
        "device_contacted",
        "credentials_read",
        "origin_authenticated",
        "current_liveness_verified",
        "custody_verified",
        "clock_synchronized",
        "rights_verdict_verified",
        "capture_authorized",
        "media_bytes_returned",
    ] {
        assert_eq!(field(report, name)?.boolean(), Some(false), "{name}");
    }
    Ok(())
}

fn refused(output: Output, expected_code: &str, canaries: &[&str]) -> Test<Value> {
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    for bytes in [&output.stdout, &output.stderr] {
        let text = std::str::from_utf8(bytes)?;
        for canary in canaries {
            assert!(!text.contains(canary), "refusal disclosed a private input");
        }
    }
    let value = json_input::parse(std::str::from_utf8(&output.stdout)?)?;
    assert_eq!(text(&value, "schema")?, "fss.site_diagnostic.v1");
    assert_eq!(text(&value, "error_id")?, expected_code);
    assert!(
        !value
            .object()
            .ok_or("diagnostic object")?
            .contains_key("receipts")
    );
    assert!(
        !value
            .object()
            .ok_or("diagnostic object")?
            .contains_key("evidence_digest")
    );
    for name in [
        "device_contacted",
        "credentials_read",
        "effect_started",
        "partial_plan",
    ] {
        assert_eq!(field(&value, name)?.boolean(), Some(false));
    }
    Ok(value)
}

struct Fixture {
    directory: Directory,
    manifest: Vec<u8>,
    response: Vec<u8>,
    dump: Vec<u8>,
    codec: &'static str,
}

impl Fixture {
    fn new(name: &str, codec: &'static str) -> Test<Self> {
        let (response, dump) = match codec {
            "avc" => (AVC_RESPONSE, AVC_DUMP),
            "hevc" => (HEVC_RESPONSE, HEVC_DUMP),
            "jpeg" => (JPEG_RESPONSE, JPEG_DUMP),
            _ => return Err("unknown test codec".into()),
        };
        Ok(Self {
            directory: Directory::new(name)?,
            manifest: MANIFEST.to_vec(),
            response: response.to_vec(),
            dump: dump.to_vec(),
            codec,
        })
    }

    fn write(&self) -> Test {
        self.directory.write("manifest.json", &self.manifest)?;
        self.directory.write("describe.rtsp", &self.response)?;
        self.directory.write("trace.rtpdump", &self.dump)?;
        Ok(())
    }

    fn args(&self) -> Vec<OsString> {
        let mut args = vec!["site".into(), "probe-file".into(), "--json".into()];
        for (flag, value) in [
            ("--manifest", self.directory.0.join("manifest.json")),
            (
                "--describe-response",
                self.directory.0.join("describe.rtsp"),
            ),
            ("--rtp-dump", self.directory.0.join("trace.rtpdump")),
        ] {
            args.extend([OsString::from(flag), value.into_os_string()]);
        }
        for (flag, bytes) in [
            ("--manifest-digest", self.manifest.as_slice()),
            ("--describe-digest", self.response.as_slice()),
            ("--rtp-dump-digest", self.dump.as_slice()),
        ] {
            args.extend([
                OsString::from(flag),
                ContentDigest::sha256(bytes).to_text().into(),
            ]);
        }
        args.extend([
            "--source".into(),
            "source:front".into(),
            "--codec".into(),
            self.codec.into(),
        ]);
        args
    }

    fn run(&self) -> Test<Output> {
        run(&self.directory.0, &self.args())
    }

    fn unchanged_inputs(&self) -> Test {
        assert_eq!(
            fs::read(self.directory.0.join("manifest.json"))?,
            self.manifest
        );
        assert_eq!(
            fs::read(self.directory.0.join("describe.rtsp"))?,
            self.response
        );
        assert_eq!(fs::read(self.directory.0.join("trace.rtpdump"))?, self.dump);
        Ok(())
    }
}

fn receipt(report: &Value) -> Test<SiteProbeReceipt> {
    let receipts = parse_probe_receipts(render(field(report, "receipts")?).as_bytes())?;
    assert_eq!(receipts.len(), 1);
    receipts
        .into_iter()
        .next()
        .ok_or_else(|| "missing measured receipt".into())
}

fn body(response: &[u8]) -> Test<&[u8]> {
    let at = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .ok_or("missing fixture RTSP header boundary")?;
    Ok(&response[at + 4..])
}

fn argument<'a>(source: &'a Value, flag: &str) -> Test<&'a str> {
    let args = items(source, "argv")?;
    let index = args
        .iter()
        .position(|value| value.text() == Some(flag))
        .ok_or("missing emitted native argument")?;
    args.get(index + 1)
        .and_then(Value::text)
        .ok_or_else(|| "missing emitted native value".into())
}

#[test]
fn an_empty_token_slice_is_a_typed_grammar_refusal() -> Test {
    assert!(matches!(
        fss_cli::site_probe_cmd::parse(&[]),
        Err(fss_cli::error::CliError::MissingValue { .. })
    ));
    Ok(())
}

#[test]
fn measured_native_codec_receipts_are_deterministic_and_bound_to_all_inputs() -> Test {
    for (codec, frame_count, packet_count, ssrc, payload_type, parameters) in [
        (
            "avc",
            4_u64,
            23_u64,
            0x1122_3344_u32,
            96_u8,
            &[
                "sha256:4b785dee94baff0aba95ac94a2c8fddf606fbea0a3c34af762bebc9cdc871dce",
                "sha256:02115ac26216f7491ada16416042fac8c0d181ae6e336f3e1d9e49b2c99a24a5",
            ][..],
        ),
        (
            "hevc",
            3,
            14,
            0x5566_7788,
            98,
            &[
                "sha256:af9692dd6787a0fbd6f6da1af2fb7e8cf82466eae7efda9b673091fcbbce813b",
                "sha256:e009b8316000e668f9d2c10012232c604cc9d30935b98490091833997a660732",
                "sha256:a7adbe577180ca6f0faac120bba141068e7abbbee4116d284c3a6d6d6663f0bf",
            ][..],
        ),
        ("jpeg", 3, 6, 0x99aa_bbcc, 26, &[][..]),
    ] {
        let fixture = Fixture::new(codec, codec)?;
        fixture.write()?;
        let original_entries = fixture.directory.entries()?;
        let first = fixture.run()?;
        let report = good(&first)?;
        let second = fixture.run()?;
        good(&second)?;
        assert_eq!(first.stdout, second.stdout);
        assert_eq!(text(&report, "schema")?, "fss.site_probe_observation.v1");
        assert_eq!(text(&report, "status")?, "measured");
        assert_eq!(
            text(&report, "measurement_basis")?,
            "offline_describe_response_and_rtpdump"
        );
        assert_eq!(
            text(&report, "channel_basis")?,
            "operator_selected_not_measured_from_rtpdump"
        );
        assert_eq!(text(&report, "source_id")?, "source:front");
        no_effects(&report)?;
        let manifest = parse_manifest(&fixture.manifest)?;
        for (name, digest) in [
            ("manifest_digest", manifest.digest()?),
            (
                "manifest_input_digest",
                ContentDigest::sha256(&fixture.manifest),
            ),
            (
                "describe_response_digest",
                ContentDigest::sha256(&fixture.response),
            ),
            ("rtp_dump_digest", ContentDigest::sha256(&fixture.dump)),
            (
                "sdp_digest",
                ContentDigest::sha256(body(&fixture.response)?),
            ),
            (
                "server_header_digest",
                ContentDigest::sha256(SERVER_CANARY.as_bytes()),
            ),
        ] {
            assert_eq!(text(&report, name)?, digest.to_text());
        }
        assert_eq!(number(&report, "rtp_packets")?, packet_count);
        assert_eq!(number(&report, "rtcp_packets")?, 0);
        assert_eq!(number(&report, "observed_frames")?, frame_count);
        let observed = receipt(&report)?;
        observed.validate_for(&manifest)?;
        assert_eq!(observed.codec.as_str(), codec);
        assert_eq!(observed.ssrc, ssrc);
        assert_eq!(observed.payload_type, payload_type);
        assert_eq!(observed.observed_frames, frame_count as u32);
        assert_eq!(observed.frame_duration_ticks, 3600);
        assert_eq!(observed.clock_rate_hz, 90_000);
        assert_eq!(observed.first_rtp_timestamp, FIRST_TIMESTAMP);
        assert_eq!(
            observed.last_rtp_timestamp,
            FIRST_TIMESTAMP.wrapping_add((frame_count as u32 - 1) * 3600)
        );
        assert_eq!(
            (
                observed.media_index,
                observed.rtp_channel,
                observed.rtcp_channel
            ),
            (0, 0, 1)
        );
        assert_eq!(
            observed
                .parameter_set_digests
                .iter()
                .map(|digest| digest.to_text())
                .collect::<Vec<_>>(),
            parameters
        );
        assert!(!std::str::from_utf8(&first.stdout)?.contains(SERVER_CANARY));
        assert_eq!(fixture.directory.entries()?, original_entries);
        fixture.unchanged_inputs()?;
    }
    Ok(())
}

#[test]
fn measured_receipts_feed_the_real_site_compiler() -> Test {
    for codec in ["avc", "hevc", "jpeg"] {
        let fixture = Fixture::new("site-plan", codec)?;
        fixture.write()?;
        let report = good(&fixture.run()?)?;
        let observed = receipt(&report)?;
        observed.validate_for(&parse_manifest(&fixture.manifest)?)?;
        let probes = fixture
            .directory
            .write("receipts.json", render(field(&report, "receipts")?))?;
        let archive = fixture.directory.0.join("archive-not-created");
        let pins = fixture.directory.0.join("pins-not-created");
        let args = vec![
            "site".into(),
            "plan".into(),
            "--json".into(),
            "--manifest".into(),
            fixture.directory.0.join("manifest.json").into_os_string(),
            "--probes".into(),
            probes.into_os_string(),
            "--archive-root".into(),
            archive.clone().into_os_string(),
            "--pins-root".into(),
            pins.clone().into_os_string(),
            "--epoch".into(),
            "9".into(),
            "--stop-after-pictures".into(),
            "25".into(),
        ];
        let planned = good(&run(&fixture.directory.0, &args)?)?;
        assert_eq!(text(&planned, "schema")?, "fss.site_capture_plan.v1");
        assert_eq!(number(&planned, "source_count")?, 1);
        assert_eq!(
            field(&planned, "capture_authorized")?.boolean(),
            Some(false)
        );
        let source = items(&planned, "sources")?
            .first()
            .ok_or("missing source plan")?;
        if codec == "jpeg" {
            assert_eq!(
                items(source, "argv")?.first().and_then(Value::text),
                Some("jpeg")
            );
            assert!(argument(source, "--retention-evidence")?.starts_with("sha256:"));
        } else {
            assert_eq!(argument(source, "--codec")?, codec);
            assert_eq!(argument(source, "--frame-duration-ticks")?, "3600");
        }
        assert_eq!(argument(source, "--ssrc")?, observed.ssrc.to_string());
        assert_eq!(
            argument(source, "--payload-type")?,
            observed.payload_type.to_string()
        );
        assert_eq!(argument(source, "--generation")?, "9");
        assert!(
            !items(source, "argv")?
                .iter()
                .any(|value| value.text() == Some("--approve"))
        );
        assert!(!archive.exists());
        assert!(!pins.exists());
        fixture.unchanged_inputs()?;
    }
    Ok(())
}

#[test]
fn each_control_and_media_input_requires_its_own_exact_byte_pin() -> Test {
    let fixture = Fixture::new("pins", "avc")?;
    fixture.write()?;
    let before = fixture.directory.entries()?;
    for flag in [
        "--manifest-digest",
        "--describe-digest",
        "--rtp-dump-digest",
    ] {
        let mut args = fixture.args();
        replace_arg(
            &mut args,
            flag,
            ContentDigest::sha256(b"different input").to_text(),
        )?;
        refused(
            run(&fixture.directory.0, &args)?,
            "ERR-SITE-PROBE-INPUT-PIN-001",
            &[SERVER_CANARY],
        )?;
    }
    assert_eq!(fixture.directory.entries()?, before);
    fixture.unchanged_inputs()?;
    Ok(())
}

fn records(dump: &[u8]) -> Test<(Vec<u8>, Vec<Vec<u8>>)> {
    let header = dump
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or("fixture magic")?
        + 17;
    if header > dump.len() {
        return Err("truncated fixture header".into());
    }
    let mut at = header;
    let mut result = Vec::new();
    while at < dump.len() {
        let length = u16::from_be_bytes(
            dump.get(at..at + 2)
                .ok_or("fixture record length")?
                .try_into()?,
        ) as usize;
        if length < 20 {
            return Err("fixture RTP record too short".into());
        }
        result.push(
            dump.get(at..at + length)
                .ok_or("truncated fixture record")?
                .to_vec(),
        );
        at += length;
    }
    Ok((dump[..header].to_vec(), result))
}

fn join_records(header: &[u8], records: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = header.to_vec();
    for record in records {
        bytes.extend_from_slice(record);
    }
    bytes
}

fn record_timestamp(record: &[u8]) -> Test<u32> {
    Ok(u32::from_be_bytes(
        record
            .get(12..16)
            .ok_or("fixture RTP timestamp")?
            .try_into()?,
    ))
}

#[test]
fn loss_duplicates_reordering_and_stream_changes_refuse_the_whole_observation() -> Test {
    let (header, original) = records(AVC_DUMP)?;
    let first_slice = original
        .iter()
        .position(|record| {
            record.len() > 21
                && record[20] & 31 == 28
                && record[21] & 31 == 5
                && record[21] & 0x80 != 0
        })
        .ok_or("fixture IDR FU start")?;
    for name in ["loss", "duplicate", "reorder", "ssrc", "payload"] {
        let mut fixture = Fixture::new(name, "avc")?;
        let mut changed = original.clone();
        match name {
            "loss" => {
                let _ = changed.remove(first_slice + 1);
            }
            "duplicate" => changed.insert(first_slice + 1, changed[first_slice].clone()),
            "reorder" => changed.swap(first_slice, first_slice + 1),
            "ssrc" => changed.last_mut().ok_or("last record")?[16..20]
                .copy_from_slice(&0x8877_6655_u32.to_be_bytes()),
            "payload" => {
                let last = changed.last_mut().ok_or("last record")?;
                last[9] = (last[9] & 0x80) | 97;
            }
            _ => return Err("unknown mutation".into()),
        }
        fixture.dump = join_records(&header, &changed);
        fixture.write()?;
        refused(
            fixture.run()?,
            "ERR-SITE-PROBE-CONTINUITY-001",
            &[SERVER_CANARY],
        )?;
        fixture.unchanged_inputs()?;
    }
    Ok(())
}

#[test]
fn an_incomplete_suffix_or_truncated_datagram_cannot_publish_a_valid_prefix() -> Test {
    for (codec, name, expected) in [
        ("avc", "unfinished-fu", "ERR-SITE-PROBE-PICTURE-001"),
        ("hevc", "no-hevc-eos", "ERR-SITE-PROBE-PICTURE-001"),
    ] {
        let mut fixture = Fixture::new(name, codec)?;
        let (header, mut packets) = records(&fixture.dump)?;
        let _ = packets.pop().ok_or("fixture tail packet")?;
        fixture.dump = join_records(&header, &packets);
        fixture.write()?;
        refused(fixture.run()?, expected, &[SERVER_CANARY])?;
    }
    let mut fixture = Fixture::new("truncated-record", "avc")?;
    let _ = fixture.dump.pop().ok_or("fixture last byte")?;
    fixture.write()?;
    refused(
        fixture.run()?,
        "ERR-SITE-PROBE-PACKET-001",
        &[SERVER_CANARY],
    )?;
    Ok(())
}

#[test]
fn frame_cadence_comes_from_native_picture_syntax_and_refuses_variable_timestamps() -> Test {
    let mut fixture = Fixture::new("variable-cadence", "avc")?;
    let (header, mut packets) = records(&fixture.dump)?;
    let third = FIRST_TIMESTAMP.wrapping_add(7200);
    for packet in &mut packets {
        if record_timestamp(packet)? == third {
            packet[12..16].copy_from_slice(&third.wrapping_add(1).to_be_bytes());
        }
    }
    fixture.dump = join_records(&header, &packets);
    fixture.write()?;
    refused(
        fixture.run()?,
        "ERR-SITE-PROBE-CADENCE-001",
        &[SERVER_CANARY],
    )?;

    let mut fixture = Fixture::new("marker-only", "avc")?;
    let (header, _) = records(&fixture.dump)?;
    let mut packets = Vec::new();
    for index in 0_u16..4 {
        let mut rtp = vec![0x80, 0x80 | 96];
        rtp.extend_from_slice(&index.to_be_bytes());
        rtp.extend_from_slice(
            &FIRST_TIMESTAMP
                .wrapping_add(u32::from(index) * 3600)
                .to_be_bytes(),
        );
        rtp.extend_from_slice(&0x1122_3344_u32.to_be_bytes());
        rtp.extend_from_slice(&[0x65, 0x80]); // IDR tag and first_mb bit; no valid slice header/data.
        let mut record = Vec::new();
        record.extend_from_slice(&((rtp.len() + 8) as u16).to_be_bytes());
        record.extend_from_slice(&(rtp.len() as u16).to_be_bytes());
        record.extend_from_slice(&(u32::from(index) * 40).to_be_bytes());
        record.extend_from_slice(&rtp);
        packets.push(record);
    }
    fixture.dump = join_records(&header, &packets);
    fixture.write()?;
    refused(
        fixture.run()?,
        "ERR-SITE-PROBE-PICTURE-001",
        &[SERVER_CANARY],
    )?;
    Ok(())
}

#[test]
fn secret_bearing_or_malformed_control_evidence_is_refused_without_echoing_it() -> Test {
    let mut manifest_fixture = Fixture::new("manifest-secret", "avc")?;
    let mut manifest = json_input::parse(std::str::from_utf8(&manifest_fixture.manifest)?)?;
    source_mut(&mut manifest)?.insert(
        "password".into(),
        Value::Text("site-probe-password-canary".into()),
    );
    manifest_fixture.manifest = render(&manifest).into_bytes();
    manifest_fixture.write()?;
    refused(
        manifest_fixture.run()?,
        "ERR-SITE-PROBE-MANIFEST-001",
        &["site-probe-password-canary", SERVER_CANARY],
    )?;

    let mut response_fixture = Fixture::new("response-secret", "avc")?;
    let response = std::str::from_utf8(&response_fixture.response)?.replace(
        "Content-Type:",
        "Content-Base: rtsp://operator:describe-secret-canary@camera-10.example:554/live/\r\nContent-Type:",
    );
    response_fixture.response = response.into_bytes();
    response_fixture.write()?;
    refused(
        response_fixture.run()?,
        "ERR-SITE-PROBE-DESCRIPTION-001",
        &["describe-secret-canary", SERVER_CANARY],
    )?;

    let mut truncated = Fixture::new("response-truncated", "avc")?;
    let _ = truncated.response.pop().ok_or("last response byte")?;
    truncated.write()?;
    refused(
        truncated.run()?,
        "ERR-SITE-PROBE-DESCRIPTION-001",
        &[SERVER_CANARY],
    )?;
    Ok(())
}

#[test]
fn unreadable_nonregular_and_oversized_named_inputs_are_bounded_refusals() -> Test {
    let fixture = Fixture::new("input-kinds", "avc")?;
    fixture.write()?;
    for path in [
        fixture.directory.0.join("missing-private-input-canary"),
        fixture.directory.0.clone(),
    ] {
        let mut args = fixture.args();
        replace_arg(&mut args, "--describe-response", path.into_os_string())?;
        refused(
            run(&fixture.directory.0, &args)?,
            "ERR-SITE-INPUT-001",
            &["missing-private-input-canary", SERVER_CANARY],
        )?;
    }
    #[cfg(unix)]
    {
        let link = fixture.directory.0.join("private-symlink-canary");
        std::os::unix::fs::symlink(fixture.directory.0.join("describe.rtsp"), &link)?;
        let mut args = fixture.args();
        replace_arg(&mut args, "--describe-response", link.into_os_string())?;
        refused(
            run(&fixture.directory.0, &args)?,
            "ERR-SITE-INPUT-001",
            &["private-symlink-canary", SERVER_CANARY],
        )?;
    }
    let mut oversized = Fixture::new("oversized-response", "avc")?;
    oversized.response = vec![b'x'; 128 * 1024 + 1];
    oversized.write()?;
    refused(oversized.run()?, "ERR-SITE-INPUT-001", &[SERVER_CANARY])?;
    fixture.unchanged_inputs()?;
    Ok(())
}

#[test]
fn measurement_does_not_contact_the_declared_camera_read_credentials_or_create_outputs() -> Test {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let mut fixture = Fixture::new("no-effects", "avc")?;
    let credential = fixture.directory.0.join("credentials-not-created");
    let mut manifest = json_input::parse(std::str::from_utf8(&fixture.manifest)?)?;
    let source = source_mut(&mut manifest)?;
    source.insert(
        "peer".into(),
        Value::Text(listener.local_addr()?.to_string()),
    );
    source.insert(
        "authority".into(),
        Value::Text(format!(
            "camera-10.example:{}",
            listener.local_addr()?.port()
        )),
    );
    source.insert(
        "authentication".into(),
        json_input::parse(&format!(
            r#"{{"credential_file":{},"realm":"site-probe-realm-canary","legacy_md5":false,"legacy_no_qop":false}}"#,
            string(credential.to_str().ok_or("UTF-8 test path")?)
        ))?,
    );
    fixture.manifest = render(&manifest).into_bytes();
    fixture.write()?;
    let before = fixture.directory.entries()?;
    let output = fixture.run()?;
    let report = good(&output)?;
    no_effects(&report)?;
    assert!(!std::str::from_utf8(&output.stdout)?.contains("site-probe-realm-canary"));
    receipt(&report)?.validate_for(&parse_manifest(&fixture.manifest)?)?;
    match listener.accept() {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Err(error) => return Err(error.into()),
        Ok(_) => return Err("offline probe contacted the manifest peer".into()),
    }
    assert!(!credential.exists());
    assert_eq!(fixture.directory.entries()?, before);
    fixture.unchanged_inputs()?;
    Ok(())
}

#[test]
fn proposed_channels_are_explicitly_labelled_and_invalid_media_selection_refuses() -> Test {
    let fixture = Fixture::new("selection", "avc")?;
    fixture.write()?;
    let default = good(&fixture.run()?)?;
    let mut explicit = fixture.args();
    explicit.extend([
        "--media-index".into(),
        "0".into(),
        "--rtp-channel".into(),
        "8".into(),
    ]);
    let changed = good(&run(&fixture.directory.0, &explicit)?)?;
    let changed_receipt = receipt(&changed)?;
    assert_eq!(
        (changed_receipt.rtp_channel, changed_receipt.rtcp_channel),
        (8, 9)
    );
    assert_eq!(changed_receipt.ssrc, receipt(&default)?.ssrc);
    assert_eq!(
        text(&changed, "channel_basis")?,
        "operator_selected_not_measured_from_rtpdump"
    );
    assert_ne!(
        text(&default, "evidence_digest")?,
        text(&changed, "evidence_digest")?
    );
    replace_arg(&mut explicit, "--media-index", "1")?;
    refused(
        run(&fixture.directory.0, &explicit)?,
        "ERR-SITE-PROBE-DESCRIPTION-001",
        &[SERVER_CANARY],
    )?;
    Ok(())
}
