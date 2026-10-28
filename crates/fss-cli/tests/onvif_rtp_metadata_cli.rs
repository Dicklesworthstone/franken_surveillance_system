#![forbid(unsafe_code)]
//! Real-process original-packet import, private reporting and cold ONVIF metadata verification.
//! These finite local fixtures establish command wiring and custody, not device qualification.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use fss_core::ContentDigest;

type Test<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const SITE: &str = "site:rtp-metadata-cli-test";
const SENSOR: &str = "sensor:private-metadata-camera";
const PROFILE: &str = "private-profile-canary";
const INGRESS: &str = "18446744073709551633";
const ARGUMENT_ERROR: &str = "ERR-ONVIF-METADATA-ARGUMENT-001";
const CUSTODY_ERROR: &str = "ERR-ONVIF-METADATA-CUSTODY-001";
const XML: &str = r#"<t:MetadataStream xmlns:t="http://www.onvif.org/ver10/schema"><t:VideoAnalytics><t:Frame UtcTime="2026-10-28T12:34:56Z" Source="private-module-canary"><t:Transformation><t:Translate x="-0.37591" y="0.75"/><t:Scale x="0.25" y="-0.5"/></t:Transformation><t:Object ObjectId="732103"><t:Appearance><t:Shape><t:BoundingBox left="-0.12591" top="0.87391" right="0.5" bottom="-0.2"/><t:CenterOfGravity x="0.1" y="0.2"/></t:Shape><t:Class><t:Type Likelihood="0.75">private&quot;class\canary</t:Type></t:Class><t:Face><t:Identity>opaque-biometric-canary</t:Identity></t:Face></t:Appearance></t:Object></t:Frame></t:VideoAnalytics></t:MetadataStream>"#;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..64 {
            let path = std::env::temp_dir().join(format!(
                "fss-onvif-rtp-metadata-cli-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("owned fixture-directory allowance exhausted".into())
    }
    fn root(&self) -> PathBuf {
        self.0.join("deployment")
    }
    fn input(&self) -> PathBuf {
        self.0.join("source.rtpdump")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// The override permits a constrained host to build just this real binary and this test.
// A missing executable is an error; process qualification is never silently skipped.
fn binary() -> Test<PathBuf> {
    std::env::var_os("FSS_ONVIF_METADATA_BIN")
        .or_else(|| option_env!("CARGO_BIN_EXE_fss-onvif-metadata").map(OsString::from))
        .map(PathBuf::from)
        .ok_or_else(|| "missing metadata binary; set FSS_ONVIF_METADATA_BIN".into())
}
fn output_bytes(reader: impl Read, exceeded: &AtomicBool) -> io::Result<Vec<u8>> {
    const MAX_OUTPUT_BYTES: u64 = 4 * 1024 * 1024;
    let mut bytes = Vec::new();
    reader.take(MAX_OUTPUT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_OUTPUT_BYTES {
        exceeded.store(true, Ordering::Release);
        return Err(io::Error::other("fixture process output bound exceeded"));
    }
    Ok(bytes)
}
fn run(args: &[OsString]) -> Test<Output> {
    let mut child = Command::new(binary()?)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().ok_or("missing stdout pipe")?;
    let stderr = child.stderr.take().ok_or("missing stderr pipe")?;
    let exceeded = AtomicBool::new(false);
    thread::scope(|scope| {
        let limit = &exceeded;
        let stdout = scope.spawn(move || output_bytes(stdout, limit));
        let stderr = scope.spawn(move || output_bytes(stderr, limit));
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut timed_out = false;
        let status = loop {
            if exceeded.load(Ordering::Acquire) {
                let _ = child.kill();
                break child.wait();
            }
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
                Ok(None) => {
                    timed_out = true;
                    let _ = child.kill();
                    break child.wait();
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err(error);
                }
            }
        };
        let stdout = stdout.join().map_err(|_| "stdout reader panicked")??;
        let stderr = stderr.join().map_err(|_| "stderr reader panicked")??;
        if timed_out {
            return Err(format!(
                "metadata command exceeded fixture deadline: {}",
                String::from_utf8_lossy(&stderr)
            )
            .into());
        }
        Ok(Output {
            status: status?,
            stdout,
            stderr,
        })
    })
}
fn report(output: Output, success: bool) -> Test<String> {
    assert_eq!(
        output.status.success(),
        success,
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}
fn field<'a>(report: &'a str, name: &str) -> Test<&'a str> {
    report
        .lines()
        .filter_map(|line| line.split_once('='))
        .find_map(|(key, value)| (key == name).then_some(value))
        .ok_or_else(|| format!("missing report field {name}: {report}").into())
}
fn set(args: &mut [OsString], flag: &str, value: &str) -> Test {
    let index = args
        .iter()
        .position(|arg| arg == flag)
        .ok_or("missing fixture flag")?;
    *args.get_mut(index + 1).ok_or("missing fixture value")? = value.into();
    Ok(())
}
fn import_args(root: &Path, input: &Path) -> Vec<OsString> {
    vec![
        "import-rtp".into(),
        "--root".into(),
        root.into(),
        "--site".into(),
        SITE.into(),
        "--input".into(),
        input.into(),
        "--sensor".into(),
        SENSOR.into(),
        "--device-generation".into(),
        ContentDigest::sha256(b"device-v1").to_text().into(),
        "--profile-generation".into(),
        ContentDigest::sha256(b"profile-v1").to_text().into(),
        "--profile".into(),
        PROFILE.into(),
        "--received-start-ns".into(),
        "100".into(),
        "--received-end-ns".into(),
        "110".into(),
        "--ingress".into(),
        INGRESS.into(),
        "--stream-generation".into(),
        "3".into(),
        "--ssrc".into(),
        "42".into(),
        "--payload-type".into(),
        "107".into(),
    ]
}
fn cold_args(operation: &str, root: &Path, identity: &str) -> Vec<OsString> {
    vec![
        operation.into(),
        "--root".into(),
        root.into(),
        "--site".into(),
        SITE.into(),
        "--import-id".into(),
        identity.into(),
    ]
}
fn packet(sequence: u16, timestamp: u32, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x80, 107 | if marker { 0x80 } else { 0 }];
    bytes.extend(sequence.to_be_bytes());
    bytes.extend(timestamp.to_be_bytes());
    bytes.extend(42_u32.to_be_bytes());
    bytes.extend(payload);
    bytes
}
fn dump(packets: &[Vec<u8>]) -> Test<Vec<u8>> {
    let mut bytes = b"#!rtpplay1.0 198.51.100.23/59999\n".to_vec();
    bytes.extend([0_u8; 16]);
    for (index, packet) in packets.iter().enumerate() {
        bytes.extend(u16::try_from(packet.len() + 8)?.to_be_bytes());
        bytes.extend(u16::try_from(packet.len())?.to_be_bytes());
        bytes.extend((5000 + u32::try_from(index)?).to_be_bytes());
        bytes.extend(packet);
    }
    Ok(bytes)
}
fn synchronized(documents: &[&[u8]]) -> Test<Vec<u8>> {
    let mut packets = vec![
        packet(100, 1, false, b"unknown-initial-fragment"),
        packet(101, 2, true, b"discarded-through-marker"),
    ];
    for (index, document) in documents.iter().enumerate() {
        packets.push(packet(
            102 + u16::try_from(index)?,
            9000 * (u32::try_from(index)? + 1),
            true,
            document,
        ));
    }
    dump(&packets)
}
fn fragmented() -> Test<Vec<u8>> {
    let half = XML.len() / 2;
    dump(&[
        packet(100, 1, false, b"unknown-initial-fragment"),
        packet(101, 2, true, b"discarded-through-marker"),
        packet(102, 53_000, false, &XML.as_bytes()[..half]),
        packet(103, 17, true, &XML.as_bytes()[half..]),
    ])
}

#[test]
fn native_import_freezes_independent_owner_pins_and_cold_verifies_without_input() -> Test {
    let directory = Directory::new("roundtrip")?;
    let input = fragmented()?;
    fs::write(directory.input(), &input)?;
    let mut args = import_args(&directory.root(), &directory.input());
    args.extend([
        "--source-sha256".into(),
        ContentDigest::sha256(&input).to_text().into(),
        "--encoding".into(),
        "vnd.onvif.metadata".into(),
        "--clock-rate".into(),
        "90000".into(),
    ]);
    let imported = report(run(&args)?, true)?;
    for (key, expected) in [
        ("operation", "import-rtp"),
        ("source_mode", "owner_supplied_rtpdump"),
        ("durable_publication", "true"),
        ("processing_complete", "true"),
        ("complete_documents", "1"),
        ("usable_documents", "1"),
        ("rejected_documents", "0"),
        ("record_count", "4"),
        ("ingress", INGRESS),
        ("stream_generation", "3"),
        ("ssrc", "42"),
        ("payload_type", "107"),
        ("received_start_ns", "100"),
        ("received_end_ns", "110"),
        ("receive_interval_source", "owner_declaration"),
        ("reconstruction_scope", "after_first_observed_marker"),
        ("recorded_offsets_trusted", "false"),
        ("document.0.boundary_record", "1"),
        ("document.0.boundary_sequence", "101"),
        ("document.0.boundary_replay_received_ns", "5001000000"),
        ("document.0.fragment_count", "2"),
        ("document.0.first_sequence", "102"),
        ("document.0.last_sequence", "103"),
        ("document.0.xml_accepted", "true"),
    ] {
        assert_eq!(field(&imported, key)?, expected, "{key}");
    }
    assert_eq!(
        field(&imported, "source_sha256")?,
        ContentDigest::sha256(&input).to_text()
    );
    assert_eq!(
        field(&imported, "document.0.xml_sha256")?,
        ContentDigest::sha256(XML.as_bytes()).to_text()
    );
    assert_eq!(
        field(&imported, "sensor_sha256")?,
        ContentDigest::sha256(SENSOR.as_bytes()).to_text()
    );
    assert_eq!(
        field(&imported, "profile_token_sha256")?,
        ContentDigest::sha256(PROFILE.as_bytes()).to_text()
    );
    let repeated = report(run(&args)?, true)?;
    for key in [
        "import_identity",
        "publication_root",
        "authority_sequence",
        "replay_report_sha256",
    ] {
        assert_eq!(field(&repeated, key)?, field(&imported, key)?);
    }
    set(
        &mut args,
        "--profile-generation",
        &ContentDigest::sha256(b"profile-v2").to_text(),
    )?;
    let changed_owner = report(run(&args)?, true)?;
    assert_eq!(
        field(&changed_owner, "source_sha256")?,
        field(&imported, "source_sha256")?
    );
    assert_ne!(
        field(&changed_owner, "import_identity")?,
        field(&imported, "import_identity")?
    );
    fs::remove_file(directory.input())?;
    for operation in ["inspect-rtp", "verify-rtp"] {
        let mut cold = cold_args(
            operation,
            &directory.root(),
            field(&imported, "import_identity")?,
        );
        cold.extend([
            "--expected-root".into(),
            field(&imported, "publication_root")?.into(),
            "--document-index".into(),
            "0".into(),
        ]);
        let verified = report(run(&cold)?, true)?;
        assert_eq!(field(&verified, "operation")?, operation);
        for key in [
            "import_identity",
            "publication_root",
            "authority_sequence",
            "source_sha256",
            "replay_report_sha256",
        ] {
            assert_eq!(field(&verified, key)?, field(&imported, key)?);
        }
        assert!(field(&verified, "document.0.fragment.0")?.starts_with("record:2,sequence:102,"));
        assert!(
            field(&verified, "document.0.fragment.0")?
                .contains("timestamp:53000,replay_received_ns:5002000000")
        );
        assert!(
            field(&verified, "document.0.fragment.1")?
                .contains("timestamp:17,replay_received_ns:5003000000")
        );
    }
    Ok(())
}

#[test]
fn vendor_and_owner_values_require_explicit_disclosure_and_remain_escaped() -> Test {
    let directory = Directory::new("disclosure")?;
    fs::write(directory.input(), synchronized(&[XML.as_bytes()])?)?;
    let hidden = report(
        run(&import_args(&directory.root(), &directory.input()))?,
        true,
    )?;
    assert_eq!(field(&hidden, "values_disclosed")?, "false");
    assert_eq!(field(&hidden, "document.0.analytics_frame_count")?, "1");
    assert_eq!(field(&hidden, "document.0.analytics_object_count")?, "1");
    for private in [
        SENSOR,
        PROFILE,
        "private-module-canary",
        "732103",
        "-0.37591",
        "-0.12591",
        "private\\\"class",
        "opaque-biometric-canary",
    ] {
        assert!(
            !hidden.contains(private),
            "default report exposed {private}"
        );
    }
    let mut inspect = cold_args(
        "inspect-rtp",
        &directory.root(),
        field(&hidden, "import_identity")?,
    );
    inspect.extend(["--include-values".into(), "yes".into()]);
    let shown = report(run(&inspect)?, true)?;
    assert_eq!(field(&shown, "values_disclosed")?, "true");
    assert_eq!(field(&shown, "sensor")?, format!("{SENSOR:?}"));
    assert_eq!(field(&shown, "profile_token")?, format!("{PROFILE:?}"));
    assert_eq!(
        field(&shown, "document.0.analytics.0.object.0.object_id")?,
        "\"732103\""
    );
    assert!(shown.contains(&format!("label={:?}", "private\"class\\canary")));
    assert_eq!(
        field(&shown, "document.0.analytics.0.source.value")?,
        "\"private-module-canary\""
    );
    assert!(!shown.contains("opaque-biometric-canary"));
    for flag in [
        "camera_authenticated",
        "vendor_clock_trusted",
        "coordinates_calibrated",
        "classes_calibrated",
        "identity_claimed",
        "coverage_claimed",
        "absence_claimed",
        "effects_authorized",
        "sensitive_features_enabled",
    ] {
        assert_eq!(field(&shown, flag)?, "false");
    }
    Ok(())
}

#[test]
fn incomplete_or_rejected_imports_exit_nonzero_but_keep_cold_verifiable_source() -> Test {
    let mut truncated = synchronized(&[XML.as_bytes()])?;
    truncated.extend([0, 20, 0]);
    let partial = dump(&[
        packet(100, 1, false, b"unknown"),
        packet(101, 2, true, b"old-tail"),
        packet(102, 3, true, XML.as_bytes()),
        packet(103, 4, false, &XML.as_bytes()[..XML.len() / 2]),
    ])?;
    for (label, input, count, rejected, end, issue) in [
        (
            "malformed-header",
            b"not an RTP dump".to_vec(),
            "0",
            "0",
            "framing_error",
            "rtpdump_truncated_header",
        ),
        (
            "rejected-xml",
            synchronized(&[b"<!DOCTYPE root><root/>"])?,
            "1",
            "1",
            "end_of_input",
            "unsupported_xml",
        ),
        (
            "incomplete-xml",
            partial,
            "1",
            "0",
            "end_of_input",
            "incomplete_document_end_of_input",
        ),
        (
            "truncated-record",
            truncated,
            "1",
            "0",
            "framing_error",
            "rtpdump_truncated_record_header",
        ),
    ] {
        let directory = Directory::new(label)?;
        fs::write(directory.input(), &input)?;
        let imported = report(
            run(&import_args(&directory.root(), &directory.input()))?,
            false,
        )?;
        assert_eq!(field(&imported, "durable_publication")?, "true");
        assert_eq!(field(&imported, "processing_complete")?, "false");
        assert_eq!(field(&imported, "complete_documents")?, count);
        assert_eq!(field(&imported, "rejected_documents")?, rejected);
        assert_eq!(field(&imported, "end_reason")?, end);
        assert_eq!(field(&imported, &format!("issues.{issue}"))?, "1");
        assert_eq!(
            field(&imported, "source_sha256")?,
            ContentDigest::sha256(&input).to_text()
        );
        assert!(field(&imported, "import_identity")?.starts_with("sha256:"));
        fs::remove_file(directory.input())?;
        let verified = report(
            run(&cold_args(
                "verify-rtp",
                &directory.root(),
                field(&imported, "import_identity")?,
            ))?,
            true,
        )?;
        assert_eq!(field(&verified, "processing_complete")?, "false");
        for key in [
            "import_identity",
            "publication_root",
            "source_sha256",
            "replay_report_sha256",
            "complete_documents",
            "rejected_documents",
            "end_reason",
        ] {
            assert_eq!(field(&verified, key)?, field(&imported, key)?);
        }
    }
    Ok(())
}

#[test]
fn source_digest_refusal_happens_before_destination_publication() -> Test {
    let directory = Directory::new("wrong-digest")?;
    let input = synchronized(&[XML.as_bytes()])?;
    fs::write(directory.input(), &input)?;
    let mut args = import_args(&directory.root(), &directory.input());
    args.extend([
        "--source-sha256".into(),
        ContentDigest::sha256(b"different-source").to_text().into(),
    ]);
    let refused = run(&args)?;
    assert!(!refused.status.success());
    assert!(String::from_utf8(refused.stderr)?.contains(CUSTODY_ERROR));
    assert!(refused.stdout.is_empty());
    assert!(!directory.root().exists());
    assert_eq!(fs::read(directory.input())?, input);
    Ok(())
}

#[test]
fn explicit_ssrc_and_payload_pins_are_never_inferred_from_original_packets() -> Test {
    let directory = Directory::new("stream-pins")?;
    fs::write(directory.input(), synchronized(&[XML.as_bytes()])?)?;
    for (flag, value, reason) in [
        ("--ssrc", "43", "stream_mismatch"),
        ("--payload-type", "108", "payload_type_mismatch"),
    ] {
        let root = directory.0.join(reason);
        let mut args = import_args(&root, &directory.input());
        set(&mut args, flag, value)?;
        let imported = report(run(&args)?, false)?;
        assert_eq!(field(&imported, "complete_documents")?, "0");
        assert_eq!(field(&imported, "processing_complete")?, "false");
        assert_eq!(field(&imported, &format!("records.{reason}"))?, "3");
        let verified = report(
            run(&cold_args(
                "verify-rtp",
                &root,
                field(&imported, "import_identity")?,
            ))?,
            true,
        )?;
        assert_eq!(field(&verified, &format!("records.{reason}"))?, "3");
    }
    Ok(())
}

#[test]
fn unsupported_encoding_limits_flags_and_missing_owner_pins_refuse_before_io() -> Test {
    let directory = Directory::new("strict-arguments")?;
    let base = import_args(&directory.root(), &directory.input());
    // The input intentionally does not exist: argument failures must precede any read/open.
    for (flag, value) in [
        ("--encoding", "vnd.onvif.metadata+gzip"),
        ("--encoding", "vnd.onvif.metadata.exi.ext"),
        ("--clock-rate", "48000"),
        ("--max-input-bytes", "8388609"),
        ("--max-records", "16385"),
        ("--max-documents", "65"),
        ("--max-document-bytes", "262145"),
        ("--max-document-bytes", "0"),
        ("--max-fragments", "4097"),
        ("--document-timeout-ms", "0"),
        ("--document-timeout-ms", "60001"),
        ("--reorder-delay-ms", "0"),
        ("--document-index", "64"),
        ("--include-values", "maybe"),
        ("--interpretation", "events-v1"),
        ("--unknown", "value"),
    ] {
        let mut args = base.clone();
        args.extend([flag.into(), value.into()]);
        let refused = run(&args)?;
        assert_eq!(refused.status.code(), Some(2), "{flag}={value}");
        assert!(String::from_utf8(refused.stderr)?.contains(ARGUMENT_ERROR));
        assert!(refused.stdout.is_empty());
        assert!(!directory.root().exists());
    }
    for (flag, value) in [
        ("--ingress", "0"),
        ("--stream-generation", "0"),
        ("--payload-type", "95"),
        ("--payload-type", "128"),
        ("--received-end-ns", "99"),
    ] {
        let mut args = base.clone();
        set(&mut args, flag, value)?;
        let refused = run(&args)?;
        assert_eq!(refused.status.code(), Some(2), "{flag}={value}");
        assert!(String::from_utf8(refused.stderr)?.contains(ARGUMENT_ERROR));
        assert!(!directory.root().exists());
    }
    for flag in [
        "--ingress",
        "--stream-generation",
        "--ssrc",
        "--payload-type",
        "--device-generation",
        "--profile-generation",
        "--received-start-ns",
    ] {
        let mut args = base.clone();
        let index = args
            .iter()
            .position(|arg| arg == flag)
            .ok_or("fixture flag")?;
        args.drain(index..index + 2);
        let refused = run(&args)?;
        assert_eq!(refused.status.code(), Some(2), "missing {flag}");
        assert!(String::from_utf8(refused.stderr)?.contains(ARGUMENT_ERROR));
        assert!(!directory.root().exists());
    }
    let mut duplicate = base;
    duplicate.extend(["--ssrc".into(), "42".into()]);
    assert_eq!(run(&duplicate)?.status.code(), Some(2));
    assert!(!directory.root().exists());
    Ok(())
}

#[test]
fn document_selection_limits_disclosure_but_still_verifies_every_retained_document() -> Test {
    let directory = Directory::new("document-selection")?;
    let other = XML
        .replace("732103", "732104")
        .replace("private-module-canary", "other-module-canary")
        .replace("private&quot;class\\canary", "second-class-canary");
    fs::write(
        directory.input(),
        synchronized(&[XML.as_bytes(), other.as_bytes()])?,
    )?;
    let mut args = import_args(&directory.root(), &directory.input());
    args.extend([
        "--document-index".into(),
        "1".into(),
        "--include-values".into(),
        "yes".into(),
    ]);
    let imported = report(run(&args)?, true)?;
    assert_eq!(field(&imported, "complete_documents")?, "2");
    assert_eq!(field(&imported, "usable_documents")?, "2");
    assert_eq!(field(&imported, "document_selection")?, "1");
    assert!(!imported.lines().any(|line| line.starts_with("document.0.")));
    assert_eq!(
        field(&imported, "document.1.xml_sha256")?,
        ContentDigest::sha256(other.as_bytes()).to_text()
    );
    assert_eq!(
        field(&imported, "document.1.analytics.0.object.0.object_id")?,
        "\"732104\""
    );
    assert!(imported.contains("second-class-canary"));
    assert!(!imported.contains("private-module-canary"));
    assert!(field(&imported, "document.1.fragment.0")?.starts_with("record:3,sequence:103,"));
    let identity = field(&imported, "import_identity")?.to_owned();
    let mut selected = cold_args("verify-rtp", &directory.root(), &identity);
    selected.extend(["--document-index".into(), "1".into()]);
    fs::remove_file(directory.input())?;
    assert_eq!(
        field(&report(run(&selected)?, true)?, "complete_documents")?,
        "2"
    );
    let mut outside = selected.clone();
    set(&mut outside, "--document-index", "2")?;
    let refused = run(&outside)?;
    assert_eq!(refused.status.code(), Some(2));
    assert!(String::from_utf8(refused.stderr)?.contains(ARGUMENT_ERROR));
    // Fault only the unselected XML derivative in this test's own publication spool.
    let digest = ContentDigest::sha256(XML.as_bytes()).to_text();
    let unselected = directory
        .root()
        .join("objects/spool/objects")
        .join(digest.strip_prefix("sha256:").ok_or("SHA-256 hex")?);
    assert!(unselected.is_file());
    fs::remove_file(&unselected)?;
    let refused = run(&selected)?;
    assert!(!refused.status.success());
    assert!(String::from_utf8(refused.stderr)?.contains(CUSTODY_ERROR));
    assert!(!unselected.exists());
    Ok(())
}

#[test]
fn post_publication_bad_document_selection_preserves_recoverable_identity() -> Test {
    let directory = Directory::new("post-publication-selection")?;
    fs::write(directory.input(), synchronized(&[XML.as_bytes()])?)?;
    let mut args = import_args(&directory.root(), &directory.input());
    args.extend([
        "--document-index".into(),
        "1".into(),
        "--include-values".into(),
        "yes".into(),
    ]);
    let retained = report(run(&args)?, false)?;
    assert_eq!(field(&retained, "durable_publication")?, "true");
    assert_eq!(field(&retained, "phase")?, "retained_with_error");
    assert_eq!(field(&retained, "error")?, ARGUMENT_ERROR);
    assert_eq!(field(&retained, "values_disclosed")?, "false");
    assert!(!retained.contains("private-module-canary"));
    fs::remove_file(directory.input())?;
    let verified = report(
        run(&cold_args(
            "verify-rtp",
            &directory.root(),
            field(&retained, "import_identity")?,
        ))?,
        true,
    )?;
    assert_eq!(field(&verified, "complete_documents")?, "1");
    assert_eq!(field(&verified, "processing_complete")?, "true");
    assert_eq!(
        field(&verified, "publication_root")?,
        field(&retained, "publication_root")?
    );
    Ok(())
}
