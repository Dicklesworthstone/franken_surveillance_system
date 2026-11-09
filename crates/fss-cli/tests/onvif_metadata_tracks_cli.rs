#![forbid(unsafe_code)]
//! Actual-process source import -> bounded vendor-tracklet JSON, privacy and refusal contracts.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use fss_core::{
    ContentDigest,
    json_input::{Value, parse},
};

type Test<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const SITE: &str = "site:onvif-tracks-cli";
const PRIVATE_MODULE: &str = "private\"module\\canary";
const PRIVATE_OBJECT: &str = "8675309";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..64 {
            let path = std::env::temp_dir().join(format!(
                "fss-tracks-cli-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("owned fixture-directory capacity".into())
    }
    fn root(&self) -> PathBuf {
        self.0.join("deployment")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn binary() -> Test<PathBuf> {
    std::env::var_os("FSS_ONVIF_METADATA_BIN")
        .or_else(|| option_env!("CARGO_BIN_EXE_fss-onvif-metadata").map(OsString::from))
        .map(PathBuf::from)
        .ok_or_else(|| "missing metadata binary; set FSS_ONVIF_METADATA_BIN".into())
}
fn read_output(reader: impl Read) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(2 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err(io::Error::other("fixture output exceeded bound"));
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
    let stdout = child.stdout.take().ok_or("stdout pipe")?;
    let stderr = child.stderr.take().ok_or("stderr pipe")?;
    thread::scope(|scope| {
        let stdout = scope.spawn(move || read_output(stdout));
        let stderr = scope.spawn(move || read_output(stderr));
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("tracklet fixture command timed out".into());
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error.into());
                }
            }
        };
        Ok(Output {
            status,
            stdout: stdout.join().map_err(|_| "stdout thread")??,
            stderr: stderr.join().map_err(|_| "stderr thread")??,
        })
    })
}
fn success(output: Output) -> Test<String> {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}
fn line<'a>(output: &'a str, field: &str) -> Test<&'a str> {
    output
        .lines()
        .filter_map(|line| line.split_once('='))
        .find_map(|(name, value)| (name == field).then_some(value))
        .ok_or_else(|| format!("missing {field}").into())
}
fn field<'a>(value: &'a Value, name: &str) -> Test<&'a Value> {
    value
        .object()
        .and_then(|object| object.get(name))
        .ok_or_else(|| format!("missing JSON field {name}").into())
}
fn list<'a>(value: &'a Value, name: &str) -> Test<&'a [Value]> {
    field(value, name)?
        .array()
        .ok_or_else(|| format!("not an array: {name}").into())
}
fn xml(seconds: &[u8]) -> Vec<u8> {
    let frames: String = seconds.iter().map(|second| format!(r#"<t:Frame UtcTime="2026-10-28T00:00:{second:02}Z" Source="private&quot;module\canary"><t:Object ObjectId="8675309"/></t:Frame>"#)).collect();
    format!(r#"<t:MetadataStream xmlns:t="http://www.onvif.org/ver10/schema"><t:VideoAnalytics>{frames}</t:VideoAnalytics></t:MetadataStream>"#).into_bytes()
}
fn import_args(root: &Path, input: &Path, rtp: bool) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        if rtp { "import-rtp" } else { "import" }.into(),
        "--root".into(),
        root.into(),
        "--site".into(),
        SITE.into(),
        "--input".into(),
        input.into(),
        "--sensor".into(),
        "sensor:front".into(),
        "--device-generation".into(),
        ContentDigest::sha256(b"device").to_text().into(),
        "--profile-generation".into(),
        ContentDigest::sha256(b"profile").to_text().into(),
        "--profile".into(),
        "private-profile-canary".into(),
        "--received-start-ns".into(),
        "100".into(),
        "--received-end-ns".into(),
        "110".into(),
    ];
    if rtp {
        args.extend(
            [
                "--ingress",
                "17",
                "--stream-generation",
                "3",
                "--ssrc",
                "42",
                "--payload-type",
                "107",
            ]
            .into_iter()
            .map(Into::into),
        );
    }
    args
}
fn tracks_args(root: &Path, source_flag: &str, receipt: &str) -> Test<Vec<OsString>> {
    Ok(vec![
        "tracks".into(),
        "--root".into(),
        root.into(),
        "--site".into(),
        SITE.into(),
        source_flag.into(),
        format!(
            "{}@{}",
            line(receipt, "import_identity")?,
            line(receipt, "publication_root")?
        )
        .into(),
    ])
}
fn packet(sequence: u16, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut result = vec![0x80, 107 | if marker { 0x80 } else { 0 }];
    result.extend_from_slice(&sequence.to_be_bytes());
    result.extend_from_slice(&(sequence as u32 * 1000).to_be_bytes());
    result.extend_from_slice(&42_u32.to_be_bytes());
    result.extend_from_slice(payload);
    result
}
fn dump(documents: &[Vec<u8>]) -> Vec<u8> {
    let mut result = b"#!rtpplay1.0 192.0.2.1/5004\n".to_vec();
    result.extend_from_slice(&[0; 16]);
    let mut packets = vec![
        packet(100, false, b"unknown"),
        packet(101, true, b"boundary"),
    ];
    for (index, xml) in documents.iter().enumerate() {
        packets.push(packet(102 + index as u16, true, xml));
    }
    for (index, packet) in packets.iter().enumerate() {
        result.extend_from_slice(&((packet.len() + 8) as u16).to_be_bytes());
        result.extend_from_slice(&(packet.len() as u16).to_be_bytes());
        result.extend_from_slice(&(index as u32).to_be_bytes());
        result.extend_from_slice(packet);
    }
    result
}

#[test]
fn xml_import_to_tracks_is_private_by_default_and_explicit_values_are_json_escaped() -> Test {
    let directory = Directory::new("xml")?;
    let input = directory.0.join("source.xml");
    fs::write(&input, xml(&[0, 1]))?;
    let receipt = success(run(&import_args(&directory.root(), &input, false))?)?;
    fs::remove_file(input)?;
    let args = tracks_args(&directory.root(), "--xml-source", &receipt)?;
    let hidden_text = success(run(&args)?)?;
    assert!(!hidden_text.contains("private"));
    assert!(!hidden_text.contains(PRIVATE_OBJECT));
    assert!(!hidden_text.contains("2026-10-28"));
    let hidden = parse(&hidden_text)?;
    assert_eq!(
        field(&hidden, "schema")?.text(),
        Some("fss.onvif_vendor_tracklets_report.v1")
    );
    assert_eq!(field(&hidden, "provenance")?.text(), Some("derived"));
    assert_eq!(
        field(&hidden, "source_provenance")?.text(),
        Some("vendor_claimed")
    );
    assert_eq!(list(&hidden, "frames")?.len(), 2);
    assert_eq!(list(&hidden, "tracklets")?.len(), 1);
    assert_eq!(
        field(&list(&hidden, "occurrences")?[0], "values")?,
        &Value::Null
    );
    let mut revealed_args = args.clone();
    revealed_args.extend(["--include-values".into(), "yes".into()]);
    let revealed = parse(&success(run(&revealed_args)?)?)?;
    let values = field(&list(&revealed, "occurrences")?[0], "values")?;
    assert_eq!(
        field(values, "vendor_object_id")?.text(),
        Some(PRIVATE_OBJECT)
    );
    assert_eq!(field(values, "module_source")?.text(), Some(PRIVATE_MODULE));
    assert_eq!(
        field(&hidden, "snapshot_digest")?,
        field(&revealed, "snapshot_digest")?
    );
    assert_eq!(
        field(&hidden, "report_digest")?,
        field(&revealed, "report_digest")?
    );
    assert_eq!(success(run(&args)?)?, hidden_text);
    let source = &list(&hidden, "sources")?[0];
    assert_eq!(
        field(source, "identity")?.text(),
        Some(line(&receipt, "import_identity")?)
    );
    assert_eq!(
        field(source, "root")?.text(),
        Some(line(&receipt, "publication_root")?)
    );
    Ok(())
}

#[test]
fn rtp_import_to_tracks_keeps_document_custody_and_cross_document_vendor_run() -> Test {
    let directory = Directory::new("rtp")?;
    let input = directory.0.join("source.rtpdump");
    let docs = [xml(&[0]), xml(&[1])];
    fs::write(&input, dump(&docs))?;
    let receipt = success(run(&import_args(&directory.root(), &input, true))?)?;
    fs::remove_file(input)?;
    let report = parse(&success(run(&tracks_args(
        &directory.root(),
        "--rtp-source",
        &receipt,
    )?)?)?)?;
    assert_eq!(list(&report, "tracklets")?.len(), 1);
    let frames = list(&report, "frames")?;
    assert_eq!(frames.len(), 2);
    for (index, frame) in frames.iter().enumerate() {
        assert_eq!(
            field(frame, "document_index")?.integer(),
            Some(index as i128)
        );
        assert_eq!(
            field(frame, "source_digest")?.text(),
            Some(ContentDigest::sha256(&docs[index]).to_text().as_str())
        );
    }
    Ok(())
}

#[test]
fn required_root_duplicate_source_and_tiny_budget_refuse_without_partial_json() -> Test {
    let directory = Directory::new("refusal")?;
    let input = directory.0.join("source.xml");
    fs::write(&input, xml(&[0, 1]))?;
    let receipt = success(run(&import_args(&directory.root(), &input, false))?)?;
    let base = tracks_args(&directory.root(), "--xml-source", &receipt)?;
    let mut unpinned = base.clone();
    unpinned[6] = line(&receipt, "import_identity")?.into();
    let mut duplicated = base.clone();
    duplicated.extend(["--rtp-source".into(), base[6].clone()]);
    let mut limited = base.clone();
    limited.extend(["--max-read-bytes".into(), "1".into()]);
    for args in [unpinned, duplicated, limited] {
        let output = run(&args)?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains(PRIVATE_OBJECT));
    }
    let missing = directory.0.join("missing");
    let mut args = base;
    args[2] = missing.as_os_str().into();
    let output = run(&args)?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!missing.exists());
    Ok(())
}
