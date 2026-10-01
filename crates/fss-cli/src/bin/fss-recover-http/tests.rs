#![forbid(unsafe_code)]
use super::*;
use fss_codec_mjpeg::stream::StreamBasis;
use fss_object::ObjectManifest;
use fss_reference::ingest::http_archive::{HTTP_WIRE_KIND, HttpWireScope};
use fss_reference::ingest::http_camera::HttpWireReceipt;
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};

type Test = Result<(), Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
const RAW: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace\r\n";

fn key() -> Result<(HttpWireRecoveryKey, Vec<u8>), Box<dyn std::error::Error>> {
    let source = StreamBasis {
        source: [51; 32],
        generation: 9,
    };
    let scope = HttpWireScope {
        stream: source,
        receive_clock: [52; 32],
        retention_evidence: [53; 32],
    };
    let prior = HttpWirePin {
        scope: scope.digest()?,
        head: scope.digest()?,
        reads: 0,
        bytes: 0,
    };
    let wire = HttpWireReceipt {
        basis: source,
        range: [0, RAW.len() as u64],
        sha256: ContentDigest::sha256(RAW).bytes(),
        admitted_ns: 100,
    };
    // Explicit fixture for the existing canonical read record, not a simulated camera receipt.
    let mut e = CanonicalEncoder::new();
    e.text("fss.http_camera_wire.v1");
    e.digest(prior.scope);
    e.digest(prior.head);
    e.u64(0);
    e.u64(0);
    e.digest(ContentDigest::new(DigestAlgorithm::Sha256, source.source));
    e.u64(source.generation);
    e.u64(0);
    e.u64(RAW.len() as u64);
    e.digest(ContentDigest::sha256(RAW));
    e.u64(100);
    let metadata = e.finish();
    let manifest = ObjectManifest::new(
        HTTP_WIRE_KIND,
        [ContentDigest::sha256(RAW)],
        Some(ContentDigest::sha256(&metadata)),
    )?;
    let expected = HttpWirePin {
        scope: prior.scope,
        head: manifest.root(),
        reads: 1,
        bytes: RAW.len() as u64,
    };
    Ok((
        HttpWireRecoveryKey::new(scope, prior, wire, expected)?,
        metadata,
    ))
}
fn args(root: &str) -> Result<Vec<OsString>, Box<dyn std::error::Error>> {
    Ok([
        "--root".to_owned(),
        root.to_owned(),
        "--recovery-key".to_owned(),
        key()?.0.to_text()?,
        "--owner-authorized".to_owned(),
        "yes".to_owned(),
        "--retain-originals".to_owned(),
        "yes".to_owned(),
    ]
    .into_iter()
    .map(Into::into)
    .collect())
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self, std::io::Error> {
        for _ in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-recover-cli-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::other("directory collision bound"))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn staged() -> Result<(Directory, Options), Box<dyn std::error::Error>> {
    let dir = Directory::new()?;
    let mut options = Options::parse(&args(dir.0.to_str().ok_or("path")?)?)?;
    let mut publisher = LocalRootPublisher::open(&dir.0, options.storage_limits())?;
    publisher.stage_object(RAW)?;
    publisher.stage_object(&key()?.1)?;
    options.approve = Some(options.approval()?);
    drop(publisher);
    Ok((dir, options))
}

#[test]
fn preview_is_pure_and_never_claims_a_read_has_been_recovered() -> Test {
    let dir = Directory::new()?;
    let absent = dir.0.join("absent");
    let options = Options::parse(&args(absent.to_str().ok_or("path")?)?)?;
    let preview = options.preview()?;
    assert!(!absent.exists());
    assert!(options.approve.is_none());
    assert!(preview.contains("\"writes\":\"none\""));
    assert!(preview.contains("\"network\":\"none\""));
    assert!(!preview.contains("local_durable"));
    assert!(!preview.contains("HTTP/1.1"));
    Ok(())
}

#[test]
fn approval_binds_root_actor_key_and_every_runtime_limit() -> Test {
    let original = args("/tmp/fss-recovery-approval")?;
    let base = Options::parse(&original)?.approval()?;
    for (flag, value) in [
        ("--root", "/tmp/fss-recovery-other"),
        ("--principal", "principal:other"),
        ("--timeout-ms", "20000"),
        ("--max-work", "1000000"),
        ("--max-reads", "2"),
        ("--max-source-bytes", "65536"),
        ("--max-scan-roots", "128"),
        ("--max-object-bytes", "65536"),
    ] {
        let mut changed = original.clone();
        if let Some(i) = changed.iter().position(|part| part == flag) {
            changed[i + 1] = value.into();
        } else {
            changed.extend([flag.into(), value.into()]);
        }
        assert_ne!(Options::parse(&changed)?.approval()?, base, "{flag}");
    }
    let mut approved = original;
    approved.extend(["--approve".into(), base.to_text().into()]);
    assert_eq!(Options::parse(&approved)?.approval()?, base);
    Ok(())
}

#[test]
fn stale_approval_refuses_before_output_or_replacement_archive_creation() -> Test {
    let dir = Directory::new()?;
    let absent = dir.0.join("absent");
    let mut options = Options::parse(&args(absent.to_str().ok_or("path")?)?)?;
    options.approve = Some(ContentDigest::sha256(b"stale"));
    let mut output = Vec::new();
    assert_eq!(
        recover(&options, &mut output),
        Err("ERR-HTTP-WIRE-RECOVERY-APPROVAL-001")
    );
    assert!(output.is_empty());
    assert!(!absent.exists());
    options.approve = Some(options.approval()?);
    assert_eq!(
        recover(&options, &mut output),
        Err("ERR-HTTP-WIRE-RECOVERY-ROOT-001")
    );
    assert!(!absent.exists());
    Ok(())
}

#[test]
fn approved_cold_recovery_and_an_exact_rerun_produce_one_root() -> Test {
    let (dir, options) = staged()?;
    let mut output = Vec::new();
    recover(&options, &mut output)?;
    let report = String::from_utf8(output)?;
    assert!(report.contains("\"kind\":\"recovered\""));
    assert!(report.contains("\"local_durable\":true"));
    assert!(report.contains("\"capture_resumed\":false"));
    assert!(report.contains("\"parser_acknowledged\":false"));
    assert!(!report.contains("Content-Type"));
    let publisher = LocalRootPublisher::open(&dir.0, options.storage_limits())?;
    assert_eq!(publisher.visible_roots().count(), 1);
    drop(publisher);
    let mut output = Vec::new();
    recover(&options, &mut output)?;
    assert!(String::from_utf8(output)?.contains("\"prior_state\":\"durable\""));
    let publisher = LocalRootPublisher::open(&dir.0, options.storage_limits())?;
    assert_eq!(publisher.visible_roots().count(), 1);
    Ok(())
}

struct RejectVerified;
impl Write for RejectVerified {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if String::from_utf8_lossy(bytes).contains("verified_before_recovery") {
            Err(io::Error::other("sink refused"))
        } else {
            Ok(bytes.len())
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn a_failed_prepublication_sink_prevents_root_publication() -> Test {
    let (dir, options) = staged()?;
    assert_eq!(
        recover(&options, &mut RejectVerified),
        Err("ERR-HTTP-WIRE-RECOVERY-OUTPUT-001")
    );
    let publisher = LocalRootPublisher::open(&dir.0, options.storage_limits())?;
    assert_eq!(publisher.visible_roots().count(), 0);
    assert_eq!(publisher.spool().read(ContentDigest::sha256(RAW))?, RAW);
    Ok(())
}

struct RejectFinal;
impl Write for RejectFinal {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if String::from_utf8_lossy(bytes).contains("\"kind\":\"recovered\"") {
            Err(io::Error::other("lost final output"))
        } else {
            Ok(bytes.len())
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn lost_final_output_does_not_rollback_a_durable_read_and_retry_is_safe() -> Test {
    let (dir, options) = staged()?;
    assert_eq!(
        recover(&options, &mut RejectFinal),
        Err("ERR-HTTP-WIRE-RECOVERY-OUTPUT-001")
    );
    let publisher = LocalRootPublisher::open(&dir.0, options.storage_limits())?;
    assert_eq!(publisher.visible_roots().count(), 1);
    drop(publisher);
    recover(&options, &mut Vec::new())?;
    let publisher = LocalRootPublisher::open(&dir.0, options.storage_limits())?;
    assert_eq!(publisher.visible_roots().count(), 1);
    Ok(())
}

#[test]
fn malformed_arguments_and_unapproved_scope_are_refused() -> Test {
    for suffix in [
        vec!["--principal"],
        vec!["--network", "yes"],
        vec!["--max-work", "0"],
        vec!["--max-reads", "4097"],
        vec!["--max-work", "18446744073709551616"],
        vec!["--root", "/tmp/duplicate"],
    ] {
        let mut values = args("/tmp/fss-recovery")?;
        values.extend(suffix.into_iter().map(OsString::from));
        assert!(Options::parse(&values).is_err());
    }
    for (flag, value) in [
        ("--root", "relative"),
        ("--root", "/"),
        ("--root", "/tmp/../escape"),
        ("--recovery-key", "hex:00"),
        ("--owner-authorized", "no"),
        ("--retain-originals", "no"),
    ] {
        let mut values = args("/tmp/fss-recovery")?;
        let i = values.iter().position(|part| part == flag).ok_or("flag")?;
        values[i + 1] = value.into();
        assert!(Options::parse(&values).is_err());
    }
    Ok(())
}

struct Interrupted(Cell<u32>);
impl Write for Interrupted {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        self.0.set(self.0.get() + 1);
        Err(io::ErrorKind::Interrupted.into())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn output_interruption_retries_are_bounded() {
    let mut sink = Interrupted(Cell::new(0));
    assert_eq!(
        emit(&mut sink, "{}"),
        Err("ERR-HTTP-WIRE-RECOVERY-OUTPUT-001")
    );
    assert_eq!(sink.0.get(), 8);
}

#[test]
fn missing_metadata_reports_the_custody_refusal_without_source_disclosure() -> Test {
    let dir = Directory::new()?;
    let mut options = Options::parse(&args(dir.0.to_str().ok_or("path")?)?)?;
    let mut p = LocalRootPublisher::open(&dir.0, options.storage_limits())?;
    p.stage_object(RAW)?;
    drop(p);
    options.approve = Some(options.approval()?);
    let mut out = Vec::new();
    assert_eq!(
        recover(&options, &mut out),
        Err("ERR-HTTP-WIRE-RECOVERY-CUSTODY-001")
    );
    let text = String::from_utf8(out)?;
    assert!(text.contains("\"kind\":\"refused\""));
    assert!(text.contains("\"stage\":\"inspect\""));
    assert!(text.contains("HTTP source archive refused: Storage"));
    assert!(!text.contains("HTTP/1.1"));
    let p = LocalRootPublisher::open(&dir.0, options.storage_limits())?;
    assert_eq!(p.visible_roots().count(), 0);
    assert!(p.spool().read(ContentDigest::sha256(&key()?.1)).is_err());
    Ok(())
}
