#![forbid(unsafe_code)]
//! Exact, owner-approved conversion of retained HTTP originals into a recording import.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use fss_cli::ExitIdentity;
use fss_cli::agent_json::{object, string};
use fss_codec_mjpeg::{DecodeBudget, stream::StreamBasis};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, CanonicalEncoder, ContentDigest, DigestAlgorithm, OperationId, PrincipalId,
    SensorId, StreamId, TimestampNs,
};
use fss_geometry::WorkBudget;
use fss_object::{MAX_MANIFEST_CHILDREN, SpoolLimits};
use fss_publication::{LocalPublicationLimits, LocalRootPublisher};
use fss_reference::ingest::CaptureHint;
use fss_reference::ingest::http_archive::{HttpWirePin, HttpWireScope};
use fss_reference::ingest::http_import::{
    HttpImportAuthority, HttpImportRequest, MAX_BYTES, MAX_FRAMES, import_http,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

const FORMAT: &str = "fss.http_mjpeg_import_operator.v1";
const CAPS: [&str; 4] = [
    "CAP-READ-MEDIA-001",
    "CAP-OBJECT-STAGE-001",
    "CAP-OBJECT-PUBLISH-001",
    "CAP-RETENTION-COMMIT-001",
];
const HELP: &str = "fss-import-http --archive EXISTING_ABSOLUTE_ARCHIVE --root ABSOLUTE_DEPLOYMENT --site SITE\n\
  --source sha256:HEX --generation N --receive-clock sha256:HEX --retention-evidence sha256:HEX\n\
  --head sha256:HEX --reads N --bytes N --sensor-id ID --stream-id ID --receive-time-ns N\n\
  --owner-authorized yes --read-originals yes --retain-originals yes [--approve sha256:PLAN]\n\
  Optional timing: --capture-start-ns N --capture-uncertainty-ns N --fps F (all three required).\n\
  Bounds: --max-frames 128 --max-source-bytes 67108864 --max-work 1000000000000\n\
          --max-framing-work 10000000000 --timeout-ms 30000. Optional --principal ID.\n\
  Without --approve: prints an exact plan without filesystem, clock or network I/O.\n\
  Replay selects ALL complete JPEGs from the exact pinned prefix; exceeded bounds refuse.\n\
  Original HTTP headers, wrappers and partial tail are copied into the recording custody.\n\
  The ordered JPEG stream is reconstructed media. No source EOF or capture clock is invented.\n\
  Native retained decode, inference and fss-event watch consume the returned import identity.\n\
  Existing destination sensor privacy masks apply when decoding. No pixels are printed.\n\
  Source and destination must be distinct, non-nested stores. Originals remain local unencrypted.\n\
  Existing publisher locks/recovery sync apply; archive opening is not forensic read-only.\n";

struct Options {
    archive: PathBuf,
    root: PathBuf,
    site: String,
    principal: String,
    request: HttpImportRequest,
    work: u64,
    framing: u64,
    timeout_ms: u64,
    approve: Option<ContentDigest>,
}

fn path(text: &str) -> Result<PathBuf, &'static str> {
    let path = PathBuf::from(text);
    if !path.is_absolute()
        || path.parent().is_none()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err("non-root absolute path without dot components required");
    }
    Ok(path)
}
fn digest(text: &str) -> Result<ContentDigest, &'static str> {
    let value = ContentDigest::parse(text).map_err(|_| "invalid digest")?;
    if value.algorithm() != DigestAlgorithm::Sha256 || value.bytes() == [0; 32] {
        return Err("nonzero SHA-256 digest required");
    }
    Ok(value)
}
impl Options {
    fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        if args.is_empty()
            || args.len() > 64
            || !args.len().is_multiple_of(2)
            || args.iter().any(|s| s.as_encoded_bytes().len() > 4096)
        {
            return Err("argument count or byte bound");
        }
        let allowed = [
            "--archive",
            "--root",
            "--site",
            "--principal",
            "--source",
            "--generation",
            "--receive-clock",
            "--retention-evidence",
            "--head",
            "--reads",
            "--bytes",
            "--sensor-id",
            "--stream-id",
            "--receive-time-ns",
            "--capture-start-ns",
            "--capture-uncertainty-ns",
            "--fps",
            "--owner-authorized",
            "--read-originals",
            "--retain-originals",
            "--approve",
            "--max-frames",
            "--max-source-bytes",
            "--max-work",
            "--max-framing-work",
            "--timeout-ms",
        ];
        let mut values = BTreeMap::new();
        for pair in args.as_chunks::<2>().0 {
            let key = pair[0].to_str().ok_or("UTF-8 option required")?;
            let value = pair[1].to_str().ok_or("UTF-8 value required")?;
            if !allowed.contains(&key) || value.is_empty() || value.starts_with("--") {
                return Err("unknown option or missing value");
            }
            if values.insert(key, value).is_some() {
                return Err("duplicate option");
            }
        }
        let required = |key: &str| values.get(key).copied().ok_or("required option missing");
        for key in [
            "--owner-authorized",
            "--read-originals",
            "--retain-originals",
        ] {
            if required(key)? != "yes" {
                return Err(
                    "explicit owner, original-read and destination-retention acknowledgements required",
                );
            }
        }
        let number = |key: &str, default: u64, high: u64| -> Result<u64, &'static str> {
            let n = match values.get(key) {
                None => default,
                Some(text) if text.bytes().all(|b| b.is_ascii_digit()) => {
                    text.parse().map_err(|_| "integer overflow")?
                }
                Some(_) => return Err("unsigned decimal integer required"),
            };
            if n == 0 || n > high {
                return Err("numeric bound exceeded");
            }
            Ok(n)
        };
        for key in ["--generation", "--reads", "--bytes"] {
            let _ = required(key)?;
        }
        let source = HttpWireScope {
            stream: StreamBasis {
                source: digest(required("--source")?)?.bytes(),
                generation: number("--generation", 0, u64::MAX)?,
            },
            receive_clock: digest(required("--receive-clock")?)?.bytes(),
            retention_evidence: digest(required("--retention-evidence")?)?.bytes(),
        };
        let pin = HttpWirePin {
            scope: source.digest().map_err(|_| "invalid source scope")?,
            head: digest(required("--head")?)?,
            reads: number("--reads", 0, 4096)?,
            bytes: number("--bytes", 0, MAX_BYTES)?,
        };
        let capture_hint = if ["--capture-start-ns", "--capture-uncertainty-ns", "--fps"]
            .iter()
            .any(|k| values.contains_key(k))
        {
            let start = required("--capture-start-ns")?
                .parse()
                .map_err(|_| "invalid capture start")?;
            let uncertainty = required("--capture-uncertainty-ns")?
                .parse()
                .map_err(|_| "invalid capture uncertainty")?;
            let fps = required("--fps")?
                .parse()
                .map_err(|_| "invalid assumed frame rate")?;
            Some(
                CaptureHint::new(TimestampNs(start), uncertainty, fps)
                    .map_err(|_| "invalid capture hint")?,
            )
        } else {
            None
        };
        let request = HttpImportRequest {
            source,
            pin,
            sensor: SensorId::parse(required("--sensor-id")?).map_err(|_| "invalid sensor")?,
            stream: StreamId::parse(required("--stream-id")?).map_err(|_| "invalid stream")?,
            receive_time: TimestampNs(
                required("--receive-time-ns")?
                    .parse()
                    .map_err(|_| "invalid explicit receive time")?,
            ),
            capture_hint,
            max_frames: number("--max-frames", 128, MAX_FRAMES as u64)? as usize,
            max_bytes: number("--max-source-bytes", MAX_BYTES, MAX_BYTES)?,
        };
        request.digest().map_err(|_| "invalid request")?;
        let archive = path(required("--archive")?)?;
        let root = path(required("--root")?)?;
        if archive.starts_with(&root) || root.starts_with(&archive) {
            return Err("distinct non-nested stores required");
        }
        let site = required("--site")?.to_owned();
        if site.len() > 256 || site.chars().any(char::is_control) {
            return Err("invalid site");
        }
        let principal = values
            .get("--principal")
            .copied()
            .unwrap_or("principal:local-operator")
            .to_owned();
        PrincipalId::parse(&principal).map_err(|_| "invalid principal")?;
        if principal.len() > 256 {
            return Err("principal byte bound");
        }
        Ok(Self {
            archive,
            root,
            site,
            principal,
            request,
            work: number("--max-work", 1_000_000_000_000, 1_000_000_000_000_000)?,
            framing: number("--max-framing-work", 10_000_000_000, 1_000_000_000_000_000)?,
            timeout_ms: number("--timeout-ms", 30_000, 600_000)?,
            approve: values.get("--approve").map(|s| digest(s)).transpose()?,
        })
    }
    fn approval(&self) -> Result<ContentDigest, &'static str> {
        let mut e = CanonicalEncoder::new();
        e.text("fss.http_mjpeg_import_cli_plan.v1");
        e.text("original-read:source-closed-destination-retention:no-network:v1");
        e.digest(self.request.digest().map_err(|_| "invalid request")?);
        e.text(self.archive.to_str().ok_or("UTF-8 path required")?);
        e.text(self.root.to_str().ok_or("UTF-8 path required")?);
        e.text(&self.site);
        e.text(&self.principal);
        e.u64(self.work);
        e.u64(self.framing);
        e.u64(self.timeout_ms);
        Ok(ContentDigest::sha256(&e.finish()))
    }
    fn preview(&self) -> Result<String, &'static str> {
        Ok(object(&[
            ("format", string(FORMAT)),
            ("kind", string("plan")),
            ("approval_digest", string(&self.approval()?.to_text())),
            (
                "archive",
                string(self.archive.to_str().ok_or("UTF-8 path required")?),
            ),
            (
                "root",
                string(self.root.to_str().ok_or("UTF-8 path required")?),
            ),
            ("site", string(&self.site)),
            ("principal", string(&self.principal)),
            (
                "request_digest",
                string(
                    &self
                        .request
                        .digest()
                        .map_err(|_| "invalid request")?
                        .to_text(),
                ),
            ),
            ("source_scope", string(&self.request.pin.scope.to_text())),
            (
                "source",
                object(&[
                    (
                        "identity",
                        string(
                            &ContentDigest::new(
                                DigestAlgorithm::Sha256,
                                self.request.source.stream.source,
                            )
                            .to_text(),
                        ),
                    ),
                    (
                        "generation",
                        self.request.source.stream.generation.to_string(),
                    ),
                    (
                        "receive_clock",
                        string(
                            &ContentDigest::new(
                                DigestAlgorithm::Sha256,
                                self.request.source.receive_clock,
                            )
                            .to_text(),
                        ),
                    ),
                    (
                        "retention_evidence",
                        string(
                            &ContentDigest::new(
                                DigestAlgorithm::Sha256,
                                self.request.source.retention_evidence,
                            )
                            .to_text(),
                        ),
                    ),
                ]),
            ),
            ("head", string(&self.request.pin.head.to_text())),
            ("original_reads", self.request.pin.reads.to_string()),
            ("original_bytes", self.request.pin.bytes.to_string()),
            ("sensor_id", string(self.request.sensor.as_str())),
            ("stream_id", string(self.request.stream.as_str())),
            (
                "receive_time_ns",
                string(&self.request.receive_time.0.to_string()),
            ),
            (
                "capture_time_label",
                string(if self.request.capture_hint.is_some() {
                    "operator_assumption"
                } else {
                    "unknown"
                }),
            ),
            (
                "capture_hint",
                self.request.capture_hint.map_or_else(
                    || "null".into(),
                    |h| {
                        object(&[
                            ("start_ns", string(&h.start_ns.0.to_string())),
                            ("uncertainty_ns", h.uncertainty_ns.to_string()),
                            ("assumed_fps", h.assumed_fps.to_string()),
                        ])
                    },
                ),
            ),
            ("maximum_frames", self.request.max_frames.to_string()),
            ("maximum_source_bytes", self.request.max_bytes.to_string()),
            ("maximum_work", self.work.to_string()),
            ("maximum_framing_work", self.framing.to_string()),
            ("timeout_ms", self.timeout_ms.to_string()),
            ("writes", string("none")),
            ("network", string("none")),
            (
                "retention",
                string("all_original_headers_media_and_tail_in_destination_custody"),
            ),
        ]))
    }
}

struct Owner<'a> {
    options: &'a Options,
    cx: &'a ReplayCx,
    authority: &'a ContextAuthority,
    start: Instant,
}
impl HttpImportAuthority for Owner<'_> {
    fn permit(&self, request: &HttpImportRequest, destination: &ReferenceDeployment) -> bool {
        self.options.request.digest().ok() == request.digest().ok()
            && destination.root() == self.options.root
            && destination.site_lineage() == self.options.site
            && self.cx.checkpoint("import_http:operator").is_ok()
            && self.authority.cancellation_reason.is_none()
            && CAPS.iter().all(|c| self.authority.has_capability(c))
            && self.start.elapsed() < Duration::from_millis(self.options.timeout_ms)
    }
}
fn existing_directory(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_dir())
}
fn execute(options: &Options) -> Result<String, &'static str> {
    // Exact approval precedes all filesystem and clock use, including context construction.
    let approval = options.approval()?;
    if options.approve != Some(approval) {
        return Err("ERR-HTTP-IMPORT-APPROVAL-001");
    }
    let mut capabilities: Vec<_> = CAPS.iter().map(|c| (*c).to_owned()).collect();
    capabilities.push("ADP-REPLAY-001".into());
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:http-import".into(),
        operation_id: OperationId::parse("operation:http-import")
            .map_err(|_| fss_cli::ERR_CLI_RUNTIME_FAILURE)?,
        principal: options.principal.clone(),
        capabilities,
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(1024 * 1024 * 1024)
            .storage_operations(1_000_000)
            .build()
            .map_err(|_| fss_cli::ERR_CLI_RUNTIME_FAILURE)?,
        privacy_scope: "privacy:owner-original-http-custody".into(),
        retention_scope: "retention:source-closed-http-import".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })
    .map_err(|_| fss_cli::ERR_CLI_RUNTIME_FAILURE)?;
    authority
        .validate()
        .map_err(|_| fss_cli::ERR_CLI_RUNTIME_FAILURE)?;
    let start = Instant::now();
    for name in ["", "spool", "roots", "tombstones"] {
        if !existing_directory(&options.archive.join(name)) {
            return Err("ERR-HTTP-IMPORT-SOURCE-001");
        }
    }
    let source = options
        .archive
        .canonicalize()
        .map_err(|_| "ERR-HTTP-IMPORT-SOURCE-001")?;
    let target = match std::fs::symlink_metadata(&options.root) {
        Ok(m) if m.file_type().is_dir() => options
            .root
            .canonicalize()
            .map_err(|_| "ERR-HTTP-IMPORT-REQUEST-001")?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => options
            .root
            .parent()
            .ok_or("ERR-HTTP-IMPORT-REQUEST-001")?
            .canonicalize()
            .map_err(|_| "ERR-HTTP-IMPORT-REQUEST-001")?
            .join(
                options
                    .root
                    .file_name()
                    .ok_or("ERR-HTTP-IMPORT-REQUEST-001")?,
            ),
        _ => return Err("ERR-HTTP-IMPORT-REQUEST-001"),
    };
    if source.starts_with(&target) || target.starts_with(&source) {
        return Err("ERR-HTTP-IMPORT-REQUEST-001");
    }
    let cx = ReplayCx::from_context_authority(&authority, options.root.clone())
        .map_err(|_| "ERR-HTTP-IMPORT-AUTHORITY-001")?;
    let owner = Owner {
        options,
        cx: &cx,
        authority: &authority,
        start,
    };
    if start.elapsed() >= Duration::from_millis(options.timeout_ms) {
        return Err("ERR-HTTP-IMPORT-AUTHORITY-001");
    }
    let source = LocalRootPublisher::open(
        &options.archive,
        LocalPublicationLimits::new(
            65536,
            MAX_MANIFEST_CHILDREN,
            65536,
            65536,
            SpoolLimits::new(65536, 1024 * 1024 * 1024, 16 * 1024 * 1024, 131072),
        ),
    )
    .map_err(|_| "ERR-HTTP-IMPORT-SOURCE-001")?;
    cx.checkpoint("import_http:destination")
        .map_err(|_| "ERR-HTTP-IMPORT-AUTHORITY-001")?;
    if start.elapsed() >= Duration::from_millis(options.timeout_ms) {
        return Err("ERR-HTTP-IMPORT-AUTHORITY-001");
    }
    let mut destination = ReferenceDeployment::open(&options.root, &options.site, &cx)
        .map_err(|_| "ERR-HTTP-IMPORT-CUSTODY-001")?;
    let mut work = WorkBudget::new(options.work);
    let mut framing = DecodeBudget::new(options.framing);
    let receipt = import_http(
        &source,
        &mut destination,
        &options.request,
        &owner,
        &cx,
        &mut work,
        &mut framing,
    )
    .map_err(|e| e.stable_id())?;
    Ok(object(&[
        ("format", string(FORMAT)),
        ("kind", string("imported")),
        (
            "import_identity",
            string(&receipt.import_identity.to_text()),
        ),
        ("import_root", string(&receipt.import_root.to_text())),
        (
            "manifest_digest",
            string(&receipt.manifest_digest.to_text()),
        ),
        ("origin_proof", string(&receipt.proof.to_text())),
        ("frames", receipt.frames.to_string()),
        ("source_ending", string(receipt.ending.as_str())),
        ("capture_time_label", string(receipt.capture_time_label)),
        ("reused", receipt.reused.to_string()),
        (
            "original_bytes_retained",
            options.request.pin.bytes.to_string(),
        ),
        ("source_archive_retained_separately", "true".into()),
        ("network", string("none")),
        ("work_used", work.used().to_string()),
    ]))
}
fn emit(text: &str) -> io::Result<()> {
    if text.len() > 16 * 1024 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut out = io::stdout().lock();
    let line = format!("{text}\n");
    let mut bytes = line.as_bytes();
    let mut interrupted = 0;
    while !bytes.is_empty() {
        match out.write(&bytes[..bytes.len().min(4096)]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) if n <= bytes.len().min(4096) => {
                bytes = &bytes[n..];
                interrupted = 0;
            }
            Ok(_) => return Err(io::ErrorKind::InvalidData.into()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted && interrupted < 7 => interrupted += 1,
            Err(e) => return Err(e),
        }
    }
    out.flush()
}
fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).take(65).collect();
    if args.len() == 1 && matches!(args[0].to_str(), Some("--help" | "help")) {
        return ExitCode::from(if emit(HELP).is_ok() {
            ExitIdentity::SUCCESS.code
        } else {
            ExitIdentity::RUNTIME_FAILURE.code
        });
    }
    let options = match Options::parse(&args) {
        Ok(options) => options,
        Err(reason) => {
            eprintln!("ERR-CLI-MALFORMED-VALUE-001: {reason}. Use fss-import-http --help.");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    let result = if options.approve.is_none() {
        options.preview()
    } else {
        execute(&options)
    };
    match result {
        Ok(report) if emit(&report).is_ok() => ExitCode::from(ExitIdentity::SUCCESS.code),
        Ok(_) => {
            eprintln!(
                "ERR-CLI-RUNTIME-FAILURE-001: output failed; an approved import may already be durable. Retry the exact plan to reconcile."
            );
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
        Err(code) => {
            eprintln!(
                "{code}: import not confirmed by this attempt; retain the exact plan for reconciliation."
            );
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args() -> Vec<OsString> {
        let sha = ContentDigest::sha256(b"fixture").to_text();
        [
            "--archive",
            "/absent-http-import-fixture/source",
            "--root",
            "/absent-http-import-fixture/destination",
            "--site",
            "site:test",
            "--source",
            &sha,
            "--generation",
            "1",
            "--receive-clock",
            &sha,
            "--retention-evidence",
            &sha,
            "--head",
            &sha,
            "--reads",
            "1",
            "--bytes",
            "100",
            "--sensor-id",
            "sensor:test",
            "--stream-id",
            "stream:test",
            "--receive-time-ns",
            "2000000000",
            "--owner-authorized",
            "yes",
            "--read-originals",
            "yes",
            "--retain-originals",
            "yes",
        ]
        .iter()
        .map(OsString::from)
        .collect()
    }
    #[test]
    fn preview_is_pure_and_approval_binds_destination_sensor_and_time() -> Result<(), &'static str>
    {
        let original = Options::parse(&args())?;
        let approval = original.approval()?;
        assert!(original.preview()?.contains("\"writes\":\"none\""));
        for (key, value) in [
            ("--root", "/absent-http-import-fixture/other"),
            ("--sensor-id", "sensor:other"),
            ("--receive-time-ns", "3000000000"),
        ] {
            let mut changed = args();
            let position = changed
                .iter()
                .position(|s| s == key)
                .ok_or("fixture option")?;
            changed[position + 1] = value.into();
            let mut changed = Options::parse(&changed)?;
            assert_ne!(changed.approval()?, approval);
            changed.approve = Some(approval);
            assert_eq!(
                execute(&changed).err(),
                Some("ERR-HTTP-IMPORT-APPROVAL-001")
            );
        }
        Ok(())
    }
    #[test]
    fn independent_original_permissions_and_complete_timing_are_required()
    -> Result<(), &'static str> {
        for key in ["--read-originals", "--retain-originals"] {
            let mut changed = args();
            let position = changed
                .iter()
                .position(|s| s == key)
                .ok_or("fixture option")?;
            changed[position + 1] = "no".into();
            assert!(Options::parse(&changed).is_err());
        }
        let mut changed = args();
        changed.extend([OsString::from("--fps"), OsString::from("30")]);
        assert!(Options::parse(&changed).is_err());
        Ok(())
    }
}
