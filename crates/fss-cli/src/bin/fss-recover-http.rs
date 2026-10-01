#![forbid(unsafe_code)]
//! Explicit cold recovery of a saved HTTP original-read key. Never connects to a camera.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Component, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use fss_cli::ExitIdentity;
use fss_cli::agent_json::{object, string};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, CanonicalEncoder, ContentDigest, DigestAlgorithm, OperationId, PrincipalId};
use fss_geometry::WorkBudget;
use fss_object::{MAX_MANIFEST_CHILDREN, SpoolLimits};
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, PublishCancellation, PublishCutPoint};
use fss_reference::ReplayCx;
use fss_reference::ingest::http_archive::{HttpArchiveError, HttpArchiveLimits, HttpWirePin};
use fss_reference::ingest::http_archive::recovery::HttpWireRecoveryKey;

const FORMAT: &str = "fss.http_wire_recovery_operator.v1";
const DOMAIN: &str = "fss.http_wire_recovery_approval.v1";
const CAPS: [&str; 4] = ["CAP-READ-MEDIA-001", "CAP-OBJECT-STAGE-001", "CAP-OBJECT-PUBLISH-001", "CAP-RETENTION-COMMIT-001"];
const MAX_ARGS: usize = 28;
const HELP: &str = "fss-recover-http --root EXISTING_ABSOLUTE_ARCHIVE --recovery-key hex:KEY\n\
  --owner-authorized yes --retain-originals yes [--approve sha256:APPROVAL]\n\
  Without --approve: exact plan only, no filesystem, clock or network I/O.\n\
  Preserve a wire_prepared.recovery_key from fss-capture-reconnect --recoverable yes.\n\
  Review the plan, then repeat with its approval. The key is NOT an approval or custody proof.\n\
  Recovery requires the original bytes AND read metadata already staged in the same archive.\n\
  Re-verifies every predecessor; never overwrites conflicting roots or follows later history.\n\
  No camera connection, parser ACK, capture resume, decode, completion, event or coverage claim.\n\
  Bounds: --timeout-ms 30000 --max-work 1000000000000 --max-reads 4096\n\
          --max-source-bytes 268435456 --max-scan-roots 65536 --max-object-bytes 16777216.\n\
  Optional --principal ID is an audit label, not remote authentication.\n\
  Ordinary publisher open takes locks and syncs recovered roots; it is not forensic read-only.\n\
  Original headers/media stay local unencrypted custody. No raw bytes or pixels are printed.\n";

#[derive(Debug)]
struct Options {
    root: PathBuf,
    principal: String,
    key: HttpWireRecoveryKey,
    limits: HttpArchiveLimits,
    work: u64,
    timeout_ms: u64,
    approve: Option<ContentDigest>,
}
impl Options {
    fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        if args.is_empty() || args.len() > MAX_ARGS || args.len() % 2 != 0
            || args.iter().any(|s| s.as_encoded_bytes().len() > 4096)
        { return Err("argument count or byte bound"); }
        let allowed = ["--root", "--principal", "--recovery-key", "--owner-authorized",
            "--retain-originals", "--approve", "--timeout-ms", "--max-work", "--max-reads",
            "--max-source-bytes", "--max-scan-roots", "--max-object-bytes"];
        let mut values = BTreeMap::new();
        for pair in args.chunks_exact(2) {
            let key = pair[0].to_str().ok_or("UTF-8 option required")?;
            let value = pair[1].to_str().ok_or("UTF-8 value required")?;
            if !allowed.contains(&key) || value.is_empty() || value.starts_with("--") {
                return Err("unknown option or missing value");
            }
            if values.insert(key, value).is_some() { return Err("duplicate option"); }
        }
        let required = |key: &str| values.get(key).copied().ok_or("required option missing");
        for key in ["--owner-authorized", "--retain-originals"] {
            if required(key)? != "yes" { return Err("explicit owner and original-retention acknowledgements required"); }
        }
        let root = PathBuf::from(required("--root")?);
        if !root.is_absolute() || root.parent().is_none()
            || root.components().any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        { return Err("non-root absolute archive path without dot components required"); }
        let key = HttpWireRecoveryKey::from_text(required("--recovery-key")?)
            .map_err(|_| "invalid or noncanonical recovery key")?;
        let number = |key: &str, default: u64, low: u64, high: u64| -> Result<u64, &'static str> {
            let value = match values.get(key) {
                None => default,
                Some(text) if text.bytes().all(|b| b.is_ascii_digit()) => text.parse().map_err(|_| "integer overflow")?,
                Some(_) => return Err("unsigned decimal required"),
            };
            if !(low..=high).contains(&value) { return Err("numeric bound exceeded"); }
            Ok(value)
        };
        let principal = values.get("--principal").copied().unwrap_or("principal:local-operator").to_owned();
        PrincipalId::parse(&principal).map_err(|_| "invalid principal")?;
        if principal.len() > 256 { return Err("principal byte bound"); }
        let limits = HttpArchiveLimits {
            maximum_reads: number("--max-reads", 4096, 1, 4096)? as usize,
            maximum_bytes: number("--max-source-bytes", 256 * 1024 * 1024, 1, 256 * 1024 * 1024)?,
            maximum_scan_roots: number("--max-scan-roots", 65536, 1, 65536)? as usize,
            maximum_spool_object_bytes: number("--max-object-bytes", 16 * 1024 * 1024, 1024, 16 * 1024 * 1024)? as usize,
        };
        if key.expected_pin().reads > limits.maximum_reads as u64 || key.expected_pin().bytes > limits.maximum_bytes {
            return Err("recovery key exceeds declared limits");
        }
        let approve = values.get("--approve").map(|text| {
            let digest = ContentDigest::parse(text).map_err(|_| "invalid approval digest")?;
            if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
                return Err("nonzero SHA-256 approval required");
            }
            Ok(digest)
        }).transpose()?;
        Ok(Self {
            root, principal, key, limits, approve,
            work: number("--max-work", 1_000_000_000_000, 1, 1_000_000_000_000_000)?,
            timeout_ms: number("--timeout-ms", 30_000, 1, 600_000)?,
        })
    }
    fn storage_limits(&self) -> LocalPublicationLimits {
        LocalPublicationLimits::new(65536, MAX_MANIFEST_CHILDREN, 65536, 65536,
            SpoolLimits::new(65536, 1024 * 1024 * 1024, self.limits.maximum_spool_object_bytes, 131072))
    }
    fn approval(&self) -> Result<ContentDigest, &'static str> {
        let mut e = CanonicalEncoder::new();
        e.text(DOMAIN);
        e.text("one-staged-read:full-predecessor-verification:no-network:no-implicit-repair:v1");
        e.text(self.root.to_str().ok_or("UTF-8 root required")?);
        e.text(&self.principal);
        e.digest(self.key.digest().map_err(|_| "invalid recovery key")?);
        for value in [self.limits.maximum_reads as u64, self.limits.maximum_bytes,
            self.limits.maximum_scan_roots as u64, self.limits.maximum_spool_object_bytes as u64,
            self.work, self.timeout_ms, 65536, MAX_MANIFEST_CHILDREN as u64, 65536, 65536,
            65536, 1024 * 1024 * 1024, 131072]
        { e.u64(value); }
        Ok(ContentDigest::sha256(&e.finish()))
    }
    fn preview(&self) -> Result<String, &'static str> {
        Ok(object(&[
            ("format", string(FORMAT)), ("kind", string("plan")),
            ("approval_digest", string(&self.approval()?.to_text())),
            ("root", string(self.root.to_str().ok_or("UTF-8 root required")?)),
            ("principal", string(&self.principal)),
            ("key_digest", string(&self.key.digest().map_err(|_| "invalid recovery key")?.to_text())),
            ("prior", pin_json(self.key.prior_pin())), ("expected", pin_json(self.key.expected_pin())),
            ("maximum_reads", self.limits.maximum_reads.to_string()),
            ("maximum_source_bytes", self.limits.maximum_bytes.to_string()),
            ("maximum_scan_roots", self.limits.maximum_scan_roots.to_string()),
            ("maximum_object_bytes", self.limits.maximum_spool_object_bytes.to_string()),
            ("maximum_work", self.work.to_string()), ("timeout_ms", self.timeout_ms.to_string()),
            ("writes", string("none")), ("network", string("none")),
            ("scope", string("one_original_read_not_capture_resume_or_completion")),
            ("retention", string("original_headers_and_media_local_unencrypted")),
        ]))
    }
}
fn pin_json(pin: HttpWirePin) -> String {
    object(&[("scope", string(&pin.scope.to_text())), ("head", string(&pin.head.to_text())),
        ("reads", pin.reads.to_string()), ("bytes", pin.bytes.to_string())])
}
fn emit(out: &mut impl Write, row: &str) -> Result<(), &'static str> {
    if row.len() > 16 * 1024 { return Err("ERR-HTTP-WIRE-RECOVERY-OUTPUT-001"); }
    let text = format!("{row}\n");
    let mut remaining = text.as_bytes();
    let mut interrupts = 0;
    while !remaining.is_empty() {
        let maximum = remaining.len().min(4096);
        match out.write(&remaining[..maximum]) {
            Ok(n) if n > 0 && n <= maximum => { remaining = &remaining[n..]; interrupts = 0; }
            Err(e) if e.kind() == io::ErrorKind::Interrupted && interrupts < 7 => interrupts += 1,
            _ => return Err("ERR-HTTP-WIRE-RECOVERY-OUTPUT-001"),
        }
    }
    out.flush().map_err(|_| "ERR-HTTP-WIRE-RECOVERY-OUTPUT-001")
}
// Keep the owning subsystem's typed reason without printing private OS paths or source bytes.
fn custody_refusal(out: &mut impl Write, stage: &str, reason: HttpArchiveError,
    expected: HttpWirePin, work: &WorkBudget<'_>) -> Result<(), &'static str>
{
    emit(out, &object(&[
        ("format", string(FORMAT)), ("kind", string("refused")), ("stage", string(stage)),
        ("error_code", string("ERR-HTTP-WIRE-RECOVERY-CUSTODY-001")),
        ("reason", string(&reason.to_string())), ("expected", pin_json(expected)),
        ("publication", string("not_confirmed_by_this_attempt")),
        ("staged_or_visible_work_may_remain", "true".to_owned()),
        ("capture_resumed", "false".to_owned()), ("network", string("none")),
        ("work_used", work.used().to_string()), ("work_remaining", work.remaining().to_string()),
    ]))
}
struct Owner<'a> { cx: &'a ReplayCx, authority: &'a ContextAuthority, start: Instant, timeout: Duration }
impl PublishCancellation for Owner<'_> {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        self.cx.checkpoint("recover_http:storage").is_err()
            || self.authority.cancellation_reason.is_some()
            || !CAPS.iter().all(|cap| self.authority.has_capability(cap))
            || self.start.elapsed() >= self.timeout
    }
}
fn recover(options: &Options, out: &mut impl Write) -> Result<(), &'static str> {
    // This check precedes context construction, clocks, output and every filesystem access.
    let approval = options.approval()?;
    if options.approve != Some(approval) { return Err("ERR-HTTP-WIRE-RECOVERY-APPROVAL-001"); }
    let mut capabilities: Vec<String> = CAPS.iter().map(|cap| (*cap).to_owned()).collect();
    capabilities.push("ADP-REPLAY-001".to_owned());
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:http-wire-recovery".to_owned(),
        operation_id: OperationId::parse("operation:http-wire-recovery").map_err(|_| "ERR-HTTP-WIRE-RECOVERY-001")?,
        principal: options.principal.clone(), capabilities, deadline: None, priority: 10,
        budgets: BudgetVector::builder().bytes(1024 * 1024 * 1024).storage_operations(1_000_000)
            .build().map_err(|_| "ERR-HTTP-WIRE-RECOVERY-001")?,
        privacy_scope: "privacy:owner-original-http-custody".to_owned(),
        retention_scope: "retention:exact-staged-http-read".to_owned(),
        anchor_universe: approval, generation: 1,
    }).map_err(|_| "ERR-HTTP-WIRE-RECOVERY-001")?;
    authority.validate().map_err(|_| "ERR-HTTP-WIRE-RECOVERY-001")?;
    // Never let ReplayCx or publisher open manufacture a replacement archive on a typo.
    for path in [options.root.clone(), options.root.join("spool"), options.root.join("roots"), options.root.join("tombstones")] {
        if authority.cancellation_reason.is_some() || !CAPS.iter().all(|cap| authority.has_capability(cap)) {
            return Err("ERR-HTTP-WIRE-RECOVERY-AUTHORITY-001");
        }
        if !std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_dir()) {
            return Err("ERR-HTTP-WIRE-RECOVERY-ROOT-001");
        }
    }
    let cx = ReplayCx::from_context_authority(&authority, options.root.clone())
        .map_err(|_| "ERR-HTTP-WIRE-RECOVERY-ROOT-001")?;
    let owner = Owner { cx: &cx, authority: &authority, start: Instant::now(), timeout: Duration::from_millis(options.timeout_ms) };
    let result = (|| {
        emit(out, &object(&[("format", string(FORMAT)), ("kind", string("admitted")),
            ("plan", options.preview()?)]))?;
        if owner.cancel_requested(PublishCutPoint::AfterChildrenVerified) { return Err("ERR-HTTP-WIRE-RECOVERY-AUTHORITY-001"); }
        let mut p = LocalRootPublisher::open(&options.root, options.storage_limits())
            .map_err(|_| "ERR-HTTP-WIRE-RECOVERY-ROOT-001")?;
        let mut work = WorkBudget::new(options.work);
        let before = match options.key.inspect(&p, options.limits, &owner, &mut work) {
            Ok(state) => state,
            Err(error) => {
                custody_refusal(out, "inspect", error, options.key.expected_pin(), &work)?;
                return Err("ERR-HTTP-WIRE-RECOVERY-CUSTODY-001");
            }
        };
        // A failed sink prevents publication. Sink acceptance is not external durability proof.
        emit(out, &object(&[("format", string(FORMAT)), ("kind", string("verified_before_recovery")),
            ("prior_state", string(before.as_str())), ("expected", pin_json(options.key.expected_pin()))]))?;
        let receipt = match options.key.recover(&mut p, options.limits, &owner, &mut work) {
            Ok(receipt) => receipt,
            Err(error) => {
                custody_refusal(out, "publish", error, options.key.expected_pin(), &work)?;
                return Err("ERR-HTTP-WIRE-RECOVERY-CUSTODY-001");
            }
        };
        // No late optional verification or authority refusal hides a successful durable result.
        emit(out, &object(&[("format", string(FORMAT)), ("kind", string("recovered")),
            ("pin", pin_json(receipt.pin)), ("prior_state", string(before.as_str())),
            ("local_durable", "true".to_owned()), ("parser_acknowledged", "false".to_owned()),
            ("capture_resumed", "false".to_owned()), ("stream_complete", "false".to_owned()),
            ("event_published", "false".to_owned()), ("coverage_certified", "false".to_owned()),
            ("network", string("none")), ("work_used", work.used().to_string()),
            ("work_remaining", work.remaining().to_string()),
            ("qualification", string("implemented_not_qualified"))]))
    })();
    cx.drain_and_finalize();
    result
}
fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).take(MAX_ARGS + 1).collect();
    let mut out = io::stdout().lock();
    if args.len() == 1 && matches!(args[0].to_str(), Some("--help" | "-h" | "help")) {
        return match emit(&mut out, HELP) { Ok(()) => ExitCode::SUCCESS, Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code) };
    }
    let options = match Options::parse(&args) {
        Ok(options) => options,
        Err(reason) => {
            eprintln!("ERR-HTTP-WIRE-RECOVERY-ARGUMENT-001: {reason}; use --help");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    let result = if options.approve.is_none() {
        options.preview().and_then(|row| emit(&mut out, &row))
    } else { recover(&options, &mut out) };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => {
            eprintln!("{code}: preserve the exact key and prior output; a lost final report may follow successful durability. Do not reacquire this generation.");
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}

#[cfg(test)]
#[path = "fss-recover-http/tests.rs"]
mod tests;
