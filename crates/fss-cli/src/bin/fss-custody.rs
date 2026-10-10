#![forbid(unsafe_code)]
//! Operator-local custody audit of one exact current event's publication closure.
//! No effect, export or universal agent-operation authority is granted.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use fss_cli::agent_json::{array, evidence_anchor, object, string};
use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::{ContentDigest, DigestAlgorithm, EventId, LedgerAnchor};
use fss_object::{HostSpoolIo, SpoolIo};
use fss_publication::custody_audit::{
    CustodyAuditError, CustodyAuditLimits, LocalCustodyAudit,
    MAX_AUDIT_CATALOGUE_ENTRIES, MAX_AUDIT_EDGES, MAX_AUDIT_IO_CALLS, MAX_AUDIT_OBJECTS,
    MAX_AUDIT_READ_BYTES, audit_authority_roots,
};
use fss_reference::agent_orient::{HistoryPosition, OrientLimits, read_deployment};
use fss_reference::reference_deployment::RELATIVE_PATH_OBJECTS;

const FORMAT: &str = "fss.evidence_custody_audit.v1";
const MAX_ARGS: usize = 25;
const MAX_ARG_BYTES: usize = 4096;
const MAX_REPORT_BYTES: usize = 2 * 1024 * 1024;
const HELP: &str = "fss-custody audit --root DIR --site SITE --event-id EVENT\n\
  [--expected-root sha256:HEX] [--max-read-bytes N] [--max-io-calls N]\n\
  [--max-objects N] [--max-edges N] [--max-object-bytes N]\n\
  [--max-catalogue-entries N] [--max-report-bytes N] [--timeout-ms N]\n\
\n\
  Rehash the published closure of one verified CURRENT event root. No arbitrary\n\
  artifact scope, media output, decoding, locks, writes, repairs or effects.\n\
  Committed deletions and local tombstones deny reads even when bytes remain.\n\
  The selected manifest is bound to the committed event, not a local root slot.\n\
  Descendant manifests require local publication records; opaque leaves stay opaque.\n\
  Missing/corrupt/deleted/unreadable objects remain explicit. Missing manifests\n\
  leave unknown descendants. Event truth is never upgraded or invalidated here.\n\
\n\
  --expected-root pins the current event publication, NOT availability. The\n\
  ledger, event and deletion basis must match again after the payload audit.\n\
  Root/tombstone catalogues are also compared before and after. This is a\n\
  sequential observation, not an atomic snapshot, lease or durability proof.\n\
\n\
  Read/IO limits apply to the custody walk and both publication catalogues.\n\
  Two deployment reads have separate existing OrientLimits (64 MiB/journal,\n\
  16 MiB/object, 128 events, 64 revisions/event); they may inspect other objects.\n\
  The deadline brackets those reads and is checked at every custody IO boundary;\n\
  blocking syscalls cannot be preempted. Default timeout 30000 ms.\n\
  Complete JSON must fit 2 MiB (default/hard maximum), otherwise no stdout.\n\
  Exit 0 only when every selected closure object verified. Custody faults still\n\
  emit their complete report, with a runtime-failure exit. Errors emit no report.\n\
  Operator-local metadata, no redaction transform; NOT an approved export.\n\
  Reference candidate: native compilation/tests/qualification remain unverified.\n";

#[derive(Clone, Debug)]
struct Request {
    root: PathBuf,
    site: String,
    event: EventId,
    expected: Option<ContentDigest>,
    limits: CustodyAuditLimits,
    report_limit: usize,
    timeout: Duration,
}
#[derive(Debug, PartialEq)]
enum Error {
    Usage(&'static str), Source, SiteMismatch, EventNotFound, StaleRoot,
    BasisChanged, Stopped, OutputBound, Audit(CustodyAuditError),
}
fn text(v: &OsStr) -> Result<&str, Error> {
    v.to_str().filter(|s| !s.is_empty()).ok_or(Error::Usage("nonempty UTF-8 required"))
}
fn number(v: &OsStr, low: u64, high: u64) -> Result<u64, Error> {
    let s = text(v)?;
    if !s.bytes().all(|b| b.is_ascii_digit()) { return Err(Error::Usage("unsigned decimal required")); }
    let n = s.parse::<u64>().map_err(|_| Error::Usage("integer overflow"))?;
    if n < low || n > high { return Err(Error::Usage("numeric value exceeds its bounds")); }
    Ok(n)
}
fn parse(args: &[OsString]) -> Result<Option<Request>, Error> {
    if args.len() > MAX_ARGS || args.iter().any(|a| a.as_encoded_bytes().len() > MAX_ARG_BYTES) {
        return Err(Error::Usage("argument count or length exceeds its bound"));
    }
    if (args.len() == 1 && matches!(args[0].to_str(), Some("help" | "--help" | "-h")))
        || (args.len() == 2 && args[0] == "audit" && matches!(args[1].to_str(), Some("--help" | "-h")))
    { return Ok(None); }
    if args.first().and_then(|a| a.to_str()) != Some("audit") || args.len() % 2 != 1 {
        return Err(Error::Usage("expected audit and separate option/value pairs"));
    }
    let (mut root, mut site, mut event, mut expected) = (None, None, None, None);
    let mut limits = CustodyAuditLimits::default();
    let mut report_limit = MAX_REPORT_BYTES;
    let mut timeout = Duration::from_millis(30_000);
    let mut seen = BTreeSet::new();
    for pair in args[1..].as_chunks::<2>().0 {
        let key = text(&pair[0])?;
        let value = &pair[1];
        if value.is_empty() || value.to_str().is_some_and(|s| s.starts_with("--")) {
            return Err(Error::Usage("missing option value"));
        }
        if !seen.insert(key) { return Err(Error::Usage("duplicate singleton option")); }
        match key {
            "--root" => root = Some(PathBuf::from(value)),
            "--site" => {
                let value = text(value)?;
                if value.len() > 256 || fss_reference::reference_deployment::validate_site_lineage(value).is_err() {
                    return Err(Error::Usage("invalid site lineage"));
                }
                site = Some(value.to_owned());
            }
            "--event-id" => {
                let value = text(value)?;
                if value.len() > fss_core::MAX_EVENT_ID_LEN { return Err(Error::Usage("event identity too long")); }
                event = Some(EventId::parse(value).map_err(|_| Error::Usage("invalid event identity"))?);
            }
            "--expected-root" => {
                let digest = ContentDigest::parse(text(value)?).map_err(|_| Error::Usage("invalid root digest"))?;
                if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
                    return Err(Error::Usage("root requires a nonzero SHA-256 digest"));
                }
                expected = Some(digest);
            }
            "--max-read-bytes" => limits.max_read_bytes = number(value, 0, MAX_AUDIT_READ_BYTES)?,
            "--max-io-calls" => limits.max_io_calls = number(value, 0, MAX_AUDIT_IO_CALLS)?,
            "--max-objects" => limits.max_objects = number(value, 0, MAX_AUDIT_OBJECTS as u64)? as usize,
            "--max-edges" => limits.max_edges = number(value, 0, MAX_AUDIT_EDGES as u64)? as usize,
            "--max-object-bytes" => limits.max_object_bytes = number(value, 0, fss_object::MAX_OBJECT_BYTES as u64)? as usize,
            "--max-catalogue-entries" => limits.max_catalogue_entries = number(value, 0, MAX_AUDIT_CATALOGUE_ENTRIES as u64)? as usize,
            "--max-report-bytes" => report_limit = number(value, 1024, MAX_REPORT_BYTES as u64)? as usize,
            "--timeout-ms" => timeout = Duration::from_millis(number(value, 1, 3_600_000)?),
            _ => return Err(Error::Usage("unknown option")),
        }
    }
    Ok(Some(Request {
        root: root.ok_or(Error::Usage("--root is required"))?,
        site: site.ok_or(Error::Usage("--site is required"))?,
        event: event.ok_or(Error::Usage("--event-id is required"))?,
        expected, limits, report_limit, timeout,
    }))
}

// Compact verified authority binding. I/O counters are not semantic state and are separate.
#[derive(Clone, Debug, PartialEq)]
struct Basis {
    site: String,
    position: HistoryPosition,
    anchor: LedgerAnchor,
    ledger_root: ContentDigest,
    effect_root: ContentDigest,
    ledger_tail: bool,
    effect_tail: bool,
    event: EventId,
    event_root: ContentDigest,
    revision_digest: ContentDigest,
    event_json: String,
    denied: BTreeMap<ContentDigest, ContentDigest>,
}
#[derive(Clone, Debug)]
struct ReadView { basis: Basis, files: u64, bytes: u64 }

fn load_view(request: &Request) -> Result<ReadView, Error> {
    let snapshot = read_deployment(&request.root, &OrientLimits::default()).map_err(|_| Error::Source)?;
    if snapshot.site_lineage != request.site { return Err(Error::SiteMismatch); }
    let retained = snapshot.event(&request.event).ok_or(Error::EventNotFound)?;
    if retained.revisions.last() != Some(&retained.event)
        || retained.revision_digest != retained.event.revision_digest()
        || retained.committed_sequence > snapshot.anchor.commit_sequence
    { return Err(Error::Source); }
    fss_core::EventHypothesis::verify_chain(&retained.revisions).map_err(|_| Error::Source)?;
    let mut denied = BTreeMap::new();
    for entry in snapshot.deletions.entries() {
        for object in &entry.plan.deletable {
            if !denied.contains_key(&object.digest) && denied.len() >= MAX_AUDIT_OBJECTS {
                return Err(Error::Audit(CustodyAuditError::Limit("deletion_objects")));
            }
            denied.insert(object.digest, entry.plan_digest);
        }
    }
    Ok(ReadView {
        basis: Basis {
            site: snapshot.site_lineage.clone(), position: snapshot.position,
            anchor: snapshot.anchor.clone(), ledger_root: snapshot.ledger_root,
            effect_root: snapshot.effect_journal_root,
            ledger_tail: snapshot.ledger_tail_uncommitted, effect_tail: snapshot.effect_tail_uncommitted,
            event: retained.event.event_id.clone(), event_root: retained.event_root,
            revision_digest: retained.revision_digest, event_json: retained.event.to_canonical_json(), denied,
        },
        files: snapshot.files_read, bytes: snapshot.bytes_read,
    })
}
fn stop(check: &(impl Fn() -> bool + Sync)) -> Result<(), Error> {
    if check() { Err(Error::Stopped) } else { Ok(()) }
}
fn validate_selection(request: &Request, basis: &Basis) -> Result<(), Error> {
    if basis.site != request.site || basis.anchor.site_lineage != request.site { return Err(Error::SiteMismatch); }
    if basis.event != request.event { return Err(Error::EventNotFound); }
    if request.expected.is_some_and(|d| d != basis.event_root) { return Err(Error::StaleRoot); }
    Ok(())
}
fn execute(request: &Request, check: &(impl Fn() -> bool + Sync)) -> Result<(String, bool), Error> {
    execute_with(request, &HostSpoolIo, || load_view(request), check)
}
fn execute_with(
    request: &Request,
    io: &dyn SpoolIo,
    mut read: impl FnMut() -> Result<ReadView, Error>,
    check: &(impl Fn() -> bool + Sync),
) -> Result<(String, bool), Error> {
    stop(check)?;
    let before = read()?;
    stop(check)?;
    validate_selection(request, &before.basis)?;
    // publish_event commits a manifest to the ledger without a local .root slot.
    // Only the exact event root selected by the verifying reader gains a manifest role;
    // never repair that mismatch by creating a slot or trial-parsing arbitrary leaves.
    let audit = audit_authority_roots(io, &request.root.join(RELATIVE_PATH_OBJECTS),
        &[before.basis.event_root], &before.basis.denied, request.limits, check).map_err(Error::Audit)?;
    stop(check)?;
    let after = read()?;
    stop(check)?;
    if before.basis != after.basis { return Err(Error::BasisChanged); }
    let report = render(request, &before, &after, &audit)?;
    stop(check)?;
    Ok((report, audit.all_verified()))
}
fn bounded_rows(rows: impl Iterator<Item = String>, limit: usize) -> Result<String, Error> {
    let mut result = String::from("[");
    for row in rows {
        let comma = usize::from(result.len() > 1);
        if result.len().saturating_add(comma).saturating_add(row.len()).saturating_add(1) > limit { return Err(Error::OutputBound); }
        if comma != 0 { result.push(','); }
        result.push_str(&row);
    }
    result.push(']');
    Ok(result)
}
fn render(request: &Request, before: &ReadView, after: &ReadView, audit: &LocalCustodyAudit) -> Result<String, Error> {
    let rows = bounded_rows(audit.objects().iter().map(|row| {
        object(&[
            ("digest", string(&row.digest.to_text())),
            ("declared_manifest", row.declared_manifest.to_string()),
            ("state", string(row.state.as_str())),
            ("verified_payload_bytes", row.verified_payload_bytes.map_or_else(|| "null".to_owned(), |v| v.to_string())),
            ("children", array(&row.children.iter().map(|d| string(&d.to_text())).collect::<Vec<_>>())),
            ("denial_digest", row.denial_digest.map_or_else(|| "null".to_owned(), |d| string(&d.to_text()))),
        ])
    }), request.report_limit)?;
    let b = &before.basis;
    let text = object(&[
        ("format", string(FORMAT)),
        ("site", string(&b.site)), ("anchor", evidence_anchor(&b.anchor)),
        ("ledger_root", string(&b.ledger_root.to_text())),
        ("effect_journal_root", string(&b.effect_root.to_text())),
        ("ledger_tail_uncommitted", b.ledger_tail.to_string()),
        ("effect_tail_uncommitted", b.effect_tail.to_string()),
        ("event_id", string(b.event.as_str())),
        ("event_root", string(&b.event_root.to_text())),
        ("root_basis", string(audit.root_basis().as_str())),
        ("revision_digest", string(&b.revision_digest.to_text())),
        ("event_record", b.event_json.clone()),
        ("status", string(if audit.all_verified() { "intact_at_observation" } else { "custody_faults" })),
        ("all_verified", audit.all_verified().to_string()),
        ("manifest_expansion_complete", audit.manifest_expansion_complete().to_string()),
        ("objects", rows), ("manifest_edges", audit.edges().to_string()),
        ("publication_records_per_pass", audit.publication_records().to_string()),
        ("local_tombstones_per_pass", audit.local_tombstones().to_string()),
        ("charged_audit_read_bytes", audit.charged_read_bytes().to_string()),
        ("peak_reserved_audit_read_bytes", audit.peak_reserved_read_bytes().to_string()),
        ("audit_io_calls", audit.io_calls().to_string()),
        ("audit_limits", object(&[
            ("read_bytes", request.limits.max_read_bytes.to_string()),
            ("io_calls", request.limits.max_io_calls.to_string()),
            ("objects", request.limits.max_objects.to_string()),
            ("edges", request.limits.max_edges.to_string()),
            ("object_bytes", request.limits.max_object_bytes.to_string()),
            ("catalogue_entries", request.limits.max_catalogue_entries.to_string()),
        ])),
        ("deployment_reader_files", array(&[before.files.to_string(), after.files.to_string()])),
        ("deployment_reader_bytes", array(&[before.bytes.to_string(), after.bytes.to_string()])),
        ("accounting_scope", string("audit IO includes two publication catalogues and selected payload closure; two existing deployment readers and their doctor inspections are separately bounded, not charged to audit allowance")),
        ("authority", string("read_only_operator_diagnostic_no_effect_or_export_authority")),
        ("privacy", string("operator_local_event_metadata; no redaction transform; no media bytes emitted")),
        ("interpretation", string("exact ledger-selected event manifest and locally declared descendant closure during sequential reads; not an atomic snapshot, future availability, complete embedded semantic provenance, durability, event truth, independent corroboration or absence")),
        ("qualification", string("authored_unvalidated_reference_candidate")),
    ]);
    if text.len().saturating_add(1) > request.report_limit { return Err(Error::OutputBound); }
    Ok(text + "\n")
}
fn emit(writer: &mut impl Write, mut bytes: &[u8]) -> io::Result<()> {
    let mut interruptions = 0;
    while !bytes.is_empty() {
        let part = &bytes[..bytes.len().min(65_536)];
        match writer.write(part) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) if n <= part.len() => { bytes = &bytes[n..]; interruptions = 0; }
            Ok(_) => return Err(io::ErrorKind::InvalidData.into()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted && interruptions < 7 => interruptions += 1,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).take(MAX_ARGS + 1).collect();
    let result = match parse(&args) {
        Ok(None) => Ok((HELP.to_owned(), true)),
        Ok(Some(request)) => { let start = Instant::now(); execute(&request, &|| start.elapsed() >= request.timeout) }
        Err(error) => Err(error),
    };
    match result {
        Ok((report, intact)) => {
            let delivered = emit(&mut io::stdout().lock(), report.as_bytes()).is_ok();
            ExitCode::from(if delivered && intact { ExitIdentity::SUCCESS.code } else { ExitIdentity::RUNTIME_FAILURE.code })
        }
        Err(error) => {
            let usage = matches!(&error, Error::Usage(_));
            let reason = match &error {
                Error::Usage(reason) => *reason,
                Error::Source => "deployment history unavailable, damaged or beyond its read bounds",
                Error::SiteMismatch => "site lineage mismatch",
                Error::EventNotFound => "requested current event unavailable",
                Error::StaleRoot => "current event root differs from --expected-root",
                Error::BasisChanged => "ledger, event or deletion basis changed during audit",
                Error::Stopped => "deadline or cancellation reached",
                Error::OutputBound => "complete report exceeds byte budget; nothing truncated",
                Error::Audit(error) => error.reason(),
            };
            let detail = match &error { Error::Audit(e) => e.to_string(), _ => reason.to_owned() };
            eprintln!("{}: {detail}; no effect authorized", if usage { ERR_CLI_MALFORMED_VALUE } else { ERR_CLI_RUNTIME_FAILURE });
            ExitCode::from(if usage { ExitIdentity::MALFORMED_VALUE.code } else { ExitIdentity::RUNTIME_FAILURE.code })
        }
    }
}

#[cfg(test)]
#[path = "fss-custody/tests.rs"]
mod tests;
