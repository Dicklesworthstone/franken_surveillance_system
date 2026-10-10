#![forbid(unsafe_code)]
//! Read-only operator analysis of retained event support dependencies.
//! This is not an agent-session operation, an evidence export, or an effect grant.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use fss_cli::agent_json::{array, evidence_anchor, object, string, strings};
use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::{ContentDigest, DigestAlgorithm, EventHypothesis, GraphAlgorithmWitness, LedgerAnchor};
use fss_graph_algorithms::certified::Budget;
use fss_graph_algorithms::evidence::{
    EvidenceClaimAnalysis, EvidenceClaimProjection, EvidenceProjectionError,
    EvidenceProjectionLimits, object_node,
};
use fss_reference::agent_orient::{OrientLimits, read_deployment};

const FORMAT: &str = "fss.evidence_support_analysis.v1";
const MAX_ARGS: usize = 17;
const MAX_ARG_BYTES: usize = 4096;
const MAX_REPORT_BYTES: usize = 2 * 1024 * 1024;
const MAX_OPERATIONS: u64 = 50_000_000;
const MAX_OUTPUT_ENTRIES: u64 = 65_536;
const HELP: &str = "fss-evidence analyze --root DIR --site SITE\n\
  [--expected-witness sha256:HEX] [--max-operations N]\n\
  [--max-output-entries N] [--max-report-bytes N] [--timeout-ms N]\n\
\n\
  Read-only operator diagnostic over ONE verified committed deployment snapshot.\n\
  Selects the latest retained revision of EVERY event (maximum 128); no ranking,\n\
  truncation, automatic scope change, source hydration, locks, writes or repairs.\n\
  Only explicit Supports edges are traversed. All other relations and the complete\n\
  selected records, including uncertainty and counterevidence, stay in the report.\n\
  Shared object digests are shared vertices, not independent observations.\n\
  References outside the selected revisions remain explicitly UNEXPANDED.\n\
\n\
  Rootedness and dominators describe declared support paths ONLY. They do not prove\n\
  truth, custody, independence, observability, absence, AND/OR proof satisfaction,\n\
  calibration or permission to act. Unsupported/unrooted claims are NOT rejected.\n\
  Old revision references are not redirected to successors. No effect is authorized.\n\
  This operator-local report contains event metadata without a privacy transform;\n\
  it is not an approved evidence export or a universal agent response envelope.\n\
\n\
  --expected-witness pins the exact algorithm witness, including its authority\n\
  anchor. A changed witness is refused. Source custody can change independently,\n\
  so the pin is not a current-availability certificate. Exit 0 means a complete\n\
  QUERY report, never that the claims are proved or independent.\n\
\n\
  Defaults: 2000000 graph operations; 65536 algorithm output entries; 2 MiB report;\n\
  30000 ms timeout. Hard operation ceiling 50000000. Input ceilings: 128 active\n\
  revisions, 8192 evidence edges, 8 MiB canonical event bytes. Snapshot reads have\n\
  separate OrientLimits bounds. Timeout checks bracket read/build/analysis/render;\n\
  they do NOT preempt filesystem calls or the bounded algorithm. Oversized reports\n\
  fail before stdout; there is no partial-answer or heuristic fallback.\n\
  Reference candidate: native tests and production qualification have not run.\n";

#[derive(Clone, Debug)]
struct Request {
    root: PathBuf,
    site: String,
    expected: Option<ContentDigest>,
    budget: Budget,
    report_limit: usize,
    timeout: Duration,
}

#[derive(Debug)]
enum CommandError {
    Usage(&'static str),
    Source,
    SiteMismatch,
    StaleWitness,
    Projection(EvidenceProjectionError),
    Stopped,
    OutputBound,
}

fn text(value: &OsStr) -> Result<&str, CommandError> {
    value
        .to_str()
        .filter(|s| !s.is_empty())
        .ok_or(CommandError::Usage("value requires nonempty UTF-8"))
}

fn number(value: &OsStr, low: u64, high: u64) -> Result<u64, CommandError> {
    let raw = text(value)?;
    if !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(CommandError::Usage("expected unsigned decimal integer"));
    }
    let n = raw
        .parse::<u64>()
        .map_err(|_| CommandError::Usage("integer overflow"))?;
    if n < low || n > high {
        return Err(CommandError::Usage("numeric option outside its bounds"));
    }
    Ok(n)
}

// Parse everything before opening a deployment. Root paths keep native OS bytes.
fn parse(args: &[OsString]) -> Result<Option<Request>, CommandError> {
    if args.len() > MAX_ARGS
        || args.iter().any(|v| v.as_encoded_bytes().len() > MAX_ARG_BYTES)
    {
        return Err(CommandError::Usage("argument count or length exceeds its bound"));
    }
    if (args.len() == 1 && matches!(args[0].to_str(), Some("help" | "--help" | "-h")))
        || (args.len() == 2 && args[0] == "analyze"
            && matches!(args[1].to_str(), Some("--help" | "-h")))
    {
        return Ok(None);
    }
    if args.first().and_then(|v| v.to_str()) != Some("analyze") || args.len() % 2 != 1 {
        return Err(CommandError::Usage("expected analyze and separate option/value pairs"));
    }
    let mut root = None;
    let mut site = None;
    let mut expected = None;
    let mut budget = Budget::new(2_000_000, MAX_OUTPUT_ENTRIES);
    let mut report_limit = MAX_REPORT_BYTES;
    let mut timeout = Duration::from_millis(30_000);
    let mut seen = BTreeSet::new();
    for pair in args[1..].as_chunks::<2>().0 {
        let key = text(&pair[0])?;
        let value = &pair[1];
        if value.is_empty() || value.to_str().is_some_and(|s| s.starts_with("--")) {
            return Err(CommandError::Usage("missing option value"));
        }
        if !seen.insert(key) {
            return Err(CommandError::Usage("duplicate singleton option"));
        }
        match key {
            "--root" => root = Some(PathBuf::from(value)),
            "--site" => {
                let value = text(value)?;
                if value.len() > 256
                    || fss_reference::reference_deployment::validate_site_lineage(value).is_err()
                {
                    return Err(CommandError::Usage("invalid bounded site lineage"));
                }
                site = Some(value.to_owned());
            }
            "--expected-witness" => {
                let digest = ContentDigest::parse(text(value)?)
                    .map_err(|_| CommandError::Usage("invalid witness digest"))?;
                if digest.algorithm() != DigestAlgorithm::Sha256 {
                    return Err(CommandError::Usage("witness pin must be SHA-256"));
                }
                expected = Some(digest);
            }
            "--max-operations" => budget.max_operations = number(value, 1, MAX_OPERATIONS)?,
            "--max-output-entries" => {
                budget.max_output_entries = number(value, 1, MAX_OUTPUT_ENTRIES)?;
            }
            "--max-report-bytes" => {
                report_limit = number(value, 1024, MAX_REPORT_BYTES as u64)? as usize;
            }
            "--timeout-ms" => timeout = Duration::from_millis(number(value, 1, 3_600_000)?),
            _ => return Err(CommandError::Usage("unknown or inapplicable option")),
        }
    }
    Ok(Some(Request {
        root: root.ok_or(CommandError::Usage("--root is required"))?,
        site: site.ok_or(CommandError::Usage("--site is required"))?,
        expected,
        budget,
        report_limit,
        timeout,
    }))
}

// Read accounting and authority are distinct from the graph's algorithm witness.
#[derive(Clone, Debug)]
struct ReadFacts {
    site: String,
    anchor: LedgerAnchor,
    ledger_root: ContentDigest,
    ledger_tail_uncommitted: bool,
    effect_tail_uncommitted: bool,
    files_read: u64,
    bytes_read: u64,
}

fn stopped(check: &impl Fn() -> bool) -> Result<(), CommandError> {
    if check() { Err(CommandError::Stopped) } else { Ok(()) }
}

fn execute(request: &Request, check: &impl Fn() -> bool) -> Result<String, CommandError> {
    stopped(check)?;
    let snapshot = read_deployment(&request.root, &OrientLimits::default())
        .map_err(|_| CommandError::Source)?;
    stopped(check)?;
    if snapshot.site_lineage != request.site {
        return Err(CommandError::SiteMismatch);
    }
    // read_deployment rehashes payloads and validates retained revision chains. Check the
    // selected record/root binding as well; never substitute or synthesize a revision.
    let mut events = Vec::with_capacity(snapshot.events.len());
    for retained in &snapshot.events {
        if retained.revisions.last() != Some(&retained.event)
            || retained.revision_digest != retained.event.revision_digest()
        {
            return Err(CommandError::Source);
        }
        events.push(retained.event.clone());
    }
    let facts = ReadFacts {
        site: snapshot.site_lineage.clone(),
        anchor: snapshot.anchor.clone(),
        ledger_root: snapshot.ledger_root,
        ledger_tail_uncommitted: snapshot.ledger_tail_uncommitted,
        effect_tail_uncommitted: snapshot.effect_tail_uncommitted,
        files_read: snapshot.files_read,
        bytes_read: snapshot.bytes_read,
    };
    report_for_records(request, &facts, &events, check)
}

fn report_for_records(
    request: &Request,
    facts: &ReadFacts,
    events: &[EventHypothesis],
    check: &impl Fn() -> bool,
) -> Result<String, CommandError> {
    stopped(check)?;
    if facts.site != request.site {
        return Err(CommandError::SiteMismatch);
    }
    let projection = EvidenceClaimProjection::build(events, EvidenceProjectionLimits::default())
        .map_err(CommandError::Projection)?;
    stopped(check)?;
    let analysis = projection.analyze(facts.anchor.clone(), request.budget)
        .map_err(CommandError::Projection)?;
    stopped(check)?;
    if request.expected.is_some_and(|pin| pin != analysis.witness.digest()) {
        return Err(CommandError::StaleWitness);
    }
    let report = render(request, facts, &projection, &analysis)?;
    stopped(check)?;
    Ok(report)
}

fn counts(values: &std::collections::BTreeMap<String, u64>) -> String {
    let fields: Vec<String> = values.iter()
        .map(|(name, n)| format!("{}:{n}", string(name))).collect();
    format!("{{{}}}", fields.join(","))
}

fn witness(value: &GraphAlgorithmWitness) -> String {
    object(&[
        ("schema", string(GraphAlgorithmWitness::SCHEMA)),
        ("algorithmId", string(value.algorithm_id())),
        ("implementationId", string(value.implementation_id())),
        ("projectionId", string(value.projection_id())),
        ("anchor", evidence_anchor(value.anchor())),
        ("nodeCount", value.node_count().to_string()),
        ("edgeCount", value.edge_count().to_string()),
        ("inputDigest", string(&value.input_digest().to_text())),
        ("policyId", string(value.policy_id())),
        ("dominantOperationCounts", counts(value.dominant_operation_counts())),
        ("peakWorkingBytes", value.peak_working_bytes().to_string()),
        ("budgetConsumed", counts(value.budget_consumed())),
        ("exactness", string(value.exactness())),
        ("errorBound", "null".to_owned()),
        ("stopReason", string(value.stop_reason())),
        ("decisionPathDigest", string(&value.decision_path_digest().to_text())),
        ("outputDigest", string(&value.output_digest().to_text())),
    ])
}

// Charge rows before retaining them. A whole final report is checked again before stdout.
fn bounded_array(rows: impl Iterator<Item = String>, limit: usize) -> Result<String, CommandError> {
    if limit < 2 { return Err(CommandError::OutputBound); }
    let mut out = String::from("[");
    for row in rows {
        let separator = usize::from(out.len() > 1);
        if out.len().saturating_add(separator).saturating_add(row.len()).saturating_add(1) > limit {
            return Err(CommandError::OutputBound);
        }
        if separator != 0 { out.push(','); }
        out.push_str(&row);
    }
    out.push(']');
    Ok(out)
}

fn render(
    request: &Request,
    facts: &ReadFacts,
    projection: &EvidenceClaimProjection,
    analysis: &EvidenceClaimAnalysis,
) -> Result<String, CommandError> {
    // No hand-written alternate event serialization: preserve every field through the
    // canonical core renderer, including all typed edges and explicit uncertainty.
    let records = bounded_array(projection.events().iter().zip(&analysis.claims).map(|(event, claim)| {
        object(&[
            ("revision_digest", string(&claim.revision.to_text())),
            ("graph_node", string(&object_node(claim.revision))),
            ("record", event.to_canonical_json()),
            ("supports", claim.supports.to_string()),
            ("contradictions", claim.contradictions.to_string()),
            ("other_relations", claim.neutral.to_string()),
            ("support_reachability", string(claim.reachability.as_str())),
            ("immediate_dominator", claim.immediate_dominator.as_deref()
                .map_or_else(|| "null".to_owned(), string)),
        ])
    }), request.report_limit)?;
    let idoms = bounded_array(analysis.run.output.immediate_dominators.iter().map(|(node, parent)| {
        array(&[string(node), string(parent)])
    }), request.report_limit)?;
    let dominance = bounded_array(analysis.run.output.dominance.iter().map(|(node, count)| {
        array(&[string(node), count.to_string()])
    }), request.report_limit)?;
    let digests = |values: &[ContentDigest]| {
        bounded_array(values.iter().map(|d| string(&d.to_text())), request.report_limit)
    };
    let report = object(&[
        ("format", string(FORMAT)),
        ("site", string(&facts.site)),
        ("anchor", evidence_anchor(&facts.anchor)),
        ("ledger_root", string(&facts.ledger_root.to_text())),
        ("ledger_tail_uncommitted", facts.ledger_tail_uncommitted.to_string()),
        ("effect_tail_uncommitted", facts.effect_tail_uncommitted.to_string()),
        ("selection", string("latest_retained_revision_of_every_event; no filtering")),
        ("projection_digest", string(&projection.graph().digest().to_text())),
        ("records", records),
        ("unexpanded_support_references", digests(projection.unexpanded_support())?),
        ("unexpanded_evidence_references", digests(projection.unexpanded_evidence())?),
        ("dominator_root", string(&analysis.run.output.root)),
        ("immediate_dominators", idoms),
        ("unreachable_nodes", strings(&analysis.run.output.unreachable)),
        ("dominated_node_counts", dominance),
        ("witness", witness(&analysis.witness)),
        ("witness_digest", string(&analysis.witness.digest().to_text())),
        ("source_files_read", facts.files_read.to_string()),
        ("source_bytes_read", facts.bytes_read.to_string()),
        ("canonical_event_bytes", projection.canonical_bytes().to_string()),
        ("evidence_edges_inspected", projection.evidence_edges().to_string()),
        ("graph_operation_limit", request.budget.max_operations.to_string()),
        ("algorithm_output_entry_limit", request.budget.max_output_entries.to_string()),
        ("budget_scope", string("algorithm witness excludes separately bounded snapshot IO, compiler and JSON rendering")),
        ("node_key", string("object:<digest>; support:<revision-digest>:<zero-based-edge-index, minimum four decimal digits>")),
        ("authority", string("derived_cognition_no_effect_authority")),
        ("privacy", string("operator_local_metadata; no redaction transform; not an approved evidence export")),
        ("interpretation", string("declared support-path structure only; not custody, independent corroboration, truth, absence, AND/OR proof satisfaction or effect authority")),
        ("unexpanded_reference_semantics", string("referenced objects were not hydrated; historical revisions are not redirected to successors")),
        ("qualification", string("authored_unvalidated_reference_candidate")),
    ]);
    if report.len().saturating_add(1) > request.report_limit {
        return Err(CommandError::OutputBound);
    }
    Ok(report + "\n")
}

fn emit(writer: &mut impl Write, mut bytes: &[u8]) -> io::Result<()> {
    let mut interruptions = 0;
    while !bytes.is_empty() {
        let chunk = &bytes[..bytes.len().min(64 * 1024)];
        match writer.write(chunk) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) if n <= chunk.len() => { bytes = &bytes[n..]; interruptions = 0; }
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
        Ok(None) => Ok(HELP.to_owned()),
        Ok(Some(request)) => {
            let started = Instant::now();
            execute(&request, &|| started.elapsed() >= request.timeout)
        }
        Err(error) => Err(error),
    };
    match result {
        Ok(report) => match emit(&mut io::stdout().lock(), report.as_bytes()) {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        },
        Err(error) => {
            let usage = matches!(&error, CommandError::Usage(_));
            let code = match &error {
                CommandError::Usage(_) => ERR_CLI_MALFORMED_VALUE,
                CommandError::Projection(error) => error.stable_id(),
                _ => ERR_CLI_RUNTIME_FAILURE,
            };
            let explanation = match &error {
                CommandError::Usage(reason) => *reason,
                CommandError::Source => "retained deployment is unreadable, corrupt, or beyond its read bounds",
                CommandError::SiteMismatch => "deployment site differs from the explicitly requested site",
                CommandError::StaleWitness => "witness differs from --expected-witness; refresh the read",
                CommandError::Projection(_) => "graph input, budget or registered bound refused; no partial answer",
                CommandError::Stopped => "deadline or cancellation reached; no report emitted",
                CommandError::OutputBound => "complete report exceeds its byte budget; nothing was truncated",
            };
            eprintln!("{code}: {explanation}. No effect was authorized. Use fss-evidence --help.");
            ExitCode::from(if usage { ExitIdentity::MALFORMED_VALUE.code } else { ExitIdentity::RUNTIME_FAILURE.code })
        }
    }
}

#[cfg(test)]
#[path = "fss-evidence/tests.rs"]
mod tests;
