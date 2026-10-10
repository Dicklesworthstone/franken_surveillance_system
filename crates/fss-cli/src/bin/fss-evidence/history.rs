#![forbid(unsafe_code)]
//! Historical support and exact-artifact impact, read-only over one verified deployment.

use std::collections::BTreeMap;

use fss_graph_algorithms::certified::CertifiedRun;
use fss_graph_algorithms::dominators::DominanceOutput;
use fss_graph_algorithms::evidence_history::{EvidenceHistoryProjection, HistoryLimits};

use super::*;

const HISTORY_FORMAT: &str = "fss.evidence_support_history.v1";
const HISTORY_HELP: &str = "fss-evidence analyze-history --root DIR --site SITE\n\
fss-evidence impact --root DIR --site SITE --artifact sha256:HEX\n\
  Both accept --expected-witness, --max-operations, --max-output-entries,\n\
  --max-report-bytes and --timeout-ms with the same bounds as analyze.\n\
\n\
  Read-only: verify complete retained lineages, select every current head, then\n\
  expand exact historical event references across ALL evidence relations. Only\n\
  explicit Supports edges enter positive paths. Never redirect to successors.\n\
  All expanded records and counterevidence remain in the bounded complete report.\n\
  Unreferenced ancestors are validated but not bulk-expanded; their cost is counted.\n\
\n\
  analyze-history uses the explicitly unexpanded-reference frontier as query root.\n\
  impact roots the same registered algorithm at the exact --artifact and lists\n\
  current heads with a positive path from it, including through old revisions.\n\
  A reachable head may have independent alternative paths: this is NOT proof that\n\
  removing the artifact invalidates it. No positive path says nothing about other\n\
  relations or physical reality. A root outside the expanded graph is refused.\n\
\n\
  Catalogue limits: 128 lineages, 64 revisions each, 8192 revisions total,\n\
  16384 total evidence edges and 16 MiB canonical versioned bytes. Source reader,\n\
  compiler, algorithm and JSON limits are separate. Budget exhaustion fails closed.\n\
  Deadline checks bracket stages, not individual filesystem or algorithm steps.\n\
  Same-root exact witness pins do not certify current object availability.\n\
  This is operator-local metadata without a redaction transform, not an approved\n\
  export, source-custody check, truth/absence certificate, or effect authority.\n\
  No writes, locks, repair, retraction or dispatch. Native qualification remains open.\n";

#[derive(Clone, Debug)]
struct HistoryRequest {
    base: Request,
    artifact: Option<ContentDigest>,
}

fn parse_history(args: &[OsString]) -> Result<Option<HistoryRequest>, CommandError> {
    if args.len() > MAX_ARGS || args.iter().any(|arg| arg.as_encoded_bytes().len() > MAX_ARG_BYTES) {
        return Err(CommandError::Usage("argument count or length exceeds its bound"));
    }
    let impact = match args.first().and_then(|arg| arg.to_str()) {
        Some("analyze-history") => false,
        Some("impact") => true,
        _ => return Err(CommandError::Usage("expected analyze-history or impact")),
    };
    if args.len() == 2 && matches!(args[1].to_str(), Some("--help" | "-h")) {
        return Ok(None);
    }
    if args.len() % 2 != 1 {
        return Err(CommandError::Usage("expected separate option/value pairs"));
    }
    let mut forwarded = vec![OsString::from("analyze")];
    let mut artifact = None;
    for pair in args[1..].as_chunks::<2>().0 {
        if pair[0] == "--artifact" {
            if !impact || artifact.is_some() {
                return Err(CommandError::Usage("--artifact is unique and valid only for impact"));
            }
            let digest = ContentDigest::parse(text(&pair[1])?)
                .map_err(|_| CommandError::Usage("invalid artifact digest"))?;
            if digest.algorithm() != DigestAlgorithm::Sha256 {
                return Err(CommandError::Usage("artifact identity must be SHA-256"));
            }
            artifact = Some(digest);
        } else {
            forwarded.extend_from_slice(pair);
        }
    }
    if impact && artifact.is_none() {
        return Err(CommandError::Usage("impact requires --artifact"));
    }
    let base = parse(&forwarded)?.ok_or(CommandError::Usage("unexpected help arguments"))?;
    Ok(Some(HistoryRequest { base, artifact }))
}

pub(super) fn run(args: &[OsString]) -> Result<String, CommandError> {
    match parse_history(args)? {
        None => Ok(HISTORY_HELP.to_owned()),
        Some(request) => {
            let started = Instant::now();
            execute_history(&request, &|| started.elapsed() >= request.base.timeout)
        }
    }
}

fn execute_history(request: &HistoryRequest, check: &impl Fn() -> bool) -> Result<String, CommandError> {
    stopped(check)?;
    let snapshot = read_deployment(&request.base.root, &OrientLimits::default())
        .map_err(|_| CommandError::Source)?;
    stopped(check)?;
    if snapshot.site_lineage != request.base.site {
        return Err(CommandError::SiteMismatch);
    }
    for retained in &snapshot.events {
        if retained.revisions.last() != Some(&retained.event)
            || retained.revision_digest != retained.event.revision_digest()
        {
            return Err(CommandError::Source);
        }
    }
    let facts = ReadFacts {
        site: snapshot.site_lineage.clone(), anchor: snapshot.anchor.clone(),
        ledger_root: snapshot.ledger_root,
        ledger_tail_uncommitted: snapshot.ledger_tail_uncommitted,
        effect_tail_uncommitted: snapshot.effect_tail_uncommitted,
        files_read: snapshot.files_read, bytes_read: snapshot.bytes_read,
    };
    let lineages: Vec<_> = snapshot.events.iter().map(|retained| retained.revisions.as_slice()).collect();
    report_history(request, &facts, &lineages, check)
}

fn report_history(
    request: &HistoryRequest,
    facts: &ReadFacts,
    lineages: &[&[EventHypothesis]],
    check: &impl Fn() -> bool,
) -> Result<String, CommandError> {
    stopped(check)?;
    if facts.site != request.base.site { return Err(CommandError::SiteMismatch); }
    let projection = EvidenceHistoryProjection::build(lineages, HistoryLimits::default())
        .map_err(CommandError::Projection)?;
    stopped(check)?;
    let (run, witness) = match request.artifact {
        Some(artifact) => {
            let result = projection.support_impact(artifact, facts.anchor.clone(), request.base.budget)
                .map_err(CommandError::Projection)?;
            (result.run, result.witness)
        }
        None => {
            let result = projection.analyze(facts.anchor.clone(), request.base.budget)
                .map_err(CommandError::Projection)?;
            (result.run, result.witness)
        }
    };
    stopped(check)?;
    if request.base.expected.is_some_and(|pin| pin != witness.digest()) {
        return Err(CommandError::StaleWitness);
    }
    let report = render_history(request, facts, &projection, &run, &witness)?;
    stopped(check)?;
    Ok(report)
}

fn render_history(
    request: &HistoryRequest,
    facts: &ReadFacts,
    projection: &EvidenceHistoryProjection,
    run: &CertifiedRun<DominanceOutput>,
    proof: &GraphAlgorithmWitness,
) -> Result<String, CommandError> {
    let limit = request.base.report_limit;
    let immediate: BTreeMap<_, _> = run.output.immediate_dominators.iter().cloned().collect();
    let reachable = |digest: ContentDigest| {
        let node = object_node(digest);
        node == run.output.root || immediate.contains_key(&node)
    };
    let heads = bounded_array(projection.heads().iter().map(|(id, digest)| object(&[
        ("event_id", string(id)), ("revision_digest", string(&digest.to_text())),
        ("positive_path_from_query_root", reachable(*digest).to_string()),
    ])), limit)?;
    let records = bounded_array(projection.records().iter().map(|record| {
        let digest = record.revision_digest();
        let head = projection.heads().get(record.event_id.as_str());
        let supports = record.evidence.iter().filter(|edge| edge.counts_as_support()).count();
        let contradictions = record.evidence.iter().filter(|edge| edge.counts_as_contradiction()).count();
        object(&[
            ("revision_digest", string(&digest.to_text())),
            ("is_current_head", (head == Some(&digest)).to_string()),
            ("current_head_digest", head.map_or_else(|| "null".to_owned(), |d| string(&d.to_text()))),
            ("record", record.to_canonical_json()),
            ("supports", supports.to_string()), ("contradictions", contradictions.to_string()),
            ("other_relations", (record.evidence.len() - supports - contradictions).to_string()),
            ("positive_path_from_query_root", reachable(digest).to_string()),
            ("immediate_dominator", immediate.get(&object_node(digest))
                .map_or_else(|| "null".to_owned(), |node| string(node))),
        ])
    }), limit)?;
    let idoms = bounded_array(run.output.immediate_dominators.iter()
        .map(|(node, parent)| array(&[string(node), string(parent)])), limit)?;
    let digest_array = |values: &[ContentDigest]| {
        bounded_array(values.iter().map(|digest| string(&digest.to_text())), limit)
    };
    let affected = bounded_array(projection.heads().iter().filter(|(_, digest)| reachable(**digest))
        .map(|(id, digest)| object(&[
            ("event_id", string(id)), ("revision_digest", string(&digest.to_text())),
        ])), limit)?;
    let report = object(&[
        ("format", string(HISTORY_FORMAT)),
        ("mode", string(if request.artifact.is_some() { "artifact_positive_support_impact" } else { "historical_support_analysis" })),
        ("site", string(&facts.site)), ("anchor", evidence_anchor(&facts.anchor)),
        ("ledger_root", string(&facts.ledger_root.to_text())),
        ("ledger_tail_uncommitted", facts.ledger_tail_uncommitted.to_string()),
        ("effect_tail_uncommitted", facts.effect_tail_uncommitted.to_string()),
        ("selection", string("all_current_heads_then_exact_transitive_event_evidence_references; all_relations_expanded; only_supports_traversed")),
        ("requested_artifact", request.artifact.map_or_else(|| "null".to_owned(), |d| string(&d.to_text()))),
        ("query_root", string(&run.output.root)),
        ("projection_digest", string(&projection.graph().digest().to_text())),
        ("current_heads", heads), ("heads_reachable_from_query_root", affected),
        ("expanded_records", records),
        ("unexpanded_support_references", digest_array(projection.unexpanded_support())?),
        ("unexpanded_evidence_references", digest_array(projection.unexpanded_evidence())?),
        ("immediate_dominators", idoms),
        ("unreachable_nodes", strings(&run.output.unreachable)),
        ("witness", witness(proof)), ("witness_digest", string(&proof.digest().to_text())),
        ("source_files_read", facts.files_read.to_string()), ("source_bytes_read", facts.bytes_read.to_string()),
        ("catalogue_revisions_validated", projection.catalogue_revisions().to_string()),
        ("expanded_revision_count", projection.records().len().to_string()),
        ("catalogue_only_revision_count", (projection.catalogue_revisions() - projection.records().len()).to_string()),
        ("catalogue_evidence_edges", projection.catalogue_edges().to_string()),
        ("catalogue_canonical_bytes", projection.catalogue_bytes().to_string()),
        ("graph_operation_limit", request.base.budget.max_operations.to_string()),
        ("algorithm_output_entry_limit", request.base.budget.max_output_entries.to_string()),
        ("budget_scope", string("algorithm witness excludes separately bounded snapshot IO, catalogue validation and JSON rendering")),
        ("authority", string("derived_cognition_no_effect_authority")),
        ("privacy", string("operator_local_metadata; no redaction transform; not an approved evidence export")),
        ("interpretation", string("positive-path structure only; reachable does not mean indispensable, true, independent, available or invalidated; no positive path is not absence or lack of non-support influence")),
        ("historical_semantics", string("exact old revisions, never successor redirects; current heads remain explicit; non-event artifacts are unexpanded and custody is unchecked")),
        ("qualification", string("authored_unvalidated_reference_candidate")),
    ]);
    if report.len().saturating_add(1) > limit { return Err(CommandError::OutputBound); }
    Ok(report + "\n")
}

#[cfg(test)]
#[path = "history_tests.rs"]
mod tests;
