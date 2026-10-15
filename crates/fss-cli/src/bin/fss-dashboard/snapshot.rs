#![forbid(unsafe_code)]
//! Human/operator projection; native event records remain unmodified canonical JSON strings.

use std::collections::BTreeMap;
use std::io;
use std::time::{Duration, Instant};
use fss_cli::agent_json::{array, evidence_anchor, object, string, strings};
use fss_reference::agent_orient::{OrientLimits, obligation_state_str, read_deployment};
use super::{Lease, Options};

pub(super) const MAX_REPORT: usize = 4 * 1024 * 1024;
fn refused() -> io::Error { io::Error::other("metadata snapshot unavailable") }

pub(super) fn read(options: &Options, lease: &Lease) -> io::Result<String> {
    lease.check()?;
    if options.demo { return Ok(include_str!("web/demo.json").to_owned()); }
    let started = Instant::now();
    let root = options.root.as_ref().ok_or_else(refused)?;
    let limits = OrientLimits {
        max_events: 256,
        max_journal_bytes: 16 * 1024 * 1024,
        max_object_bytes: 2 * 1024 * 1024,
        max_revisions_per_event: 64,
        ..OrientLimits::default()
    };
    let snapshot = read_deployment(root, &limits).map_err(|_| refused())?;
    lease.check()?;
    if started.elapsed() >= Duration::from_secs(5) || options.site.as_deref() != Some(snapshot.site_lineage.as_str()) || snapshot.completed_imports.len() > 4096 {
        return Err(refused());
    }
    let mut events = Vec::new();
    let mut event_bytes = 0usize;
    for retained in &snapshot.events {
        if retained.revisions.last() != Some(&retained.event) || retained.revision_digest != retained.event.revision_digest() {
            return Err(refused());
        }
        let row = object(&[
            ("recordJson", string(&retained.event.to_canonical_json())),
            ("eventRoot", string(&retained.event_root.to_text())),
            ("revisionDigest", string(&retained.revision_digest.to_text())),
            ("sequence", string(&retained.committed_sequence.to_string())),
            ("revisions", retained.revisions.len().to_string()),
        ]);
        event_bytes = event_bytes.saturating_add(row.len() + 1);
        if event_bytes > MAX_REPORT { return Err(refused()); }
        events.push(row);
    }
    let mut operation_states = BTreeMap::<String, usize>::new();
    for op in &snapshot.operations { *operation_states.entry(op.state.as_str().to_owned()).or_default() += 1; }
    let mut obligation_states = BTreeMap::<String, usize>::new();
    for item in &snapshot.obligations { *obligation_states.entry(obligation_state_str(item.state).to_owned()).or_default() += 1; }
    let rows = |counts: &BTreeMap<String, usize>| array(&counts.iter().map(|(name, n)| object(&[("name", string(name)), ("count", n.to_string())])).collect::<Vec<_>>());
    let body = object(&[
        ("format", string("fss.operator_dashboard.v1")),
        ("demo", "false".to_owned()),
        ("site", string(&snapshot.site_lineage)),
        ("anchorJson", string(&evidence_anchor(&snapshot.anchor))),
        ("sequence", string(&snapshot.position.commit_sequence.to_string())),
        ("ledgerRoot", string(&snapshot.ledger_root.to_text())),
        ("latestEvidenceNs", string(&snapshot.latest_evidence_time.0.to_string())),
        ("events", array(&events)),
        ("imports", strings(snapshot.completed_imports.iter().map(|d| d.to_text()))),
        ("counts", object(&[
            ("events", snapshot.events.len().to_string()),
            ("imports", snapshot.completed_imports.len().to_string()),
            ("openObligations", snapshot.open_obligations().len().to_string()),
            ("indeterminateOperations", snapshot.indeterminate_operations().len().to_string()),
            ("coverageRecords", snapshot.coverage.len().to_string()),
            ("sourceCoverageRecords", snapshot.source_coverage.len().to_string()),
            ("deletions", snapshot.deletions_committed.to_string()),
        ])),
        ("integrity", object(&[
            ("doctor", string(&format!("{:?}", snapshot.doctor_verdict))),
            ("ledgerTailUncommitted", snapshot.ledger_tail_uncommitted.to_string()),
            ("effectTailUncommitted", snapshot.effect_tail_uncommitted.to_string()),
            ("effectJournalPresent", snapshot.effect_journal_present.to_string()),
            ("filesRead", string(&snapshot.files_read.to_string())),
            ("bytesRead", string(&snapshot.bytes_read.to_string())),
        ])),
        ("families", rows(&snapshot.family_counts)),
        ("operationStates", rows(&operation_states)),
        ("obligationStates", rows(&obligation_states)),
        ("scope", string("Latest retained event revisions; metadata only. No source hydration, current camera health, coverage assessment, absence certification or effect authority.")),
    ]);
    lease.check()?;
    if body.len() > MAX_REPORT || started.elapsed() >= Duration::from_secs(5) { return Err(refused()); }
    Ok(body)
}
