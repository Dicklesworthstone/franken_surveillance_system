#![forbid(unsafe_code)]
//! Real ledger publication -> custody process; no injected snapshot or invented event slot.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_cli::json_input::{self, Value};
use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, DecisionPath, EventEvidence,
    EventHypothesis, EventId, EventKind, EventState, EvidenceClass, EvidenceEdgeRelation,
    Generation, ObjectId, OperationId, ProbabilityInterval, RootAuthoritySpec, TimestampNs,
    TombstoneReason, TombstoneRecord,
};
use fss_object::HostSpoolIo;
use fss_publication::custody_audit::{CustodyAuditError, CustodyAuditLimits, audit_local_roots};
use fss_publication::{SlotName, tombstone_record_bytes};
use fss_reference::agent_orient::{OrientLimits, read_deployment};
use fss_reference::{
    ADP_REPLAY_ROW_ID, ReferenceDeployment, ReferencePolicyAction, ReferencePolicyDecision,
    ReplayCx, ReplayIoAuthority,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:custody-authority-cli";
const EVENT: &str = "event:custody-authority-cli";
const SOURCE: &[u8] = b"PRIVATE SOURCE BYTES: these must never appear in an audit report";
const COUNTER: &[u8] = b"PRIVATE COUNTEREVIDENCE: preserve the reference, not these bytes";

struct Fixture {
    directory: PathBuf,
    root: PathBuf,
    event: EventHypothesis,
    event_root: ContentDigest,
    provenance: ContentDigest,
    source: ContentDigest,
    counter: ContentDigest,
}
impl Fixture {
    fn new(label: &str) -> TestResult<Self> {
        for attempt in 0..32 {
            let directory = std::env::temp_dir().join(format!(
                "fss-custody-authority-process-{label}-{}-{attempt}", std::process::id(),
            ));
            match fs::create_dir(&directory) {
                Ok(()) => return Self::populate(directory),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("temporary names exhausted".into())
    }

    fn populate(directory: PathBuf) -> TestResult<Self> {
        let root = directory.join("deployment");
        let cx = context(&directory)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let interval = CaptureInterval::new(TimestampNs(0), TimestampNs(1))?;
        let slot = SlotName::parse("custody-source")?;
        let staged = deployment.stage_and_publish(&slot, &[SOURCE, COUNTER], &cx)?;
        deployment.publish_and_commit(&slot, &staged.manifest, interval, &cx)?;
        let source = ContentDigest::sha256(SOURCE);
        let counter = ContentDigest::sha256(COUNTER);
        let policy = ContentDigest::sha256(b"uncalibrated synthetic custody fixture");
        let edge = |digest, relation: EvidenceEdgeRelation| EventEvidence {
            digest, class: EvidenceClass::Observed,
            failure_domain: "sensor:custody-fixture".to_owned(),
            supports: relation.required_supports_flag(), relation,
            capsule_digest: None, identity_digest: None,
        };
        let event = EventHypothesis {
            schema: EventHypothesis::SCHEMA.to_owned(), event_id: EventId::parse(EVENT)?,
            revision: 1, supersedes: None, state: EventState::Indeterminate,
            kind: EventKind::Unclassified, interval,
            uncertainty_reason: Some("synthetic; custody does not adjudicate either observation".to_owned()),
            zone_ids: vec!["fixture-zone".to_owned()], track_ids: vec![],
            probability: ProbabilityInterval { lower: 0.0, upper: 1.0, calibration_generation: None },
            evidence: vec![edge(source, EvidenceEdgeRelation::Supports), edge(counter, EvidenceEdgeRelation::Contradicts)],
            model_receipts: vec![staged.root],
            decision_path: DecisionPath {
                policy_generation: policy, fingerprint: policy, abstained: true,
                abstention_reason: Some("uncalibrated reference fixture".to_owned()),
            },
        };
        event.verify()?;
        let receipt = deployment.publish_event(&ReferencePolicyDecision {
            event: event.clone(), action: ReferencePolicyAction::Hold,
        }, &cx)?;
        drop(deployment);
        Ok(Self { directory, root, event, event_root: receipt.event_root,
            provenance: staged.root, source, counter })
    }

    fn object_path(&self, digest: ContentDigest) -> PathBuf {
        self.root.join("objects/spool/objects").join(digest.to_text().trim_start_matches("sha256:"))
    }

    fn run(&self, extra: &[&str]) -> TestResult<Output> {
        self.run_as(SITE, EVENT, extra)
    }

    fn run_as(&self, site: &str, event: &str, extra: &[&str]) -> TestResult<Output> {
        Ok(Command::new(env!("CARGO_BIN_EXE_fss-custody"))
            .args(["audit", "--root"]).arg(&self.root)
            .args(["--site", site, "--event-id", event]).args(extra).output()?)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.directory); }
}

fn context(directory: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:custody-process".to_owned(),
        operation_id: OperationId::parse("operation:custody-process")?,
        principal: "operator:custody-process".to_owned(),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()], deadline: None, priority: 10,
        budgets: BudgetVector::default(), privacy_scope: "privacy:internal".to_owned(),
        retention_scope: "retention:ephemeral".to_owned(),
        anchor_universe: ContentDigest::sha256(b"custody-process"), generation: 1,
    })?;
    Ok(ReplayCx::new(ReplayIoAuthority::from_context_authority(&authority, directory.join("cx"))?))
}

fn field<'a>(value: &'a Value, key: &str) -> TestResult<&'a Value> {
    value.object().and_then(|fields| fields.get(key)).ok_or_else(|| format!("missing {key}").into())
}
fn row(value: &Value, digest: ContentDigest) -> TestResult<&Value> {
    field(value, "objects")?.array().ok_or("objects not an array")?.iter()
        .find(|row| field(row, "digest").ok().and_then(Value::text) == Some(digest.to_text().as_str()))
        .ok_or_else(|| format!("object {digest} missing").into())
}
fn report(output: &Output) -> TestResult<Value> {
    Ok(json_input::parse(std::str::from_utf8(&output.stdout)?)?)
}
fn inventory(root: &Path) -> TestResult<BTreeMap<PathBuf, Vec<u8>>> {
    let mut result = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() { pending.push(entry.path()); }
            else { result.insert(entry.path(), fs::read(entry.path())?); }
        }
    }
    Ok(result)
}
fn no_report(output: &Output) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "refusal emitted a report: {}", String::from_utf8_lossy(&output.stdout));
    assert!(!output.stderr.is_empty());
}

#[test]
fn committed_slotless_event_audits_real_source_and_preserves_all_metadata() -> TestResult {
    let f = Fixture::new("intact")?;
    // Verify that this fixture crosses the precise seam the original command got wrong.
    let snapshot = read_deployment(&f.root, &OrientLimits::default())?;
    assert_eq!(snapshot.event(&f.event.event_id).ok_or("event absent")?.event_root, f.event_root);
    assert_eq!(audit_local_roots(&HostSpoolIo, &f.root.join("objects"), &[f.event_root],
        &BTreeMap::new(), CustodyAuditLimits::default(), &|| false), Err(CustodyAuditError::RootNotPublished));
    let before = inventory(&f.root)?;
    let output = f.run(&[])?;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let json = report(&output)?;
    assert_eq!(field(&json, "root_basis")?.text(), Some("caller_verified_authority"));
    assert_eq!(field(&json, "status")?.text(), Some("intact_at_observation"));
    assert_eq!(field(&json, "all_verified")?.boolean(), Some(true));
    assert_eq!(field(&json, "event_record")?, &json_input::parse(&f.event.to_canonical_json())?);
    assert_eq!(field(&json, "objects")?.array().ok_or("objects")?.len(), 5);
    assert_eq!(field(row(&json, f.source)?, "state")?.text(), Some("verified"));
    assert_eq!(field(row(&json, f.counter)?, "state")?.text(), Some("verified"));
    assert_eq!(field(row(&json, f.event_root)?, "declared_manifest")?.boolean(), Some(true));
    let text = std::str::from_utf8(&output.stdout)?;
    assert!(!text.contains(std::str::from_utf8(SOURCE)?));
    assert!(!text.contains(std::str::from_utf8(COUNTER)?));
    assert!(snapshot.operations.is_empty());
    assert_eq!(output.stdout, f.run(&[])?.stdout);
    assert_eq!(inventory(&f.root)?, before);
    assert_eq!(fs::read_dir(f.root.join("objects/roots"))?.count(), 1);
    Ok(())
}

#[test]
fn source_damage_is_a_nonzero_complete_fault_report_not_a_successful_metadata_only_read() -> TestResult {
    for (label, missing) in [("missing", true), ("corrupt", false)] {
        let f = Fixture::new(label)?;
        if missing { fs::remove_file(f.object_path(f.source))?; }
        else { fs::write(f.object_path(f.source), b"broken spool envelope")?; }
        let before = inventory(&f.root)?;
        let output = f.run(&[])?;
        assert!(!output.status.success());
        let json = report(&output)?;
        assert_eq!(field(&json, "status")?.text(), Some("custody_faults"));
        assert_eq!(field(&json, "all_verified")?.boolean(), Some(false));
        assert_eq!(field(row(&json, f.source)?, "state")?.text(), Some(label));
        assert_eq!(field(row(&json, f.counter)?, "state")?.text(), Some("verified"));
        assert_eq!(field(&json, "event_record")?, &json_input::parse(&f.event.to_canonical_json())?);
        assert_eq!(inventory(&f.root)?, before);
    }
    Ok(())
}

#[test]
fn lost_provenance_manifest_keeps_unknown_descendants_explicit() -> TestResult {
    let f = Fixture::new("missing-provenance")?;
    fs::remove_file(f.object_path(f.provenance))?;
    let output = f.run(&[])?;
    assert!(!output.status.success());
    let json = report(&output)?;
    assert_eq!(field(&json, "manifest_expansion_complete")?.boolean(), Some(false));
    assert_eq!(field(row(&json, f.provenance)?, "state")?.text(), Some("missing"));
    assert!(row(&json, f.source).is_err());
    assert!(row(&json, f.counter).is_err());
    assert_eq!(field(&json, "event_record")?, &json_input::parse(&f.event.to_canonical_json())?);
    Ok(())
}

#[test]
fn local_tombstone_remains_a_denial_when_payload_bytes_are_still_present() -> TestResult {
    let f = Fixture::new("tombstone")?;
    let tombstone = TombstoneRecord::new(
        ObjectId::parse("object:custody-source")?, Generation(2), Generation(1),
        TombstoneReason::Deleted, Some(f.source), ContentDigest::sha256(b"fixture privacy policy"),
    )?;
    let bytes = tombstone_record_bytes(&tombstone)?;
    fs::write(f.root.join("objects/tombstones").join(format!(
        "{}.tomb", f.source.to_text().replacen(':', "-", 1),
    )), &bytes)?;
    let before = inventory(&f.root)?;
    let output = f.run(&[])?;
    assert!(!output.status.success());
    let json = report(&output)?;
    let source = row(&json, f.source)?;
    assert_eq!(field(source, "state")?.text(), Some("locally_tombstoned"));
    assert_eq!(field(source, "verified_payload_bytes")?, &Value::Null);
    assert_eq!(field(source, "denial_digest")?.text(), Some(ContentDigest::sha256(&bytes).to_text().as_str()));
    assert!(f.object_path(f.source).is_file());
    assert_eq!(inventory(&f.root)?, before);
    Ok(())
}

#[test]
fn current_event_pin_and_work_limits_refuse_without_fallback_or_partial_output() -> TestResult {
    let f = Fixture::new("pins-and-limits")?;
    let pin = f.event_root.to_text();
    assert!(f.run(&["--expected-root", &pin])?.status.success());
    no_report(&f.run_as("site:wrong", EVENT, &[])?);
    no_report(&f.run_as(SITE, "event:missing", &[])?);
    for options in [
        ["--max-objects", "0"], ["--max-edges", "0"],
        ["--max-io-calls", "0"], ["--max-read-bytes", "0"],
        ["--max-report-bytes", "1024"],
    ] { no_report(&f.run(&options)?); }
    let cx = context(&f.directory)?;
    let mut deployment = ReferenceDeployment::open(&f.root, SITE, &cx)?;
    let mut successor = f.event.clone();
    successor.revision += 1;
    successor.supersedes = Some(f.event.revision_digest());
    successor.uncertainty_reason = Some("later retained qualification; not automatic invalidation".to_owned());
    let next = deployment.publish_event(&ReferencePolicyDecision {
        event: successor, action: ReferencePolicyAction::Hold,
    }, &cx)?;
    drop(deployment);
    assert_ne!(next.event_root, f.event_root);
    no_report(&f.run(&["--expected-root", &pin])?);
    assert!(f.run(&["--expected-root", &next.event_root.to_text()])?.status.success());
    Ok(())
}

#[test]
fn corrupt_event_authority_is_not_rescued_by_an_intact_source_tree() -> TestResult {
    let f = Fixture::new("authority-damage")?;
    fs::write(f.object_path(f.event_root), b"damaged authority manifest")?;
    no_report(&f.run(&[])?);
    Ok(())
}
