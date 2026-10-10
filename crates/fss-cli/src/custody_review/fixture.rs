#![forbid(unsafe_code)]
//! Test-only real event publication shared by library and process regressions.
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, DecisionPath, EventEvidence,
    EventHypothesis, EventId, EventKind, EventState, EvidenceClass, EvidenceEdgeRelation,
    OperationId, ProbabilityInterval, RootAuthoritySpec, TimestampNs,
};
use fss_publication::SlotName;
use fss_reference::{
    ADP_REPLAY_ROW_ID, ReferenceDeployment, ReferencePolicyAction, ReferencePolicyDecision,
    ReplayCx, ReplayIoAuthority,
};

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub const SITE: &str = "site:agent-custody";
pub const EVENT: &str = "event:agent-custody";
pub const SOURCE: &[u8] = b"PRIVATE SOURCE: never disclose these payload bytes";
pub const COUNTER: &[u8] = b"PRIVATE COUNTEREVIDENCE: metadata is not permission to disclose";

pub struct Fixture {
    pub directory: PathBuf,
    pub root: PathBuf,
    pub event: EventHypothesis,
    pub event_root: ContentDigest,
    pub provenance: ContentDigest,
    pub source: ContentDigest,
    pub counter: ContentDigest,
    pub extras: Vec<ContentDigest>,
}
impl Fixture {
    pub fn new(label: &str) -> TestResult<Self> { Self::with_extra(label, 0) }
    pub fn with_extra(label: &str, extra: usize) -> TestResult<Self> {
        for attempt in 0..32 {
            let directory = std::env::temp_dir().join(format!(
                "fss-agent-custody-{label}-{}-{attempt}", std::process::id(),
            ));
            match fs::create_dir(&directory) {
                Ok(()) => return Self::populate(directory, extra),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("temporary names exhausted".into())
    }
    fn populate(directory: PathBuf, extra: usize) -> TestResult<Self> {
        let root = directory.join("deployment");
        let cx = context(&directory)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let interval = CaptureInterval::new(TimestampNs(0), TimestampNs(1))?;
        let slot = SlotName::parse("custody-source")?;
        let extra_bytes: Vec<_> = (0..extra).map(|n| format!("private additional source {n}").into_bytes()).collect();
        let mut objects = vec![SOURCE, COUNTER];
        objects.extend(extra_bytes.iter().map(Vec::as_slice));
        let staged = deployment.stage_and_publish(&slot, &objects, &cx)?;
        deployment.publish_and_commit(&slot, &staged.manifest, interval, &cx)?;
        let source = ContentDigest::sha256(SOURCE);
        let counter = ContentDigest::sha256(COUNTER);
        let policy = ContentDigest::sha256(b"uncalibrated synthetic custody fixture");
        let edge = |digest, relation: EvidenceEdgeRelation| EventEvidence {
            digest, class: EvidenceClass::Observed, failure_domain: "sensor:custody".to_owned(),
            supports: relation.required_supports_flag(), relation,
            capsule_digest: None, identity_digest: None,
        };
        let event = EventHypothesis {
            schema: EventHypothesis::SCHEMA.to_owned(), event_id: EventId::parse(EVENT)?,
            revision: 1, supersedes: None, state: EventState::Indeterminate,
            kind: EventKind::Unclassified, interval,
            uncertainty_reason: Some("custody does not adjudicate either observation".to_owned()),
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
            provenance: staged.root, source, counter,
            extras: extra_bytes.iter().map(|b| ContentDigest::sha256(b)).collect() })
    }
    pub fn object_path(&self, digest: ContentDigest) -> PathBuf {
        self.root.join("objects/spool/objects").join(digest.to_text().trim_start_matches("sha256:"))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.directory); }
}

pub fn context(directory: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:agent-custody".to_owned(),
        operation_id: OperationId::parse("operation:agent-custody")?,
        principal: "operator:agent-custody".to_owned(),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()], deadline: None, priority: 10,
        budgets: BudgetVector::default(), privacy_scope: "privacy:internal".to_owned(),
        retention_scope: "retention:ephemeral".to_owned(),
        anchor_universe: ContentDigest::sha256(b"agent-custody"), generation: 1,
    })?;
    Ok(ReplayCx::new(ReplayIoAuthority::from_context_authority(&authority, directory.join("cx"))?))
}

pub fn inventory(root: &Path) -> TestResult<BTreeMap<PathBuf, Vec<u8>>> {
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
