#![forbid(unsafe_code)]
//! Redacted event export over real reference deployment authority/custody.

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, DecisionPath, EventEvidence, EventHypothesis,
    EventId, EventKind, EventState, EvidenceClass, EvidenceEdgeRelation, OperationId,
    ProbabilityInterval, TimestampNs,
};
use fss_reference::evidence_export::*;
use fss_reference::{
    ReferenceDeployment, ReferencePolicyAction, ReferencePolicyDecision, ReplayCx,
};
use std::fs;
use std::path::PathBuf;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:evidence-export";
const ACTOR: &str = "principal:evidence-export";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for n in 0..100 {
            let p =
                std::env::temp_dir().join(format!("fss-export-{label}-{}-{n}", std::process::id()));
            match fs::create_dir(&p) {
                Ok(()) => return Ok(Self(p)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("temporary directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn authority(caps: &[&str]) -> Test<ContextAuthority> {
    Ok(ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:evidence-export".into(),
        operation_id: OperationId::parse("operation:evidence-export")?,
        principal: ACTOR.into(),
        capabilities: caps.iter().map(|v| (*v).into()).collect(),
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(8192)
            .build()?,
        privacy_scope: "privacy:redacted-export-test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?)
}
fn event() -> Test<EventHypothesis> {
    Ok(EventHypothesis {
        schema: EventHypothesis::SCHEMA.into(),
        event_id: EventId::parse("event:export-fixture")?,
        revision: 1,
        supersedes: None,
        state: EventState::Indeterminate,
        kind: EventKind::Unclassified,
        interval: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
        uncertainty_reason: Some("Synthetic fixture".into()),
        zone_ids: vec!["private-zone-name".into()],
        track_ids: vec!["private-track-name".into()],
        probability: ProbabilityInterval::new(0.0, 1.0)?,
        evidence: vec![EventEvidence {
            digest: ContentDigest::sha256(b"synthetic source assertion"),
            class: EvidenceClass::Assertion,
            failure_domain: "sensor:private-front-door".into(),
            supports: false,
            relation: EvidenceEdgeRelation::DerivedFrom,
            capsule_digest: None,
            identity_digest: Some(ContentDigest::sha256(b"private identity")),
        }],
        model_receipts: vec![ContentDigest::sha256(b"model receipt")],
        decision_path: DecisionPath {
            policy_generation: ContentDigest::sha256(b"policy"),
            fingerprint: ContentDigest::sha256(b"decision"),
            abstained: true,
            abstention_reason: Some("synthetic".into()),
        },
    })
}
struct Fixture {
    deployment: ReferenceDeployment,
    cx: ReplayCx,
    auth: ContextAuthority,
    event: EventHypothesis,
    _dir: Directory,
}
impl Fixture {
    fn new(label: &str) -> Test<Self> {
        let dir = Directory::new(label)?;
        let auth = authority(&["ADP-REPLAY-001", CAP_EXPORT_PREPARE, CAP_EXPORT_COMMIT])?;
        let root = dir.0.join("deployment");
        let cx = ReplayCx::from_context_authority(&auth, root.clone())?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let event = event()?;
        deployment.stage_payload(b"synthetic source assertion")?;
        // publish_event requires every referenced digest, including model receipts, in custody.
        deployment.stage_payload(b"model receipt")?;
        deployment.publish_event(
            &ReferencePolicyDecision {
                event: event.clone(),
                action: ReferencePolicyAction::Hold,
            },
            &cx,
        )?;
        Ok(Self {
            deployment,
            cx,
            auth,
            event,
            _dir: dir,
        })
    }
    fn request(&self) -> EventExportRequest {
        EventExportRequest {
            event_id: self.event.event_id.clone(),
            expected_revision: self.event.revision_digest(),
            recipient: "recipient:insurer-case-7".into(),
            purpose: "Owner-authorized incident review".into(),
            expires_at: TimestampNs(100),
        }
    }
    fn snapshot(&self) -> (fss_core::LedgerAnchor, usize) {
        (
            self.deployment.current_anchor().clone(),
            self.deployment.publisher().spool().digests().count(),
        )
    }
}

#[test]
fn preview_is_read_only_and_projection_drops_sensitive_identifiers() -> Test {
    let f = Fixture::new("preview")?;
    let before = f.snapshot();
    let preview = preview_export(&f.deployment, &f.request(), &f.auth, &f.cx)?;
    let json = preview.record().to_redacted_json();
    assert!(!json.contains("private-zone-name"));
    assert!(!json.contains("private-track-name"));
    assert!(!json.contains("sensor:private-front-door"));
    assert!(!json.contains("private identity"));
    assert!(json.contains("\"raw_media_included\":false"));
    assert!(json.contains("\"live_archive_namespace_exposed\":false"));
    let manifest = preview.record().manifest()?;
    assert_eq!(manifest.children(), &[preview.record().digest()]);
    assert!(!manifest.children().contains(&preview.record().event_root()));
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn commit_is_idempotent_and_survives_reopen() -> Test {
    let mut f = Fixture::new("retry")?;
    let request = f.request();
    let preview = preview_export(&f.deployment, &request, &f.auth, &f.cx)?;
    let first = commit_export(
        &mut f.deployment,
        &request,
        preview.approval(),
        &f.auth,
        &f.cx,
    )?;
    assert!(first.published);
    let after = f.snapshot();
    let retry = commit_export(
        &mut f.deployment,
        &request,
        preview.approval(),
        &f.auth,
        &f.cx,
    )?;
    assert!(!retry.published);
    assert_eq!(f.snapshot(), after);
    let root = f.deployment.root().to_path_buf();
    drop(f.deployment);
    let mut reopened = ReferenceDeployment::reopen(&root, SITE, &f.cx)?;
    let retry = commit_export(&mut reopened, &request, preview.approval(), &f.auth, &f.cx)?;
    assert!(!retry.published);
    assert_eq!(*reopened.current_anchor(), after.0);
    let (verified, authority_anchor) = read_export(&reopened, preview.root(), &f.auth, &f.cx)?;
    assert_eq!(verified.digest(), preview.record().digest());
    assert_eq!(verified.request(), &request);
    assert_eq!(authority_anchor, after.0);
    Ok(())
}

#[test]
fn stale_approval_revision_and_missing_commit_capability_fail_closed() -> Test {
    let mut f = Fixture::new("stale")?;
    let request = f.request();
    let preview = preview_export(&f.deployment, &request, &f.auth, &f.cx)?;
    let before = f.snapshot();
    let mut changed = request.clone();
    changed.recipient = "recipient:other".into();
    assert!(matches!(
        commit_export(
            &mut f.deployment,
            &changed,
            preview.approval(),
            &f.auth,
            &f.cx
        ),
        Err(ExportError::StaleApproval)
    ));
    assert_eq!(f.snapshot(), before);
    let mut stale = request.clone();
    stale.expected_revision = ContentDigest::sha256(b"old revision");
    assert!(matches!(
        preview_export(&f.deployment, &stale, &f.auth, &f.cx),
        Err(ExportError::StaleRevision)
    ));
    let prepare = authority(&["ADP-REPLAY-001", CAP_EXPORT_PREPARE])?;
    let current = preview_export(&f.deployment, &request, &prepare, &f.cx)?;
    assert!(matches!(
        commit_export(
            &mut f.deployment,
            &request,
            current.approval(),
            &prepare,
            &f.cx
        ),
        Err(ExportError::Unauthorized)
    ));
    assert_eq!(f.snapshot(), before);
    Ok(())
}
