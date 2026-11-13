#![forbid(unsafe_code)]
//! Real deployment/session recovery and metadata custody, without a source-media reader.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::*;
use crate::agent_session::SessionRefresh;
use crate::agent_session::checkpoint::journal::{
    DurableSessionLimits, SessionRecoveryState, inspect_session_bytes,
};
use crate::agent_session::work_claims::WorkClaimLimits;
use crate::deployment_session::{
    OpenSessionRequest, SESSION_JOURNAL_FILE, SESSIONS_RELPATH, open_session,
};
use crate::reference_deployment::{RELATIVE_PATH_EFFECTS, RELATIVE_PATH_LEDGER};
use crate::{ReferenceDeployment, ReferencePolicyAction, ReferencePolicyDecision};
use fss_core::{
    CaptureInterval, DecisionPath, EventEvidence, EventHypothesis, EventKind, EventState,
    EvidenceClass, EvidenceEdgeRelation, H0Identity, H1SemanticSynopsis, ProbabilityInterval,
};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:durable-event-hydration";
const SOURCE: &[u8] = b"PRIVATE_ORIGINAL_SOURCE_IS_NEVER_A_METADATA_HYDRATION_PAYLOAD";

struct Fixture {
    directory: PathBuf,
    root: PathBuf,
    cx: ReplayCx,
    request: EvidenceHydrationRequest,
}

impl Fixture {
    fn new(label: &str) -> Test<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = loop {
            let path = std::env::temp_dir().join(format!(
                "fss-durable-event-hydration-{label}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => break path,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        };
        let root = directory.join("deployment");
        let principal = PrincipalId::parse("principal:durable-event-hydration")?;
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:durable-event-hydration".into(),
            operation_id: OperationId::parse("operation:durable-event-hydration")?,
            principal: principal.as_str().into(),
            capabilities: vec![ADP_REPLAY_ROW_ID.into()],
            deadline: None,
            priority: 10,
            budgets: event_hydration_cost(HydrationLevel::H1)?,
            privacy_scope: "privacy:internal".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?;
        let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let event = EventHypothesis {
            schema: EventHypothesis::SCHEMA.into(),
            event_id: EventId::parse("event:durable-hydration")?,
            revision: 1,
            supersedes: None,
            state: EventState::Hypothesized,
            kind: EventKind::UnknownPresence,
            interval: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
            uncertainty_reason: Some(
                "Synthetic retained metadata; no physical determination".into(),
            ),
            zone_ids: vec!["front-door".into()],
            track_ids: Vec::new(),
            probability: ProbabilityInterval::new(0.0, 1.0)?,
            evidence: vec![EventEvidence {
                digest: ContentDigest::sha256(SOURCE),
                class: EvidenceClass::Assertion,
                failure_domain: "sensor:metadata-fixture".into(),
                supports: false,
                relation: EvidenceEdgeRelation::DerivedFrom,
                capsule_digest: None,
                identity_digest: None,
            }],
            model_receipts: Vec::new(),
            decision_path: DecisionPath {
                policy_generation: ContentDigest::sha256(b"metadata-policy"),
                fingerprint: ContentDigest::sha256(b"metadata-decision"),
                abstained: true,
                abstention_reason: Some("Metadata cannot determine physical presence".into()),
            },
        };
        deployment.stage_payload(SOURCE)?;
        deployment.publish_event(
            &ReferencePolicyDecision {
                event: event.clone(),
                action: ReferencePolicyAction::Hold,
            },
            &cx,
        )?;
        drop(deployment);
        let opened = open_session(
            &root,
            &OpenSessionRequest {
                mission: "Explain exact retained event evidence".into(),
                objective: "Inspect metadata without granting source-media disclosure".into(),
                principal: principal.clone(),
                view: AgentView::Brief,
                token_budget: 100_000,
            },
        )?;
        let request = EvidenceHydrationRequest {
            session_id: opened.session.session_id,
            principal,
            generation: opened.session.symbol_table_generation,
            event_id: event.event_id.clone(),
            expected_revision: event.revision_digest(),
            expected_anchor: AnchorToken::parse(&opened.orientation.anchor_token)
                .ok_or("invalid fixture anchor")?,
            expected_descriptor: None,
            level: HydrationLevel::H0,
            budget_tokens: 5_000,
            continuation: None,
        };
        Ok(Self {
            directory,
            root,
            cx,
            request,
        })
    }

    fn journal_bytes(&self) -> Test<Vec<u8>> {
        Ok(fs::read(
            self.root.join(SESSIONS_RELPATH).join(SESSION_JOURNAL_FILE),
        )?)
    }

    fn retained(&self) -> Test<SessionRecoveryState> {
        Ok(inspect_session_bytes(
            &self.journal_bytes()?,
            DurableSessionLimits::default(),
            WorkClaimLimits::default(),
        )?)
    }

    fn spent(&self) -> Test<u64> {
        self.retained()?
            .sessions
            .into_iter()
            .find(|entry| entry.session.session_id == self.request.session_id)
            .map(|entry| entry.spent_tokens)
            .ok_or_else(|| "fixture session missing".into())
    }

    fn authority_digests(&self) -> Test<(ContentDigest, ContentDigest)> {
        let digest = |path: &str| -> Test<ContentDigest> {
            match fs::read(self.root.join(path)) {
                Ok(bytes) => Ok(ContentDigest::sha256(&bytes)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    Ok(ContentDigest::sha256(&[]))
                }
                Err(error) => Err(error.into()),
            }
        };
        Ok((
            digest(RELATIVE_PATH_LEDGER)?,
            digest(RELATIVE_PATH_EFFECTS)?,
        ))
    }

    fn object_path(&self, digest: ContentDigest) -> PathBuf {
        self.root
            .join("objects")
            .join(fss_publication::LOCAL_SPOOL_DIR)
            .join(fss_object::SPOOL_OBJECTS_DIR)
            .join(
                digest
                    .bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
            )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn h0_h1_cold_reopen_charges_once_per_delivery_and_never_revives_consumed_cursor() -> Test {
    let fixture = Fixture::new("progressive")?;
    let authority = fixture.authority_digests()?;
    let before = fixture.retained()?;
    // A cooperating recorder/publisher can keep its independent owner open throughout reads.
    let _writer = ReferenceDeployment::open(&fixture.root, SITE, &fixture.cx)?;
    let h0 = hydrate_event_evidence(&fixture.root, &fixture.request, &|| false)?;
    h0.response.validate_for(&h0.request, &h0.descriptor)?;
    let identity = H0Identity::from_canonical_bytes(
        &h0.response.artifact.as_ref().ok_or("H0 missing")?.payload,
    )?;
    assert_eq!(identity, h0.descriptor.to_h0_identity()?);
    assert_eq!(h0.charged_tokens, 5_000);
    assert_eq!(h0.remaining_tokens, 95_000);
    assert_eq!(fixture.retained()?.inspection.root, h0.journal_root);
    let mut request = fixture.request.clone();
    request.level = HydrationLevel::H1;
    request.budget_tokens = 16_000;
    request.expected_descriptor = Some(h0.descriptor.descriptor_digest);
    request.continuation = Some(
        h0.response
            .receipt
            .continuation
            .clone()
            .ok_or("cursor missing")?,
    );
    let h1 = hydrate_event_evidence(&fixture.root, &request, &|| false)?;
    h1.response.validate_for(&h1.request, &h1.descriptor)?;
    assert_eq!(h1.descriptor, h0.descriptor);
    H1SemanticSynopsis::from_canonical_bytes(
        &h1.response.artifact.as_ref().ok_or("H1 missing")?.payload,
    )?;
    assert_eq!(h1.response.receipt.continuation, None);
    assert_eq!(h1.charged_tokens, 16_000);
    assert_eq!(h1.remaining_tokens, 79_000);
    assert_eq!(fixture.spent()?, 21_000);
    let retained = fixture.retained()?;
    assert_eq!(
        retained.workspace_checkpoint_digest,
        before.workspace_checkpoint_digest
    );
    assert_eq!(retained.workspace_revisions, before.workspace_revisions);
    assert_eq!(retained.missions, before.missions);
    let stable_bytes = fixture.journal_bytes()?;
    assert!(hydrate_event_evidence(&fixture.root, &request, &|| false).is_err());
    // A rebuilt catalog must not treat this exact old H0 as a new cursor issuance either.
    assert!(hydrate_event_evidence(&fixture.root, &fixture.request, &|| false).is_err());
    assert_eq!(fixture.journal_bytes()?, stable_bytes);
    assert_eq!(fixture.spent()?, 21_000);
    assert_eq!(fixture.authority_digests()?, authority);
    assert!(
        !stable_bytes
            .windows(SOURCE.len())
            .any(|value| value == SOURCE)
    );
    Ok(())
}

#[test]
fn missing_original_media_does_not_prevent_retained_metadata_hydration() -> Test {
    let fixture = Fixture::new("no-media")?;
    fs::remove_file(fixture.object_path(ContentDigest::sha256(SOURCE)))?;
    let answer = hydrate_event_evidence(&fixture.root, &fixture.request, &|| false)?;
    assert_eq!(answer.charged_tokens, 5_000);
    assert_eq!(
        answer.explanation.event.event.state,
        EventState::Hypothesized
    );
    assert!(
        !answer
            .response
            .artifact
            .ok_or("missing artifact")?
            .payload
            .windows(SOURCE.len())
            .any(|value| value == SOURCE)
    );
    Ok(())
}

#[test]
fn changed_scope_or_precommit_cancellation_has_no_disclosure_or_charge() -> Test {
    let fixture = Fixture::new("scope")?;
    let stable = fixture.journal_bytes()?;
    for choice in 0..7 {
        let mut request = fixture.request.clone();
        match choice {
            0 => request.principal = PrincipalId::parse("principal:foreign")?,
            1 => request.generation += 1,
            2 => request.expected_revision = ContentDigest::sha256(b"foreign-revision"),
            3 => request.expected_descriptor = Some(ContentDigest::sha256(b"foreign-descriptor")),
            4 => request.budget_tokens = 4_999,
            5 => {
                request.level = HydrationLevel::H3;
                request.expected_descriptor = Some(ContentDigest::sha256(b"ungranted-source"));
            }
            _ => {}
        }
        let failure = hydrate_event_evidence(&fixture.root, &request, &|| choice == 6)
            .expect_err("scope must be refused");
        assert!(failure.committed.is_none());
        if choice <= 3 {
            assert!(
                failure.observed.is_some(),
                "refusal retains the already verified metadata anchor without another read"
            );
        } else {
            assert!(
                failure.observed.is_none(),
                "malformed or cancelled admission performs no metadata read"
            );
        }
        assert_eq!(fixture.journal_bytes()?, stable);
        assert_eq!(fixture.spent()?, 0);
    }
    Ok(())
}

#[test]
fn stored_grants_and_privacy_cannot_be_recreated_by_metadata_request() -> Test {
    for removed in [
        EVIDENCE_HYDRATION_CAPABILITY,
        EVIDENCE_QUERY_CAPABILITY,
        "privacy",
    ] {
        let mut fixture = Fixture::new("narrowed")?;
        let now = TimestampNs(20);
        let mut journal = SessionJournal::open(&fixture.root)?;
        let session =
            journal
                .store
                .session(&fixture.request.principal, &fixture.request.session_id, now)?;
        let mut capabilities = session.capabilities.clone();
        let mut privacy_scope = session.privacy_scope.clone();
        if removed == "privacy" {
            privacy_scope = BTreeSet::new();
        } else {
            capabilities.remove(removed);
        }
        let narrowed = journal.store.refresh(
            &fixture.request.principal,
            &fixture.request.session_id,
            SessionRefresh {
                expected_session_digest: session.session_digest(),
                current_anchor: session.current_anchor,
                capabilities,
                privacy_scope,
            },
            now,
        )?;
        journal.commit_pin()?;
        drop(journal);
        fixture.request.generation = narrowed.symbol_table_generation;
        let stable = fixture.journal_bytes()?;
        let failure = hydrate_event_evidence(&fixture.root, &fixture.request, &|| false)
            .expect_err("stored narrowed scope must refuse");
        assert!(failure.committed.is_none());
        assert_eq!(fixture.journal_bytes()?, stable);
        assert_eq!(fixture.spent()?, 0);
    }
    Ok(())
}

#[test]
fn postcommit_cancellation_withholds_artifact_but_preserves_charge_and_cursor() -> Test {
    let fixture = Fixture::new("cancel-after-charge")?;
    let observed = AtomicBool::new(false);
    let cancelled = || {
        let committed = fixture.spent().is_ok_and(|tokens| tokens == 5_000);
        if committed {
            observed.store(true, Ordering::Relaxed);
        }
        committed
    };
    let failure = hydrate_event_evidence(&fixture.root, &fixture.request, &cancelled)
        .expect_err("final cancellation must withhold payload");
    assert!(observed.load(Ordering::Relaxed));
    let charge = failure
        .committed
        .ok_or("committed charge must survive refusal")?;
    let retained = fixture.retained()?;
    assert_eq!(charge.journal_root, retained.inspection.root);
    assert_eq!(charge.charged_tokens, 5_000);
    assert_eq!(charge.remaining_tokens, 95_000);
    assert_eq!(fixture.spent()?, 5_000);
    // A retry is a separately charged delivery and reuses, rather than resets, native issuance.
    let retry = hydrate_event_evidence(&fixture.root, &fixture.request, &|| false)?;
    assert_eq!(retry.remaining_tokens, 90_000);
    assert!(retry.response.receipt.continuation.is_some());
    assert_eq!(fixture.spent()?, 10_000);
    Ok(())
}

#[test]
fn selected_metadata_corrupted_after_charge_is_withheld_without_refund() -> Test {
    let fixture = Fixture::new("corrupt-after-charge")?;
    let owner = ImmutableRetainedSource::open(
        &fixture.root,
        ImmutableRetainedReadLimits {
            snapshot: OrientLimits::default(),
            max_read_bytes: MAX_EVENT_HYDRATION_READ_BYTES,
            max_read_objects: MAX_EVENT_HYDRATION_READ_OBJECTS,
        },
        &fixture.cx,
    )?;
    let root = owner
        .snapshot()
        .event(&fixture.request.event_id)
        .ok_or("missing event")?
        .event_root;
    let manifest = fss_object::ObjectManifest::from_canonical_bytes(
        &owner.read_object_bounded(root, OrientLimits::default().max_object_bytes)?,
    )?;
    let path = fixture.object_path(
        manifest
            .metadata_digest()
            .ok_or("metadata digest missing")?,
    );
    drop(owner);
    let observed = AtomicBool::new(false);
    let cancelled = || {
        if fixture.spent().is_ok_and(|tokens| tokens == 5_000)
            && !observed.swap(true, Ordering::Relaxed)
        {
            fs::write(
                &path,
                b"corrupt selected event object after synchronized disclosure",
            )
            .expect("exclusive fixture metadata should be writable");
        }
        false
    };
    let failure = hydrate_event_evidence(&fixture.root, &fixture.request, &cancelled)
        .expect_err("selected metadata drift must withhold payload");
    assert!(observed.load(Ordering::Relaxed));
    assert_eq!(
        failure.committed.ok_or("charge lost")?.charged_tokens,
        5_000
    );
    assert_eq!(fixture.spent()?, 5_000);
    Ok(())
}

#[test]
fn initial_metadata_admission_consumes_the_same_later_owner_allowance() -> Test {
    let fixture = Fixture::new("one-allowance")?;
    let measure = MetadataReadBudget::new(
        MAX_EVENT_HYDRATION_READ_BYTES,
        MAX_EVENT_HYDRATION_READ_OBJECTS,
    );
    with_admitted_session_metadata_read(
        &fixture.root,
        &fixture.request.principal,
        &fixture.request.session_id,
        &measure,
        &|| false,
        |_| {},
        |_| Ok(()),
    )?;
    let (_, attempts) = measure.consumed();
    assert!(attempts > 0);
    let exact = MetadataReadBudget::new(MAX_EVENT_HYDRATION_READ_BYTES, attempts as usize);
    let stable = fixture.journal_bytes()?;
    with_admitted_session_metadata_read(
        &fixture.root,
        &fixture.request.principal,
        &fixture.request.session_id,
        &exact,
        &|| false,
        |_| {},
        |_| Ok(()),
    )?;
    assert_eq!(exact.consumed().1, attempts);
    assert!(
        ImmutableRetainedSource::open_with_metadata_budget(
            &fixture.root,
            ImmutableRetainedReadLimits {
                snapshot: OrientLimits::default(),
                max_read_bytes: MAX_EVENT_HYDRATION_READ_BYTES,
                max_read_objects: MAX_EVENT_HYDRATION_READ_OBJECTS,
            },
            &fixture.cx,
            &|| false,
            exact
        )
        .is_err()
    );
    assert_eq!(fixture.journal_bytes()?, stable);
    assert_eq!(fixture.spent()?, 0);
    Ok(())
}
