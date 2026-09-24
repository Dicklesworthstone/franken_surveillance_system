#![forbid(unsafe_code)]
use super::super::super::tests::{basis, opening, params};
use super::*;
use crate::agent_session::SessionRefresh;
use crate::agent_session::checkpoint::journal::SessionAppendRecovery;
use crate::agent_session::work_claims::WorkClaimLimits;
use fss_core::AgentSessionParams;
use fss_ledger::{AppendPhase, IncompleteTailPolicy, Journal};
use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

type TestResult = Result<(), Box<dyn Error>>;
static NEXT_PATH: AtomicU64 = AtomicU64::new(0);
fn root(text: &str) -> ContentDigest {
    ContentDigest::sha256(text.as_bytes())
}
fn unused_path() -> Result<PathBuf, Box<dyn Error>> {
    for _ in 0..128 {
        let serial = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fss-case-evolution-{}-{serial}.journal",
            std::process::id()
        ));
        if !path.exists() {
            return Ok(path);
        }
    }
    Err("test path capacity exhausted".into())
}
fn opened() -> Result<
    (
        DurableSessionStore,
        AgentSessionParams,
        InvestigationRevision,
    ),
    Box<dyn Error>,
> {
    let p = params("session:evolution-durable")?;
    let mut store = DurableSessionStore::create(unused_path()?, DurableSessionLimits::default())?;
    store.open(p.clone(), basis(), TimestampNs(1))?;
    store.enable_coordination(WorkClaimLimits::default())?;
    store.enable_investigations(InvestigationLimits::default())?;
    let mut command = opening()?;
    if let InvestigationCommand::Open { record, .. } = &mut command {
        record.hypotheses[0].evidence.push(root("old"));
    }
    let head = store.investigate(&p.principal_id, &p.session_id, command, TimestampNs(10))?;
    Ok((store, p, head))
}
fn request(
    head: &InvestigationRevision,
    change: InvestigationEvolution,
) -> InvestigationEvolutionRequest {
    InvestigationEvolutionRequest {
        case_id: head.record.investigation_id.clone(),
        expected: head.digest(),
        change,
    }
}
fn rebase_request(
    store: &mut DurableSessionStore,
    p: &AgentSessionParams,
    head: &InvestigationRevision,
) -> Result<InvestigationEvolutionRequest, Box<dyn Error>> {
    let session = store.session(&p.principal_id, &p.session_id, TimestampNs(20))?;
    let mut anchor = session.current_anchor.clone();
    anchor.commit_sequence += 1;
    store.refresh(
        &p.principal_id,
        &p.session_id,
        SessionRefresh {
            expected_session_digest: session.session_digest(),
            current_anchor: anchor.clone(),
            capabilities: session.capabilities,
            privacy_scope: session.privacy_scope,
        },
        TimestampNs(20),
    )?;
    Ok(request(
        head,
        InvestigationEvolution::Rebase {
            anchor,
            witness: root("drift rationale"),
        },
    ))
}
fn expansion() -> InvestigationEvolution {
    InvestigationEvolution::Expand {
        hypothesis: Box::new(CaseHypothesis {
            hypothesis_id: "hypothesis:c".to_owned(),
            description: "Another explanation".to_owned(),
            epistemic_state: KnowledgeState::Unknown,
            predictions: vec!["independent view".to_owned()],
            evidence: vec![],
            contradictions: vec![],
        }),
        discriminator: Box::new(CaseDiscriminator {
            discriminator_id: "discriminator:new".to_owned(),
            description: "Observe the other view".to_owned(),
            separates: vec!["hypothesis:a".to_owned(), "hypothesis:c".to_owned()],
            expected_outcomes: vec!["present".to_owned(), "absent".to_owned()],
        }),
        probe: "probe:second".to_owned(),
    }
}
fn head(
    store: &mut DurableSessionStore,
    p: &AgentSessionParams,
) -> Result<InvestigationRevision, DurableInvestigationError> {
    store.investigate(
        &p.principal_id,
        &p.session_id,
        InvestigationCommand::Inspect {
            case_id: "case:window".to_owned(),
            revision: None,
        },
        TimestampNs(20),
    )
}
fn change(
    store: &mut DurableSessionStore,
    p: &AgentSessionParams,
    r: &InvestigationRevision,
    change: InvestigationChange,
) -> Result<InvestigationRevision, DurableInvestigationError> {
    store.investigate(
        &p.principal_id,
        &p.session_id,
        InvestigationCommand::Change {
            case_id: r.record.investigation_id.clone(),
            expected: r.digest(),
            change,
        },
        TimestampNs(20),
    )
}
fn reopen(store: DurableSessionStore) -> Result<DurableSessionStore, DurableSessionError> {
    let path = store.path().to_path_buf();
    let root = store.committed_root();
    drop(store);
    DurableSessionStore::open_existing_with_coordination(
        path,
        root,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )
}

#[test]
fn rebase_and_exact_use_readmission_survive_interleaved_legacy_commands_and_restart() -> TestResult
{
    let (mut store, p, old) = opened()?;
    let intent = rebase_request(&mut store, &p, &old)?;
    let rebased =
        store.evolve_investigation(&p.principal_id, &p.session_id, intent, TimestampNs(20))?;
    let mut store = reopen(store)?;
    assert_eq!(head(&mut store, &p)?, rebased);
    let active = change(&mut store, &p, &rebased, InvestigationChange::Activate)?;
    let repeat = change(
        &mut store,
        &p,
        &active,
        InvestigationChange::Cite {
            hypothesis: "hypothesis:a".to_owned(),
            evidence: root("old"),
            contradicts: false,
        },
    )?;
    let assess = InvestigationChange::Assess {
        hypothesis: "hypothesis:a".to_owned(),
        evidence: root("old"),
        disposition: HypothesisDisposition::Supported,
    };
    assert!(matches!(
        change(&mut store, &p, &repeat, assess.clone()),
        Err(DurableInvestigationError::Refused(
            InvestigationError::EvidenceRequired
        ))
    ));
    let admitted = store.evolve_investigation(
        &p.principal_id,
        &p.session_id,
        request(
            &repeat,
            InvestigationEvolution::ReadmitCitation {
                citation: InvestigationCitation {
                    hypothesis: "hypothesis:a".to_owned(),
                    evidence: root("old"),
                    contradicts: false,
                },
                witness: root("current applicability"),
            },
        ),
        TimestampNs(20),
    )?;
    let mut store = reopen(store)?;
    assert_eq!(head(&mut store, &p)?, admitted);
    let supported = change(&mut store, &p, &admitted, assess)?;
    let mut store = reopen(store)?;
    assert_eq!(head(&mut store, &p)?, supported);
    store.verify_storage()?;
    Ok(())
}

#[test]
fn expanded_hypothesis_and_discriminator_replay_without_changing_old_alternatives() -> TestResult {
    let (mut store, p, old) = opened()?;
    let expanded = store.evolve_investigation(
        &p.principal_id,
        &p.session_id,
        request(&old, expansion()),
        TimestampNs(20),
    )?;
    let mut store = reopen(store)?;
    let restored = head(&mut store, &p)?;
    assert_eq!(restored, expanded);
    assert_eq!(restored.record.hypotheses[..2], old.record.hypotheses[..]);
    assert_eq!(
        restored.control.hypotheses().get("hypothesis:c"),
        Some(&HypothesisDisposition::Live)
    );
    assert_eq!(restored.record.discriminators.len(), 1);
    assert_eq!(
        restored.record.decision_deadline_ns,
        old.record.decision_deadline_ns
    );
    Ok(())
}

#[test]
fn every_append_phase_fences_evolution_and_cases_until_hot_reconciliation() -> TestResult {
    for (phase, committed) in [
        (AppendPhase::BodyWrite, false),
        (AppendPhase::BodySync, false),
        (AppendPhase::CommitWrite, true),
        (AppendPhase::CommitSync, true),
    ] {
        let (mut store, p, old) = opened()?;
        let intent = rebase_request(&mut store, &p, &old)?;
        let before = store.committed_root();
        store.journal.fail_after_phase(phase);
        assert!(
            store
                .evolve_investigation(
                    &p.principal_id,
                    &p.session_id,
                    intent.clone(),
                    TimestampNs(20)
                )
                .is_err()
        );
        assert!(store.needs_reconciliation());
        assert!(matches!(
            store.session(&p.principal_id, &p.session_id, TimestampNs(20)),
            Err(DurableSessionError::ReconciliationRequired)
        ));
        assert!(matches!(
            head(&mut store, &p),
            Err(DurableInvestigationError::Durability(
                DurableSessionError::ReconciliationRequired
            ))
        ));
        assert!(matches!(
            store.evolve_investigation(&p.principal_id, &p.session_id, intent, TimestampNs(20)),
            Err(DurableInvestigationError::Durability(
                DurableSessionError::ReconciliationRequired
            ))
        ));
        assert_eq!(
            store.reconcile_pending(IncompleteTailPolicy::Truncate)?,
            if committed {
                SessionAppendRecovery::Committed
            } else {
                SessionAppendRecovery::NotCommitted
            }
        );
        assert_eq!(before != store.committed_root(), committed);
        let current = head(&mut store, &p)?;
        assert_eq!(current.validity().is_some(), committed);
        if !committed {
            assert_eq!(current, old);
        }
        store.verify_storage()?;
    }
    Ok(())
}

#[test]
fn cold_recovery_keeps_committed_rebase_and_never_trims_it_to_an_older_root() -> TestResult {
    for (phase, committed) in [
        (AppendPhase::BodyWrite, false),
        (AppendPhase::BodySync, false),
        (AppendPhase::CommitWrite, true),
        (AppendPhase::CommitSync, true),
    ] {
        let (mut store, p, old) = opened()?;
        let intent = rebase_request(&mut store, &p, &old)?;
        let previous = store.committed_root();
        let path = store.path().to_path_buf();
        store.journal.fail_after_phase(phase);
        assert!(
            store
                .evolve_investigation(&p.principal_id, &p.session_id, intent, TimestampNs(20))
                .is_err()
        );
        drop(store);
        // The test owns these bytes and the injected fault schedule. A production caller cannot
        // adopt an untrusted inspection root as authorization for recovery.
        let inspection = DurableSessionStore::inspect_with_coordination(
            &path,
            DurableSessionLimits::default(),
            WorkClaimLimits::default(),
        )?;
        assert_eq!(inspection.root != previous, committed);
        if committed {
            let before = std::fs::read(&path)?;
            assert!(matches!(
                DurableSessionStore::recover_existing_with_coordination(
                    &path,
                    previous,
                    DurableSessionLimits::default(),
                    WorkClaimLimits::default(),
                    IncompleteTailPolicy::Truncate
                ),
                Err(DurableSessionError::RootMismatch)
            ));
            assert_eq!(std::fs::read(&path)?, before);
        }
        let (mut recovered, _) = DurableSessionStore::recover_existing_with_coordination(
            &path,
            inspection.root,
            DurableSessionLimits::default(),
            WorkClaimLimits::default(),
            IncompleteTailPolicy::Truncate,
        )?;
        let current = head(&mut recovered, &p)?;
        assert_eq!(current.validity().is_some(), committed);
        if !committed {
            assert_eq!(current, old);
        }
        recovered.verify_storage()?;
    }
    Ok(())
}

#[test]
fn semantic_forgery_before_a_torn_tail_is_refused_without_truncating_any_bytes() -> TestResult {
    let (mut store, p, old) = opened()?;
    let intent = rebase_request(&mut store, &p, &old)?;
    let checkpoint = store.checkpoint_digest;
    let bytes = encode_request(&p.principal_id, &p.session_id, &intent, TimestampNs(20))?;
    let forged = encode_record(
        &bytes,
        checkpoint,
        checkpoint,
        root("fabricated success digest"),
    )?;
    let path = store.path().to_path_buf();
    drop(store);
    let mut journal = Journal::open(&path, IncompleteTailPolicy::Reject)?;
    journal.append(COORDINATION_COMMAND_RECORD_KIND, &forged)?;
    let forged_root = journal.last_root();
    drop(journal);
    let mut file = OpenOptions::new().append(true).open(&path)?;
    file.write_all(b"FSSJ")?;
    file.sync_all()?;
    drop(file);
    let before = std::fs::read(&path)?;
    assert!(matches!(
        DurableSessionStore::recover_existing_with_coordination(
            &path,
            forged_root,
            DurableSessionLimits::default(),
            WorkClaimLimits::default(),
            IncompleteTailPolicy::Truncate
        ),
        Err(DurableSessionError::InvalidHistory)
    ));
    assert_eq!(std::fs::read(&path)?, before);
    Ok(())
}

#[test]
fn refusal_side_clock_advancement_survives_replay() -> TestResult {
    let (mut store, p, old) = opened()?;
    let mut intent = request(&old, expansion());
    intent.expected = root("stale revision");
    let before = store.committed_root();
    assert!(matches!(
        store.evolve_investigation(&p.principal_id, &p.session_id, intent, TimestampNs(30)),
        Err(DurableInvestigationError::Refused(
            InvestigationError::StaleRevision
        ))
    ));
    assert_ne!(store.committed_root(), before);
    let mut store = reopen(store)?;
    assert!(matches!(
        store.evolve_investigation(
            &p.principal_id,
            &p.session_id,
            request(&old, expansion()),
            TimestampNs(20)
        ),
        Err(DurableInvestigationError::Refused(
            InvestigationError::ClockRegression
        ))
    ));
    Ok(())
}

#[test]
fn capacity_failure_cannot_publish_or_forget_an_evolution() -> TestResult {
    let (mut store, p, old) = opened()?;
    store.limits.max_records = store.records;
    let before = std::fs::read(store.path())?;
    assert!(matches!(
        store.evolve_investigation(
            &p.principal_id,
            &p.session_id,
            request(&old, expansion()),
            TimestampNs(20)
        ),
        Err(DurableInvestigationError::Durability(
            DurableSessionError::CapacityExceeded
        ))
    ));
    assert!(store.needs_reconciliation());
    assert_eq!(std::fs::read(store.path())?, before);
    Ok(())
}

#[test]
fn all_evolution_request_variants_round_trip_and_every_truncated_prefix_is_refused() -> TestResult {
    let (mut store, p, old) = opened()?;
    let rebase = rebase_request(&mut store, &p, &old)?;
    let readmit = request(
        &old,
        InvestigationEvolution::ReadmitCitation {
            citation: InvestigationCitation {
                hypothesis: "hypothesis:a".to_owned(),
                evidence: root("old"),
                contradicts: true,
            },
            witness: root("receipt"),
        },
    );
    for input in [rebase, readmit, request(&old, expansion())] {
        let bytes = encode_request(&p.principal_id, &p.session_id, &input, TimestampNs(20))?;
        let decoded = decode_request(&bytes)?;
        assert_eq!(
            decoded,
            (
                p.principal_id.clone(),
                p.session_id.clone(),
                input,
                TimestampNs(20)
            )
        );
        for end in 0..bytes.len() {
            assert!(decode_request(&bytes[..end]).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_request(&trailing).is_err());
    }
    Ok(())
}

#[test]
fn malformed_tags_and_oversized_nested_counts_fail_before_allocation() -> TestResult {
    let (_, p, old) = opened()?;
    let bytes = encode_request(
        &p.principal_id,
        &p.session_id,
        &request(&old, expansion()),
        TimestampNs(20),
    )?;
    let mut d = CanonicalDecoder::new(&bytes);
    d.text()?;
    d.text()?;
    d.text()?;
    d.i128()?;
    d.text()?;
    d.digest()?;
    let tag = d.offset();
    d.tag()?;
    d.text()?;
    d.text()?;
    let count = d.offset();
    let mut wrong = bytes.clone();
    wrong[tag] = 255;
    assert!(decode_request(&wrong).is_err());
    let mut excess = bytes;
    excess[count..count + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        decode_request(&excess),
        Err(DurableSessionError::CapacityExceeded)
    ));
    Ok(())
}

#[test]
fn never_rebased_revisions_keep_the_exact_original_canonical_layout() -> TestResult {
    let (_, _, r) = opened()?;
    let mut e = CanonicalEncoder::new();
    r.record.encode_canonical(&mut e);
    r.control.encode_canonical(&mut e);
    r.principal.encode_canonical(&mut e);
    r.author_session.encode_canonical(&mut e);
    e.text(&r.privacy_class);
    e.bool(r.predecessor.is_some());
    if let Some(root) = r.predecessor {
        e.digest(root);
    }
    e.i128(r.changed_at.0);
    e.bool(r.assessment.is_some());
    if let Some(root) = r.assessment {
        e.digest(root);
    }
    assert_eq!(r.try_canonical_bytes()?, e.finish_checked()?);
    assert_eq!(
        r.digest(),
        r.canonical_digest(INVESTIGATION_REVISION_DOMAIN)
    );
    Ok(())
}
