#![forbid(unsafe_code)]
use super::super::super::CoordinationCommand;
use super::super::tests::{basis, opening, params};
use super::*;
use crate::agent_session::checkpoint::journal::SessionAppendRecovery;
use crate::agent_session::work_claims::{CAPABILITY_WORK_CLAIM, WorkClaimLimits, WorkClaimRequest};
use fss_ledger::{AppendPhase, IncompleteTailPolicy, Journal, recover_bytes};
use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

type TestResult = Result<(), Box<dyn Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);

fn unused_path() -> Result<PathBuf, Box<dyn Error>> {
    for _ in 0..128 {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fss-investigation-{}-{n}.journal",
            std::process::id()
        ));
        if !path.exists() {
            return Ok(path);
        }
    }
    Err("test journal path capacity exhausted".into())
}
fn store() -> Result<DurableSessionStore, Box<dyn Error>> {
    let mut s = DurableSessionStore::create(unused_path()?, DurableSessionLimits::default())?;
    s.enable_coordination(WorkClaimLimits::default())?;
    s.enable_investigations(InvestigationLimits::default())?;
    let mut p = params("session:a")?;
    p.capabilities.insert(CAPABILITY_WORK_CLAIM.to_owned());
    s.open(p, basis(), TimestampNs(1))?;
    Ok(s)
}
fn run(
    s: &mut DurableSessionStore,
    c: InvestigationCommand,
    now: i128,
) -> Result<InvestigationRevision, DurableInvestigationError> {
    let p = params("session:a").map_err(|_| DurableSessionError::InvalidHistory)?;
    s.investigate(&p.principal_id, &p.session_id, c, TimestampNs(now))
}
fn inspect() -> InvestigationCommand {
    InvestigationCommand::Inspect {
        case_id: "case:window".to_owned(),
        revision: None,
    }
}
fn change(r: &InvestigationRevision, change: InvestigationChange) -> InvestigationCommand {
    InvestigationCommand::Change {
        case_id: r.record().investigation_id.clone(),
        expected: r.digest(),
        change,
    }
}
fn reopen(s: DurableSessionStore) -> Result<DurableSessionStore, Box<dyn Error>> {
    let root = s.committed_root();
    let path = s.path().to_path_buf();
    drop(s);
    Ok(DurableSessionStore::open_existing_with_coordination(
        path,
        root,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )?)
}

#[test]
fn case_revisions_and_work_claims_survive_interleaved_session_checkpoints() -> TestResult {
    let mut s = store()?;
    let first = run(&mut s, opening()?, 10)?;
    let active = run(&mut s, change(&first, InvestigationChange::Activate), 10)?;
    let p = params("session:a")?;
    s.rotate_symbols(&p.principal_id, &p.session_id, 0, TimestampNs(10))?;
    let claim = s.coordinate(
        &p.principal_id,
        &p.session_id,
        CoordinationCommand::Acquire(WorkClaimRequest {
            claim_id: "claim:crop".to_owned(),
            case_id: CaseId::parse("case:window")?,
            work_root: ContentDigest::sha256(b"crop work"),
            privacy_class: "private:property".to_owned(),
            expires_at: TimestampNs(90),
            dependencies: BTreeSet::new(),
        }),
        TimestampNs(10),
    )?;
    let mut s = reopen(s)?;
    assert_eq!(run(&mut s, inspect(), 10)?, active);
    assert_eq!(run(&mut s, opening()?, 10)?, active);
    assert_eq!(
        s.coordinate(
            &p.principal_id,
            &p.session_id,
            CoordinationCommand::Inspect {
                claim_id: "claim:crop".to_owned()
            },
            TimestampNs(10)
        )?,
        claim
    );
    let old = InvestigationCommand::Inspect {
        case_id: "case:window".to_owned(),
        revision: Some(first.digest()),
    };
    assert_eq!(run(&mut s, old, 10)?, first);
    assert!(matches!(
        run(&mut s, change(&first, InvestigationChange::Activate), 10),
        Err(DurableInvestigationError::Refused(
            InvestigationError::StaleRevision
        ))
    ));
    s.verify_storage()?;
    Ok(())
}

#[test]
fn refused_expiry_is_durable_and_cannot_reopen_the_session() -> TestResult {
    let mut s = store()?;
    run(&mut s, opening()?, 10)?;
    let before = s.committed_root();
    assert!(matches!(
        run(&mut s, inspect(), 1_000),
        Err(DurableInvestigationError::Refused(
            InvestigationError::Unavailable
        ))
    ));
    assert_ne!(s.committed_root(), before);
    let mut s = reopen(s)?;
    let p = params("session:a")?;
    assert!(matches!(
        s.session(&p.principal_id, &p.session_id, TimestampNs(10)),
        Err(DurableSessionError::Session(
            ReferenceSessionError::Unavailable
        ))
    ));
    Ok(())
}

#[test]
fn close_and_new_session_continue_history_without_replacing_the_case() -> TestResult {
    let mut s = store()?;
    let r = run(&mut s, opening()?, 10)?;
    let p = params("session:a")?;
    s.close(&p.principal_id, &p.session_id, TimestampNs(10))?;
    let mut s = reopen(s)?;
    let p = params("session:b")?;
    s.open(p.clone(), basis(), TimestampNs(10))?;
    let next = s.investigate(
        &p.principal_id,
        &p.session_id,
        change(&r, InvestigationChange::Activate),
        TimestampNs(10),
    )?;
    assert_eq!(next.author_session(), &p.session_id);
    assert_eq!(next.predecessor(), Some(r.digest()));
    let mut s = reopen(s)?;
    assert_eq!(
        s.investigate(&p.principal_id, &p.session_id, inspect(), TimestampNs(10))?,
        next
    );
    Ok(())
}

#[test]
fn all_append_cut_points_fence_sessions_claims_and_cases_until_reconciled() -> TestResult {
    for (phase, committed) in [
        (AppendPhase::BodyWrite, false),
        (AppendPhase::BodySync, false),
        (AppendPhase::CommitWrite, true),
        (AppendPhase::CommitSync, true),
    ] {
        let mut s = store()?;
        let r = run(&mut s, opening()?, 10)?;
        s.journal.fail_after_phase(phase);
        assert!(matches!(
            run(&mut s, change(&r, InvestigationChange::Activate), 10),
            Err(DurableInvestigationError::Durability(
                DurableSessionError::Journal(_)
            ))
        ));
        assert!(s.needs_reconciliation());
        assert!(matches!(
            run(&mut s, inspect(), 10),
            Err(DurableInvestigationError::Durability(
                DurableSessionError::ReconciliationRequired
            ))
        ));
        let p = params("session:a")?;
        assert!(matches!(
            s.session(&p.principal_id, &p.session_id, TimestampNs(10)),
            Err(DurableSessionError::ReconciliationRequired)
        ));
        assert!(matches!(
            s.coordinate(
                &p.principal_id,
                &p.session_id,
                CoordinationCommand::Inspect {
                    claim_id: "claim:none".to_owned()
                },
                TimestampNs(10)
            ),
            Err(DurableSessionError::ReconciliationRequired)
        ));
        assert_eq!(
            s.reconcile_pending(IncompleteTailPolicy::Truncate)?,
            if committed {
                SessionAppendRecovery::Committed
            } else {
                SessionAppendRecovery::NotCommitted
            }
        );
        let actual = run(&mut s, inspect(), 10)?;
        assert_eq!(
            actual.record().state,
            if committed {
                InvestigationLifecycle::Active
            } else {
                InvestigationLifecycle::Draft
            }
        );
        assert_eq!(actual.record().revision, if committed { 2 } else { 1 });
        s.verify_storage()?;
    }
    Ok(())
}

#[test]
fn cold_recovery_never_discards_a_committed_case_change_to_match_an_old_root() -> TestResult {
    for (phase, committed) in [
        (AppendPhase::BodyWrite, false),
        (AppendPhase::BodySync, false),
        (AppendPhase::CommitWrite, true),
        (AppendPhase::CommitSync, true),
    ] {
        let mut s = store()?;
        let r = run(&mut s, opening()?, 10)?;
        let old = s.committed_root();
        s.journal.fail_after_phase(phase);
        assert!(run(&mut s, change(&r, InvestigationChange::Activate), 10).is_err());
        let path = s.path().to_path_buf();
        let inspected = DurableSessionStore::inspect_with_coordination(
            &path,
            DurableSessionLimits::default(),
            WorkClaimLimits::default(),
        )?;
        // The deterministic test owner knows which attempted command these bytes represent.
        // Production must obtain this exact root through independent trusted custody.
        assert_eq!(inspected.root != old, committed);
        drop(s);
        let before = std::fs::read(&path)?;
        if committed {
            assert!(
                DurableSessionStore::recover_existing_with_coordination(
                    &path,
                    old,
                    DurableSessionLimits::default(),
                    WorkClaimLimits::default(),
                    IncompleteTailPolicy::Truncate
                )
                .is_err()
            );
            assert_eq!(std::fs::read(&path)?, before);
        }
        let (mut s, _) = DurableSessionStore::recover_existing_with_coordination(
            &path,
            inspected.root,
            DurableSessionLimits::default(),
            WorkClaimLimits::default(),
            IncompleteTailPolicy::Truncate,
        )?;
        assert_eq!(
            run(&mut s, inspect(), 10)?.record().state,
            if committed {
                InvestigationLifecycle::Active
            } else {
                InvestigationLifecycle::Draft
            }
        );
    }
    Ok(())
}

#[test]
fn consistently_rehashed_false_outcomes_fail_before_any_tail_is_trimmed() -> TestResult {
    let mut s = store()?;
    run(&mut s, opening()?, 10)?;
    let source = std::fs::read(s.path())?;
    let report = recover_bytes(&source)?;
    let path = unused_path()?;
    let mut journal = Journal::open(&path, IncompleteTailPolicy::Reject)?;
    for (index, record) in report.records().iter().enumerate() {
        let mut payload = record.payload().to_vec();
        if index + 1 == report.records().len() {
            let last = payload.last_mut().ok_or("empty record")?;
            *last ^= 1;
        }
        journal.append(record.kind(), &payload)?;
    }
    let root = journal.last_root();
    drop(journal);
    let mut file = OpenOptions::new().append(true).open(&path)?;
    file.write_all(&source[..4])?;
    file.sync_all()?;
    drop(file);
    let before = std::fs::read(&path)?;
    assert!(
        DurableSessionStore::recover_existing_with_coordination(
            &path,
            root,
            DurableSessionLimits::default(),
            WorkClaimLimits::default(),
            IncompleteTailPolicy::Truncate
        )
        .is_err()
    );
    assert_eq!(std::fs::read(&path)?, before);
    Ok(())
}

#[test]
fn exact_initialization_retry_is_harmless_but_replayed_reset_is_rejected() -> TestResult {
    let s = store()?;
    let mut s = reopen(s)?;
    let before = s.committed_root();
    s.enable_investigations(InvestigationLimits::default())?;
    assert_eq!(s.committed_root(), before);
    assert!(
        s.enable_investigations(InvestigationLimits {
            max_cases: 1,
            ..InvestigationLimits::default()
        })
        .is_err()
    );
    let records = recover_bytes(&std::fs::read(s.path())?)?;
    let init = records
        .records()
        .iter()
        .find(|record| {
            let mut d = CanonicalDecoder::new(record.payload());
            d.text().ok() == Some(INIT)
        })
        .ok_or("missing initialization")?;
    let path = s.path().to_path_buf();
    drop(s);
    let mut journal = Journal::open(&path, IncompleteTailPolicy::Reject)?;
    journal.append(COORDINATION_COMMAND_RECORD_KIND, init.payload())?;
    let root = journal.last_root();
    drop(journal);
    assert!(
        DurableSessionStore::open_existing_with_coordination(
            &path,
            root,
            DurableSessionLimits::default(),
            WorkClaimLimits::default()
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn capacity_failure_does_not_acknowledge_or_persist_an_uncommitted_case() -> TestResult {
    let mut s = store()?;
    let r = run(&mut s, opening()?, 10)?;
    s.limits.max_records = s.records;
    let before = std::fs::read(s.path())?;
    assert!(matches!(
        run(&mut s, change(&r, InvestigationChange::Activate), 10),
        Err(DurableInvestigationError::Durability(
            DurableSessionError::CapacityExceeded
        ))
    ));
    assert!(s.needs_reconciliation());
    assert_eq!(std::fs::read(s.path())?, before);
    let mut s = reopen(s)?;
    assert_eq!(run(&mut s, inspect(), 10)?, r);
    Ok(())
}

#[test]
fn private_request_codec_rejects_every_truncated_prefix_and_trailing_bytes() -> TestResult {
    let p = params("session:a")?;
    let request = codec::Request {
        principal: p.principal_id,
        session: p.session_id,
        command: opening()?,
        now: TimestampNs(10),
    };
    let bytes = codec::encode(&request)?;
    assert_eq!(codec::decode(&bytes)?.command, request.command);
    for cut in 0..bytes.len() {
        assert!(codec::decode(&bytes[..cut]).is_err(), "cut={cut}");
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(codec::decode(&trailing).is_err());
    Ok(())
}

#[test]
fn all_change_payloads_and_explicit_refusal_tags_round_trip() -> TestResult {
    let p = params("session:a")?;
    let root = ContentDigest::sha256(b"citation");
    let mut commands = vec![
        inspect(),
        InvestigationCommand::Inspect {
            case_id: "case:window".to_owned(),
            revision: Some(root),
        },
    ];
    for change in [
        InvestigationChange::Activate,
        InvestigationChange::Cite {
            hypothesis: "hypothesis:a".to_owned(),
            evidence: root,
            contradicts: true,
        },
        InvestigationChange::Assess {
            hypothesis: "hypothesis:a".to_owned(),
            evidence: root,
            disposition: HypothesisDisposition::Refuted,
        },
        InvestigationChange::SetState {
            state: InvestigationLifecycle::Indeterminate,
            reason: root,
        },
        InvestigationChange::Conclude {
            refuted: true,
            stop_rule: "stop".to_owned(),
            assessment: root,
            residual_unknowns: BTreeSet::from(["unknown:a".to_owned(), "unknown:b".to_owned()]),
        },
    ] {
        commands.push(InvestigationCommand::Change {
            case_id: "case:window".to_owned(),
            expected: root,
            change,
        });
    }
    for command in commands {
        let request = codec::Request {
            principal: p.principal_id.clone(),
            session: p.session_id.clone(),
            command,
            now: TimestampNs(10),
        };
        let bytes = codec::encode(&request)?;
        assert_eq!(codec::decode(&bytes)?.command, request.command);
    }
    use InvestigationError as E;
    let identities: BTreeSet<_> = [
        E::Unavailable,
        E::Denied,
        E::InvalidRecord,
        E::Conflict,
        E::StaleRevision,
        E::StaleBasis,
        E::DeadlineElapsed,
        E::InvalidTransition,
        E::UnresolvedAlternatives,
        E::EvidenceRequired,
        E::ResidualsRequired,
        E::CapacityExceeded,
        E::CounterExhausted,
        E::ClockRegression,
    ]
    .into_iter()
    .map(|error| outcome(&Err(error)))
    .collect();
    assert_eq!(identities.len(), 14);
    Ok(())
}

#[test]
fn every_knowledge_lifecycle_and_disposition_variant_retains_its_identity() -> TestResult {
    use InvestigationLifecycle as L;
    use fss_core::KnowledgeState as K;
    let p = params("session:a")?;
    for state in [
        L::Draft,
        L::Active,
        L::AwaitingEvidence,
        L::AwaitingApproval,
        L::Blocked,
        L::Resolved,
        L::Refuted,
        L::Cancelled,
        L::Indeterminate,
        L::Closed,
    ] {
        for knowledge in [
            K::Known,
            K::Estimated,
            K::Unknown,
            K::Conflicted,
            K::Stale,
            K::NotObservable,
            K::Redacted,
            K::Indeterminate,
            K::NotApplicable,
        ] {
            let mut command = opening()?;
            if let InvestigationCommand::Open { record, .. } = &mut command {
                record.state = state;
                record.hypotheses[0].epistemic_state = knowledge;
                record.unknowns[0].epistemic_state = knowledge;
            }
            let request = codec::Request {
                principal: p.principal_id.clone(),
                session: p.session_id.clone(),
                command,
                now: TimestampNs(10),
            };
            assert_eq!(
                codec::decode(&codec::encode(&request)?)?.command,
                request.command
            );
        }
    }
    use HypothesisDisposition as D;
    for disposition in [
        D::Live,
        D::Supported,
        D::Disfavored,
        D::Refuted,
        D::Resolved,
        D::Superseded,
    ] {
        let request = codec::Request {
            principal: p.principal_id.clone(),
            session: p.session_id.clone(),
            command: InvestigationCommand::Change {
                case_id: "case:window".to_owned(),
                expected: ContentDigest::sha256(b"revision"),
                change: InvestigationChange::Assess {
                    hypothesis: "hypothesis:a".to_owned(),
                    disposition,
                    evidence: ContentDigest::sha256(b"citation"),
                },
            },
            now: TimestampNs(10),
        };
        assert_eq!(
            codec::decode(&codec::encode(&request)?)?.command,
            request.command
        );
    }
    Ok(())
}

#[test]
fn decoder_rejects_unknown_tags_noncanonical_residuals_and_oversized_counts() -> TestResult {
    let p = params("session:a")?;
    let request = codec::Request {
        principal: p.principal_id,
        session: p.session_id,
        command: InvestigationCommand::Change {
            case_id: "case:window".to_owned(),
            expected: ContentDigest::sha256(b"revision"),
            change: InvestigationChange::Conclude {
                refuted: true,
                stop_rule: "stop".to_owned(),
                assessment: ContentDigest::sha256(b"assessment"),
                residual_unknowns: BTreeSet::from(["unknown:a".to_owned(), "unknown:b".to_owned()]),
            },
        },
        now: TimestampNs(10),
    };
    let bytes = codec::encode(&request)?;
    let mut d = CanonicalDecoder::new(&bytes);
    for _ in 0..3 {
        d.text()?;
    }
    d.i128()?;
    let command_tag = d.offset();
    d.tag()?;
    d.text()?;
    d.digest()?;
    let change_tag = d.offset();
    d.tag()?;
    let boolean_tag = d.offset();
    d.bool()?;
    d.text()?;
    d.digest()?;
    let count = d.offset();
    for index in [command_tag, change_tag, boolean_tag] {
        let mut bad = bytes.clone();
        bad[index] = 255;
        assert!(codec::decode(&bad).is_err());
    }
    let mut oversized = bytes.clone();
    oversized[count..count + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        codec::decode(&oversized),
        Err(DurableSessionError::CapacityExceeded)
    ));
    let mut duplicate = bytes.clone();
    let start = duplicate
        .windows(9)
        .position(|w| w == b"unknown:b")
        .ok_or("missing residual")?;
    duplicate[start + 8] = b'a';
    assert!(codec::decode(&duplicate).is_err());
    let mut unsorted = bytes;
    let first = unsorted
        .windows(9)
        .position(|w| w == b"unknown:a")
        .ok_or("missing residual")?;
    unsorted[first + 8] = b'z';
    assert!(codec::decode(&unsorted).is_err());
    assert!(matches!(
        codec::decode(&vec![0; MAX_INVESTIGATION_BYTES + 1]),
        Err(DurableSessionError::CapacityExceeded)
    ));
    Ok(())
}
