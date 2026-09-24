#![forbid(unsafe_code)]
//! Actual native Journal persistence and crash cut points, not a replacement storage model.
use super::*;
use fss_ledger::AppendPhase;
use fss_publication::NeverCancel;
use std::sync::atomic::{AtomicU64, Ordering};
type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
fn path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "fss-pin-journal-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}
fn scope() -> ArchivePinScope {
    ArchivePinScope {
        journal_id: ContentDigest::sha256(b"independent journal epoch"),
        archive_namespace: ContentDigest::sha256(b"exact namespace"),
    }
}
fn pin(i: u8) -> Test<StoredArchivePin> {
    let retirement = ContentDigest::sha256(&[i, 1]);
    let text = retirement.to_text();
    Ok(StoredArchivePin {
        slot: SlotName::parse(&format!(
            "fssaw1-{}-r",
            text.strip_prefix("sha256:").ok_or("digest")?
        ))?,
        root: ContentDigest::sha256(&[i, 2]),
        retirement,
        new_payload_bytes: 600,
    })
}
fn create(path: &Path) -> Test<ArchivePinJournal> {
    Ok(ArchivePinJournal::create(
        path,
        scope(),
        ArchivePinLimits::default(),
        &NeverCancel,
    )?)
}
fn open(
    path: &Path,
    minimum: Option<ArchivePinAnchor>,
    tail: IncompleteTailPolicy,
) -> PinResult<ArchivePinJournal> {
    ArchivePinJournal::open_existing(
        path,
        scope(),
        minimum,
        ArchivePinLimits::default(),
        tail,
        &NeverCancel,
    )
}
struct Cancel;
impl PublishCancellation for Cancel {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        true
    }
}

#[test]
fn cold_open_preserves_candidate_and_prior_confirmation_with_no_old_objects() -> Test {
    let path = path();
    let (anchor, old, next) = {
        let mut j = create(&path)?;
        let old = pin(1)?;
        let next = pin(2)?;
        j.persist(old.clone(), ArchivePinPhase::Candidate, &NeverCancel)?;
        j.persist(old.clone(), ArchivePinPhase::Confirmed, &NeverCancel)?;
        let anchor = j.anchor();
        j.persist(next.clone(), ArchivePinPhase::Candidate, &NeverCancel)?;
        (anchor, old, next)
    };
    let mut j = open(&path, Some(anchor), IncompleteTailPolicy::Reject)?;
    assert_eq!(j.state().candidate(), Some(&next));
    assert_eq!(j.state().last_confirmed(), Some(&old));
    assert_eq!(j.anchor().sequence, 4);
    j.verify(&NeverCancel)?;
    Ok(())
}
#[test]
fn exact_retries_do_not_append_and_reused_older_checkpoints_are_refused() -> Test {
    let path = path();
    let mut j = create(&path)?;
    let first = pin(1)?;
    let second = pin(2)?;
    let staged = j.persist(first.clone(), ArchivePinPhase::Candidate, &NeverCancel)?;
    assert_eq!(
        j.persist(first.clone(), ArchivePinPhase::Candidate, &NeverCancel)?,
        staged
    );
    let confirmed = j.persist(first.clone(), ArchivePinPhase::Confirmed, &NeverCancel)?;
    assert_eq!(
        j.persist(first.clone(), ArchivePinPhase::Confirmed, &NeverCancel)?,
        confirmed
    );
    j.persist(second.clone(), ArchivePinPhase::Candidate, &NeverCancel)?;
    j.persist(second.clone(), ArchivePinPhase::Confirmed, &NeverCancel)?;
    let anchor = j.anchor();
    assert!(matches!(
        j.persist(first, ArchivePinPhase::Candidate, &NeverCancel),
        Err(ArchivePinError::History)
    ));
    assert_eq!(j.anchor(), anchor);
    assert_eq!(j.state().last_confirmed(), Some(&second));
    Ok(())
}
#[test]
fn competing_candidates_and_wrong_confirmation_cannot_erase_pending_work() -> Test {
    let path = path();
    let mut j = create(&path)?;
    let first = pin(1)?;
    j.persist(first.clone(), ArchivePinPhase::Candidate, &NeverCancel)?;
    let anchor = j.anchor();
    assert!(
        j.persist(pin(2)?, ArchivePinPhase::Candidate, &NeverCancel)
            .is_err()
    );
    assert!(
        j.persist(pin(2)?, ArchivePinPhase::Confirmed, &NeverCancel)
            .is_err()
    );
    assert_eq!(j.anchor(), anchor);
    assert_eq!(j.state().candidate(), Some(&first));
    Ok(())
}
#[test]
fn both_transition_kinds_preserve_exact_state_at_all_four_real_append_cuts() -> Test {
    for confirm in [false, true] {
        for phase in [
            AppendPhase::BodyWrite,
            AppendPhase::BodySync,
            AppendPhase::CommitWrite,
            AppendPhase::CommitSync,
        ] {
            let path = path();
            let value = pin(1)?;
            let prior = {
                let mut j = create(&path)?;
                if confirm {
                    j.persist(value.clone(), ArchivePinPhase::Candidate, &NeverCancel)?;
                }
                let prior = j.anchor();
                j.journal.fail_after_phase(phase);
                let action = if confirm {
                    ArchivePinPhase::Confirmed
                } else {
                    ArchivePinPhase::Candidate
                };
                assert!(j.persist(value.clone(), action, &NeverCancel).is_err());
                assert!(j.is_fenced());
                assert!(matches!(
                    j.persist(value.clone(), action, &NeverCancel),
                    Err(ArchivePinError::Fenced)
                ));
                assert_eq!(j.anchor(), prior);
                prior
            };
            let committed = matches!(phase, AppendPhase::CommitWrite | AppendPhase::CommitSync);
            let before = fs::read(path.join(JOURNAL_FILE))?;
            if !committed {
                assert!(open(&path, Some(prior), IncompleteTailPolicy::Reject).is_err());
                assert_eq!(fs::read(path.join(JOURNAL_FILE))?, before);
            }
            // Truncation is deliberately requested only after the preceding no-mutation assertion.
            let j = open(&path, Some(prior), IncompleteTailPolicy::Truncate)?;
            assert_eq!(j.anchor().sequence, prior.sequence + u64::from(committed));
            if confirm && committed {
                assert_eq!(j.state().last_confirmed(), Some(&value));
                assert!(j.state().candidate().is_none());
            } else if confirm || committed {
                assert_eq!(j.state().candidate(), Some(&value));
                assert!(j.state().last_confirmed().is_none());
            } else {
                assert_eq!(j.state(), &ArchivePinState::default());
            }
        }
    }
    Ok(())
}
#[test]
fn stale_or_forged_minimum_prefix_refuses_before_explicit_tail_repair() -> Test {
    let path = path();
    let anchor = {
        let mut j = create(&path)?;
        j.persist(pin(1)?, ArchivePinPhase::Candidate, &NeverCancel)?;
        let anchor = j.anchor();
        j.journal.fail_after_phase(AppendPhase::BodySync);
        assert!(
            j.persist(pin(1)?, ArchivePinPhase::Confirmed, &NeverCancel)
                .is_err()
        );
        anchor
    };
    let original = fs::read(path.join(JOURNAL_FILE))?;
    for bad in [
        ArchivePinAnchor {
            sequence: anchor.sequence + 1,
            ..anchor
        },
        ArchivePinAnchor {
            root: ContentDigest::sha256(b"different prefix"),
            ..anchor
        },
    ] {
        assert!(matches!(
            open(&path, Some(bad), IncompleteTailPolicy::Truncate),
            Err(ArchivePinError::RootMismatch)
        ));
        assert_eq!(fs::read(path.join(JOURNAL_FILE))?, original);
    }
    Ok(())
}
#[test]
fn actual_sidecar_lock_excludes_a_second_owner_and_releases_on_drop() -> Test {
    let path = path();
    let j = create(&path)?;
    assert!(matches!(
        open(&path, None, IncompleteTailPolicy::Reject),
        Err(ArchivePinError::Busy)
    ));
    let anchor = j.anchor();
    drop(j);
    let reopened = open(&path, Some(anchor), IncompleteTailPolicy::Reject)?;
    assert_eq!(reopened.anchor(), anchor);
    Ok(())
}
#[test]
fn missing_owner_empty_history_wrong_scope_and_duplicate_create_are_not_initialized() -> Test {
    let missing = path();
    assert!(open(&missing, None, IncompleteTailPolicy::Reject).is_err());
    assert!(!missing.exists());
    let path = path();
    let j = create(&path)?;
    let root = j.anchor();
    drop(j);
    assert!(create(&path).is_err());
    let wrong = ArchivePinScope {
        archive_namespace: ContentDigest::sha256(b"other camera"),
        ..scope()
    };
    assert!(matches!(
        ArchivePinJournal::open_existing(
            &path,
            wrong,
            None,
            ArchivePinLimits::default(),
            IncompleteTailPolicy::Truncate,
            &NeverCancel
        ),
        Err(ArchivePinError::Scope)
    ));
    assert_eq!(
        open(&path, Some(root), IncompleteTailPolicy::Reject)?.anchor(),
        root
    );
    fs::write(path.join(JOURNAL_FILE), [])?;
    assert!(matches!(
        open(&path, None, IncompleteTailPolicy::Reject),
        Err(ArchivePinError::History)
    ));
    Ok(())
}
#[test]
fn complete_corruption_is_never_truncated_even_under_repair_policy() -> Test {
    let path = path();
    {
        let mut j = create(&path)?;
        j.persist(pin(1)?, ArchivePinPhase::Candidate, &NeverCancel)?;
    }
    let mut bytes = fs::read(path.join(JOURNAL_FILE))?;
    bytes[90] ^= 1;
    fs::write(path.join(JOURNAL_FILE), &bytes)?;
    assert!(open(&path, None, IncompleteTailPolicy::Truncate).is_err());
    assert_eq!(fs::read(path.join(JOURNAL_FILE))?, bytes);
    Ok(())
}
#[test]
fn exact_retry_rehashes_history_and_fences_after_prior_record_corruption() -> Test {
    let path = path();
    let mut j = create(&path)?;
    j.persist(pin(1)?, ArchivePinPhase::Candidate, &NeverCancel)?;
    let mut bytes = fs::read(path.join(JOURNAL_FILE))?;
    bytes[90] ^= 1;
    fs::write(path.join(JOURNAL_FILE), bytes)?;
    assert!(
        j.persist(pin(1)?, ArchivePinPhase::Candidate, &NeverCancel)
            .is_err()
    );
    assert!(j.is_fenced());
    Ok(())
}
#[test]
fn ceilings_and_cancellation_never_discard_history_or_issue_an_ack() -> Test {
    let path = path();
    let mut j = ArchivePinJournal::create(
        &path,
        scope(),
        ArchivePinLimits {
            max_records: 2,
            ..ArchivePinLimits::default()
        },
        &NeverCancel,
    )?;
    j.persist(pin(1)?, ArchivePinPhase::Candidate, &NeverCancel)?;
    let anchor = j.anchor();
    assert!(matches!(
        j.persist(pin(1)?, ArchivePinPhase::Confirmed, &NeverCancel),
        Err(ArchivePinError::Limit)
    ));
    assert_eq!(j.anchor(), anchor);
    assert!(matches!(
        j.persist(pin(1)?, ArchivePinPhase::Candidate, &Cancel),
        Err(ArchivePinError::Cancelled)
    ));
    drop(j);
    let bytes = fs::metadata(path.join(JOURNAL_FILE))?.len() as usize;
    for bounds in [
        ArchivePinLimits {
            max_records: 1,
            ..ArchivePinLimits::default()
        },
        ArchivePinLimits {
            max_bytes: bytes - 1,
            ..ArchivePinLimits::default()
        },
    ] {
        assert!(
            ArchivePinJournal::open_existing(
                &path,
                scope(),
                None,
                bounds,
                IncompleteTailPolicy::Reject,
                &NeverCancel
            )
            .is_err()
        );
    }
    assert_eq!(
        open(&path, Some(anchor), IncompleteTailPolicy::Reject)?.anchor(),
        anchor
    );
    Ok(())
}
#[test]
fn valid_frame_checksums_do_not_authorize_invalid_application_history() -> Test {
    for bad in [0, 1, 2, 3] {
        let path = path();
        {
            let j = create(&path)?;
            drop(j);
        }
        let mut raw = Journal::open(path.join(JOURNAL_FILE), IncompleteTailPolicy::Reject)?;
        let value = pin(1)?;
        match bad {
            0 => {
                raw.append(RECORD_KIND, &codec::encode(scope(), 0, None)?)?;
            }
            1 => {
                raw.append(RECORD_KIND, &codec::encode(scope(), 2, Some(&value))?)?;
            }
            2 => {
                raw.append(0xFFFF, &codec::encode(scope(), 1, Some(&value))?)?;
            }
            _ => {
                let payload = codec::encode(scope(), 1, Some(&value))?;
                raw.append(RECORD_KIND, &payload)?;
                raw.append(RECORD_KIND, &payload)?;
            }
        }
        drop(raw);
        assert!(matches!(
            open(&path, None, IncompleteTailPolicy::Reject),
            Err(ArchivePinError::History)
        ));
    }
    Ok(())
}
#[test]
fn canonical_pin_slot_and_quote_are_checked_before_mutation() -> Test {
    let mut state = ReplayState::default();
    for bad in [
        StoredArchivePin {
            slot: SlotName::parse("arbitrary")?,
            ..pin(1)?
        },
        StoredArchivePin {
            new_payload_bytes: 0,
            ..pin(1)?
        },
        StoredArchivePin {
            root: ContentDigest::new(DigestAlgorithm::Blake3, [1; 32]),
            ..pin(1)?
        },
    ] {
        assert!(codec::apply(&mut state, 1, bad).is_err());
        assert_eq!(state.pins, ArchivePinState::default());
        assert!(state.seen.is_empty());
    }
    Ok(())
}
#[cfg(unix)]
#[test]
fn symlinked_directory_or_journal_never_becomes_a_writable_owner() -> Test {
    use std::os::unix::fs::symlink;
    let original = path();
    {
        let _journal = create(&original)?;
    }
    let link = path();
    symlink(&original, &link)?;
    assert!(matches!(
        open(&link, None, IncompleteTailPolicy::Reject),
        Err(ArchivePinError::Layout)
    ));
    let saved = path();
    fs::rename(original.join(JOURNAL_FILE), &saved)?;
    symlink(&saved, original.join(JOURNAL_FILE))?;
    assert!(matches!(
        open(&original, None, IncompleteTailPolicy::Reject),
        Err(ArchivePinError::Layout)
    ));
    Ok(())
}
