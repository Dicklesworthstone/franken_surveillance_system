#![forbid(unsafe_code)]
//! Ingest gauntlet (fss-2h5zq.31): bounded, deterministic mutations of the checked-in H.264
//! Annex-B and MJPEG fixtures, driven through `FileIngestAdapter` and root-last publication, each
//! combined with one fault from a fixed cycle (none, cancellation at a checkpoint, a crash at a
//! `PublishCutPoint`, the ledger `AfterRootDurable` crash, an indeterminate first append).
//!
//! Invariant per case (fss-2h5zq.31 round 3), stated before running; every case ends in exactly
//! one of:
//! - `Ok`, with every capsule's custody span reassembling to its exact source bytes, every
//!   planned batch committed exactly once, and the import retained;
//! - a typed error with ZERO batches of the import identity and no visible import root
//!   (`Untouched`); when no fault was injected, the error is a media/limit refusal that also
//!   staged nothing;
//! - a typed error after the first capsule batch, leaving a recognizably incomplete import
//!   (generation 1, gap-free `c0..c<j>`, no manifest batch, refused by `RetainedFileImport`,
//!   listed by doctor) that a re-import completes exactly once (`resumed`), with no duplicate
//!   batch or delta;
//! - (only an indeterminate manifest append that reconciles as committed) a complete import that a
//!   re-import reports `idempotent_existing`.
//!
//! No panic is admitted anywhere (a panic fails the test). Sparse oversize files are refused by
//! the stat check before any read. The same bytes under two names have one identity.
//!
//! No-Claim: evidence against these mutation classes and fault points over this corpus only; not
//! coverage-guided fuzzing, not a proof, and in-process injection is not process death.

mod file_import_fault_support;

use std::collections::BTreeMap;
use std::fs;

use file_import_fault_support::{
    Error, Outcome, TestResult, assert_clean_after_reopen, assert_complete_once, classify, cx,
    doctor_incomplete, expected_reimport, fixture, fresh_dir, identity_hex, open, request,
    standard,
};
use fss_ledger::DurableAppendReconciliation;
use fss_publication::{LedgerCutPoint, PublishCutPoint};
use fss_reference::ingest::file_adapter::{
    STAGE_COMMIT_CAPSULES, STAGE_COMMIT_MANIFEST, STAGE_PUBLISH_ROOT, STAGE_READ, STAGE_SPLIT,
    STAGE_STAGE,
};
use fss_reference::{
    AppendPhase, FileIngestAdapter, FileIngestError, FileIngestOutcome, IncompleteTailPolicy,
};

const CHUNK: u64 = 512;
const KNOB: usize = 2;
const MIN_CASES: usize = 500;

const SEEDS: [&str; 4] = [
    "h264/clean.264",
    "mjpeg/mjpeg_clean_3frames.mjpeg",
    "mjpeg/mjpeg_garbage_between_frames.mjpeg",
    "mjpeg/mjpeg_truncated_last.mjpeg",
];

#[derive(Clone, Copy, Debug)]
enum Fault {
    None,
    Cancel(&'static str, usize),
    PublishCrash(PublishCutPoint),
    LedgerCrash,
    FirstAppendIndeterminate(AppendPhase),
}

const FAULTS: [Fault; 16] = [
    Fault::None,
    Fault::Cancel(STAGE_READ, 1),
    Fault::Cancel(STAGE_SPLIT, 1),
    Fault::Cancel(STAGE_STAGE, 1),
    Fault::Cancel(STAGE_COMMIT_CAPSULES, 1),
    Fault::Cancel(STAGE_COMMIT_CAPSULES, 2),
    Fault::Cancel(STAGE_PUBLISH_ROOT, 1),
    Fault::Cancel("after_manifest_body", 1),
    Fault::Cancel(STAGE_COMMIT_MANIFEST, 1),
    Fault::PublishCrash(PublishCutPoint::AfterChildrenVerified),
    Fault::PublishCrash(PublishCutPoint::AfterManifestBody),
    Fault::PublishCrash(PublishCutPoint::AfterRootTempWrite),
    Fault::PublishCrash(PublishCutPoint::AfterRootRename),
    Fault::LedgerCrash,
    Fault::FirstAppendIndeterminate(AppendPhase::BodyWrite),
    Fault::FirstAppendIndeterminate(AppendPhase::CommitSync),
];

/// Deterministic xorshift64* generator.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next() % bound as u64) as usize
        }
    }
}

/// One mutated input: family label and bytes.
struct Mutant {
    family: &'static str,
    bytes: Vec<u8>,
}

fn mutants(seed: &[u8], seed_index: usize) -> Vec<Mutant> {
    let mut out = vec![Mutant {
        family: "identity",
        bytes: seed.to_vec(),
    }];
    // Truncation at every 64th byte.
    let mut cut = 64;
    while cut < seed.len() {
        out.push(Mutant {
            family: "truncate64",
            bytes: seed[..cut].to_vec(),
        });
        cut += 64;
    }
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15 ^ (seed_index as u64 + 1));
    for _ in 0..15 {
        let mut flipped = seed.to_vec();
        let at = rng.below(flipped.len());
        flipped[at] ^= 1 << rng.below(8);
        out.push(Mutant {
            family: "bit_flip",
            bytes: flipped,
        });

        let mut injected = seed.to_vec();
        let at = rng.below(injected.len());
        injected.splice(at..at, [0u8, 0, 1, (rng.next() & 0xff) as u8]);
        out.push(Mutant {
            family: "start_code_injection",
            bytes: injected,
        });

        let mut zeroed = seed.to_vec();
        let at = rng.below(zeroed.len());
        let end = (at + 1 + rng.below(32)).min(zeroed.len());
        zeroed[at..end].fill(0);
        out.push(Mutant {
            family: "zero_run",
            bytes: zeroed,
        });

        let mut duplicated = seed.to_vec();
        let at = rng.below(duplicated.len());
        let end = (at + 1 + rng.below(256)).min(duplicated.len());
        let copy = duplicated[at..end].to_vec();
        duplicated.splice(end..end, copy);
        out.push(Mutant {
            family: "duplicate_range",
            bytes: duplicated,
        });

        let mut deleted = seed.to_vec();
        let at = rng.below(deleted.len());
        let end = (at + 1 + rng.below(128)).min(deleted.len());
        deleted.drain(at..end);
        out.push(Mutant {
            family: "delete_range",
            bytes: deleted,
        });

        // Length-field / dimension overflow: two 0xff bytes (a huge SOF dimension, a forbidden
        // NAL bit, or a marker length near 64 KiB, depending on where they land).
        let mut widened = seed.to_vec();
        let at = rng.below(widened.len().saturating_sub(1));
        widened[at] = 0xff;
        widened[at + 1] = 0xff;
        out.push(Mutant {
            family: "length_overflow",
            bytes: widened,
        });
    }
    out
}

/// Observed class of one case.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Class {
    Ok,
    TypedRefusal,
    FaultUntouchedThenNew,
    FaultIncompleteThenResumed,
    FaultCompleteThenIdempotent,
    RefusedEvenWithoutFault,
}

fn arm(fault: Fault, dep: &mut fss_reference::ReferenceDeployment, cx: &fss_reference::ReplayCx) {
    match fault {
        Fault::None => {}
        Fault::Cancel(stage, occurrence) => {
            cx.set_cancel_at_checkpoint_occurrence(stage, occurrence)
        }
        Fault::PublishCrash(point) => dep.publisher_mut().inject_crash_at(point),
        Fault::LedgerCrash => dep.inject_ledger_crash_at(LedgerCutPoint::AfterRootDurable),
        Fault::FirstAppendIndeterminate(phase) => dep.fail_ledger_append_after_phase(phase),
    }
}

fn run_case(case: usize, family: &str, bytes: &[u8], fault: Fault) -> Result<Class, Error> {
    let dir = fresh_dir(&format!("g{case:04}"))?;
    let input = dir.join("input.bin");
    fs::write(&input, bytes)?;
    let deployment_dir = dir.join("deployment");
    let req = request(&input, CHUNK, KNOB)?;
    let label = format!("g{case:04}");

    let first = {
        let mut dep = open(&deployment_dir, standard())?;
        let cx1 = cx(&label)?;
        arm(fault, &mut dep, &cx1);
        let result = FileIngestAdapter::ingest(req.clone(), &cx1, &mut dep);
        if let Err(error) = &result
            && format!("{error:?}").contains("Indeterminate")
        {
            let reconciled = dep
                .ledgered_publisher()
                .reconcile_ledger_append(IncompleteTailPolicy::Truncate)?;
            let committed = matches!(reconciled, DurableAppendReconciliation::Committed { .. });
            let expected = matches!(
                fault,
                Fault::FirstAppendIndeterminate(AppendPhase::CommitSync)
            );
            if committed != expected {
                return Err(
                    format!("case {case}: reconciliation {reconciled:?} under {fault:?}").into(),
                );
            }
        }
        if let Ok(receipt) = &result {
            // Ok: every capsule digest matches its span and the import is complete once.
            if !matches!(receipt.outcome, FileIngestOutcome::New) {
                return Err(
                    format!("case {case}: first import reported {:?}", receipt.outcome).into(),
                );
            }
            assert_complete_once(&dep, receipt, bytes, &cx(&label)?)?;
            return Ok(Class::Ok);
        }
        result
    };
    let Err(error) = first else {
        return Err("unreachable: Ok handled above".into());
    };

    let hex = identity_hex(&req)?;
    let dep = open(&deployment_dir, standard())?;
    let Some(hex) = hex else {
        // No recognizable format: refused before any identity, so nothing may exist at all.
        if !dep.ledger().batches().is_empty() || dep.publisher().spool().object_count() != 0 {
            return Err(format!("case {case}: unidentified input left state behind").into());
        }
        return Ok(Class::TypedRefusal);
    };
    let outcome = classify(&dep, &hex, &cx(&label)?)?;
    let fault_free = matches!(fault, Fault::None);
    if fault_free {
        // A fault-free typed error is a media/limit refusal before the first stage.
        if outcome != Outcome::Untouched
            || !dep.ledger().batches().is_empty()
            || dep.publisher().spool().object_count() != 0
        {
            return Err(format!(
                "case {case} ({family}): fault-free error {error:?} left {outcome:?}"
            )
            .into());
        }
        return Ok(Class::TypedRefusal);
    }
    drop(dep);
    if let Outcome::Incomplete(_) = outcome {
        let listed = doctor_incomplete(&deployment_dir)?;
        if listed != vec![hex.clone()] {
            return Err(
                format!("case {case}: doctor lists {listed:?} for an incomplete import").into(),
            );
        }
    }

    // Re-import without a fault.
    let mut dep = open(&deployment_dir, standard())?;
    let cx2 = cx(&format!("{label}-re"))?;
    match FileIngestAdapter::ingest(req.clone(), &cx2, &mut dep) {
        Ok(receipt) => {
            if receipt.outcome != expected_reimport(outcome) {
                return Err(format!(
                    "case {case}: re-import after {outcome:?} reported {:?}",
                    receipt.outcome
                )
                .into());
            }
            assert_complete_once(&dep, &receipt, bytes, &cx2)?;
            let batches = dep.ledger().batches().len();
            let again = FileIngestAdapter::ingest(req, &cx2, &mut dep)?;
            if again.outcome != FileIngestOutcome::IdempotentExisting
                || dep.ledger().batches().len() != batches
            {
                return Err(format!("case {case}: second re-import not idempotent").into());
            }
            drop(dep);
            if case.is_multiple_of(16) {
                assert_clean_after_reopen(&deployment_dir, standard())?;
            }
            Ok(match outcome {
                Outcome::Untouched => Class::FaultUntouchedThenNew,
                Outcome::Incomplete(_) => Class::FaultIncompleteThenResumed,
                Outcome::Complete => Class::FaultCompleteThenIdempotent,
            })
        }
        Err(refusal) => {
            // The media itself is refused; then the fault cannot have committed anything.
            if outcome != Outcome::Untouched || !dep.ledger().batches().is_empty() {
                return Err(format!(
                    "case {case}: refused re-import {refusal:?} after {outcome:?}"
                )
                .into());
            }
            Ok(Class::RefusedEvenWithoutFault)
        }
    }
}

#[test]
fn gauntlet_every_case_is_ok_untouched_or_resumably_incomplete() -> TestResult {
    let mut case = 0usize;
    let mut tally: BTreeMap<(String, Class), usize> = BTreeMap::new();
    let mut failures = Vec::new();
    for (seed_index, seed_path) in SEEDS.iter().enumerate() {
        let seed = fs::read(fixture(seed_path)?)?;
        for mutant in mutants(&seed, seed_index) {
            let fault = FAULTS[case % FAULTS.len()];
            match run_case(case, mutant.family, &mutant.bytes, fault) {
                Ok(class) => *tally.entry((mutant.family.to_owned(), class)).or_default() += 1,
                Err(error) => failures.push(format!(
                    "case {case} {seed_path} {}: {error}",
                    mutant.family
                )),
            }
            case += 1;
        }
    }
    for ((family, class), count) in &tally {
        eprintln!("CAPLOG gauntlet family={family} class={class:?} count={count}");
    }
    eprintln!("CAPLOG gauntlet cases={case} failures={}", failures.len());
    assert!(
        failures.is_empty(),
        "gauntlet failures:\n{}",
        failures.join("\n")
    );
    assert!(case >= MIN_CASES, "only {case} cases");
    let count = |class: Class| -> usize {
        tally
            .iter()
            .filter(|((_, c), _)| *c == class)
            .map(|(_, n)| n)
            .sum()
    };
    assert!(count(Class::Ok) > 0, "some mutants must import");
    assert!(
        count(Class::TypedRefusal) > 0,
        "some mutants must be refused"
    );
    assert!(
        count(Class::FaultIncompleteThenResumed) > 0,
        "some faults must leave a resumable incomplete import"
    );
    assert!(
        count(Class::FaultUntouchedThenNew) > 0,
        "some faults must stop before c0"
    );
    Ok(())
}

/// A sparse file one byte over the limit is refused by the stat check before any read, and a
/// 1 GiB sparse file over the standard 512 MiB limit is refused the same way; nothing is staged
/// or appended. The file is created with `set_len` and never filled.
#[test]
fn sparse_oversize_files_are_refused_before_reading() -> TestResult {
    let dir = fresh_dir("sparse")?;
    let deployment_dir = dir.join("deployment");
    let cx1 = cx("sparse")?;
    let mut dep = open(&deployment_dir, standard())?;
    for (name, len, max) in [
        ("over-by-one.bin", 4097u64, 4096u64),
        ("one-gib.bin", 1 << 30, 512 * 1024 * 1024),
    ] {
        let path = dir.join(name);
        let file = fs::File::create(&path)?;
        file.set_len(len)?;
        drop(file);
        let mut req = request(&path, CHUNK, KNOB)?;
        req.limits.max_file_bytes = max;
        match FileIngestAdapter::ingest(req, &cx1, &mut dep) {
            Err(FileIngestError::FileTooLarge {
                len: got,
                max: limit,
                ..
            }) if got == len && limit == max => {}
            other => return Err(format!("{name}: expected FileTooLarge, got {other:?}").into()),
        }
    }
    assert_eq!(dep.publisher().spool().object_count(), 0);
    assert!(dep.ledger().batches().is_empty());
    Ok(())
}

/// The same bytes under two names have one identity (fss-2h5zq.23 round 1): the second import
/// is `idempotent_existing` and appends nothing; a duplicate import of the same path likewise.
#[test]
fn same_bytes_under_two_names_are_one_import() -> TestResult {
    let dir = fresh_dir("two-names")?;
    let seed = fs::read(fixture(SEEDS[0])?)?;
    let (a, b) = (dir.join("a.264"), dir.join("renamed-b.264"));
    fs::write(&a, &seed)?;
    fs::write(&b, &seed)?;
    let deployment_dir = dir.join("deployment");
    let cx1 = cx("two-names")?;
    let mut dep = open(&deployment_dir, standard())?;
    let first = FileIngestAdapter::ingest(request(&a, CHUNK, KNOB)?, &cx1, &mut dep)?;
    let batches = dep.ledger().batches().len();
    let second = FileIngestAdapter::ingest(request(&b, CHUNK, KNOB)?, &cx1, &mut dep)?;
    let third = FileIngestAdapter::ingest(request(&a, CHUNK, KNOB)?, &cx1, &mut dep)?;
    assert_eq!(first.import_identity, second.import_identity);
    assert_eq!(second.outcome, FileIngestOutcome::IdempotentExisting);
    assert_eq!(third.outcome, FileIngestOutcome::IdempotentExisting);
    assert_eq!(dep.ledger().batches().len(), batches);
    assert_complete_once(&dep, &first, &seed, &cx1)?;
    drop(dep);
    assert_clean_after_reopen(&deployment_dir, standard())?;
    Ok(())
}
