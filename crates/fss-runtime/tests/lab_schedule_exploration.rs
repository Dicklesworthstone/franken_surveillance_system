#![forbid(unsafe_code)]
//! Deterministic schedule-exploration tests using `asupersync::lab::LabRuntime`
//! (`TEST-SCHEDULE-001` / `fss-x4a.28.3`).
//!
//! Proves that `fss-runtime`'s explicit-authority region tree, obligation lifecycle,
//! and request->drain->finalize cancellation state machine remain quiescent, leak-free,
//! and bit-for-bit reproducible under deterministic multi-seed and multi-worker
//! `LabRuntime` scheduling with virtual time.

use std::sync::{Arc, Mutex};

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::Budget as AsupersyncBudget;
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RegionTree, RootAuthoritySpec,
    TimestampNs,
};
use fss_runtime::authority::AuthorityCx;
use fss_runtime::obligation::{ObligationTerminal, new_obligation, tree_report};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn make_authority(op: &str) -> TestResult<(AuthorityCx, RegionTree)> {
    let spec = RootAuthoritySpec {
        trace_id: format!("trace:{op}"),
        operation_id: OperationId::parse(op)?,
        principal: "principal:lab-schedule".to_owned(),
        capabilities: vec!["CAP-MEDIA-DECODE-001".to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().tokens(512).bytes(65_536).build()?,
        privacy_scope: "privacy:lab".to_owned(),
        retention_scope: "retention:lab".to_owned(),
        anchor_universe: ContentDigest::sha256(b"lab-schedule-universe"),
        generation: 1,
    };
    let root = AuthorityCx::root(
        spec,
        RegionId::new("region:lab-process")?,
        RegionKind::Process,
        BudgetVector::builder().tokens(512).bytes(65_536).build()?,
        TimestampNs(1),
    )?;
    Ok(root)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PipelineTrace {
    steps: u64,
    events: Vec<&'static str>,
    total_obligations: u64,
    leaked_obligations: usize,
}

fn run_seeded_pipeline(seed: u64, worker_count: usize) -> TestResult<PipelineTrace> {
    let mut config = LabConfig::new(seed);
    config.worker_count = worker_count;
    let mut runtime = LabRuntime::new(config);
    let region = runtime.state.create_root_region(AsupersyncBudget::INFINITE);

    let (auth, tree) = make_authority("op:lab-pipeline")?;
    let shared = Arc::new(Mutex::new((auth, tree, Vec::<&'static str>::new())));

    let s1 = Arc::clone(&shared);
    let (t1, _h1) = runtime
        .state
        .create_task(region, AsupersyncBudget::INFINITE, async move {
            if let Ok(mut guard) = s1.lock() {
                let (auth, tree, events) = &mut *guard;
                if let Ok(op_id) = OperationId::parse("op:lab-ingest")
                    && let Ok(ob) = new_obligation("ob:lab-ingest", op_id, "source custody staged")
                {
                    let ob_id = ob.obligation_id.clone();
                    if auth.register_obligation(tree, ob).is_ok() {
                        events.push("ingest:registered");
                        let _ = auth.resolve_obligation(
                            tree,
                            &ob_id,
                            ObligationTerminal::Completed,
                            Some(ContentDigest::sha256(b"ingest:proof")),
                            None,
                        );
                        events.push("ingest:completed");
                    }
                }
            }
        })
        .map_err(|e| format!("create_task t1 failed: {e:?}"))?;

    let s2 = Arc::clone(&shared);
    let (t2, _h2) = runtime
        .state
        .create_task(region, AsupersyncBudget::INFINITE, async move {
            if let Ok(mut guard) = s2.lock() {
                let (auth, tree, events) = &mut *guard;
                if let Ok(op_id) = OperationId::parse("op:lab-derive")
                    && let Ok(ob) =
                        new_obligation("ob:lab-derive", op_id, "derived belief anchored")
                {
                    let ob_id = ob.obligation_id.clone();
                    if auth.register_obligation(tree, ob).is_ok() {
                        events.push("derive:registered");
                        let _ = auth.resolve_obligation(
                            tree,
                            &ob_id,
                            ObligationTerminal::Completed,
                            Some(ContentDigest::sha256(b"derive:proof")),
                            None,
                        );
                        events.push("derive:completed");
                    }
                }
            }
        })
        .map_err(|e| format!("create_task t2 failed: {e:?}"))?;

    let s3 = Arc::clone(&shared);
    let (t3, _h3) = runtime
        .state
        .create_task(region, AsupersyncBudget::INFINITE, async move {
            if let Ok(mut guard) = s3.lock() {
                let (auth, tree, events) = &mut *guard;
                if let Ok(op_id) = OperationId::parse("op:lab-handoff")
                    && let Ok(ob) =
                        new_obligation("ob:lab-handoff", op_id, "typed handoff persisted")
                {
                    let ob_id = ob.obligation_id.clone();
                    if auth.register_obligation(tree, ob).is_ok() {
                        events.push("handoff:registered");
                        let _ = auth.resolve_obligation(
                            tree,
                            &ob_id,
                            ObligationTerminal::Completed,
                            Some(ContentDigest::sha256(b"handoff:proof")),
                            None,
                        );
                        events.push("handoff:completed");
                    }
                }
            }
        })
        .map_err(|e| format!("create_task t3 failed: {e:?}"))?;

    {
        let mut sched = runtime.scheduler.lock();
        sched.schedule(t1, 1);
        sched.schedule(t2, 1);
        sched.schedule(t3, 1);
    }

    let steps = runtime.run_until_quiescent();
    assert!(runtime.is_quiescent(), "seed {seed}: runtime not quiescent");
    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "seed {seed}: LabRuntime invariant violations: {violations:?}"
    );

    let mut guard = shared
        .lock()
        .map_err(|_| "shared mutex poisoned in lab test")?;
    let (auth, tree, events) = &mut *guard;
    let leaked = tree_report(tree)
        .iter()
        .map(|entry| entry.leaked.len())
        .sum::<usize>();
    assert_eq!(leaked, 0, "seed {seed}: leaked FSS obligations");
    auth.request_cancellation(tree, TimestampNs(10))?;
    auth.begin_drain(tree, TimestampNs(20))?;
    let quiescence = auth.finalize(tree, TimestampNs(30))?;

    Ok(PipelineTrace {
        steps,
        events: events.clone(),
        total_obligations: quiescence.total_obligations,
        leaked_obligations: leaked,
    })
}

#[test]
fn multi_seed_deterministic_replay_is_bit_identical() -> TestResult {
    for seed in [0x0001_u64, 0x1111, 0x2222, 0xCAFE_BABE, 0xDEAD_BEEF] {
        let first = run_seeded_pipeline(seed, 1)?;
        let second = run_seeded_pipeline(seed, 1)?;
        assert_eq!(
            first, second,
            "same seed {seed} must replay identically on LabRuntime"
        );
        assert_eq!(first.total_obligations, 3);
        assert_eq!(first.leaked_obligations, 0);
        assert_eq!(first.events.len(), 6);
    }
    Ok(())
}

#[test]
fn multi_worker_virtual_scheduler_preserves_determinism_and_invariants() -> TestResult {
    for seed in 1_u64..=12 {
        let a = run_seeded_pipeline(seed, 4)?;
        let b = run_seeded_pipeline(seed, 4)?;
        assert_eq!(a, b, "4-worker virtual schedule diverged on seed {seed}");
        assert_eq!(a.total_obligations, 3);
    }
    Ok(())
}

#[test]
fn virtual_time_advancement_drives_deterministic_lifecycle_without_wall_clock() -> TestResult {
    let mut runtime = LabRuntime::new(LabConfig::new(0x5150));
    let region = runtime.state.create_root_region(AsupersyncBudget::INFINITE);
    let (auth, mut tree) = make_authority("op:lab-virtual-time")?;

    let t0 = runtime.now().as_nanos();
    runtime.advance_time(5_000_000_000);
    let t1 = runtime.now().as_nanos();
    assert_eq!(t1 - t0, 5_000_000_000);

    let observed_ns = Arc::new(Mutex::new(Vec::<u64>::new()));
    let obs = Arc::clone(&observed_ns);
    let (task_id, _handle) = runtime
        .state
        .create_task(region, AsupersyncBudget::INFINITE, async move {
            if let Ok(mut log) = obs.lock() {
                log.push(t1);
            }
        })
        .map_err(|e| format!("create_task failed: {e:?}"))?;
    runtime.scheduler.lock().schedule(task_id, 0);
    runtime.run_until_quiescent();

    runtime.advance_time(2_500_000_000);
    let t2 = runtime.now().as_nanos();
    assert_eq!(t2 - t1, 2_500_000_000);

    auth.request_cancellation(&mut tree, TimestampNs(i128::from(t1)))?;
    auth.begin_drain(&mut tree, TimestampNs(i128::from(t1) + 1))?;
    let proof = auth.finalize(&mut tree, TimestampNs(i128::from(t2)))?;
    assert_eq!(proof.total_obligations, 0);
    assert!(runtime.is_quiescent());
    assert!(runtime.check_invariants().is_empty());

    let log = observed_ns
        .lock()
        .map_err(|_| "observed_ns mutex poisoned")?;
    assert_eq!(*log, vec![t1]);
    Ok(())
}

#[test]
fn cancellation_interleavings_drain_all_obligations_across_seeds() -> TestResult {
    for seed in 1_u64..=16 {
        let mut config = LabConfig::new(seed);
        config.worker_count = 3;
        let mut runtime = LabRuntime::new(config);
        let region = runtime.state.create_root_region(AsupersyncBudget::INFINITE);
        let (auth, mut tree) = make_authority("op:lab-cancel-race")?;

        // Pre-register a pending obligation before racing work vs cancellation.
        let op = OperationId::parse("op:lab-raced-effect")?;
        let ob = new_obligation("ob:lab-raced-effect", op, "effect drained or completed")?;
        let ob_id = ob.obligation_id.clone();
        auth.register_obligation(&mut tree, ob)?;

        let shared = Arc::new(Mutex::new((auth, tree, false)));

        // Worker task: if region still active, complete obligation; otherwise drain it cleanly.
        let s_worker = Arc::clone(&shared);
        let ob_worker = ob_id.clone();
        let (t_worker, _hw) = runtime
            .state
            .create_task(region, AsupersyncBudget::INFINITE, async move {
                if let Ok(mut guard) = s_worker.lock() {
                    let (auth, tree, settled) = &mut *guard;
                    if !*settled {
                        let terminal = if auth.is_cancel_requested(tree).unwrap_or(true) {
                            ObligationTerminal::Drained
                        } else {
                            ObligationTerminal::Completed
                        };
                        if auth
                            .resolve_obligation(
                                tree,
                                &ob_worker,
                                terminal,
                                Some(ContentDigest::sha256(b"raced:settled")),
                                None,
                            )
                            .is_ok()
                        {
                            *settled = true;
                        }
                    }
                }
            })
            .map_err(|e| format!("create_task worker failed: {e:?}"))?;

        // Canceller task: requests cancellation and initiates drain.
        let s_cancel = Arc::clone(&shared);
        let (t_cancel, _hc) = runtime
            .state
            .create_task(region, AsupersyncBudget::INFINITE, async move {
                if let Ok(mut guard) = s_cancel.lock() {
                    let (auth, tree, _) = &mut *guard;
                    let _ = auth.request_cancellation(tree, TimestampNs(100));
                    let _ = auth.begin_drain(tree, TimestampNs(101));
                }
            })
            .map_err(|e| format!("create_task cancel failed: {e:?}"))?;

        {
            let mut sched = runtime.scheduler.lock();
            sched.schedule(t_worker, 1);
            sched.schedule(t_cancel, 1);
        }
        runtime.run_until_quiescent();

        assert!(runtime.is_quiescent());
        assert!(runtime.check_invariants().is_empty());

        let mut guard = shared
            .lock()
            .map_err(|_| "shared mutex poisoned in cancel race")?;
        let (auth, tree, settled) = &mut *guard;
        assert!(*settled, "seed {seed}: obligation was never settled");
        let leaked: usize = tree_report(tree).iter().map(|r| r.leaked.len()).sum();
        assert_eq!(
            leaked, 0,
            "seed {seed}: obligation leaked after cancellation"
        );
        let proof = auth.finalize(tree, TimestampNs(200))?;
        assert_eq!(proof.total_obligations, 1);
    }
    Ok(())
}
