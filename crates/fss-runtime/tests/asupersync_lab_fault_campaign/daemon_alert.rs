#![forbid(unsafe_code)]
//! Workflows 3 (`fss-daemon` multi-camera shutdown + slow disk + clock skew race)
//! and 4 (alert relay TLS dispatch timeout -> `Indeterminate`, never auto-resent)
//! for the 128-seed `asupersync::lab::LabRuntime` deterministic fault campaign.

use std::sync::{Arc, Mutex};

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::Budget as AsupersyncBudget;
use fss_core::effect::EffectState;
use fss_core::{
    ContentDigest, IdempotencyKey, ObligationId, ObligationState, OperationId, RegionKind,
    RegionTree, RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_runtime::authority::AuthorityCx;
use fss_runtime::effect::{CommitApproval, EffectCoordinator, PrepareSpec};
use fss_runtime::lease::LeaseRegistry;
use fss_runtime::obligation::{ObligationTerminal, new_obligation};

use super::rtsp_tutk::{
    TestResult, WorkflowRun, count_active, count_leaked, digest_events, finalize_child,
    full_grants, make_root, scope_child,
};

/// Workflow 3: `fss-daemon` multi-camera region tree concurrent shutdown + slow disk + clock skew race.
pub fn run_workflow_daemon_shutdown_race(seed: u64) -> TestResult<WorkflowRun> {
    let mut config = LabConfig::new(seed ^ 0x1357_2468);
    config.worker_count = 1 + (((seed >> 1) as usize) % 4);
    let mut runtime = LabRuntime::new(config);
    let root_region = runtime.state.create_root_region(AsupersyncBudget::INFINITE);

    let (mut proc_cx, mut tree) =
        make_root("op:daemon:proc", "region:daemon:proc", TimestampNs(10))?;
    let mut prop_cx = scope_child(
        &mut proc_cx,
        &mut tree,
        "region:daemon:prop",
        RegionKind::Property,
        "op:daemon:prop",
        full_grants(),
        TimestampNs(11),
    )?;
    let storage_cx = scope_child(
        &mut prop_cx,
        &mut tree,
        "region:daemon:storage",
        RegionKind::Ledger,
        "op:daemon:storage",
        vec![RuntimeGrant::LedgerAppend.as_str().to_owned()],
        TimestampNs(12),
    )?;
    let mut perc_ev_cx = scope_child(
        &mut prop_cx,
        &mut tree,
        "region:daemon:perc:ev",
        RegionKind::Event,
        "op:daemon:perc",
        vec![
            RuntimeGrant::ModelInfer.as_str().to_owned(),
            RuntimeGrant::ObserveEvent.as_str().to_owned(),
        ],
        TimestampNs(13),
    )?;
    let perc_model_cx = scope_child(
        &mut perc_ev_cx,
        &mut tree,
        "region:daemon:perc:model",
        RegionKind::ModelCall,
        "op:daemon:perc:model",
        vec![RuntimeGrant::ModelInfer.as_str().to_owned()],
        TimestampNs(14),
    )?;
    let ctrl_cx = scope_child(
        &mut prop_cx,
        &mut tree,
        "region:daemon:ctrl",
        RegionKind::Operations,
        "op:daemon:ctrl",
        vec![RuntimeGrant::ObserveStatus.as_str().to_owned()],
        TimestampNs(15),
    )?;

    let mut sensors = Vec::with_capacity(3);
    for idx in 1..=3_usize {
        let scx = scope_child(
            &mut prop_cx,
            &mut tree,
            &format!("region:daemon:sensor:{idx}"),
            RegionKind::Sensor,
            &format!("op:daemon:sensor:{idx}"),
            vec![RuntimeGrant::AdapterNet.as_str().to_owned()],
            TimestampNs(15 + idx as i128),
        )?;
        tree.register_task(
            scx.region(),
            TaskId::new(format!("task:daemon:s{idx}"))?,
            TimestampNs(20),
        )?;
        scx.register_obligation(
            &mut tree,
            new_obligation(
                format!("ob:daemon:s{idx}"),
                OperationId::parse(format!("op:daemon:sensor:{idx}"))?,
                "sensor gap or custody flushed",
            )?,
        )?;
        sensors.push(scx);
    }
    tree.register_task(
        storage_cx.region(),
        TaskId::new("task:daemon:storage")?,
        TimestampNs(20),
    )?;
    storage_cx.register_obligation(
        &mut tree,
        new_obligation(
            "ob:daemon:storage",
            OperationId::parse("op:daemon:storage")?,
            "packs flushed",
        )?,
    )?;
    tree.register_task(
        perc_model_cx.region(),
        TaskId::new("task:daemon:perc")?,
        TimestampNs(20),
    )?;
    perc_ev_cx.register_obligation(
        &mut tree,
        new_obligation(
            "ob:daemon:perc",
            OperationId::parse("op:daemon:perc")?,
            "cascade drained",
        )?,
    )?;
    tree.register_task(
        ctrl_cx.region(),
        TaskId::new("task:daemon:ctrl")?,
        TimestampNs(20),
    )?;
    ctrl_cx.register_obligation(
        &mut tree,
        new_obligation(
            "ob:daemon:ctrl",
            OperationId::parse("op:daemon:ctrl")?,
            "IPC drained",
        )?,
    )?;

    let disk_yields = 1_usize + ((seed as usize) % 4);
    let skew_ns = i128::from((seed % 50) * 1_000_000);

    struct DaemonState {
        tree: RegionTree,
        proc_cx: AuthorityCx,
        prop_cx: AuthorityCx,
        storage_cx: AuthorityCx,
        perc_ev_cx: AuthorityCx,
        perc_model_cx: AuthorityCx,
        ctrl_cx: AuthorityCx,
        sensors: Vec<AuthorityCx>,
        shutdown_req: bool,
        flushed: bool,
        events: Vec<String>,
    }
    let shared = Arc::new(Mutex::new(DaemonState {
        tree,
        proc_cx,
        prop_cx,
        storage_cx,
        perc_ev_cx,
        perc_model_cx,
        ctrl_cx,
        sensors,
        shutdown_req: false,
        flushed: false,
        events: Vec::new(),
    }));

    let mut tids = Vec::new();
    for idx in 0..3_usize {
        let s = Arc::clone(&shared);
        let (tid, _h) = runtime
            .state
            .create_task(root_region, AsupersyncBudget::INFINITE, async move {
                asupersync::runtime::yield_now().await;
                if let Ok(mut st) = s.lock() {
                    let DaemonState {
                        tree,
                        sensors,
                        events,
                        ..
                    } = &mut *st;
                    let n = idx + 1;
                    if let (Ok(t), Ok(o)) = (
                        TaskId::new(format!("task:daemon:s{n}")),
                        ObligationId::parse(format!("ob:daemon:s{n}")),
                    ) {
                        let _ = tree.complete_task(
                            sensors[idx].region(),
                            &t,
                            TaskOutcome::Cancelled,
                            TimestampNs(100 + skew_ns),
                        );
                        let _ = sensors[idx].resolve_obligation(
                            tree,
                            &o,
                            ObligationTerminal::Drained,
                            Some(ContentDigest::sha256(t.as_str().as_bytes())),
                            None,
                        );
                        events.push(format!("daemon:sensor{n}:drained"));
                    }
                }
            })
            .map_err(|e| format!("create_task sensor {idx}: {e:?}"))?;
        tids.push(tid);
    }

    let s_disk = Arc::clone(&shared);
    let (t_disk, _hd) = runtime
        .state
        .create_task(root_region, AsupersyncBudget::INFINITE, async move {
            for step in 0..disk_yields {
                if let Ok(mut st) = s_disk.lock() {
                    st.events.push(format!("daemon:slow_disk:{step}"));
                }
                asupersync::runtime::yield_now().await;
            }
            if let Ok(mut st) = s_disk.lock() {
                let DaemonState {
                    tree,
                    storage_cx,
                    flushed,
                    events,
                    ..
                } = &mut *st;
                if let (Ok(t), Ok(o)) = (
                    TaskId::new("task:daemon:storage"),
                    ObligationId::parse("ob:daemon:storage"),
                ) {
                    let _ = tree.complete_task(
                        storage_cx.region(),
                        &t,
                        TaskOutcome::Success,
                        TimestampNs(200 + skew_ns),
                    );
                    let _ = storage_cx.resolve_obligation(
                        tree,
                        &o,
                        ObligationTerminal::Completed,
                        Some(ContentDigest::sha256(b"flushed")),
                        None,
                    );
                    *flushed = true;
                    events.push("daemon:storage:flushed".to_owned());
                }
            }
        })
        .map_err(|e| format!("create_task storage: {e:?}"))?;
    tids.push(t_disk);

    let s_perc = Arc::clone(&shared);
    let (t_perc, _hp) = runtime
        .state
        .create_task(root_region, AsupersyncBudget::INFINITE, async move {
            asupersync::runtime::yield_now().await;
            if let Ok(mut st) = s_perc.lock() {
                let DaemonState {
                    tree,
                    perc_ev_cx,
                    perc_model_cx,
                    events,
                    ..
                } = &mut *st;
                if let (Ok(t), Ok(o)) = (
                    TaskId::new("task:daemon:perc"),
                    ObligationId::parse("ob:daemon:perc"),
                ) {
                    let _ = tree.complete_task(
                        perc_model_cx.region(),
                        &t,
                        TaskOutcome::Cancelled,
                        TimestampNs(150 + skew_ns),
                    );
                    let _ = perc_ev_cx.resolve_obligation(
                        tree,
                        &o,
                        ObligationTerminal::Completed,
                        Some(ContentDigest::sha256(b"perc")),
                        None,
                    );
                    events.push("daemon:perc:drained".to_owned());
                }
            }
        })
        .map_err(|e| format!("create_task perc: {e:?}"))?;
    tids.push(t_perc);

    let s_ctrl = Arc::clone(&shared);
    let (t_ctrl, _hc) = runtime
        .state
        .create_task(root_region, AsupersyncBudget::INFINITE, async move {
            if let Ok(mut st) = s_ctrl.lock() {
                let DaemonState {
                    tree,
                    proc_cx,
                    ctrl_cx,
                    shutdown_req,
                    events,
                    ..
                } = &mut *st;
                let _ = proc_cx.request_cancellation(tree, TimestampNs(90 + skew_ns));
                *shutdown_req = true;
                events.push("daemon:ctrl:shutdown_requested".to_owned());
                if let (Ok(t), Ok(o)) = (
                    TaskId::new("task:daemon:ctrl"),
                    ObligationId::parse("ob:daemon:ctrl"),
                ) {
                    let _ = tree.complete_task(
                        ctrl_cx.region(),
                        &t,
                        TaskOutcome::Cancelled,
                        TimestampNs(160 + skew_ns),
                    );
                    let _ = ctrl_cx.resolve_obligation(
                        tree,
                        &o,
                        ObligationTerminal::Completed,
                        Some(ContentDigest::sha256(b"ipc")),
                        None,
                    );
                    events.push("daemon:ctrl:ipc_drained".to_owned());
                }
            }
        })
        .map_err(|e| format!("create_task ctrl: {e:?}"))?;
    tids.push(t_ctrl);

    {
        let mut sched = runtime.scheduler.lock();
        for tid in tids {
            sched.schedule(tid, 1);
        }
    }

    let steps = runtime.run_until_quiescent();
    runtime.advance_time(500_000_000 + (seed % 100) * 1_000_000);
    let quiescent = runtime.is_quiescent();
    let violations = runtime.check_invariants();

    let mut st = shared.lock().map_err(|_| "daemon mutex poisoned")?;
    assert!(
        st.shutdown_req && st.flushed,
        "seed {seed}: daemon shutdown incomplete"
    );
    let fin = TimestampNs(300 + skew_ns);
    let DaemonState {
        tree,
        proc_cx,
        prop_cx,
        storage_cx,
        perc_ev_cx,
        perc_model_cx,
        ctrl_cx,
        sensors,
        events,
        ..
    } = &mut *st;
    for scx in sensors.iter_mut() {
        finalize_child(prop_cx, scx, tree, fin)?;
    }
    finalize_child(perc_ev_cx, perc_model_cx, tree, fin)?;
    finalize_child(prop_cx, perc_ev_cx, tree, fin)?;
    finalize_child(prop_cx, ctrl_cx, tree, fin)?;
    finalize_child(prop_cx, storage_cx, tree, fin)?;
    finalize_child(proc_cx, prop_cx, tree, fin)?;
    proc_cx.begin_drain(tree, fin)?;
    let proof = proc_cx.finalize(tree, fin)?;

    Ok(WorkflowRun {
        trace_digest: digest_events(events),
        steps,
        quiescent,
        active_tasks: count_active(tree),
        leaked_obligations: count_leaked(tree),
        invariant_violations: violations.len(),
        detail_counter: proof.total_obligations,
    })
}

/// Workflow 4: Alert relay TLS dispatch timeout -> Indeterminate (never auto-resent!) + obligation retirement.
pub fn run_workflow_alert_tls_indeterminate(seed: u64) -> TestResult<WorkflowRun> {
    let mut config = LabConfig::new(seed ^ 0xCAFE_1234);
    config.worker_count = 1 + (((seed >> 3) as usize) % 4);
    let mut runtime = LabRuntime::new(config);
    let root_region = runtime.state.create_root_region(AsupersyncBudget::INFINITE);

    let (auth, mut tree) = make_root("op:alert:root", "region:proc:alert", TimestampNs(10))?;
    let mut leases = LeaseRegistry::new();
    let lease = leases.acquire(
        "relay:tls:primary",
        auth.region().as_str(),
        Some(30_000_000_000),
        TimestampNs(11),
    )?;
    let mut coordinator = EffectCoordinator::new();
    let op_id = OperationId::parse(format!("op:alert:dispatch:{seed}"))?;
    let idem_key = IdempotencyKey::parse(format!("idem:alert:{seed}"))?;
    let req_digest = ContentDigest::sha256(format!("alert-payload-{seed}").as_bytes());
    let pre_digest = ContentDigest::sha256(format!("alert-precond-{seed}").as_bytes());

    let prepared = coordinator.prepare(
        &auth,
        &mut tree,
        &mut leases,
        PrepareSpec {
            operation: &op_id,
            idempotency_key: idem_key,
            request_digest: req_digest,
            precondition_digest: pre_digest,
            resource: "relay:tls:primary",
            fence: lease.fence,
            prepare_grant: RuntimeGrant::AlertPrepare,
            commit_grant: RuntimeGrant::AlertCommit,
            terminal_predicate: "alert dispatch verified or explicitly marked indeterminate",
        },
        TimestampNs(12),
    )?;
    let approval = CommitApproval {
        prepared_digest: prepared.digest(),
        current_precondition_digest: pre_digest,
    };

    struct AlertState {
        auth: AuthorityCx,
        tree: RegionTree,
        leases: LeaseRegistry,
        coordinator: EffectCoordinator,
        prepared: Option<fss_runtime::effect::PreparedEffect>,
        committed: Option<fss_runtime::effect::CommittedEffect>,
        dispatch_attempts: u64,
        duplicate_refused: bool,
        events: Vec<String>,
    }
    let shared = Arc::new(Mutex::new(AlertState {
        auth,
        tree,
        leases,
        coordinator,
        prepared: Some(prepared.clone()),
        committed: None,
        dispatch_attempts: 0,
        duplicate_refused: false,
        events: vec!["alert:prepared".to_owned()],
    }));

    let s_disp = Arc::clone(&shared);
    let dup_prepared = prepared;
    let (t_disp, _h1) = runtime
        .state
        .create_task(root_region, AsupersyncBudget::INFINITE, async move {
            if let Ok(mut st) = s_disp.lock()
                && let Some(prep) = st.prepared.take()
            {
                let AlertState {
                    auth,
                    tree,
                    leases,
                    coordinator,
                    committed,
                    dispatch_attempts,
                    events,
                    ..
                } = &mut *st;
                if let Ok(comm) =
                    coordinator.commit(auth, tree, leases, prep, TimestampNs(20), approval)
                {
                    *dispatch_attempts = dispatch_attempts.saturating_add(1);
                    *committed = Some(comm);
                    events.push("alert:committed_once".to_owned());
                }
            }
            asupersync::runtime::yield_now().await;
            if let Ok(mut st) = s_disp.lock() {
                let AlertState {
                    auth,
                    tree,
                    leases,
                    coordinator,
                    committed,
                    duplicate_refused,
                    events,
                    ..
                } = &mut *st;
                if coordinator
                    .commit(auth, tree, leases, dup_prepared, TimestampNs(25), approval)
                    .is_err()
                {
                    *duplicate_refused = true;
                    events.push("alert:duplicate_resend_refused".to_owned());
                }
                if let Some(comm) = committed.take()
                    && let Ok(indet) = coordinator.indeterminate(
                        tree,
                        auth,
                        comm,
                        Some("tls relay timed out after commit; readback required before retry"),
                        TimestampNs(30),
                    )
                {
                    *committed = Some(indet);
                    events.push("alert:reconciled_indeterminate".to_owned());
                }
            }
        })
        .map_err(|e| format!("create_task alert dispatch: {e:?}"))?;

    let s_to = Arc::clone(&shared);
    let (t_to, _h2) = runtime
        .state
        .create_task(root_region, AsupersyncBudget::INFINITE, async move {
            asupersync::runtime::yield_now().await;
            if let Ok(mut st) = s_to.lock() {
                st.events.push("alert:tls_timeout_observed".to_owned());
            }
        })
        .map_err(|e| format!("create_task alert timeout: {e:?}"))?;

    {
        let mut sched = runtime.scheduler.lock();
        sched.schedule(t_disp, 1);
        sched.schedule(t_to, 1);
    }

    let steps = runtime.run_until_quiescent();
    runtime.advance_time(5_000_000_000);
    let quiescent = runtime.is_quiescent();
    let violations = runtime.check_invariants();

    let mut st = shared.lock().map_err(|_| "alert mutex poisoned")?;
    assert_eq!(st.dispatch_attempts, 1, "seed {seed}: alert auto-resent!");
    assert!(
        st.duplicate_refused,
        "seed {seed}: duplicate alert not refused"
    );
    let AlertState {
        auth,
        tree,
        leases,
        coordinator,
        committed,
        events,
        dispatch_attempts,
        ..
    } = &mut *st;
    let comm_ref = committed.as_ref().ok_or("missing indeterminate handle")?;
    assert_eq!(coordinator.state(comm_ref)?, EffectState::Indeterminate);
    let node = tree.get(auth.region())?;
    assert!(
        node.obligations
            .values()
            .all(|o| o.state == ObligationState::Indeterminate)
    );
    assert!(!node.reconciliation_obligations.is_empty());
    leases.release(&lease.id)?;
    auth.request_cancellation(tree, TimestampNs(40))?;
    auth.begin_drain(tree, TimestampNs(41))?;
    let _ = auth.finalize(tree, TimestampNs(42))?;

    Ok(WorkflowRun {
        trace_digest: digest_events(events),
        steps,
        quiescent,
        active_tasks: count_active(tree),
        leaked_obligations: count_leaked(tree),
        invariant_violations: violations.len(),
        detail_counter: *dispatch_attempts,
    })
}
