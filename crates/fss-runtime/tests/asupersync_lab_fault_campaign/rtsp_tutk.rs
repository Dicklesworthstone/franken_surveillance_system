#![forbid(unsafe_code)]
//! Shared region fixtures plus Workflows 1 (RTSP TEARDOWN) and 2 (TUTK backoff reconnect)
//! for the 128-seed `asupersync::lab::LabRuntime` deterministic fault campaign.

use std::error::Error;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::Budget as AsupersyncBudget;
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RegionTree, RootAuthoritySpec,
    RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_runtime::asupersync_ops::BackoffPolicy;
use fss_runtime::authority::AuthorityCx;
use fss_runtime::obligation::{ObligationTerminal, new_obligation, tree_report};

pub type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// Deterministic summary emitted by each `LabRuntime` workflow run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowRun {
    pub trace_digest: ContentDigest,
    pub steps: u64,
    pub quiescent: bool,
    pub active_tasks: usize,
    pub leaked_obligations: usize,
    pub invariant_violations: usize,
    pub detail_counter: u64,
}

pub fn full_grants() -> Vec<String> {
    [
        RuntimeGrant::AdapterAuth,
        RuntimeGrant::AdapterNet,
        RuntimeGrant::AlertCommit,
        RuntimeGrant::AlertPrepare,
        RuntimeGrant::LedgerAppend,
        RuntimeGrant::MediaDecode,
        RuntimeGrant::ModelInfer,
        RuntimeGrant::ObjectPublish,
        RuntimeGrant::ObjectStage,
        RuntimeGrant::ObserveEvent,
        RuntimeGrant::ObserveStatus,
        RuntimeGrant::ReadMedia,
        RuntimeGrant::RetentionCommit,
        RuntimeGrant::RetentionPrepare,
    ]
    .iter()
    .map(|g| g.as_str().to_owned())
    .collect()
}

pub fn make_budget(scale: u32) -> TestResult<BudgetVector> {
    let mult = 1_u32 << scale.min(10);
    Ok(BudgetVector::builder()
        .bytes(1_u64 << (28 + scale.min(12)))
        .network_bytes(1_u64 << (24 + scale.min(12)))
        .model_calls(1_000_u32.saturating_mul(mult))
        .cpu_millis(1_u64 << (22 + scale.min(12)))
        .storage_operations(u64::from(1_000_u32.saturating_mul(mult)))
        .tokens(u64::from(1_000_u32.saturating_mul(mult)))
        .build()?)
}

pub fn make_spec(
    op: &str,
    caps: Vec<String>,
    budget: BudgetVector,
) -> TestResult<RootAuthoritySpec> {
    Ok(RootAuthoritySpec {
        trace_id: "trace:asupersync-lab-campaign".to_owned(),
        operation_id: OperationId::parse(op)?,
        principal: "principal:lab-campaign".to_owned(),
        capabilities: caps,
        deadline: None,
        priority: 10,
        budgets: budget,
        privacy_scope: "privacy:site-local".to_owned(),
        retention_scope: "retention:site-ring".to_owned(),
        anchor_universe: ContentDigest::sha256(b"asupersync-lab-fault-campaign"),
        generation: 1,
    })
}

pub fn make_root(
    op: &str,
    region: &str,
    now: TimestampNs,
) -> TestResult<(AuthorityCx, RegionTree)> {
    let budget = make_budget(8)?;
    let spec = make_spec(op, full_grants(), budget)?;
    Ok(AuthorityCx::root(
        spec,
        RegionId::new(region)?,
        RegionKind::Process,
        budget,
        now,
    )?)
}

pub fn scope_child(
    parent: &mut AuthorityCx,
    tree: &mut RegionTree,
    region: &str,
    kind: RegionKind,
    op: &str,
    caps: Vec<String>,
    now: TimestampNs,
) -> TestResult<AuthorityCx> {
    let scale = match kind {
        RegionKind::Property => 6,
        RegionKind::Event => 3,
        _ => 0,
    };
    let budget = make_budget(scale)?;
    let spec = make_spec(op, caps, budget)?;
    Ok(parent.scope_down(tree, RegionId::new(region)?, kind, budget, spec, now)?)
}

pub fn count_active(tree: &RegionTree) -> usize {
    tree.iter().map(|node| node.active_tasks.len()).sum()
}

pub fn count_leaked(tree: &RegionTree) -> usize {
    tree_report(tree).iter().map(|r| r.leaked.len()).sum()
}

pub fn digest_events(events: &[String]) -> ContentDigest {
    let mut bytes = Vec::new();
    for ev in events {
        bytes.extend_from_slice(&(ev.len() as u32).to_be_bytes());
        bytes.extend_from_slice(ev.as_bytes());
    }
    ContentDigest::sha256(&bytes)
}

pub fn finalize_child(
    parent: &mut AuthorityCx,
    child: &mut AuthorityCx,
    tree: &mut RegionTree,
    ts: TimestampNs,
) -> TestResult {
    child.begin_drain(tree, ts)?;
    let _ = child.finalize(tree, ts)?;
    let _ = parent.release_scope_reservation(tree, child)?;
    Ok(())
}

/// Workflow 1: RTSP connect -> stream -> packet loss / stall -> cancellation -> TEARDOWN.
pub fn run_workflow_rtsp_teardown(seed: u64) -> TestResult<WorkflowRun> {
    let mut config = LabConfig::new(seed);
    config.worker_count = 1 + ((seed as usize) % 4);
    let mut runtime = LabRuntime::new(config);
    let root_region = runtime.state.create_root_region(AsupersyncBudget::INFINITE);

    let (mut proc_cx, mut tree) = make_root("op:rtsp:root", "region:proc:rtsp", TimestampNs(1))?;
    let mut prop_cx = scope_child(
        &mut proc_cx,
        &mut tree,
        "region:prop:rtsp",
        RegionKind::Property,
        "op:rtsp:prop",
        full_grants(),
        TimestampNs(2),
    )?;
    let sensor_cx = scope_child(
        &mut prop_cx,
        &mut tree,
        "region:sensor:rtsp:cam01",
        RegionKind::Sensor,
        "op:rtsp:sensor",
        vec![
            RuntimeGrant::AdapterAuth.as_str().to_owned(),
            RuntimeGrant::AdapterNet.as_str().to_owned(),
            RuntimeGrant::MediaDecode.as_str().to_owned(),
        ],
        TimestampNs(3),
    )?;
    let task_id = TaskId::new("task:rtsp:stream:cam01")?;
    tree.register_task(sensor_cx.region(), task_id.clone(), TimestampNs(4))?;
    let ob = new_obligation(
        "ob:rtsp:teardown:cam01",
        OperationId::parse("op:rtsp:sensor")?,
        "RTSP TEARDOWN issued and sensor stream drained cleanly",
    )?;
    let ob_id = ob.obligation_id.clone();
    sensor_cx.register_obligation(&mut tree, ob)?;

    let packets = 3_u64 + (seed % 7);
    let drop_mod = 2_u64 + ((seed >> 3) % 3);
    struct RtspState {
        tree: RegionTree,
        sensor_cx: AuthorityCx,
        frames_rx: u64,
        teardown_sent: bool,
        events: Vec<String>,
    }
    let shared = Arc::new(Mutex::new(RtspState {
        tree,
        sensor_cx,
        frames_rx: 0,
        teardown_sent: false,
        events: Vec::new(),
    }));

    let s_stream = Arc::clone(&shared);
    let (t_stream, _h1) = runtime
        .state
        .create_task(root_region, AsupersyncBudget::INFINITE, async move {
            if let Ok(mut st) = s_stream.lock() {
                st.events.push("rtsp:connect:ok".to_owned());
                for seq in 1..=packets {
                    if st.sensor_cx.is_cancel_requested(&st.tree).unwrap_or(true) {
                        st.events.push(format!("rtsp:cancel_mid_stream:{seq}"));
                        break;
                    }
                    if seq % drop_mod == 0 {
                        st.events.push(format!("rtsp:pkt_loss:{seq}"));
                    } else {
                        st.frames_rx = st.frames_rx.saturating_add(1);
                        st.events.push(format!("rtsp:frame:{seq}"));
                    }
                }
                st.events.push("rtsp:stall_detected".to_owned());
            }
            asupersync::runtime::yield_now().await;
            if let Ok(mut st) = s_stream.lock() {
                let RtspState {
                    tree,
                    sensor_cx,
                    teardown_sent,
                    events,
                    ..
                } = &mut *st;
                let _ = sensor_cx.request_cancellation(tree, TimestampNs(50));
                let _ = sensor_cx.begin_drain(tree, TimestampNs(51));
                *teardown_sent = true;
                events.push("rtsp:teardown:sent".to_owned());
                let _ = tree.complete_task(
                    sensor_cx.region(),
                    &task_id,
                    TaskOutcome::Cancelled,
                    TimestampNs(52),
                );
                let _ = sensor_cx.resolve_obligation(
                    tree,
                    &ob_id,
                    ObligationTerminal::Drained,
                    Some(ContentDigest::sha256(b"rtsp:teardown:200ok")),
                    None,
                );
                events.push("rtsp:obligation:drained".to_owned());
            }
        })
        .map_err(|e| format!("create_task rtsp stream failed: {e:?}"))?;

    let s_watch = Arc::clone(&shared);
    let (t_watch, _h2) = runtime
        .state
        .create_task(root_region, AsupersyncBudget::INFINITE, async move {
            asupersync::runtime::yield_now().await;
            if let Ok(mut st) = s_watch.lock() {
                let RtspState {
                    tree,
                    sensor_cx,
                    events,
                    ..
                } = &mut *st;
                let _ = sensor_cx.request_cancellation(tree, TimestampNs(40));
                events.push("rtsp:watchdog:cancel_requested".to_owned());
            }
        })
        .map_err(|e| format!("create_task rtsp watchdog failed: {e:?}"))?;

    {
        let mut sched = runtime.scheduler.lock();
        sched.schedule(t_stream, 1);
        sched.schedule(t_watch, 1);
    }

    let steps = runtime.run_until_quiescent();
    runtime.advance_time(250_000_000);
    let quiescent = runtime.is_quiescent();
    let violations = runtime.check_invariants();

    let mut st = shared.lock().map_err(|_| "rtsp mutex poisoned")?;
    assert!(st.teardown_sent, "seed {seed}: RTSP TEARDOWN never emitted");
    let RtspState {
        tree,
        sensor_cx,
        events,
        frames_rx,
        ..
    } = &mut *st;
    let _ = sensor_cx.finalize(tree, TimestampNs(60))?;
    let _ = prop_cx.release_scope_reservation(tree, sensor_cx)?;
    prop_cx.request_cancellation(tree, TimestampNs(61))?;
    finalize_child(&mut proc_cx, &mut prop_cx, tree, TimestampNs(62))?;
    proc_cx.request_cancellation(tree, TimestampNs(63))?;
    proc_cx.begin_drain(tree, TimestampNs(64))?;
    let _ = proc_cx.finalize(tree, TimestampNs(65))?;

    Ok(WorkflowRun {
        trace_digest: digest_events(events),
        steps,
        quiescent,
        active_tasks: count_active(tree),
        leaked_obligations: count_leaked(tree),
        invariant_violations: violations.len(),
        detail_counter: *frames_rx,
    })
}

/// Workflow 2: TUTK UDP session -> drop -> bounded backoff reconnect -> cancellation -> zero-orphan close.
pub fn run_workflow_tutk_backoff_reconnect(seed: u64) -> TestResult<WorkflowRun> {
    let mut config = LabConfig::new(seed ^ 0x55AA_55AA);
    config.worker_count = 1 + (((seed >> 2) as usize) % 4);
    let mut runtime = LabRuntime::new(config);
    let root_region = runtime.state.create_root_region(AsupersyncBudget::INFINITE);

    let (mut proc_cx, mut tree) = make_root("op:tutk:root", "region:proc:tutk", TimestampNs(1))?;
    let mut prop_cx = scope_child(
        &mut proc_cx,
        &mut tree,
        "region:prop:tutk",
        RegionKind::Property,
        "op:tutk:prop",
        full_grants(),
        TimestampNs(2),
    )?;
    let g1_cx = scope_child(
        &mut prop_cx,
        &mut tree,
        "region:sensor:tutk:g1",
        RegionKind::Sensor,
        "op:tutk:g1",
        vec![
            RuntimeGrant::AdapterAuth.as_str().to_owned(),
            RuntimeGrant::AdapterNet.as_str().to_owned(),
        ],
        TimestampNs(3),
    )?;
    let g1_task = TaskId::new("task:tutk:session:g1")?;
    tree.register_task(g1_cx.region(), g1_task.clone(), TimestampNs(4))?;
    let g1_ob = new_obligation(
        "ob:tutk:close:g1",
        OperationId::parse("op:tutk:g1")?,
        "TUTK UDP session g1 closed with zero orphan socket",
    )?;
    let g1_ob_id = g1_ob.obligation_id.clone();
    g1_cx.register_obligation(&mut tree, g1_ob)?;

    let backoff = BackoffPolicy::new(
        Duration::from_millis(50),
        Duration::from_millis(800),
        4,
        seed,
    )?;
    struct TutkState {
        tree: RegionTree,
        prop_cx: AuthorityCx,
        g1_cx: Option<AuthorityCx>,
        g2_cx: Option<AuthorityCx>,
        active_sessions: u32,
        peak_sessions: u32,
        backoff_ms: Vec<u64>,
        cancelled: bool,
        events: Vec<String>,
    }
    let shared = Arc::new(Mutex::new(TutkState {
        tree,
        prop_cx,
        g1_cx: Some(g1_cx),
        g2_cx: None,
        active_sessions: 1,
        peak_sessions: 1,
        backoff_ms: Vec::new(),
        cancelled: false,
        events: vec!["tutk:g1:connected".to_owned()],
    }));

    let retries = 1_u32 + ((seed % 3) as u32);
    let s_sess = Arc::clone(&shared);
    let (t_sess, _h1) = runtime
        .state
        .create_task(root_region, AsupersyncBudget::INFINITE, async move {
            if let Ok(mut st) = s_sess.lock() {
                let TutkState {
                    tree,
                    prop_cx,
                    g1_cx,
                    active_sessions,
                    events,
                    ..
                } = &mut *st;
                *active_sessions = active_sessions.saturating_sub(1);
                events.push("tutk:g1:udp_drop".to_owned());
                if let Some(mut g1) = g1_cx.take() {
                    let _ = g1.request_cancellation(tree, TimestampNs(20));
                    let _ = g1.begin_drain(tree, TimestampNs(21));
                    let _ = tree.complete_task(
                        g1.region(),
                        &g1_task,
                        TaskOutcome::Failed("udp_keepalive_timeout".to_owned()),
                        TimestampNs(22),
                    );
                    let _ = g1.resolve_obligation(
                        tree,
                        &g1_ob_id,
                        ObligationTerminal::Drained,
                        Some(ContentDigest::sha256(b"tutk:g1:closed")),
                        None,
                    );
                    let _ = g1.finalize(tree, TimestampNs(23));
                    let _ = prop_cx.release_scope_reservation(tree, &mut g1);
                    events.push("tutk:g1:region_finalized".to_owned());
                }
            }
            asupersync::runtime::yield_now().await;

            for attempt in 0..retries {
                let Some(delay) = backoff.delay_for_attempt(attempt) else {
                    break;
                };
                let ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
                if let Ok(mut st) = s_sess.lock() {
                    if st.cancelled {
                        st.events.push(format!("tutk:backoff_cancelled:{attempt}"));
                        return;
                    }
                    st.backoff_ms.push(ms);
                    st.events.push(format!("tutk:backoff:{attempt}:{ms}ms"));
                }
                asupersync::runtime::yield_now().await;
            }

            if let Ok(mut st) = s_sess.lock() {
                if st.cancelled {
                    st.events.push("tutk:cancelled_before_g2".to_owned());
                    return;
                }
                let TutkState {
                    tree,
                    prop_cx,
                    g2_cx,
                    active_sessions,
                    peak_sessions,
                    events,
                    ..
                } = &mut *st;
                if let Ok(g2) = scope_child(
                    prop_cx,
                    tree,
                    "region:sensor:tutk:g2",
                    RegionKind::Sensor,
                    "op:tutk:g2",
                    vec![
                        RuntimeGrant::AdapterAuth.as_str().to_owned(),
                        RuntimeGrant::AdapterNet.as_str().to_owned(),
                    ],
                    TimestampNs(40),
                ) {
                    *active_sessions = active_sessions.saturating_add(1);
                    *peak_sessions = (*peak_sessions).max(*active_sessions);
                    if let Ok(t2) = TaskId::new("task:tutk:session:g2")
                        && tree
                            .register_task(g2.region(), t2.clone(), TimestampNs(41))
                            .is_ok()
                        && let Ok(op2) = OperationId::parse("op:tutk:g2")
                        && let Ok(ob2) = new_obligation(
                            "ob:tutk:close:g2",
                            op2,
                            "TUTK UDP session g2 closed with zero orphan socket",
                        )
                    {
                        let ob2_id = ob2.obligation_id.clone();
                        let _ = g2.register_obligation(tree, ob2);
                        events.push("tutk:g2:connected".to_owned());
                        let _ = g2.request_cancellation(tree, TimestampNs(60));
                        let _ = g2.begin_drain(tree, TimestampNs(61));
                        let _ = tree.complete_task(
                            g2.region(),
                            &t2,
                            TaskOutcome::Cancelled,
                            TimestampNs(62),
                        );
                        let _ = g2.resolve_obligation(
                            tree,
                            &ob2_id,
                            ObligationTerminal::Drained,
                            Some(ContentDigest::sha256(b"tutk:g2:closed")),
                            None,
                        );
                        *active_sessions = active_sessions.saturating_sub(1);
                        events.push("tutk:g2:closed".to_owned());
                    }
                    *g2_cx = Some(g2);
                }
            }
        })
        .map_err(|e| format!("create_task tutk session failed: {e:?}"))?;

    let cancel_yields = (seed >> 4) % 4;
    let s_cancel = Arc::clone(&shared);
    let (t_cancel, _h2) = runtime
        .state
        .create_task(root_region, AsupersyncBudget::INFINITE, async move {
            for _ in 0..cancel_yields {
                asupersync::runtime::yield_now().await;
            }
            if let Ok(mut st) = s_cancel.lock() {
                st.cancelled = true;
                st.events.push("tutk:cancel_signal".to_owned());
            }
        })
        .map_err(|e| format!("create_task tutk cancel failed: {e:?}"))?;

    {
        let mut sched = runtime.scheduler.lock();
        sched.schedule(t_sess, 1);
        sched.schedule(t_cancel, 1);
    }

    let steps = runtime.run_until_quiescent();
    let advance_ns = {
        let st = shared.lock().map_err(|_| "tutk mutex poisoned")?;
        st.backoff_ms.iter().fold(0_u64, |acc, ms| {
            acc.saturating_add(ms.saturating_mul(1_000_000))
        })
    };
    runtime.advance_time(advance_ns.max(1_000_000));
    let quiescent = runtime.is_quiescent();
    let violations = runtime.check_invariants();

    let mut st = shared.lock().map_err(|_| "tutk mutex poisoned")?;
    assert_eq!(
        st.active_sessions, 0,
        "seed {seed}: TUTK leaked active session"
    );
    assert!(
        st.peak_sessions <= 1,
        "seed {seed}: TUTK exceeded single session"
    );
    let TutkState {
        tree,
        prop_cx,
        g2_cx,
        events,
        backoff_ms,
        ..
    } = &mut *st;
    if let Some(mut g2) = g2_cx.take() {
        let _ = g2.finalize(tree, TimestampNs(70))?;
        let _ = prop_cx.release_scope_reservation(tree, &mut g2)?;
    }
    prop_cx.request_cancellation(tree, TimestampNs(80))?;
    finalize_child(&mut proc_cx, prop_cx, tree, TimestampNs(81))?;
    proc_cx.request_cancellation(tree, TimestampNs(82))?;
    proc_cx.begin_drain(tree, TimestampNs(83))?;
    let _ = proc_cx.finalize(tree, TimestampNs(84))?;

    Ok(WorkflowRun {
        trace_digest: digest_events(events),
        steps,
        quiescent,
        active_tasks: count_active(tree),
        leaked_obligations: count_leaked(tree),
        invariant_violations: violations.len(),
        detail_counter: backoff_ms.len() as u64,
    })
}
