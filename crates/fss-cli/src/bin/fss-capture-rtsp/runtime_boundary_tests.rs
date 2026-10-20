#![forbid(unsafe_code)]
//! Actual native Owner callbacks obey live resource grants and canonical drain.

use super::super::Owner;
use super::*;
use fss_packet::StreamKey;
use fss_reference::rtsp::tcp::{
    TcpAuthority, TcpBinding, TcpDenial, TcpOperation, TcpSecurityPolicy,
};
use fss_runtime::grant::GrantSet;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const LIVE_DEADLINE_NS: u64 = 20_000_000_000;
const STORAGE_DEADLINE_NS: u64 = 30_000_000_000;

fn root() -> Test<(AuthorityCx, RegionTree)> {
    let mut capabilities = STORAGE_GRANTS
        .iter()
        .map(|grant| grant.as_str().to_owned())
        .collect::<Vec<_>>();
    capabilities.push(RuntimeGrant::AdapterNet.as_str().to_owned());
    let allowance = BudgetVector::builder()
        .bytes(1024)
        .network_bytes(1024)
        .storage_operations(16)
        .latency_ms(STORAGE_DEADLINE_NS / 1_000_000)
        .build()?;
    Ok(AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:rtsp-owner-boundary".into(),
            operation_id: OperationId::parse("operation:rtsp-owner-boundary")?,
            principal: "principal:fixture-owner".into(),
            capabilities,
            deadline: Some(TimestampNs(i128::from(STORAGE_DEADLINE_NS))),
            priority: 10,
            budgets: allowance,
            privacy_scope: "privacy:fixture".into(),
            retention_scope: "retention:fixture".into(),
            anchor_universe: ContentDigest::sha256(b"RTSP owner callback boundary"),
            generation: 1,
        },
        RegionId::new("region:rtsp-owner-boundary")?,
        RegionKind::Process,
        allowance,
        TimestampNs(0),
    )?)
}

fn resources() -> Resources {
    Resources {
        network: "rtsp-route:approved-fixture".into(),
        storage: "rtsp-custody:approved-fixture".into(),
        secret: "rtsp-credential:approved-fixture".into(),
        preview: "rtsp-local-preview:approved-fixture".into(),
    }
}

fn owner<'a, 'task>(
    task: &'a TaskCx<'task>,
    clock: &'a TaskClock,
    resources: &'a Resources,
) -> Test<Owner<'a, 'task>> {
    Ok(Owner {
        task,
        clock,
        resources,
        binding: TcpBinding::new(
            StreamKey {
                ingress: 1,
                generation: 1,
                ssrc: 7,
            },
            ([127, 0, 0, 1], 8554).into(),
            "camera.fixture:8554",
            TcpSecurityPolicy::OwnerApprovedPlaintext,
        )?,
        live_deadline: LIVE_DEADLINE_NS,
        storage_deadline: STORAGE_DEADLINE_NS,
        drain_timeout: STORAGE_DEADLINE_NS - LIVE_DEADLINE_NS,
        drain_deadline: Cell::new(None),
        credentials: None,
        supervision: None,
        preview_scope: None,
        preview: std::cell::RefCell::new(None),
    })
}

fn checked<T>(result: Result<T, Failure>) -> Test<T> {
    result.map_err(|error| error.code().into())
}

fn run_test(
    task: &TaskCx<'_>,
    outcome: TaskOutcome,
    work: impl FnOnce(&TaskClock) -> Test,
) -> TaskCompletion<Test> {
    let (output, now) = match TaskClock::start(task) {
        Ok(clock) => {
            let mut output = work(&clock);
            let now = match clock.elapsed() {
                Ok(now) => now,
                Err(error) => {
                    if output.is_ok() {
                        output = Err(error.code().into());
                    }
                    clock.observed_ns.get()
                }
            };
            (output, now)
        }
        Err(error) => (Err(error.code().into()), 0),
    };
    TaskCompletion {
        outcome: if output.is_ok() {
            outcome
        } else {
            TaskOutcome::Failed("native owner contract failed".into())
        },
        output,
        completed_at: TimestampNs(i128::from(now)),
    }
}

#[test]
fn revoked_or_wrong_resource_network_grants_refuse_native_admission_without_debit() -> Test {
    for revoked in [true, false] {
        let (mut authority, mut tree) = root()?;
        let grants = if revoked {
            GrantSet::empty()
        } else {
            authority.grants().clone().with_scope(
                RuntimeGrant::AdapterNet,
                BTreeSet::from(["rtsp-route:another-fixture".to_owned()]),
            )
        };
        authority.narrow_grants(grants)?;
        let resources = resources();
        let result = run_owned(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:refused-network")?,
                started_at: TimestampNs(0),
            },
            |task| {
                run_test(
                    task,
                    TaskOutcome::Failed("native resource refused".into()),
                    |clock| {
                        let owner = owner(task, clock, &resources)?;
                        let before = task.remaining_budget()?;
                        for operation in [
                            TcpOperation::Connect,
                            TcpOperation::QueueRequest,
                            TcpOperation::Read,
                            TcpOperation::Write,
                        ] {
                            assert_eq!(
                                owner.checkpoint(&owner.binding, operation, 0, LIVE_DEADLINE_NS),
                                Err(TcpDenial::Unauthorized),
                                "revoked={revoked}, operation={operation:?}"
                            );
                            assert_eq!(
                                task.remaining_budget()?,
                                before,
                                "a refused resource consumed another budget dimension"
                            );
                        }
                        Ok(())
                    },
                )
            },
        )?;
        result.output?;
        assert!(matches!(result.receipt?.outcome, TaskOutcome::Failed(_)));
        assert!(tree.get(authority.region())?.active_tasks.is_empty());
    }
    Ok(())
}

#[test]
fn explicit_cancellation_keeps_native_input_closed_while_bounded_storage_drains() -> Test {
    let (mut authority, mut tree) = root()?;
    let resources = resources();
    let result = run_owned(
        &mut authority,
        &mut tree,
        TaskSpec {
            task_id: TaskId::new("task:cancelled-native-capture")?,
            started_at: TimestampNs(0),
        },
        |task| {
            run_test(task, TaskOutcome::Cancelled, |clock| {
                let owner = owner(task, clock, &resources)?;
                owner
                    .checkpoint(&owner.binding, TcpOperation::Read, 0, LIVE_DEADLINE_NS)
                    .map_err(|denial| format!("initial native admission refused: {denial:?}"))?;
                let now = checked(clock.now(task, false))?;
                task.request_cancellation(TimestampNs(i128::from(now)))?;
                assert_eq!(
                    owner.checkpoint(&owner.binding, TcpOperation::Read, now, LIVE_DEADLINE_NS),
                    Err(TcpDenial::Cancelled),
                    "a canonical cancellation must retain its native typed reason"
                );

                checked(owner.begin_drain())?;
                let deadline = owner
                    .drain_deadline
                    .get()
                    .ok_or("missing bounded drain deadline")?;
                assert!(deadline <= STORAGE_DEADLINE_NS);
                let before = task.remaining_budget()?;
                let admissions = clock.storage_admissions.get();
                checked(owner.storage_check())?;
                assert_eq!(
                    task.remaining_budget()?.storage_operations,
                    before.storage_operations - 1
                );
                assert_eq!(clock.storage_admissions.get(), admissions + 1);
                checked(owner.begin_drain())?;
                assert_eq!(owner.drain_deadline.get(), Some(deadline));
                assert!(owner.check_storage_deadline(deadline - 1).is_ok());
                assert!(matches!(
                    owner.check_storage_deadline(deadline),
                    Err(Failure::Deadline)
                ));

                let before = task.remaining_budget()?;
                for operation in [
                    TcpOperation::Connect,
                    TcpOperation::Read,
                    TcpOperation::Write,
                ] {
                    assert_eq!(
                        owner.checkpoint(&owner.binding, operation, now, LIVE_DEADLINE_NS),
                        Err(TcpDenial::Cancelled)
                    );
                }
                assert_eq!(task.remaining_budget()?, before);
                Ok(())
            })
        },
    )?;
    result.output?;
    let receipt = result.receipt?;
    assert_eq!(receipt.outcome, TaskOutcome::Cancelled);
    assert_eq!(
        tree.get(authority.region())?.state,
        fss_core::RegionState::Draining
    );
    let proof = authority.finalize(&mut tree, receipt.completed_at)?;
    assert_eq!(proof.total_tasks, 1);
    assert_eq!(proof.total_obligations, 0);
    Ok(())
}
