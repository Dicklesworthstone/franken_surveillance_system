#![forbid(unsafe_code)]
//! Cancellation through the public native facade, with real immutable reads and receipts.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, EffectIntent, EffectState, IdempotencyKey,
    ObligationId, OperationId, PrincipalId, RootAuthoritySpec, TimestampNs,
};
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx};

use super::RequestControl;
use crate::effect_cmd::{EffectCommand, WaitArgs};
use crate::{ExitIdentity, FssCommand, StatusArgs, execute_live_fss_with_control, parse_fss_args};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..64 {
            let path = std::env::temp_dir().join(format!(
                "fss-request-control-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("test directory capacity".into())
    }

    fn root(&self) -> PathBuf {
        self.0.join("deployment")
    }

    fn initialize(&self) -> Test<(ReferenceDeployment, ReplayCx)> {
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:request-control".to_owned(),
            operation_id: OperationId::parse("operation:request-control")?,
            principal: "principal:request-control".to_owned(),
            capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::default(),
            privacy_scope: "privacy:request-control-test".to_owned(),
            retention_scope: "retention:request-control-test".to_owned(),
            anchor_universe: ContentDigest::sha256(b"request-control-test"),
            generation: 1,
        })?;
        let cx = ReplayCx::from_context_authority_read_only(&authority, self.root())?;
        let deployment = ReferenceDeployment::open(&self.root(), "site:request-control", &cx)?;
        Ok((deployment, cx))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn tree(root: &Path) -> Test<BTreeMap<PathBuf, Option<Vec<u8>>>> {
    let mut paths = vec![root.to_owned()];
    let mut result = BTreeMap::new();
    while let Some(path) = paths.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        let contents = if metadata.is_dir() {
            for entry in fs::read_dir(&path)? {
                paths.push(entry?.path());
            }
            None
        } else if metadata.is_file() {
            Some(fs::read(&path)?)
        } else {
            return Err("unexpected fixture file type".into());
        };
        result.insert(path.strip_prefix(root)?.to_owned(), contents);
    }
    Ok(result)
}

#[test]
fn cancelled_before_dispatch_never_starts_a_command() -> Test {
    let scratch = Scratch::new("not-started")?;
    let control = RequestControl::new(&|| true);
    for command in [
        FssCommand::Help,
        FssCommand::Status(StatusArgs {
            root: Some(scratch.root()),
            ..StatusArgs::default()
        }),
        FssCommand::Effect(Box::new(EffectCommand::Wait(WaitArgs {
            root: scratch.root(),
            operation: OperationId::parse("operation:not-started")?,
            principal: PrincipalId::parse("principal:request-control")?,
            deadline_ms: 10_000,
        }))),
    ] {
        assert!(execute_live_fss_with_control(command, &control).is_none());
    }
    assert!(fs::read_dir(&scratch.0)?.next().is_none());
    assert_eq!(
        execute_live_fss_with_control(FssCommand::Help, &RequestControl::uncancelled()),
        Some(crate::execute_live_fss_with_exit(FssCommand::Help)),
    );
    Ok(())
}

#[test]
fn cancellation_after_dispatch_reaches_the_native_status_checkpoint() -> Test {
    let scratch = Scratch::new("status")?;
    let observations = AtomicUsize::new(0);
    let probe = || observations.fetch_add(1, Ordering::AcqRel) != 0;
    let command = FssCommand::Status(StatusArgs {
        root: Some(scratch.root()),
        ..StatusArgs::default()
    });
    let (body, exit) = execute_live_fss_with_control(command, &RequestControl::new(&probe))
        .ok_or("a started command lost its native outcome")?;
    assert_eq!(exit, ExitIdentity::STATUS_REFUSED);
    assert!(body.contains(crate::ERR_STATUS_CANCELLED), "{body}");
    assert!(observations.load(Ordering::Acquire) > 1);
    assert!(fs::read_dir(&scratch.0)?.next().is_none());
    Ok(())
}

#[test]
fn source_queries_stop_at_their_native_admission_instead_of_reading_an_absent_root() -> Test {
    let scratch = Scratch::new("source-read")?;
    for target in ["footage", "sources", "reports", "localizations"] {
        let observations = AtomicUsize::new(0);
        let probe = || observations.fetch_add(1, Ordering::AcqRel) != 0;
        let command = parse_fss_args([
            OsString::from("query"),
            OsString::from("--json"),
            OsString::from(format!("--target={target}")),
            OsString::from("--root"),
            scratch.root().into_os_string(),
        ])?;
        let (body, exit) = execute_live_fss_with_control(command, &RequestControl::new(&probe))
            .ok_or("a started source read lost its native refusal")?;
        assert_eq!(exit, ExitIdentity::AGENT_REFUSED, "{target}: {body}");
        assert!(
            body.contains(crate::ERR_AGENT_CONTEXT_INCOMPLETE),
            "{target}: {body}"
        );
        assert!(
            !body.contains(crate::ERR_DOCTOR_NOT_A_DEPLOYMENT),
            "{target}: {body}"
        );
        assert!(observations.load(Ordering::Acquire) > 1, "{target}");
    }
    assert!(fs::read_dir(&scratch.0)?.next().is_none());
    Ok(())
}

#[test]
fn both_follow_modes_stop_at_native_admission_without_creating_session_state() -> Test {
    let scratch = Scratch::new("follow")?;
    for subscription in [false, true] {
        let observations = AtomicUsize::new(0);
        let probe = || observations.fetch_add(1, Ordering::AcqRel) != 0;
        let mut arguments = vec![
            OsString::from("follow"),
            OsString::from("--json"),
            OsString::from("--root"),
            scratch.root().into_os_string(),
            OsString::from("--since"),
            OsString::from(
                "anchor:0123456789abcdef:3:e2:abababababababababababababababababababababababababababababababab",
            ),
            OsString::from("--wait-ms=10000"),
        ];
        if subscription {
            arguments.extend([
                OsString::from("--session=session:request-control"),
                OsString::from("--subscription=watch"),
            ]);
        }
        let command = parse_fss_args(arguments)?;
        let (body, exit) = execute_live_fss_with_control(command, &RequestControl::new(&probe))
            .ok_or("a started follow lost its native refusal")?;
        assert_eq!(exit, ExitIdentity::AGENT_REFUSED, "{body}");
        assert!(!body.contains(crate::ERR_DOCTOR_NOT_A_DEPLOYMENT), "{body}");
        assert!(observations.load(Ordering::Acquire) > 1);
        assert!(fs::read_dir(&scratch.0)?.next().is_none());
    }
    Ok(())
}

#[test]
fn cancelled_effect_observation_preserves_the_last_receipt_and_entire_deployment() -> Test {
    let scratch = Scratch::new("effect-wait")?;
    let (mut deployment, cx) = scratch.initialize()?;
    let operation = OperationId::parse("operation:request-control:effect")?;
    deployment.effects_mut().prepare(
        EffectIntent::new(
            operation.clone(),
            IdempotencyKey::parse("idempotency:request-control:effect")?,
            "fixture:notification",
            ContentDigest::sha256(b"request"),
            ContentDigest::sha256(b"preconditions"),
        )?,
        ObligationId::parse("obligation:request-control:effect")?,
        "notification observed",
        TimestampNs(1),
    )?;
    deployment.effects_mut().transition(
        &operation,
        EffectState::Committed,
        TimestampNs(2),
        None,
        None,
    )?;
    let receipt = deployment
        .effects()
        .operation(&operation)
        .ok_or("prepared effect")?
        .clone();
    // Keep the native writer held: this observer must neither acquire it nor reconcile the effect.
    let before = tree(&scratch.root())?;
    let observations = AtomicUsize::new(0);
    let probe = || observations.fetch_add(1, Ordering::AcqRel) >= 2;
    let command = FssCommand::Effect(Box::new(EffectCommand::Wait(WaitArgs {
        root: scratch.root(),
        operation: operation.clone(),
        principal: PrincipalId::parse("principal:request-control")?,
        deadline_ms: 10_000,
    })));
    let (body, exit) = execute_live_fss_with_control(command, &RequestControl::new(&probe))
        .ok_or("started observation lost its receipt")?;
    assert_eq!(exit, ExitIdentity::AGENT_REFUSED, "{body}");
    assert!(body.contains("\"outcome\":\"cancelled\""), "{body}");
    assert!(body.contains(&receipt.receipt_digest().to_text()), "{body}");
    assert!(!body.contains("ERR-OP-TIMEOUT"), "{body}");
    assert!(!body.contains("for the whole"), "{body}");
    assert_eq!(tree(&scratch.root())?, before);
    assert_eq!(deployment.effects().operation(&operation), Some(&receipt));
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn borrowed_control_observes_the_same_live_owner_signal() {
    let cancelled = AtomicBool::new(false);
    let probe = || cancelled.load(Ordering::Acquire);
    let control = RequestControl::new(&probe);
    assert!(!control.is_cancelled());
    cancelled.store(true, Ordering::Release);
    assert!(control.is_cancelled());
    assert!(!RequestControl::uncancelled().is_cancelled());
}
