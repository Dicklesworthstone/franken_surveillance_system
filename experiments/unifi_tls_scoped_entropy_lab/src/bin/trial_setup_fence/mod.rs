#![forbid(unsafe_code)]
//! Owner-scoped inspection of laboratory attempt fences; never dispatches effects.

use super::{
    FENCE_RECOVERY_USAGE, ResultBox, epoch, pinned_camera_claim, trial_checkpoint,
    trial_http_checkpoint,
};
use asupersync::runtime::RuntimeBuilder;
use fss_core::effect::EffectState;
use fss_core::{
    BudgetVector, CanonicalDecoder, ContentDigest, OperationId, RegionId, RegionKind,
    RootAuthoritySpec, RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_reference::unifi_direct::{Identity, metered::MeteredClock};
use fss_runtime::{
    authority::AuthorityCx,
    effect::EffectCoordinator,
    execution::{TaskCompletion, TaskSpec, run_owned_async},
};
use rustix::fs::{self as rfs, Mode, OFlags};
use std::{
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};

const MAX_FILE: u64 = 16 * 1024;

fn normal_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

// Every path component is opened without following links. The caller still
// selects the storage namespace; a later rename of an open directory is not
// evidence of independent custody or rollback protection.
fn open_directory(path: &Path, private: bool) -> ResultBox<File> {
    if !normal_absolute(path) {
        return Err("invalid inspection directory".into());
    }
    let mut directory = File::open("/")?;
    for part in path.components() {
        match part {
            Component::RootDir => (),
            Component::Normal(name) => {
                directory = File::from(rfs::openat(
                    &directory,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )?);
            }
            _ => return Err("invalid inspection directory".into()),
        }
    }
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || (private && metadata.mode() & 0o077 != 0) {
        return Err("inspection directory is not private".into());
    }
    Ok(directory)
}

fn read_file(parent: &File, name: &std::ffi::OsStr, private: bool) -> ResultBox<Vec<u8>> {
    let fd = rfs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut file = File::from(fd);
    let before = file.metadata()?;
    if !before.is_file()
        || before.len() == 0
        || before.len() > MAX_FILE
        || (private && (before.mode() & 0o077 != 0 || before.nlink() != 1))
    {
        return Err("invalid inspection file".into());
    }
    let mut bytes = Vec::new();
    (&mut file).take(MAX_FILE + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != before.len()
        || before.len() != after.len()
        || (
            before.dev(),
            before.ino(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        )
    {
        return Err("inspection file changed while reading".into());
    }
    Ok(bytes)
}

struct Fence {
    run: String,
    uuid: String,
    mac: [u8; 6],
    paths: [PathBuf; 3],
}

fn decode(bytes: &[u8], claim: ContentDigest, scope: &Path) -> ResultBox<Fence> {
    let mut decoder = CanonicalDecoder::new(bytes);
    if decoder.text()? != "fss.unifi-direct.lab-setup-fence.v1" || decoder.bytes()? != claim.bytes()
    {
        return Err("setup fence identity mismatch".into());
    }
    let run = decoder.text()?;
    if run.len() != 32 || !run.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid setup fence run identity".into());
    }
    let run = run.to_owned();
    let uuid = decoder.text()?.to_owned();
    Identity::new("FSS", &uuid, "1.20.0")?;
    let mac: [u8; 6] = decoder
        .bytes()?
        .try_into()
        .map_err(|_| "invalid setup fence MAC")?;
    if mac == [0; 6] || mac[0] & 1 != 0 {
        return Err("invalid setup fence MAC".into());
    }
    let paths = [
        PathBuf::from(decoder.text()?),
        PathBuf::from(decoder.text()?),
        PathBuf::from(decoder.text()?),
    ];
    decoder.ensure_finished()?;
    if paths
        .iter()
        .any(|path| !normal_absolute(path) || path == scope || !path.starts_with(scope))
        || paths.iter().enumerate().any(|(i, path)| {
            paths
                .iter()
                .skip(i + 1)
                .any(|other| path.starts_with(other) || other.starts_with(path))
        })
    {
        return Err("setup fence journal paths are outside the authorized scope".into());
    }
    Ok(Fence {
        run,
        uuid,
        mac,
        paths,
    })
}

/// Inspect the exact operator-scoped marker and its journal; this grants no
/// dispatch, verification, settlement, fence release or physical identity.
pub(super) fn inspect(args: &[String]) -> ResultBox<()> {
    let (fence, cert, scope, checkpoints, restored, peer) = match args {
        [mode, fence, cert, scope, auth]
            if mode == "--inspect-setup-fence" && auth == "--owner-authorized" =>
        {
            (
                PathBuf::from(fence),
                PathBuf::from(cert),
                PathBuf::from(scope),
                None,
                None,
                None,
            )
        }
        [mode, fence, cert, scope, before, after, auth]
            if mode == "--inspect-setup-fence-with-checkpoints" && auth == "--owner-authorized" =>
        {
            (
                PathBuf::from(fence),
                PathBuf::from(cert),
                PathBuf::from(scope),
                Some((PathBuf::from(before), PathBuf::from(after))),
                None,
                None,
            )
        }
        [mode, fence, cert, scope, before, after, restored, auth]
            if mode == "--inspect-setup-fence-with-restored" && auth == "--owner-authorized" =>
        {
            (
                PathBuf::from(fence), PathBuf::from(cert), PathBuf::from(scope),
                Some((PathBuf::from(before), PathBuf::from(after))), Some(PathBuf::from(restored)),
                None,
            )
        }
        [mode, fence, cert, scope, before, after, restored, peer, auth]
            if mode == "--inspect-setup-fence-with-restore-request" && auth == "--owner-authorized" =>
        {
            (
                PathBuf::from(fence), PathBuf::from(cert), PathBuf::from(scope),
                Some((PathBuf::from(before), PathBuf::from(after))), Some(PathBuf::from(restored)),
                Some(peer.parse::<std::net::Ipv4Addr>()?),
            )
        }
        _ => return Err(FENCE_RECOVERY_USAGE.into()),
    };
    if !normal_absolute(&fence) || !normal_absolute(&cert) || !normal_absolute(&scope) {
        return Err("inspection paths must be absolute and normal".into());
    }
    if checkpoints.as_ref().is_some_and(|(before, after)| {
        [before, after]
            .into_iter()
            .any(|path| !normal_absolute(path) || path == &scope || !path.starts_with(&scope))
            || before == after
    }) {
        return Err("checkpoint paths must be distinct and inside the inspection scope".into());
    }
    if restored.as_ref().is_some_and(|path| {
        !normal_absolute(path) || path == &scope || !path.starts_with(&scope)
            || checkpoints.as_ref().is_none_or(|(before, after)| path == before || path == after)
    }) {
        return Err("restored checkpoint must be distinct and inside the inspection scope".into());
    }
    let (start, _) = epoch()?;
    let deadline = TimestampNs(
        start
            .0
            .checked_add(30_000_000_000)
            .ok_or("deadline overflow")?,
    );
    let mut budget = BudgetVector::ZERO;
    budget.bytes = 32 * 1024;
    budget.storage_operations = 256;
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:unifi-fence-inspection".into(),
            operation_id: OperationId::parse("operation:unifi-fence-inspection")?,
            principal: "principal:owner".into(),
            capabilities: vec![
                RuntimeGrant::AdapterAuth.as_str().into(),
                RuntimeGrant::ObjectStage.as_str().into(),
            ],
            deadline: Some(deadline),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:owner".into(),
            retention_scope: "retention:trial".into(),
            anchor_universe: ContentDigest::sha256(b"owner-authorized unifi fence inspection"),
            generation: 1,
        },
        RegionId::new("region:unifi-fence-inspection")?,
        RegionKind::Process,
        budget,
        start,
    )?;
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let task_start = TimestampNs(start.0 + 1);
        let result = run_owned_async(&mut authority, &mut tree, TaskSpec {
            task_id: TaskId::new("task:unifi-fence-inspection")?, started_at: task_start,
        }, &cx, async |task, cx| {
            let clock = match MeteredClock::new(task, cx, TimestampNs(start.0 + 2)) {
                Ok(clock) => clock,
                Err(error) => return TaskCompletion { output: Err(Box::new(error) as Box<dyn std::error::Error>), outcome: TaskOutcome::Failed("inspection clock unavailable".into()), completed_at: task_start },
            };
            let output: ResultBox<()> = async {
                let mut cost = BudgetVector::ZERO; cost.bytes = 32 * 1024; cost.storage_operations = 4;
                task.checkpoint_for(RuntimeGrant::AdapterAuth, &cert.to_string_lossy(), clock.now()?, &cost)?;
                task.checkpoint_for(RuntimeGrant::ObjectStage, &fence.to_string_lossy(), clock.now()?, &BudgetVector::ZERO)?;
                task.checkpoint_for(RuntimeGrant::ObjectStage, &scope.to_string_lossy(), clock.now()?, &BudgetVector::ZERO)?;
                let cert_parent = open_directory(cert.parent().ok_or("certificate parent missing")?, false)?;
                let cert_bytes = read_file(&cert_parent, cert.file_name().ok_or("certificate name missing")?, false)?;
                let claim = pinned_camera_claim(&cert_bytes);
                let directory = open_directory(&fence, true)?;
                let _scope_directory = open_directory(&scope, true)?;
                let name = format!("{}.fence", claim.to_text());
                let bytes = read_file(&directory, std::ffi::OsStr::new(&name), true)?;
                let retained = decode(&bytes, claim, &scope)?;
                for path in &retained.paths {
                    task.checkpoint_for(RuntimeGrant::ObjectStage, &path.to_string_lossy(), clock.now()?, &BudgetVector::ZERO)?;
                }
                let (journal, minimum) = trial_checkpoint::reopen(&retained.paths[0], &retained.paths[1], &retained.paths[2], &retained.uuid, retained.mac)?;
                let recovered = EffectCoordinator::recover(journal, minimum)?;
                let expected_operation_prefix = format!("operation:unifi-trial-{}-", retained.run);
                let mut states = [0usize; 8];
                for receipt in recovered.journal().operations() {
                    if !receipt.intent.operation_id.as_str().starts_with(&expected_operation_prefix) {
                        return Err("setup fence run does not match journal operations".into());
                    }
                    let index = match receipt.state {
                        EffectState::Prepared => 0, EffectState::Committed => 1,
                        EffectState::AdapterAccepted => 2, EffectState::Observed => 3,
                        EffectState::Verified => 4, EffectState::Cancelled => 5,
                        EffectState::Failed => 6, EffectState::Indeterminate => 7,
                    };
                    states[index] += 1;
                }
                let total: usize = states.iter().sum();
                let unresolved = states[0] + states[1] + states[2] + states[3] + states[7];
                if let Some((before, after)) = checkpoints {
                    let _before_dir = open_directory(&before, true)?;
                    let _after_dir = open_directory(&after, true)?;
                    let checkpoint_scope = trial_http_checkpoint::inspect(task, cx, clock, before.clone(), Some(after.clone()), false).await?;
                    if !checkpoint_scope.matches_camera(claim, ContentDigest::sha256(&cert_bytes)) {
                        return Err("checkpoint camera claim does not match setup fence".into());
                    }
                    let operation = OperationId::parse(format!("operation:unifi-trial-{}-http-start", retained.run))?;
                    let receipt = recovered.journal().operation(&operation).ok_or("checkpoint effect missing from journal")?;
                    if receipt.intent.effect_class != fss_reference::unifi_direct::intent::EFFECT_CLASS
                        || receipt.intent.request_digest != checkpoint_scope.request_digest()
                        || receipt.intent.precondition_digest != checkpoint_scope.precondition_digest() {
                        return Err("checkpoint does not match journaled effect".into());
                    }
                    println!("trial_fence_checkpoint_match=consistent effect_state={} settlement=none root_trust=operator_selected independence=unverified", receipt.state.as_str());
                    let acceptance = match receipt.state {
                        EffectState::AdapterAccepted if receipt.result_digest.is_some() => "present",
                        EffectState::Committed | EffectState::AdapterAccepted => "absent",
                        _ => "not_available",
                    };
                    println!("trial_fence_start_acceptance_digest={acceptance} settlement=not_inferred");
                    if let Some(restored) = restored {
                        let _restored_dir = open_directory(&restored, true)?;
                        let observed_scope = trial_http_checkpoint::inspect(task, cx, clock, after, None, false).await?;
                        let restored_scope = trial_http_checkpoint::inspect(task, cx, clock, before.clone(), Some(restored), true).await?;
                        if restored_scope != checkpoint_scope {
                            return Err("restored checkpoint scope differs".into());
                        }
                        let operation = OperationId::parse(format!("operation:unifi-trial-{}-http-restore", retained.run))?;
                        let receipt = recovered.journal().operation(&operation).ok_or("restore effect missing from journal")?;
                        if receipt.intent.effect_class != fss_reference::unifi_direct::intent::EFFECT_CLASS
                            || receipt.intent.precondition_digest != observed_scope.precondition_digest() {
                            return Err("restore effect precondition does not match observation".into());
                        }
                        println!("trial_fence_restore_precondition=consistent effect_state={} request_binding=unverified settlement=none root_trust=operator_selected independence=unverified", receipt.state.as_str());
                        let acceptance = match receipt.state {
                            EffectState::AdapterAccepted if receipt.result_digest.is_some() => "present",
                            EffectState::Committed | EffectState::AdapterAccepted => "absent",
                            _ => "not_available",
                        };
                        println!("trial_fence_restore_acceptance_digest={acceptance} settlement=not_inferred");
                        if let Some(peer) = peer {
                            trial_http_checkpoint::compare_restore_request(task, cx, clock, before, peer, receipt.intent.request_digest).await?;
                            println!("trial_fence_restore_request=matches_baseline effect_state={} settlement=none peer=operator_selected identity=unverified", receipt.state.as_str());
                        }
                    }
                }
                println!("trial_fence_inspection=reconciliation_only operations={total} unresolved={unresolved} restart_authority=none fence_trust=operator_selected root_trust=operator_selected independence=unverified");
                println!("trial_fence_effect_states prepared={} committed={} adapter_accepted={} observed={} verified={} cancelled={} failed={} indeterminate={}", states[0], states[1], states[2], states[3], states[4], states[5], states[6], states[7]);
                Ok(())
            }.await;
            let outcome = if output.is_ok() { TaskOutcome::Success } else { TaskOutcome::Failed("fence inspection refused".into()) };
            TaskCompletion { output, outcome, completed_at: clock.now().unwrap_or(deadline) }
        }).await?;
        result.receipt?;
        result.output
    })
}
