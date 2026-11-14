#![forbid(unsafe_code)]
//! Bounded event archival for the owned capture trial.
//!
//! This experimental owner waits for each event publication before polling
//! the capture session again. It does not establish uninterrupted coverage,
//! authenticated device identity, physical capture time, or 30-day retention.

use std::{fmt, path::Path, sync::Arc};

use asupersync::Cx;
use fss_container::flv_avc::SourceKey;
use fss_core::{BudgetVector, ContentDigest, RuntimeGrant, region::ContextAuthority};
use fss_object::{
    HostSpoolIo,
    effect_journal::{EffectJournalLimits, FileEffectJournal},
};
use fss_reference::{
    ReferenceDeployment, ReplayCx,
    unifi_direct::{
        archive,
        event_worker::{self, Input},
        events::Frame,
        metered::MeteredClock,
    },
};
use fss_runtime::execution::TaskCx;

use super::{Retention, anchor_scope};

/// Storage and the single task-owned event in this bounded trial.
#[must_use = "drain and inspect event archive custody"]
pub(super) struct Archive {
    worker: Option<event_worker::Worker>,
    retired: Option<event_worker::Retirement>,
    source: SourceKey,
    camera: ContentDigest,
    confirmed: usize,
    running: bool,
    unaccepted: Option<Input>,
    pending_digest: Option<ContentDigest>,
    pins: Vec<(archive::UnknownTimePin, ContentDigest)>,
    access: Arc<Retention>,
    failure: Option<event_worker::Completion>,
}

/// A failure returns the event, any publication receipt, and storage owners.
#[must_use = "retain the event archive failure for inspection and reconciliation"]
pub(super) struct Failure {
    reason: &'static str,
    owner: Box<Archive>,
}
impl fmt::Debug for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventArchiveFailure")
            .field("reason", &self.reason)
            .field(
                "source_retained",
                &(self.owner.pending_digest.is_some() || self.owner.unaccepted.is_some()),
            )
            .field("completion_retained", &self.owner.failure.is_some())
            .finish_non_exhaustive()
    }
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason)
    }
}
impl std::error::Error for Failure {}

impl Archive {
    /// Create a fresh dedicated event store under the already-created run root.
    pub(super) fn create<'scope, 'task>(
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        root: &Path,
        storage_authority: &ContextAuthority,
        source: SourceKey,
        camera: ContentDigest,
        retention: ContentDigest,
        access: Arc<Retention>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if !clock.matches(task, cx) {
            return Err("event archive context mismatch".into());
        }
        let resource = root.to_str().ok_or("event archive path is not UTF-8")?;
        task.checkpoint_for(
            RuntimeGrant::ObjectStage,
            resource,
            clock.now()?,
            &BudgetVector::ZERO,
        )?;
        let replay = ReplayCx::from_context_authority(storage_authority, root.to_path_buf())?;
        let deployment = ReferenceDeployment::open(
            &root.join("event-deployment"),
            "site:unifi-owned-event",
            &replay,
        )?;
        let journal_store = FileEffectJournal::create(
            root.join("event-journal"),
            EffectJournalLimits::default(),
            Arc::new(HostSpoolIo),
        )?;
        let journal = archive::journal::UnknownTimeJournal::create(
            Box::new(journal_store),
            anchor_scope("event-journal", camera)?,
            &replay,
        )?;
        let keeper_store = FileEffectJournal::create(
            root.join("event-keeper"),
            EffectJournalLimits::default(),
            Arc::new(HostSpoolIo),
        )?;
        let keeper = archive::journal::UnknownTimeAnchorKeeper::create(
            Box::new(keeper_store),
            &journal,
            &replay,
        )?;
        let authority: Arc<dyn archive::RetainAuthority + Send + Sync> = access.clone();
        let worker = event_worker::Worker::new(event_worker::Parts {
            deployment,
            journal,
            keeper,
            replay,
            authority,
            retention,
            limits: archive::Limits::default(),
            max_event_bytes: fss_reference::unifi_direct::MAX_MESSAGE_BYTES,
            work_limit: 4_000_000_000,
        })
        .map_err(|_| "event archive worker configuration refused")?;
        let mut pins = Vec::new();
        pins.try_reserve_exact(1024)?;
        Ok(Self {
            worker: Some(worker),
            retired: None,
            source,
            camera,
            confirmed: 0,
            running: false,
            unaccepted: None,
            pending_digest: None,
            pins,
            access,
            failure: None,
        })
    }

    /// Retain one exact camera event before advancing the capture session.
    /// A refusal leaves the original source held by this owner for inspection.
    pub(super) fn begin<'scope, 'task>(
        &mut self,
        frame: Frame,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        resource: &str,
    ) -> Result<(), &'static str> {
        let digest = frame.digest();
        let worker = self
            .worker
            .as_mut()
            .ok_or("event archive already retired")?;
        if let Err(refusal) = worker.offer(Input::Original {
            frame,
            key: self.source,
            camera_claim: self.camera,
        }) {
            self.unaccepted = Some(match refusal {
                event_worker::OfferRefusal::Busy(input)
                | event_worker::OfferRefusal::Invalid(input)
                | event_worker::OfferRefusal::Fenced(input) => input,
            });
            return Err("event archive offer refused; source requires reconciliation");
        }
        self.pending_digest = Some(digest);
        if self.confirmed >= 1024 {
            return Err("event archive run limit reached; source requires reconciliation");
        }
        worker
            .start(task, cx, clock, resource, &BudgetVector::ZERO)
            .map_err(|_| "event archive admission refused; pending source requires recovery")?;
        self.running = true;
        Ok(())
    }

    /// Drain the started publication and account for its actual outcome.
    pub(super) async fn complete(&mut self) -> Result<(), &'static str> {
        if !self.running {
            return Err("event archive attempt not running");
        }
        let completion = self
            .worker
            .as_mut()
            .ok_or("event archive already retired")?
            .join()
            .await
            .ok_or("event archive completion unavailable")?;
        self.running = false;
        if completion.runtime.is_err() {
            self.failure = Some(completion);
            return Err("event archive refused; pending source requires recovery");
        }
        let pin = match completion.outcome {
            event_worker::Outcome::Publication(event_worker::Publication::Published {
                pin,
                ..
            }) => pin,
            outcome => {
                self.failure = Some(event_worker::Completion {
                    runtime: completion.runtime,
                    outcome,
                });
                return Err("event archive refused; pending source requires recovery");
            }
        };
        let digest = self
            .pending_digest
            .take()
            .ok_or("event archive digest missing")?;
        self.pins.push((pin, digest));
        self.confirmed += 1;
        Ok(())
    }

    /// Inspect and return all storage owners after all work has drained.
    pub(super) async fn finish<'scope, 'task>(
        mut self,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        resource: &str,
    ) -> Result<usize, Failure> {
        if self.running {
            if let Err(reason) = self.complete().await {
                return Err(Failure {
                    reason,
                    owner: Box::new(self),
                });
            }
        }
        if self.failure.is_some() || self.unaccepted.is_some() {
            return Err(Failure {
                reason: "event archive source requires reconciliation",
                owner: Box::new(self),
            });
        }
        let Some(worker) = self.worker.take() else {
            return Err(Failure {
                reason: "event archive worker unavailable",
                owner: Box::new(self),
            });
        };
        self.retired = match worker.retire() {
            Ok(retired) => Some(retired),
            Err(worker) => {
                self.worker = Some(worker);
                return Err(Failure {
                    reason: "event archive work did not drain",
                    owner: Box::new(self),
                });
            }
        };
        if self
            .retired
            .as_ref()
            .is_some_and(|retired| retired.pending.is_some() || retired.fenced)
        {
            return Err(Failure {
                reason: "event archive source requires reconciliation",
                owner: Box::new(self),
            });
        }
        if !clock.matches(task, cx) {
            return Err(Failure {
                reason: "event archive readback context mismatch",
                owner: Box::new(self),
            });
        }
        let verification = (|| -> Result<(), &'static str> {
            let retired = self
                .retired
                .as_mut()
                .ok_or("event archive storage unavailable")?;
            for (pin, digest) in &self.pins {
                task.checkpoint_for(
                    RuntimeGrant::ReadMedia,
                    resource,
                    clock
                        .now()
                        .map_err(|_| "event readback clock unavailable")?,
                    &BudgetVector::ZERO,
                )
                .map_err(|_| "event readback authority refused")?;
                let recovered = archive::read_unknown_time_event(
                    &mut retired.parts.deployment,
                    *pin,
                    self.access.as_ref(),
                    archive::Limits::default(),
                    &mut fss_geometry::WorkBudget::new(4_000_000_000),
                    &retired.parts.replay,
                )
                .map_err(|_| "event readback failed")?;
                if recovered.key() != self.source
                    || recovered.camera_claim() != self.camera
                    || recovered.frame().digest() != *digest
                {
                    return Err("event readback source mismatch");
                }
            }
            Ok(())
        })();
        if let Err(reason) = verification {
            return Err(Failure {
                reason,
                owner: Box::new(self),
            });
        }
        Ok(self.confirmed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::{bytes::Bytes, runtime::RuntimeBuilder};
    use fss_core::{
        OperationId, RegionId, RegionKind, RootAuthoritySpec, TaskId, TaskOutcome, TimestampNs,
    };
    use fss_runtime::{
        authority::AuthorityCx,
        execution::{TaskCompletion, TaskSpec, run_owned_async},
    };
    use std::{error::Error, os::unix::fs::PermissionsExt, path::PathBuf};

    fn exercise(policy_denied: bool, root_variable: &str) -> Result<(), Box<dyn Error>> {
        let root = PathBuf::from(std::env::var_os(root_variable).ok_or("missing test root")?);
        if !root.is_absolute()
            || !root.is_dir()
            || std::fs::metadata(&root)?.permissions().mode() & 0o077 != 0
        {
            return Err("expected private existing test root".into());
        }
        let budget = BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(1000)
            .build()?;
        let camera = ContentDigest::sha256(b"failure fixture camera");
        let spec =
            |name: &str, capabilities: Vec<String>| -> Result<RootAuthoritySpec, Box<dyn Error>> {
                Ok(RootAuthoritySpec {
                    trace_id: format!("trace:{name}"),
                    operation_id: OperationId::parse(format!("operation:{name}"))?,
                    principal: "principal:fixture".into(),
                    capabilities,
                    deadline: None,
                    priority: 1,
                    budgets: budget,
                    privacy_scope: "privacy:test".into(),
                    retention_scope: "retention:test".into(),
                    anchor_universe: camera,
                    generation: 1,
                })
            };
        let storage = ContextAuthority::new_root(spec(
            "event-failure-storage",
            vec!["ADP-REPLAY-001".into()],
        )?)?;
        let mut grants = vec![RuntimeGrant::ObjectStage.as_str().into()];
        if policy_denied {
            grants.push(RuntimeGrant::ObjectPublish.as_str().into());
        }
        let (mut authority, mut tree) = AuthorityCx::root(
            spec("event-failure-task", grants)?,
            RegionId::new("region:event-failure")?,
            RegionKind::Process,
            budget,
            TimestampNs(1),
        )?;
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(1, 1)
            .build()?;
        runtime.block_on(async {
            let cx = Cx::current().ok_or("missing runtime")?;
            let run = run_owned_async(&mut authority, &mut tree, TaskSpec { task_id: TaskId::new("task:event-failure")?, started_at: TimestampNs(2) }, &cx, async |task, cx| {
                let output: Result<(), String> = async {
                    let clock = MeteredClock::new(task, cx, TimestampNs(3)).map_err(|e| e.to_string())?;
                    let source = Bytes::from_static(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"EventSmartAudio","messageId":7,"responseExpected":false,"payload":{"levelDb":-40}}"#);
                    let frame = Frame::from_untrusted_source(source.clone()).map_err(|_| "fixture event refused")?;
                    let retention = ContentDigest::sha256(b"failure fixture retention");
                    let key = SourceKey { connection: 1, generation: 1 };
                    let allowed = if policy_denied { ContentDigest::sha256(b"different retention") } else { retention };
                    let mut archive = Archive::create(task, cx, clock, &root, &storage, key, camera, retention, Arc::new(Retention(allowed))).map_err(|e| e.to_string())?;
                    let started = archive.begin(frame, task, cx, clock, "fixture:event");
                    if policy_denied {
                        started.map_err(str::to_string)?;
                        if archive.complete().await.is_ok() { return Err("retention refusal was accepted".into()); }
                    } else if started.is_ok() { return Err("publication without grant was accepted".into()); }
                    let failure = match archive.finish(task, cx, clock, "fixture:event").await {
                        Ok(_) => return Err("pending event was reported as complete".into()),
                        Err(failure) => failure,
                    };
                    let mut owner = *failure.owner;
                    if policy_denied && !matches!(owner.failure.as_ref().map(|c| &c.outcome), Some(event_worker::Outcome::Publication(event_worker::Publication::Refused { .. }))) {
                        return Err("publication refusal was not retained".into());
                    }
                    if let Some(worker) = owner.worker.take() {
                        owner.retired = Some(worker.retire().map_err(|_| "worker custody lost")?);
                    }
                    let retained = owner.retired.as_ref().and_then(|parts| parts.pending.as_ref()).ok_or("pending event custody lost")?;
                    match retained {
                        Input::Original { frame, key: retained_key, camera_claim } if frame.source() == source.as_ref() && *retained_key == key && *camera_claim == camera => Ok(()),
                        _ => Err("returned event or binding changed".into()),
                    }
                }.await;
                let outcome = if output.is_ok() { TaskOutcome::Success } else { TaskOutcome::Failed("event failure fixture failed".into()) };
                TaskCompletion { output, outcome, completed_at: TimestampNs(60_000_000_000) }
            }).await?;
            run.receipt?;
            run.output.map_err(|e| -> Box<dyn Error> { e.into() })
        })?;
        Ok(())
    }

    #[test]
    #[ignore = "requires a fresh private FSS_EVENT_TRIAL_FAILURE_ROOT; retains test files"]
    fn denied_admission_returns_exact_event_and_storage_custody() -> Result<(), Box<dyn Error>> {
        exercise(false, "FSS_EVENT_TRIAL_FAILURE_ROOT")
    }

    #[test]
    #[ignore = "requires a fresh private FSS_EVENT_TRIAL_POLICY_FAILURE_ROOT; retains test files"]
    fn denied_retention_returns_exact_event_and_failure() -> Result<(), Box<dyn Error>> {
        exercise(true, "FSS_EVENT_TRIAL_POLICY_FAILURE_ROOT")
    }

    #[test]
    #[ignore = "requires a private FSS_PASSIVE_EVENT_ROOT and one bounded source frame on stdin"]
    fn passive_unattributed_event_archives_and_reads_back() -> Result<(), Box<dyn Error>> {
        use std::io::Read;
        let root =
            PathBuf::from(std::env::var_os("FSS_PASSIVE_EVENT_ROOT").ok_or("missing test root")?);
        if !root.is_absolute()
            || !root.is_dir()
            || std::fs::metadata(&root)?.permissions().mode() & 0o077 != 0
        {
            return Err("expected private existing test root".into());
        }
        let mut input = std::io::stdin().lock();
        let mut header = [0_u8; 4];
        input.read_exact(&mut header)?;
        let len = u32::from_be_bytes(header) as usize;
        if !(1..=4096).contains(&len) {
            return Err("invalid passive event bound".into());
        }
        let mut bytes = vec![0_u8; len];
        input.read_exact(&mut bytes)?;
        let frame = Frame::from_untrusted_source(Bytes::from(bytes))
            .map_err(|_| "passive event refused")?;
        let budget = BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(1000)
            .build()?;
        let camera_claim = ContentDigest::sha256(b"unattributed passive controller event");
        let retention = ContentDigest::sha256(b"owner approved passive event diagnostic");
        let spec =
            |name: &str, capabilities: Vec<String>| -> Result<RootAuthoritySpec, Box<dyn Error>> {
                Ok(RootAuthoritySpec {
                    trace_id: format!("trace:{name}"),
                    operation_id: OperationId::parse(format!("operation:{name}"))?,
                    principal: "principal:owner".into(),
                    capabilities,
                    deadline: None,
                    priority: 1,
                    budgets: budget,
                    privacy_scope: "privacy:owner".into(),
                    retention_scope: "retention:diagnostic".into(),
                    anchor_universe: camera_claim,
                    generation: 1,
                })
            };
        let storage = ContextAuthority::new_root(spec(
            "passive-event-storage",
            vec!["ADP-REPLAY-001".into()],
        )?)?;
        let grants = vec![
            RuntimeGrant::ObjectStage.as_str().into(),
            RuntimeGrant::ObjectPublish.as_str().into(),
            RuntimeGrant::ReadMedia.as_str().into(),
        ];
        let (mut authority, mut tree) = AuthorityCx::root(
            spec("passive-event-task", grants)?,
            RegionId::new("region:passive-event")?,
            RegionKind::Process,
            budget,
            TimestampNs(1),
        )?;
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(1, 1)
            .build()?;
        runtime.block_on(async {
            let cx = Cx::current().ok_or("missing runtime")?;
            let run = run_owned_async(
                &mut authority,
                &mut tree,
                TaskSpec {
                    task_id: TaskId::new("task:passive-event")?,
                    started_at: TimestampNs(2),
                },
                &cx,
                async |task, cx| {
                    let output: Result<(), String> = async {
                        let clock = MeteredClock::new(task, cx, TimestampNs(3))
                            .map_err(|e| e.to_string())?;
                        let key = SourceKey {
                            connection: 1,
                            generation: 1,
                        };
                        let mut archive = Archive::create(
                            task,
                            cx,
                            clock,
                            &root,
                            &storage,
                            key,
                            camera_claim,
                            retention,
                            Arc::new(Retention(retention)),
                        )
                        .map_err(|e| e.to_string())?;
                        archive
                            .begin(frame, task, cx, clock, "passive:event")
                            .map_err(str::to_string)?;
                        archive.complete().await.map_err(str::to_string)?;
                        if archive
                            .finish(task, cx, clock, "passive:event")
                            .await
                            .map_err(|e| e.to_string())?
                            != 1
                        {
                            return Err("passive event count mismatch".into());
                        }
                        Ok(())
                    }
                    .await;
                    let outcome = if output.is_ok() {
                        TaskOutcome::Success
                    } else {
                        TaskOutcome::Failed("passive event archive failed".into())
                    };
                    TaskCompletion {
                        output,
                        outcome,
                        completed_at: TimestampNs(60_000_000_000),
                    }
                },
            )
            .await?;
            run.receipt?;
            run.output.map_err(|e| -> Box<dyn Error> { e.into() })
        })?;
        println!(
            "passive_event_archive=verified count=1 camera_identity=unattributed capture_bounds=unknown"
        );
        Ok(())
    }
}
