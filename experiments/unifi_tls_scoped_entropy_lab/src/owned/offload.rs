#![forbid(unsafe_code)]
//! Explicitly owned, drainable Linux entropy acquisition experiment.
//!
//! The caller must keep the acquisition owner until `join` has completed,
//! including after `abort`. Dropping this owner requests cancellation but cannot
//! synchronously drain an already-running system call. This is not production
//! admission or proof of all cancellation schedules.
use super::{MAX_ENTROPY, O_CLOEXEC, O_NOFOLLOW, Pool, admitted};
use asupersync::Cx;
use fss_core::BudgetVector;
use fss_reference::unifi_direct::metered::MeteredClock;
use fss_runtime::{
    drained_blocking::{self, Drained, WorkOutcome},
    execution::TaskCx,
};
use rustls::crypto::SecureRandom;
use std::{
    fs::OpenOptions,
    io::{self, Read},
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    sync::Arc,
};
use zeroize::Zeroizing;

type Bytes = Zeroizing<Vec<u8>>;
type Work = Box<dyn FnOnce(Cx) -> io::Result<Bytes> + Send + 'static>;

fn read_entropy(cx: Cx, len: usize) -> io::Result<Bytes> {
    cx.checkpoint().map_err(|_| io::ErrorKind::Interrupted)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    bytes.resize(len, 0);
    let mut bytes = Zeroizing::new(bytes);
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_CLOEXEC)
        .open("/dev/urandom")?;
    cx.checkpoint().map_err(|_| io::ErrorKind::Interrupted)?;
    let metadata = source.metadata()?;
    if !metadata.file_type().is_char_device() || metadata.rdev() != 0x109 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut offset = 0;
    for _ in 0..16 {
        cx.checkpoint().map_err(|_| io::ErrorKind::Interrupted)?;
        let result = source.read(&mut bytes[offset..]);
        cx.checkpoint().map_err(|_| io::ErrorKind::Interrupted)?;
        match result {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => {
                offset += n;
                if offset == len {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => (),
            Err(e) => return Err(e),
        }
    }
    if offset != len {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(bytes)
}

/// A one-use source tied to the exact task, runtime context, clock and resource.
/// Dropping it clears its remaining bytes; it does not authenticate any peer.
#[must_use]
pub struct Lease<'scope, 'task> {
    pub(super) task: &'scope TaskCx<'task>,
    pub(super) cx: &'scope Cx,
    pub(super) clock: MeteredClock<'scope, 'task>,
    pub(super) resource: &'scope str,
    pub(super) pool: Option<Arc<Pool>>,
}
impl Drop for Lease<'_, '_> {
    fn drop(&mut self) {
        if let Some(pool) = &self.pool {
            pool.close();
        }
    }
}
impl<'scope, 'task> Lease<'scope, 'task> {
    /// Check exact authority and clock mapping before transferring the lease.
    pub fn matches(
        &self,
        task: &TaskCx<'task>,
        cx: &Cx,
        clock: &MeteredClock<'_, 'task>,
        resource: &str,
    ) -> bool {
        std::ptr::eq(self.task, task)
            && std::ptr::eq(self.cx, cx)
            && self.clock.same_mapping(clock)
            && self.resource == resource
            && self.pool.is_some()
    }
    /// Exact authority resource, never entropy bytes.
    pub fn resource(&self) -> &str {
        self.resource
    }
    /// Consume a lease scoped specifically to the laboratory trial run ID.
    /// The returned nonce is public and must not be reused as TLS entropy.
    /// Authority and cancellation are checked both before and after the draw;
    /// the pool and any unused bytes are closed on all paths.
    pub fn trial_public_nonce(self) -> io::Result<[u8; 16]> {
        if self.resource != "trial:run-identity-entropy" {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let (task, cx, clock, resource, pool) = self.into_parts()?;
        admitted(task, cx, clock, resource, &BudgetVector::ZERO)?;
        let mut nonce = Zeroizing::new([0u8; 16]);
        pool.fill(nonce.as_mut())
            .map_err(|_| io::ErrorKind::Other)?;
        admitted(task, cx, clock, resource, &BudgetVector::ZERO)?;
        pool.close();
        Ok(*nonce)
    }
    pub(super) fn into_parts(
        mut self,
    ) -> io::Result<(
        &'scope TaskCx<'task>,
        &'scope Cx,
        MeteredClock<'scope, 'task>,
        &'scope str,
        Arc<Pool>,
    )> {
        let pool = self.pool.take().ok_or(io::ErrorKind::InvalidInput)?;
        Ok((self.task, self.cx, self.clock, self.resource, pool))
    }
}

/// Caller-owned work. Cancel by `abort`, then retain and `join` the owner.
#[must_use = "retain and join the acquisition, including after cancellation"]
pub struct Acquisition<'scope, 'task> {
    job: Drained<Work, io::Result<Bytes>>,
    task: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    resource: &'scope str,
    len: usize,
    aborted: bool,
    joined: bool,
}
impl<'scope, 'task> Acquisition<'scope, 'task> {
    /// Whether the worker's terminal receipt has been consumed by `join`.
    pub fn is_drained(&self) -> bool {
        self.joined
    }

    /// Check the intended authority binding without consuming or joining work.
    pub fn matches(
        &self,
        task: &TaskCx<'task>,
        cx: &Cx,
        clock: &MeteredClock<'_, 'task>,
        resource: &str,
    ) -> bool {
        std::ptr::eq(self.task, task)
            && std::ptr::eq(self.cx, cx)
            && self.clock.same_mapping(clock)
            && self.resource == resource
            && !self.joined
            && !self.aborted
    }
    /// Check and debit the exact task/resource budget before pool admission.
    /// Refuses when no runtime-owned blocking pool exists; no inline fallback.
    pub fn begin(
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        resource: &'scope str,
        len: usize,
    ) -> io::Result<Self> {
        if !(1..=MAX_ENTROPY).contains(&len) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let work: Work = Box::new(move |child| read_entropy(child, len));
        Self::begin_with(task, cx, clock, resource, len, work)
    }
    fn begin_with(
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        resource: &'scope str,
        len: usize,
        work: Work,
    ) -> io::Result<Self> {
        if !(1..=MAX_ENTROPY).contains(&len) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if cx.blocking_pool_handle().is_none() {
            return Err(io::ErrorKind::Unsupported.into());
        }
        let mut cost = BudgetVector::ZERO;
        cost.bytes = len as u64;
        admitted(task, cx, clock, resource, &cost)?;
        let job = drained_blocking::start(cx, work).map_err(|refusal| match refusal.reason {
            drained_blocking::StartFailure::Cancelled => io::ErrorKind::Interrupted,
            drained_blocking::StartFailure::NoPool => io::ErrorKind::Unsupported,
            drained_blocking::StartFailure::Spawn(_) => io::ErrorKind::WouldBlock,
        })?;
        Ok(Self {
            job,
            task,
            cx,
            clock,
            resource,
            len,
            aborted: false,
            joined: false,
        })
    }
    /// Request cancellation without discarding ownership of the in-flight job.
    pub fn abort(&mut self) {
        self.aborted = true;
        self.job.abort();
    }
    /// Wait for the worker to stop, then recheck task authority before returning
    /// the lease. Dropping this borrowing wait retains the owner for rejoining.
    pub async fn join(&mut self) -> io::Result<Lease<'scope, 'task>> {
        if self.joined {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let receipt = self.job.join().await.ok_or(io::ErrorKind::InvalidInput)?;
        self.joined = true;
        if self.aborted || receipt.runtime.is_err() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let bytes = match receipt.work {
            WorkOutcome::Finished(result) => result?,
            WorkOutcome::NotStarted(_) => return Err(io::ErrorKind::Interrupted.into()),
            WorkOutcome::Panicked | WorkOutcome::Indeterminate => {
                return Err(io::ErrorKind::Other.into());
            }
        };
        if bytes.len() != self.len {
            return Err(io::ErrorKind::InvalidData.into());
        }
        admitted(
            self.task,
            self.cx,
            self.clock,
            self.resource,
            &BudgetVector::ZERO,
        )?;
        let pool = Arc::new(Pool::from_bytes(self.cx, bytes)?);
        Ok(Lease {
            task: self.task,
            cx: self.cx,
            clock: self.clock,
            resource: self.resource,
            pool: Some(pool),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::{
        runtime::{RuntimeBuilder, yield_now},
        time::timeout,
    };
    use fss_core::{
        ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec, RuntimeGrant, TaskId,
        TaskOutcome, TimestampNs,
    };
    use fss_runtime::{
        authority::AuthorityCx,
        execution::{TaskCompletion, TaskSpec, run_owned_async},
    };
    use std::{
        future::{Future, poll_fn},
        pin::pin,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        task::Poll,
        time::Duration,
    };
    type Test = Result<(), Box<dyn std::error::Error>>;
    fn authority() -> Result<(AuthorityCx, fss_core::RegionTree), Box<dyn std::error::Error>> {
        let mut budget = BudgetVector::ZERO;
        budget.bytes = 4096;
        Ok(AuthorityCx::root(
            RootAuthoritySpec {
                trace_id: "trace:offload-owner".into(),
                operation_id: OperationId::parse("operation:offload-owner")?,
                principal: "principal:fixture".into(),
                capabilities: vec![RuntimeGrant::AdapterAuth.as_str().into()],
                deadline: Some(TimestampNs(30_000_000_000)),
                priority: 1,
                budgets: budget,
                privacy_scope: "privacy:test".into(),
                retention_scope: "retention:test".into(),
                anchor_universe: ContentDigest::sha256(b"fixture"),
                generation: 1,
            },
            RegionId::new("region:offload-owner")?,
            RegionKind::Process,
            budget,
            TimestampNs(1),
        )?)
    }
    #[test]
    fn missing_blocking_pool_refuses_without_inline_work() -> Test {
        let (mut authority, mut tree) = authority()?;
        RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()?
            .block_on(async {
                let cx = Cx::current().ok_or("missing context")?;
                let run = run_owned_async(
                    &mut authority,
                    &mut tree,
                    TaskSpec {
                        task_id: TaskId::new("task:no-pool")?,
                        started_at: TimestampNs(2),
                    },
                    &cx,
                    async |task, cx| {
                        let output: Test = (|| {
                            let clock = MeteredClock::new(task, cx, TimestampNs(3))?;
                            match Acquisition::begin(task, cx, clock, "fixture:no-pool", 128) {
                                Err(error) if error.kind() == io::ErrorKind::Unsupported => Ok(()),
                                _ => Err("missing pool not refused".into()),
                            }
                        })();
                        let outcome = if output.is_ok() {
                            TaskOutcome::Success
                        } else {
                            TaskOutcome::Failed("no-pool fixture".into())
                        };
                        TaskCompletion {
                            output,
                            outcome,
                            completed_at: TimestampNs(29_000_000_000),
                        }
                    },
                )
                .await?;
                run.receipt?;
                run.output
            })
    }
    #[test]
    fn abort_retains_started_work_until_actual_release() -> Test {
        let (mut authority, mut tree) = authority()?;
        RuntimeBuilder::current_thread().blocking_threads(1,1).build()?.block_on(async {
            let cx=Cx::current().ok_or("missing context")?;
            let run=run_owned_async(&mut authority,&mut tree,TaskSpec {task_id:TaskId::new("task:drain")?,started_at:TimestampNs(2)},&cx,async |task,cx| {
                let output: Test=async {
                    let clock=MeteredClock::new(task,cx,TimestampNs(3))?;
                    let entered=Arc::new(AtomicBool::new(false));let worker_entered=entered.clone();
                    let (release_tx,release_rx)=mpsc::channel();
                    let work: Work=Box::new(move |_| {
                        worker_entered.store(true,Ordering::Release);
                        release_rx.recv_timeout(Duration::from_secs(5)).map_err(|_|io::ErrorKind::TimedOut)?;
                        Ok(Zeroizing::new(vec![0x5a;128]))
                    });
                    let mut owner=Acquisition::begin_with(task,cx,clock,"fixture:drain",128,work)?;
                    timeout(cx.now(),Duration::from_secs(5),async {while !entered.load(Ordering::Acquire) {yield_now().await;}}).await?;
                    owner.abort();
                    let pending=poll_fn(|context|{let mut wait=pin!(owner.join());Poll::Ready(wait.as_mut().poll(context).is_pending())}).await;
                    assert!(pending,"join finished before the worker released");
                    release_tx.send(())?;
                    let result=timeout(cx.now(),Duration::from_secs(5),owner.join()).await?;
                    assert!(matches!(result,Err(error) if error.kind()==io::ErrorKind::Interrupted));
                    assert!(owner.join().await.is_err());
                    Ok(())
                }.await;
                let outcome=if output.is_ok(){TaskOutcome::Success}else{TaskOutcome::Failed("drain fixture".into())};
                TaskCompletion {output,outcome,completed_at:TimestampNs(29_000_000_000)}
            }).await?;run.receipt?;run.output
        })
    }
    #[test]
    fn lease_rejects_different_clock_mapping_and_resource() -> Test {
        let (mut authority, mut tree) = authority()?;
        RuntimeBuilder::current_thread()
            .blocking_threads(1, 1)
            .build()?
            .block_on(async {
                let cx = Cx::current().ok_or("missing context")?;
                let run = run_owned_async(
                    &mut authority,
                    &mut tree,
                    TaskSpec {
                        task_id: TaskId::new("task:lease-binding")?,
                        started_at: TimestampNs(2),
                    },
                    &cx,
                    async |task, cx| {
                        let output: Test = async {
                            let clock = MeteredClock::new(task, cx, TimestampNs(3))?;
                            let mut owner =
                                Acquisition::begin(task, cx, clock, "fixture:binding", 128)?;
                            let lease =
                                timeout(cx.now(), Duration::from_secs(5), owner.join()).await??;
                            let other = MeteredClock::new(task, cx, TimestampNs(2))?;
                            assert!(lease.matches(task, cx, &clock, "fixture:binding"));
                            assert!(!lease.matches(task, cx, &other, "fixture:binding"));
                            assert!(!lease.matches(task, cx, &clock, "fixture:other"));
                            Ok(())
                        }
                        .await;
                        let outcome = if output.is_ok() {
                            TaskOutcome::Success
                        } else {
                            TaskOutcome::Failed("lease-binding fixture".into())
                        };
                        TaskCompletion {
                            output,
                            outcome,
                            completed_at: TimestampNs(29_000_000_000),
                        }
                    },
                )
                .await?;
                run.receipt?;
                run.output
            })
    }

    #[test]
    fn trial_nonce_is_scoped_consumed_and_cleared() -> Test {
        let (mut authority, mut tree) = authority()?;
        RuntimeBuilder::current_thread().blocking_threads(1, 1).build()?.block_on(async {
            let cx = Cx::current().ok_or("missing context")?;
            let run = run_owned_async(&mut authority, &mut tree, TaskSpec {
                task_id: TaskId::new("task:trial-nonce")?, started_at: TimestampNs(2),
            }, &cx, async |task, cx| {
                let output: Test = async {
                    let clock = MeteredClock::new(task, cx, TimestampNs(3))?;
                    let work: Work = Box::new(|_| Ok(Zeroizing::new(vec![0x5a; 32])));
                    let mut acquisition = Acquisition::begin_with(task, cx, clock, "trial:run-identity-entropy", 32, work)?;
                    let lease = timeout(cx.now(), Duration::from_secs(5), acquisition.join()).await??;
                    let pool = lease.pool.as_ref().ok_or("missing pool")?.clone();
                    assert_eq!(lease.trial_public_nonce()?, [0x5a; 16]);
                    assert!(!pool.live.load(Ordering::SeqCst));
                    assert!(pool.data.iter().all(|byte| byte.load(Ordering::SeqCst) == 0));

                    let work: Work = Box::new(|_| Ok(Zeroizing::new(vec![0x6a; 32])));
                    let mut wrong = Acquisition::begin_with(task, cx, clock, "fixture:other", 32, work)?;
                    let lease = timeout(cx.now(), Duration::from_secs(5), wrong.join()).await??;
                    let pool = lease.pool.as_ref().ok_or("missing pool")?.clone();
                    assert!(matches!(lease.trial_public_nonce(), Err(error) if error.kind() == io::ErrorKind::PermissionDenied));
                    assert!(!pool.live.load(Ordering::SeqCst));
                    assert!(pool.data.iter().all(|byte| byte.load(Ordering::SeqCst) == 0));

                    let work: Work = Box::new(|_| Ok(Zeroizing::new(vec![0x7a; 8])));
                    let mut short = Acquisition::begin_with(task, cx, clock, "trial:run-identity-entropy", 8, work)?;
                    let lease = timeout(cx.now(), Duration::from_secs(5), short.join()).await??;
                    let pool = lease.pool.as_ref().ok_or("missing pool")?.clone();
                    assert!(lease.trial_public_nonce().is_err());
                    assert!(!pool.live.load(Ordering::SeqCst));
                    assert!(pool.data.iter().all(|byte| byte.load(Ordering::SeqCst) == 0));
                    Ok(())
                }.await;
                let outcome = if output.is_ok() { TaskOutcome::Success } else { TaskOutcome::Failed("nonce fixture".into()) };
                TaskCompletion { output, outcome, completed_at: TimestampNs(29_000_000_000) }
            }).await?;
            run.receipt?;
            run.output
        })
    }
}
