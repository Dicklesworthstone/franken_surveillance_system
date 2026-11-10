#![forbid(unsafe_code)]
//! Fresh, bounded storage owners for a UniFi recording session.
//!
//! Creation is exclusive and may leave a partial directory on failure. It is
//! not a recovery operation and must never overwrite or reopen earlier state.
//! The caller retains the path for inspection and separately supplies the
//! retention decision and scoped replay authorities.

use std::{path::Path, sync::Arc};

use asupersync::Cx;
use fss_container::flv_avc::SourceKey;
use fss_core::{BudgetVector, ContentDigest, DigestAlgorithm, RuntimeGrant};
use fss_object::{
    HostSpoolIo,
    effect_journal::{EffectJournalLimits, FileEffectJournal},
};
use fss_runtime::{
    effect_journal::{
        EffectJournalPin, EffectJournalStore, EffectPersistenceError, EffectPinRetainer,
        PinRetainedEffectJournal,
    },
    execution::TaskCx,
};

use super::{
    archive, av_unknown_worker_guard, metered::MeteredClock, source_coordinator, source_worker,
};
use crate::{DeploymentLimits, ReferenceDeployment, ReplayCx};

/// Canonically retained restart boundaries for recovered recording owners.
pub mod boundary;

/// Caller-selected source identity, independent scopes and storage bounds.
#[derive(Clone, Copy)]
pub struct Configuration<'a> {
    /// New absolute directory; its parent must already exist.
    pub root: &'a Path,
    /// Deployment lineage used for both separate stores.
    pub site_lineage: &'a str,
    /// Claimed connection and generation, not an authentication result.
    pub source: SourceKey,
    /// Camera claim, not an authentication result.
    pub camera_claim: ContentDigest,
    /// Separately authorized original-source retention decision.
    pub source_retention: ContentDigest,
    /// Scope for the source publication journal.
    pub source_scope: ContentDigest,
    /// Distinct scope for the A/V publication journal.
    pub av_scope: ContentDigest,
    /// Explicit source archive capacity; reopening requires the same values.
    pub source_deployment_limits: DeploymentLimits,
    /// Explicit A/V archive capacity; reopening requires the same values.
    pub av_deployment_limits: DeploymentLimits,
    /// Bounds for both archive owners.
    pub limits: archive::Limits,
    /// Bound on one separately archived source record.
    pub max_source_bytes: usize,
    /// Bound on the work for one publication attempt.
    pub work_limit: u64,
}

/// The exclusive storage owners required by a new recording session.
#[must_use = "attach or retire both archive owners"]
pub struct Created {
    /// Separate-source publication coordinator.
    pub coordinator: source_coordinator::Coordinator,
    /// A/V archive owners; the collector retains its own retention decision.
    pub av: Box<av_unknown_worker_guard::BootstrapResources>,
}

/// Separate caller-owned custody for each archive journal and keeper.
/// The caller must authorize and establish the actual failure-domain separation.
#[must_use = "attach or explicitly recover every retainer"]
pub struct Retainers {
    /// Custody for each acknowledged source-journal prefix.
    pub source_journal: Box<dyn EffectPinRetainer>,
    /// Custody for each acknowledged source-keeper prefix.
    pub source_keeper: Box<dyn EffectPinRetainer>,
    /// Custody for each acknowledged A/V-journal prefix.
    pub av_journal: Box<dyn EffectPinRetainer>,
    /// Custody for each acknowledged A/V-keeper prefix.
    pub av_keeper: Box<dyn EffectPinRetainer>,
}

/// Separately retained minimum prefixes for one journal and its keeper.
#[derive(Clone, Copy, Debug)]
pub struct HistoryMinimum {
    /// Minimum publication-journal prefix retained independently.
    pub journal: EffectJournalPin,
    /// Minimum keeper prefix retained independently.
    pub keeper: EffectJournalPin,
}

/// Reopened exact history, held for inspection or explicit reconciliation.
#[must_use = "inspect or reconcile the returned journal and keeper"]
pub struct RecoveredHistory {
    /// Complete verified publication history.
    pub journal: archive::journal::UnknownTimeJournal,
    /// Complete verified keeper history, scoped to the same journal.
    pub keeper: archive::journal::UnknownTimeAnchorKeeper,
    /// Original scoped replay authority.
    pub replay: ReplayCx,
}

impl RecoveredHistory {
    /// Whether the keeper's last retained target equals the current journal head.
    /// This does not prove independent storage or resolve pending publication.
    pub fn keeper_caught_up(&self) -> bool {
        self.keeper.target() == self.journal.anchor()
    }
}

/// Reopened source and A/V histories; neither authorizes starting a session.
#[must_use = "inspect or reconcile both histories"]
pub struct Recovered {
    /// Separate-source archive history.
    pub source: RecoveredHistory,
    /// A/V archive history.
    pub av: RecoveredHistory,
    retained: bool,
}

/// Boundary between the verified prior connection and a newly selected one.
/// Both claims are caller-bound; no time interval or continuous coverage is implied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestartBoundary {
    /// Caller-supplied camera claim, not an authentication result.
    pub camera_claim: ContentDigest,
    /// Connection claim found in both previously confirmed archives.
    pub previous: SourceKey,
    /// New caller-selected connection claim, strictly later than `previous`.
    pub next: SourceKey,
    /// Last verified separate-source root.
    pub source_root: archive::UnknownTimePin,
    /// Last verified A/V root.
    pub av_root: archive::UnknownTimePin,
}

/// Recovered archive owners and a mandatory explicit connection boundary.
#[must_use = "record the boundary and attach or retire both owners"]
pub struct Resumed {
    boundary: RestartBoundary,
    owners: Created,
}

impl Resumed {
    /// Inspect the boundary before retaining it in canonical evidence.
    pub fn boundary(&self) -> RestartBoundary {
        self.boundary
    }
}

/// A restart refusal retains both histories for inspection or another recovery.
#[must_use = "inspect or recover the returned histories"]
pub struct ResumeRefusal {
    /// Payload-free refusal stage.
    pub reason: Error,
    /// Original histories, including any in-memory replay progress.
    pub histories: Recovered,
}

impl std::fmt::Debug for ResumeRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResumeRefusal")
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for ResumeRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UniFi recording restart refused: {:?}", self.reason)
    }
}
impl std::error::Error for ResumeRefusal {}

struct RecoveryAuthority<'a> {
    read: &'a dyn archive::ReadAuthority,
    retain: &'a dyn archive::RetainAuthority,
}
impl archive::RetainAuthority for RecoveryAuthority<'_> {
    fn permits(&self, retention: ContentDigest, root: ContentDigest) -> bool {
        self.read.permits(retention, root) && self.retain.permits(retention, root)
    }
}

/// Readback counts for the latest confirmed roots, if present. These counts
/// do not include earlier roots or resolve an outstanding replay obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfirmedReadback {
    /// Connection claim and length of the last confirmed standalone source record.
    pub source: Option<(SourceKey, usize)>,
    /// Profile and structural sample counts in the last confirmed root.
    pub av_samples: Option<ConfirmedSamples>,
}

/// Distinguishes an audio-bearing fragment from unknown audio coverage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfirmedSamples {
    /// Verified source mappings for audio and video samples.
    AudioVideo {
        /// Number of structurally mapped video samples.
        video: usize,
        /// Number of structurally mapped audio samples.
        audio: usize,
    },
    /// Video samples only; this does not establish audio absence or coverage.
    VideoOnly {
        /// Number of structurally mapped video samples.
        video: usize,
    },
}

/// Payload-free creation stage. Any previously created files must be inspected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Inputs or scopes were inconsistent, before filesystem work.
    Configuration,
    /// Task, grant, cancellation or clock admission failed.
    Admission,
    /// The root could not be created exclusively.
    Root,
    /// A deployment, journal or keeper could not be created.
    Storage,
    /// Source-worker bounds or retention identity were refused.
    Worker,
    /// Existing journal history, namespace, scope or supplied minimum failed verification.
    Recovery,
    /// The caller-supplied independent minimum was absent from verified history.
    MinimumMismatch,
    /// An existing source deployment could not be reopened.
    SourceReadbackOpen,
    /// An existing A/V deployment could not be reopened.
    AvReadbackOpen,
    /// The confirmed source graph could not be verified under read authority.
    SourceReadback,
    /// The confirmed A/V graph could not be verified under read authority.
    AvReadback,
    /// The confirmed source's caller-supplied camera claim differs from configuration.
    SourceClaimMismatch,
    /// Histories were not reopened with all four retained custodians.
    Custody,
    /// Prior publication or replay needs reconciliation.
    Reconciliation,
    /// Prior source claims conflict or the new connection is not strictly later.
    RestartBoundary,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UniFi recording storage operation refused: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Create a new source and A/V archive; never reopen or delete prior state.
///
/// `source_replay` and `av_replay` are independently supplied storage
/// authorities. The caller supplies capacity limits for both deployments;
/// each is bound into its persisted layout and must match on reopen. Capacity
/// is a bound, not reserved disk space. Journal keepers are separate files
/// within this root, so their physical independence is not asserted. External
/// retention/recovery of anchors, capture time and 30-day deletion are not
/// implemented by this creation function.
pub fn create<'task>(
    task: &TaskCx<'task>,
    cx: &Cx,
    clock: MeteredClock<'_, 'task>,
    cfg: Configuration<'_>,
    source_replay: ReplayCx,
    av_replay: ReplayCx,
    authority: Arc<dyn archive::RetainAuthority + Send + Sync>,
) -> Result<Created, Error> {
    create_inner(
        task,
        cx,
        clock,
        cfg,
        source_replay,
        av_replay,
        authority,
        None,
    )
}

/// Create fresh archive owners whose four history prefixes are retained by
/// caller-supplied custodians before each append is acknowledged. This does
/// not establish the custodians' independence or authorize restart/retry.
pub fn create_retained<'task>(
    task: &TaskCx<'task>,
    cx: &Cx,
    clock: MeteredClock<'_, 'task>,
    cfg: Configuration<'_>,
    source_replay: ReplayCx,
    av_replay: ReplayCx,
    authority: Arc<dyn archive::RetainAuthority + Send + Sync>,
    retainers: Retainers,
) -> Result<Created, Error> {
    create_inner(
        task,
        cx,
        clock,
        cfg,
        source_replay,
        av_replay,
        authority,
        Some(retainers),
    )
}

fn create_inner<'task>(
    task: &TaskCx<'task>,
    cx: &Cx,
    clock: MeteredClock<'_, 'task>,
    cfg: Configuration<'_>,
    source_replay: ReplayCx,
    av_replay: ReplayCx,
    authority: Arc<dyn archive::RetainAuthority + Send + Sync>,
    retainers: Option<Retainers>,
) -> Result<Created, Error> {
    if !valid_configuration(&cfg, &source_replay, &av_replay) {
        return Err(Error::Configuration);
    }
    if !clock.matches(task, cx) {
        return Err(Error::Admission);
    }
    let resource = cfg.root.to_str().ok_or(Error::Configuration)?;
    admit(task, cx, clock, resource, &source_replay)?;
    admit(task, cx, clock, resource, &av_replay)?;
    create_private_root(cfg.root).map_err(|_| Error::Root)?;

    admit(task, cx, clock, resource, &source_replay)?;
    let source_deployment = ReferenceDeployment::open_with_limits(
        &cfg.root.join("source"),
        cfg.site_lineage,
        cfg.source_deployment_limits,
        &source_replay,
    )
    .map_err(|_| Error::Storage)?;
    admit(task, cx, clock, resource, &source_replay)?;
    let (source_journal, source_keeper, av_journal, av_keeper) = match retainers {
        Some(retainers) => (
            Some(retainers.source_journal),
            Some(retainers.source_keeper),
            Some(retainers.av_journal),
            Some(retainers.av_keeper),
        ),
        None => (None, None, None, None),
    };
    let store = create_store(&cfg.root.join("source-intent"), source_journal)?;
    let source_journal =
        archive::journal::UnknownTimeJournal::create(store, cfg.source_scope, &source_replay)
            .map_err(|_| Error::Storage)?;
    admit(task, cx, clock, resource, &source_replay)?;
    let store = create_store(&cfg.root.join("source-anchor"), source_keeper)?;
    let source_keeper =
        archive::journal::UnknownTimeAnchorKeeper::create(store, &source_journal, &source_replay)
            .map_err(|_| Error::Storage)?;
    let worker = source_worker::Worker::new(source_worker::Parts {
        deployment: source_deployment,
        journal: source_journal,
        keeper: source_keeper,
        replay: source_replay,
        authority: authority.clone(),
        retention: cfg.source_retention,
        limits: cfg.limits,
        max_source_bytes: cfg.max_source_bytes,
        work_limit: cfg.work_limit,
    })
    .map_err(|_| Error::Worker)?;
    let coordinator = source_coordinator::Coordinator::new(worker, cfg.source, cfg.camera_claim);

    admit(task, cx, clock, resource, &av_replay)?;
    let av_deployment = ReferenceDeployment::open_with_limits(
        &cfg.root.join("av"),
        cfg.site_lineage,
        cfg.av_deployment_limits,
        &av_replay,
    )
    .map_err(|_| Error::Storage)?;
    admit(task, cx, clock, resource, &av_replay)?;
    let store = create_store(&cfg.root.join("av-intent"), av_journal)?;
    let av_journal = archive::journal::UnknownTimeJournal::create(store, cfg.av_scope, &av_replay)
        .map_err(|_| Error::Storage)?;
    admit(task, cx, clock, resource, &av_replay)?;
    let store = create_store(&cfg.root.join("av-anchor"), av_keeper)?;
    let av_keeper =
        archive::journal::UnknownTimeAnchorKeeper::create(store, &av_journal, &av_replay)
            .map_err(|_| Error::Storage)?;
    Ok(Created {
        coordinator,
        av: Box::new(av_unknown_worker_guard::BootstrapResources {
            deployment: av_deployment,
            journal: av_journal,
            keeper: av_keeper,
            replay: av_replay,
            authority,
            limits: cfg.limits,
            work_limit: cfg.work_limit,
        }),
    })
}

fn create_store(
    path: &Path,
    retainer: Option<Box<dyn EffectPinRetainer>>,
) -> Result<Box<dyn EffectJournalStore>, Error> {
    let store =
        FileEffectJournal::create(path, EffectJournalLimits::default(), Arc::new(HostSpoolIo))
            .map_err(|_| Error::Storage)?;
    match retainer {
        Some(retainer) => Ok(Box::new(
            PinRetainedEffectJournal::new(Box::new(store), retainer).map_err(|_| Error::Storage)?,
        )),
        None => Ok(Box::new(store)),
    }
}

/// Reopen both existing histories against separately supplied minimum anchors.
///
/// This verifies the complete journal and keeper chains and returns their
/// exact pending and replay states for reconciliation. It does not open the
/// archive deployments, infer anchor independence, resume a session, or
/// authorize repeating any effect. A missing or changed root is never created.
pub fn recover_histories<'task>(
    task: &TaskCx<'task>,
    cx: &Cx,
    clock: MeteredClock<'_, 'task>,
    cfg: Configuration<'_>,
    source_minimum: HistoryMinimum,
    av_minimum: HistoryMinimum,
    source_replay: ReplayCx,
    av_replay: ReplayCx,
) -> Result<Recovered, Error> {
    recover_histories_inner(
        task,
        cx,
        clock,
        cfg,
        source_minimum,
        av_minimum,
        source_replay,
        av_replay,
        None,
    )
}

/// Reopen histories while reattaching all four caller-supplied pin custodians.
///
/// Every custodian must verify the complete history and exactly match its
/// current journal head. A longer local history or stale/missing retained pin
/// is refused without advancing either side. The returned journals preserve
/// replay fences; reattaching custody alone does not authorize publication,
/// prove failure-domain independence, or restore media/muxer state.
pub fn recover_histories_retained<'task>(
    task: &TaskCx<'task>,
    cx: &Cx,
    clock: MeteredClock<'_, 'task>,
    cfg: Configuration<'_>,
    source_minimum: HistoryMinimum,
    av_minimum: HistoryMinimum,
    source_replay: ReplayCx,
    av_replay: ReplayCx,
    retainers: Retainers,
) -> Result<Recovered, Error> {
    recover_histories_inner(
        task,
        cx,
        clock,
        cfg,
        source_minimum,
        av_minimum,
        source_replay,
        av_replay,
        Some(retainers),
    )
}

fn recover_histories_inner<'task>(
    task: &TaskCx<'task>,
    cx: &Cx,
    clock: MeteredClock<'_, 'task>,
    cfg: Configuration<'_>,
    source_minimum: HistoryMinimum,
    av_minimum: HistoryMinimum,
    source_replay: ReplayCx,
    av_replay: ReplayCx,
    retainers: Option<Retainers>,
) -> Result<Recovered, Error> {
    if !valid_configuration(&cfg, &source_replay, &av_replay) {
        return Err(Error::Configuration);
    }
    if !clock.matches(task, cx) {
        return Err(Error::Admission);
    }
    let resource = cfg.root.to_str().ok_or(Error::Configuration)?;
    admit(task, cx, clock, resource, &source_replay)?;
    let root_meta = std::fs::symlink_metadata(cfg.root).map_err(|_| Error::Recovery)?;
    if !root_meta.is_dir() {
        return Err(Error::Recovery);
    }
    let retained = retainers.is_some();
    let (source_journal, source_keeper, av_journal, av_keeper) = match retainers {
        Some(retainers) => (
            Some(retainers.source_journal),
            Some(retainers.source_keeper),
            Some(retainers.av_journal),
            Some(retainers.av_keeper),
        ),
        None => (None, None, None, None),
    };
    let source = recover_one(
        task,
        cx,
        clock,
        cfg.root,
        "source",
        cfg.source_scope,
        source_minimum,
        source_replay,
        source_journal,
        source_keeper,
    )?;
    let av = recover_one(
        task,
        cx,
        clock,
        cfg.root,
        "av",
        cfg.av_scope,
        av_minimum,
        av_replay,
        av_journal,
        av_keeper,
    )?;
    Ok(Recovered {
        source,
        av,
        retained,
    })
}

/// Reconcile both confirmed roots and transfer their retained owners to a new
/// recording connection. This starts no network operation or recorder task.
///
/// The caller must reserve a new monotonically increasing source key and
/// record the returned boundary in canonical evidence before consuming new
/// media. This function checks the last source and A/V claims agree and that
/// the selected next key is later; it cannot establish global key uniqueness,
/// camera identity, uninterrupted coverage, or the boundary's physical time.
/// A fresh collector must bootstrap new muxer clocks and honor the prior A/V
/// retention decision unless a separately authorized change is made. The
/// caller must separately settle all camera-control effects before reconnecting.
pub fn resume_confirmed<'task>(
    task: &TaskCx<'task>,
    cx: &Cx,
    clock: MeteredClock<'_, 'task>,
    cfg: Configuration<'_>,
    mut histories: Recovered,
    read_authority: &dyn archive::ReadAuthority,
    retain_authority: Arc<dyn archive::RetainAuthority + Send + Sync>,
    object_limits: archive::StagedAvLimits,
) -> Result<Resumed, ResumeRefusal> {
    let prepared = (|| -> Result<_, Error> {
        if !histories.retained {
            return Err(Error::Custody);
        }
        if !valid_configuration(&cfg, &histories.source.replay, &histories.av.replay)
            || histories.source.journal.scope() != cfg.source_scope
            || histories.av.journal.scope() != cfg.av_scope
        {
            return Err(Error::Configuration);
        }
        if !clock.matches(task, cx) {
            return Err(Error::Admission);
        }
        let resource = cfg.root.to_str().ok_or(Error::Configuration)?;
        for history in [&histories.source, &histories.av] {
            admit(task, cx, clock, resource, &history.replay)?;
            for grant in [RuntimeGrant::ReadMedia, RuntimeGrant::ObjectPublish] {
                task.checkpoint_for(
                    grant,
                    resource,
                    clock.now().map_err(|_| Error::Admission)?,
                    &BudgetVector::ZERO,
                )
                .map_err(|_| Error::Admission)?;
            }
            if !history.keeper_caught_up() || history.journal.pending().is_some() {
                return Err(Error::Reconciliation);
            }
        }
        let source_pin = histories
            .source
            .journal
            .confirmed()
            .ok_or(Error::Reconciliation)?;
        let av_pin = histories
            .av
            .journal
            .confirmed()
            .ok_or(Error::Reconciliation)?;
        if source_pin.retention != cfg.source_retention {
            return Err(Error::Configuration);
        }
        let mut source_deployment =
            ReferenceDeployment::open_existing_with_limits_without_effect_reconciliation(
                &cfg.root.join("source"),
                cfg.site_lineage,
                cfg.source_deployment_limits,
                &histories.source.replay,
            )
            .map_err(|_| Error::SourceReadbackOpen)?;
        let mut av_deployment =
            ReferenceDeployment::open_existing_with_limits_without_effect_reconciliation(
                &cfg.root.join("av"),
                cfg.site_lineage,
                cfg.av_deployment_limits,
                &histories.av.replay,
            )
            .map_err(|_| Error::AvReadbackOpen)?;
        let source = archive::read_unknown_time_source(
            &mut source_deployment,
            source_pin,
            read_authority,
            cfg.limits,
            &mut fss_geometry::WorkBudget::new(cfg.work_limit),
            &histories.source.replay,
        )
        .map_err(|_| Error::SourceReadback)?;
        if source.camera_claim() != cfg.camera_claim {
            return Err(Error::SourceClaimMismatch);
        }
        let previous = source.key();
        let clip = archive::read_unknown_time_av_any(
            &mut av_deployment,
            av_pin,
            read_authority,
            cfg.limits,
            &mut fss_geometry::WorkBudget::new(cfg.work_limit),
            &histories.av.replay,
        )
        .map_err(|_| Error::AvReadback)?;
        if clip.claimed_source() != previous
            || (cfg.source.generation, cfg.source.connection)
                <= (previous.generation, previous.connection)
        {
            return Err(Error::RestartBoundary);
        }
        drop(clip);
        let source_plan = super::source_evidence::Prepared::from_recovered(&source);
        let recovery_authority = RecoveryAuthority {
            read: read_authority,
            retain: retain_authority.as_ref(),
        };
        let source_receipt = archive::publish_unknown_time_source_anchored(
            &source_plan,
            &mut source_deployment,
            &recovery_authority,
            cfg.limits,
            &mut fss_geometry::WorkBudget::new(cfg.work_limit),
            &histories.source.replay,
            &mut histories.source.journal,
            &mut histories.source.keeper,
        )
        .map_err(|_| Error::Reconciliation)?;
        if source_receipt.outcome != fss_publication::RootLedgerOutcome::AlreadyLedgered {
            return Err(Error::Reconciliation);
        }
        let av_receipt = archive::replay_confirmed_unknown_time_av_anchored(
            &mut av_deployment,
            read_authority,
            retain_authority.as_ref(),
            cfg.limits,
            object_limits,
            &mut fss_geometry::WorkBudget::new(cfg.work_limit),
            &histories.av.replay,
            &mut histories.av.journal,
            &mut histories.av.keeper,
        )
        .map_err(|_| Error::Reconciliation)?;
        if av_receipt.outcome != fss_publication::RootLedgerOutcome::AlreadyLedgered {
            return Err(Error::Reconciliation);
        }
        Ok((
            source_deployment,
            av_deployment,
            RestartBoundary {
                camera_claim: cfg.camera_claim,
                previous,
                next: cfg.source,
                source_root: source_pin,
                av_root: av_pin,
            },
        ))
    })();
    let (source_deployment, av_deployment, boundary) = match prepared {
        Ok(value) => value,
        Err(reason) => return Err(ResumeRefusal { reason, histories }),
    };
    let Recovered {
        source,
        av,
        retained,
    } = histories;
    let parts = source_worker::Parts {
        deployment: source_deployment,
        journal: source.journal,
        keeper: source.keeper,
        replay: source.replay,
        authority: retain_authority.clone(),
        retention: cfg.source_retention,
        limits: cfg.limits,
        max_source_bytes: cfg.max_source_bytes,
        work_limit: cfg.work_limit,
    };
    let worker = match source_worker::Worker::new(parts) {
        Ok(worker) => worker,
        Err(parts) => {
            let source = RecoveredHistory {
                journal: parts.journal,
                keeper: parts.keeper,
                replay: parts.replay,
            };
            return Err(ResumeRefusal {
                reason: Error::Worker,
                histories: Recovered {
                    source,
                    av,
                    retained,
                },
            });
        }
    };
    Ok(Resumed {
        boundary,
        owners: Created {
            coordinator: source_coordinator::Coordinator::new(worker, cfg.source, cfg.camera_claim),
            av: Box::new(av_unknown_worker_guard::BootstrapResources {
                deployment: av_deployment,
                journal: av.journal,
                keeper: av.keeper,
                replay: av.replay,
                authority: retain_authority,
                limits: cfg.limits,
                work_limit: cfg.work_limit,
            }),
        },
    })
}

/// Verify the latest confirmed source and A/V graphs after reopening storage.
///
/// This opens only existing deployments and does not reconcile effect states,
/// though deployment opening may perform local publisher recovery and takes
/// exclusive locks. It checks retained source mappings, not codec decoding,
/// device identity, earlier roots, coverage, or any pending publication. The
/// source's recorded connection claim is returned rather than equated with a
/// new session's `cfg.source`. Histories and replay obligations remain intact.
pub fn readback_confirmed<'task>(
    task: &TaskCx<'task>,
    cx: &Cx,
    clock: MeteredClock<'_, 'task>,
    cfg: Configuration<'_>,
    histories: &Recovered,
    authority: &dyn archive::ReadAuthority,
) -> Result<ConfirmedReadback, Error> {
    if !valid_configuration(&cfg, &histories.source.replay, &histories.av.replay)
        || histories.source.journal.scope() != cfg.source_scope
        || histories.av.journal.scope() != cfg.av_scope
    {
        return Err(Error::Configuration);
    }
    if !clock.matches(task, cx) {
        return Err(Error::Admission);
    }
    let resource = cfg.root.to_str().ok_or(Error::Configuration)?;
    let read_one = |name: &str, history: &RecoveredHistory, open_error: Error, limits| {
        admit(task, cx, clock, resource, &history.replay)?;
        task.checkpoint_for(
            RuntimeGrant::ReadMedia,
            resource,
            clock.now().map_err(|_| Error::Admission)?,
            &BudgetVector::ZERO,
        )
        .map_err(|_| Error::Admission)?;
        ReferenceDeployment::open_existing_with_limits_without_effect_reconciliation(
            &cfg.root.join(name),
            cfg.site_lineage,
            limits,
            &history.replay,
        )
        .map_err(|_| open_error)
    };
    let source = if let Some(pin) = histories.source.journal.confirmed() {
        let mut deployment = read_one(
            "source",
            &histories.source,
            Error::SourceReadbackOpen,
            cfg.source_deployment_limits,
        )?;
        let source = archive::read_unknown_time_source(
            &mut deployment,
            pin,
            authority,
            cfg.limits,
            &mut fss_geometry::WorkBudget::new(cfg.work_limit),
            &histories.source.replay,
        )
        .map_err(|_| Error::SourceReadback)?;
        if source.camera_claim() != cfg.camera_claim {
            return Err(Error::SourceClaimMismatch);
        }
        Some((source.key(), source.bytes().len()))
    } else {
        None
    };
    let av_samples = if let Some(pin) = histories.av.journal.confirmed() {
        let mut deployment = read_one(
            "av",
            &histories.av,
            Error::AvReadbackOpen,
            cfg.av_deployment_limits,
        )?;
        let clip = archive::read_unknown_time_av_any(
            &mut deployment,
            pin,
            authority,
            cfg.limits,
            &mut fss_geometry::WorkBudget::new(cfg.work_limit),
            &histories.av.replay,
        )
        .map_err(|_| Error::AvReadback)?;
        Some(match clip {
            archive::RecoveredUnknownTimeAv::AudioVideo(clip) => ConfirmedSamples::AudioVideo {
                video: clip.video_samples(),
                audio: clip.audio().frames,
            },
            archive::RecoveredUnknownTimeAv::VideoOnly(clip) => ConfirmedSamples::VideoOnly {
                video: clip.video_samples(),
            },
        })
    } else {
        None
    };
    Ok(ConfirmedReadback { source, av_samples })
}

fn recover_one<'task>(
    task: &TaskCx<'task>,
    cx: &Cx,
    clock: MeteredClock<'_, 'task>,
    root: &Path,
    name: &str,
    scope: ContentDigest,
    minimum: HistoryMinimum,
    replay: ReplayCx,
    journal_retainer: Option<Box<dyn EffectPinRetainer>>,
    keeper_retainer: Option<Box<dyn EffectPinRetainer>>,
) -> Result<RecoveredHistory, Error> {
    let resource = root.to_str().ok_or(Error::Configuration)?;
    admit(task, cx, clock, resource, &replay)?;
    let store = FileEffectJournal::open(
        root.join(format!("{name}-intent")),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
        minimum.journal,
    )
    .map_err(recovery_store_error)?;
    let store = attach_retainer(store, journal_retainer)?;
    let journal =
        archive::journal::UnknownTimeJournal::reopen(store, scope, minimum.journal, &replay)
            .map_err(recovery_journal_error)?;
    admit(task, cx, clock, resource, &replay)?;
    let store = FileEffectJournal::open(
        root.join(format!("{name}-anchor")),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
        minimum.keeper,
    )
    .map_err(recovery_store_error)?;
    let store = attach_retainer(store, keeper_retainer)?;
    let keeper =
        archive::journal::UnknownTimeAnchorKeeper::reopen(store, &journal, minimum.keeper, &replay)
            .map_err(recovery_journal_error)?;
    Ok(RecoveredHistory {
        journal,
        keeper,
        replay,
    })
}

fn attach_retainer(
    store: FileEffectJournal,
    retainer: Option<Box<dyn EffectPinRetainer>>,
) -> Result<Box<dyn EffectJournalStore>, Error> {
    match retainer {
        Some(retainer) => Ok(Box::new(
            PinRetainedEffectJournal::for_reconciliation(Box::new(store), retainer)
                .map_err(recovery_store_error)?,
        )),
        None => Ok(Box::new(store)),
    }
}

fn recovery_store_error(error: EffectPersistenceError) -> Error {
    if matches!(error, EffectPersistenceError::PinMismatch) {
        Error::MinimumMismatch
    } else {
        Error::Recovery
    }
}

fn recovery_journal_error(error: archive::journal::Error) -> Error {
    match error {
        archive::journal::Error::Cancelled => Error::Admission,
        archive::journal::Error::Storage(error) => recovery_store_error(error),
        _ => Error::Recovery,
    }
}

fn valid_configuration(cfg: &Configuration<'_>, source: &ReplayCx, av: &ReplayCx) -> bool {
    cfg.root.is_absolute()
        && cfg.root.file_name().is_some()
        && cfg.source.connection != 0
        && cfg.source.generation != 0
        && !cfg.site_lineage.is_empty()
        && cfg.source_scope != cfg.av_scope
        && [
            cfg.camera_claim,
            cfg.source_retention,
            cfg.source_scope,
            cfg.av_scope,
        ]
        .iter()
        .all(|d| {
            d.algorithm() == DigestAlgorithm::Sha256 && !d.is_laboratory() && d.bytes() != [0; 32]
        })
        && cfg.root.parent() == Some(source.root_dir())
        && cfg.root.parent() == Some(av.root_dir())
        && (1024..=64 * 1024 * 1024).contains(&cfg.limits.maximum_spool_object_bytes)
        && (1..=262_144).contains(&cfg.limits.maximum_ledger_deltas)
        && (1..=64 * 1024 * 1024).contains(&cfg.max_source_bytes)
        && (1..=100_000_000_000).contains(&cfg.work_limit)
        && [cfg.source_deployment_limits, cfg.av_deployment_limits]
            .into_iter()
            .all(|limits| {
                limits.to_publication_limits().validate().is_ok()
                    && limits.spool_total_max_bytes > 0
                    && limits.spool_object_max_bytes > 0
                    && limits.spool_object_max_bytes <= cfg.limits.maximum_spool_object_bytes as u64
                    && limits.batch_entries_max > 0
                    && limits.journal_record_max_bytes > 0
            })
        && cfg.max_source_bytes as u64 <= cfg.source_deployment_limits.spool_object_max_bytes
}

#[cfg(unix)]
fn create_private_root(root: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o700).create(root)
}

#[cfg(not(unix))]
fn create_private_root(_root: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "private recording storage is not implemented on this platform",
    ))
}

fn admit<'task>(
    task: &TaskCx<'task>,
    cx: &Cx,
    clock: MeteredClock<'_, 'task>,
    resource: &str,
    replay: &ReplayCx,
) -> Result<(), Error> {
    if !clock.matches(task, cx) {
        return Err(Error::Admission);
    }
    task.checkpoint_for(
        RuntimeGrant::ObjectStage,
        resource,
        clock.now().map_err(|_| Error::Admission)?,
        &BudgetVector::ZERO,
    )
    .map_err(|_| Error::Admission)?;
    replay
        .checkpoint("unifi-recording-storage-create")
        .map_err(|_| Error::Admission)
}
