#![forbid(unsafe_code)]
//! Pre-effect, private checkpoint for the camera-local HTTP experiment.
//! No camera request or stream listener is created by this module.

use std::{
    fs::{self, DirBuilder, File},
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use asupersync::Cx;
use fss_core::{BudgetVector, ContentDigest, RuntimeGrant};
use fss_object::{
    HostSpoolIo, SpoolLimits, StagingSpool,
    effect_journal::{EffectJournalLimits, FileEffectJournal, FileTrustedRootPinRetainer},
};
use fss_reference::unifi_direct::{
    camera_api::VideoSerializers,
    http_stream::{
        Plan,
        checkpoint::{self, Action, Anchored, Authority, Scope, Sealed, Stored, keyfile::KeyLease},
    },
    metered::MeteredClock,
};
use fss_runtime::{
    drained_blocking::{self, WorkOutcome},
    effect_journal::{EffectPinRetainer, PinRetainedEffectJournal},
    execution::TaskCx,
};

/// Owners needed by a later start, kept together with the anchored checkpoint.
#[must_use]
pub struct Prepared {
    pub plan: Plan,
    pub baseline: VideoSerializers,
    pub anchored: Anchored,
    pub key: KeyLease,
    pub spool: StagingSpool,
    pub journal: PinRetainedEffectJournal,
}

struct Policy(Scope);
impl Authority for Policy {
    fn permits(&self, cx: &Cx, scope: &Scope, action: Action) -> bool {
        *scope == self.0
            && cx.checkpoint().is_ok()
            && (action != Action::Entropy || cx.entropy().source_id() == "os")
    }
}

fn create(
    cx: Cx,
    root: &Path,
    plan: Plan,
    baseline: VideoSerializers,
    certificate: ContentDigest,
) -> Result<Prepared, &'static str> {
    let parent = root.parent().ok_or("checkpoint parent missing")?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| "checkpoint parent unavailable")?;
    if !root.is_absolute() || !metadata.file_type().is_dir() || metadata.mode() & 0o077 != 0 {
        return Err("checkpoint parent must be an existing private directory");
    }
    cx.checkpoint().map_err(|_| "checkpoint cancelled")?;
    DirBuilder::new()
        .mode(0o700)
        .create(root)
        .map_err(|_| "checkpoint directory creation refused")?;
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|_| "checkpoint parent sync failed")?;
    let scope = Scope::from_plan(&plan, certificate).map_err(|_| "checkpoint scope refused")?;
    let policy = Policy(scope);
    let key = KeyLease::create(&cx, &policy, scope, &root.join("key"))
        .map_err(|_| "checkpoint key creation refused")?;
    let mut spool = StagingSpool::open(
        root.join("spool"),
        SpoolLimits::new(4, 1_000_000, 100_000, 8),
    )
    .map_err(|_| "checkpoint spool creation refused")?;
    let stored =
        Stored::capture_with_keyfile(&cx, &policy, scope, &key, &plan, &baseline, &mut spool)
            .map_err(|_| "checkpoint capture refused")?;
    let limits = EffectJournalLimits::default();
    let journal = FileEffectJournal::create(root.join("journal"), limits, Arc::new(HostSpoolIo))
        .map_err(|_| "checkpoint journal creation refused")?;
    let retainer = FileTrustedRootPinRetainer::create(
        root.join("pin"),
        limits,
        Arc::new(HostSpoolIo),
        ContentDigest::sha256(b"unifi-http-trial-checkpoint"),
    )
    .map_err(|_| "checkpoint pin creation refused")?;
    let mut journal = PinRetainedEffectJournal::new(Box::new(journal), Box::new(retainer))
        .map_err(|_| "checkpoint journal binding refused")?;
    let anchored = stored
        .anchor_with_keyfile(&cx, &policy, &key, &mut spool, &mut journal)
        .map_err(|_| "checkpoint anchor refused")?;
    Ok(Prepared {
        plan,
        baseline,
        anchored,
        key,
        spool,
        journal,
    })
}

/// Create and verify private checkpoint custody on a drained blocking worker.
/// A failure can leave partial create-only artifacts; inspect before retrying.
/// The parent and its ancestors are explicitly trusted by the caller.
pub async fn prepare<'scope, 'task>(
    task: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    root: PathBuf,
    plan: Plan,
    baseline: VideoSerializers,
    certificate: ContentDigest,
) -> Result<Prepared, &'static str> {
    let resource = root.to_str().ok_or("checkpoint path must be UTF-8")?;
    let mut cost = BudgetVector::ZERO;
    cost.storage_operations = 32;
    task.checkpoint_for(
        RuntimeGrant::ObjectStage,
        resource,
        clock.now().map_err(|_| "checkpoint clock unavailable")?,
        &cost,
    )
    .map_err(|_| "checkpoint authority refused")?;
    let work = move |child: Cx| create(child, &root, plan, baseline, certificate);
    let mut worker = drained_blocking::start(cx, work).map_err(|_| "checkpoint worker refused")?;
    let receipt =
        match asupersync::time::timeout(cx.now(), Duration::from_secs(15), worker.join()).await {
            Ok(receipt) => receipt.ok_or("checkpoint worker already joined")?,
            Err(_) => {
                worker.abort();
                let _drained = worker.join().await;
                return Err("checkpoint worker timed out; inspect artifacts");
            }
        };
    if receipt.runtime.is_err() {
        return Err("checkpoint worker runtime failed; inspect artifacts");
    }
    match receipt.work {
        WorkOutcome::Finished(result) => result,
        WorkOutcome::NotStarted(_) => Err("checkpoint worker did not start"),
        WorkOutcome::Panicked | WorkOutcome::Indeterminate => {
            Err("checkpoint worker outcome indeterminate; inspect artifacts")
        }
    }
}

struct InspectionPolicy;
impl Authority for InspectionPolicy {
    fn permits(&self, cx: &Cx, _: &Scope, action: Action) -> bool {
        cx.checkpoint().is_ok()
            && matches!(
                action,
                Action::Anchor | Action::KeyRead | Action::KeyUse | Action::Open
            )
    }
}

fn inspect_disk(cx: Cx, root: &Path) -> Result<(), &'static str> {
    if !root.is_absolute() {
        return Err("checkpoint path must be absolute");
    }
    let meta = fs::symlink_metadata(root).map_err(|_| "checkpoint directory unavailable")?;
    if !meta.file_type().is_dir() || meta.mode() & 0o077 != 0 {
        return Err("checkpoint directory must be private");
    }
    // Require the complete layout before opening; this inspection must not
    // create a missing spool directory or silently initialize missing state.
    for name in ["spool", "journal", "pin"] {
        let base = root.join(name);
        for path in [
            base.clone(),
            base.join("objects"),
            base.join("staging"),
            base.join("verified"),
        ] {
            if !fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_dir()) {
                return Err("checkpoint layout incomplete");
            }
        }
    }
    let limits = EffectJournalLimits::default();
    let mut retainer = FileTrustedRootPinRetainer::open_trusting_storage(
        root.join("pin"),
        limits,
        Arc::new(HostSpoolIo),
        ContentDigest::sha256(b"unifi-http-trial-checkpoint"),
    )
    .map_err(|_| "checkpoint pin recovery refused")?;
    let pin = retainer
        .retained_pin()
        .map_err(|_| "checkpoint pin unavailable")?
        .ok_or("checkpoint pin missing")?;
    let journal = FileEffectJournal::open(root.join("journal"), limits, Arc::new(HostSpoolIo), pin)
        .map_err(|_| "checkpoint journal recovery refused")?;
    let mut journal =
        PinRetainedEffectJournal::for_reconciliation(Box::new(journal), Box::new(retainer))
            .map_err(|_| "checkpoint journal binding refused")?;
    let policy = InspectionPolicy;
    let record = checkpoint::recover_record(&cx, &policy, &mut journal, pin)
        .map_err(|_| "checkpoint record recovery refused")?;
    let key = KeyLease::load(&cx, &policy, record.scope(), &root.join("key"))
        .map_err(|_| "checkpoint key recovery refused")?;
    let mut spool = StagingSpool::open(
        root.join("spool"),
        SpoolLimits::new(4, 1_000_000, 100_000, 8),
    )
    .map_err(|_| "checkpoint spool recovery refused")?;
    let bytes = spool
        .read_bounded(record.digest(), 100_000)
        .map_err(|_| "checkpoint ciphertext unavailable")?;
    key.with_key(&cx, &policy, |key| {
        Sealed::from_bytes(&bytes)?.open(&cx, &policy, record.scope(), key)
    })
    .map_err(|_| "checkpoint key use refused")?
    .map_err(|_| "checkpoint authentication refused")?;
    Ok(())
}

/// Reopen and authenticate the stored checkpoint on a drained worker.
/// The root remains a caller-trusted storage domain, not proof of camera identity
/// or authority to dispatch or restore a camera setting.
pub async fn inspect<'scope, 'task>(
    task: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    root: PathBuf,
) -> Result<(), &'static str> {
    let resource = root.to_str().ok_or("checkpoint path must be UTF-8")?;
    let mut cost = BudgetVector::ZERO;
    cost.storage_operations = 32;
    task.checkpoint_for(
        RuntimeGrant::ObjectStage,
        resource,
        clock.now().map_err(|_| "checkpoint clock unavailable")?,
        &cost,
    )
    .map_err(|_| "checkpoint authority refused")?;
    let mut worker = drained_blocking::start(cx, move |child: Cx| inspect_disk(child, &root))
        .map_err(|_| "checkpoint inspection worker refused")?;
    let receipt =
        match asupersync::time::timeout(cx.now(), Duration::from_secs(15), worker.join()).await {
            Ok(receipt) => receipt.ok_or("checkpoint inspection already joined")?,
            Err(_) => {
                worker.abort();
                let _drained = worker.join().await;
                return Err("checkpoint inspection timed out");
            }
        };
    if receipt.runtime.is_err() {
        return Err("checkpoint inspection runtime failed");
    }
    match receipt.work {
        WorkOutcome::Finished(result) => result,
        WorkOutcome::NotStarted(_) => Err("checkpoint inspection did not start"),
        WorkOutcome::Panicked | WorkOutcome::Indeterminate => {
            Err("checkpoint inspection outcome indeterminate")
        }
    }
}
