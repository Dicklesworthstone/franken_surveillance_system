#![forbid(unsafe_code)]
#![cfg(unix)]
//! Explicitly bounded source archive capacity across a cold reopen.

use std::{error::Error, path::PathBuf, sync::Arc};

use asupersync::runtime::RuntimeBuilder;
use fss_container::flv_avc::SourceKey;
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
    RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_geometry::WorkBudget;
use fss_packet::extended_flv::{
    Limits as FlvLimits,
    stream::{Framer, Next, RecordKind},
};
use fss_reference::{
    DeploymentLimits, ReferenceDeployment, ReplayCx,
    unifi_direct::{
        archive, metered::MeteredClock, recording::SourceDisposition, recording_storage,
        source_evidence,
    },
};
use fss_runtime::{
    authority::AuthorityCx,
    execution::{TaskCompletion, TaskSpec, run_owned_async},
};

type Test = Result<(), Box<dyn Error>>;

struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Access(ContentDigest);
impl archive::RetainAuthority for Access {
    fn permits(&self, retention: ContentDigest, _: ContentDigest) -> bool {
        retention == self.0
    }
}
impl archive::ReadAuthority for Access {
    fn permits(&self, retention: ContentDigest, _: ContentDigest) -> bool {
        retention == self.0
    }
}

#[test]
fn rollover_replays_real_source_root_before_next_publication() -> Test {
    use fss_object::{
        HostSpoolIo,
        effect_journal::{EffectJournalLimits, FileEffectJournal, FileTrustedRootPinRetainer},
    };
    use fss_publication::RootLedgerOutcome;
    use fss_runtime::effect_journal::{EffectJournalStore, PinRetainedEffectJournal};

    struct Deny;
    impl archive::ReadAuthority for Deny {
        fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
            false
        }
    }
    impl archive::RetainAuthority for Deny {
        fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
            false
        }
    }
    let root = std::env::temp_dir().join(format!("fss-rollover-source-{}", std::process::id()));
    std::fs::create_dir(&root)?;
    let temp = Temp(std::fs::canonicalize(root)?);
    let replay_authority = fss_core::region::ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:rollover-source".into(),
        operation_id: OperationId::parse("operation:rollover-source")?,
        principal: "principal:fixture".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 1,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"rollover source fixture"),
        generation: 1,
    })?;
    let replay = ReplayCx::from_context_authority(&replay_authority, temp.0.clone())?;
    let mut deployment =
        ReferenceDeployment::open(&temp.0.join("archive"), "site:rollover-source", &replay)?;
    let storage_limits = EffectJournalLimits::default();
    let store = |name: &str| -> Result<Box<dyn EffectJournalStore>, Box<dyn Error>> {
        Ok(Box::new(FileEffectJournal::create(
            temp.0.join(name),
            storage_limits,
            Arc::new(HostSpoolIo),
        )?))
    };
    let scope = ContentDigest::sha256(b"rollover source scope");
    let retention = ContentDigest::sha256(b"rollover source retention");
    let camera = ContentDigest::sha256(b"rollover source camera claim");
    let access = Access(retention);
    let key = SourceKey {
        connection: 1,
        generation: 1,
    };
    let mut journal =
        archive::journal::UnknownTimeJournal::create(store("old-journal")?, scope, &replay)?;
    let mut keeper =
        archive::journal::UnknownTimeAnchorKeeper::create(store("old-keeper")?, &journal, &replay)?;
    let mut wire = b"FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
    for index in 0..2_u32 {
        wire.extend_from_slice(&[18, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0]);
        wire.extend_from_slice(&index.to_be_bytes());
        wire.extend_from_slice(&15_u32.to_be_bytes());
    }
    let mut framer = Framer::new(FlvLimits::default(), 64 * 1024)?;
    framer.append(0, &wire)?;
    for _ in 0..2 {
        let Next::Record(record) = framer.take()? else {
            return Err("missing source record".into());
        };
        let disposition = if matches!(record.kind(), RecordKind::Header) {
            SourceDisposition::Header
        } else {
            SourceDisposition::PreRoll
        };
        let plan =
            source_evidence::Prepared::new(&record, key, disposition, camera, retention, 1024)?;
        archive::publish_unknown_time_source_anchored(
            &plan,
            &mut deployment,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &replay,
            &mut journal,
            &mut keeper,
        )?;
    }
    let previous = archive::journal::rollover::Previous { journal, keeper };
    let staged = archive::journal::rollover::Staged::begin(
        previous,
        store("new-journal")?,
        store("new-keeper")?,
        &replay,
    )
    .map_err(|_| "rollover staging failed")?;
    let custodian = FileTrustedRootPinRetainer::create(
        temp.0.join("switch-retainer"),
        storage_limits,
        Arc::new(HostSpoolIo),
        ContentDigest::sha256(b"rollover switch custody"),
    )?;
    let switch = PinRetainedEffectJournal::new(store("switch")?, Box::new(custodian))?;
    let mut active = staged
        .commit(switch, &replay)
        .map_err(|_| "rollover switch failed")?;
    let confirmed = active.binding().confirmed;
    assert!(matches!(
        active.replay_confirmed_source(
            &mut deployment,
            camera,
            &Deny,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &replay
        ),
        Err(archive::journal::rollover::SourceReplayError::Readback(_))
    ));
    assert_eq!(active.successor().0.replay_pin(), Some(confirmed));
    assert!(matches!(
        active.replay_confirmed_source(
            &mut deployment,
            ContentDigest::sha256(b"wrong camera"),
            &access,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &replay
        ),
        Err(archive::journal::rollover::SourceReplayError::ClaimMismatch)
    ));
    assert_eq!(active.successor().0.replay_pin(), Some(confirmed));
    assert!(
        active
            .replay_confirmed_source(
                &mut deployment,
                camera,
                &access,
                &Deny,
                archive::Limits::default(),
                &mut WorkBudget::new(4_000_000_000),
                &replay
            )
            .is_err()
    );
    assert_eq!(active.successor().0.replay_pin(), Some(confirmed));
    let receipt = active.replay_confirmed_source(
        &mut deployment,
        camera,
        &access,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &replay,
    )?;
    assert_eq!(receipt.outcome, RootLedgerOutcome::AlreadyLedgered);
    assert_eq!(active.successor().0.replay_pin(), None);
    let Next::Record(record) = framer.take()? else {
        return Err("missing next source".into());
    };
    let plan = source_evidence::Prepared::new(
        &record,
        key,
        SourceDisposition::PreRoll,
        camera,
        retention,
        1024,
    )?;
    let (journal, keeper) = active.successor();
    archive::publish_unknown_time_source_anchored(
        &plan,
        &mut deployment,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &replay,
        journal,
        keeper,
    )?;
    assert_eq!(deployment.publisher().visible_roots().count(), 3);
    Ok(())
}

#[test]
fn configured_source_archive_crosses_standard_root_limit_and_reopens() -> Test {
    let parent = std::env::temp_dir().join(format!("fss-unifi-capacity-{}", std::process::id()));
    std::fs::create_dir(&parent)?;
    let temp = Temp(std::fs::canonicalize(parent)?);
    let root = temp.0.join("storage");
    let mut budget = BudgetVector::ZERO;
    budget.bytes = 64 * 1024 * 1024;
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:unifi-capacity".into(),
            operation_id: OperationId::parse("operation:unifi-capacity")?,
            principal: "principal:fixture".into(),
            capabilities: vec![
                RuntimeGrant::ObjectStage.as_str().into(),
                RuntimeGrant::ObjectPublish.as_str().into(),
                RuntimeGrant::ReadMedia.as_str().into(),
            ],
            deadline: Some(TimestampNs(60_000_000_000)),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"capacity fixture"),
            generation: 1,
        },
        RegionId::new("region:unifi-capacity")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let replay_authority = fss_core::region::ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:unifi-capacity-replay".into(),
        operation_id: OperationId::parse("operation:unifi-capacity-replay")?,
        principal: "principal:fixture".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 1,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"capacity fixture"),
        generation: 1,
    })?;
    let source_limits = DeploymentLimits {
        max_roots: 160,
        spool_total_max_bytes: 1024 * 1024 * 1024,
        ..DeploymentLimits::standard()
    };
    let retention = ContentDigest::sha256(b"capacity retention");
    let camera = ContentDigest::sha256(b"capacity camera claim");
    let key = SourceKey {
        connection: 1,
        generation: 1,
    };
    let cfg = recording_storage::Configuration {
        root: &root,
        site_lineage: "site:unifi-capacity",
        source: key,
        camera_claim: camera,
        source_retention: retention,
        source_scope: ContentDigest::sha256(b"capacity source"),
        av_scope: ContentDigest::sha256(b"capacity av"),
        source_deployment_limits: source_limits,
        av_deployment_limits: DeploymentLimits::standard(),
        limits: archive::Limits::default(),
        max_source_bytes: 1024 * 1024,
        work_limit: 4_000_000_000,
    };
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:unifi-capacity")?,
                started_at: TimestampNs(3),
            },
            &cx,
            async |task, cx| {
                let output = (|| -> Test {
                    let clock = MeteredClock::new(task, cx, TimestampNs(4))?;
                    let replay =
                        ReplayCx::from_context_authority(&replay_authority, temp.0.clone())?;
                    let av_replay =
                        ReplayCx::from_context_authority(&replay_authority, temp.0.clone())?;
                    let created = recording_storage::create(
                        task,
                        cx,
                        clock,
                        cfg,
                        replay,
                        av_replay,
                        Arc::new(Access(retention)),
                    )?;
                    let retired = created
                        .coordinator
                        .into_worker()
                        .retire()
                        .map_err(|_| "worker busy")?;
                    if retired.fenced || retired.pending.is_some() {
                        return Err("worker not idle".into());
                    }
                    let mut parts = retired.parts;
                    drop(created.av);
                    let mut wire = b"FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
                    for i in 0..130_u32 {
                        let payload = i.to_be_bytes();
                        wire.extend_from_slice(&[18, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0]);
                        wire.extend_from_slice(&payload);
                        wire.extend_from_slice(&15_u32.to_be_bytes());
                    }
                    let mut framer = Framer::new(FlvLimits::default(), 64 * 1024)?;
                    framer.append(0, &wire)?;
                    let mut count = 0;
                    while count < 129 {
                        let Next::Record(record) = framer.take()? else {
                            return Err("missing fixture record".into());
                        };
                        let disposition = if matches!(record.kind(), RecordKind::Header) {
                            SourceDisposition::Header
                        } else {
                            SourceDisposition::PreRoll
                        };
                        let plan = source_evidence::Prepared::new(
                            &record,
                            key,
                            disposition,
                            camera,
                            retention,
                            cfg.max_source_bytes,
                        )?;
                        archive::publish_unknown_time_source_anchored(
                            &plan,
                            &mut parts.deployment,
                            &Access(retention),
                            cfg.limits,
                            &mut WorkBudget::new(cfg.work_limit),
                            &parts.replay,
                            &mut parts.journal,
                            &mut parts.keeper,
                        )?;
                        count += 1;
                    }
                    assert_eq!(parts.deployment.publisher().visible_roots().count(), 129);
                    assert!(parts.journal.pending().is_none());
                    assert_eq!(parts.keeper.target(), parts.journal.anchor());
                    drop(parts);
                    let replay =
                        ReplayCx::from_context_authority(&replay_authority, temp.0.clone())?;
                    let reopened = ReferenceDeployment::open_with_limits(
                        &root.join("source"),
                        cfg.site_lineage,
                        source_limits,
                        &replay,
                    )?;
                    assert_eq!(*reopened.limits(), source_limits);
                    assert_eq!(reopened.publisher().visible_roots().count(), 129);
                    Ok(())
                })();
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("capacity fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(59_000_000_000),
                }
            },
        )
        .await?;
        result.receipt?;
        result.output
    })?;
    assert!(authority.finalize_report(&tree)?.is_empty());
    Ok(())
}

#[test]
fn insufficient_keeper_capacity_refuses_before_publication() -> Test {
    use fss_object::{
        HostSpoolIo,
        effect_journal::{EffectJournalLimits, FileEffectJournal},
    };
    use fss_runtime::effect_journal::EffectPersistenceError;

    let parent =
        std::env::temp_dir().join(format!("fss-unifi-keeper-capacity-{}", std::process::id()));
    std::fs::create_dir(&parent)?;
    let temp = Temp(std::fs::canonicalize(parent)?);
    let authority = fss_core::region::ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:keeper-capacity".into(),
        operation_id: OperationId::parse("operation:keeper-capacity")?,
        principal: "principal:fixture".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 1,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"keeper capacity fixture"),
        generation: 1,
    })?;
    let replay = ReplayCx::from_context_authority(&authority, temp.0.clone())?;
    let mut deployment =
        ReferenceDeployment::open(&temp.0.join("archive"), "site:keeper-capacity", &replay)?;
    let store = FileEffectJournal::create(
        temp.0.join("journal"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut journal = archive::journal::UnknownTimeJournal::create(
        Box::new(store),
        ContentDigest::sha256(b"keeper capacity scope"),
        &replay,
    )?;
    // Genesis occupies one slot; one slot remains, but a publication needs two keeper updates.
    let keeper_limits = EffectJournalLimits {
        max_records: 2,
        ..EffectJournalLimits::default()
    };
    let store =
        FileEffectJournal::create(temp.0.join("keeper"), keeper_limits, Arc::new(HostSpoolIo))?;
    let mut keeper =
        archive::journal::UnknownTimeAnchorKeeper::create(Box::new(store), &journal, &replay)?;
    let original_journal = journal.anchor();
    let original_keeper = keeper.anchor();
    let mut framer = Framer::new(FlvLimits::default(), 1024)?;
    framer.append(0, b"FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00")?;
    let Next::Record(record) = framer.take()? else {
        return Err("missing source header".into());
    };
    let retention = ContentDigest::sha256(b"keeper capacity retention");
    let plan = source_evidence::Prepared::new(
        &record,
        SourceKey {
            connection: 1,
            generation: 1,
        },
        SourceDisposition::Header,
        ContentDigest::sha256(b"keeper capacity camera"),
        retention,
        1024,
    )?;
    let result = archive::publish_unknown_time_source_anchored(
        &plan,
        &mut deployment,
        &Access(retention),
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &replay,
        &mut journal,
        &mut keeper,
    );
    assert!(
        matches!(
            result,
            Err(archive::UnknownTimePublishError::BeforePublication(
                archive::journal::Error::Storage(EffectPersistenceError::Capacity)
            ))
        ),
        "unexpected publication result: {result:?}"
    );
    assert_eq!(journal.anchor(), original_journal);
    assert_eq!(keeper.anchor(), original_keeper);
    assert_eq!(keeper.target(), original_journal);
    assert!(journal.pending().is_none());
    assert_eq!(deployment.publisher().visible_roots().count(), 0);

    // Reopen the unchanged keeper with one additional slot, then publish.
    // Repeating that same confirmed candidate must not need another slot.
    drop(keeper);
    let larger = EffectJournalLimits {
        max_records: 3,
        ..keeper_limits
    };
    let store = FileEffectJournal::open(
        temp.0.join("keeper"),
        larger,
        Arc::new(HostSpoolIo),
        original_keeper,
    )?;
    let mut keeper = archive::journal::UnknownTimeAnchorKeeper::reopen(
        Box::new(store),
        &journal,
        original_keeper,
        &replay,
    )?;
    for _ in 0..2 {
        archive::publish_unknown_time_source_anchored(
            &plan,
            &mut deployment,
            &Access(retention),
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &replay,
            &mut journal,
            &mut keeper,
        )?;
        assert_eq!(keeper.target(), journal.anchor());
        assert!(journal.pending().is_none());
        assert_eq!(deployment.publisher().visible_roots().count(), 1);
    }

    // A pending candidate whose first keeper update was retained needs only
    // one remaining update, so capacity preflight must admit its exact retry.
    struct Deny;
    impl archive::RetainAuthority for Deny {
        fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
            false
        }
    }
    let store = FileEffectJournal::create(
        temp.0.join("pending-journal"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut pending_journal = archive::journal::UnknownTimeJournal::create(
        Box::new(store),
        ContentDigest::sha256(b"pending capacity scope"),
        &replay,
    )?;
    let store =
        FileEffectJournal::create(temp.0.join("pending-keeper"), larger, Arc::new(HostSpoolIo))?;
    let mut pending_keeper = archive::journal::UnknownTimeAnchorKeeper::create(
        Box::new(store),
        &pending_journal,
        &replay,
    )?;
    let mut pending_deployment = ReferenceDeployment::open(
        &temp.0.join("pending-archive"),
        "site:keeper-capacity",
        &replay,
    )?;
    assert!(matches!(
        archive::publish_unknown_time_source_anchored(
            &plan,
            &mut pending_deployment,
            &Deny,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &replay,
            &mut pending_journal,
            &mut pending_keeper,
        ),
        Err(archive::UnknownTimePublishError::Archive(
            archive::Error::Denied
        ))
    ));
    assert!(pending_journal.pending().is_some());
    assert_eq!(pending_keeper.target(), pending_journal.anchor());
    archive::publish_unknown_time_source_anchored(
        &plan,
        &mut pending_deployment,
        &Access(retention),
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &replay,
        &mut pending_journal,
        &mut pending_keeper,
    )?;
    assert!(pending_journal.pending().is_none());
    assert_eq!(pending_keeper.target(), pending_journal.anchor());
    assert_eq!(pending_deployment.publisher().visible_roots().count(), 1);
    Ok(())
}

#[test]
fn worker_reports_keeper_capacity_and_retains_source() -> Test {
    use fss_object::{
        HostSpoolIo,
        effect_journal::{EffectJournalLimits, FileEffectJournal},
    };
    use fss_reference::unifi_direct::{av_worker, source_worker};

    let parent =
        std::env::temp_dir().join(format!("fss-unifi-worker-capacity-{}", std::process::id()));
    std::fs::create_dir(&parent)?;
    let temp = Temp(std::fs::canonicalize(parent)?);
    let mut budget = BudgetVector::ZERO;
    budget.bytes = 64 * 1024 * 1024;
    let spec =
        |name: &str, capabilities: Vec<String>| -> Result<RootAuthoritySpec, Box<dyn Error>> {
            Ok(RootAuthoritySpec {
                trace_id: format!("trace:{name}"),
                operation_id: OperationId::parse(&format!("operation:{name}"))?,
                principal: "principal:fixture".into(),
                capabilities,
                deadline: None,
                priority: 1,
                budgets: budget,
                privacy_scope: "privacy:test".into(),
                retention_scope: "retention:test".into(),
                anchor_universe: ContentDigest::sha256(b"worker capacity fixture"),
                generation: 1,
            })
        };
    let (mut authority, mut tree) = AuthorityCx::root(
        spec(
            "worker-capacity",
            vec![
                RuntimeGrant::ObjectPublish.as_str().into(),
                RuntimeGrant::ObjectStage.as_str().into(),
            ],
        )?,
        RegionId::new("region:worker-capacity")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let replay_authority = fss_core::region::ContextAuthority::new_root(spec(
        "worker-capacity-replay",
        vec!["ADP-REPLAY-001".into()],
    )?)?;
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:worker-capacity")?,
                started_at: TimestampNs(3),
            },
            &cx,
            async |task, cx| {
                let output: Test = async {
                    let clock = MeteredClock::new(task, cx, TimestampNs(4))?;
                    let replay =
                        ReplayCx::from_context_authority(&replay_authority, temp.0.clone())?;
                    let deployment = ReferenceDeployment::open(
                        &temp.0.join("archive"),
                        "site:worker-capacity",
                        &replay,
                    )?;
                    let store = FileEffectJournal::create(
                        temp.0.join("journal"),
                        EffectJournalLimits::default(),
                        Arc::new(HostSpoolIo),
                    )?;
                    let journal = archive::journal::UnknownTimeJournal::create(
                        Box::new(store),
                        ContentDigest::sha256(b"worker capacity scope"),
                        &replay,
                    )?;
                    let store = FileEffectJournal::create(
                        temp.0.join("keeper"),
                        EffectJournalLimits {
                            max_records: 2,
                            ..EffectJournalLimits::default()
                        },
                        Arc::new(HostSpoolIo),
                    )?;
                    let keeper = archive::journal::UnknownTimeAnchorKeeper::create(
                        Box::new(store),
                        &journal,
                        &replay,
                    )?;
                    let journal_head = journal.anchor();
                    let keeper_head = keeper.anchor();
                    let retention = ContentDigest::sha256(b"worker capacity retention");
                    let mut worker = source_worker::Worker::new(source_worker::Parts {
                        deployment,
                        journal,
                        keeper,
                        replay,
                        authority: Arc::new(Access(retention)),
                        retention,
                        limits: archive::Limits::default(),
                        max_source_bytes: 1024,
                        work_limit: 4_000_000_000,
                    })
                    .map_err(|_| "worker configuration rejected")?;
                    let mut framer = Framer::new(FlvLimits::default(), 1024)?;
                    framer.append(0, b"FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00")?;
                    let Next::Record(record) = framer.take()? else {
                        return Err("missing source header".into());
                    };
                    let original_digest = ContentDigest::sha256(record.bytes());
                    worker
                        .offer(source_worker::Input::Original {
                            record,
                            key: SourceKey {
                                connection: 1,
                                generation: 1,
                            },
                            disposition: SourceDisposition::Header,
                            camera_claim: ContentDigest::sha256(b"worker capacity camera"),
                        })
                        .map_err(|_| "offer refused")?;
                    worker
                        .start(
                            task,
                            cx,
                            clock,
                            "fixture:worker-capacity",
                            &BudgetVector::ZERO,
                        )
                        .map_err(|error| format!("worker start refused: {error:?}"))?;
                    let completion = worker.join().await.ok_or("worker did not finish")?;
                    assert!(completion.runtime.is_ok());
                    assert!(matches!(
                        completion.outcome,
                        source_worker::Outcome::Publication(source_worker::Publication::Refused {
                            reason: source_worker::Refusal::BeforePublication(
                                av_worker::FailureReason::JournalCapacity
                            ),
                            ..
                        })
                    ));
                    let retired = worker.retire().map_err(|_| "worker still running")?;
                    assert!(!retired.fenced);
                    assert_eq!(retired.parts.journal.anchor(), journal_head);
                    assert_eq!(retired.parts.keeper.anchor(), keeper_head);
                    assert_eq!(retired.parts.keeper.target(), journal_head);
                    assert_eq!(
                        retired.parts.deployment.publisher().visible_roots().count(),
                        0
                    );
                    match retired.pending.ok_or("source was lost")? {
                        source_worker::Input::Original { record, .. } => {
                            assert_eq!(ContentDigest::sha256(record.bytes()), original_digest)
                        }
                        _ => return Err("source kind changed".into()),
                    }
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("worker capacity fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(59_000_000_000),
                }
            },
        )
        .await?;
        result.receipt?;
        result.output
    })?;
    assert!(authority.finalize_report(&tree)?.is_empty());
    Ok(())
}
