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
