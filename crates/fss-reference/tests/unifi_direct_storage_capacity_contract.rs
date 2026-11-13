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
fn rollover_readback_preserves_cancellation_classification() {
    use fss_geometry::GeometryError;
    use fss_reference::unifi_direct::av_rollover_worker::ArchiveFailure;

    assert_eq!(
        ArchiveFailure::from(archive::Error::Work(GeometryError::Cancelled)),
        ArchiveFailure::Cancelled
    );
    assert_eq!(
        ArchiveFailure::from(archive::Error::Work(GeometryError::BudgetExhausted)),
        ArchiveFailure::BudgetExhausted
    );
    assert_eq!(ArchiveFailure::from(archive::Error::Work(GeometryError::OutOfRange)), ArchiveFailure::Work);
    assert_eq!(ArchiveFailure::from(archive::Error::Cancelled), ArchiveFailure::Cancelled);
}

#[test]
fn rollover_supply_worker_retains_partial_and_ready_owners() -> Test {
    use fss_object::{HostSpoolIo, effect_journal::{EffectJournalLimits, FileEffectJournal, FileTrustedRootPinRetainer}};
    use fss_reference::unifi_direct::av_rollover_supplies::{Inputs, Outcome, Stage, Worker};
    use fss_runtime::effect_journal::{EffectJournalStore, PinRetainedEffectJournal};
    use std::os::unix::fs::PermissionsExt;

    let parent = std::env::temp_dir().join(format!("fss-supply-worker-{}", std::process::id()));
    std::fs::create_dir(&parent)?;
    let temp = Temp(std::fs::canonicalize(parent)?);
    let mut budget = BudgetVector::ZERO;
    budget.bytes = 64 * 1024 * 1024;
    let spec = |name: &str, capabilities: Vec<String>| -> Result<RootAuthoritySpec, Box<dyn Error>> {
        Ok(RootAuthoritySpec { trace_id: format!("trace:{name}"), operation_id: OperationId::parse(&format!("operation:{name}"))?, principal: "principal:fixture".into(), capabilities, deadline: None, priority: 1, budgets: budget, privacy_scope: "privacy:test".into(), retention_scope: "retention:test".into(), anchor_universe: ContentDigest::sha256(b"supply worker fixture"), generation: 1 })
    };
    let (mut authority, mut tree) = AuthorityCx::root(spec("supply-worker", vec![RuntimeGrant::ObjectStage.as_str().into()])?, RegionId::new("region:supply-worker")?, RegionKind::Process, budget, TimestampNs(1))?;
    let replay_authority = fss_core::region::ContextAuthority::new_root(spec("supply-replay",vec!["ADP-REPLAY-001".into()])?)?;
    let limits = EffectJournalLimits::default();
    let runtime = RuntimeBuilder::current_thread().blocking_threads(1,1).build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(&mut authority,&mut tree,TaskSpec {task_id:TaskId::new("task:supply-worker")?,started_at:TimestampNs(3)},&cx,async |task,cx| {
            let output: Test = async {
                let clock = MeteredClock::new(task,cx,TimestampNs(4))?;
                let make = |name: &str| -> Result<Inputs, Box<dyn Error>> {
                    let retainer = FileTrustedRootPinRetainer::create(temp.0.join(format!("{name}-retainer")),limits,Arc::new(HostSpoolIo),ContentDigest::sha256(name.as_bytes()))?;
                    let switch = FileEffectJournal::create(temp.0.join(format!("{name}-switch")),limits,Arc::new(HostSpoolIo))?;
                    Ok(Inputs {root:temp.0.join(name), replay:Arc::new(ReplayCx::from_context_authority(&replay_authority,temp.0.clone())?), io:Arc::new(HostSpoolIo), journal_limits:limits, switch:fss_reference::unifi_direct::av_rollover_supplies::SwitchInput::Prepared(PinRetainedEffectJournal::new(Box::new(switch),Box::new(retainer))?), read:Arc::new(Access(ContentDigest::sha256(b"retention"))), object_limits:archive::StagedAvLimits {max_objects:16,max_object_bytes:4096,max_total_bytes:65536},work_limit:100_000})
                };

                let mut invalid = make("invalid")?;
                invalid.root=temp.0.join("outside").join("nested");
                let invalid=match Worker::new(invalid) {Err(inputs)=>inputs,Ok(_)=>return Err("invalid parent accepted".into())};
                assert!(!invalid.root.exists());
                drop(invalid);

                let collision=make("collision")?;
                std::fs::create_dir(&collision.root)?;
                std::fs::write(collision.root.join("sentinel"),b"unchanged")?;
                let mut worker=Worker::new(collision).map_err(|_|"collision setup invalid")?;
                worker.start(task,cx,clock,&BudgetVector::ZERO).map_err(|_|"collision admission refused")?;
                let completion=worker.join().await.ok_or("collision not joined")?;
                assert!(completion.runtime.is_ok());
                assert_eq!(completion.outcome,Outcome::Refused(Stage::Root));
                let mut retired=worker.retire().map_err(|_|"collision still running")?;
                assert!(!retired.root_created && retired.journal.is_none() && retired.keeper.is_none());
                assert!(retired.take_supplies().is_none());
                assert_eq!(std::fs::read(retired.inputs.as_ref().ok_or("collision input lost")?.root.join("sentinel"))?,b"unchanged");
                drop(retired);

                let interrupted=make("interrupted")?;
                interrupted.replay.set_cancel_at_checkpoint_occurrence("unifi-rollover-supplies-create",4);
                let mut worker=Worker::new(interrupted).map_err(|_|"interrupt setup invalid")?;
                worker.start(task,cx,clock,&BudgetVector::ZERO).map_err(|_|"interrupt admission refused")?;
                let completion=worker.join().await.ok_or("interrupt not joined")?;
                assert!(completion.runtime.is_ok());
                assert_eq!(completion.outcome,Outcome::Refused(Stage::Checkpoint));
                let mut retired=worker.retire().map_err(|_|"interrupt still running")?;
                assert!(retired.root_created && retired.journal.is_some() && retired.keeper.is_none());
                assert!(retired.inputs.is_some() && retired.take_supplies().is_none());
                drop(retired);

                let ready=make("ready")?;
                let mut worker=Worker::new(ready).map_err(|_|"ready setup invalid")?;
                worker.start(task,cx,clock,&BudgetVector::ZERO).map_err(|_|"ready admission refused")?;
                assert!(matches!(worker.start(task,cx,clock,&BudgetVector::ZERO),Err(fss_reference::unifi_direct::av_rollover_supplies::StartError::Running)));
                let mut worker=worker.retire().err().ok_or("running worker retired")?;
                let completion=worker.join().await.ok_or("ready not joined")?;
                assert!(completion.runtime.is_ok());
                assert_eq!(completion.outcome,Outcome::Ready);
                let mut retired=worker.retire().map_err(|_|"ready still running")?;
                assert_eq!(std::fs::metadata(temp.0.join("ready"))?.permissions().mode() & 0o777,0o700);
                let created=retired.take_supplies().ok_or("ready supplies lost")?;
                assert_eq!(created.root,temp.0.join("ready"));
                assert_eq!(created.journal_limits,limits);
                let supplies=created.supplies;
                assert!(supplies.next_journal.head().is_none() && supplies.next_keeper.head().is_none());
                assert!(supplies.switch.head().is_none());
                assert!(retired.take_supplies().is_none());

                let make_auto = |name: &str| -> Result<Inputs, Box<dyn Error>> {
                    Ok(Inputs { root:temp.0.join(name), replay:Arc::new(ReplayCx::from_context_authority(&replay_authority,temp.0.clone())?), io:Arc::new(HostSpoolIo), journal_limits:limits, switch:fss_reference::unifi_direct::av_rollover_supplies::SwitchInput::Create(fss_reference::unifi_direct::av_rollover_supplies::SwitchCustody {root:temp.0.join(format!("{name}-pin")), replay:Arc::new(ReplayCx::from_context_authority(&replay_authority,temp.0.clone())?), io:Arc::new(HostSpoolIo), limits, scope:ContentDigest::sha256(name.as_bytes())}), read:Arc::new(Access(ContentDigest::sha256(b"retention"))), object_limits:archive::StagedAvLimits {max_objects:16,max_object_bytes:4096,max_total_bytes:65536}, work_limit:100_000 })
                };
                let mut overlap=make_auto("overlap")?;
                if let fss_reference::unifi_direct::av_rollover_supplies::SwitchInput::Create(custody)=&mut overlap.switch {custody.root=overlap.root.clone();}
                let overlap=match Worker::new(overlap) {Err(inputs)=>inputs,Ok(_)=>return Err("overlapping custody accepted".into())};
                assert!(!overlap.root.exists());
                drop(overlap);

                let collision=make_auto("pin-collision")?;
                let pin_root=match &collision.switch {fss_reference::unifi_direct::av_rollover_supplies::SwitchInput::Create(custody)=>custody.root.clone(),_=>return Err("pin plan missing".into())};
                std::fs::create_dir(&pin_root)?;
                std::fs::write(pin_root.join("sentinel"),b"untouched")?;
                let mut worker=Worker::new(collision).map_err(|_|"pin collision setup invalid")?;
                worker.start(task,cx,clock,&BudgetVector::ZERO).map_err(|_|"pin collision admission refused")?;
                let completion=worker.join().await.ok_or("pin collision not joined")?;
                assert!(completion.runtime.is_ok());
                assert_eq!(completion.outcome,Outcome::Refused(Stage::PinRoot));
                let mut retired=worker.retire().map_err(|_|"pin collision still running")?;
                assert!(retired.root_created && !retired.pin_root_created && retired.journal.is_some() && retired.keeper.is_some());
                assert!(retired.take_supplies().is_none());
                assert_eq!(std::fs::read(pin_root.join("sentinel"))?,b"untouched");
                drop(retired);

                let interrupted=make_auto("pin-interrupted")?;
                interrupted.replay.set_cancel_at_checkpoint_occurrence("unifi-rollover-supplies-create",8);
                let mut worker=Worker::new(interrupted).map_err(|_|"pin interruption setup invalid")?;
                worker.start(task,cx,clock,&BudgetVector::ZERO).map_err(|_|"pin interruption admission refused")?;
                let completion=worker.join().await.ok_or("pin interruption not joined")?;
                assert!(completion.runtime.is_ok());
                assert_eq!(completion.outcome,Outcome::Refused(Stage::Checkpoint));
                let mut retired=worker.retire().map_err(|_|"pin interruption still running")?;
                assert!(retired.root_created && retired.pin_root_created && retired.journal.is_some() && retired.keeper.is_some() && retired.pin_retainer.is_some() && retired.switch_journal.is_none() && retired.switch.is_none());
                assert!(retired.inputs.is_some() && retired.take_supplies().is_none());
                drop(retired);

                let automatic=make_auto("automatic")?;
                let mut worker=Worker::new(automatic).map_err(|_|"automatic switch setup invalid")?;
                worker.start(task,cx,clock,&BudgetVector::ZERO).map_err(|_|"automatic switch admission refused")?;
                let completion=worker.join().await.ok_or("automatic switch not joined")?;
                assert!(completion.runtime.is_ok());
                assert_eq!(completion.outcome,Outcome::Ready);
                let mut retired=worker.retire().map_err(|_|"automatic switch still running")?;
                assert!(retired.root_created && retired.pin_root_created && retired.switch.is_some());
                let created=retired.take_supplies().ok_or("automatic switch supplies lost")?;
                let custody=created.switch_custody.ok_or("automatic switch custody lost")?;
                assert_eq!(custody.root,temp.0.join("automatic-pin"));
                assert!(created.supplies.switch.head().is_none());
                assert!(created.supplies.next_journal.head().is_none() && created.supplies.next_keeper.head().is_none());
                assert!(retired.take_supplies().is_none());

                let shared_journal=Arc::new(ReplayCx::from_context_authority(&replay_authority,temp.0.clone())?);
                let shared_pin=Arc::new(ReplayCx::from_context_authority(&replay_authority,temp.0.clone())?);
                let configuration=|namespace:&str,first:u64,count:u64| fss_reference::unifi_direct::av_rollover_generation::Configuration {namespace:namespace.into(),scope_seed:ContentDigest::sha256(b"generation seed"),first,count,journal_replay:shared_journal.clone(),pin_replay:shared_pin.clone(),journal_io:Arc::new(HostSpoolIo),pin_io:Arc::new(HostSpoolIo),journal_limits:limits,pin_limits:limits,read:Arc::new(Access(ContentDigest::sha256(b"retention"))),object_limits:archive::StagedAvLimits {max_objects:16,max_object_bytes:4096,max_total_bytes:65536},work_limit:100_000};
                assert!(fss_reference::unifi_direct::av_rollover_generation::Plan::new(configuration("../invalid",7,2)).is_err());
                assert!(fss_reference::unifi_direct::av_rollover_generation::Plan::new(configuration("camera_a",u64::MAX,2)).is_err());
                let mut plan=fss_reference::unifi_direct::av_rollover_generation::Plan::new(configuration("camera_a",7,2)).map_err(|_|"generation plan refused")?;
                assert!(plan.extend(1).is_err());
                let (first,worker)=plan.next_worker().map_err(|_|"first generation refused")?.ok_or("first generation absent")?;
                let mut twin=fss_reference::unifi_direct::av_rollover_generation::Plan::new(configuration("camera_a",7,2)).map_err(|_|"matching plan refused")?;
                let (same,twin_worker)=twin.next_worker().map_err(|_|"matching generation refused")?.ok_or("matching generation absent")?;
                assert_eq!(same,first);
                assert!(twin_worker.retire().map_err(|_|"matching worker unexpectedly running")?.inputs.is_some());
                assert_eq!(first.generation,7);
                assert!(!first.journal_root.exists() && !first.pin_root.exists());
                let first_retired=worker.retire().map_err(|_|"first planned worker unexpectedly running")?;
                let first_inputs=first_retired.inputs.ok_or("first planned inputs lost")?;
                assert!(Arc::ptr_eq(&first_inputs.replay,&shared_journal));
                shared_journal.request_cancellation();
                let (second,mut worker)=plan.next_worker().map_err(|_|"second generation refused")?.ok_or("second generation absent")?;
                assert_eq!(second.generation,8);
                assert_ne!(first.journal_root,second.journal_root);
                assert_ne!(first.pin_scope,second.pin_scope);
                assert!(matches!(worker.start(task,cx,clock,&BudgetVector::ZERO),Err(fss_reference::unifi_direct::av_rollover_supplies::StartError::Replay)));
                assert!(!second.journal_root.exists() && !second.pin_root.exists());
                let second_retired=worker.retire().map_err(|_|"second planned worker unexpectedly running")?;
                assert!(Arc::ptr_eq(&second_retired.inputs.ok_or("second planned inputs lost")?.replay,&shared_journal));
                assert_eq!(plan.remaining(),0);
                assert!(plan.next_worker().map_err(|_|"exhausted generation failed")?.is_none());
                assert!(plan.extend(0).is_err());
                assert!(plan.extend(1_000_001).is_err());
                assert_eq!(plan.remaining(),0);
                plan.extend(2).map_err(|_|"bounded plan extension refused")?;
                let (third,worker)=plan.next_worker().map_err(|_|"extended generation refused")?.ok_or("extended generation missing")?;
                assert_eq!(third.generation,9);
                assert_ne!(second.pin_scope,third.pin_scope);
                assert!(!third.journal_root.exists() && !third.pin_root.exists());
                assert!(worker.retire().map_err(|_|"extended worker unexpectedly running")?.inputs.is_some());
                assert!(plan.extend(1).is_err());
                let (fourth,worker)=plan.next_worker().map_err(|_|"fourth generation refused")?.ok_or("fourth generation missing")?;
                assert_eq!(fourth.generation,10);
                assert!(worker.retire().map_err(|_|"fourth worker unexpectedly running")?.inputs.is_some());
                let mut final_plan=fss_reference::unifi_direct::av_rollover_generation::Plan::new(configuration("last",u64::MAX,1)).map_err(|_|"last generation plan refused")?;
                let (_,worker)=final_plan.next_worker().map_err(|_|"last generation refused")?.ok_or("last generation missing")?;
                assert!(worker.retire().map_err(|_|"last worker unexpectedly running")?.inputs.is_some());
                assert!(final_plan.extend(1).is_err());
                assert_eq!(final_plan.remaining(),0);
                Ok(())
            }.await;
            let outcome=if output.is_ok() {TaskOutcome::Success} else {TaskOutcome::Failed("supply worker fixture".into())};
            TaskCompletion {output,outcome,completed_at:TimestampNs(60_000_000_000)}
        }).await?;
        result.receipt?;
        result.output
    })?;
    assert!(authority.finalize_report(&tree)?.is_empty());
    Ok(())
}

#[test]
fn retained_generation_reservations_survive_reopen_and_refuse_mismatch() -> Test {
    use fss_object::{HostSpoolIo, effect_journal::{EffectJournalLimits, FileEffectJournal, FileTrustedRootPinRetainer}};
    use fss_reference::unifi_direct::av_rollover_generation::{Configuration, DiscoverError, InventoryDisposition, InventoryError, Plan, ReservedPlan, ReservationError};
    use fss_runtime::effect_journal::PinRetainedEffectJournal;

    let root=std::env::temp_dir().join(format!("fss-generation-reservation-{}",std::process::id()));
    std::fs::create_dir(&root)?;
    let temp=Temp(std::fs::canonicalize(root)?);
    let authority=fss_core::region::ContextAuthority::new_root(RootAuthoritySpec {
        trace_id:"trace:generation-reservation".into(),operation_id:OperationId::parse("operation:generation-reservation")?,principal:"principal:fixture".into(),
        capabilities:vec!["ADP-REPLAY-001".into()],deadline:None,priority:1,budgets:BudgetVector::builder().bytes(64*1024*1024).build()?,
        privacy_scope:"privacy:test".into(),retention_scope:"retention:test".into(),anchor_universe:ContentDigest::sha256(b"generation reservation fixture"),generation:1,
    })?;
    let replay=Arc::new(ReplayCx::from_context_authority(&authority,temp.0.clone())?);
    let limits=EffectJournalLimits::default();
    let config=|namespace:&str,first:u64| Configuration {
        namespace:namespace.into(),scope_seed:ContentDigest::sha256(b"reservation scope"),first,count:2,
        journal_replay:replay.clone(),pin_replay:replay.clone(),journal_io:Arc::new(HostSpoolIo),pin_io:Arc::new(HostSpoolIo),
        journal_limits:limits,pin_limits:limits,read:Arc::new(Access(ContentDigest::sha256(b"retention"))),
        object_limits:archive::StagedAvLimits {max_objects:16,max_object_bytes:4096,max_total_bytes:65536},work_limit:100_000,
    };
    let store=FileEffectJournal::create(temp.0.join("reservations"),limits,Arc::new(HostSpoolIo))?;
    let pin_scope=ContentDigest::sha256(b"reservation independent pin fixture");
    let retainer=FileTrustedRootPinRetainer::create(temp.0.join("reservation-pin"),limits,Arc::new(HostSpoolIo),pin_scope)?;
    let journal=PinRetainedEffectJournal::new(Box::new(store),Box::new(retainer))?;
    let plan=Plan::new(config("camera",20)).map_err(|_|"reservation plan invalid")?;
    let mut reserved=ReservedPlan::create(plan,journal,&replay).map_err(|_|"reservation creation refused")?;
    let (first,worker)=reserved.reserve_next(&replay).map_err(|_|"first reservation refused")?.ok_or("first reservation absent")?;
    assert_eq!(first.generation,20);
    assert!(!first.journal_root.exists() && !first.pin_root.exists());
    assert!(worker.retire().map_err(|_|"reserved worker unexpectedly running")?.inputs.is_some());
    let retained_head=reserved.head().ok_or("reservation head missing")?;
    assert_eq!(retained_head.sequence,2);
    let page=reserved.inventory_page(None,1,32,&mut WorkBudget::new(100_000),&replay).map_err(|_|"pending inventory refused")?;
    assert_eq!(page.snapshot,retained_head);
    assert_eq!(page.entries.len(),1);
    assert_eq!(page.entries[0].identity,first);
    assert_eq!(page.entries[0].disposition,InventoryDisposition::Pending);
    assert!(page.next.is_none());
    assert!(matches!(reserved.inventory_page(None,1,1,&mut WorkBudget::new(100_000),&replay),Err(InventoryError::Limit)));
    assert!(matches!(reserved.inventory_page(None,1,32,&mut WorkBudget::new(0),&replay),Err(InventoryError::Work(fss_geometry::GeometryError::BudgetExhausted))));
    let cancelled=ReplayCx::from_context_authority(&authority,temp.0.clone())?;
    cancelled.request_cancellation();
    assert!(matches!(reserved.inventory_page(None,1,32,&mut WorkBudget::new(100_000),&cancelled),Err(InventoryError::Cancelled)));
    assert_eq!(reserved.head(),Some(retained_head));
    let (_plan,journal)=reserved.into_parts();
    drop(journal);
    let reopened=FileEffectJournal::open(temp.0.join("reservations"),limits,Arc::new(HostSpoolIo),retained_head)?;
    let retainer=FileTrustedRootPinRetainer::open_trusting_storage(temp.0.join("reservation-pin"),limits,Arc::new(HostSpoolIo),pin_scope)?;
    let journal=PinRetainedEffectJournal::for_reconciliation(Box::new(reopened),Box::new(retainer))?;
    let wrong=Plan::new(config("camera",20)).map_err(|_|"wrong plan invalid")?;
    let refusal=match ReservedPlan::recover(wrong,journal,&replay) {Err(refusal)=>refusal,Ok(_)=>return Err("reused generation admitted".into())};
    assert!(matches!(refusal.reason,ReservationError::Invalid));
    let wrong_scope=Plan::new(config("different-camera",21)).map_err(|_|"wrong scope plan invalid")?;
    let refusal=match ReservedPlan::recover(wrong_scope,refusal.journal,&replay) {Err(refusal)=>refusal,Ok(_)=>return Err("different configuration admitted".into())};
    assert!(matches!(refusal.reason,ReservationError::Invalid));
    let wrong_first=Plan::new(config("camera",19)).map_err(|_|"wrong starting generation invalid")?;
    let refusal=match ReservedPlan::recover_discovered(wrong_first,refusal.journal,&replay,32,&mut WorkBudget::new(100_000)) {Err(refusal)=>refusal,Ok(_)=>return Err("wrong original generation accepted".into())};
    assert!(matches!(refusal.reason,DiscoverError::Invalid));
    let plan=Plan::new(config("camera",20)).map_err(|_|"recovery plan invalid")?;
    let refusal=match ReservedPlan::recover_discovered(plan,refusal.journal,&replay,1,&mut WorkBudget::new(100_000)) {Err(refusal)=>refusal,Ok(_)=>return Err("undersized discovery scan accepted".into())};
    assert!(matches!(refusal.reason,DiscoverError::Limit));
    let refusal=match ReservedPlan::recover_discovered(refusal.plan,refusal.journal,&replay,32,&mut WorkBudget::new(0)) {Err(refusal)=>refusal,Ok(_)=>return Err("unbudgeted discovery accepted".into())};
    assert!(matches!(refusal.reason,DiscoverError::Work(fss_geometry::GeometryError::BudgetExhausted)));
    let cancelled=ReplayCx::from_context_authority(&authority,temp.0.clone())?;
    cancelled.request_cancellation();
    let refusal=match ReservedPlan::recover_discovered(refusal.plan,refusal.journal,&cancelled,32,&mut WorkBudget::new(100_000)) {Err(refusal)=>refusal,Ok(_)=>return Err("cancelled discovery accepted".into())};
    assert!(matches!(refusal.reason,DiscoverError::Cancelled));
    let mut recovered=ReservedPlan::recover_discovered(refusal.plan,refusal.journal,&replay,32,&mut WorkBudget::new(100_000)).map_err(|_|"automatic reservation recovery refused")?;
    assert_eq!(recovered.pending(),Some(&first));
    let refusal=match recovered.reserve_next(&replay) {Err(refusal)=>refusal,Ok(_)=>return Err("unreconciled reservation admitted".into())};
    assert!(matches!(refusal.reason,ReservationError::ReconciliationRequired) && refusal.candidate.is_none());
    let mut wrong_identity=first.clone(); wrong_identity.generation+=1;
    assert!(matches!(recovered.record_reconciliation(&wrong_identity,ContentDigest::sha256(b"fixture evidence"),&replay),Err(ReservationError::Invalid)));
    recovered.record_reconciliation(&first,ContentDigest::sha256(b"fixture evidence"),&replay).map_err(|_|"reconciliation record refused")?;
    assert!(recovered.pending().is_none());
    let (second,worker)=recovered.reserve_next(&replay).map_err(|_|"second reservation refused")?.ok_or("second reservation absent")?;
    assert_eq!(second.generation,21);
    assert_ne!(first.pin_scope,second.pin_scope);
    assert_eq!(recovered.head().ok_or("second head missing")?.sequence,4);
    assert!(worker.retire().map_err(|_|"second worker unexpectedly running")?.inputs.is_some());
    assert!(!second.journal_root.exists() && !second.pin_root.exists());
    let page=recovered.inventory_page(None,1,32,&mut WorkBudget::new(100_000),&replay).map_err(|_|"first inventory page refused")?;
    assert_eq!(page.entries.len(),1);
    assert_eq!(page.entries[0].identity,first);
    assert_eq!(page.entries[0].disposition,InventoryDisposition::Reconciled(ContentDigest::sha256(b"fixture evidence")));
    let cursor=page.next.ok_or("inventory continuation missing")?;
    let next=recovered.inventory_page(Some(&cursor),1,32,&mut WorkBudget::new(100_000),&replay).map_err(|_|"second inventory page refused")?;
    assert_eq!(next.entries.len(),1);
    assert_eq!(next.entries[0].identity,second);
    assert_eq!(next.entries[0].disposition,InventoryDisposition::Pending);
    assert!(next.next.is_none());
    recovered.record_reconciliation(&second,ContentDigest::sha256(b"second fixture evidence"),&replay).map_err(|_|"second reconciliation refused")?;
    assert!(matches!(recovered.inventory_page(Some(&cursor),1,32,&mut WorkBudget::new(100_000),&replay),Err(InventoryError::Stale)));
    let page=recovered.inventory_page(None,2,32,&mut WorkBudget::new(100_000),&replay).map_err(|_|"refreshed inventory refused")?;
    assert_eq!(page.entries.len(),2);
    assert_eq!(page.entries[1].disposition,InventoryDisposition::Reconciled(ContentDigest::sha256(b"second fixture evidence")));

    let small=EffectJournalLimits {max_records:2,..limits};
    let store=FileEffectJournal::create(temp.0.join("small-reservations"),small,Arc::new(HostSpoolIo))?;
    let pin=FileTrustedRootPinRetainer::create(temp.0.join("small-reservation-pin"),limits,Arc::new(HostSpoolIo),ContentDigest::sha256(b"small pin"))?;
    let journal=PinRetainedEffectJournal::new(Box::new(store),Box::new(pin))?;
    let plan=Plan::new(config("small",40)).map_err(|_|"small plan invalid")?;
    let mut limited=ReservedPlan::create(plan,journal,&replay).map_err(|_|"small reservation creation refused")?;
    let (identity,worker)=limited.reserve_next(&replay).map_err(|_|"small reservation refused")?.ok_or("small reservation absent")?;
    assert!(worker.retire().map_err(|_|"small worker unexpectedly running")?.inputs.is_some());
    assert!(matches!(limited.record_reconciliation(&identity,ContentDigest::sha256(b"fixture evidence"),&replay),Err(ReservationError::Storage(_))));
    assert_eq!(limited.pending(),Some(&identity));
    let refusal=match limited.reserve_next(&replay) {Err(refusal)=>refusal,Ok(_)=>return Err("fenced reservation admitted".into())};
    assert!(matches!(refusal.reason,ReservationError::Fenced) && refusal.candidate.is_none());

    let store=FileEffectJournal::create(temp.0.join("cancel-reservations"),limits,Arc::new(HostSpoolIo))?;
    let cancel_scope=ContentDigest::sha256(b"cancel reservation pin");
    let pin=FileTrustedRootPinRetainer::create(temp.0.join("cancel-reservation-pin"),limits,Arc::new(HostSpoolIo),cancel_scope)?;
    let journal=PinRetainedEffectJournal::new(Box::new(store),Box::new(pin))?;
    let plan=Plan::new(config("cancel",50)).map_err(|_|"cancel plan invalid")?;
    let cancel=ReplayCx::from_context_authority(&authority,temp.0.clone())?;
    let mut interrupted=ReservedPlan::create(plan,journal,&cancel).map_err(|_|"cancel reservation creation refused")?;
    cancel.set_cancel_at_checkpoint_occurrence("unifi-generation-reservation",3);
    let refusal=match interrupted.reserve_next(&cancel) {Err(refusal)=>refusal,Ok(_)=>return Err("post-append cancellation did not refuse".into())};
    assert!(matches!(refusal.reason,ReservationError::Cancelled));
    let (selected,worker)=refusal.candidate.ok_or("cancelled reservation candidate lost")?;
    assert_eq!(selected.generation,50);
    assert!(worker.retire().map_err(|_|"cancelled worker unexpectedly running")?.inputs.is_some());
    let pin=interrupted.head().ok_or("cancelled retained head missing")?;
    assert_eq!(pin.sequence,2);
    let refusal=match interrupted.reserve_next(&replay) {Err(refusal)=>refusal,Ok(_)=>return Err("cancelled owner resumed".into())};
    assert!(matches!(refusal.reason,ReservationError::Fenced));
    let (_,journal)=interrupted.into_parts();drop(journal);
    let store=FileEffectJournal::open(temp.0.join("cancel-reservations"),limits,Arc::new(HostSpoolIo),pin)?;
    let keeper=FileTrustedRootPinRetainer::open_trusting_storage(temp.0.join("cancel-reservation-pin"),limits,Arc::new(HostSpoolIo),cancel_scope)?;
    let journal=PinRetainedEffectJournal::for_reconciliation(Box::new(store),Box::new(keeper))?;
    let plan=Plan::new(config("cancel",51)).map_err(|_|"cancel recovery plan invalid")?;
    let recovered=ReservedPlan::recover(plan,journal,&replay).map_err(|_|"cancelled reservation recovery refused")?;
    assert_eq!(recovered.pending(),Some(&selected));
    Ok(())
}

/// Child side of the cross-process reservation test. The parent retains the
/// journal head between the two processes; no physical camera is contacted.
#[test]
#[ignore = "invoked by the separate-process reservation fixture"]
fn generation_reservation_process_child() -> Test {
    use fss_object::{
        HostSpoolIo,
        effect_journal::{EffectJournalLimits, FileEffectJournal, FileTrustedRootPinRetainer},
    };
    use fss_reference::unifi_direct::av_rollover_generation::{
        Configuration, Plan, ReservationError, ReservedPlan,
    };
    use fss_runtime::effect_journal::{EffectJournalPin, PinRetainedEffectJournal};

    let root = PathBuf::from(std::env::var("FSS_TEST_GENERATION_ROOT")?);
    let mode = std::env::var("FSS_TEST_GENERATION_MODE")?;
    let authority = fss_core::region::ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:generation-process".into(),
        operation_id: OperationId::parse("operation:generation-process")?,
        principal: "principal:fixture".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 1,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"generation process fixture"),
        generation: 1,
    })?;
    let replay = Arc::new(ReplayCx::from_context_authority(&authority, root.clone())?);
    let limits = EffectJournalLimits::default();
    let config = |first: u64| Configuration {
        namespace: "camera".into(),
        scope_seed: ContentDigest::sha256(b"generation process scope"),
        first,
        count: 2,
        journal_replay: replay.clone(),
        pin_replay: replay.clone(),
        journal_io: Arc::new(HostSpoolIo),
        pin_io: Arc::new(HostSpoolIo),
        journal_limits: limits,
        pin_limits: limits,
        read: Arc::new(Access(ContentDigest::sha256(b"retention"))),
        object_limits: archive::StagedAvLimits {
            max_objects: 16,
            max_object_bytes: 4096,
            max_total_bytes: 65536,
        },
        work_limit: 100_000,
    };
    let pin_scope = ContentDigest::sha256(b"generation process pin fixture");
    if mode == "write" {
        let store = FileEffectJournal::create(root.join("reservations"), limits, Arc::new(HostSpoolIo))?;
        let pin = FileTrustedRootPinRetainer::create(root.join("reservation-pin"), limits, Arc::new(HostSpoolIo), pin_scope)?;
        let journal = PinRetainedEffectJournal::new(Box::new(store), Box::new(pin))?;
        let plan = Plan::new(config(20)).map_err(|_| "writer plan invalid")?;
        let mut reserved = ReservedPlan::create(plan, journal, &replay).map_err(|_| "writer plan refused")?;
        let (identity, worker) = reserved.reserve_next(&replay).map_err(|_| "writer reservation refused")?.ok_or("writer reservation missing")?;
        if identity.generation != 20 || identity.journal_root.exists() || identity.pin_root.exists() {
            return Err("writer unexpectedly started the creator".into());
        }
        let retired = worker.retire().map_err(|_| "writer creator unexpectedly running")?;
        if retired.outcome.is_some() || retired.inputs.is_none() {
            return Err("writer creator ownership not retained".into());
        }
        let head = reserved.head().ok_or("writer head missing")?;
        if head.sequence != 2 { return Err("writer head sequence changed".into()); }
        println!("generation_reservation_head={}", head.root.to_text());
        return Ok(());
    }
    if mode != "read" { return Err("unknown generation fixture mode".into()); }
    let minimum = EffectJournalPin {
        sequence: 2,
        root: ContentDigest::parse(std::env::var("FSS_TEST_GENERATION_HEAD")?)?,
    };
    let store = FileEffectJournal::open(root.join("reservations"), limits, Arc::new(HostSpoolIo), minimum)?;
    let pin = FileTrustedRootPinRetainer::open_trusting_storage(root.join("reservation-pin"), limits, Arc::new(HostSpoolIo), pin_scope)?;
    let journal = PinRetainedEffectJournal::for_reconciliation(Box::new(store), Box::new(pin))?;
    let plan = Plan::new(config(20)).map_err(|_| "reader plan invalid")?;
    let mut recovered = ReservedPlan::recover_discovered(
        plan, journal, &replay, 32, &mut fss_geometry::WorkBudget::new(100_000),
    ).map_err(|_| "reader plan refused")?;
    let first = recovered.pending().cloned().ok_or("reader lost pending reservation")?;
    if first.generation != 20 || first.journal_root.exists() || first.pin_root.exists() || recovered.head() != Some(minimum) {
        return Err("reader recovered incorrect reservation".into());
    }
    let refusal = match recovered.reserve_next(&replay) {
        Err(refusal) => refusal,
        Ok(_) => return Err("reader allowed a new generation before reconciliation".into()),
    };
    if !matches!(refusal.reason, ReservationError::ReconciliationRequired) || refusal.candidate.is_some() {
        return Err("reader lost the pending reservation fence".into());
    }
    recovered.record_reconciliation(&first, ContentDigest::sha256(b"synthetic assessed evidence"), &replay)
        .map_err(|_| "reader reconciliation refused")?;
    let (second, worker) = recovered.reserve_next(&replay).map_err(|_| "reader next reservation refused")?.ok_or("reader next reservation missing")?;
    if second.generation != 21 || second.pin_scope == first.pin_scope || second.journal_root.exists() || second.pin_root.exists() {
        return Err("reader reused or started a generation".into());
    }
    let retired = worker.retire().map_err(|_| "reader creator unexpectedly running")?;
    if retired.outcome.is_some() || retired.inputs.is_none() { return Err("reader creator ownership lost".into()); }
    println!("generation_reservation_process=recovered pending_fenced=true next_generation=21");
    Ok(())
}

#[test]
fn retained_generation_survives_reserving_process_exit() -> Test {
    use std::{os::unix::fs::DirBuilderExt, process::Command};

    let root = std::env::temp_dir().join(format!("fss-generation-process-{}", std::process::id()));
    std::fs::DirBuilder::new().mode(0o700).create(&root)?;
    let temp = Temp(std::fs::canonicalize(root)?);
    let exe = std::env::current_exe()?;
    let run = |mode: &str, head: Option<&str>| -> std::io::Result<std::process::Output> {
        let mut command = Command::new(&exe);
        command.args(["generation_reservation_process_child", "--ignored", "--exact", "--nocapture", "--test-threads=1"])
            .env("FSS_TEST_GENERATION_ROOT", &temp.0)
            .env("FSS_TEST_GENERATION_MODE", mode);
        if let Some(head) = head { command.env("FSS_TEST_GENERATION_HEAD", head); }
        command.output()
    };
    let writer = run("write", None)?;
    if !writer.status.success() { return Err(format!("reservation writer failed: {}", String::from_utf8_lossy(&writer.stderr)).into()); }
    let stdout = std::str::from_utf8(&writer.stdout)?;
    let heads: Vec<_> = stdout.lines().filter_map(|line| line.split_once("generation_reservation_head=").map(|(_, head)| head.trim())).collect();
    if heads.len() != 1 { return Err("writer did not return exactly one retained head".into()); }
    let head = ContentDigest::parse(heads[0])?.to_text();
    let wrong = ContentDigest::sha256(b"wrong process minimum").to_text();
    if run("read", Some(&wrong))?.status.success() { return Err("reader accepted an incorrect minimum head".into()); }
    let reader = run("read", Some(&head))?;
    if !reader.status.success() || !String::from_utf8_lossy(&reader.stdout).contains("generation_reservation_process=recovered pending_fenced=true next_generation=21") {
        return Err(format!("reservation reader failed: {}", String::from_utf8_lossy(&reader.stderr)).into());
    }
    Ok(())
}

#[test]
fn retained_generation_worker_drains_and_preserves_cancelled_reservations() -> Test {
    use fss_object::{HostSpoolIo,effect_journal::{EffectJournalLimits,FileEffectJournal,FileTrustedRootPinRetainer}};
    use fss_reference::unifi_direct::av_rollover_generation::{Configuration,Plan,ReservedPlan,ReservationInputs,ReservationRequest,ReservationOutcome,ReservationError,ReservationStartError,ReservationWorker};
    use fss_runtime::effect_journal::{EffectJournalPin,EffectJournalStore,EffectPersistenceError,EffectPinRetainer,PinRetainedEffectJournal};
    use std::sync::{atomic::{AtomicBool,Ordering},Condvar,Mutex};

    #[derive(Debug,Default)]
    struct Gate {armed:AtomicBool,entered:AtomicBool,released:Mutex<bool>,wake:Condvar}
    #[derive(Debug)]
    struct GatedRetainer {inner:Box<dyn EffectPinRetainer>,gate:Arc<Gate>}
    impl EffectPinRetainer for GatedRetainer {
        fn retained_pin(&mut self)->Result<Option<EffectJournalPin>,EffectPersistenceError> {
            if self.gate.armed.load(Ordering::Acquire) && !self.gate.entered.swap(true,Ordering::AcqRel) {
                let released=self.gate.released.lock().map_err(|_|EffectPersistenceError::Storage("fixture gate poisoned".into()))?;
                let (released,_)=self.gate.wake.wait_timeout_while(released,std::time::Duration::from_secs(10),|released|!*released).map_err(|_|EffectPersistenceError::Storage("fixture gate poisoned".into()))?;
                if !*released {return Err(EffectPersistenceError::Storage("fixture gate timed out".into()));}
            }
            self.inner.retained_pin()
        }
        fn reserve_capacity(&mut self,n:usize)->Result<(),EffectPersistenceError> {self.inner.reserve_capacity(n)}
        fn verify_effect_history(&mut self,journal:&dyn EffectJournalStore)->Result<(),EffectPersistenceError> {self.inner.verify_effect_history(journal)}
        fn retain(&mut self,expected:Option<EffectJournalPin>,next:EffectJournalPin)->Result<(),EffectPersistenceError> {self.inner.retain(expected,next)}
    }
    struct Release(Arc<Gate>);
    impl Drop for Release {fn drop(&mut self) {if let Ok(mut released)=self.0.released.lock(){*released=true;self.0.wake.notify_all();}}}


    let root=std::env::temp_dir().join(format!("fss-reservation-worker-{}",std::process::id()));
    std::fs::create_dir(&root)?;
    let temp=Temp(std::fs::canonicalize(root)?);
    let budget=BudgetVector::builder().bytes(64*1024*1024).build()?;
    let spec=|name:&str,capabilities:Vec<String>| -> Result<RootAuthoritySpec,Box<dyn Error>> {Ok(RootAuthoritySpec {
        trace_id:format!("trace:{name}"),operation_id:OperationId::parse(&format!("operation:{name}"))?,principal:"principal:fixture".into(),capabilities,
        deadline:None,priority:1,budgets:budget,privacy_scope:"privacy:test".into(),retention_scope:"retention:test".into(),anchor_universe:ContentDigest::sha256(b"reservation worker"),generation:1,
    })};
    let (mut authority,mut tree)=AuthorityCx::root(spec("reservation-worker",vec![RuntimeGrant::ObjectStage.as_str().into()])?,RegionId::new("region:reservation-worker")?,RegionKind::Process,budget,TimestampNs(1))?;
    let replay_authority=fss_core::region::ContextAuthority::new_root(spec("reservation-replay",vec!["ADP-REPLAY-001".into()])?)?;
    let limits=EffectJournalLimits::default();
    let make=|name:&str,gate:Option<Arc<Gate>>| -> Result<ReservationInputs,Box<dyn Error>> {
        let journal_replay=Arc::new(ReplayCx::from_context_authority(&replay_authority,temp.0.clone())?);
        let custody_replay=Arc::new(ReplayCx::from_context_authority(&replay_authority,temp.0.clone())?);
        let journal_resource=temp.0.join(format!("{name}-journal"));
        let custody_resource=temp.0.join(format!("{name}-pin"));
        let journal=FileEffectJournal::create(&journal_resource,limits,Arc::new(HostSpoolIo))?;
        let pin=FileTrustedRootPinRetainer::create(&custody_resource,limits,Arc::new(HostSpoolIo),ContentDigest::sha256(name.as_bytes()))?;
        let pin:Box<dyn EffectPinRetainer>=match gate {Some(gate)=>Box::new(GatedRetainer {inner:Box::new(pin),gate}),None=>Box::new(pin)};
        let journal=PinRetainedEffectJournal::new(Box::new(journal),pin)?;
        let plan=Plan::new(Configuration {namespace:name.into(),scope_seed:ContentDigest::sha256(name.as_bytes()),first:1,count:2,
            journal_replay:journal_replay.clone(),pin_replay:custody_replay.clone(),journal_io:Arc::new(HostSpoolIo),pin_io:Arc::new(HostSpoolIo),journal_limits:limits,pin_limits:limits,
            read:Arc::new(Access(ContentDigest::sha256(b"retention"))),object_limits:archive::StagedAvLimits {max_objects:16,max_object_bytes:4096,max_total_bytes:65536},work_limit:100_000,
        }).map_err(|_|"worker plan invalid")?;
        let plan=ReservedPlan::create(plan,journal,&journal_replay).map_err(|_|"worker retained plan invalid")?;
        Ok(ReservationInputs {plan,request:ReservationRequest::Reserve,journal_resource,custody_resource,journal_replay,custody_replay})
    };
    let ready=make("ready-worker",None)?;
    let cancelled=make("cancel-worker",None)?;
    let never=make("never-worker",None)?;
    let gate=Arc::new(Gate::default());
    let blocked=make("blocked-worker",Some(gate.clone()))?;
    let runtime=RuntimeBuilder::current_thread().blocking_threads(1,1).build()?;
    runtime.block_on(async {
        let cx=asupersync::Cx::current().ok_or("missing runtime")?;
        let result=run_owned_async(&mut authority,&mut tree,TaskSpec {task_id:TaskId::new("task:reservation-worker")?,started_at:TimestampNs(3)},&cx,async |task,cx| {
            let output:Test=async {
                let clock=MeteredClock::new(task,cx,TimestampNs(4))?;
                let mut worker=ReservationWorker::new(never).map_err(|_|"never worker invalid")?;
                worker.abort();
                assert!(matches!(worker.start(task,cx,clock,&BudgetVector::ZERO),Err(ReservationStartError::Fenced)));
                let mut retired=worker.retire().map_err(|_|"never worker still running")?;
                assert!(retired.aborted && retired.fenced && retired.outcome.is_none() && retired.inputs.plan.pending().is_none());
                let refusal=match retired.inputs.plan.reserve_next(&retired.inputs.journal_replay) {Err(refusal)=>refusal,Ok(_)=>return Err("aborted plan admitted work".into())};
                assert!(matches!(refusal.reason,ReservationError::Fenced));

                let mut worker=ReservationWorker::new(ready).map_err(|_|"ready worker invalid")?;
                worker.start(task,cx,clock,&BudgetVector::ZERO).map_err(|_|"reservation admission refused")?;
                assert!(matches!(worker.start(task,cx,clock,&BudgetVector::ZERO),Err(ReservationStartError::Running)));
                let mut worker=worker.retire().err().ok_or("running worker retired")?;
                let result=worker.join().await.ok_or("reservation not joined")?;
                assert!(result.runtime.is_ok() && result.outcome_available && !result.indeterminate && !result.cancellation_requested);
                let mut retired=worker.retire().map_err(|_|"reservation still running")?;
                let (identity,creator)=match retired.outcome.take() {Some(ReservationOutcome::Reserved {identity,worker})=>(identity,worker),_=>return Err("reserved creator missing".into())};
                assert_eq!(identity.generation,1);
                assert_eq!(retired.inputs.plan.pending(),Some(&identity));
                assert!(!identity.journal_root.exists() && !identity.pin_root.exists());
                assert!(creator.retire().map_err(|_|"creator unexpectedly running")?.inputs.is_some());
                retired.inputs.request=ReservationRequest::Reconcile {identity:identity.clone(),evidence:ContentDigest::sha256(b"fixture reconciliation")};
                let mut worker=ReservationWorker::new(retired.inputs).map_err(|_|"reconciliation worker invalid")?;
                worker.start(task,cx,clock,&BudgetVector::ZERO).map_err(|_|"reconciliation admission refused")?;
                let result=worker.join().await.ok_or("reconciliation not joined")?;
                assert!(result.runtime.is_ok() && result.outcome_available && !result.indeterminate);
                let retired=worker.retire().map_err(|_|"reconciliation still running")?;
                assert!(matches!(retired.outcome,Some(ReservationOutcome::Reconciled(_))));
                assert!(retired.inputs.plan.pending().is_none());

                cancelled.journal_replay.set_cancel_at_checkpoint_occurrence("unifi-generation-reservation",3);
                let mut worker=ReservationWorker::new(cancelled).map_err(|_|"cancel worker invalid")?;
                worker.start(task,cx,clock,&BudgetVector::ZERO).map_err(|_|"cancel admission refused")?;
                let result=worker.join().await.ok_or("cancelled reservation not joined")?;
                assert!(result.runtime.is_ok() && result.outcome_available && !result.indeterminate);
                let mut retired=worker.retire().map_err(|_|"cancelled reservation still running")?;
                let refusal=match retired.outcome.take() {Some(ReservationOutcome::ReservationRefused(refusal))=>refusal,_=>return Err("cancelled refusal missing".into())};
                assert!(matches!(refusal.reason,ReservationError::Cancelled));
                let (identity,creator)=refusal.candidate.ok_or("cancelled creator missing")?;
                assert_eq!(identity.generation,1);
                assert!(!identity.journal_root.exists() && !identity.pin_root.exists());
                assert!(creator.retire().map_err(|_|"cancelled creator unexpectedly running")?.inputs.is_some());
                assert_eq!(retired.inputs.plan.head().ok_or("cancelled journal head missing")?.sequence,2);

                let _release=Release(gate.clone());
                gate.armed.store(true,Ordering::Release);
                let mut worker=ReservationWorker::new(blocked).map_err(|_|"blocked worker invalid")?;
                worker.start(task,cx,clock,&BudgetVector::ZERO).map_err(|_|"blocked admission refused")?;
                asupersync::time::timeout(cx.now(),std::time::Duration::from_secs(5),async {
                    while !gate.entered.load(Ordering::Acquire) {asupersync::runtime::yield_now().await;}
                }).await.map_err(|_|"runtime did not progress while pin custody was blocked")?;
                worker.abort();
                {let mut released=gate.released.lock().map_err(|_|"fixture gate poisoned")?;*released=true;gate.wake.notify_all();}
                let completion=worker.join().await.ok_or("blocked worker not joined")?;
                assert!(completion.cancellation_requested && completion.outcome_available);
                let mut retired=worker.retire().map_err(|_|"blocked worker still running")?;
                assert!(retired.fenced && retired.aborted);
                let refusal=match retired.outcome.take() {Some(ReservationOutcome::ReservationRefused(refusal))=>refusal,_=>return Err("blocked cancellation lost its refusal".into())};
                assert!(matches!(refusal.reason,ReservationError::Cancelled));
                let (identity,creator)=refusal.candidate.ok_or("blocked candidate missing")?;
                assert!(!identity.journal_root.exists() && !identity.pin_root.exists());
                assert!(creator.retire().map_err(|_|"blocked creator unexpectedly running")?.inputs.is_some());
                Ok(())
            }.await;
            let outcome=if output.is_ok() {TaskOutcome::Success} else {TaskOutcome::Failed("reservation worker fixture".into())};
            TaskCompletion {output,outcome,completed_at:TimestampNs(60_000_000_000)}
        }).await?;
        result.receipt?;result.output
    })?;
    assert!(authority.finalize_report(&tree)?.is_empty());
    Ok(())
}

#[test]
fn retained_generation_bootstrap_drains_create_recover_and_partial_failure() -> Test {
    use fss_object::{HostSpoolIo,effect_journal::EffectJournalLimits};
    use fss_reference::unifi_direct::av_rollover_generation::{BootstrapInputs,BootstrapMode,BootstrapOutcome,BootstrapStage,BootstrapStorage,BootstrapStartError,BootstrapWorker,Configuration,Plan,ReservationInputs,ReservationOutcome,ReservationRequest,ReservationStartError,ReservationWorker};
    use fss_runtime::effect_journal::EffectJournalPin;
    let root=std::env::temp_dir().join(format!("fss-reservation-bootstrap-{}",std::process::id()));
    std::fs::create_dir(&root)?;
    let temp=Temp(std::fs::canonicalize(root)?);
    let budget=BudgetVector::builder().bytes(64*1024*1024).build()?;
    let spec=|name:&str,capabilities:Vec<String>| -> Result<RootAuthoritySpec,Box<dyn Error>> {Ok(RootAuthoritySpec {
        trace_id:format!("trace:{name}"),operation_id:OperationId::parse(&format!("operation:{name}"))?,principal:"principal:fixture".into(),capabilities,
        deadline:None,priority:1,budgets:budget,privacy_scope:"privacy:test".into(),retention_scope:"retention:test".into(),anchor_universe:ContentDigest::sha256(b"bootstrap worker fixture"),generation:1,
    })};
    let (mut authority,mut tree)=AuthorityCx::root(spec("bootstrap-worker",vec![RuntimeGrant::ObjectStage.as_str().into()])?,RegionId::new("region:bootstrap-worker")?,RegionKind::Process,budget,TimestampNs(1))?;
    let replay_authority=fss_core::region::ContextAuthority::new_root(spec("bootstrap-replay",vec!["ADP-REPLAY-001".into()])?)?;
    let limits=EffectJournalLimits::default();
    let storage=|name:&str,mode:BootstrapMode| -> Result<BootstrapStorage,Box<dyn Error>> {Ok(BootstrapStorage {
        mode,journal_root:temp.0.join(format!("{name}-journal")),custody_root:temp.0.join(format!("{name}-pin")),
        journal_replay:Arc::new(ReplayCx::from_context_authority(&replay_authority,temp.0.clone())?),custody_replay:Arc::new(ReplayCx::from_context_authority(&replay_authority,temp.0.clone())?),
        journal_io:Arc::new(HostSpoolIo),custody_io:Arc::new(HostSpoolIo),journal_limits:limits,custody_limits:limits,custody_scope:ContentDigest::sha256(name.as_bytes()),
    })};
    let make_plan=|name:&str,first:u64,s:&BootstrapStorage| -> Result<Plan,Box<dyn Error>> {Plan::new(Configuration {
        namespace:name.into(),scope_seed:ContentDigest::sha256(name.as_bytes()),first,count:2,journal_replay:s.journal_replay.clone(),pin_replay:s.custody_replay.clone(),
        journal_io:Arc::new(HostSpoolIo),pin_io:Arc::new(HostSpoolIo),journal_limits:limits,pin_limits:limits,read:Arc::new(Access(ContentDigest::sha256(b"retention"))),
        object_limits:archive::StagedAvLimits {max_objects:16,max_object_bytes:4096,max_total_bytes:65536},work_limit:100_000,
    }).map_err(|_|"bootstrap plan invalid".into())};
    let mut invalid=storage("invalid-bootstrap",BootstrapMode::Create)?;
    invalid.journal_limits.max_records=0;
    let invalid_plan=make_plan("invalid-bootstrap",1,&invalid)?;
    let invalid=match BootstrapWorker::new(BootstrapInputs {plan:invalid_plan,storage:invalid}) {Err(inputs)=>inputs,Ok(_)=>return Err("invalid bootstrap limit accepted".into())};
    assert!(!invalid.storage.journal_root.exists() && !invalid.storage.custody_root.exists());
    let mut overlap=storage("overlap-bootstrap",BootstrapMode::Create)?;
    overlap.custody_root=overlap.journal_root.clone();
    let overlap_plan=make_plan("overlap-bootstrap",1,&overlap)?;
    let overlap=match BootstrapWorker::new(BootstrapInputs {plan:overlap_plan,storage:overlap}) {Err(inputs)=>inputs,Ok(_)=>return Err("overlapping bootstrap custody accepted".into())};
    assert!(!overlap.storage.journal_root.exists());
    let invalid_pin=EffectJournalPin {sequence:0,root:ContentDigest::sha256(b"invalid minimum")};
    let invalid=storage("invalid-recovery",BootstrapMode::Recover {minimum:invalid_pin})?;
    let plan=make_plan("invalid-recovery",1,&invalid)?;
    let invalid=match BootstrapWorker::new(BootstrapInputs {plan,storage:invalid}) {Err(inputs)=>inputs,Ok(_)=>return Err("invalid recovery minimum accepted".into())};
    assert!(!invalid.storage.journal_root.exists());
    let invalid=storage("invalid-discovery",BootstrapMode::Discover {minimum:EffectJournalPin {sequence:1,root:ContentDigest::sha256(b"valid minimum")},max_records:0,work_limit:100_000})?;
    let plan=make_plan("invalid-discovery",1,&invalid)?;
    let invalid=match BootstrapWorker::new(BootstrapInputs {plan,storage:invalid}) {Err(inputs)=>inputs,Ok(_)=>return Err("invalid discovery limit accepted".into())};
    assert!(!invalid.storage.journal_root.exists());
    let first_storage=storage("ready-bootstrap",BootstrapMode::Create)?;
    let first_plan=make_plan("ready-bootstrap",1,&first_storage)?;
    let cancelled_storage=storage("cancel-bootstrap",BootstrapMode::Create)?;
    let cancelled_plan=make_plan("cancel-bootstrap",1,&cancelled_storage)?;
    cancelled_storage.journal_replay.set_cancel_at_checkpoint_occurrence("unifi-reservation-bootstrap-work",3);
    let runtime=RuntimeBuilder::current_thread().blocking_threads(1,1).build()?;
    runtime.block_on(async {
        let cx=asupersync::Cx::current().ok_or("missing runtime")?;
        let result=run_owned_async(&mut authority,&mut tree,TaskSpec {task_id:TaskId::new("task:bootstrap-worker")?,started_at:TimestampNs(3)},&cx,async |task,cx| {
            let output:Test=async {
                let clock=MeteredClock::new(task,cx,TimestampNs(4))?;
                let mut bootstrap=BootstrapWorker::new(BootstrapInputs {plan:first_plan,storage:first_storage}).map_err(|_|"bootstrap inputs invalid")?;
                bootstrap.start(task,cx,clock,&BudgetVector::ZERO).map_err(|_|"bootstrap admission refused")?;
                assert!(matches!(bootstrap.start(task,cx,clock,&BudgetVector::ZERO),Err(BootstrapStartError::Running)));
                let mut bootstrap=bootstrap.retire().err().ok_or("running bootstrap retired")?;
                let completion=bootstrap.join().await.ok_or("bootstrap not joined")?;
                assert!(completion.runtime.is_ok() && completion.outcome==BootstrapOutcome::Ready && !completion.cancellation_requested);
                let mut retirement=bootstrap.retire().map_err(|_|"bootstrap still running")?;
                assert!(retirement.journal_root_created && retirement.custody_root_created && !retirement.fenced);
                let plan=retirement.take_ready().ok_or("created retained plan missing")?;
                let predecessor=archive::journal::rollover::SwitchPredecessor {
                    scope:ContentDigest::sha256(b"bootstrap switch scope"),
                    confirmed:archive::UnknownTimePin {root:ContentDigest::sha256(b"bootstrap switch root"),retention:ContentDigest::sha256(b"bootstrap switch retention")},
                    journal:plan.head().ok_or("bootstrap plan head missing")?,keeper:plan.head().ok_or("bootstrap plan head missing")?,
                };
                let mut inspection=ReservationWorker::new(ReservationInputs {
                    plan,request:ReservationRequest::InspectSwitches {predecessor,max_candidates:2,max_records:32,work_limit:4_000_000_000},
                    journal_resource:retirement.storage.journal_root.clone(),custody_resource:retirement.storage.custody_root.clone(),
                    journal_replay:retirement.storage.journal_replay.clone(),custody_replay:retirement.storage.custody_replay.clone(),
                }).map_err(|_|"switch inspection inputs invalid")?;
                inspection.start(task,cx,clock,&BudgetVector::ZERO).map_err(|_|"switch inspection admission refused")?;
                let mut inspection=inspection.retire().err().ok_or("running inspection retired")?;
                let completion=inspection.join().await.ok_or("inspection did not join")?;
                assert!(completion.runtime.is_ok() && completion.outcome_available && !completion.indeterminate);
                let mut inspection=inspection.retire().map_err(|_|"inspection still running")?;
                assert!(!inspection.fenced);
                match inspection.outcome.take() {
                    Some(ReservationOutcome::SwitchesInspected {opened,selected})=>{assert!(opened.entries().is_empty() && selected.is_none());},
                    _=>return Err("empty inventory inspection failed".into()),
                }
                let plan=inspection.inputs.plan;
                let mut reservation=ReservationWorker::new(ReservationInputs {plan,request:ReservationRequest::Reserve,journal_resource:retirement.storage.journal_root.clone(),custody_resource:retirement.storage.custody_root.clone(),journal_replay:retirement.storage.journal_replay.clone(),custody_replay:retirement.storage.custody_replay.clone()}).map_err(|_|"reservation inputs invalid")?;
                reservation.start(task,cx,clock,&BudgetVector::ZERO).map_err(|_|"reservation admission refused")?;
                let completion=reservation.join().await.ok_or("reservation not joined")?;
                assert!(completion.runtime.is_ok() && completion.outcome_available);
                let mut retirement=reservation.retire().map_err(|_|"reservation still running")?;
                let (identity,creator)=match retirement.outcome.take() {Some(ReservationOutcome::Reserved {identity,worker})=>(identity,worker),_=>return Err("reserved creator missing".into())};
                assert!(creator.retire().map_err(|_|"creator unexpectedly running")?.inputs.is_some());
                let head=retirement.inputs.plan.head().ok_or("reservation head missing")?;
                let (_,journal)=retirement.inputs.plan.into_parts();drop(journal);

                let wrong=EffectJournalPin {sequence:head.sequence,root:ContentDigest::sha256(b"wrong minimum")};
                let s=storage("ready-bootstrap",BootstrapMode::Recover {minimum:wrong})?;
                let plan=make_plan("ready-bootstrap",2,&s)?;
                let mut bootstrap=BootstrapWorker::new(BootstrapInputs {plan,storage:s}).map_err(|_|"wrong bootstrap invalid")?;
                bootstrap.start(task,cx,clock,&BudgetVector::ZERO).map_err(|_|"wrong bootstrap admission")?;
                let completion=bootstrap.join().await.ok_or("wrong bootstrap not joined")?;
                assert!(completion.runtime.is_ok() && completion.outcome==BootstrapOutcome::Refused(BootstrapStage::Journal));
                let retirement=bootstrap.retire().map_err(|_|"wrong bootstrap still running")?;
                assert!(retirement.plan.is_some() && retirement.error.is_some() && !retirement.journal_root_created && !retirement.custody_attempted);

                let s=storage("ready-bootstrap",BootstrapMode::Discover {minimum:head,max_records:32,work_limit:1})?;
                let plan=make_plan("ready-bootstrap",1,&s)?;
                let mut bootstrap=BootstrapWorker::new(BootstrapInputs {plan,storage:s}).map_err(|_|"bounded discovery invalid")?;
                bootstrap.start(task,cx,clock,&BudgetVector::ZERO).map_err(|_|"bounded discovery admission refused")?;
                let completion=bootstrap.join().await.ok_or("bounded discovery not joined")?;
                assert!(completion.runtime.is_ok() && completion.outcome==BootstrapOutcome::Refused(BootstrapStage::Plan));
                let retirement=bootstrap.retire().map_err(|_|"bounded discovery still running")?;
                assert!(retirement.plan.is_some() && retirement.bound.is_some() && retirement.discover_error.is_some());
                drop(retirement);

                let s=storage("ready-bootstrap",BootstrapMode::Discover {minimum:head,max_records:32,work_limit:100_000})?;
                let plan=make_plan("ready-bootstrap",1,&s)?;
                let mut bootstrap=BootstrapWorker::new(BootstrapInputs {plan,storage:s}).map_err(|_|"recovery bootstrap invalid")?;
                bootstrap.start(task,cx,clock,&BudgetVector::ZERO).map_err(|_|"recovery admission refused")?;
                let completion=bootstrap.join().await.ok_or("recovery not joined")?;
                assert!(completion.runtime.is_ok() && completion.outcome==BootstrapOutcome::Ready);
                let mut retirement=bootstrap.retire().map_err(|_|"recovery still running")?;
                assert!(!retirement.journal_root_created && !retirement.custody_root_created);
                let plan=retirement.take_ready().ok_or("recovered plan missing")?;
                assert_eq!(plan.pending(),Some(&identity));

                let mut inspection=ReservationWorker::new(ReservationInputs {
                    plan,request:ReservationRequest::InspectSwitches {predecessor,max_candidates:2,max_records:32,work_limit:4_000_000_000},
                    journal_resource:retirement.storage.journal_root.clone(),custody_resource:retirement.storage.custody_root.clone(),
                    journal_replay:retirement.storage.journal_replay.clone(),custody_replay:retirement.storage.custody_replay.clone(),
                }).map_err(|_|"pending inspection inputs invalid")?;
                inspection.start(task,cx,clock,&BudgetVector::ZERO).map_err(|_|"pending inspection admission refused")?;
                let completion=inspection.join().await.ok_or("pending inspection did not join")?;
                assert!(completion.runtime.is_ok() && completion.outcome_available && !completion.indeterminate);
                let inspection=inspection.retire().map_err(|_|"pending inspection still running")?;
                assert!(matches!(inspection.outcome,Some(ReservationOutcome::SwitchOpeningRefused(_))));
                assert_eq!(inspection.inputs.plan.pending(),Some(&identity));
                let mut cancelled_inspection=ReservationWorker::new(ReservationInputs {
                    plan:inspection.inputs.plan,request:ReservationRequest::InspectSwitches {predecessor,max_candidates:2,max_records:32,work_limit:4_000_000_000},
                    journal_resource:retirement.storage.journal_root.clone(),custody_resource:retirement.storage.custody_root.clone(),
                    journal_replay:retirement.storage.journal_replay.clone(),custody_replay:retirement.storage.custody_replay.clone(),
                }).map_err(|_|"cancelled inspection inputs invalid")?;
                cancelled_inspection.abort();
                assert!(matches!(cancelled_inspection.start(task,cx,clock,&BudgetVector::ZERO),Err(ReservationStartError::Fenced)));
                let cancelled_inspection=cancelled_inspection.retire().map_err(|_|"cancelled inspection still running")?;
                assert!(cancelled_inspection.fenced && cancelled_inspection.aborted && cancelled_inspection.outcome.is_none());
                assert_eq!(cancelled_inspection.inputs.plan.pending(),Some(&identity));

                let mut bootstrap=BootstrapWorker::new(BootstrapInputs {plan:cancelled_plan,storage:cancelled_storage}).map_err(|_|"cancel bootstrap invalid")?;
                bootstrap.start(task,cx,clock,&BudgetVector::ZERO).map_err(|_|"cancel bootstrap admission refused")?;
                let completion=bootstrap.join().await.ok_or("cancel bootstrap not joined")?;
                assert!(completion.runtime.is_ok() && completion.outcome==BootstrapOutcome::Cancelled);
                let mut retirement=bootstrap.retire().map_err(|_|"cancel bootstrap still running")?;
                assert!(retirement.fenced && retirement.journal_root_created && retirement.journal.is_some() && !retirement.custody_attempted && retirement.plan.is_some());
                assert!(retirement.take_ready().is_none());
                Ok(())
            }.await;
            let outcome=if output.is_ok(){TaskOutcome::Success}else{TaskOutcome::Failed("bootstrap worker fixture".into())};
            TaskCompletion {output,outcome,completed_at:TimestampNs(60_000_000_000)}
        }).await?;
        result.receipt?;result.output
    })?;
    assert!(authority.finalize_report(&tree)?.is_empty());
    Ok(())
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

    // Create a second switch, then close every history before reopening the
    // same intermediate owner exactly once for chained recovery.
    let first_binding = active.binding();
    let first_switch = active.switch_head();
    let first_heads = {
        let (journal, keeper) = active.successor();
        archive::journal::rollover::SuccessorHeads {
            journal: journal.anchor(),
            keeper: keeper.anchor(),
        }
    };
    let lineage = active
        .into_recovered_lineage(&replay)
        .map_err(|_| "first lineage refused")?;
    let (previous, first_custody) = lineage.into_parts();
    let stage = archive::journal::rollover::Staged::begin(
        previous,
        store("newer-journal")?,
        store("newer-keeper")?,
        &replay,
    )
    .map_err(|_| "second cold stage refused")?;
    let second_scope = ContentDigest::sha256(b"rollover second switch custody");
    let root = FileTrustedRootPinRetainer::create(
        temp.0.join("second-retainer"),
        storage_limits,
        Arc::new(HostSpoolIo),
        second_scope,
    )?;
    let switch = PinRetainedEffectJournal::new(store("second-switch")?, Box::new(root))?;
    let mut second = stage
        .commit(switch, &replay)
        .map_err(|_| "second cold switch refused")?;
    let second_binding = second.binding();
    let second_switch = second.switch_head();
    let second_heads = {
        let (journal, keeper) = second.successor();
        archive::journal::rollover::SuccessorHeads {
            journal: journal.anchor(),
            keeper: keeper.anchor(),
        }
    };
    drop(second);
    drop(first_custody);

    let open = |name: &str, pin| -> Result<Box<dyn EffectJournalStore>, Box<dyn Error>> {
        Ok(Box::new(FileEffectJournal::open(
            temp.0.join(name),
            storage_limits,
            Arc::new(HostSpoolIo),
            pin,
        )?))
    };
    let pair = |journal_name: &str,
                keeper_name: &str,
                heads: archive::journal::rollover::SuccessorHeads|
     -> Result<archive::journal::rollover::Previous, Box<dyn Error>> {
        let journal = archive::journal::UnknownTimeJournal::reopen(
            open(journal_name, heads.journal)?,
            scope,
            heads.journal,
            &replay,
        )?;
        let keeper = archive::journal::UnknownTimeAnchorKeeper::reopen(
            open(keeper_name, heads.keeper)?,
            &journal,
            heads.keeper,
            &replay,
        )?;
        Ok(archive::journal::rollover::Previous { journal, keeper })
    };
    let old = pair(
        "old-journal",
        "old-keeper",
        archive::journal::rollover::SuccessorHeads {
            journal: first_binding.old_journal,
            keeper: first_binding.old_keeper,
        },
    )?;
    let middle = pair("new-journal", "new-keeper", first_heads)?;
    let newest = pair("newer-journal", "newer-keeper", second_heads)?;
    let switch = |name: &str,
                  root: &str,
                  pin,
                  custody_scope|
     -> Result<PinRetainedEffectJournal, Box<dyn Error>> {
        let retainer = FileTrustedRootPinRetainer::open_trusting_storage(
            temp.0.join(root),
            storage_limits,
            Arc::new(HostSpoolIo),
            custody_scope,
        )?;
        Ok(PinRetainedEffectJournal::for_reconciliation(
            open(name, pin)?,
            Box::new(retainer),
        )?)
    };
    let mut first_switch_owner = switch(
        "switch", "switch-retainer", first_switch,
        ContentDigest::sha256(b"rollover switch custody"),
    )?;
    assert!(matches!(
        archive::journal::rollover::inspect_switch(&mut first_switch_owner, scope, &mut WorkBudget::new(0), &replay),
        Err(archive::journal::rollover::SwitchInspectionError::Work(_))
    ));
    assert!(matches!(
        archive::journal::rollover::inspect_switch(&mut first_switch_owner, ContentDigest::sha256(b"wrong scope"), &mut WorkBudget::new(100_000), &replay),
        Err(archive::journal::rollover::SwitchInspectionError::ScopeMismatch)
    ));
    let first_observation = archive::journal::rollover::inspect_switch(
        &mut first_switch_owner, scope, &mut WorkBudget::new(100_000), &replay,
    ).map_err(|e| format!("first switch inspection failed: {e:?}"))?;
    assert_eq!(first_observation.binding, first_binding);
    assert_eq!(first_observation.head, first_switch);
    let mut second_switch_owner = switch("second-switch", "second-retainer", second_switch, second_scope)?;
    let second_observation = archive::journal::rollover::inspect_switch(
        &mut second_switch_owner, scope, &mut WorkBudget::new(100_000), &replay,
    ).map_err(|e| format!("second switch inspection failed: {e:?}"))?;
    assert_eq!(second_observation.binding, second_binding);
    assert_eq!(second_observation.head, second_switch);
    assert_eq!(second_observation.binding.old_journal, first_heads.journal);
    assert_eq!(second_observation.binding.old_keeper, first_heads.keeper);
    let predecessor = archive::journal::rollover::SwitchPredecessor {
        scope, confirmed:first_binding.confirmed, journal:first_binding.old_journal, keeper:first_binding.old_keeper,
    };
    // Inventory-driven opening uses different physical candidate stores, with
    // the same canonical synthetic switch records as the recovered chain.
    let shared_replay=Arc::new(ReplayCx::from_context_authority(&replay_authority,temp.0.clone())?);
    let config=fss_reference::unifi_direct::av_rollover_generation::Configuration {
        namespace:"opened".into(),scope_seed:ContentDigest::sha256(b"opened candidates"),first:1,count:2,
        journal_replay:shared_replay.clone(),pin_replay:shared_replay.clone(),journal_io:Arc::new(HostSpoolIo),pin_io:Arc::new(HostSpoolIo),
        journal_limits:storage_limits,pin_limits:storage_limits,read:Arc::new(Access(retention)),
        object_limits:archive::StagedAvLimits {max_objects:16,max_object_bytes:4096,max_total_bytes:65536},work_limit:100_000,
    };
    let reservation_pin=FileTrustedRootPinRetainer::create(temp.0.join("opened-reservation-pin"),storage_limits,Arc::new(HostSpoolIo),ContentDigest::sha256(b"opened reservation custody"))?;
    let reservation_journal=PinRetainedEffectJournal::new(store("opened-reservations")?,Box::new(reservation_pin))?;
    let plan=fss_reference::unifi_direct::av_rollover_generation::Plan::new(config).map_err(|_|"candidate plan invalid")?;
    let mut reserved=fss_reference::unifi_direct::av_rollover_generation::ReservedPlan::create(plan,reservation_journal,&replay).map_err(|_|"candidate reservation failed")?;
    let (candidate1,worker)=reserved.reserve_next(&replay).map_err(|_|"first candidate refused")?.ok_or("first candidate missing")?;
    assert!(worker.retire().map_err(|_|"candidate worker running")?.inputs.is_some());
    let create_candidate=|identity:&fss_reference::unifi_direct::av_rollover_generation::Identity, bytes:&[u8]| -> Test {
        std::fs::create_dir(&identity.journal_root)?;
        let pin=FileTrustedRootPinRetainer::create(&identity.pin_root,storage_limits,Arc::new(HostSpoolIo),identity.pin_scope)?;
        let journal=FileEffectJournal::create(identity.journal_root.join("switch"),storage_limits,Arc::new(HostSpoolIo))?;
        let mut switch=PinRetainedEffectJournal::new(Box::new(journal),Box::new(pin))?;
        switch.append(None,bytes)?;
        Ok(())
    };
    create_candidate(&candidate1,&first_switch_owner.records()[0])?;
    reserved.record_reconciliation(&candidate1,ContentDigest::sha256(b"candidate assessed"),&replay).map_err(|_|"first candidate reconcile refused")?;
    let (candidate2,worker)=reserved.reserve_next(&replay).map_err(|_|"second candidate refused")?.ok_or("second candidate missing")?;
    assert!(worker.retire().map_err(|_|"candidate worker running")?.inputs.is_some());
    assert!(matches!(reserved.open_switches_trusting_custody(1,32,&mut WorkBudget::new(4_000_000_000),&replay),
        Err(fss_reference::unifi_direct::av_rollover_generation::OpenSwitchesRefusal {reason:fss_reference::unifi_direct::av_rollover_generation::OpenSwitchesError::Incomplete,..})));
    assert!(matches!(reserved.open_switches_trusting_custody(2,32,&mut WorkBudget::new(0),&replay),
        Err(fss_reference::unifi_direct::av_rollover_generation::OpenSwitchesRefusal {reason:fss_reference::unifi_direct::av_rollover_generation::OpenSwitchesError::Inventory(_),..})));
    let failure=match reserved.open_switches_trusting_custody(2,32,&mut WorkBudget::new(4_000_000_000),&replay) {
        Err(failure)=>failure,Ok(_)=>return Err("missing candidate silently skipped".into()),
    };
    assert!(matches!(failure.reason,fss_reference::unifi_direct::av_rollover_generation::OpenSwitchesError::Storage {index:1,..}));
    assert_eq!(failure.opened.len(),1);
    drop(failure);
    create_candidate(&candidate2,&second_switch_owner.records()[0])?;
    let budget=BudgetVector::builder().bytes(64*1024*1024).build()?;
    let (mut authority,mut tree)=AuthorityCx::root(RootAuthoritySpec {
        trace_id:"trace:switch-inventory-worker".into(),operation_id:OperationId::parse("operation:switch-inventory-worker")?,
        principal:"principal:fixture".into(),capabilities:vec![RuntimeGrant::ObjectStage.as_str().into()],deadline:None,priority:1,budgets:budget,
        privacy_scope:"privacy:test".into(),retention_scope:"retention:test".into(),anchor_universe:ContentDigest::sha256(b"switch inventory worker"),generation:1,
    },RegionId::new("region:switch-inventory-worker")?,RegionKind::Process,budget,TimestampNs(1))?;
    let runtime=RuntimeBuilder::current_thread().blocking_threads(1,1).build()?;
    let (mut reserved,mut opened)=runtime.block_on(async {
        let cx=asupersync::Cx::current().ok_or("missing runtime")?;
        let result=run_owned_async(&mut authority,&mut tree,TaskSpec {task_id:TaskId::new("task:switch-inventory-worker")?,started_at:TimestampNs(3)},&cx,async |task,cx| {
            let output:Result<_,Box<dyn Error>>=async {
                use fss_reference::unifi_direct::av_rollover_generation::{ReservationInputs,ReservationOutcome,ReservationRequest,ReservationWorker};
                let clock=MeteredClock::new(task,cx,TimestampNs(4))?;
                let mut worker=ReservationWorker::new(ReservationInputs {
                    plan:reserved,request:ReservationRequest::InspectSwitches {predecessor,max_candidates:2,max_records:32,work_limit:4_000_000_000},
                    journal_resource:temp.0.join("opened-reservations"),custody_resource:temp.0.join("opened-reservation-pin"),
                    journal_replay:shared_replay.clone(),custody_replay:shared_replay.clone(),
                }).map_err(|_|"candidate worker invalid")?;
                worker.start(task,cx,clock,&BudgetVector::ZERO).map_err(|_|"candidate worker admission refused")?;
                let completion=worker.join().await.ok_or("candidate worker did not drain")?;
                if completion.runtime.is_err() || !completion.outcome_available || completion.indeterminate {return Err("candidate worker failed".into());}
                let mut retirement=worker.retire().map_err(|_|"candidate worker still running")?;
                if retirement.fenced {return Err("candidate worker fenced".into());}
                let (opened,chosen)=match retirement.outcome.take() {
                    Some(ReservationOutcome::SwitchesInspected {opened,selected:Some(chosen)})=>(opened,chosen),
                    _=>return Err("candidate worker selection missing".into()),
                };
                assert_eq!(opened.entries().len(),2);
                assert_eq!(chosen.index,0);
                assert_eq!(chosen.observation.binding,first_binding);
                Ok((retirement.inputs.plan,opened))
            }.await;
            let outcome=if output.is_ok(){TaskOutcome::Success}else{TaskOutcome::Failed("switch inventory worker fixture".into())};
            TaskCompletion {output,outcome,completed_at:TimestampNs(60_000_000_000)}
        }).await?;
        result.receipt?;result.output
    })?;
    assert!(authority.finalize_report(&tree)?.is_empty());
    reserved.record_reconciliation(&candidate2,ContentDigest::sha256(b"second candidate assessed"),&replay).map_err(|_|"second candidate reconcile refused")?;
    assert!(matches!(opened.select(&mut reserved,predecessor,32,&mut WorkBudget::new(100_000),&replay),Err(fss_reference::unifi_direct::av_rollover_generation::OpenSwitchesError::Stale)));
    let (_,entries,switches)=opened.into_parts();
    assert_eq!(entries.len(),2);
    assert_eq!(switches.len(),2);
    drop(switches);
    let duplicate_retainer = FileTrustedRootPinRetainer::create(
        temp.0.join("duplicate-switch-retainer"), storage_limits, Arc::new(HostSpoolIo),
        ContentDigest::sha256(b"duplicate switch custody"),
    )?;
    let mut duplicate_switch = PinRetainedEffectJournal::new(store("duplicate-switch")?, Box::new(duplicate_retainer))?;
    duplicate_switch.append(None, &first_switch_owner.records()[0])?;
    let mut candidates = [second_switch_owner, first_switch_owner, duplicate_switch];
    assert!(matches!(
        archive::journal::rollover::select_successor_switch(predecessor, &mut candidates[1..], &mut WorkBudget::new(100_000), &replay),
        Err(archive::journal::rollover::SwitchSelectionError::Ambiguous)
    ));
    let selected = archive::journal::rollover::select_successor_switch(predecessor, &mut candidates[..2], &mut WorkBudget::new(100_000), &replay)
        .map_err(|e| format!("switch selection failed: {e:?}"))?.ok_or("first switch not selected")?;
    assert_eq!(selected.index, 1);
    assert_eq!(selected.observation, first_observation);
    let no_match = archive::journal::rollover::SwitchPredecessor {confirmed:second_binding.confirmed, journal:first_binding.old_journal, keeper:first_heads.keeper, scope};
    assert!(archive::journal::rollover::select_successor_switch(no_match, &mut candidates[..2], &mut WorkBudget::new(100_000), &replay)
        .map_err(|e| format!("unmatched selection failed: {e:?}"))?.is_none());
    let [second_switch_owner, first_switch_owner, _duplicate_switch] = candidates;
    let mut first = archive::journal::rollover::recover(
        old,
        middle,
        first_switch_owner,
        first_heads,
        &replay,
    )
    .map_err(|_| "first cold recovery refused")?;
    first = match first.into_recovered_lineage(&replay) {
        Err(first) => first,
        Ok(_) => return Err("unreplayed first history admitted".into()),
    };
    first.replay_confirmed_source(
        &mut deployment,
        camera,
        &access,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &replay,
    )?;
    let first = first
        .into_recovered_lineage(&replay)
        .map_err(|_| "first lineage replay refused")?;
    let second_switch = second_switch_owner;
    let stale = archive::journal::rollover::SuccessorHeads {
        journal: second_binding.old_journal,
        keeper: second_heads.keeper,
    };
    let refusal = match first.advance(newest, second_switch, stale, &replay) {
        Err(refusal) => refusal,
        Ok(_) => return Err("stale second head accepted".into()),
    };
    assert_eq!(refusal.lineage.transition_count(), 1);
    let mut second = refusal
        .lineage
        .advance(refusal.successor, refusal.switch, second_heads, &replay)
        .map_err(|_| "second cold recovery refused")?;
    assert_eq!(second.binding(), second_binding);
    second = match second.into_recovered_lineage(&replay) {
        Err(second) => second,
        Ok(_) => return Err("unreplayed second history admitted".into()),
    };
    assert!(
        second
            .replay_confirmed_source(
                &mut deployment,
                camera,
                &Deny,
                &access,
                archive::Limits::default(),
                &mut WorkBudget::new(4_000_000_000),
                &replay
            )
            .is_err()
    );
    let receipt = second.replay_confirmed_source(
        &mut deployment,
        camera,
        &access,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &replay,
    )?;
    assert_eq!(receipt.outcome, RootLedgerOutcome::AlreadyLedgered);
    let lineage = second
        .into_recovered_lineage(&replay)
        .map_err(|_| "second lineage replay refused")?;
    assert_eq!(lineage.transition_count(), 2);
    let (current, custody) = lineage.into_parts();
    let recovered = archive::read_unknown_time_source(
        &mut deployment,
        second_binding.confirmed,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &replay,
    )?;
    let recovered_hash = ContentDigest::sha256(recovered.bytes());
    let mut worker = fss_reference::unifi_direct::source_worker::Worker::from_recovered(
        fss_reference::unifi_direct::source_worker::Parts {
            deployment,
            journal: current.journal,
            keeper: current.keeper,
            replay,
            authority: Arc::new(Access(retention)),
            retention,
            limits: archive::Limits::default(),
            max_source_bytes: 1024,
            work_limit: 4_000_000_000,
        },
        custody,
    )
    .map_err(|_| "recovered source worker refused")?;
    worker
        .offer(fss_reference::unifi_direct::source_worker::Input::Recovered(recovered))
        .map_err(|_| "recovered input refused")?;
    let budget = BudgetVector::builder().bytes(64 * 1024 * 1024).build()?;
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:chained-cold-worker".into(),
            operation_id: OperationId::parse("operation:chained-cold-worker")?,
            principal: "principal:fixture".into(),
            capabilities: vec![
                RuntimeGrant::ObjectStage.as_str().into(),
                RuntimeGrant::ObjectPublish.as_str().into(),
            ],
            deadline: Some(TimestampNs(60_000_000_000)),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"chained cold worker"),
            generation: 1,
        },
        RegionId::new("region:chained-cold-worker")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:chained-cold-worker")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |task, cx| {
                let output: Test = async {
                    let clock = MeteredClock::new(task, cx, TimestampNs(3))?;
                    worker
                        .start(
                            task,
                            cx,
                            clock,
                            "fixture:chained-cold-worker",
                            &BudgetVector::ZERO,
                        )
                        .map_err(|e| format!("cold worker start: {e:?}"))?;
                    let complete = worker
                        .join()
                        .await
                        .ok_or("missing cold worker completion")?;
                    if complete.runtime.is_err() {
                        return Err("cold worker runtime failed".into());
                    }
                    let pin = match complete.outcome {
                        fss_reference::unifi_direct::source_worker::Outcome::Publication(
                            fss_reference::unifi_direct::source_worker::Publication::Published {
                                pin,
                                ..
                            },
                        ) => pin,
                        _ => return Err("cold worker publication refused".into()),
                    };
                    let mut retired = worker.retire().map_err(|_| "recovered worker busy")?;
                    assert_eq!(
                        retired
                            .rollover_custody
                            .as_ref()
                            .ok_or("cold lineage lost")?
                            .transition_count(),
                        2
                    );
                    let read = archive::read_unknown_time_source(
                        &mut retired.parts.deployment,
                        pin,
                        &access,
                        archive::Limits::default(),
                        &mut WorkBudget::new(4_000_000_000),
                        &retired.parts.replay,
                    )?;
                    assert_eq!(ContentDigest::sha256(read.bytes()), recovered_hash);
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("cold worker fixture failed".into())
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
        source_history_limits: fss_object::effect_journal::EffectJournalLimits::default(),
        av_history_limits: fss_object::effect_journal::EffectJournalLimits::default(),
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

#[test]
fn worker_rollover_preserves_pending_source_and_switch_custody() -> Test {
    use fss_object::{
        HostSpoolIo,
        effect_journal::{EffectJournalLimits, FileEffectJournal, FileTrustedRootPinRetainer},
    };
    use fss_publication::RootLedgerOutcome;
    use fss_reference::unifi_direct::source_worker;
    use fss_runtime::effect_journal::{EffectJournalStore, PinRetainedEffectJournal};

    let parent = std::env::temp_dir().join(format!("fss-worker-rollover-{}", std::process::id()));
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
                anchor_universe: ContentDigest::sha256(b"worker rollover fixture"),
                generation: 1,
            })
        };
    let (mut authority, mut tree) = AuthorityCx::root(
        spec(
            "worker-rollover",
            vec![
                RuntimeGrant::ObjectPublish.as_str().into(),
                RuntimeGrant::ObjectStage.as_str().into(),
            ],
        )?,
        RegionId::new("region:worker-rollover")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let replay_authority = fss_core::region::ContextAuthority::new_root(spec(
        "worker-rollover-replay",
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
                task_id: TaskId::new("task:worker-rollover")?,
                started_at: TimestampNs(3),
            },
            &cx,
            async |task, cx| {
                let output: Test = async {
                    let clock = MeteredClock::new(task, cx, TimestampNs(4))?;
                    let replay =
                        ReplayCx::from_context_authority(&replay_authority, temp.0.clone())?;
                    let mut deployment = ReferenceDeployment::open(
                        &temp.0.join("archive"),
                        "site:worker-rollover",
                        &replay,
                    )?;
                    let storage_limits = EffectJournalLimits::default();
                    let store =
                        |name: &str| -> Result<Box<dyn EffectJournalStore>, Box<dyn Error>> {
                            Ok(Box::new(FileEffectJournal::create(
                                temp.0.join(name),
                                storage_limits,
                                Arc::new(HostSpoolIo),
                            )?))
                        };
                    let scope = ContentDigest::sha256(b"worker rollover scope");
                    let retention = ContentDigest::sha256(b"worker rollover retention");
                    let camera = ContentDigest::sha256(b"worker rollover camera");
                    let access = Arc::new(Access(retention));
                    let key = SourceKey {
                        connection: 1,
                        generation: 1,
                    };
                    let mut journal = archive::journal::UnknownTimeJournal::create(
                        store("old-journal")?,
                        scope,
                        &replay,
                    )?;
                    let mut keeper = archive::journal::UnknownTimeAnchorKeeper::create(
                        store("old-keeper")?,
                        &journal,
                        &replay,
                    )?;
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
                            return Err("missing initial record".into());
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
                            1024,
                        )?;
                        archive::publish_unknown_time_source_anchored(
                            &plan,
                            &mut deployment,
                            access.as_ref(),
                            archive::Limits::default(),
                            &mut WorkBudget::new(4_000_000_000),
                            &replay,
                            &mut journal,
                            &mut keeper,
                        )?;
                    }
                    let Next::Record(record) = framer.take()? else {
                        return Err("missing pending record".into());
                    };
                    let pending_hash = ContentDigest::sha256(record.bytes());
                    let mut worker = source_worker::Worker::new(source_worker::Parts {
                        deployment,
                        journal,
                        keeper,
                        replay,
                        authority: access.clone(),
                        retention,
                        limits: archive::Limits::default(),
                        max_source_bytes: 1024,
                        work_limit: 4_000_000_000,
                    })
                    .map_err(|_| "worker initialization")?;
                    worker
                        .offer(source_worker::Input::Original {
                            record,
                            key,
                            disposition: SourceDisposition::PreRoll,
                            camera_claim: camera,
                        })
                        .map_err(|_| "pending offer refused")?;
                    let mut retired = worker.retire().map_err(|_| "worker busy")?;
                    retired.parts.retention = ContentDigest::sha256(b"wrong rollover retention");
                    let mut retired = match retired.into_rollover() {
                        Err(retired) => retired,
                        Ok(_) => return Err("changed retention admitted before rollover".into()),
                    };
                    assert!(retired.pending.is_some());
                    retired.parts.retention = retention;
                    let (resources, previous) =
                        retired.into_rollover().map_err(|_| "detach refused")?;
                    assert!(resources.has_pending());
                    let staged = archive::journal::rollover::Staged::begin(
                        previous,
                        store("aborted-journal")?,
                        store("aborted-keeper")?,
                        resources.replay(),
                    )
                    .map_err(|_| "abort stage refused")?;
                    let retired = resources
                        .restore(staged.abort())
                        .map_err(|_| "restore refused")?;
                    let (resources, previous) = retired
                        .into_rollover()
                        .map_err(|_| "second detach refused")?;
                    assert!(resources.has_pending());
                    let staged = archive::journal::rollover::Staged::begin(
                        previous,
                        store("next-journal")?,
                        store("next-keeper")?,
                        resources.replay(),
                    )
                    .map_err(|_| "stage refused")?;
                    let retainer = FileTrustedRootPinRetainer::create(
                        temp.0.join("switch-retainer"),
                        storage_limits,
                        Arc::new(HostSpoolIo),
                        ContentDigest::sha256(b"worker switch custody"),
                    )?;
                    let switch =
                        PinRetainedEffectJournal::new(store("switch")?, Box::new(retainer))?;
                    let active = staged
                        .commit(switch, resources.replay())
                        .map_err(|_| "switch refused")?;
                    let refusal = match resources.attach(active) {
                        Err(refusal) => refusal,
                        Ok(_) => return Err("unreplayed successor attached".into()),
                    };
                    let mut resources = refusal.resources;
                    let mut active = refusal.active;
                    assert!(resources.has_pending());
                    let receipt = resources.replay_confirmed_source(
                        &mut active,
                        camera,
                        access.as_ref(),
                        &mut WorkBudget::new(4_000_000_000),
                    )?;
                    assert_eq!(receipt.outcome, RootLedgerOutcome::AlreadyLedgered);
                    let mut worker = resources
                        .attach(active)
                        .map_err(|_| "replayed attach refused")?;
                    assert_eq!(worker.status(), source_worker::Status::Pending);
                    worker
                        .start(
                            task,
                            cx,
                            clock,
                            "fixture:worker-rollover",
                            &BudgetVector::ZERO,
                        )
                        .map_err(|error| format!("worker start refused: {error:?}"))?;
                    let completed = worker.join().await.ok_or("worker missing completion")?;
                    assert!(completed.runtime.is_ok());
                    let pin = match completed.outcome {
                        source_worker::Outcome::Publication(
                            source_worker::Publication::Published { pin, .. },
                        ) => pin,
                        _ => return Err("pending source was not published".into()),
                    };
                    let mut retired = worker.retire().map_err(|_| "worker still running")?;
                    assert!(
                        !retired.fenced
                            && retired.pending.is_none()
                            && retired.rollover_custody.is_some()
                    );
                    assert_eq!(
                        retired.parts.deployment.publisher().visible_roots().count(),
                        3
                    );
                    let read = archive::read_unknown_time_source(
                        &mut retired.parts.deployment,
                        pin,
                        access.as_ref(),
                        archive::Limits::default(),
                        &mut WorkBudget::new(4_000_000_000),
                        &retired.parts.replay,
                    )?;
                    assert_eq!(ContentDigest::sha256(read.bytes()), pending_hash);
                    let (resources, previous) = retired
                        .into_rollover()
                        .map_err(|_| "second transition detach refused")?;
                    let stage = archive::journal::rollover::Staged::begin(
                        previous,
                        store("second-abort-journal")?,
                        store("second-abort-keeper")?,
                        resources.replay(),
                    )
                    .map_err(|_| "second abort stage refused")?;
                    let retired = resources
                        .restore(stage.abort())
                        .map_err(|_| "second restore refused")?;
                    assert_eq!(
                        retired
                            .rollover_custody
                            .as_ref()
                            .ok_or("lost first transition")?
                            .transition_count(),
                        1
                    );
                    let (mut resources, previous) = retired
                        .into_rollover()
                        .map_err(|_| "second transition redetach refused")?;
                    let stage = archive::journal::rollover::Staged::begin(
                        previous,
                        store("second-journal")?,
                        store("second-keeper")?,
                        resources.replay(),
                    )
                    .map_err(|_| "second stage refused")?;
                    let root = FileTrustedRootPinRetainer::create(
                        temp.0.join("second-switch-retainer"),
                        storage_limits,
                        Arc::new(HostSpoolIo),
                        ContentDigest::sha256(b"worker second switch custody"),
                    )?;
                    let switch =
                        PinRetainedEffectJournal::new(store("second-switch")?, Box::new(root))?;
                    let mut active = stage
                        .commit(switch, resources.replay())
                        .map_err(|_| "second switch refused")?;
                    resources.replay_confirmed_source(
                        &mut active,
                        camera,
                        access.as_ref(),
                        &mut WorkBudget::new(4_000_000_000),
                    )?;
                    let mut worker = resources
                        .attach(active)
                        .map_err(|_| "second attach refused")?;
                    worker
                        .offer(source_worker::Input::Recovered(read))
                        .map_err(|_| "recovered source refused")?;
                    worker
                        .start(
                            task,
                            cx,
                            clock,
                            "fixture:worker-rollover",
                            &BudgetVector::ZERO,
                        )
                        .map_err(|e| format!("second start: {e:?}"))?;
                    let result = worker.join().await.ok_or("second completion missing")?;
                    assert!(result.runtime.is_ok());
                    assert!(matches!(
                        result.outcome,
                        source_worker::Outcome::Publication(
                            source_worker::Publication::Published { .. }
                        )
                    ));
                    let retired = worker.retire().map_err(|_| "second worker busy")?;
                    assert_eq!(
                        retired
                            .rollover_custody
                            .as_ref()
                            .ok_or("lost transition chain")?
                            .transition_count(),
                        2
                    );
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("worker rollover fixture failed".into())
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
