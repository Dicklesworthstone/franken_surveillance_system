#![forbid(unsafe_code)]
//! One guarded controller-address restoration, for an owner-authorized lab.
//! An indeterminate write remains a journal obligation and is never replayed.
#[cfg(target_os = "linux")]
#[path = "../../../unifi_https_snapshot_lab/src/auth.rs"]
mod auth;
#[cfg(target_os = "linux")]
#[path = "trial_checkpoint/mod.rs"]
mod trial_checkpoint;
#[cfg(target_os = "linux")]
#[path = "trial_run_id/mod.rs"]
mod trial_run_id;

#[cfg(target_os = "linux")]
mod linux {
    use crate::{auth, trial_checkpoint, trial_run_id::TrialRunId};
    use asupersync::runtime::RuntimeBuilder;
    use fss_core::{
        BudgetVector, ContentDigest, IdempotencyKey, OperationId, RegionId, RegionKind,
        RootAuthoritySpec, RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
    };
    use fss_object::{
        HostSpoolIo,
        effect_journal::{EffectJournalLimits, FileEffectJournal},
    };
    use fss_reference::unifi_direct::{
        camera_api, camera_http, handoff,
        metered::{MeteredClock, MeteredIo},
    };
    use fss_runtime::{
        authority::AuthorityCx,
        effect::{CommitApproval, CommittedEffect, EffectCoordinator, PrepareSpec},
        execution::{TaskCompletion, TaskSpec, run_owned_async},
        lease::LeaseRegistry,
    };
    use std::{
        cell::{Cell, RefCell},
        error::Error,
        fs,
        net::{Ipv4Addr, SocketAddrV4},
        os::unix::fs::MetadataExt,
        path::PathBuf,
        sync::Arc,
        time::Duration,
    };
    use unifi_tls_05_server_lab::camera_tls;

    struct Guard<'a, 'scope, 'task, F> {
        peer: Ipv4Addr,
        expected: Ipv4Addr,
        lease: &'a auth::Lease,
        check: F,
        leases: &'a RefCell<LeaseRegistry>,
        clock: MeteredClock<'scope, 'task>,
        fence: u64,
    }
    impl<F: Fn() -> Result<(), &'static str>> camera_http::Authority for Guard<'_, '_, '_, F> {
        fn permits(&self, peer: Ipv4Addr, generation: u64, _: camera_http::Operation) -> bool {
            peer == self.peer && generation == 1 && self.lease.revalidate(&self.check).is_ok()
        }
    }
    impl<F: Fn() -> Result<(), &'static str>> camera_api::HandoffAuthority for Guard<'_, '_, '_, F> {
        fn permits(
            &self,
            plan: &handoff::Plan,
            current: handoff::Preconditions,
            permit: &CommittedEffect,
        ) -> bool {
            current.settings.controller == camera_api::ControllerAddress::Reported(self.expected)
                && plan.check_current(current).is_ok()
                && permit.fence() == self.fence
                && self.lease.revalidate(&self.check).is_ok()
                && self.clock.now().ok().is_some_and(|now| {
                    self.leases
                        .borrow_mut()
                        .check_fence(&plan.resource(), self.fence, now)
                        .is_ok()
                })
        }
    }
    fn scoped(ip: Ipv4Addr) -> bool {
        (ip.is_private() || ip.is_link_local())
            && !ip.is_unspecified()
            && !ip.is_multicast()
            && !ip.is_broadcast()
    }

    pub fn run() -> Result<(), Box<dyn Error>> {
        let args: Vec<_> = std::env::args().skip(1).collect();
        if !(8..=11).contains(&args.len())
            || args.last().map(String::as_str) != Some("--owner-authorized")
        {
            return Err("usage: unifi_controller_restore CAMERA_IPV4 HTTPS_PORT CERT_DER CREDENTIAL_FILE EXPECTED_TEMP_IPV4 RESTORE_IPV4 NEW_JOURNAL_DIR [--chunked] [--observe-only] [--anchored-journal=KEEPER,ROOT,SCOPE,MAC_HEX] --owner-authorized".into());
        }
        let mut chunked = false;
        let mut observe_only = false;
        let mut anchored = None;
        for flag in &args[7..args.len() - 1] {
            match flag.as_str() {
                "--chunked" if !chunked => chunked = true,
                "--observe-only" if !observe_only => observe_only = true,
                value if value.starts_with("--anchored-journal=") && anchored.is_none() => {
                    let fields: Vec<_> = value["--anchored-journal=".len()..].split(',').collect();
                    if fields.len()!=4 || fields[0].is_empty() || fields[1].is_empty() {
                        return Err("invalid anchored journal option".into());
                    }
                    OperationId::parse(fields[2])?;
                    let raw=fields[3].as_bytes();
                    if raw.len()!=12 || !raw.iter().all(u8::is_ascii_hexdigit) {
                        return Err("anchored camera MAC must be twelve hexadecimal digits".into());
                    }
                    let mut mac=[0u8;6];
                    for (index,byte) in mac.iter_mut().enumerate() {
                        *byte=u8::from_str_radix(&fields[3][index*2..index*2+2],16)?;
                    }
                    if mac==[0;6] || mac[0]&1!=0 { return Err("anchored camera MAC must be unicast".into()); }
                    anchored=Some((PathBuf::from(fields[0]),PathBuf::from(fields[1]),fields[2].to_owned(),mac));
                }
                _ => return Err("invalid or repeated restore option".into()),
            }
        }
        let peer: Ipv4Addr = args[0].parse()?;
        let port: u16 = args[1].parse()?;
        let cert_path = PathBuf::from(&args[2]);
        let credential = PathBuf::from(&args[3]);
        let expected: Ipv4Addr = args[4].parse()?;
        let destination: Ipv4Addr = args[5].parse()?;
        let journal_path = PathBuf::from(&args[6]);
        if !(peer.is_loopback() || scoped(peer))
            || !scoped(expected)
            || !scoped(destination)
            || expected == destination
            || port == 0
            || !cert_path.is_absolute()
            || !credential.is_absolute()
            || !journal_path.is_absolute()
            || journal_path.exists()
        {
            return Err("invalid restoration scope".into());
        }
        let parent = fs::symlink_metadata(journal_path.parent().ok_or("missing journal parent")?)?;
        if !parent.is_dir() || parent.mode() & 0o077 != 0 {
            return Err("journal parent must be private".into());
        }
        if let Some((keeper, root, _, _))=&anchored {
            let paths=[&journal_path,keeper,root];
            let mut resolved=Vec::with_capacity(paths.len());
            for path in paths {
                if !path.is_absolute() { return Err("anchored paths must be absolute".into()); }
                match fs::symlink_metadata(path) {
                    Err(e) if e.kind()==std::io::ErrorKind::NotFound => (),
                    Ok(_) => return Err("anchored paths must not exist".into()),
                    Err(e) => return Err(e.into()),
                }
                let parent=fs::symlink_metadata(path.parent().ok_or("missing anchored parent")?)?;
                if !parent.is_dir() || parent.mode() & 0o077 != 0 { return Err("anchored parent must be private".into()); }
                let name=path.file_name().ok_or("missing anchored path name")?;
                resolved.push(fs::canonicalize(path.parent().ok_or("missing anchored parent")?)?.join(name));
            }
            if resolved.iter().enumerate().any(|(i,p)| resolved.iter().skip(i+1).any(|q|p.starts_with(q)||q.starts_with(p))) {
                return Err("anchored paths must be distinct".into());
            }
        }
        let mut budget = BudgetVector::ZERO;
        budget.network_bytes = 8 * 1024 * 1024;
        budget.bytes = 8 * 1024 * 1024;
        budget.storage_operations = 4;
        let caps = [
            RuntimeGrant::AdapterNet,
            RuntimeGrant::AdapterAuth,
            RuntimeGrant::ObserveStatus,
            RuntimeGrant::ObjectStage,
            RuntimeGrant::CameraManagementPrepare,
            RuntimeGrant::CameraManagementCommit,
        ];
        let (mut authority, mut tree) = AuthorityCx::root(
            RootAuthoritySpec {
                trace_id: "trace:unifi-controller-restore".into(),
                operation_id: OperationId::parse("operation:unifi-controller-restore")?,
                principal: "principal:owner".into(),
                capabilities: caps.iter().map(|v| v.as_str().into()).collect(),
                deadline: Some(TimestampNs(60_000_000_000)),
                priority: 1,
                budgets: budget,
                privacy_scope: "privacy:owner".into(),
                retention_scope: "retention:trial".into(),
                anchor_universe: ContentDigest::sha256(b"owner-authorized controller restoration")
                    .with_laboratory(true),
                generation: 1,
            },
            RegionId::new("region:unifi-controller-restore")?,
            RegionKind::Process,
            budget,
            TimestampNs(1),
        )?;
        let runtime = RuntimeBuilder::current_thread().build()?;
        runtime.block_on(async {
            let cx=asupersync::Cx::current().ok_or("runtime unavailable")?;
            let run=run_owned_async(&mut authority,&mut tree,TaskSpec {task_id:TaskId::new("task:unifi-controller-restore")?,started_at:TimestampNs(2)},&cx,async |task,cx| {
                let effect_prepared=Cell::new(false);
                let output:Result<&'static str,Box<dyn Error>>=async {
                    let clock=MeteredClock::new(task,cx,TimestampNs(3))?;
                    task.checkpoint_for(RuntimeGrant::AdapterAuth,"unifi:certificate-pin",clock.now()?,&BudgetVector::ZERO)?;
                    let metadata=fs::symlink_metadata(&cert_path)?;
                    if !metadata.is_file() || metadata.len()==0 || metadata.len()>8192 {return Err("invalid certificate file".into());}
                    let cert=fs::read(&cert_path)?;
                    let admission=ContentDigest::sha256(&cert);
                    let mut binding=Vec::from(cert.as_slice());binding.extend_from_slice(&peer.octets());
                    let camera=ContentDigest::sha256(&binding);let resource=format!("camera:{}",camera.to_text());
                    let tls=camera_tls::connect(cx,task,clock,SocketAddrV4::new(peer,port),&cert,&resource,Duration::from_secs(10)).await?;
                    let check=||->Result<(), &'static str> {cx.checkpoint().map_err(|_|"runtime cancelled")?;
                        task.checkpoint_for(RuntimeGrant::AdapterAuth,&resource,clock.now().map_err(|_|"clock unavailable")?,&BudgetVector::ZERO).map_err(|_|"authorization unavailable")};
                    let credential=auth::Lease::load(&credential,&check)?;
                    let mut leases=LeaseRegistry::new();let fence=leases.acquire(&resource,"region:unifi-controller-restore",None,clock.now()?)?.fence;
                    let leases=RefCell::new(leases);
                    let guard=Guard {peer,expected,lease:&credential,check,leases:&leases,clock,fence};
                    let io=MeteredIo::with_clock(tls,clock,&resource,4096)?;
                    let mut api=camera_http::Owner::new(io,task,cx,clock,&guard,peer,1,&resource)?;
                    api.login(&credential.secret.0,Duration::from_secs(10)).await?;
                    let _status=api.status(Duration::from_secs(10)).await?;
                    let before=api.settings(Duration::from_secs(10)).await?;
                    let fresh=api.settings(Duration::from_secs(10)).await?;
                    if before!=fresh {return Err("controller claim changed; no write attempted".into());}
                    if observe_only {
                        return Ok(if before.controller==camera_api::ControllerAddress::Reported(destination) {"observed_original_no_effect"}
                            else if before.controller==camera_api::ControllerAddress::Reported(expected) {"observed_temporary_no_effect"}
                            else {"observed_other_no_effect"});
                    }
                    if before.controller==camera_api::ControllerAddress::Reported(destination) {return Ok("already_restored_no_effect");}
                    if before.controller!=camera_api::ControllerAddress::Reported(expected) {return Err("unexpected controller claim; no write attempted".into());}
                    let current=handoff::Preconditions {camera,peer_admission:admission,session_generation:1,lease_fence:fence,settings:before};
                    let framing=if chunked {handoff::Framing::Chunked} else {handoff::Framing::ContentLength};
                    let plan=handoff::Plan::new_with_framing(peer,destination,current,framing)?;
                    cx.checkpoint().map_err(|_|"cancelled before restore identity")?;
                    task.checkpoint_for(RuntimeGrant::AdapterAuth,"restore:run-identity-entropy",clock.now()?,&BudgetVector::ZERO)?;
                    let run_id=TrialRunId::fresh()?;
                    let operation=run_id.operation("restore")?;
                    let journal:Box<dyn fss_runtime::effect_journal::EffectJournalStore>=if let Some((keeper,root,scope,mac))=&anchored {
                        for path in [&journal_path,keeper,root] { task.checkpoint_for(RuntimeGrant::ObjectStage,&path.to_string_lossy(),clock.now()?,&BudgetVector::ZERO)?; }
                        let journal=trial_checkpoint::create(&journal_path,keeper,root,scope,*mac)?;
                        println!("restore_journal=anchored root_trust=operator_selected independence=unverified");
                        journal
                    } else {
                        task.checkpoint_for(RuntimeGrant::ObjectStage,&journal_path.to_string_lossy(),clock.now()?,&BudgetVector::ZERO)?;
                        Box::new(FileEffectJournal::create(&journal_path,EffectJournalLimits::default(),Arc::new(HostSpoolIo))?)
                    };
                    println!("restore_run_id={}",run_id.as_str());
                    let mut effects=EffectCoordinator::with_journal(journal)?;
                    let prepared=task.prepare_effect(cx,&mut effects,&mut leases.borrow_mut(),PrepareSpec {
                        operation:&operation,idempotency_key:IdempotencyKey::parse(operation.as_str())?,
                        request_digest:plan.request_digest(),precondition_digest:plan.precondition_digest(),resource:&resource,fence,
                        prepare_grant:RuntimeGrant::CameraManagementPrepare,commit_grant:RuntimeGrant::CameraManagementCommit,
                        terminal_predicate:"independent original-controller observation or reconciliation",
                    },clock.now()?)?;
                    effect_prepared.set(true);
                    credential.revalidate(&guard.check)?;plan.check_current(current)?;
                    let approval=CommitApproval {prepared_digest:prepared.digest(),current_precondition_digest:prepared.precondition_digest()};
                    let permit=task.commit_effect(cx,&mut effects,&mut leases.borrow_mut(),prepared,clock.now()?,approval)?;
                    let permit=match api.dispatch_handoff(&plan,current,permit,&guard,Duration::from_secs(10)).await {
                        Ok(camera_api::HandoffWrite::Written{permit})=>permit,
                        _=>return Err("restore dispatch refused or indeterminate; inspect journal and do not replay".into()),
                    };
                    let response=api.read_handoff_response_observed(&permit,Duration::from_secs(10)).await?;
                    if matches!(response,camera_api::HandoffResponseObservation::Object {success:Some(false),..}) {return Err("restore response refused; reconcile journal".into());}
                    let after=api.settings(Duration::from_secs(10)).await?;
                    if plan.classify_readback(after)?!=handoff::Readback::Requested {return Err("restore readback unconfirmed; reconcile journal".into());}
                    Ok("restore_claim_observed_effect_unsettled")
                }.await;
                let outcome=if effect_prepared.get(){TaskOutcome::Indeterminate("restore effect requires independent reconciliation".into())}
                    else if output.is_ok(){TaskOutcome::Success}
                    else{TaskOutcome::Failed("restore stopped before effect preparation".into())};
                TaskCompletion{output,outcome,completed_at:TimestampNs(59_000_000_000)}
            }).await?;
            run.receipt?;let result=run.output?;
            println!("restore={result} identity=network_pin_unverified retries=none");
            Ok::<(),Box<dyn Error>>(())
        })
    }
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    linux::run()
}
#[cfg(not(target_os = "linux"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    Err("the laboratory private-file boundary currently supports Linux only".into())
}
