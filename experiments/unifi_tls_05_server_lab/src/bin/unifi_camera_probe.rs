#![forbid(unsafe_code)]
//! Bounded, owner-authorized camera HTTPS snapshot probe. No settings writes.
#[cfg(target_os = "linux")]
#[path = "../../../unifi_https_snapshot_lab/src/auth.rs"]
mod auth;

#[cfg(target_os = "linux")]
mod linux {
    use crate::auth;
    use asupersync::runtime::RuntimeBuilder;
    use fss_core::{
        BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
        RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
    };
    use fss_reference::unifi_direct::{
        camera_api, camera_http,
        metered::{MeteredClock, MeteredIo},
    };
    use fss_runtime::{
        authority::AuthorityCx,
        execution::{TaskCompletion, TaskSpec, run_owned_async},
    };
    use std::{
        error::Error,
        fs,
        io::{self, Write},
        net::{Ipv4Addr, SocketAddrV4},
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
        time::Duration,
    };
    use unifi_tls_05_server_lab::camera_tls;

    struct Authority<'a, F> {
        peer: Ipv4Addr,
        lease: &'a auth::Lease,
        check: F,
    }
    impl<F: Fn() -> Result<(), &'static str>> camera_http::Authority for Authority<'_, F> {
        fn permits(&self, peer: Ipv4Addr, generation: u64, _: camera_http::Operation) -> bool {
            peer == self.peer && generation == 1 && self.lease.revalidate(&self.check).is_ok()
        }
    }

    pub fn run() -> Result<(), Box<dyn Error>> {
        let args: Vec<_> = std::env::args().skip(1).collect();
        if args.len() < 5 || args.len() > 7 || args.last().map(String::as_str) != Some("--owner-authorized") {
            return Err("usage: unifi_camera_probe CAMERA_IPV4 HTTPS_PORT CAMERA_CERT_DER CREDENTIAL_FILE [--observe-profiles] [--save-snapshot=ABSOLUTE_PATH] --owner-authorized".into());
        }
        let mut observe_profiles=false;
        let mut export_arg=None;
        for arg in &args[4..args.len()-1] {
            if arg == "--observe-profiles" && !observe_profiles { observe_profiles=true; }
            else if let Some(path)=arg.strip_prefix("--save-snapshot=") {
                if export_arg.replace(path).is_some() { return Err("duplicate export argument".into()); }
            } else { return Err("invalid probe option".into()); }
        }
        let export = if let Some(value) = export_arg {
            let path = PathBuf::from(value);
            if !path.is_absolute() { return Err("export path must be absolute".into()); }
            match fs::symlink_metadata(&path) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                Ok(_) => return Err("export path already exists".into()),
                Err(e) => return Err(e.into()),
            }
            let parent = fs::symlink_metadata(path.parent().ok_or("export parent required")?)?;
            if !parent.is_dir() || parent.mode() & 0o077 != 0 { return Err("export parent must be a private directory".into()); }
            Some(path)
        } else { None };
        let peer: Ipv4Addr = args[0].parse()?;
        let port: u16 = args[1].parse()?;
        let cert_path = PathBuf::from(&args[2]);
        let credential = PathBuf::from(&args[3]);
        if !(peer.is_private() || peer.is_loopback() || peer.is_link_local())
            || port == 0
            || !cert_path.is_absolute()
            || !credential.is_absolute()
        {
            return Err("invalid scoped probe arguments".into());
        }
        let mut budget = BudgetVector::ZERO;
        budget.network_bytes = 16 * 1024 * 1024;
        budget.bytes = 16 * 1024 * 1024;
        budget.storage_operations = if export.is_some() { 3 } else { 0 };
        let mut capabilities = vec![
            RuntimeGrant::AdapterNet,
            RuntimeGrant::AdapterAuth,
            RuntimeGrant::ObserveStatus,
            RuntimeGrant::ReadMedia,
            RuntimeGrant::MediaDecode,
        ];
        if export.is_some() { capabilities.push(RuntimeGrant::ObjectStage); }
        let (mut authority, mut tree) = AuthorityCx::root(
            RootAuthoritySpec {
                trace_id: "trace:unifi-camera-probe".into(),
                operation_id: OperationId::parse("operation:unifi-camera-probe")?,
                principal: "principal:owner".into(),
                capabilities: capabilities.iter().map(|v| v.as_str().into()).collect(),
                deadline: Some(TimestampNs(60_000_000_000)),
                priority: 1,
                budgets: budget,
                privacy_scope: "privacy:owner".into(),
                retention_scope: if export.is_some() { "retention:owner-export" } else { "retention:in-memory" }.into(),
                anchor_universe: ContentDigest::sha256(b"owner-authorized camera probe")
                    .with_laboratory(true),
                generation: 1,
            },
            RegionId::new("region:unifi-camera-probe")?,
            RegionKind::Process,
            budget,
            TimestampNs(1),
        )?;
        let runtime = RuntimeBuilder::current_thread().build()?;
        runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("runtime unavailable")?;
        let result = run_owned_async(&mut authority, &mut tree,
            TaskSpec { task_id: TaskId::new("task:unifi-camera-probe")?, started_at: TimestampNs(2) }, &cx,
            async |task, cx| {
                let output: Result<(u32,u32,Option<String>,Option<camera_api::SettingsObservation>), Box<dyn Error>> = async {
                    let clock = MeteredClock::new(task, cx, TimestampNs(3))?;
                    task.checkpoint_for(RuntimeGrant::AdapterAuth, "unifi:certificate-pin", clock.now()?, &BudgetVector::ZERO)?;
                    let metadata = fs::symlink_metadata(&cert_path)?;
                    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 8192 { return Err("invalid certificate file".into()); }
                    let cert = fs::read(&cert_path)?;
                    let mut binding=Vec::from(cert.as_slice()); binding.extend_from_slice(&peer.octets());
                    let resource=format!("camera:{}",ContentDigest::sha256(&binding).to_text());
                    let tls=camera_tls::connect(cx,task,clock,SocketAddrV4::new(peer,port),&cert,&resource,Duration::from_secs(10)).await?;
                    let check=||->Result<(), &'static str> {
                        cx.checkpoint().map_err(|_| "runtime cancelled")?;
                        task.checkpoint_for(RuntimeGrant::AdapterAuth,&resource,clock.now().map_err(|_| "clock unavailable")?,&BudgetVector::ZERO).map_err(|_| "authorization unavailable")
                    };
                    let lease=auth::Lease::load(Path::new(&credential),&check)?;
                    let policy=Authority {peer,lease:&lease,check};
                    let io=MeteredIo::with_clock(tls,clock,&resource,4096)?;
                    let mut camera=camera_http::Owner::new(io,task,cx,clock,&policy,peer,1,&resource)?;
                    camera.login(&lease.secret.0,Duration::from_secs(10)).await?;
                    let _status=camera.status(Duration::from_secs(10)).await?;
                    let profiles=if observe_profiles {Some(camera.settings(Duration::from_secs(10)).await?)} else {None};
                    task.checkpoint_for(RuntimeGrant::ReadMedia,&resource,clock.now()?,&BudgetVector::ZERO)?;
                    let snapshot=camera.snapshot(Duration::from_secs(10)).await?;
                    task.checkpoint_for(RuntimeGrant::MediaDecode,&resource,clock.now()?,&BudgetVector::ZERO)?;
                    let limits=fss_codec_mjpeg::DecodeLimits {maximum_bytes:4*1024*1024,..Default::default()};
                    let mut work=fss_codec_mjpeg::DecodeBudget::new(limits.luma_work_bound().min(1_500_000_000));
                    let image=fss_codec_mjpeg::decode_luma(snapshot.bytes(),snapshot.digest().bytes(),fss_codec_mjpeg::ComponentInterpretation::YCbCr,limits,&mut work)?;
                    let [width,height]=image.dimensions();
                    if image.pixels().len()!=width as usize*height as usize {return Err("invalid decoded image size".into());}
                    let exported = if let Some(path) = &export {
                        let mut cost=BudgetVector::ZERO;
                        cost.bytes=u64::try_from(snapshot.bytes().len())?;
                        cost.storage_operations=3;
                        task.checkpoint_for(RuntimeGrant::ObjectStage,&path.to_string_lossy(),clock.now()?,&cost)?;
                        let mut file=fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
                        file.write_all(snapshot.bytes())?;
                        file.sync_all()?;
                        Some(snapshot.digest().to_text())
                    } else { None };
                    Ok((width,height,exported,profiles))
                }.await;
                let outcome=if output.is_ok() {TaskOutcome::Success} else {TaskOutcome::Failed("read-only camera probe failed".into())};
                TaskCompletion {output,outcome,completed_at:TimestampNs(59_000_000_000)}
            }).await?;
        result.receipt?;
        let (width,height,exported,profiles)=result.output?;
        println!("probe=ok tls_pin=matched controller_peer=unverified snapshot_decoded={width}x{height} media_persisted={} settings_written=false", exported.is_some());
        if let Some(digest)=exported { println!("snapshot_sha256={digest}"); }
        if let Some(settings)=profiles { println!("video_profiles={:?} snapshot_profile={:?} source=camera_claim",settings.video_profiles,settings.snapshot_profile); }
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
