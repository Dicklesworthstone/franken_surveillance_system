#![forbid(unsafe_code)]
//! Isolated owner-authorized journaled controller handoff experiment.
//! The same-network observed certificate is not independent proof of device identity.
#[cfg(not(target_os = "linux"))]
compile_error!("the laboratory private-file boundary currently supports Linux only");
use asupersync::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    runtime::RuntimeBuilder,
    time::{sleep, timeout},
};
#[path = "../auth.rs"]
mod auth;
#[path = "../client.rs"]
mod client;
use fss_core::{
    BudgetVector, ContentDigest, DigestAlgorithm, IdempotencyKey, OperationId, RegionId,
    RegionKind, RootAuthoritySpec, RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_object::{
    HostSpoolIo,
    effect_journal::{EffectJournalLimits, FileEffectJournal},
};
use fss_reference::unifi_direct::{camera_api, camera_http, handoff, metered};
use fss_runtime::{
    authority::AuthorityCx,
    effect::{CommitApproval, CommittedEffect, EffectCoordinator, PrepareSpec},
    execution::{TaskCompletion, TaskSpec, run_owned_async},
    lease::LeaseRegistry,
};
use metered::{MeteredClock, MeteredIo};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{WebPkiSupportedAlgorithms, verify_tls13_signature_with_raw_key},
    pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime},
};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeSet,
};
use std::{
    error::Error,
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::unix::fs::MetadataExt,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use x509_cert::{
    Certificate,
    der::{Decode, Encode},
};

struct ObservedPin {
    cert: Vec<u8>,
    spki: SubjectPublicKeyInfoDer<'static>,
    algorithms: WebPkiSupportedAlgorithms,
}
impl std::fmt::Debug for ObservedPin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ObservedPin(<redacted>)")
    }
}
impl ObservedPin {
    fn verify_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        if cert.as_ref() != self.cert || signature.scheme != SignatureScheme::ECDSA_NISTP256_SHA256
        {
            return Err(rustls::Error::General("LAB_SIGNATURE_REJECTED".into()));
        }
        verify_tls13_signature_with_raw_key(msg, &self.spki, signature, &self.algorithms)
            .map_err(|_| rustls::Error::General("LAB_SIGNATURE_REJECTED".into()))
    }
}
impl ServerCertVerifier for ObservedPin {
    fn verify_server_cert(
        &self,
        end: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end.as_ref() == self.cert {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("LAB_PIN_MISMATCH".into()))
        }
    }
    fn verify_tls12_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify_signature(msg, cert, signature)
    }
    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify_signature(msg, cert, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}
fn observed(start: Instant) -> TimestampNs {
    TimestampNs(
        i128::try_from(start.elapsed().as_nanos())
            .unwrap_or(i128::MAX)
            .saturating_add(1),
    )
}

// This fixture-only policy deliberately revalidates a private file with
// synchronous filesystem calls. It is not a production nonblocking lease.
struct LabAuthority<'a, F> {
    lease: &'a auth::Lease,
    check: F,
    peer: std::net::Ipv4Addr,
}
impl<F: Fn() -> Result<(), &'static str>> camera_http::Authority for LabAuthority<'_, F> {
    fn permits(
        &self,
        peer: std::net::Ipv4Addr,
        generation: u64,
        _: camera_http::Operation,
    ) -> bool {
        peer == self.peer && generation == 1 && self.lease.revalidate(&self.check).is_ok()
    }
}

struct HandoffGuard<'a, 'scope, 'task, F> {
    auth: &'a LabAuthority<'a, F>,
    leases: &'a RefCell<LeaseRegistry>,
    clock: MeteredClock<'scope, 'task>,
}
impl<F: Fn() -> Result<(), &'static str>> camera_api::HandoffAuthority
    for HandoffGuard<'_, '_, '_, F>
{
    fn permits(
        &self,
        plan: &handoff::Plan,
        current: handoff::Preconditions,
        permit: &CommittedEffect,
    ) -> bool {
        self.auth.lease.revalidate(&self.auth.check).is_ok()
            && plan.check_current(current).is_ok()
            && permit.fence() == plan.fence()
            && self.clock.now().ok().is_some_and(|now| {
                self.leases
                    .borrow_mut()
                    .check_fence(&plan.resource(), plan.fence(), now)
                    .is_ok()
            })
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if !(args.len() == 11 || (args.len() == 12 && matches!(args[11].as_str(), "--chunked" | "--observe-only"))) || args[10] != "--owner-authorized" {
        return Err("expected CERT_DER CAMERA_IPV4 TLS_VERSION PIN_CASE SCOPE_SHA CREDENTIAL_FILE PORT EXPECTED_CONTROLLER DESTINATION JOURNAL_DIR --owner-authorized [--chunked|--observe-only]".into());
    }
    let observe_only = args.get(11).is_some_and(|s| s == "--observe-only");
    let expected: Ipv4Addr = args[7].parse()?;
    let destination: Ipv4Addr = args[8].parse()?;
    let journal_path = Path::new(&args[9]);
    if !journal_path.is_absolute() || journal_path.exists() {
        return Err("journal path must be absolute and new".into());
    }
    let parent = fs::symlink_metadata(journal_path.parent().ok_or("journal parent missing")?)?;
    if !parent.file_type().is_dir() || parent.mode() & 0o077 != 0 {
        return Err("journal parent must be a private directory".into());
    }
    let mut cert = fs::read(&args[0])?;
    if cert.is_empty() || cert.len() > 8192 {
        return Err("invalid certificate size".into());
    }
    let peer_admission = ContentDigest::sha256(&cert);
    let parsed = Certificate::from_der(&cert)?;
    let mut spki = parsed.tbs_certificate.subject_public_key_info.to_der()?;
    let expected_failure = match args[3].as_str() {
        "match" => None,
        "mismatch" => {
            cert[0] ^= 1;
            Some("LAB_PIN_MISMATCH")
        }
        "bad-key" => {
            // Public, valid P-256 generator point (not a generated secret).
            let point: [u8; 65] = [
                0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
                0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39,
                0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e,
                0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e,
                0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
            ];
            if spki.len() != 91 || spki[26] != 4 || spki[26..] == point {
                return Err("unexpected public-key shape".into());
            }
            spki[26..].copy_from_slice(&point);
            Some("LAB_SIGNATURE_REJECTED")
        }
        _ => return Err("invalid pin case".into()),
    };
    let version = match args[2].as_str() {
        "tls12" => &rustls::version::TLS12,
        "tls13" => &rustls::version::TLS13,
        _ => return Err("invalid TLS version".into()),
    };
    let provider = Arc::new(rustls_rustcrypto::provider());
    let verifier = Arc::new(ObservedPin {
        cert,
        spki: spki.into(),
        algorithms: provider.signature_verification_algorithms,
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let ip: IpAddr = args[1].parse()?;
    if !matches!(ip, IpAddr::V4(v4) if v4.is_private() || v4.is_loopback() || v4.is_link_local()) {
        return Err("private or loopback IPv4 required".into());
    }
    let port: u16 = args[6].parse()?;
    if port == 0 || (!ip.is_loopback() && port != 443) {
        return Err("private camera must use HTTPS port 443".into());
    }
    let address = SocketAddr::new(ip, port);
    let scope = ContentDigest::parse(&args[4])?;
    if scope.algorithm() != DigestAlgorithm::Sha256 || scope.bytes() == [0; 32] {
        return Err("a nonzero SHA-256 scope digest is required".into());
    }
    let start = Instant::now();
    let mut camera_binding = Vec::from(peer_admission.bytes());
    if let IpAddr::V4(peer) = ip {
        camera_binding.extend_from_slice(&peer.octets());
    }
    let camera = ContentDigest::sha256(&camera_binding);
    let resource = format!("camera:{}", camera.to_text());
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 12 * 1024 * 1024;
    budget.bytes = 4 * 1024 * 1024;
    budget.storage_operations = 3;
    let capabilities = vec![
        RuntimeGrant::AdapterNet.as_str().into(),
        RuntimeGrant::AdapterAuth.as_str().into(),
        RuntimeGrant::ObserveStatus.as_str().into(),
        RuntimeGrant::CameraManagementPrepare.as_str().into(),
        RuntimeGrant::CameraManagementCommit.as_str().into(),
    ];
    let (mut owner, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:unifi-owned-lab".into(),
            operation_id: OperationId::parse("operation:unifi-owned-lab")?,
            principal: "principal:owner".into(),
            capabilities,
            deadline: Some(TimestampNs(60_000_000_000)),
            priority: 10,
            budgets: budget,
            privacy_scope: "privacy:local".into(),
            retention_scope: "retention:lab".into(),
            anchor_universe: scope.with_laboratory(true),
            generation: 1,
        },
        RegionId::new("region:unifi-owned-lab")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let grants = owner
        .grants()
        .clone()
        .with_scope(RuntimeGrant::AdapterNet, BTreeSet::from([resource.clone()]))
        .with_scope(
            RuntimeGrant::AdapterAuth,
            BTreeSet::from([resource.clone()]),
        )
        .with_scope(
            RuntimeGrant::ObserveStatus,
            BTreeSet::from([resource.clone()]),
        )
        .with_scope(
            RuntimeGrant::CameraManagementPrepare,
            BTreeSet::from([resource.clone()]),
        )
        .with_scope(
            RuntimeGrant::CameraManagementCommit,
            BTreeSet::from([resource.clone()]),
        );
    owner.narrow_grants(grants)?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime context")?;
        let result = run_owned_async(&mut owner, &mut tree,
            TaskSpec { task_id: TaskId::new("task:unifi-owned-lab")?, started_at: observed(start) },
            &cx,
            async |task, cx| {
        let effect_started=Cell::new(false);
        let output: Result<String, Box<dyn Error>> = async {
        task.checkpoint_for(RuntimeGrant::AdapterNet, &resource, observed(start), &BudgetVector::ZERO)?;
        let raw = timeout(cx.now(), Duration::from_secs(5), TcpStream::connect(address)).await??;
        let clock = MeteredClock::new(task, cx, observed(start))?;
        let mut stream = MeteredIo::with_clock(raw, clock, &resource, 4096)?;
        let mut connection = ClientConnection::new(Arc::new(config), ServerName::IpAddress(ip.into()))?;
        let handshake = async {
            let mut sent = 0_usize;
            let mut received = 0_usize;
            let mut input = [0_u8; 4096];
            for _ in 0..128 {
                cx.checkpoint().map_err(|_| "runtime cancelled")?;
                while connection.wants_write() {
                    let mut output = Vec::new();
                    let written = connection.write_tls(&mut output)?;
                    if written == 0 || output.len() > 65_536 || sent.saturating_add(output.len()) > 262_144 {
                        return Err("outbound handshake limit".into());
                    }
                    stream.write_all(&output).await?;
                    sent += output.len();
                }
                if !connection.is_handshaking() { return Ok::<bool, Box<dyn Error>>(true); }
                if !connection.wants_read() { return Err("TLS handshake made no progress".into()); }
                let count = stream.read(&mut input).await?;
                if count == 0 || received.saturating_add(count) > 262_144 { return Err("EOF or inbound handshake limit".into()); }
                received += count;
                let mut source = std::io::Cursor::new(&input[..count]);
                while source.position() < count as u64 {
                    if connection.read_tls(&mut source)? == 0 { return Err("TLS read made no progress".into()); }
                    if let Err(error) = connection.process_new_packets() {
                        if expected_failure.is_some_and(|expected| error.to_string().contains(expected)) {
                            return Ok(false);
                        }
                        return Err(error.into());
                    }
                }
            }
            Err("handshake iteration limit".into())
        };
        let accepted = timeout(cx.now(), Duration::from_secs(10), handshake).await??;
        if !accepted { return Ok(format!("{}=rejected", args[3])); }
        if expected_failure.is_some() { return Err("invalid pin or public key was accepted".into()); }
        let check_auth = || -> Result<(), &'static str> {
            cx.checkpoint().map_err(|_| "runtime cancelled")?;
            let now=clock.now().map_err(|_| "task clock unavailable")?;
            task.checkpoint_for(RuntimeGrant::AdapterAuth, &resource, now, &BudgetVector::ZERO).map_err(|_| "camera authentication authority refused")
        };
        let lease=auth::Lease::load(Path::new(&args[5]), &check_auth)?;
        lease.revalidate(&check_auth)?;
        let peer=match ip { IpAddr::V4(peer)=>peer, _=>return Err("IPv4 required".into()) };
        let policy=LabAuthority { lease: &lease, check: check_auth, peer };
        let tls=client::Client::new(connection,stream);
        let plaintext=MeteredIo::with_clock(tls,clock,&resource,4096)?;
        let mut api=camera_http::Owner::new(plaintext,task,cx,clock,&policy,peer,1,&resource)?;
        api.login(&lease.secret.0,Duration::from_secs(10)).await?;
        api.status(Duration::from_secs(10)).await?;
        let settings=api.settings(Duration::from_secs(10)).await?;
        if observe_only {
            let fresh=api.settings(Duration::from_secs(10)).await?;
            if fresh!=settings {return Err("controller claim changed during observation".into());}
            let claim=match settings.controller {
                camera_api::ControllerAddress::Reported(address) if address==expected => "expected",
                camera_api::ControllerAddress::Reported(address) if address==destination => "destination",
                camera_api::ControllerAddress::Reported(_) => "different",
                camera_api::ControllerAddress::Unset => "unset",
                camera_api::ControllerAddress::Missing => "missing",
                camera_api::ControllerAddress::Unsupported => "unsupported",
            };
            return Ok(format!("controller_claim={claim} effect=none identity=unverified"));
        }
        if settings.controller==camera_api::ControllerAddress::Reported(destination) {
            return Ok("controller_claim=already_destination effect=none identity=unverified".into());
        }
        if settings.controller!=camera_api::ControllerAddress::Reported(expected) {
            return Err("current controller claim does not match expected address".into());
        }
        let fresh=api.settings(Duration::from_secs(10)).await?;
        if fresh!=settings {return Err("controller claim changed during handoff preparation".into());}
        let mut lease_registry=LeaseRegistry::new();
        let fence=lease_registry.acquire(&resource,"region:unifi-owned-lab",None,clock.now()?)?.fence;
        let lease_registry=RefCell::new(lease_registry);
        let conditions=handoff::Preconditions {camera,peer_admission,session_generation:1,lease_fence:fence,settings};
        let framing=if args.get(11).is_some_and(|s| s=="--chunked") {handoff::Framing::Chunked} else {handoff::Framing::ContentLength};
        let plan=handoff::Plan::new_with_framing(peer,destination,conditions,framing)?;
        let journal=FileEffectJournal::create(journal_path,EffectJournalLimits::default(),Arc::new(HostSpoolIo))?;
        let mut effects=EffectCoordinator::with_journal(Box::new(journal))?;
        let operation=OperationId::parse("operation:unifi-handoff-trial")?;
        let prepared=task.prepare_effect(cx,&mut effects,&mut lease_registry.borrow_mut(),PrepareSpec {
            operation:&operation,idempotency_key:IdempotencyKey::parse(operation.as_str())?,
            request_digest:plan.request_digest(),precondition_digest:plan.precondition_digest(),resource:&resource,fence,
            prepare_grant:RuntimeGrant::CameraManagementPrepare,commit_grant:RuntimeGrant::CameraManagementCommit,
            terminal_predicate:"fresh independent controller association observation or reconciliation",
        },clock.now()?)?;
        effect_started.set(true);
        lease.revalidate(&policy.check)?;
        plan.check_current(conditions)?;
        lease_registry.borrow_mut().check_fence(&resource,fence,clock.now()?)?;
        let approval=CommitApproval {prepared_digest:prepared.digest(),current_precondition_digest:prepared.precondition_digest()};
        let permit=task.commit_effect(cx,&mut effects,&mut lease_registry.borrow_mut(),prepared,clock.now()?,approval)?;
        let guard=HandoffGuard {auth:&policy,leases:&lease_registry,clock};
        let permit=match api.dispatch_handoff(&plan,conditions,permit,&guard,Duration::from_secs(10)).await.map_err(|_|"handoff was refused; inspect journal")? {
            camera_api::HandoffWrite::Written {permit}=>permit,
            camera_api::HandoffWrite::Indeterminate {..}=>return Err("handoff write indeterminate; do not retry without reconciliation".into()),
        };
        let response=api.read_handoff_response_observed(&permit,Duration::from_secs(10)).await?;
        println!("handoff_response={response:?} identity=unverified");
        let mut all_requested=true;
        for (index,delay_ms) in [0_u64,500,1500].into_iter().enumerate() {
            if delay_ms != 0 {
                task.checkpoint_for(RuntimeGrant::ObserveStatus,&resource,clock.now()?,&BudgetVector::ZERO)?;
                sleep(cx.now(),Duration::from_millis(delay_ms)).await;
                cx.checkpoint().map_err(|_|"runtime cancelled")?;
            }
            let after=api.settings(Duration::from_secs(10)).await?;
            let readback=plan.classify_readback(after)?;
            println!("handoff_readback[{index}]={readback:?} identity=unverified");
            all_requested &= readback==handoff::Readback::Requested;
        }
        if !all_requested {
            return Err("handoff readback was not consistently requested; effect requires reconciliation; do not retry automatically".into());
        }
        Ok("controller_claim=requested effect=reconciliation_required identity=unverified".into())
        }.await;
        let outcome = if effect_started.get() { TaskOutcome::Indeterminate("handoff effect requires independent reconciliation".into()) } else if output.is_ok() { TaskOutcome::Success } else { TaskOutcome::Failed("handoff stopped before effect preparation".into()) };
        TaskCompletion { output, outcome, completed_at: observed(start) }
            },
        ).await?;
        result.receipt?;
        println!("{} task_receipt=completed", result.output?);
        Ok::<(), Box<dyn Error>>(())
    })
}
