#![forbid(unsafe_code)]
//! Isolated credentialed HTTPS snapshot experiment. NOT a production verifier.
//! The same-network observed certificate is not independent proof of device identity.
#[cfg(not(target_os = "linux"))]
compile_error!("the laboratory private-file boundary currently supports Linux only");
use asupersync::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    runtime::RuntimeBuilder,
    time::{sleep, timeout},
};
mod auth;
#[path = "../../../crates/fss-reference/src/unifi_direct/camera_api.rs"]
mod camera_api;
#[path = "../../../crates/fss-reference/src/unifi_direct/camera_http.rs"]
mod camera_http;
mod client;
#[path = "../../../crates/fss-reference/src/unifi_direct/handoff.rs"]
mod handoff;
#[path = "../../../crates/fss-reference/src/unifi_direct/metered.rs"]
mod metered;
mod output;
use fss_core::{
    BudgetVector, ContentDigest, DigestAlgorithm, OperationId, RegionId, RegionKind,
    RootAuthoritySpec, RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_runtime::{
    authority::AuthorityCx,
    execution::{TaskCompletion, TaskSpec, run_owned_async},
};
use metered::{MeteredClock, MeteredIo};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{WebPkiSupportedAlgorithms, verify_tls13_signature_with_raw_key},
    pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime},
};
use std::collections::BTreeSet;
use std::{
    error::Error,
    fs,
    net::{IpAddr, SocketAddr},
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

fn serializer_fields(tracks: [Option<&fss_core::json_input::Value>; 3]) -> [(&'static str, &'static str); 3] {
    use fss_core::json_input::Value;
    tracks.map(|value| {
        let Some(Value::Object(serializer)) = value else {
            return (if value.is_none() { "absent" } else { "not-object" }, "unknown");
        };
        let destinations = match serializer.get("destinations") {
            None => "missing",
            Some(Value::Null) => "null",
            Some(Value::Array(_)) => "array",
            Some(_) => "other",
        };
        let opus = match serializer.get("parameters").and_then(Value::object).and_then(|p| p.get("withOpus")) {
            Some(Value::Bool(true)) => "true",
            Some(Value::Bool(false)) => "false",
            _ => "unknown",
        };
        (destinations, opus)
    })
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

fn main() -> Result<(), Box<dyn Error>> {
    let mut args: Vec<_> = std::env::args().skip(1).collect();
    let inspect_serializers = args.len() >= 2 && args[args.len() - 2] == "--serializer-inspect";
    if inspect_serializers {
        args.remove(args.len() - 2);
    }
    let repeat_serializers = args.len() >= 2 && args[args.len() - 2] == "--repeat-serializers";
    if repeat_serializers {
        args.remove(args.len() - 2);
        if !inspect_serializers {
            return Err("repeat-serializers requires serializer-inspect".into());
        }
    }
    let three_snapshots = args.len() >= 2 && args[args.len() - 2] == "--three-snapshots";
    if three_snapshots {
        args.remove(args.len() - 2);
    }
    if !(args.len() == 8 || args.len() == 9)
        || args.last().is_none_or(|s| s != "--owner-authorized")
    {
        return Err("expected certificate path, private IPv4 address, tls12|tls13, match|mismatch|bad-key, scope-sha256, credential-file path, port, optional output path, optional --three-snapshots, --owner-authorized".into());
    }
    let output_path = if args.len() == 9 {
        let path = Path::new(&args[7]);
        output::validate(path)?;
        Some(path)
    } else {
        None
    };
    let mut cert = fs::read(&args[0])?;
    if cert.is_empty() || cert.len() > 8192 {
        return Err("invalid certificate size".into());
    }
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
    let resource = format!("unifi-owned-lab:{ip}:{port}");
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 12 * 1024 * 1024;
    budget.bytes = 4 * 1024 * 1024;
    budget.storage_operations = 3;
    let mut capabilities = vec![
        RuntimeGrant::AdapterNet.as_str().into(),
        RuntimeGrant::AdapterAuth.as_str().into(),
        RuntimeGrant::ObserveStatus.as_str().into(),
        RuntimeGrant::ReadMedia.as_str().into(),
        RuntimeGrant::MediaDecode.as_str().into(),
    ];
    if output_path.is_some() {
        capabilities.push(RuntimeGrant::ObjectStage.as_str().into());
    }
    let (mut owner, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:unifi-owned-lab".into(),
            operation_id: OperationId::parse("operation:unifi-owned-lab")?,
            principal: "principal:owner".into(),
            capabilities,
            deadline: Some(TimestampNs(30_000_000_000)),
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
    let mut grants = owner
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
        .with_scope(RuntimeGrant::ReadMedia, BTreeSet::from([resource.clone()]))
        .with_scope(
            RuntimeGrant::MediaDecode,
            BTreeSet::from([resource.clone()]),
        );
    if let Some(path) = output_path {
        grants = grants.with_scope(
            RuntimeGrant::ObjectStage,
            BTreeSet::from([path.to_string_lossy().into_owned()]),
        );
    }
    owner.narrow_grants(grants)?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime context")?;
        let result = run_owned_async(&mut owner, &mut tree,
            TaskSpec { task_id: TaskId::new("task:unifi-owned-lab")?, started_at: observed(start) },
            &cx,
            async |task, cx| {
        let output: Result<String, Box<dyn Error>> = async {
        task.checkpoint_for(RuntimeGrant::AdapterNet, &resource, observed(start), &BudgetVector::ZERO)?;
        let raw = timeout(cx.now(), Duration::from_secs(5), TcpStream::connect(address)).await??;
        let local_ip=raw.local_addr()?.ip();
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
        let protocol = connection.protocol_version();
        let policy=LabAuthority { lease: &lease, check: check_auth, peer };
        let tls=client::Client::new(connection,stream);
        let plaintext=MeteredIo::with_clock(tls,clock,&resource,4096)?;
        let mut api=camera_http::Owner::new(plaintext,task,cx,clock,&policy,peer,1,&resource)?;
        api.login(&lease.secret.0,Duration::from_secs(10)).await?;
        let shape=api.status(Duration::from_secs(10)).await?;
        let (settings,serializer_fields,serializer_binding_stable) = if inspect_serializers {
            let (settings,serializers)=api.settings_serializers(Duration::from_secs(10)).await?;
            let authorize=|peer,generation| {
                cx.checkpoint().is_ok()
                    && camera_http::Authority::permits(&policy,peer,generation,camera_http::Operation::SettingsSerializers)
                    && clock.now().ok().is_some_and(|now| task.checkpoint_for(RuntimeGrant::ObserveStatus,&resource,now,&BudgetVector::ZERO).is_ok())
            };
            let fields=serializers.visit(authorize,serializer_fields)?;
            let stable=if repeat_serializers {
                let first=serializers.binding(authorize)?;
                drop(serializers);
                let (_,again)=api.settings_serializers(Duration::from_secs(10)).await?;
                let second=again.binding(authorize)?;
                Some(first==second)
            } else { None };
            (settings,Some(fields),stable)
        } else {
            (api.settings(Duration::from_secs(10)).await?,None,None)
        };
        let (controller_claim,controller_matches_route)=match settings.controller {
            camera_api::ControllerAddress::Reported(ip)=>("reported",if IpAddr::V4(ip)==local_ip {"true"} else {"false"}),
            camera_api::ControllerAddress::Unset=>("unset","unknown"),
            camera_api::ControllerAddress::Missing=>("missing","unknown"),
            camera_api::ControllerAddress::Unsupported=>("unsupported","unknown"),
        };
        let count = if three_snapshots { 3 } else { 1 };
        let mut previous_digest = None;
        let mut changed = 0_u8;
        let mut dimensions = None;
        for index in 0..count {
            if index != 0 {
                cx.checkpoint().map_err(|_| "runtime cancelled")?;
                sleep(cx.now(), Duration::from_secs(1)).await;
                cx.checkpoint().map_err(|_| "runtime cancelled")?;
            }
            let snapshot=api.snapshot(Duration::from_secs(10)).await?;
            task.checkpoint_for(RuntimeGrant::ReadMedia, &resource, clock.now()?, &BudgetVector::ZERO)?;
            task.checkpoint_for(RuntimeGrant::MediaDecode, &resource, clock.now()?, &BudgetVector::ZERO)?;
            let limits=fss_codec_mjpeg::DecodeLimits { maximum_bytes: 4*1024*1024, ..Default::default() };
            let digest=snapshot.digest().bytes();
            if previous_digest.is_some_and(|previous| previous != digest) { changed += 1; }
            previous_digest = Some(digest);
            let mut decode_budget=fss_codec_mjpeg::DecodeBudget::new(limits.luma_work_bound().min(1_500_000_000));
            let decoded=fss_codec_mjpeg::decode_luma(snapshot.bytes(),digest,fss_codec_mjpeg::ComponentInterpretation::YCbCr,limits,&mut decode_budget)?;
            let [width,height]=decoded.dimensions();
            if decoded.pixels().len() != width as usize * height as usize { return Err("decoded dimensions inconsistent".into()); }
            if dimensions.is_some_and(|previous| previous != [width, height]) { return Err("snapshot dimensions changed".into()); }
            dimensions = Some([width, height]);
            if index + 1 == count {
                if let Some(path)=output_path {
                    lease.revalidate(&policy.check)?;
                    task.checkpoint_for(RuntimeGrant::ReadMedia,&resource,clock.now()?,&BudgetVector::ZERO)?;
                    let mut cost=BudgetVector::ZERO;
                    cost.bytes=snapshot.bytes().len() as u64;
                    cost.storage_operations=3;
                    task.checkpoint_for(RuntimeGrant::ObjectStage,&path.to_string_lossy(),clock.now()?,&cost)?;
                    output::save(path,snapshot.bytes(),digest)?;
                }
            }
        }
        let [width,height]=dimensions.ok_or("no decoded snapshots")?;
        let outcome=format!("observed_pin=matched signature=verified tls={:?} login_http_status=200 status_http_status=200 settings_http_status=200 controller_address={controller_claim} controller_matches_connection_source={controller_matches_route} controller_port={:?} video_destinations={:?} serializer_fields={serializer_fields:?} serializer_binding_stable={serializer_binding_stable:?} snapshot_http_status=200 snapshots_decoded={count} adjacent_digest_changes={changed} decoded_luma={}x{} board_object={} firmware_object={} controller_object={} identity=unverified media_persisted={} runtime=asupersync transport=fss_metered",protocol,shape.controller_port,settings.video_destinations,width,height,shape.board,shape.firmware,shape.controller,output_path.is_some());
        drop(api);
        Ok(outcome)
        }.await;
        let outcome = if output.is_ok() { TaskOutcome::Success } else { TaskOutcome::Failed("authenticated snapshot probe failed".into()) };
        TaskCompletion { output, outcome, completed_at: observed(start) }
            },
        ).await?;
        result.receipt?;
        println!("{} task_receipt=completed", result.output?);
        Ok::<(), Box<dyn Error>>(())
    })
}
