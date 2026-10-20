#![forbid(unsafe_code)]
//! Protocol replies become durable enrolled network evidence without inventing media health.
use fss_core::{
    BudgetVector, CanonicalEncoder, ContentDigest, ContextAuthority, OperationId,
    RootAuthoritySpec, SensorId,
};
use fss_reference::agent_orient::{OrientLimits, read_deployment};
use fss_reference::discovery::retained_liveness::{
    DeviceEnrollment, LIVENESS_ENROLLMENT_DOMAIN, LIVENESS_RECORD_DOMAIN,
    LIVENESS_RECORD_DOMAIN_V2, LivenessError, RetainedSensorLiveness, SensorLivenessRecord,
    has_fresh_sighting, retain_discovery_sweep, retain_discovery_window,
};
use fss_reference::discovery::watchdog::{DeviceClass, WatchOfflineReason, WatchState};
use fss_reference::discovery::{
    CensusConfig, CensusReport, DeviceCandidate, DiscoverReport, DiscoveryResponse,
    DiscoverySighting, HostObs, MdnsAnswer, MdnsObservation, assemble_discovery, classify_host,
    dispatch,
};
use fss_reference::{ReferenceDeployment, ReplayCx};
use std::error::Error;
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

type Test<T = ()> = Result<T, Box<dyn Error>>;
const SITE: &str = "site:protocol-liveness";

struct Fixture {
    directory: PathBuf,
    root: PathBuf,
    cx: ReplayCx,
}
impl Fixture {
    fn new(label: &str) -> Test<Self> {
        let mut directory = None;
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-protocol-liveness-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    directory = Some(path);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        let directory = directory.ok_or("temporary directory capacity exhausted")?;
        let root = directory.join("deployment");
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:protocol-liveness-test".into(),
            operation_id: OperationId::parse("operation:protocol-liveness-test")?,
            principal: "principal:protocol-liveness-test".into(),
            capabilities: vec!["ADP-REPLAY-001".into()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(16 * 1024 * 1024)
                .storage_operations(8192)
                .build()?,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?;
        let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
        drop(ReferenceDeployment::open(&root, SITE, &cx)?);
        Ok(Self {
            directory,
            root,
            cx,
        })
    }
    fn inventory(&self) -> Test<Vec<RetainedSensorLiveness>> {
        Ok(read_deployment(&self.root, &OrientLimits::default())?.sensor_liveness)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.cx.drain_and_finalize();
        let _ = fs::remove_dir_all(&self.directory);
    }
}
fn endpoint(last: u8) -> Ipv4Addr {
    Ipv4Addr::new(192, 168, 4, last)
}
fn enrollment(last: u8, sensor: &str) -> Test<DeviceEnrollment> {
    Ok(DeviceEnrollment::with_thresholds(
        endpoint(last),
        SensorId::parse(sensor)?,
        DeviceClass::Onvif,
        (10, 20),
    )?)
}
fn report(last: u8, kinds: &[DiscoverySighting]) -> DiscoverReport {
    DiscoverReport {
        current_responses: kinds
            .iter()
            .map(|kind| DiscoveryResponse {
                endpoint: endpoint(last),
                kind: *kind,
            })
            .collect(),
        ..DiscoverReport::default()
    }
}
fn legacy_tcp_report(last: u8) -> DiscoverReport {
    let host = HostObs {
        ip: endpoint(last),
        mac: "00:11:22:33:44:55".into(),
        oui_vendor: None,
        open_ports: vec![554],
        rtt_ms: None,
    };
    let brand = classify_host(&host, &[], None);
    let dispatch = dispatch(&brand);
    DiscoverReport {
        candidates: vec![DeviceCandidate {
            host,
            brand,
            dispatch,
        }],
        ..DiscoverReport::default()
    }
}

// Frozen v1 field order: no trailing response count existed in published v1 bytes.
fn legacy_fixture() -> Vec<u8> {
    let mut e = CanonicalEncoder::new();
    e.text(LIVENESS_RECORD_DOMAIN);
    e.text(SITE);
    e.text(LIVENESS_ENROLLMENT_DOMAIN);
    e.text("192.168.4.10");
    e.text("sensor:front");
    e.text("onvif");
    e.u64(10);
    e.u64(20);
    e.u64(1); // first generation
    e.bool(false); // no predecessor
    e.u64(100); // sweep start
    e.u64(100); // completion
    e.bool(true);
    e.u64(100); // earliest response
    e.bool(true);
    e.u64(100); // latest response
    e.bool(false); // no prior unobserved evaluation
    e.u64(1);
    e.u32(554); // registered TCP response
    e.u64(0); // no beacons
    e.finish()
}
fn v2_fixture(kinds: &[&str]) -> Test<Vec<u8>> {
    let mut bytes = legacy_fixture();
    let offset = bytes
        .windows(LIVENESS_RECORD_DOMAIN.len())
        .position(|part| part == LIVENESS_RECORD_DOMAIN.as_bytes())
        .ok_or("legacy fixture is missing its domain")?;
    bytes[offset..offset + LIVENESS_RECORD_DOMAIN_V2.len()]
        .copy_from_slice(LIVENESS_RECORD_DOMAIN_V2.as_bytes());
    let mut extra = CanonicalEncoder::new();
    extra.u64(kinds.len() as u64);
    for kind in kinds {
        extra.text(kind);
    }
    bytes.extend(extra.finish());
    Ok(bytes)
}

#[test]
fn existing_v1_bytes_identity_and_cold_reopen_are_preserved() -> Test {
    let bytes = legacy_fixture();
    let decoded = SensorLivenessRecord::from_bytes(&bytes)?;
    assert!(decoded.protocol_responses().is_empty());
    assert_eq!(decoded.to_bytes(), bytes);
    assert_eq!(decoded.digest(), ContentDigest::sha256(&bytes));
    let fixture = Fixture::new("v1")?;
    let binding = vec![enrollment(10, "sensor:front")?];
    let mut deployment = ReferenceDeployment::reopen(&fixture.root, SITE, &fixture.cx)?;
    let retained = retain_discovery_sweep(
        &mut deployment,
        &binding,
        &legacy_tcp_report(10),
        100,
        &fixture.cx,
    )?;
    assert_eq!(retained[0].record.to_bytes(), bytes);
    drop(deployment);
    assert_eq!(fixture.inventory()?, retained);
    let mut deployment = ReferenceDeployment::reopen(&fixture.root, SITE, &fixture.cx)?;
    let before = deployment.ledger().batches().len();
    assert_eq!(
        retain_discovery_sweep(
            &mut deployment,
            &binding,
            &legacy_tcp_report(10),
            100,
            &fixture.cx
        )?,
        retained
    );
    assert_eq!(deployment.ledger().batches().len(), before);
    Ok(())
}

#[test]
fn mdns_only_health_survives_outage_restart_and_wsdiscovery_return() -> Test {
    let fixture = Fixture::new("restart")?;
    let binding = vec![enrollment(10, "sensor:front")?];
    let mut deployment = ReferenceDeployment::reopen(&fixture.root, SITE, &fixture.cx)?;
    let mdns = report(10, &[DiscoverySighting::MdnsResponse]);
    assert!(mdns.candidates.is_empty());
    assert!(mdns.beacons.is_empty());
    let live = retain_discovery_sweep(&mut deployment, &binding, &mdns, 100, &fixture.cx)?;
    assert!(live[0].record.fresh_sighting());
    assert_eq!(
        live[0].record.protocol_responses(),
        &[DiscoverySighting::MdnsResponse]
    );
    assert_eq!(live[0].record.state(), WatchState::Observable);
    assert_eq!(
        SensorLivenessRecord::from_bytes(&live[0].record.to_bytes())?,
        live[0].record
    );
    let absent = DiscoverReport::default();
    let silent = retain_discovery_sweep(&mut deployment, &binding, &absent, 110, &fixture.cx)?;
    assert_eq!(
        silent[0].record.state(),
        WatchState::Silent { silent_for_ns: 10 }
    );
    let dark = retain_discovery_sweep(&mut deployment, &binding, &absent, 120, &fixture.cx)?;
    assert_eq!(
        dark[0].record.state(),
        WatchState::NotObservable {
            reason: WatchOfflineReason::SilentBeyondThreshold
        }
    );
    assert!(dark[0].record.protocol_responses().is_empty());
    drop(deployment);
    assert_eq!(fixture.inventory()?, dark);
    let mut deployment = ReferenceDeployment::reopen(&fixture.root, SITE, &fixture.cx)?;
    let returned = retain_discovery_sweep(
        &mut deployment,
        &binding,
        &report(10, &[DiscoverySighting::WsdResponse]),
        130,
        &fixture.cx,
    )?;
    assert_eq!(returned[0].record.state(), WatchState::Observable);
    assert_eq!(returned[0].record.last_seen_ns(), Some(130));
    assert_eq!(returned[0].record.last_unobserved_ns(), Some(120));
    assert_eq!(
        returned[0].record.protocol_responses(),
        &[DiscoverySighting::WsdResponse]
    );
    assert_eq!(
        returned[0].record.previous_digest(),
        Some(dark[0].record.digest())
    );
    assert_eq!(returned[0].record.generation(), 4);
    drop(deployment);
    assert_eq!(fixture.inventory()?, returned);
    Ok(())
}

#[test]
fn protocol_retry_is_exact_and_cannot_relabel_a_previous_response() -> Test {
    let fixture = Fixture::new("retry")?;
    let binding = vec![enrollment(10, "sensor:front")?];
    let mut deployment = ReferenceDeployment::reopen(&fixture.root, SITE, &fixture.cx)?;
    let original = report(
        10,
        &[
            DiscoverySighting::SsdpResponse,
            DiscoverySighting::MdnsResponse,
        ],
    );
    let retained = retain_discovery_sweep(&mut deployment, &binding, &original, 100, &fixture.cx)?;
    let before = deployment.ledger().batches().len();
    let reordered = report(
        10,
        &[
            DiscoverySighting::MdnsResponse,
            DiscoverySighting::SsdpResponse,
            DiscoverySighting::MdnsResponse,
        ],
    );
    assert_eq!(
        retain_discovery_sweep(&mut deployment, &binding, &reordered, 100, &fixture.cx)?,
        retained
    );
    for changed in [
        report(10, &[DiscoverySighting::WsdResponse]),
        DiscoverReport::default(),
    ] {
        assert!(matches!(
            retain_discovery_sweep(&mut deployment, &binding, &changed, 100, &fixture.cx),
            Err(LivenessError::ClockOrReplayConflict)
        ));
        assert_eq!(deployment.ledger().batches().len(), before);
    }
    Ok(())
}

#[test]
fn sleep_proxy_advertisement_keeps_the_camera_unobserved_in_retained_history() -> Test {
    let fixture = Fixture::new("sleep-proxy")?;
    let plan = CensusConfig {
        subnets: vec!["192.168.4.0/24".into()],
        workers: 1,
        tcp_timeout: Duration::from_millis(100),
    }
    .plan()?;
    let census = CensusReport {
        hosts: vec![],
        ping_targets: plan.ping_targets.len(),
        responders: vec![],
    };
    let packet = MdnsObservation {
        responder: endpoint(2),
        answers: vec![
            MdnsAnswer {
                name: "Camera._rtsp._tcp.local".into(),
                rr_type: 33,
                ttl: 120,
                rdata: "camera.local".into(),
                srv_port: Some(554),
            },
            MdnsAnswer {
                name: "camera.local".into(),
                rr_type: 1,
                ttl: 120,
                rdata: endpoint(44).to_string(),
                srv_port: None,
            },
        ],
    };
    let report = assemble_discovery(&plan, census, &[], &[packet], &[], &[])?;
    assert!(has_fresh_sighting(&report, endpoint(2)));
    assert!(!has_fresh_sighting(&report, endpoint(44)));
    let bindings = vec![
        enrollment(2, "sensor:proxy")?,
        enrollment(44, "sensor:camera")?,
    ];
    let mut deployment = ReferenceDeployment::reopen(&fixture.root, SITE, &fixture.cx)?;
    let retained = retain_discovery_sweep(&mut deployment, &bindings, &report, 100, &fixture.cx)?;
    let proxy = retained
        .iter()
        .find(|row| row.record.enrollment().endpoint() == endpoint(2))
        .ok_or("proxy observation is missing")?;
    let camera = retained
        .iter()
        .find(|row| row.record.enrollment().endpoint() == endpoint(44))
        .ok_or("advertised camera observation is missing")?;
    assert_eq!(
        proxy.record.protocol_responses(),
        &[DiscoverySighting::MdnsResponse]
    );
    assert_eq!(proxy.record.state(), WatchState::Observable);
    assert!(camera.record.protocol_responses().is_empty());
    assert_eq!(camera.record.last_seen_ns(), None);
    assert_eq!(
        camera.record.state(),
        WatchState::NotObservable {
            reason: WatchOfflineReason::NeverObserved
        }
    );
    drop(deployment);
    // Publication and cold inventory have different ordering. Compare the
    // complete records, including roots and anchors, by enrolled endpoint.
    let mut reopened = fixture.inventory()?;
    let mut retained = retained;
    reopened.sort_by_key(|row| row.record.enrollment().endpoint());
    retained.sort_by_key(|row| row.record.enrollment().endpoint());
    assert_eq!(reopened, retained);
    Ok(())
}

#[test]
fn v2_decoder_requires_known_distinct_ordered_nonempty_response_kinds() -> Test {
    let valid = v2_fixture(&[
        "census_response",
        "mdns_response",
        "ssdp_response",
        "tuya_beacon",
        "wsd_response",
    ])?;
    let parsed = SensorLivenessRecord::from_bytes(&valid)?;
    assert_eq!(parsed.protocol_responses().len(), DiscoverySighting::COUNT);
    assert_eq!(parsed.to_bytes(), valid);
    for end in 0..valid.len() {
        assert!(SensorLivenessRecord::from_bytes(&valid[..end]).is_err());
    }
    for invalid in [
        vec![],
        vec!["not_a_protocol"],
        vec!["mdns_response", "mdns_response"],
        vec!["wsd_response", "mdns_response"],
        vec!["mdns_response"; 6],
    ] {
        assert!(
            SensorLivenessRecord::from_bytes(&v2_fixture(&invalid)?).is_err(),
            "{invalid:?}"
        );
    }
    let mut v1_with_unversioned_extension = legacy_fixture();
    v1_with_unversioned_extension.extend_from_slice(&0u64.to_be_bytes());
    assert!(SensorLivenessRecord::from_bytes(&v1_with_unversioned_extension).is_err());
    Ok(())
}

#[test]
fn protocol_receipts_use_the_full_sweep_window_for_conservative_aging() -> Test {
    let fixture = Fixture::new("long-window")?;
    let binding = vec![enrollment(10, "sensor:front")?];
    let mut deployment = ReferenceDeployment::reopen(&fixture.root, SITE, &fixture.cx)?;
    let retained = retain_discovery_window(
        &mut deployment,
        &binding,
        &report(10, &[DiscoverySighting::CensusResponse]),
        100,
        130,
        &fixture.cx,
    )?;
    let record = &retained[0].record;
    assert_eq!(record.last_seen_ns(), Some(100));
    assert_eq!(record.last_response_latest_ns(), Some(130));
    assert_eq!(record.fresh_until_ns(), Some(110));
    assert_eq!(record.last_unobserved_ns(), Some(130));
    assert_eq!(
        record.state(),
        WatchState::NotObservable {
            reason: WatchOfflineReason::SilentBeyondThreshold
        }
    );
    assert_eq!(
        record.protocol_responses(),
        &[DiscoverySighting::CensusResponse]
    );
    Ok(())
}

#[test]
fn oversized_protocol_report_is_refused_before_any_publication() -> Test {
    let fixture = Fixture::new("bounds")?;
    let binding = vec![enrollment(10, "sensor:front")?];
    let mut deployment = ReferenceDeployment::reopen(&fixture.root, SITE, &fixture.cx)?;
    let before = deployment.ledger().batches().len();
    let report = DiscoverReport {
        current_responses: vec![
            DiscoveryResponse {
                endpoint: endpoint(10),
                kind: DiscoverySighting::MdnsResponse
            };
            fss_reference::discovery::census::MAX_SUBNET_HOSTS as usize
                * DiscoverySighting::COUNT
                + 1
        ],
        ..DiscoverReport::default()
    };
    assert!(matches!(
        retain_discovery_sweep(&mut deployment, &binding, &report, 100, &fixture.cx),
        Err(LivenessError::Limit)
    ));
    assert_eq!(deployment.ledger().batches().len(), before);
    Ok(())
}
