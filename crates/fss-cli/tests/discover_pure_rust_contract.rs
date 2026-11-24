#![forbid(unsafe_code)]
//! Integration contract tests for pure-Rust discovery, vendor OUI/fingerprint
//! classification, zero-subprocess enforcement, and UniFi Protect adapter seams.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

use fss_core::{CaptureInterval, ClockBasis, ContentDigest, SensorId, StreamId, TimestampNs};
use fss_reference::discovery::{
    AdapterPath, AuthIngredient, Brand, CensusConfig, Confidence, HostObs, OUI_SNAPSHOT, OuiTable,
    Readiness, RtspBannerObs, Signal, UniFiDiscoveryObs, assemble_discovery_with_probes,
    classify_host, classify_host_with_evidence, dispatch, parse_proc_net_arp,
    parse_rtsp_options_response, parse_unifi_discovery_reply,
};
use fss_reference::unifi_direct::protect_live::{
    UNIFI_PROTECT_RTSPS_PORT, UniFiCaptureOrigin, UniFiProtectLimits, UniFiProtectLiveAdapter,
    UniFiProtectLiveConfig, UniFiProtectTransport,
};

fn build_unifi_v1_tlv(tlvs: &[(u8, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    for &(tag, value) in tlvs {
        body.push(tag);
        body.extend_from_slice(&(value.len() as u16).to_be_bytes());
        body.extend_from_slice(value);
    }
    let mut pkt = Vec::with_capacity(4 + body.len());
    pkt.extend_from_slice(&[1, 0]);
    pkt.extend_from_slice(&(body.len() as u16).to_be_bytes());
    pkt.extend_from_slice(&body);
    pkt
}

#[test]
fn discovery_crate_contains_zero_os_command_shell_outs() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let discovery_dir = manifest_dir.join("../fss-reference/src/discovery");
    let mut stack = vec![discovery_dir];
    let mut files_checked = 0usize;
    let forbidden = [
        concat!("Command", "::new"),
        concat!("std::process::", "Command"),
        concat!("/usr/bin/", "sudo"),
        concat!("/usr/sbin/", "arp"),
        concat!("/usr/sbin/", "netstat"),
    ];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read discovery dir") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let src = std::fs::read_to_string(&path).expect("read rs source");
            let production = src.split("#[cfg(test)]").next().unwrap_or(&src);
            for needle in forbidden {
                assert!(
                    !production.contains(needle),
                    "forbidden subprocess pattern `{needle}` in {}",
                    path.display()
                );
            }
            files_checked += 1;
        }
    }
    assert!(files_checked >= 6, "checked {files_checked} files");
}

#[test]
fn canned_owner_lan_vendor_matrix_classifies_and_dispatches_accurately() {
    let oui = OuiTable::parse_snapshot(OUI_SNAPSHOT);
    let plan = CensusConfig {
        subnets: vec!["192.168.4.0/24".to_owned()],
        workers: 4,
        tcp_timeout: Duration::from_millis(200),
    }
    .plan()
    .expect("valid /24 plan");

    // Simulate Linux `/proc/net/arp` table for non-UniFi devices (UniFi MAC
    // arrives via pure-Rust UDP-10001 TLV so we also prove macOS-style MAC enrichment!).
    let proc_arp = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.4.1      0x1         0x2         48:dd:0c:c9:ec:0d     *        eth0
192.168.4.23     0x1         0x2         80:48:2c:52:59:05     *        eth0
192.168.4.37     0x1         0x2         60:d5:61:21:4d:36     *        eth0
192.168.4.50     0x1         0x2         48:a2:e6:ca:c6:76     *        eth0
192.168.4.60     0x1         0x2         b0:d5:9d:9a:8e:c4     *        eth0
192.168.4.70     0x1         0x2         ec:71:db:11:22:33     *        eth0
192.168.4.80     0x1         0x2         00:40:8c:11:22:33     *        eth0
192.168.4.90     0x1         0x2         00:bc:99:11:22:33     *        eth0
192.168.4.95     0x1         0x2         08:ed:ed:11:22:33     *        eth0
192.168.4.243    0x1         0x2         50:3d:d1:e3:e2:07     *        eth0
";
    let neighbors = parse_proc_net_arp(proc_arp);
    assert_eq!(neighbors.len(), 10);

    // Pure-Rust UniFi G4 Instant UDP-10001 TLV reply (MAC 00:15:6d = Ubiquiti Inc in OUI snapshot).
    let g4_ip = Ipv4Addr::new(192, 168, 4, 177);
    let g4_mac: [u8; 6] = [0x00, 0x15, 0x6d, 0x12, 0x34, 0x56];
    let mut g4_addr_claim = [0u8; 10];
    g4_addr_claim[..6].copy_from_slice(&g4_mac);
    g4_addr_claim[6..].copy_from_slice(&g4_ip.octets());
    let g4_pkt = build_unifi_v1_tlv(&[
        (1, &g4_mac),
        (2, &g4_addr_claim),
        (3, b"UVC.SAV530q.v4.72.38.67"),
        (11, b"G4-Instant-Front"),
        (12, b"UVC G4 Instant"),
    ]);
    let unifi_g4 = parse_unifi_discovery_reply(g4_ip, &g4_pkt).expect("valid G4 Instant TLV");

    let open_ports = BTreeMap::from([
        (Ipv4Addr::new(192, 168, 4, 1), vec![80]),
        (Ipv4Addr::new(192, 168, 4, 23), vec![554]),
        (Ipv4Addr::new(192, 168, 4, 37), vec![443, 6668, 8888]),
        (Ipv4Addr::new(192, 168, 4, 50), vec![80, 443]),
        (Ipv4Addr::new(192, 168, 4, 60), vec![554]),
        (Ipv4Addr::new(192, 168, 4, 70), vec![80, 554]),
        (Ipv4Addr::new(192, 168, 4, 80), vec![80, 554]),
        (Ipv4Addr::new(192, 168, 4, 90), vec![80, 554, 8000]),
        (Ipv4Addr::new(192, 168, 4, 95), vec![80, 554, 37777]),
        (g4_ip, vec![443, 7442, 7447]),
        (Ipv4Addr::new(192, 168, 4, 243), vec![443, 8800]),
    ]);
    let census = plan.assemble_report(neighbors, &[g4_ip], &open_ports, &oui);

    // Non-intrusive RTSP OPTIONS banner on Axis camera and UniFi Protect port 7447.
    let axis_banner = parse_rtsp_options_response(
        Ipv4Addr::new(192, 168, 4, 80),
        554,
        b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nServer: GStreamer RTSP server\r\nWWW-Authenticate: Digest realm=\"AXIS_00408C112233\", nonce=\"abc\"\r\nPublic: OPTIONS, DESCRIBE, SETUP, PLAY\r\n\r\n",
    )
    .expect("valid Axis RTSP banner");

    let report = assemble_discovery_with_probes(
        &plan,
        census,
        &[],
        &[],
        &[],
        &[],
        &[unifi_g4],
        &[axis_banner],
    )
    .expect("assemble discovery");

    let find = |ip: &str| {
        let addr: Ipv4Addr = ip.parse().unwrap();
        report
            .candidates
            .iter()
            .find(|c| c.host.ip == addr)
            .unwrap_or_else(|| panic!("missing candidate {ip}"))
    };

    // 1. Ubiquiti UniFi G4 Instant (192.168.4.177) -> Brand::UniFiProtect (Confirmed), native adapter!
    let g4 = find("192.168.4.177");
    assert_eq!(g4.host.mac, "00:15:6d:12:34:56");
    assert_eq!(g4.host.oui_vendor.as_deref(), Some("Ubiquiti Inc"));
    assert_eq!(g4.brand.brand, Brand::UniFiProtect);
    assert_eq!(g4.brand.confidence, Confidence::Confirmed);
    assert_eq!(g4.dispatch.adapter, AdapterPath::UniFiProtect);
    assert_eq!(g4.dispatch.readiness, Readiness::NeedsIngredient);
    assert_eq!(
        g4.dispatch.missing,
        Some(AuthIngredient::UniFiProtectCredentials)
    );
    assert!(g4.brand.signals.iter().any(|s| matches!(
        s,
        Signal::UniFiDiscovery { model: Some(m), .. } if m == "UVC G4 Instant"
    )));

    // 2. TP-Link Tapo C460 (192.168.4.243) -> Brand::Tapo, NEVER EmbeddedWeb / Resideo!
    let tapo = find("192.168.4.243");
    assert_eq!(tapo.brand.brand, Brand::Tapo);
    assert_ne!(tapo.brand.brand, Brand::EmbeddedWeb);
    assert_eq!(tapo.brand.confidence, Confidence::Likely);
    assert_eq!(tapo.dispatch.adapter, AdapterPath::Tapo);
    assert_eq!(
        tapo.dispatch.missing,
        Some(AuthIngredient::TapoLocalCredentials)
    );
    assert_ne!(
        tapo.dispatch.missing,
        Some(AuthIngredient::ResideoWebCredentials)
    );

    // 3. Wyze Cam v4 (192.168.4.23, port 554 open) -> Brand::Tutk (Likely) + Standards RTSP dispatch!
    let wyze = find("192.168.4.23");
    assert_eq!(wyze.brand.brand, Brand::Tutk);
    assert_eq!(wyze.brand.confidence, Confidence::Likely);
    assert_eq!(wyze.dispatch.adapter, AdapterPath::Standards);
    // And with TUTK listener corroborated -> Brand::Tutk (Confirmed) + TutkNew!
    let wyze_tutk = classify_host(&wyze.host, &[], Some(44650));
    assert_eq!(wyze_tutk.brand, Brand::Tutk);
    assert_eq!(wyze_tutk.confidence, Confidence::Confirmed);
    assert_eq!(dispatch(&wyze_tutk).adapter, AdapterPath::TutkNew);

    // 4. AOSU (Shenzhen Glazero) -> Brand::Tuya (Likely) + TuyaAosu!
    let aosu = find("192.168.4.37");
    assert_eq!(aosu.brand.brand, Brand::Tuya);
    assert_eq!(aosu.brand.confidence, Confidence::Likely);
    assert_eq!(aosu.dispatch.adapter, AdapterPath::TuyaAosu);
    assert_eq!(aosu.dispatch.missing, Some(AuthIngredient::AosuLocalKey));

    // 5. Resideo -> Brand::EmbeddedWeb + ResideoWebCredentials!
    let resideo = find("192.168.4.50");
    assert_eq!(resideo.brand.brand, Brand::EmbeddedWeb);
    assert_eq!(resideo.brand.confidence, Confidence::Likely);
    assert_eq!(
        resideo.dispatch.missing,
        Some(AuthIngredient::ResideoWebCredentials)
    );

    // 6. Yi (Shenzhen Zowee), Reolink, Axis, Hikvision, Dahua -> Brand::Standards!
    for ip in [
        "192.168.4.60",
        "192.168.4.70",
        "192.168.4.80",
        "192.168.4.90",
        "192.168.4.95",
    ] {
        let cand = find(ip);
        assert_eq!(cand.brand.brand, Brand::Standards, "ip={ip}");
        assert!(cand.brand.confidence >= Confidence::Likely, "ip={ip}");
        assert_eq!(cand.dispatch.adapter, AdapterPath::Standards, "ip={ip}");
    }
    // Axis has live RTSP OPTIONS banner + OUI + ports -> Confirmed!
    let axis = find("192.168.4.80");
    assert_eq!(axis.brand.confidence, Confidence::Confirmed);
    assert!(axis.brand.signals.iter().any(|s| matches!(
        s,
        Signal::RtspBanner { port: 554, realm: Some(r), .. } if r == "AXIS_00408C112233"
    )));

    // 7. eero -> Brand::Infrastructure (ImportOnly/Unavailable)
    let eero = find("192.168.4.1");
    assert_eq!(eero.brand.brand, Brand::Infrastructure);
    assert_eq!(eero.dispatch.adapter, AdapterPath::ImportOnly);

    // 8. Standalone Hanwha & Owlet checks
    let hanwha = HostObs {
        ip: Ipv4Addr::new(192, 168, 4, 110),
        mac: "00:16:6c:aa:bb:cc".into(),
        oui_vendor: Some("Hanwha Vision VietNam".into()),
        open_ports: vec![80, 554],
        rtt_ms: None,
    };
    let hanwha_c = classify_host_with_evidence(
        &hanwha,
        &[],
        None,
        &[],
        None,
        &[&RtspBannerObs {
            ip: hanwha.ip,
            port: 554,
            status_code: 200,
            server: Some("Hanwha RTSP".into()),
            realm: None,
            public_methods: vec!["OPTIONS".into()],
        }],
    );
    assert_eq!(hanwha_c.brand, Brand::Standards);
    assert_eq!(hanwha_c.confidence, Confidence::Confirmed);

    let owlet = HostObs {
        ip: Ipv4Addr::new(192, 168, 4, 111),
        mac: "ac:67:84:aa:bb:cc".into(),
        oui_vendor: Some("Owlet Baby Care".into()),
        open_ports: vec![],
        rtt_ms: None,
    };
    let owlet_c = classify_host(&owlet, &[], None);
    assert_eq!(owlet_c.brand, Brand::CloudOnly);
    assert_eq!(dispatch(&owlet_c).adapter, AdapterPath::ImportOnly);
}

#[test]
fn unifi_protect_live_adapter_facade_enforces_local_scope_and_packages_capsules() {
    let dir = std::env::temp_dir().join(format!(
        "fss-cli-unifi-protect-contract-{}",
        std::process::id()
    ));
    let authority = fss_core::ContextAuthority::new_root(fss_core::RootAuthoritySpec {
        trace_id: "trace:unifi-contract".into(),
        operation_id: fss_core::OperationId::parse("operation:unifi-contract").unwrap(),
        principal: "principal:owner".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: fss_core::BudgetVector::builder()
            .bytes(8 * 1024 * 1024)
            .storage_operations(1024)
            .build()
            .unwrap(),
        privacy_scope: "privacy:owner".into(),
        retention_scope: "retention:owner".into(),
        anchor_universe: ContentDigest::sha256(b"site:owner"),
        generation: 1,
    })
    .unwrap();
    let cx = fss_reference::ReplayCx::from_context_authority(&authority, dir).unwrap();

    let mut adapter = UniFiProtectLiveAdapter::new(UniFiProtectLiveConfig {
        sensor_id: SensorId::parse("sensor:unifi-g4-instant").unwrap(),
        stream_id: StreamId::parse("stream:unifi-g4-rtsps").unwrap(),
        transport: UniFiProtectTransport::ProtectRtsp {
            host: Ipv4Addr::new(192, 168, 4, 177),
            port: UNIFI_PROTECT_RTSPS_PORT,
            path: "/high".into(),
            tls: true,
        },
        resource: "unifi-protect:192.168.4.177".into(),
        limits: UniFiProtectLimits::default(),
    })
    .expect("valid local UniFi Protect adapter");

    let payload = b"\x00\x00\x00\x01\x67\x64\x00\x28";
    let obs = adapter
        .package_rtsp_segment(
            payload,
            1,
            CaptureInterval {
                earliest: TimestampNs(100),
                latest: TimestampNs(200),
            },
            TimestampNs(250),
            ClockBasis::HostMonotonic,
            false,
            &cx,
        )
        .expect("packaged UniFi Protect RTSPS segment");
    assert_eq!(obs.origin, UniFiCaptureOrigin::ProtectRtspSegment);
    assert_eq!(obs.endpoint_uri, "rtsps://192.168.4.177:7441/high");
    assert_eq!(obs.capsule.source_digest, ContentDigest::sha256(payload));
    cx.drain_and_finalize();

    // Ensure UniFiDiscoveryObs public type is constructible and usable across crate boundary.
    let obs_probe = UniFiDiscoveryObs {
        ip: Ipv4Addr::new(192, 168, 4, 177),
        mac: Some("00:15:6d:12:34:56".into()),
        model: Some("UVC G4 Instant".into()),
        firmware: Some("UVC.SAV530q.v4.72.38.67".into()),
        hostname: Some("G4-Instant".into()),
        source_advertised: true,
        is_camera_platform: true,
    };
    assert!(obs_probe.is_camera_or_protect());
}
