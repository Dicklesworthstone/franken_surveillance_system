#![forbid(unsafe_code)]
//! Service-fingerprint heuristics → typed brand confidence (DISC-5,
//! fss-yodhk.5).
//!
//! Combines census [`HostObs`] rows, Tuya beacon observations, UniFi UDP-10001
//! TLV responses, non-intrusive RTSP `OPTIONS *` banner/realm peeks, and
//! standards-probe results into [`BrandConfidence`] with explicit typed
//! evidence handles — never a bare guess. Every classification names the exact
//! signals that produced it; a host with no supporting signal is `Unknown`.

use std::collections::BTreeSet;

use crate::discovery::census::HostObs;
use crate::discovery::probes::{RtspBannerObs, UniFiDiscoveryObs};
use crate::discovery::tuya_beacon::TuyaBeaconObs;

/// UniFi Protect / direct camera signature TCP ports.
const UNIFI_PROTECT_PORTS: [u16; 5] = [7080, 7441, 7442, 7447, 7550];

/// One typed classification signal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Signal {
    /// OUI vendor string matched (evidence: the vendor string).
    OuiVendor(String),
    /// TCP port-set signature matched (evidence: the open ports).
    PortSignature(Vec<u16>),
    /// A Tuya beacon arrived from this host (evidence: cmd name).
    TuyaBeacon(&'static str),
    /// LAA/private MAC — OUI classification inapplicable.
    LocallyAdministeredMac,
    /// The host ANSWERED a credential-less TUTK NEW-protocol discovery
    /// probe (any response — even auth-failing — proves a live 0xCC51
    /// listener; evidence: responder port).
    TutkListener(u16),
    /// A camera service advertised by an attributed standards response.
    AdvertisedService(CameraService),
    /// Ubiquiti v1 UDP-10001 TLV discovery response from this host.
    UniFiDiscovery {
        /// Untrusted model/platform claim from TLV 12/21/20, if present.
        model: Option<String>,
        /// Untrusted firmware claim from TLV 3, if present.
        firmware: Option<String>,
    },
    /// Non-intrusive RTSP `OPTIONS *` banner/realm observation.
    RtspBanner {
        /// TCP port that answered RTSP `OPTIONS *`.
        port: u16,
        /// Sanitized `Server:` header, if present.
        server: Option<String>,
        /// Sanitized `WWW-Authenticate` Digest/Basic `realm`, if present.
        realm: Option<String>,
    },
}

/// Camera-relevant service claims. Advertising a service proves neither device
/// identity nor ONVIF conformance, and never grants permission to open a stream.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CameraService {
    /// ONVIF network video transmitter or DNS-SD service.
    Onvif,
    /// DNS-SD RTSP service.
    Rtsp,
    /// Axis video DNS-SD service.
    AxisVideo,
}

impl CameraService {
    /// Stable report spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Onvif => "onvif",
            Self::Rtsp => "rtsp",
            Self::AxisVideo => "axis_video",
        }
    }
}

/// Brand hypothesis with confidence and evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrandConfidence {
    /// Classified brand family.
    pub brand: Brand,
    /// Confidence level (typed, never a score).
    pub confidence: Confidence,
    /// The signals that produced this classification (evidence handles).
    pub signals: Vec<Signal>,
}

/// Camera/adapter brand families reachable by fingerprinting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Brand {
    /// Ubiquiti UniFi Protect camera / NVR (native pure-Rust `unifi_direct` + RTSP/RTSPS).
    UniFiProtect,
    /// TP-Link Tapo camera (Tapo local credentials / ONVIF+RTSP / DS-JSON).
    Tapo,
    /// TUTK/IOTC NEW protocol (Wyze-class); adapter ADP-WYZE-V4-LAB-001 path (or RTSP when 554 open).
    Tutk,
    /// Tuya-based (AOSU-class homebase/cams); ADP-AOSU-P1MAX-LAB-001 path.
    Tuya,
    /// Embedded web camera (Resideo/Honeywell-class; Digest lighttpd).
    EmbeddedWeb,
    /// Standards path (RTSP/ONVIF responder: Yi, Reolink, Hikvision, Dahua, Axis, Hanwha, etc.).
    Standards,
    /// Cloud-only accessory with no local service surface (Govee/Owlet-class).
    CloudOnly,
    /// Infrastructure (routers, speakers, switches/APs — not camera candidates).
    Infrastructure,
    /// Not classified: no supporting signal.
    Unknown,
}

/// Typed confidence — never a bare number.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Confidence {
    /// Single weak signal.
    Possible,
    /// One decisive/live signal or two independent weak signals.
    Likely,
    /// Multiple independent signals agree including a live protocol proof.
    Confirmed,
}

/// Classifies one host against the fingerprint rules.
#[must_use]
pub fn classify_host(
    host: &HostObs,
    beacons_from_host: &[&TuyaBeaconObs],
    tutk_listener_port: Option<u16>,
) -> BrandConfidence {
    classify_host_with_evidence(host, beacons_from_host, tutk_listener_port, &[], None, &[])
}

/// Combines host metadata with source-attributed camera service claims.
/// Repeated advertisements are not independent corroboration: even several
/// advertised protocols remain a `Likely` candidate until separately verified.
#[must_use]
pub fn classify_host_with_services(
    host: &HostObs,
    beacons_from_host: &[&TuyaBeaconObs],
    services: &[CameraService],
) -> BrandConfidence {
    classify_host_with_evidence(host, beacons_from_host, None, services, None, &[])
}

/// Full pure-Rust classification combining census host metadata, Tuya beacons,
/// TUTK listener responses, attributed standards services, UniFi UDP-10001 TLV
/// observations, and non-intrusive RTSP `OPTIONS *` banners.
#[must_use]
pub fn classify_host_with_evidence(
    host: &HostObs,
    beacons_from_host: &[&TuyaBeaconObs],
    tutk_listener_port: Option<u16>,
    services: &[CameraService],
    unifi: Option<&UniFiDiscoveryObs>,
    rtsp_banners: &[&RtspBannerObs],
) -> BrandConfidence {
    let mut signals = Vec::new();

    // 1. LAA check first: locally administered bit set → OUI inapplicable.
    let is_laa = host
        .mac
        .split(':')
        .next()
        .and_then(|b| u8::from_str_radix(b, 16).ok())
        .is_some_and(|b| b & 0x02 != 0);
    if is_laa {
        signals.push(Signal::LocallyAdministeredMac);
    }

    // 2. TUTK listener corroboration (credential-less probe answered).
    if let Some(port) = tutk_listener_port {
        signals.push(Signal::TutkListener(port));
    }

    // 3. Tuya beacon with verified integrity: decisive.
    if let Some(b) = beacons_from_host
        .iter()
        .find(|beacon| beacon.integrity_verified())
    {
        signals.push(Signal::TuyaBeacon(b.cmd_name));
        return BrandConfidence {
            brand: Brand::Tuya,
            confidence: Confidence::Confirmed,
            signals,
        };
    }

    // 4. OUI vendor signal (ignored for LAA MACs).
    let vendor = if is_laa {
        ""
    } else {
        host.oui_vendor.as_deref().unwrap_or("")
    };
    let oui_brand = classify_oui_vendor(vendor);
    if oui_brand.is_some() {
        signals.push(Signal::OuiVendor(vendor.to_owned()));
    }

    // 5. UniFi UDP-10001 TLV observation.
    let mut unifi_brand: Option<Brand> = None;
    if let Some(obs) = unifi {
        signals.push(Signal::UniFiDiscovery {
            model: obs.model.clone(),
            firmware: obs.firmware.clone(),
        });
        let has_protect_port = host
            .open_ports
            .iter()
            .any(|p| UNIFI_PROTECT_PORTS.contains(p));
        unifi_brand = if obs.is_camera_or_protect() || has_protect_port {
            Some(Brand::UniFiProtect)
        } else {
            Some(Brand::Infrastructure)
        };
    }

    // 6. Non-intrusive RTSP OPTIONS banner/realm observations.
    let mut rtsp_brand: Option<Brand> = None;
    for banner in rtsp_banners {
        signals.push(Signal::RtspBanner {
            port: banner.port,
            server: banner.server.clone(),
            realm: banner.realm.clone(),
        });
        let inferred = classify_rtsp_banner(banner);
        if rtsp_brand.is_none() || inferred != Brand::Standards {
            rtsp_brand = Some(inferred);
        }
    }

    // 7. Open TCP port-set signature signal (pushed once).
    let open = host.open_ports.clone();
    let port_brand = classify_open_ports(&open, oui_brand.as_ref());
    if !open.is_empty() {
        signals.push(Signal::PortSignature(open));
    }

    // 8. Source-attributed standards service claims (deduplicated).
    let unique_services: BTreeSet<CameraService> = services.iter().copied().collect();
    for service in &unique_services {
        signals.push(Signal::AdvertisedService(*service));
    }

    // 9. Combine independent brand hypotheses honestly.
    let brand = resolve_brand(
        oui_brand,
        port_brand,
        unifi_brand,
        rtsp_brand,
        tutk_listener_port.is_some(),
        !unique_services.is_empty(),
    );

    // 10. Compute typed confidence from independent evidence categories.
    let confidence = compute_confidence(&brand, &signals, !unique_services.is_empty());

    BrandConfidence {
        brand,
        confidence,
        signals,
    }
}

fn classify_oui_vendor(vendor: &str) -> Option<Brand> {
    if vendor.is_empty() {
        return None;
    }
    let v = vendor.to_ascii_lowercase();
    if v.contains("ubiquiti") {
        Some(Brand::UniFiProtect)
    } else if v.contains("tp-link") {
        // TP-Link Tapo cameras are never Resideo/EmbeddedWeb.
        Some(Brand::Tapo)
    } else if v.contains("wyze labs") {
        Some(Brand::Tutk)
    } else if v.contains("shenzhen glazero") || v.contains("tuya") {
        Some(Brand::Tuya)
    } else if v.contains("resideo") || v.contains("honeywell") {
        Some(Brand::EmbeddedWeb)
    } else if v.contains("shenzhen zowee")
        || v.contains("reolink")
        || v.contains("hikvision")
        || v.contains("dahua")
        || v.contains("axis communications")
        || v.contains("hanwha")
    {
        Some(Brand::Standards)
    } else if v.contains("shenzhen intellirocks") || v.contains("owlet") {
        Some(Brand::CloudOnly)
    } else if v.contains("eero") || v.contains("sonos") || v.contains("tesla") {
        Some(Brand::Infrastructure)
    } else {
        None
    }
}

fn classify_open_ports(open: &[u16], oui_brand: Option<&Brand>) -> Option<Brand> {
    if open.is_empty() {
        return None;
    }
    if open.iter().any(|p| UNIFI_PROTECT_PORTS.contains(p)) {
        return Some(Brand::UniFiProtect);
    }
    if open.contains(&6668) && open.contains(&8888) {
        return Some(Brand::Tuya);
    }
    // TP-Link Tapo camera port profile: HTTPS (443) + local Tapo control (8800),
    // or Tapo ONVIF port (2020) paired with HTTPS/RTSP/8800.
    if (open.contains(&443) && open.contains(&8800))
        || (open.contains(&2020)
            && (open.contains(&443) || open.contains(&554) || open.contains(&8800)))
    {
        return Some(Brand::Tapo);
    }
    // Wyze cameras running RTSP firmware/bridge expose port 554 while keeping
    // the Wyze OUI family — do not fabricate a brand conflict.
    if matches!(oui_brand, Some(Brand::Tutk)) && (open.contains(&554) || open.contains(&8554)) {
        return Some(Brand::Tutk);
    }
    // Standards / ONVIF / RTSP / vendor-standard NVR ports.
    if open.contains(&554)
        || open.contains(&8554)
        || open.contains(&10554)
        || open.contains(&8899)
        || open.contains(&34567)
        || open.contains(&37777)
    {
        return match oui_brand {
            Some(Brand::Tapo) => Some(Brand::Tapo),
            Some(Brand::UniFiProtect) => Some(Brand::UniFiProtect),
            _ => Some(Brand::Standards),
        };
    }
    None
}

fn classify_rtsp_banner(banner: &RtspBannerObs) -> Brand {
    let server = banner.server.as_deref().unwrap_or("").to_ascii_lowercase();
    let realm = banner.realm.as_deref().unwrap_or("").to_ascii_lowercase();
    if banner.port == 7447
        || server.contains("ubiquiti")
        || server.contains("unifi")
        || server.contains("ubnt")
        || server.contains("protect")
        || realm.contains("ubnt")
        || realm.contains("unifi")
        || realm.contains("protect")
    {
        Brand::UniFiProtect
    } else if server.contains("tapo")
        || server.contains("tp-link")
        || realm.contains("tapo")
        || realm.contains("tp-link")
    {
        Brand::Tapo
    } else {
        Brand::Standards
    }
}

fn resolve_brand(
    oui_brand: Option<Brand>,
    port_brand: Option<Brand>,
    unifi_brand: Option<Brand>,
    rtsp_brand: Option<Brand>,
    has_tutk_listener: bool,
    has_advertised_service: bool,
) -> Brand {
    // Live UniFi UDP-10001 TLV response directly identifies the Ubiquiti family
    // (camera/Protect vs AP/switch infrastructure).
    if let Some(ub) = unifi_brand {
        return ub;
    }
    // Live TUTK listener proves TUTK family when not contradicted by a different
    // specific camera vendor.
    if has_tutk_listener && matches!(oui_brand, None | Some(Brand::Tutk)) {
        return Brand::Tutk;
    }

    // Combine OUI and port-set signatures honestly.
    let base = match (&oui_brand, &port_brand) {
        (Some(a), Some(b)) if a == b => Some(a.clone()),
        (Some(a), None) | (None, Some(a)) => Some(a.clone()),
        // Specific vendor OUI + generic RTSP/Standards port keeps the specific vendor.
        (Some(a), Some(Brand::Standards))
            if matches!(a, Brand::UniFiProtect | Brand::Tapo | Brand::Tutk) =>
        {
            Some(a.clone())
        }
        (Some(_), Some(_)) => None, // true conflict → Unknown (honest)
        (None, None) => None,
    };

    // Apply live RTSP banner evidence.
    let after_rtsp = match (base, rtsp_brand) {
        (None, Some(rb)) => Some(rb),
        (Some(Brand::Standards), Some(rb)) => Some(rb),
        // Specific camera vendor with a generic Standards RTSP banner preserves
        // the specific vendor identity (e.g. Tapo/Wyze/UniFi speaking RTSP).
        (Some(existing), Some(Brand::Standards)) => Some(existing),
        (Some(existing), Some(rb)) if existing == rb => Some(existing),
        (Some(_), Some(rb)) => Some(rb),
        (existing, None) => existing,
    };

    // Apply attributed mDNS/WS-Discovery standards service advertisements.
    if has_advertised_service {
        match after_rtsp {
            None
            | Some(Brand::Unknown | Brand::Standards | Brand::Infrastructure | Brand::CloudOnly) => {
                return Brand::Standards;
            }
            Some(specific_camera) => return specific_camera,
        }
    }

    after_rtsp.unwrap_or(Brand::Unknown)
}

fn compute_confidence(
    brand: &Brand,
    signals: &[Signal],
    has_advertised_service: bool,
) -> Confidence {
    if *brand == Brand::Unknown {
        return Confidence::Possible;
    }
    let has_oui = signals.iter().any(|s| matches!(s, Signal::OuiVendor(_)));
    let has_ports = signals
        .iter()
        .any(|s| matches!(s, Signal::PortSignature(_)));
    let has_tutk = signals.iter().any(|s| matches!(s, Signal::TutkListener(_)));
    let has_unifi = signals
        .iter()
        .any(|s| matches!(s, Signal::UniFiDiscovery { .. }));
    let has_rtsp = signals
        .iter()
        .any(|s| matches!(s, Signal::RtspBanner { .. }));
    let has_tuya_beacon = signals.iter().any(|s| matches!(s, Signal::TuyaBeacon(_)));

    let live_protocol_proof = has_tutk || has_unifi || has_rtsp || has_tuya_beacon;
    let categories = usize::from(has_oui)
        + usize::from(has_ports)
        + usize::from(has_tutk)
        + usize::from(has_unifi)
        + usize::from(has_rtsp)
        + usize::from(has_tuya_beacon)
        + usize::from(has_advertised_service);

    if has_tuya_beacon || (live_protocol_proof && categories >= 2) {
        Confidence::Confirmed
    } else if categories >= 2 || live_protocol_proof || has_advertised_service {
        Confidence::Likely
    } else {
        Confidence::Possible
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(ip: &str, mac: &str, vendor: Option<&str>, ports: &[u16]) -> HostObs {
        HostObs {
            ip: ip.parse().unwrap(),
            mac: mac.to_owned(),
            oui_vendor: vendor.map(str::to_owned),
            open_ports: ports.to_vec(),
            rtt_ms: None,
        }
    }

    #[test]
    fn vendor_table_covers_the_owner_families() {
        let cases = [
            ("74:ac:b9:11:22:33", "Ubiquiti Inc", Brand::UniFiProtect),
            (
                "60:d5:61:21:4d:36",
                "Shenzhen Glazero Technology Co., Ltd.",
                Brand::Tuya,
            ),
            ("50:3d:d1:e3:e2:07", "TP-Link Systems Inc.", Brand::Tapo),
            (
                "b0:d5:9d:9a:8e:c4",
                "Shenzhen Zowee Technology Co., Ltd",
                Brand::Standards,
            ),
            (
                "d4:ad:fc:4d:05:ed",
                "Shenzhen Intellirocks Tech. Co. Ltd.",
                Brand::CloudOnly,
            ),
            (
                "ec:71:db:00:00:01",
                "Reolink Innovation Limited",
                Brand::Standards,
            ),
            (
                "00:40:8c:11:22:33",
                "Axis Communications AB",
                Brand::Standards,
            ),
            (
                "00:bc:99:11:22:33",
                "Hangzhou Hikvision Digital Technology Co.,Ltd.",
                Brand::Standards,
            ),
            (
                "08:ed:ed:11:22:33",
                "Zhejiang Dahua Technology Co., Ltd.",
                Brand::Standards,
            ),
            (
                "00:16:6c:11:22:33",
                "Hanwha Vision VietNam",
                Brand::Standards,
            ),
            ("ac:67:84:11:22:33", "Owlet Baby Care", Brand::CloudOnly),
        ];
        for (mac, vendor, want) in cases {
            let h = host("192.168.4.9", mac, Some(vendor), &[]);
            let c = classify_host(&h, &[], None);
            assert_eq!(c.brand, want, "{vendor}");
            assert_eq!(c.confidence, Confidence::Possible, "{vendor}");
            assert!(
                c.signals
                    .iter()
                    .any(|s| matches!(s, Signal::OuiVendor(v) if v == vendor)),
                "expected OUI signal for {vendor}"
            );
        }
    }

    #[test]
    fn ubiquiti_g4_instant_oui_plus_udp10001_tlv_is_confirmed_unifi_protect() {
        let h = host(
            "192.168.4.177",
            "74:ac:b9:11:22:33",
            Some("Ubiquiti Inc"),
            &[443, 7442],
        );
        let unifi = UniFiDiscoveryObs {
            ip: h.ip,
            mac: Some(h.mac.clone()),
            model: Some("UVC G4 Instant".into()),
            firmware: Some("UVC.SAV530q.v4.72.38.67".into()),
            hostname: Some("Front-Porch".into()),
            source_advertised: true,
            is_camera_platform: true,
        };
        let c = classify_host_with_evidence(&h, &[], None, &[], Some(&unifi), &[]);
        assert_eq!(c.brand, Brand::UniFiProtect);
        assert_eq!(c.confidence, Confidence::Confirmed);
        assert!(c.signals.iter().any(|s| matches!(
            s,
            Signal::UniFiDiscovery { model: Some(m), firmware: Some(f) }
                if m == "UVC G4 Instant" && f == "UVC.SAV530q.v4.72.38.67"
        )));
    }

    #[test]
    fn tapo_c460_classifies_as_tapo_never_embedded_web() {
        let h = host(
            "192.168.4.243",
            "50:3d:d1:e3:e2:07",
            Some("TP-Link Systems Inc."),
            &[443, 8800],
        );
        let c = classify_host(&h, &[], None);
        assert_eq!(c.brand, Brand::Tapo);
        assert_ne!(c.brand, Brand::EmbeddedWeb);
        assert_eq!(c.confidence, Confidence::Likely);
        assert!(
            c.signals
                .iter()
                .any(|s| matches!(s, Signal::OuiVendor(v) if v == "TP-Link Systems Inc."))
        );
        assert!(
            c.signals
                .iter()
                .any(|s| matches!(s, Signal::PortSignature(p) if p == &[443, 8800]))
        );
    }

    #[test]
    fn wyze_cam_v4_with_rtsp_port_554_is_likely_tutk_not_conflict() {
        let h = host(
            "192.168.4.23",
            "80:48:2c:52:59:05",
            Some("Wyze Labs Inc"),
            &[554],
        );
        let c = classify_host(&h, &[], None);
        assert_eq!(c.brand, Brand::Tutk);
        assert_eq!(c.confidence, Confidence::Likely);
    }

    #[test]
    fn wyze_oui_alone_is_possible_not_likely() {
        // Wyze also makes plugs/sensors: a bare OUI match never reaches Likely.
        let h = host(
            "192.168.4.23",
            "80:48:2c:52:59:05",
            Some("Wyze Labs Inc"),
            &[],
        );
        let c = classify_host(&h, &[], None);
        assert_eq!(c.brand, Brand::Tutk);
        assert_eq!(c.confidence, Confidence::Possible);
        assert!(matches!(&c.signals[0], Signal::OuiVendor(v) if v == "Wyze Labs Inc"));
    }

    #[test]
    fn wyze_oui_plus_listener_is_confirmed() {
        // Vendor (OUI) + live protocol proof (listener) = Confirmed: TUTK is
        // the camera transport; a Wyze TUTK speaker is a camera.
        let h = host(
            "192.168.4.23",
            "80:48:2c:52:59:05",
            Some("Wyze Labs Inc"),
            &[],
        );
        let c = classify_host(&h, &[], Some(44650));
        assert_eq!(c.brand, Brand::Tutk);
        assert_eq!(c.confidence, Confidence::Confirmed);
        assert!(
            c.signals
                .iter()
                .any(|s| matches!(s, Signal::TutkListener(44650)))
        );
    }

    #[test]
    fn aosu_homebase_oui_plus_tuya_ports_likely() {
        // Real captured shape: Glazero OUI + 443/6668/8888/51028 open.
        let h = host(
            "192.168.4.37",
            "60:d5:61:21:4d:36",
            Some("Shenzhen Glazero Technology Co., Ltd."),
            &[443, 6668, 51028, 8888],
        );
        let c = classify_host(&h, &[], None);
        assert_eq!(c.brand, Brand::Tuya);
        // OUI + port signature (two weak signals, no protocol proof): Likely.
        // A beacon makes it Confirmed (decisive), as the next test shows.
        assert_eq!(c.confidence, Confidence::Likely);
    }

    #[test]
    fn tuya_beacon_decisive_even_without_ports() {
        let h = host("192.168.4.37", "60:d5:61:21:4d:36", None, &[]);
        let beacon = crate::discovery::tuya_beacon::decode_beacon(
            "192.168.4.37:60614",
            &crate::discovery::tuya_beacon::captured_beacon_bytes(),
        )
        .unwrap();
        let refs = [&beacon];
        let c = classify_host(&h, &refs, None);
        assert_eq!(c.brand, Brand::Tuya);
        assert_eq!(c.confidence, Confidence::Confirmed);
        assert!(matches!(
            c.signals[0],
            Signal::TuyaBeacon("BOARDCAST_LPV34")
        ));
    }

    #[test]
    fn resideo_embedded_web() {
        let h = host(
            "192.168.5.211",
            "48:a2:e6:ca:c6:76",
            Some("Resideo"),
            &[80, 443],
        );
        let c = classify_host(&h, &[], None);
        assert_eq!(c.brand, Brand::EmbeddedWeb);
        assert_eq!(c.confidence, Confidence::Likely);
    }

    #[test]
    fn infrastructure_not_camera() {
        let h = host("192.168.4.1", "48:dd:0c:c9:ec:0d", Some("eero inc."), &[80]);
        let c = classify_host(&h, &[], None);
        assert_eq!(c.brand, Brand::Infrastructure);
    }

    #[test]
    fn laa_mac_excluded_with_reason() {
        // iPhone: da:91 prefix has the local bit set.
        let h = host("192.168.5.206", "da:91:aa:bb:cc:dd", None, &[]);
        let c = classify_host(&h, &[], None);
        assert_eq!(c.brand, Brand::Unknown);
        assert!(matches!(c.signals[0], Signal::LocallyAdministeredMac));
    }

    #[test]
    fn unknown_stays_unknown_with_possible() {
        let h = host("192.168.6.85", "7c:70:bc:5d:4c:09", None, &[]);
        let c = classify_host(&h, &[], None);
        assert_eq!(c.brand, Brand::Unknown);
        assert_eq!(c.confidence, Confidence::Possible);
    }
}
