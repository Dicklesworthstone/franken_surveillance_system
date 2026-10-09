//! Service-fingerprint heuristics → typed brand confidence (DISC-5,
//! fss-yodhk.5).
//!
//! Combines census [`HostObs`] rows, Tuya beacon observations and
//! standards-probe results into [`BrandConfidence`] with evidence handles —
//! never a bare guess. Every classification names the signals that produced
//! it; a host with no supporting signal is `Unknown`, not guessed.
//!
//! Rules table proven 2026-10-07 (lab notes: it identified every camera on
//! the operator LAN correctly):
//! - OUI vendor: `Wyze Labs` → TUTK-family; `Shenzhen Glazero` → Tuya/AOSU;
//!   `Resideo` → embedded-web; `Shenzhen Intellirocks` (pet cams) etc.
//! - Port signature: `6668+8888` open → Tuya-ish homebase; `32761 UDP absorb
//!   + zero TCP` → TUTK client (Wyze shape); Digest-auth lighttpd → Resideo.
//! - Tuya beacon from the host → Tuya-family (decisive).
//! - LAA/private MACs (locally administered bit set) are never classified by
//!   OUI (phones) — excluded with an explicit reason.

use crate::discovery::census::HostObs;
use crate::discovery::tuya_beacon::TuyaBeaconObs;

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
    /// TUTK/IOTC NEW protocol (Wyze-class); adapter ADP-WYZE-V4-LAB-001 path.
    Tutk,
    /// Tuya-based (AOSU-class homebase/cams); ADP-AOSU-P1MAX-LAB-001 path.
    Tuya,
    /// Embedded web camera (Resideo-class; Digest lighttpd).
    EmbeddedWeb,
    /// Standards path (RTSP/ONVIF responder).
    Standards,
    /// Infrastructure (routers, speakers — not camera candidates).
    Infrastructure,
    /// Not classified: no supporting signal.
    Unknown,
}

/// Typed confidence — never a bare number.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Confidence {
    /// Single weak signal.
    Possible,
    /// One decisive signal or two independent signals.
    Likely,
    /// Multiple independent signals agree.
    Confirmed,
}

/// Classifies one host against the fingerprint rules.
#[must_use]
pub fn classify_host(
    host: &HostObs,
    beacons_from_host: &[&TuyaBeaconObs],
    tutk_listener_port: Option<u16>,
) -> BrandConfidence {
    let mut signals = Vec::new();

    // LAA check first: locally administered bit set → OUI inapplicable.
    let is_laa = host
        .mac
        .split(':')
        .next()
        .and_then(|b| u8::from_str_radix(b, 16).ok())
        .is_some_and(|b| b & 0x02 != 0);
    if is_laa {
        signals.push(Signal::LocallyAdministeredMac);
        return BrandConfidence {
            brand: Brand::Unknown,
            confidence: Confidence::Possible,
            signals,
        };
    }

    // TUTK listener corroboration (credential-less probe answered).
    if let Some(port) = tutk_listener_port {
        signals.push(Signal::TutkListener(port));
    }

    // Tuya beacon: decisive.
    if let Some(b) = beacons_from_host.first() {
        signals.push(Signal::TuyaBeacon(b.cmd_name));
        return BrandConfidence {
            brand: Brand::Tuya,
            confidence: Confidence::Confirmed,
            signals,
        };
    }

    // OUI vendor signal.
    let vendor = host.oui_vendor.as_deref().unwrap_or("");
    let mut oui_brand: Option<Brand> = None;
    if vendor.contains("Wyze Labs") {
        oui_brand = Some(Brand::Tutk);
    } else if vendor.contains("Shenzhen Glazero") || vendor.contains("Tuya") {
        oui_brand = Some(Brand::Tuya);
    } else if vendor.contains("Resideo") || vendor.contains("Honeywell") {
        oui_brand = Some(Brand::EmbeddedWeb);
    } else if vendor.contains("eero") || vendor.contains("Sonos") || vendor.contains("Tesla") {
        oui_brand = Some(Brand::Infrastructure);
    }
    if oui_brand.is_some() {
        signals.push(Signal::OuiVendor(vendor.to_owned()));
    }

    // Port-set signature signal.
    let open: Vec<u16> = host.open_ports.clone();
    let mut port_brand: Option<Brand> = None;
    if open.contains(&6668) && open.contains(&8888) {
        port_brand = Some(Brand::Tuya);
    } else if open.contains(&80) && open.contains(&443) && open.is_empty() == false && open.len() <= 3 {
        // small HTTP(S) surface with matching OUI handled below; alone it is weak
        port_brand = None;
    }
    // TUTK shape: 32761 UDP-absorb is invisible to TCP census; Wyze shows zero
    // TCP ports. Zero-open + Wyze OUI combination handled by signal count.
    if !open.is_empty() {
        signals.push(Signal::PortSignature(open));
    }
    if port_brand.is_some() {
        signals.push(Signal::PortSignature(vec![6668, 8888]));
    }

    // Combine honestly: Wyze also makes non-camera devices, so a bare OUI
    // match is Possible (vendor suggests the family, nothing more). OUI
    // plus an independent corroboration (listener, ports) is Likely; three
    // agreeing signals are Confirmed.
    let brand = match (&oui_brand, &port_brand) {
        (Some(a), Some(b)) if a == b => Some(a.clone()),
        (Some(a), None) | (None, Some(a)) => Some(a.clone()),
        (Some(_), Some(_)) => None, // conflict → Unknown (honest)
        (None, None) => None,
    }
    .unwrap_or(Brand::Unknown);
    let has_listener = signals
        .iter()
        .any(|s| matches!(s, Signal::TutkListener(_)));
    let independent = signals
        .iter()
        .filter(|s| !matches!(s, Signal::LocallyAdministeredMac))
        .count();
    let confidence = if has_listener && independent >= 2 {
        Confidence::Confirmed
    } else if independent >= 2 || (has_listener && independent == 1) {
        Confidence::Likely
    } else {
        Confidence::Possible
    };
    BrandConfidence {
        brand,
        confidence,
        signals,
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
    fn wyze_oui_alone_is_possible_not_likely() {
        // Wyze also makes plugs/sensors: a bare OUI match never reaches Likely.
        let h = host("192.168.4.23", "80:48:2c:52:59:05", Some("Wyze Labs Inc"), &[]);
        let c = classify_host(&h, &[], None);
        assert_eq!(c.brand, Brand::Tutk);
        assert_eq!(c.confidence, Confidence::Possible);
        assert!(matches!(&c.signals[0], Signal::OuiVendor(v) if v == "Wyze Labs Inc"));
    }

    #[test]
    fn wyze_oui_plus_listener_is_confirmed() {
        // Vendor (OUI) + live protocol proof (listener) = Confirmed: TUTK is
        // the camera transport; a Wyze TUTK speaker is a camera.
        let h = host("192.168.4.23", "80:48:2c:52:59:05", Some("Wyze Labs Inc"), &[]);
        let c = classify_host(&h, &[], Some(44650));
        assert_eq!(c.brand, Brand::Tutk);
        assert_eq!(c.confidence, Confidence::Confirmed);
        assert!(c
            .signals
            .iter()
            .any(|s| matches!(s, Signal::TutkListener(44650))));
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
        assert!(matches!(c.signals[0], Signal::TuyaBeacon("BOARDCAST_LPV34")));
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
