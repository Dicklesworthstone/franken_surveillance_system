#![forbid(unsafe_code)]

use super::*;

type Test = Result<(), Box<dyn std::error::Error>>;

const MANIFEST: &str = include_str!("../../../../fixtures/site/manifest.v1.json");
const PROBES: &str = include_str!("../../../../fixtures/site/probes.v1.json");

fn manifest() -> Result<SiteManifest, SiteError> {
    parse_manifest(MANIFEST.as_bytes())
}
fn probes() -> Result<Vec<SiteProbeReceipt>, SiteError> {
    parse_probe_receipts(PROBES.as_bytes())
}

#[test]
fn fixture_is_canonical_and_every_receipt_matches() -> Test {
    let manifest = manifest()?;
    assert_eq!(
        manifest.digest()?.to_text(),
        "sha256:c93f2ba998e9df18a00b7489355e5e7ff0e7edc2d7b45d344fc9402550df8a2e"
    );
    let receipts = probes()?;
    assert_eq!(receipts.len(), 2);
    for receipt in &receipts {
        receipt.validate_for(&manifest)?;
    }
    assert_ne!(receipts[0].digest()?, receipts[1].digest()?);
    assert_ne!(manifest.sources[0].digest()?, manifest.sources[1].digest()?);
    Ok(())
}

#[test]
fn json_whitespace_and_object_key_order_do_not_change_identity() -> Test {
    let manifest = manifest()?;
    let reordered = MANIFEST.replace(
        "\"site_id\": \"site:example\",\n  \"generation\": 1",
        "\"generation\": 1,\n  \"site_id\": \"site:example\"",
    );
    assert_ne!(MANIFEST, reordered);
    assert_eq!(
        manifest.digest()?,
        SiteManifest::parse(&reordered)?.digest()?
    );
    assert_eq!(
        manifest.digest()?,
        SiteManifest::parse(&format!("\n {MANIFEST} \t"))?.digest()?
    );
    Ok(())
}

#[test]
fn unknown_and_duplicate_fields_never_smuggle_credentials() {
    for input in [
        MANIFEST.replacen(
            "\"generation\": 1",
            "\"generation\": 1, \"generation\": 2",
            1,
        ),
        MANIFEST.replacen(
            "\"site_id\":",
            "\"password\":\"DO_NOT_ECHO_PASSWORD\",\"site_id\":",
            1,
        ),
        MANIFEST.replacen(
            "\"source_id\":",
            "\"username\":\"DO_NOT_ECHO_USERNAME\",\"source_id\":",
            1,
        ),
        MANIFEST.replacen(
            "\"authentication\": null",
            "\"authentication\": {\"password\":\"DO_NOT_ECHO_PASSWORD\"}",
            1,
        ),
        format!("{MANIFEST}{{}}"),
    ] {
        let result = parse_manifest(input.as_bytes());
        assert!(result.is_err());
        let error = format!("{result:?}");
        assert!(!error.contains("DO_NOT_ECHO"));
    }
}

#[test]
fn numeric_aliases_and_overflow_are_refused() {
    for replacement in [
        "0",
        "-1",
        "-0",
        "1.0",
        "1e0",
        "\"1\"",
        "18446744073709551616",
    ] {
        let changed = MANIFEST.replacen(
            "\"generation\": 1",
            &format!("\"generation\": {replacement}"),
            1,
        );
        assert!(
            parse_manifest(changed.as_bytes()).is_err(),
            "accepted {replacement}"
        );
    }
    assert!(
        parse_probe_receipts(
            PROBES
                .replacen("\"ssrc\": 42", "\"ssrc\": 4294967296", 1)
                .as_bytes()
        )
        .is_err()
    );
    assert!(
        parse_probe_receipts(
            PROBES
                .replacen("\"observed_frames\": 4", "\"observed_frames\": 1000001", 1)
                .as_bytes()
        )
        .is_err()
    );
}

#[test]
fn complete_document_bounds_and_utf8_are_enforced() -> Test {
    assert_eq!(
        parse_manifest(&vec![b' '; MAX_SITE_INPUT_BYTES + 1]),
        Err(SiteError::Limit)
    );
    assert_eq!(parse_probe_receipts(&[0xff]), Err(SiteError::Json));
    assert!(parse_probe_receipts(b"[]")?.is_empty());
    assert!(parse_manifest(b"{}").is_err());
    assert!(parse_manifest(b"[]").is_err());
    assert!(parse_probe_receipts(MANIFEST.as_bytes()).is_err());
    let mut value = manifest()?;
    let source = value.sources[0].clone();
    value.sources = (0..MAX_SITE_SOURCES)
        .map(|index| {
            let mut source = source.clone();
            source.source_id = format!("source:{index}");
            source.presentation = Some(format!("/live/source-{index}"));
            source
        })
        .collect();
    value.digest()?;
    value.sources.push(source);
    assert_eq!(value.digest(), Err(SiteError::Limit));
    Ok(())
}

#[test]
fn all_standard_source_kinds_parse_but_mixed_routes_are_refused() -> Test {
    let mut value = manifest()?;
    let source = &mut value.sources[0];
    source.kind = SourceKind::Onvif;
    source.presentation = None;
    source.control_root = None;
    source.onvif_service_path = Some("/onvif/device_service".into());
    source.validate()?;
    source.unifi_camera_id = Some("camera:inventory".into());
    assert!(source.validate().is_err());
    source.kind = SourceKind::UnifiProtect;
    source.onvif_service_path = None;
    source.validate()?;
    source.unifi_camera_id = None;
    assert!(source.validate().is_err());
    Ok(())
}

#[test]
fn route_scope_refuses_dns_peer_userinfo_secret_query_and_traversal() -> Test {
    for peer in [
        "camera.example:554",
        "192.0.2.10:0",
        "0.0.0.0:554",
        "224.0.0.1:554",
        "255.255.255.255:554",
        "[::]:554",
        "[ff02::1]:554",
        "[::ffff:224.0.0.1]:554",
        "[::ffff:0.0.0.0]:554",
    ] {
        let changed = MANIFEST.replacen("192.0.2.10:554", peer, 1);
        assert!(
            parse_manifest(changed.as_bytes()).is_err(),
            "accepted peer {peer}"
        );
    }
    for presentation in [
        "rtsp://user:password@host/live",
        "//other/live",
        "/live/../secret",
        "/live/%2e%2e/secret",
        "/live/%252e",
        "/live/main#fragment",
        "/live/main?password=DO_NOT_ECHO",
        "/live/main?%74oken=DO_NOT_ECHO",
        "/live/main?access_token=DO_NOT_ECHO",
    ] {
        let mut value = manifest()?;
        value.sources[0].presentation = Some(presentation.into());
        assert!(
            value.digest().is_err(),
            "accepted presentation {presentation}"
        );
    }
    let mut value = manifest()?;
    value.sources[0].presentation = Some("/live/main?channel=1&subtype=0".into());
    value.digest()?;
    value.sources[0].control_root = Some("/different".into());
    assert!(value.digest().is_err());
    Ok(())
}

#[test]
fn authority_labels_are_pinned_to_the_literal_route() -> Test {
    for authority in [
        "camera.example:8554",
        "192.0.2.99:554",
        "[2001:db8::1]:554",
        "user:password@camera.example",
        "camera..example",
        "camera.example:0554",
    ] {
        let mut value = manifest()?;
        value.sources[0].authority = authority.into();
        assert!(value.digest().is_err(), "accepted {authority}");
    }
    let mut value = manifest()?;
    value.sources[0].authority = "192.0.2.10:554".into();
    value.digest()?;
    value.sources[0].peer = "[2001:db8::1]:554".parse()?;
    value.sources[0].authority = "[2001:db8::1]:554".into();
    value.digest()?;
    Ok(())
}

#[test]
fn credential_references_are_pure_bounded_and_private() -> Test {
    let mut value = manifest()?;
    value.sources[0].authentication = Some(SiteAuthentication {
        credential_file: "/not-created/DO_NOT_ECHO_CREDENTIAL".into(),
        realm: "DO_NOT_ECHO_REALM".into(),
        legacy_md5: false,
        legacy_no_qop: false,
    });
    value.digest()?;
    assert!(!format!("{value:?}").contains("DO_NOT_ECHO"));
    assert!(!format!("{:?}", value.sources[0].authentication).contains("DO_NOT_ECHO"));
    for bad in [
        "relative",
        "/",
        "/trailing/",
        "/dot/../secret",
        "/dot/./secret",
        "/double//secret",
    ] {
        let mut changed = value.clone();
        if let Some(auth) = &mut changed.sources[0].authentication {
            auth.credential_file = bad.into();
        }
        assert!(changed.digest().is_err(), "accepted {bad}");
    }
    if let Some(auth) = &mut value.sources[0].authentication {
        auth.legacy_no_qop = true;
    }
    assert!(value.digest().is_err());
    Ok(())
}

#[test]
fn canonical_identity_binds_order_policy_rights_auth_and_owner_intent() -> Test {
    let original = manifest()?;
    let digest = original.digest()?;
    let mut changed = original.clone();
    changed.sources.swap(0, 1);
    assert_ne!(changed.digest()?, digest);
    changed = original.clone();
    changed.generation += 1;
    assert_ne!(changed.digest()?, digest);
    changed = original.clone();
    changed.sources[0].generation += 1;
    assert_ne!(changed.digest()?, digest);
    changed = original.clone();
    changed.sources[0].retention_class = "hold".into();
    assert_ne!(changed.digest()?, digest);
    changed = original.clone();
    changed.sources[0].rights_verdict_ref = "fldt:rights:new".into();
    assert_ne!(changed.digest()?, digest);
    changed = original.clone();
    changed.sources[0].owner_authorized = false;
    assert_ne!(changed.digest()?, digest);
    changed = original.clone();
    changed.sources[0].plaintext = false;
    assert_ne!(changed.digest()?, digest);
    changed = original.clone();
    changed.sources[0].retain_originals = false;
    assert_ne!(changed.digest()?, digest);
    changed = original.clone();
    changed.sources[0].stream_role = StreamRole::Sub;
    assert_ne!(changed.digest()?, digest);
    changed = original.clone();
    changed.sources[0].max_connections = 2;
    assert_ne!(changed.digest()?, digest);
    changed.sources[0].source_id = "x".repeat(65_537);
    assert!(changed.digest().is_err());
    Ok(())
}

#[test]
fn duplicate_source_and_receipt_identities_are_refused() -> Test {
    let mut value = manifest()?;
    value.sources[1].source_id = value.sources[0].source_id.clone();
    assert_eq!(value.validate(), Err(SiteError::DuplicateSource));
    let changed = PROBES.replace("source:back", "source:front");
    assert_eq!(
        parse_probe_receipts(changed.as_bytes()),
        Err(SiteError::DuplicateProbe)
    );
    Ok(())
}

#[test]
fn probe_generation_and_complete_manifest_changes_invalidate_old_receipts() -> Test {
    let original = manifest()?;
    let receipt = probes()?.remove(0);
    receipt.validate_for(&original)?;
    let mut changed = original.clone();
    changed.generation += 1;
    assert_eq!(
        receipt.validate_for(&changed),
        Err(SiteError::StaleManifest)
    );
    let mut altered = receipt.clone();
    altered.source_generation += 1;
    assert_eq!(
        altered.validate_for(&original),
        Err(SiteError::SourceMismatch)
    );
    altered = receipt.clone();
    altered.peer = "192.0.2.99:554".parse()?;
    assert_eq!(
        altered.validate_for(&original),
        Err(SiteError::SourceMismatch)
    );
    altered = receipt.clone();
    altered.presentation = "/live/other".into();
    assert_eq!(
        altered.validate_for(&original),
        Err(SiteError::SourceMismatch)
    );
    altered = receipt.clone();
    altered.source_id = "source:unknown".into();
    assert_eq!(
        altered.validate_for(&original),
        Err(SiteError::UnknownSource)
    );
    Ok(())
}

#[test]
fn probe_cadence_wrap_and_selected_media_are_exact() -> Test {
    let mut receipt = probes()?.remove(0);
    receipt.first_rtp_timestamp = u32::MAX - 5000;
    receipt.last_rtp_timestamp = receipt.first_rtp_timestamp.wrapping_add(10800);
    receipt.validate()?;
    let digest = receipt.digest()?;
    receipt.ssrc = 0;
    receipt.validate()?;
    assert_ne!(receipt.digest()?, digest);
    receipt.last_rtp_timestamp = receipt.last_rtp_timestamp.wrapping_add(1);
    assert!(receipt.validate().is_err());
    receipt = probes()?.remove(0);
    receipt.clock_rate_hz = 1000;
    assert!(receipt.validate().is_err());
    receipt = probes()?.remove(0);
    receipt.rtcp_channel = 2;
    assert!(receipt.validate().is_err());
    receipt = probes()?.remove(0);
    receipt.rtp_channel = 1;
    receipt.rtcp_channel = 2;
    assert!(receipt.validate().is_err());
    receipt = probes()?.remove(0);
    receipt.parameter_set_digests.pop();
    assert!(receipt.validate().is_err());
    receipt = probes()?.remove(0);
    receipt.codec = ProbeCodec::Jpeg;
    receipt.parameter_set_digests.clear();
    receipt.payload_type = 26;
    receipt.validate()?;
    receipt.payload_type = 96;
    receipt.validate()?;
    Ok(())
}

#[test]
fn lab_digest_and_other_algorithm_never_alias_normal_evidence() -> Test {
    let mut receipt = probes()?.remove(0);
    receipt.sdp_digest = receipt.sdp_digest.with_laboratory(true);
    assert!(receipt.digest().is_err());
    receipt = probes()?.remove(0);
    receipt.sdp_digest = ContentDigest::new(DigestAlgorithm::Blake3, [0; 32]);
    assert!(receipt.digest().is_err());
    receipt.sdp_digest = ContentDigest::new(DigestAlgorithm::Sha256, [0; 32]);
    assert!(receipt.digest().is_err());
    let original = probes()?.remove(0).sdp_digest.to_text();
    assert!(
        parse_probe_receipts(
            PROBES
                .replace(&original, &format!("sha256:{}", "0".repeat(64)))
                .as_bytes()
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn geometry_is_bounded_nondegenerate_and_digest_bound() -> Test {
    let mut value = manifest()?;
    let original = value.digest()?;
    value.sources[0].zones.push(SiteZone {
        zone_id: "zone:queue".into(),
        kind: "queue".into(),
        vertices: vec![[0, 0], [500000, 0], [500000, 500000], [0, 500000]],
    });
    assert_ne!(value.digest()?, original);
    value.sources[0].payment_masks.push(PaymentMask {
        x: 100,
        y: 200,
        width: 300,
        height: 400,
    });
    value.digest()?;
    value.sources[0].payment_masks[0].width = u32::MAX;
    assert!(value.digest().is_err());
    value.sources[0].payment_masks.clear();
    for bad in [
        vec![[0, 0], [0, 0], [1, 1]],
        vec![[0, 0], [1, 1], [2, 2]],
        vec![[0, 0], [500000, 500000], [0, 500000], [500000, 0]],
        vec![[0, 0], [1000001, 0], [0, 100]],
    ] {
        value.sources[0].zones[0].vertices = bad;
        assert!(value.digest().is_err());
    }
    Ok(())
}

#[test]
fn aggregate_polygon_work_budget_is_independent_of_source_bounds() -> Test {
    let mut value = manifest()?;
    let source = value.sources[0].clone();
    value.sources = (0..64)
        .map(|index| {
            let mut s = source.clone();
            s.source_id = format!("source:{index}");
            s.presentation = Some(format!("/live/source-{index}"));
            s.zones = (0..32)
                .map(|z| SiteZone {
                    zone_id: format!("zone:{z}"),
                    kind: "other".into(),
                    vertices: vec![[0, 0], [100, 0], [200, 100], [100, 200], [0, 100]],
                })
                .collect();
            s
        })
        .collect();
    assert_eq!(value.validate(), Err(SiteError::Limit));
    Ok(())
}

#[test]
fn physical_peer_connection_limits_are_consistent_across_ports_and_ip_forms() -> Test {
    let mut value = manifest()?;
    value.sources[1].peer = value.sources[0].peer;
    value.sources[1].authority = value.sources[0].authority.clone();
    value.sources[1].presentation = Some("/live/sub".into());
    // Multiple channels with a one-connection declaration are valid. A future owner
    // may sequence them; admission does not pretend that a scheduler already exists.
    value.validate()?;
    let digest = value.digest()?;
    value.sources[1].max_connections = 2;
    assert_eq!(
        value.validate(),
        Err(SiteError::InvalidField("max_connections"))
    );
    assert_eq!(
        value.digest(),
        Err(SiteError::InvalidField("max_connections"))
    );
    value.sources[1].peer = "192.0.2.10:8554".parse()?;
    value.sources[1].authority = "camera-10.example:8554".into();
    assert_eq!(
        value.validate(),
        Err(SiteError::InvalidField("max_connections"))
    );
    value.sources[1].peer = "[::ffff:192.0.2.10]:554".parse()?;
    value.sources[1].authority = value.sources[0].authority.clone();
    assert_eq!(
        value.validate(),
        Err(SiteError::InvalidField("max_connections"))
    );
    value.sources[1].max_connections = 1;
    value.validate()?;
    assert_ne!(value.digest()?, digest); // Exact declared route still determines identity.
    value.sources[1].max_connections = 2;
    value.sources[1].peer = "192.0.2.11:554".parse()?;
    value.validate()?; // Distinct physical peers may declare different ceilings.
    Ok(())
}

#[test]
fn duplicate_rtsp_routes_refuse_aliases_before_manifest_identity() -> Test {
    let original = manifest()?;
    let first = original.sources[0].clone();
    for variant in 0..6 {
        let mut value = original.clone();
        let mut alias = first.clone();
        alias.source_id = "source:alias".into();
        match variant {
            0 => {}
            1 => alias.kind = SourceKind::NvrChannel,
            2 => alias.stream_role = StreamRole::Sub,
            3 => alias.control_root = Some("/".into()),
            4 => alias.peer = "[::ffff:192.0.2.10]:554".parse()?,
            5 => alias.presentation = Some("/live/%6dain".into()),
            _ => return Err("unexpected route alias test variant".into()),
        }
        alias.validate()?;
        value.sources = vec![first.clone(), alias];
        assert_eq!(value.validate(), Err(SiteError::DuplicateSource));
        assert_eq!(value.digest(), Err(SiteError::DuplicateSource));
    }
    let input = MANIFEST
        .replace("192.0.2.11:554", "192.0.2.10:554")
        .replace("camera-11.example:554", "camera-10.example:554");
    assert_eq!(
        parse_manifest(input.as_bytes()),
        Err(SiteError::DuplicateSource)
    );
    Ok(())
}

#[test]
fn distinct_virtual_hosts_and_presentations_retain_declared_shared_limits() -> Test {
    let mut value = manifest()?;
    value.sources[1].peer = value.sources[0].peer;
    // Equal paths at distinct, explicit authority labels can be separate virtual hosts.
    value.validate()?;
    value.sources[1].authority = value.sources[0].authority.clone();
    value.sources[1].presentation = Some("/live/sub".into());
    value.validate()?;
    value.sources[1].presentation = Some("/live/main?channel=1".into());
    value.validate()?;
    value.sources[0].presentation = Some("/live/main?channel=2".into());
    value.validate()?;
    value.sources[1].peer = "192.0.2.10:8554".parse()?;
    value.sources[1].authority = "camera-10.example:8554".into();
    value.sources[1].presentation = value.sources[0].presentation.clone();
    value.validate()?;
    Ok(())
}

#[test]
fn uri_identity_preserves_reserved_delimiters_and_query_semantics() -> Test {
    assert_eq!(
        presentation_identity("/live/%6dain?channel=%31")?,
        presentation_identity("/live/main?channel=1")?
    );
    assert_eq!(
        presentation_identity("/live/main?view=a%3ab")?,
        presentation_identity("/live/main?view=a%3Ab")?
    );
    for (first, second) in [
        ("/live/main?view=a%3db", "/live/main?view=a=b"),
        ("/live/main?a=1&b=2", "/live/main?b=2&a=1"),
        ("/live/Main", "/live/main"),
        ("/live/main?view=A", "/live/main?view=a"),
    ] {
        assert_ne!(
            presentation_identity(first)?,
            presentation_identity(second)?
        );
    }
    assert!(presentation_identity("/live/%").is_err());
    Ok(())
}

#[test]
fn authority_spelling_aliases_refuse_before_manifest_identity() -> Test {
    for (peer, first, second) in [
        (
            "192.0.2.10:554",
            "camera-10.example:554",
            "CAMERA-10.EXAMPLE:554",
        ),
        (
            "[2001:db8::1]:554",
            "[2001:db8::1]:554",
            "[2001:0DB8:0000:0000:0000:0000:0000:0001]:554",
        ),
        (
            "[::ffff:192.0.2.10]:554",
            "[::ffff:192.0.2.10]:554",
            "[0:0:0:0:0:ffff:c000:20a]:554",
        ),
    ] {
        let mut value = manifest()?;
        value.sources[0].peer = peer.parse()?;
        value.sources[0].authority = first.into();
        value.sources[1].peer = peer.parse()?;
        value.sources[1].authority = second.into();
        assert_eq!(value.validate(), Err(SiteError::DuplicateSource));
        assert_eq!(value.digest(), Err(SiteError::DuplicateSource));
    }
    let mut value = manifest()?;
    let original = value.digest()?;
    value.sources[0].authority = value.sources[0].authority.to_ascii_uppercase();
    // Comparison normalization never rewrites the declared authority or its digest.
    assert_ne!(value.digest()?, original);
    Ok(())
}

#[test]
fn authority_comparison_preserves_virtual_hosts_and_port_declarations() -> Test {
    assert_eq!(
        authority_identity("CAMERA.EXAMPLE:554")?,
        authority_identity("camera.example:554")?
    );
    assert_eq!(
        authority_identity("[2001:0DB8:0:0:0:0:0:1]:554")?,
        authority_identity("[2001:db8::1]:554")?
    );
    for (first, second) in [
        ("camera.example:554", "other.example:554"),
        ("camera.example", "camera.example:554"),
        ("camera.example", "camera.example:8554"),
        ("camera.example:554", "camera.example:8554"),
        ("[2001:db8::1]", "[2001:db8::1]:554"),
        ("[2001:db8::1]:554", "[2001:db8::2]:554"),
    ] {
        assert_ne!(authority_identity(first)?, authority_identity(second)?);
    }
    Ok(())
}

const VALID_CLOCK_EVIDENCE: &str = "\"clock_evidence\": {\
    \"wall_clock_unix_ns\": 1800000000000000000, \
    \"monotonic_ns\": 123456789, \
    \"ntp_offset_ns\": 250000, \
    \"ntp_offset_direction\": \"behind\", \
    \"ntp_uncertainty_ns\": 2000000\
}";

fn with_clock_evidence(value: &str) -> String {
    PROBES.replacen(
        "\"server_identity\": \"synthetic-example-server\"",
        &format!("\"server_identity\": \"synthetic-example-server\", {value}"),
        1,
    )
}

#[test]
fn clock_evidence_is_optional_and_absence_is_not_an_error() -> Test {
    let receipts = probes()?;
    assert_eq!(receipts[0].clock_evidence, None);
    assert_eq!(receipts[1].clock_evidence, None);
    // An explicit null is accepted identically to omitting the field entirely.
    let explicit_null = with_clock_evidence("\"clock_evidence\": null");
    assert_eq!(parse_probe_receipts(explicit_null.as_bytes())?, receipts);
    Ok(())
}

#[test]
fn valid_clock_evidence_parses_validates_and_changes_the_receipt_digest() -> Test {
    let manifest = manifest()?;
    let baseline = probes()?;
    let with_evidence = with_clock_evidence(VALID_CLOCK_EVIDENCE);
    let receipts = parse_probe_receipts(with_evidence.as_bytes())?;
    let witness = receipts[0]
        .clock_evidence
        .expect("clock_evidence should parse");
    assert_eq!(witness.wall_clock_unix_ns, 1_800_000_000_000_000_000);
    assert_eq!(witness.monotonic_ns, 123_456_789);
    assert_eq!(witness.ntp_offset_ns, 250_000);
    assert_eq!(witness.ntp_offset_direction, ClockOffsetDirection::Behind);
    assert_eq!(witness.ntp_uncertainty_ns, 2_000_000);
    receipts[0].validate_for(&manifest)?;
    assert_ne!(receipts[0].digest()?, baseline[0].digest()?);
    // Key/whitespace order around the injected object does not change identity.
    let reordered = with_clock_evidence(
        "\"clock_evidence\": {\
            \"ntp_uncertainty_ns\": 2000000, \
            \"ntp_offset_direction\": \"behind\", \
            \"ntp_offset_ns\": 250000, \
            \"monotonic_ns\": 123456789, \
            \"wall_clock_unix_ns\": 1800000000000000000\
        }",
    );
    let reparsed = parse_probe_receipts(reordered.as_bytes())?;
    assert_eq!(receipts[0].digest()?, reparsed[0].digest()?);
    Ok(())
}

#[test]
fn implausible_clock_evidence_is_refused() {
    for value in [
        // Zero uncertainty is an implausible claim, not perfect precision.
        "\"clock_evidence\": {\"wall_clock_unix_ns\": 1800000000000000000, \
            \"monotonic_ns\": 1, \"ntp_offset_ns\": 0, \
            \"ntp_offset_direction\": \"ahead\", \"ntp_uncertainty_ns\": 0}",
        // Beyond the 10-second ceiling the clock is effectively unsynchronized.
        "\"clock_evidence\": {\"wall_clock_unix_ns\": 1800000000000000000, \
            \"monotonic_ns\": 1, \"ntp_offset_ns\": 0, \
            \"ntp_offset_direction\": \"ahead\", \"ntp_uncertainty_ns\": 10000000001}",
        // Below the plausibility floor (before 2023-11-14T22:13:20Z), including zero.
        "\"clock_evidence\": {\"wall_clock_unix_ns\": 0, \
            \"monotonic_ns\": 1, \"ntp_offset_ns\": 0, \
            \"ntp_offset_direction\": \"ahead\", \"ntp_uncertainty_ns\": 1000}",
        // An unknown direction spelling is refused, not coerced.
        "\"clock_evidence\": {\"wall_clock_unix_ns\": 1800000000000000000, \
            \"monotonic_ns\": 1, \"ntp_offset_ns\": 0, \
            \"ntp_offset_direction\": \"sideways\", \"ntp_uncertainty_ns\": 1000}",
        // A negative offset magnitude is not a valid unsigned field.
        "\"clock_evidence\": {\"wall_clock_unix_ns\": 1800000000000000000, \
            \"monotonic_ns\": 1, \"ntp_offset_ns\": -5, \
            \"ntp_offset_direction\": \"ahead\", \"ntp_uncertainty_ns\": 1000}",
        // An unknown nested field is refused, matching every other object in this schema.
        "\"clock_evidence\": {\"wall_clock_unix_ns\": 1800000000000000000, \
            \"monotonic_ns\": 1, \"ntp_offset_ns\": 0, \
            \"ntp_offset_direction\": \"ahead\", \"ntp_uncertainty_ns\": 1000, \"extra\": 1}",
    ] {
        let input = with_clock_evidence(value);
        assert!(
            parse_probe_receipts(input.as_bytes()).is_err(),
            "expected refusal for: {value}"
        );
    }
}
