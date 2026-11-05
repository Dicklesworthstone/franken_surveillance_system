#![forbid(unsafe_code)]
//! Protected ONVIF probe admission, identity, privacy and native route contracts.

use super::*;
use crate::json_output::array;
use crate::site_plan::onvif_tests::{Fixture, PRESENTATION, ROOT, Test};
use fss_core::json_input::{Value, parse};
use std::cell::Cell;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};

const APPROVAL_ERROR: &str = "ERR-SITE-PROBE-APPROVAL-001";

fn options(fixture: &Fixture, codec: ProbeCodec) -> SiteProbeOptions {
    SiteProbeOptions {
        clock_ntp_peer: None,
        unifi_bindings: None,
        onvif_bindings: Some(fixture.directory.join("bindings.json")),
        receipt_file: Some(fixture.directory.join("probe-receipts.json")),
        source: fixture.manifest.sources[0].source_id.clone(),
        codec,
        media_index: 0,
        payload_type: None,
        rtp_channel: 0,
        observe_frames: 6,
        timeout_ms: 10_000,
        principal: "principal:onvif-probe-test".into(),
        output: ProbeOutput::Receipts,
        approve: None,
    }
}

fn document(fixture: &Fixture, overrides: &[(&str, String)]) -> Test<Vec<u8>> {
    let input = fixture.input();
    let mut fields = vec![
        ("source_id", string(input.source_id)),
        (
            "source_file",
            string(input.spec.source.to_str().ok_or("source path")?),
        ),
        ("source_digest", string(&input.spec.expected.to_text())),
        ("onboarding_plan", string(&input.onboarding_plan.to_text())),
        ("profile_digest", string(&input.profile_digest.to_text())),
        ("rtsp_peer", string(&input.peer.to_string())),
        ("rtsp_authority", string(input.authority)),
        ("control_root", string(input.control_root)),
    ];
    for (key, value) in overrides {
        fields
            .iter_mut()
            .find(|(name, _)| name == key)
            .ok_or("unknown field")?
            .1 = value.clone();
    }
    Ok(object(&[
        (
            "schema",
            string(crate::site_onvif::SITE_ONVIF_BINDINGS_SCHEMA),
        ),
        (
            "manifest_digest",
            string(&fixture.manifest.digest()?.to_text()),
        ),
        ("sources", array(&[object(&fields)])),
    ])
    .into_bytes())
}

fn prepared<'a>(
    fixture: &'a Fixture,
    options: &'a SiteProbeOptions,
    document: &[u8],
) -> Result<ProbePlan<'a>, &'static str> {
    let binding = probe_binding(&fixture.manifest, document, &options.source).map_err(|_| INPUT)?;
    prepare_owned(
        &fixture.manifest,
        options,
        binding,
        ContentDigest::sha256(document),
        options.receipt_file.clone().ok_or(OUTPUT)?,
        &|| Ok(()),
    )
}

fn write_private(path: &Path, bytes: &[u8]) -> Test {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

#[test]
fn media1_avc_and_media2_avc_hevc_use_separate_rtsp_endpoint_and_original_manifest() -> Test {
    for (codec, media2) in [
        (ProbeCodec::Avc, false),
        (ProbeCodec::Avc, true),
        (ProbeCodec::Hevc, true),
    ] {
        let fixture = Fixture::new(codec, media2)?;
        let options = options(&fixture, codec);
        let bytes = document(&fixture, &[])?;
        let plan = prepared(&fixture, &options, &bytes)?;
        assert_eq!(fixture.manifest.sources[0].kind, SourceKind::Onvif);
        assert_eq!(fixture.manifest.sources[0].peer.port(), 80);
        assert_eq!(plan.source_index, 0);
        assert_eq!(plan.route.manifest_digest(), fixture.manifest.digest()?);
        assert_eq!(plan.binding.peer(), fixture.receipts[0].peer);
        assert_eq!(plan.binding.authority(), fixture.receipts[0].authority);
        assert_eq!(plan.route.presentation(), PRESENTATION);
        assert_eq!(plan.route.control_root(), ROOT);
        assert_eq!(
            plan.protocol.presentation_uri,
            format!("rtsp://{}{}", fixture.receipts[0].authority, PRESENTATION)
        );
        assert_eq!(
            plan.protocol.control_root_uri,
            format!("rtsp://{}{}", fixture.receipts[0].authority, ROOT)
        );
        assert_eq!(plan.check_approval(), Ok(false));
        assert!(fixture.receipts[0].validate_for(&fixture.manifest).is_err());
        plan.route
            .validate_receipt(&fixture.manifest, &fixture.receipts[0])?;
        assert!(
            !options
                .receipt_file
                .as_ref()
                .ok_or("receipt path")?
                .exists()
        );
    }
    Ok(())
}

#[test]
fn preview_redacts_capabilities_and_never_claims_historical_http_authentication() -> Test {
    let mut fixture = Fixture::new(ProbeCodec::Avc, true)?;
    fixture.manifest.sources[0].authentication = Some(fss_reference::site::SiteAuthentication {
        credential_file: fixture.directory.join("credential-not-created"),
        realm: "PRIVATE_REALM_CANARY".to_owned(),
        legacy_md5: false,
        legacy_no_qop: false,
    });
    fixture.rebind()?;
    let options = options(&fixture, ProbeCodec::Avc);
    let bytes = document(&fixture, &[])?;
    let plan = prepared(&fixture, &options, &bytes)?;
    let preview = plan.preview()?;
    for canary in [
        "PRIVATE_CAPABILITY_CANARY",
        "PRIVATE_QUERY_CANARY",
        "PRIVATE_PROFILE_TOKEN_CANARY",
        "PRIVATE_REALM_CANARY",
    ] {
        assert!(!preview.contains(canary));
        assert!(!format!("{:?}", plan.route).contains(canary));
    }
    let value = parse(&preview)?;
    let fields = value.object().ok_or("preview object")?;
    for name in [
        "device_contacted",
        "credentials_read",
        "source_retained",
        "capture_authorized",
        "rights_verdict_verified",
    ] {
        assert_eq!(fields.get(name), Some(&Value::Bool(false)));
    }
    assert!(preview.contains("operator-bound-historical-consistency"));
    assert!(preview.contains("\"onvif_http_origin_verified\":false"));
    assert!(preview.contains("\"onvif_http_contacted\":false"));
    assert!(preview.contains("\"receipt_file_create_only\":true"));
    assert!(preview.contains("\"receipt_file_mode\":\"0600\""));
    assert!(preview.contains(&ContentDigest::sha256(PRESENTATION.as_bytes()).to_text()));
    assert!(!fixture.directory.join("credential-not-created").exists());
    assert!(
        !options
            .receipt_file
            .as_ref()
            .ok_or("receipt path")?
            .exists()
    );
    Ok(())
}

#[test]
fn protected_handoff_and_binding_require_exact_content_profile_onboarding_and_rtsp_scope() -> Test {
    let fixture = Fixture::new(ProbeCodec::Avc, true)?;
    let options = options(&fixture, ProbeCodec::Avc);
    let different = ContentDigest::sha256(b"different").to_text();
    for (field, value) in [
        ("source_digest", different.clone()),
        ("profile_digest", different.clone()),
        ("onboarding_plan", different),
        ("rtsp_peer", "192.0.2.11:554".into()),
        ("rtsp_authority", "another-camera.example:554".into()),
        ("control_root", "/unrelated".into()),
        ("control_root", format!("{ROOT}-sibling")),
    ] {
        let bytes = document(&fixture, &[(field, string(&value))])?;
        let error = prepared(&fixture, &options, &bytes)
            .err()
            .ok_or("mismatched selection accepted")?;
        assert!(!error.contains(&value));
        assert!(!error.contains(PRESENTATION));
    }
    for codec in [ProbeCodec::Hevc, ProbeCodec::Jpeg] {
        let mut changed = options.clone();
        changed.codec = codec;
        let bytes = document(&fixture, &[])?;
        assert_eq!(prepared(&fixture, &changed, &bytes).err(), Some(SELECTION));
    }
    Ok(())
}

#[test]
fn exact_approval_binds_document_bytes_destination_and_control_subtree() -> Test {
    let fixture = Fixture::new(ProbeCodec::Avc, true)?;
    let options = options(&fixture, ProbeCodec::Avc);
    let bytes = document(&fixture, &[])?;
    let approval = prepared(&fixture, &options, &bytes)?.approval;
    let mut approved = options.clone();
    approved.approve = Some(approval);
    assert_eq!(
        prepared(&fixture, &approved, &bytes)?.check_approval(),
        Ok(true)
    );
    let mut padded = bytes.clone();
    padded.push(b'\n');
    assert_eq!(
        prepared(&fixture, &approved, &padded)?.check_approval(),
        Err(APPROVAL_ERROR)
    );
    let broader = document(&fixture, &[("control_root", string("/"))])?;
    assert_eq!(
        prepared(&fixture, &approved, &broader)?.check_approval(),
        Err(APPROVAL_ERROR)
    );
    approved.receipt_file = Some(fixture.directory.join("different-receipt.json"));
    assert_eq!(
        prepared(&fixture, &approved, &bytes)?.check_approval(),
        Err(APPROVAL_ERROR)
    );
    assert!(!fixture.directory.join("probe-receipts.json").exists());
    assert!(!fixture.directory.join("different-receipt.json").exists());
    Ok(())
}

#[test]
fn same_handoff_bytes_in_a_replaced_file_stale_approval_and_live_private_lease() -> Test {
    let fixture = Fixture::new(ProbeCodec::Avc, true)?;
    let options = options(&fixture, ProbeCodec::Avc);
    let document = document(&fixture, &[])?;
    let plan = prepared(&fixture, &options, &document)?;
    let approval = plan.approval;
    let input = private_file::InputLease::open(&fixture.spec.source, &|| Ok(()))?;
    let original = fs::read(&fixture.spec.source)?;
    fs::rename(
        &fixture.spec.source,
        fixture.directory.join("old-handoff.json"),
    )?;
    write_private(&fixture.spec.source, &original)?;
    assert!(input.revalidate(&|| Ok(())).is_err());
    let replacement = private_file::InputLease::open(&fixture.spec.source, &|| Ok(()))?;
    assert!(
        plan.private
            .as_ref()
            .ok_or("private selection")?
            .verify(&replacement)
            .is_err()
    );
    let mut stale = options.clone();
    stale.approve = Some(approval);
    let updated = prepared(&fixture, &stale, &document)?;
    assert_ne!(updated.approval, approval);
    assert_eq!(updated.check_approval(), Err(APPROVAL_ERROR));
    Ok(())
}

#[test]
fn replacing_receipt_parent_keeps_output_path_but_invalidates_approval() -> Test {
    let fixture = Fixture::new(ProbeCodec::Avc, true)?;
    let parent = fixture.directory.join("receipts");
    fs::create_dir(&parent)?;
    let mut options = options(&fixture, ProbeCodec::Avc);
    options.receipt_file = Some(parent.join("probe.json"));
    let document = document(&fixture, &[])?;
    let approval = prepared(&fixture, &options, &document)?.approval;
    fs::rename(&parent, fixture.directory.join("old-receipts"))?;
    fs::create_dir(&parent)?;
    options.approve = Some(approval);
    assert_eq!(
        prepared(&fixture, &options, &document)?.check_approval(),
        Err(APPROVAL_ERROR)
    );
    assert!(!parent.join("probe.json").exists());
    Ok(())
}

#[test]
fn protected_owner_refuses_public_files_symlinks_hardlinks_and_existing_receipt() -> Test {
    let fixture = Fixture::new(ProbeCodec::Avc, true)?;
    let options = options(&fixture, ProbeCodec::Avc);
    let bytes = document(&fixture, &[])?;
    fs::set_permissions(&fixture.spec.source, fs::Permissions::from_mode(0o644))?;
    assert!(prepared(&fixture, &options, &bytes).is_err());
    fs::set_permissions(&fixture.spec.source, fs::Permissions::from_mode(0o600))?;
    let linked = fixture.directory.join("linked-handoff.json");
    symlink(&fixture.spec.source, &linked)?;
    let linked_doc = document(
        &fixture,
        &[(
            "source_file",
            string(linked.to_str().ok_or("symlink path")?),
        )],
    )?;
    assert!(prepared(&fixture, &options, &linked_doc).is_err());
    let hardlink = fixture.directory.join("hardlink.json");
    fs::hard_link(&fixture.spec.source, &hardlink)?;
    assert!(prepared(&fixture, &options, &bytes).is_err());
    fs::remove_file(hardlink)?;
    let receipt = options.receipt_file.as_ref().ok_or("receipt path")?;
    write_private(receipt, b"preexisting-receipt")?;
    assert!(prepared(&fixture, &options, &bytes).is_err());
    assert_eq!(fs::read(receipt)?, b"preexisting-receipt");
    Ok(())
}

#[test]
fn denied_file_authority_reaches_no_private_read_or_receipt_creation() -> Test {
    let fixture = Fixture::new(ProbeCodec::Avc, true)?;
    let options = options(&fixture, ProbeCodec::Avc);
    let bytes = document(&fixture, &[])?;
    let binding = probe_binding(&fixture.manifest, &bytes, &options.source)?;
    let checkpoints = Cell::new(0);
    let error = prepare_owned(
        &fixture.manifest,
        &options,
        binding,
        ContentDigest::sha256(&bytes),
        options.receipt_file.clone().ok_or("receipt path")?,
        &|| {
            checkpoints.set(checkpoints.get() + 1);
            Err("TEST-FILE-AUTHORITY-DENIED")
        },
    )
    .err()
    .ok_or("denied checkpoint accepted")?;
    assert_eq!(error, "TEST-FILE-AUTHORITY-DENIED");
    assert_eq!(checkpoints.get(), 1);
    assert!(
        !options
            .receipt_file
            .as_ref()
            .ok_or("receipt path")?
            .exists()
    );
    Ok(())
}

#[test]
fn selected_probe_keeps_original_ordinal_and_excludes_unreadable_onvif_inputs() -> Test {
    let mut fixture = Fixture::new(ProbeCodec::Avc, true)?;
    let selected = fixture.manifest.sources[0].clone();
    let mut excluded = selected.clone();
    excluded.source_id = "source:excluded".into();
    excluded.peer = "192.0.2.99:80".parse()?;
    excluded.authority = "excluded-camera.example:80".into();
    excluded.owner_authorized = false;
    fixture.manifest.sources = vec![excluded, selected];
    fixture.rebind()?;
    let mut options = options(&fixture, ProbeCodec::Avc);
    options.source = fixture.manifest.sources[1].source_id.clone();
    let bytes = document(&fixture, &[("source_id", string(&options.source))])?;
    let plan = prepared(&fixture, &options, &bytes)?;
    assert_eq!(plan.source_index, 1);
    assert_eq!(plan.route.manifest_digest(), fixture.manifest.digest()?);
    let previous_approval = plan.approval;
    drop(plan);
    fixture.manifest.sources[0].generation += 1;
    fixture.rebind()?;
    let updated = document(&fixture, &[("source_id", string(&options.source))])?;
    options.approve = Some(previous_approval);
    assert!(probe_binding(&fixture.manifest, &bytes, &options.source).is_err());
    assert_eq!(
        prepared(&fixture, &options, &updated)?.check_approval(),
        Err(APPROVAL_ERROR)
    );
    Ok(())
}

#[test]
fn known_direct_routes_and_actual_rtsp_peer_limits_remain_enforced() -> Test {
    let mut fixture = Fixture::new(ProbeCodec::Avc, true)?;
    fixture.manifest.sources[0].peer = "192.0.2.100:80".parse()?;
    fixture.manifest.sources[0].authority = "management.example:80".into();
    let mut direct = fixture.manifest.sources[0].clone();
    direct.source_id = "source:direct".into();
    direct.kind = SourceKind::Rtsp;
    direct.peer = fixture.receipts[0].peer;
    direct.authority = fixture.receipts[0].authority.clone();
    direct.presentation = Some(PRESENTATION.replace("%4a", "%4A"));
    direct.control_root = Some(ROOT.to_owned());
    direct.onvif_service_path = None;
    fixture.manifest.sources.push(direct);
    fixture.rebind()?;
    let options = options(&fixture, ProbeCodec::Avc);
    let bytes = document(&fixture, &[])?;
    assert_eq!(prepared(&fixture, &options, &bytes).err(), Some(SELECTION));
    fixture.manifest.sources[1].presentation = Some("/other-stream".into());
    fixture.manifest.sources[1].control_root = Some("/".into());
    fixture.manifest.sources[1].peer = "192.0.2.10:8554".parse()?;
    fixture.manifest.sources[1].authority = "camera-10.example:8554".into();
    fixture.manifest.sources[1].max_connections = 2;
    fixture.rebind()?;
    let bytes = document(&fixture, &[])?;
    assert_eq!(prepared(&fixture, &options, &bytes).err(), Some(SELECTION));
    fixture.manifest.sources[1].max_connections = 1;
    fixture.rebind()?;
    let bytes = document(&fixture, &[])?;
    assert!(prepared(&fixture, &options, &bytes).is_ok());
    Ok(())
}

#[test]
fn profile_change_requires_matching_handoff_binding_and_new_stream_approval() -> Test {
    let mut fixture = Fixture::new(ProbeCodec::Avc, true)?;
    let options = options(&fixture, ProbeCodec::Avc);
    let original_document = document(&fixture, &[])?;
    let (approval, ingress) = {
        let plan = prepared(&fixture, &options, &original_document)?;
        (plan.approval, plan.binding.key().ingress)
    };
    let old_profile = fixture.input().profile_digest.to_text();
    let new_profile = ContentDigest::sha256(b"different-profile-selection").to_text();
    let original = String::from_utf8(fs::read(&fixture.spec.source)?)?;
    assert_eq!(original.matches(&old_profile).count(), 1);
    let replacement = original.replace(&old_profile, &new_profile);
    fs::write(&fixture.spec.source, replacement.as_bytes())?;
    fixture.spec.expected = ContentDigest::sha256(replacement.as_bytes());
    let unchanged_binding = document(&fixture, &[])?;
    assert_eq!(
        prepared(&fixture, &options, &unchanged_binding).err(),
        Some(SELECTION)
    );
    let matching_binding = document(&fixture, &[("profile_digest", string(&new_profile))])?;
    let mut stale = options;
    stale.approve = Some(approval);
    let plan = prepared(&fixture, &stale, &matching_binding)?;
    assert_ne!(plan.binding.key().ingress, ingress);
    assert_eq!(plan.route.presentation(), PRESENTATION);
    assert_eq!(plan.check_approval(), Err(APPROVAL_ERROR));
    Ok(())
}

#[test]
fn expiring_or_single_use_handoffs_never_become_native_probe_authority() -> Test {
    for (old, new) in [
        (
            "\"invalid_after_connect\":false",
            "\"invalid_after_connect\":true",
        ),
        (
            "\"invalid_after_reboot\":false",
            "\"invalid_after_reboot\":true",
        ),
        ("\"timeout\":\"PT0S\"", "\"timeout\":\"PT1S\""),
    ] {
        let mut fixture = Fixture::new(ProbeCodec::Avc, false)?;
        let original = String::from_utf8(fs::read(&fixture.spec.source)?)?;
        assert_eq!(original.matches(old).count(), 1);
        let replacement = original.replace(old, new);
        fs::write(&fixture.spec.source, replacement.as_bytes())?;
        fixture.spec.expected = ContentDigest::sha256(replacement.as_bytes());
        let options = options(&fixture, ProbeCodec::Avc);
        let bytes = document(&fixture, &[])?;
        assert!(prepared(&fixture, &options, &bytes).is_err());
        assert!(
            !options
                .receipt_file
                .as_ref()
                .ok_or("receipt path")?
                .exists()
        );
    }
    let fixture = Fixture::new(ProbeCodec::Hevc, false)?;
    let options = options(&fixture, ProbeCodec::Hevc);
    assert!(prepared(&fixture, &options, &document(&fixture, &[])?).is_err());
    Ok(())
}

#[test]
fn command_preflight_refuses_mixed_bindings_session_output_and_missing_destinations() -> Test {
    let fixture = Fixture::new(ProbeCodec::Avc, true)?;
    let options = options(&fixture, ProbeCodec::Avc);
    // All command guards operate before a bindings document or handoff is read.
    fs::remove_file(&fixture.spec.source)?;
    let (bindings, receipt) = preflight(&fixture.manifest, &options)?;
    assert!(!bindings.exists());
    assert!(!receipt.exists());
    let mut variants = Vec::new();
    let mut changed = options.clone();
    changed.unifi_bindings = Some(fixture.directory.join("unifi-not-created.json"));
    variants.push((changed, "ERR-SITE-PROBE-PLAN-001"));
    let mut changed = options.clone();
    changed.output = ProbeOutput::Session;
    variants.push((changed, SELECTION));
    let mut changed = options.clone();
    changed.codec = ProbeCodec::Jpeg;
    variants.push((changed, SELECTION));
    let mut changed = options.clone();
    changed.onvif_bindings = None;
    variants.push((changed, SELECTION));
    let mut changed = options.clone();
    changed.receipt_file = None;
    variants.push((changed, SELECTION));
    for (changed, expected) in variants {
        assert_eq!(preflight(&fixture.manifest, &changed).err(), Some(expected));
    }
    for path in [
        PathBuf::from("relative-receipt.json"),
        fixture.directory.join("../receipt.json"),
        fixture.directory.join("./receipt.json"),
    ] {
        let mut changed = options.clone();
        changed.receipt_file = Some(path);
        assert!(preflight(&fixture.manifest, &changed).is_err());
    }
    assert!(!receipt.exists());
    Ok(())
}

#[test]
fn command_preflight_requires_exact_source_kind_and_explicit_owner_plaintext_selection() -> Test {
    let fixture = Fixture::new(ProbeCodec::Avc, true)?;
    let options = options(&fixture, ProbeCodec::Avc);
    fs::remove_file(&fixture.spec.source)?;
    let mut manifest = fixture.manifest.clone();
    manifest.sources[0].owner_authorized = false;
    assert_eq!(preflight(&manifest, &options).err(), Some(SELECTION));
    manifest = fixture.manifest.clone();
    manifest.sources[0].plaintext = false;
    assert_eq!(preflight(&manifest, &options).err(), Some(SELECTION));
    manifest = fixture.manifest.clone();
    manifest.sources[0].kind = SourceKind::Rtsp;
    manifest.sources[0].presentation = Some("/live/main".into());
    manifest.sources[0].control_root = Some("/live".into());
    manifest.sources[0].onvif_service_path = None;
    manifest.validate()?;
    assert_eq!(preflight(&manifest, &options).err(), Some(SELECTION));
    let mut changed = options;
    changed.source = "source:unknown".into();
    assert_eq!(
        preflight(&fixture.manifest, &changed).err(),
        Some(SELECTION)
    );
    Ok(())
}

#[test]
fn command_namespace_guard_rejects_outputs_overlapping_inputs_or_any_source_credentials() -> Test {
    let fixture = Fixture::new(ProbeCodec::Avc, true)?;
    let options = options(&fixture, ProbeCodec::Avc);
    let document = document(&fixture, &[])?;
    let binding = probe_binding(&fixture.manifest, &document, &options.source)?;
    let (bindings_file, receipt_file) = preflight(&fixture.manifest, &options)?;
    check_paths(&fixture.manifest, &binding, bindings_file, &receipt_file)?;
    for collision in [
        fixture.spec.source.clone(),
        fixture.spec.source.join("child.json"),
        fixture
            .spec
            .source
            .parent()
            .ok_or("handoff parent")?
            .to_path_buf(),
        bindings_file.to_path_buf(),
        bindings_file.join("child.json"),
        bindings_file
            .parent()
            .ok_or("bindings parent")?
            .to_path_buf(),
    ] {
        assert_eq!(
            check_paths(&fixture.manifest, &binding, bindings_file, &collision),
            Err(INPUT)
        );
    }
    for credential_file in [
        fixture.spec.source.clone(),
        fixture.spec.source.join("credential"),
        fixture
            .spec
            .source
            .parent()
            .ok_or("handoff parent")?
            .to_path_buf(),
        receipt_file.clone(),
        receipt_file.join("credential"),
        receipt_file.parent().ok_or("receipt parent")?.to_path_buf(),
    ] {
        let mut manifest = fixture.manifest.clone();
        let mut excluded = manifest.sources[0].clone();
        excluded.source_id = "source:excluded-credential-owner".into();
        excluded.peer = "192.0.2.99:80".parse()?;
        excluded.authority = "excluded.example:80".into();
        excluded.owner_authorized = false;
        excluded.authentication = Some(fss_reference::site::SiteAuthentication {
            credential_file,
            realm: "excluded-private-realm".into(),
            legacy_md5: false,
            legacy_no_qop: false,
        });
        manifest.sources.push(excluded);
        manifest.validate()?;
        assert_eq!(
            check_paths(&manifest, &binding, bindings_file, &receipt_file),
            Err(INPUT)
        );
    }
    // None of these namespace decisions needs a bindings or credential read.
    assert!(!bindings_file.exists());
    assert!(!receipt_file.exists());
    assert_eq!(
        ContentDigest::sha256(&fs::read(&fixture.spec.source)?),
        fixture.spec.expected
    );
    Ok(())
}

#[test]
fn canonical_create_only_output_refuses_an_aliased_bindings_destination() -> Test {
    let fixture = Fixture::new(ProbeCodec::Avc, true)?;
    let mut options = options(&fixture, ProbeCodec::Avc);
    let bytes = document(&fixture, &[])?;
    let canonical_bindings = options.onvif_bindings.clone().ok_or("bindings path")?;
    write_private(&canonical_bindings, &bytes)?;
    let alias_parent = fixture.directory.join("alias-parent");
    fs::create_dir(&alias_parent)?;
    options.onvif_bindings = Some(alias_parent.join("../bindings.json"));
    options.receipt_file = Some(canonical_bindings.clone());
    let (bindings, receipt) = preflight(&fixture.manifest, &options)?;
    let binding = probe_binding(&fixture.manifest, &bytes, &options.source)?;
    assert_eq!(bindings.canonicalize()?, canonical_bindings);
    // A lexical alias cannot weaken the actual private output owner's create-only gate.
    check_paths(&fixture.manifest, &binding, bindings, &receipt)?;
    assert!(prepared(&fixture, &options, &bytes).is_err());
    assert_eq!(fs::read(&canonical_bindings)?, bytes);
    Ok(())
}
