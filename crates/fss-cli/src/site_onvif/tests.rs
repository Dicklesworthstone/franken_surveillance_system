#![forbid(unsafe_code)]
//! Actual bounded private-file ownership and strict original-manifest binding contracts.

use super::*;
use crate::json_output::{array, object, string};
use crate::site_plan::onvif_tests::{Fixture, Test};
use fss_reference::site::ProbeCodec;
use std::cell::Cell;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};

fn parents(fixture: &Fixture) -> Test {
    fs::create_dir(&fixture.options.archive_root)?;
    fs::create_dir(&fixture.options.pins_root)?;
    Ok(())
}

fn selected_fixture() -> Test<Fixture> {
    let mut fixture = Fixture::new(ProbeCodec::Avc, true)?;
    let mut selected = fixture.manifest.sources[0].clone();
    selected.source_id = "source:onvif-selected".to_owned();
    let mut excluded = selected.clone();
    excluded.source_id = "source:excluded".to_owned();
    excluded.owner_authorized = false;
    let mut direct = selected.clone();
    direct.source_id = "source:direct".to_owned();
    direct.kind = SourceKind::Rtsp;
    direct.peer = fixture.receipts[0].peer;
    direct.authority = fixture.receipts[0].authority.clone();
    direct.presentation = Some("/direct".to_owned());
    direct.control_root = Some("/direct".to_owned());
    direct.onvif_service_path = None;
    fixture.manifest.sources = vec![excluded, direct, selected];
    fixture.receipts[0].source_id = "source:onvif-selected".to_owned();
    fixture.rebind()?;
    Ok(fixture)
}

fn binding_row(fixture: &Fixture, source_id: &str) -> Test<String> {
    let input = fixture.input();
    Ok(object(&[
        ("source_id", string(source_id)),
        (
            "source_file",
            string(input.spec.source.to_str().ok_or("fixture path")?),
        ),
        ("source_digest", string(&input.spec.expected.to_text())),
        ("onboarding_plan", string(&input.onboarding_plan.to_text())),
        ("profile_digest", string(&input.profile_digest.to_text())),
        ("rtsp_peer", string(&input.peer.to_string())),
        ("rtsp_authority", string(input.authority)),
        ("control_root", string(input.control_root)),
    ]))
}

fn binding_document(fixture: &Fixture, rows: &[String]) -> Test<Vec<u8>> {
    Ok(object(&[
        ("schema", string(SITE_ONVIF_BINDINGS_SCHEMA)),
        (
            "manifest_digest",
            string(&fixture.manifest.digest()?.to_text()),
        ),
        ("sources", array(rows)),
    ])
    .into_bytes())
}

fn selected_owned(
    fixture: &Fixture,
    source_ids: &[String],
    onvif_json: &[u8],
    unifi_json: Option<&[u8]>,
    checkpoint: &impl Fn() -> Result<(), &'static str>,
) -> Result<crate::site_plan::SitePlan, SitePlanError> {
    let (onvif, unifi) = crate::site_unifi::prepare_selected_onvif_bindings(
        &fixture.manifest,
        &fixture.receipts,
        &fixture.options,
        source_ids,
        onvif_json,
        unifi_json,
    )?;
    crate::site_unifi::compile_owned_selected_with_onvif(
        &fixture.manifest,
        &fixture.receipts,
        &fixture.options,
        source_ids,
        &onvif,
        unifi.as_ref(),
        checkpoint,
    )
}

#[test]
fn selected_handoff_bindings_preserve_full_manifest_identity_and_original_ordinals() -> Test {
    let mut fixture = selected_fixture()?;
    let row = binding_row(&fixture, "source:onvif-selected")?;
    let bytes = binding_document(&fixture, std::slice::from_ref(&row))?;
    let parsed = parse_selected_bindings(&fixture.manifest, &bytes, &[2])?;
    assert_eq!(parsed.sources.len(), 1);
    assert_eq!(parsed.sources[0].source_index, 2);
    assert_eq!(parsed.sources[0].source_id, "source:onvif-selected");
    assert_eq!(parsed.sources[0].peer.port(), 554);
    assert_eq!(fixture.manifest.sources[2].peer.port(), 80);
    let whole = parse_bindings(&fixture.manifest, &bytes)
        .err()
        .ok_or("default parser accepted a subset")?;
    assert_eq!(whole.source_index, Some(0));
    let missing =
        parse_selected_bindings(&fixture.manifest, &binding_document(&fixture, &[])?, &[2])
            .err()
            .ok_or("missing selected handoff binding accepted")?;
    assert_eq!(missing.source_index, Some(2));
    let reverse = binding_document(&fixture, &[row, binding_row(&fixture, "source:excluded")?])?;
    let parsed = parse_selected_bindings(&fixture.manifest, &reverse, &[0, 2])?;
    assert_eq!(
        parsed
            .sources
            .iter()
            .map(|s| s.source_index)
            .collect::<Vec<_>>(),
        vec![0, 2]
    );
    fixture.manifest.sources[0].generation += 1;
    let stale = parse_selected_bindings(&fixture.manifest, &bytes, &[2])
        .err()
        .ok_or("excluded source mutation did not stale bindings")?;
    assert_eq!(stale.reason, "binding manifest digest is stale");
    Ok(())
}

#[test]
fn selected_scope_and_receipt_refusals_precede_every_private_read() -> Test {
    let mut fixture = selected_fixture()?;
    let ids = vec!["source:onvif-selected".to_owned()];
    let row = binding_row(&fixture, "source:onvif-selected")?;
    let valid = binding_document(&fixture, std::slice::from_ref(&row))?;
    let checkpoints = Cell::new(0_u32);
    let check = || {
        checkpoints.set(checkpoints.get() + 1);
        Err("private read must not be reached")
    };
    for invalid_ids in [
        vec![],
        vec!["source:foreign".to_owned()],
        vec![
            "source:onvif-selected".to_owned(),
            "source:onvif-selected".to_owned(),
        ],
    ] {
        assert!(selected_owned(&fixture, &invalid_ids, &valid, None, &check).is_err());
        assert_eq!(checkpoints.get(), 0);
    }
    for rows in [
        vec![],
        vec![row.clone(), row.clone()],
        vec![row.clone(), binding_row(&fixture, "source:excluded")?],
        vec![row, binding_row(&fixture, "source:foreign")?],
    ] {
        let error = selected_owned(
            &fixture,
            &ids,
            &binding_document(&fixture, &rows)?,
            None,
            &check,
        )
        .err()
        .ok_or("binding scope accepted")?;
        assert_eq!(error.code, ERR_SITE_ONVIF_INPUT);
        assert_eq!(checkpoints.get(), 0);
        assert!(!format!("{error:?}").contains("source:foreign"));
    }
    let receipt = fixture.receipts[0].clone();
    for source_id in ["source:foreign", "source:excluded"] {
        fixture.receipts[0].source_id = source_id.to_owned();
        assert!(selected_owned(&fixture, &ids, &valid, None, &check).is_err());
        assert_eq!(checkpoints.get(), 0);
    }
    fixture.receipts = vec![receipt.clone(), receipt.clone()];
    assert!(selected_owned(&fixture, &ids, &valid, None, &check).is_err());
    fixture.receipts.clear();
    assert!(selected_owned(&fixture, &ids, &valid, None, &check).is_err());
    fixture.receipts = vec![receipt];
    fixture.receipts[0].source_generation += 1;
    assert!(selected_owned(&fixture, &ids, &valid, None, &check).is_err());
    assert_eq!(checkpoints.get(), 0);
    Ok(())
}

#[test]
fn selected_owner_accepts_independent_rtsp_scope_and_exact_native_approval() -> Test {
    let fixture = selected_fixture()?;
    parents(&fixture)?;
    let ids = vec!["source:onvif-selected".to_owned()];
    let bytes = binding_document(&fixture, &[binding_row(&fixture, "source:onvif-selected")?])?;
    assert!(fixture.receipts[0].validate_for(&fixture.manifest).is_err());
    let plan = selected_owned(&fixture, &ids, &bytes, None, &|| Ok(()))?;
    assert_eq!(plan.sources().len(), 1);
    assert_eq!(plan.sources()[0].source_index(), 2);
    assert_eq!(plan.sources()[0].argv()[0], "from-onvif");
    let mut input = fixture.input();
    input.source_id = "source:onvif-selected";
    let exact = crate::site_plan::compile_selected_with_sources(
        &fixture.manifest,
        &fixture.receipts,
        &fixture.options,
        &ids,
        &[],
        &[input],
    )?;
    assert_eq!(plan.approval(), exact.approval());
    assert_eq!(plan.render_json(), exact.render_json());
    assert!(
        plan.render_json()
            .contains(&fixture.manifest.digest()?.to_text())
    );
    for canary in [
        "PRIVATE_CAPABILITY_CANARY",
        "PRIVATE_QUERY_CANARY",
        "PRIVATE_PROFILE_TOKEN_CANARY",
    ] {
        assert!(!plan.render_json().contains(canary));
    }
    assert!(
        fs::read_dir(&fixture.options.archive_root)?
            .next()
            .is_none()
    );
    assert!(fs::read_dir(&fixture.options.pins_root)?.next().is_none());
    Ok(())
}

#[test]
fn selected_handoffs_still_protect_excluded_source_credentials_and_output_namespaces() -> Test {
    let mut fixture = selected_fixture()?;
    parents(&fixture)?;
    let ids = vec!["source:onvif-selected".to_owned()];
    fixture.manifest.sources[0].authentication = Some(fss_reference::site::SiteAuthentication {
        credential_file: fixture.spec.source.clone(),
        realm: "fixture".to_owned(),
        legacy_md5: false,
        legacy_no_qop: false,
    });
    fixture.rebind()?;
    let checks = Cell::new(0);
    let bytes = binding_document(&fixture, &[binding_row(&fixture, "source:onvif-selected")?])?;
    let error = selected_owned(&fixture, &ids, &bytes, None, &|| {
        checks.set(checks.get() + 1);
        Err("credential read forbidden")
    })
    .err()
    .ok_or("excluded credentials read as a handoff")?;
    assert_eq!(error.source_index, Some(2));
    assert_eq!(checks.get(), 0);
    fixture.manifest.sources[0]
        .authentication
        .as_mut()
        .ok_or("fixture authentication")?
        .credential_file = fixture.options.pins_root.join("credential");
    fixture.rebind()?;
    let bytes = binding_document(&fixture, &[binding_row(&fixture, "source:onvif-selected")?])?;
    let error = selected_owned(&fixture, &ids, &bytes, None, &|| Ok(()))
        .err()
        .ok_or("excluded credential output namespace unprotected")?;
    assert_eq!(error.source_index, Some(0));
    assert!(
        fs::read_dir(&fixture.options.archive_root)?
            .next()
            .is_none()
    );
    assert!(fs::read_dir(&fixture.options.pins_root)?.next().is_none());
    Ok(())
}

#[test]
fn selected_handoff_revalidation_and_revoked_owner_never_release_a_plan() -> Test {
    let fixture = selected_fixture()?;
    parents(&fixture)?;
    let ids = vec!["source:onvif-selected".to_owned()];
    let bytes = binding_document(&fixture, &[binding_row(&fixture, "source:onvif-selected")?])?;
    assert!(selected_owned(&fixture, &ids, &bytes, None, &|| Err("revoked")).is_err());
    let boundaries = Cell::new(0);
    selected_owned(&fixture, &ids, &bytes, None, &|| {
        boundaries.set(boundaries.get() + 1);
        Ok(())
    })?;
    let last_metadata_check = boundaries.get() - 3;
    boundaries.set(0);
    let error = selected_owned(&fixture, &ids, &bytes, None, &|| {
        boundaries.set(boundaries.get() + 1);
        if boundaries.get() == last_metadata_check {
            OpenOptions::new()
                .append(true)
                .open(&fixture.spec.source)
                .and_then(|mut file| file.write_all(b" "))
                .map_err(|_| "fixture mutation")?;
        }
        Ok(())
    })
    .err()
    .ok_or("changed handoff escaped final revalidation")?;
    assert_eq!(error.source_index, Some(2));
    assert_eq!(
        error.reason,
        "protected handoff changed before plan release"
    );
    Ok(())
}

#[test]
fn binding_parser_is_exact_complete_and_original_manifest_pinned() -> Test {
    let fixture = Fixture::new(ProbeCodec::Avc, false)?;
    let document = fixture.binding_document()?;
    let parsed = parse_bindings(&fixture.manifest, &document)?;
    assert_eq!(parsed.sources.len(), 1);
    assert_eq!(parsed.sources[0].source_index, 0);
    assert_eq!(parsed.sources[0].peer.port(), 554);
    assert_eq!(fixture.manifest.sources[0].peer.port(), 80);
    let original = std::str::from_utf8(&document)?;
    for changed in [
        original.replace("fss.site_onvif_bindings.v1", "fss.site_onvif_bindings.v2"),
        original.replace("\"rtsp_peer\"", "\"unapproved_peer\""),
        original.replace("source:front", "source:foreign"),
        original.replace(
            &fixture.manifest.digest()?.to_text(),
            &ContentDigest::sha256(b"stale").to_text(),
        ),
        original.replace(
            "\"rtsp_peer\":\"192.0.2.10:554\"",
            "\"rtsp_peer\":\"camera.example:554\"",
        ),
        original.replace("\"profile_digest\":", "\"extra\":true,\"profile_digest\":"),
        original.replace("\"sources\":[", "\"sources\":[],\"extra\":["),
    ] {
        let error = parse_bindings(&fixture.manifest, changed.as_bytes())
            .err()
            .ok_or("strict binding refusal")?;
        assert!(!format!("{error:?} {error}").contains("PRIVATE_CAPABILITY_CANARY"));
    }
    let value = json_input::parse(original)?;
    let source = value
        .object()
        .ok_or("object")?
        .get("sources")
        .and_then(Value::array)
        .ok_or("sources")?;
    assert_eq!(source.len(), 1);
    let row = original
        .split("\"sources\":[")
        .nth(1)
        .ok_or("sources")?
        .strip_suffix("]}")
        .ok_or("document end")?;
    let duplicate = object(&[
        ("schema", string(SITE_ONVIF_BINDINGS_SCHEMA)),
        (
            "manifest_digest",
            string(&fixture.manifest.digest()?.to_text()),
        ),
        ("sources", array(&[row.to_owned(), row.to_owned()])),
    ]);
    assert!(parse_bindings(&fixture.manifest, duplicate.as_bytes()).is_err());
    assert!(
        parse_bindings(
            &fixture.manifest,
            &vec![b' '; MAX_SITE_ONVIF_BINDINGS_BYTES + 1]
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn actual_private_input_owner_produces_the_same_complete_plan_and_spends_read_boundaries() -> Test {
    let fixture = Fixture::new(ProbeCodec::Avc, false)?;
    parents(&fixture)?;
    let bindings = parse_bindings(&fixture.manifest, &fixture.binding_document()?)?;
    check_paths(&fixture.manifest, &bindings, &fixture.options)?;
    let count = Cell::new(0_u32);
    let checkpoint = || {
        count.set(count.get() + 1);
        Ok(())
    };
    let plan = crate::site_unifi::compile_owned_with_onvif(
        &fixture.manifest,
        &fixture.receipts,
        &fixture.options,
        &bindings,
        None,
        &checkpoint,
    )?;
    assert_eq!(plan.render_json(), fixture.compile()?.render_json());
    assert!(count.get() > 10);
    assert!(
        fs::read_dir(&fixture.options.archive_root)?
            .next()
            .is_none()
    );
    assert!(fs::read_dir(&fixture.options.pins_root)?.next().is_none());
    assert!(OwnedInputs::open(&bindings, &fixture.options, &|| Err("expired")).is_err());
    Ok(())
}

#[test]
fn protected_file_permissions_digest_symlink_and_replacement_are_enforced() -> Test {
    let fixture = Fixture::new(ProbeCodec::Avc, false)?;
    parents(&fixture)?;
    let bindings = parse_bindings(&fixture.manifest, &fixture.binding_document()?)?;
    let owned = OwnedInputs::open(&bindings, &fixture.options, &|| Ok(()))?;
    fs::rename(
        &fixture.spec.source,
        fixture.directory.join("old-handoff.json"),
    )?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&fixture.spec.source)?;
    file.write_all(fixture.input().input.bytes)?;
    drop(file);
    assert!(owned.revalidate(&fixture.options, &|| Ok(())).is_err());
    fs::set_permissions(&fixture.spec.source, fs::Permissions::from_mode(0o644))?;
    assert!(OwnedInputs::open(&bindings, &fixture.options, &|| Ok(())).is_err());
    fs::set_permissions(&fixture.spec.source, fs::Permissions::from_mode(0o600))?;
    fs::write(&fixture.spec.source, b"{}").map_err(Box::<dyn std::error::Error>::from)?;
    assert!(OwnedInputs::open(&bindings, &fixture.options, &|| Ok(())).is_err());
    fs::remove_file(&fixture.spec.source)?;
    symlink(
        fixture.directory.join("old-handoff.json"),
        &fixture.spec.source,
    )?;
    assert!(OwnedInputs::open(&bindings, &fixture.options, &|| Ok(())).is_err());
    Ok(())
}

#[test]
fn outputs_and_credential_namespaces_cannot_contain_protected_handoffs() -> Test {
    let fixture = Fixture::new(ProbeCodec::Avc, false)?;
    parents(&fixture)?;
    let bindings = parse_bindings(&fixture.manifest, &fixture.binding_document()?)?;
    let mut options = fixture.options.clone();
    options.archive_root = fixture.directory.clone();
    assert!(check_paths(&fixture.manifest, &bindings, &options).is_err());
    let alias = fixture.directory.join("output-alias");
    symlink(&fixture.directory, &alias)?;
    options.archive_root = alias;
    assert!(check_paths(&fixture.manifest, &bindings, &options).is_ok());
    assert!(OwnedInputs::open(&bindings, &options, &|| Ok(())).is_err());
    let mut manifest = fixture.manifest.clone();
    manifest.sources[0].authentication = Some(fss_reference::site::SiteAuthentication {
        credential_file: fixture.spec.source.clone(),
        realm: "camera".to_owned(),
        legacy_md5: false,
        legacy_no_qop: false,
    });
    assert!(check_paths(&manifest, &bindings, &fixture.options).is_err());
    Ok(())
}

#[test]
fn mixed_onvif_and_unifi_files_stay_owned_through_atomic_compilation() -> Test {
    let mut fixture = Fixture::new(ProbeCodec::Avc, true)?;
    parents(&fixture)?;
    let export = br#"{"camera":{"id":"PRIVATE_CAMERA_CANARY"},"streams":{"high":"rtsps://192.0.2.11:7441/PRIVATE_UNIFI_ROUTE_CANARY?enableSrtp"},"rtsp":{"high":"rtsp://192.0.2.11:7447/PRIVATE_UNIFI_ROUTE_CANARY"}}"#;
    let file_path = fixture.directory.join("export.json");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&file_path)?;
    file.write_all(export)?;
    drop(file);
    let mut source = fixture.manifest.sources[0].clone();
    source.source_id = "source:unifi".to_owned();
    source.kind = SourceKind::UnifiProtect;
    source.peer = "192.0.2.11:7447".parse()?;
    source.authority = source.peer.to_string();
    source.onvif_service_path = None;
    source.unifi_camera_id = Some("PRIVATE_CAMERA_CANARY".to_owned());
    let mut receipt = fixture.receipts[0].clone();
    receipt.source_id = source.source_id.clone();
    receipt.peer = source.peer;
    receipt.authority = source.authority.clone();
    receipt.presentation = "/PRIVATE_UNIFI_ROUTE_CANARY".to_owned();
    receipt.control_root = receipt.presentation.clone();
    fixture.manifest.sources.push(source);
    fixture.receipts.push(receipt);
    fixture.rebind()?;
    let onvif = parse_bindings(&fixture.manifest, &fixture.binding_document()?)?;
    let unifi_json = object(&[
        (
            "schema",
            string(crate::site_unifi::SITE_UNIFI_BINDINGS_SCHEMA),
        ),
        (
            "manifest_digest",
            string(&fixture.manifest.digest()?.to_text()),
        ),
        (
            "sources",
            array(&[object(&[
                ("source_id", string("source:unifi")),
                (
                    "source_file",
                    string(file_path.to_str().ok_or("fixture path")?),
                ),
                (
                    "source_digest",
                    string(&ContentDigest::sha256(export).to_text()),
                ),
                ("quality", string("high")),
                ("stream_transport", string("operator-rtsp")),
            ])]),
        ),
    ]);
    let unifi = crate::site_unifi::parse_bindings(&fixture.manifest, unifi_json.as_bytes())?;
    let plan = crate::site_unifi::compile_owned_with_onvif(
        &fixture.manifest,
        &fixture.receipts,
        &fixture.options,
        &onvif,
        Some(&unifi),
        &|| Ok(()),
    )?;
    assert_eq!(plan.sources().len(), 2);
    assert_eq!(plan.sources()[0].argv()[0], "from-onvif");
    assert_eq!(plan.sources()[1].argv()[0], "from-unifi");
    for canary in [
        "PRIVATE_CAMERA_CANARY",
        "PRIVATE_UNIFI_ROUTE_CANARY",
        "PRIVATE_CAPABILITY_CANARY",
        "PRIVATE_QUERY_CANARY",
    ] {
        assert!(!plan.render_json().contains(canary));
    }
    assert!(
        crate::site_unifi::compile_owned_with_onvif(
            &fixture.manifest,
            &fixture.receipts,
            &fixture.options,
            &onvif,
            None,
            &|| Ok(()),
        )
        .is_err()
    );
    fs::write(file_path, b"{}")?;
    assert!(
        crate::site_unifi::compile_owned_with_onvif(
            &fixture.manifest,
            &fixture.receipts,
            &fixture.options,
            &onvif,
            Some(&unifi),
            &|| Ok(()),
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn selected_mixed_bindings_are_exact_and_both_private_owners_remain_active() -> Test {
    let mut fixture = selected_fixture()?;
    parents(&fixture)?;
    let export = br#"{"camera":{"id":"PRIVATE_CAMERA_CANARY"},"streams":{"high":"rtsps://192.0.2.11:7441/PRIVATE_UNIFI_ROUTE_CANARY?enableSrtp"},"rtsp":{"high":"rtsp://192.0.2.11:7447/PRIVATE_UNIFI_ROUTE_CANARY"}}"#;
    let file_path = fixture.directory.join("selected-export.json");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&file_path)?;
    file.write_all(export)?;
    drop(file);
    let mut source = fixture.manifest.sources[2].clone();
    source.source_id = "source:unifi-selected".to_owned();
    source.kind = SourceKind::UnifiProtect;
    source.peer = "192.0.2.11:7447".parse()?;
    source.authority = source.peer.to_string();
    source.onvif_service_path = None;
    source.unifi_camera_id = Some("PRIVATE_CAMERA_CANARY".to_owned());
    let mut receipt = fixture.receipts[0].clone();
    receipt.source_id = source.source_id.clone();
    receipt.peer = source.peer;
    receipt.authority = source.authority.clone();
    receipt.presentation = "/PRIVATE_UNIFI_ROUTE_CANARY".to_owned();
    receipt.control_root = receipt.presentation.clone();
    fixture.manifest.sources.push(source);
    fixture.receipts.push(receipt);
    fixture.rebind()?;
    let onvif_json =
        binding_document(&fixture, &[binding_row(&fixture, "source:onvif-selected")?])?;
    let unifi_json = object(&[
        (
            "schema",
            string(crate::site_unifi::SITE_UNIFI_BINDINGS_SCHEMA),
        ),
        (
            "manifest_digest",
            string(&fixture.manifest.digest()?.to_text()),
        ),
        (
            "sources",
            array(&[object(&[
                ("source_id", string("source:unifi-selected")),
                (
                    "source_file",
                    string(file_path.to_str().ok_or("fixture path")?),
                ),
                (
                    "source_digest",
                    string(&ContentDigest::sha256(export).to_text()),
                ),
                ("quality", string("high")),
                ("stream_transport", string("operator-rtsp")),
            ])]),
        ),
    ]);
    let ids = vec![
        "source:unifi-selected".to_owned(),
        "source:onvif-selected".to_owned(),
    ];
    let checks = Cell::new(0);
    let checkpoint = || {
        checks.set(checks.get() + 1);
        Err("private read must not be reached")
    };
    let missing = selected_owned(&fixture, &ids, &onvif_json, None, &checkpoint)
        .err()
        .ok_or("missing UniFi document reached a private read")?;
    assert_eq!(missing.source_index, Some(3));
    assert_eq!(checks.get(), 0);
    let extra = selected_owned(
        &fixture,
        &["source:onvif-selected".to_owned()],
        &onvif_json,
        Some(unifi_json.as_bytes()),
        &checkpoint,
    )
    .err()
    .ok_or("unselected UniFi document was silently consumed")?;
    assert_eq!(extra.source_index, Some(3));
    assert_eq!(checks.get(), 0);

    let plan = selected_owned(
        &fixture,
        &ids,
        &onvif_json,
        Some(unifi_json.as_bytes()),
        &|| Ok(()),
    )?;
    assert_eq!(plan.sources().len(), 2);
    assert_eq!(plan.sources()[0].source_index(), 2);
    assert_eq!(plan.sources()[0].argv()[0], "from-onvif");
    assert_eq!(plan.sources()[1].source_index(), 3);
    assert_eq!(plan.sources()[1].argv()[0], "from-unifi");
    for canary in [
        "PRIVATE_CAMERA_CANARY",
        "PRIVATE_UNIFI_ROUTE_CANARY",
        "PRIVATE_CAPABILITY_CANARY",
        "PRIVATE_QUERY_CANARY",
    ] {
        assert!(!plan.render_json().contains(canary));
    }
    // A late refusal in the second protected owner never releases the already
    // compiled first source or loses its original source index.
    fs::write(&file_path, b"{}")?;
    let error = selected_owned(
        &fixture,
        &ids,
        &onvif_json,
        Some(unifi_json.as_bytes()),
        &|| Ok(()),
    )
    .err()
    .ok_or("changed second protected input released a plan prefix")?;
    assert_eq!(error.source_index, Some(3));
    assert!(
        fs::read_dir(&fixture.options.archive_root)?
            .next()
            .is_none()
    );
    assert!(fs::read_dir(&fixture.options.pins_root)?.next().is_none());
    Ok(())
}

#[test]
fn runtime_selected_onvif_wrapper_matches_protected_compilation() -> Test {
    let fixture = selected_fixture()?;
    parents(&fixture)?;
    let ids = vec!["source:onvif-selected".to_owned()];
    let bytes = binding_document(&fixture, &[binding_row(&fixture, "source:onvif-selected")?])?;
    let expected = selected_owned(&fixture, &ids, &bytes, None, &|| Ok(()))?;
    let actual = crate::site_unifi::compile_selected_with_onvif_bindings(
        &fixture.manifest,
        &fixture.receipts,
        &fixture.options,
        &ids,
        &bytes,
        None,
    )?;
    assert_eq!(actual.approval(), expected.approval());
    assert_eq!(actual.render_json(), expected.render_json());
    Ok(())
}
