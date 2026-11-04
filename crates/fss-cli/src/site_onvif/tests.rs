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
