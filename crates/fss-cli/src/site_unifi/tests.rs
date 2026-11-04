#![forbid(unsafe_code)]
//! Binding and protected-input contracts over synthetic owner-created files only.

use super::*;
use crate::json_output::{array, object, string};
use std::path::PathBuf;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

const EXPORT: &[u8] = br#"{"camera":{"id":"PRIVATE_CAMERA_ID_CANARY","name":"PRIVATE_CAMERA_NAME_CANARY","hasPackageCamera":true},"streams":{"high":"rtsps://192.0.2.7:7441/PRIVATE_STREAM_CAPABILITY_CANARY?enableSrtp"},"rtsp":{"high":"rtsp://192.0.2.7:7447/PRIVATE_STREAM_CAPABILITY_CANARY"}}"#;

fn manifest() -> Test<SiteManifest> {
    let mut manifest = SiteManifest::parse(include_str!(
        "../../../../fixtures/site_probe/manifest.v1.json"
    ))?;
    let source = &mut manifest.sources[0];
    source.kind = SourceKind::UnifiProtect;
    source.peer = "192.0.2.7:7447".parse()?;
    source.authority = source.peer.to_string();
    source.presentation = None;
    source.control_root = None;
    source.unifi_camera_id = Some("PRIVATE_CAMERA_ID_CANARY".to_owned());
    manifest.validate()?;
    Ok(manifest)
}

fn options(root: &Path) -> SitePlanOptions {
    SitePlanOptions {
        epoch: 7,
        archive_root: root.join("archives"),
        pins_root: root.join("pins"),
        principal: "principal:local-operator".to_owned(),
        stop_after_pictures: 3,
    }
}

fn row(source_id: &str, path: &Path, bytes: &[u8]) -> Test<String> {
    Ok(object(&[
        ("source_id", string(source_id)),
        (
            "source_file",
            string(path.to_str().ok_or("fixture UTF-8 path")?),
        ),
        (
            "source_digest",
            string(&ContentDigest::sha256(bytes).to_text()),
        ),
        ("quality", string("high")),
        ("stream_transport", string("operator-rtsp")),
    ]))
}

fn document(manifest: &SiteManifest, rows: &[String]) -> Test<Vec<u8>> {
    Ok(object(&[
        ("schema", string(SITE_UNIFI_BINDINGS_SCHEMA)),
        ("manifest_digest", string(&manifest.digest()?.to_text())),
        ("sources", array(rows)),
    ])
    .into_bytes())
}

fn receipts(manifest: &SiteManifest) -> Test<Vec<SiteProbeReceipt>> {
    let mut receipt = fss_reference::site::parse_probe_receipts(include_bytes!(
        "../../../../fixtures/site/probes.v1.json"
    ))?
    .remove(0);
    let source = &manifest.sources[0];
    receipt.site_id = manifest.site_id.clone();
    receipt.source_id = source.source_id.clone();
    receipt.manifest_digest = manifest.digest()?;
    receipt.source_generation = source.generation;
    receipt.peer = source.peer;
    receipt.authority = source.authority.clone();
    receipt.presentation = "/PRIVATE_STREAM_CAPABILITY_CANARY".to_owned();
    receipt.control_root = receipt.presentation.clone();
    receipt.validate_for(manifest)?;
    Ok(vec![receipt])
}

#[test]
fn strict_bindings_cover_only_unifi_sources_and_follow_manifest_order() -> Test {
    let mut manifest = manifest()?;
    let mut direct = manifest.sources[0].clone();
    direct.source_id = "source:direct".to_owned();
    direct.kind = SourceKind::Rtsp;
    direct.presentation = Some("/direct".to_owned());
    direct.control_root = Some("/direct".to_owned());
    direct.unifi_camera_id = None;
    manifest.sources.push(direct);
    let mut second = manifest.sources[0].clone();
    second.source_id = "source:second".to_owned();
    second.unifi_camera_id = Some("camera:second".to_owned());
    manifest.sources.push(second);
    let first = row("source:front", Path::new("/private/first.json"), EXPORT)?;
    let second = row("source:second", Path::new("/private/second.json"), EXPORT)?;
    let parsed = parse_bindings(&manifest, &document(&manifest, &[second, first])?)?;
    assert_eq!(parsed.sources.len(), 2);
    assert_eq!(parsed.sources[0].source_index, 0);
    assert_eq!(parsed.sources[1].source_index, 2);
    assert_eq!(parsed.sources[0].spec.peer, manifest.sources[0].peer);
    assert_eq!(parsed.sources[1].spec.quality, ProtectQuality::High);
    assert_eq!(
        parsed.sources[1].spec.transport,
        TransportChoice::OperatorRtsp
    );
    let no_sources = parse_bindings(&manifest, &document(&manifest, &[])?)
        .err()
        .ok_or("missing refusal")?;
    assert_eq!(no_sources.source_index, Some(0));
    Ok(())
}

#[test]
fn malformed_stale_duplicate_and_extra_bindings_are_non_disclosing() -> Test {
    let manifest = manifest()?;
    let row = row(
        "source:front",
        Path::new("/private/PRIVATE_PATH_CANARY.json"),
        EXPORT,
    )?;
    let valid = String::from_utf8(document(&manifest, std::slice::from_ref(&row))?)?;
    let stale = valid.replace(
        &manifest.digest()?.to_text(),
        &ContentDigest::sha256(b"stale").to_text(),
    );
    let duplicate = String::from_utf8(document(&manifest, &[row.clone(), row])?)?;
    for bad in [
        format!("{valid} trailing"),
        stale,
        duplicate,
        valid.replace("fss.site_unifi_bindings.v1", "fss.site_unifi_bindings.v2"),
        valid.replace("\"quality\":\"high\"", "\"quality\":\"automatic\""),
        valid.replace(
            "\"quality\":\"high\"",
            "\"quality\":\"high\",\"quality\":\"low\"",
        ),
        valid.replace(
            "\"quality\":\"high\"",
            "\"quality\":\"high\",\"api_key\":\"PRIVATE_KEY_CANARY\"",
        ),
        valid.replace("source:front", "source:unknown"),
        valid.replace("/private/PRIVATE_PATH_CANARY.json", "relative.json"),
        valid.replace(
            "/private/PRIVATE_PATH_CANARY.json",
            "/private/../PRIVATE_PATH_CANARY.json",
        ),
        valid.replace(
            &ContentDigest::sha256(EXPORT).to_text(),
            &format!("sha256:{}", "0".repeat(64)),
        ),
    ] {
        let error = parse_bindings(&manifest, bad.as_bytes())
            .err()
            .ok_or("invalid binding was accepted")?;
        assert_eq!(error.code, ERR_SITE_UNIFI_INPUT);
        for canary in [
            "PRIVATE_PATH_CANARY",
            "PRIVATE_KEY_CANARY",
            "source:unknown",
            "relative.json",
        ] {
            assert!(!format!("{error:?} {error}").contains(canary));
        }
    }
    assert!(parse_bindings(&manifest, &vec![b' '; MAX_SITE_UNIFI_BINDINGS_BYTES + 1]).is_err());
    Ok(())
}

#[test]
fn bindings_cannot_bypass_source_coverage_or_the_source_count_bound() -> Test {
    let mut manifest = manifest()?;
    let source = manifest.sources[0].clone();
    manifest.sources = (0..64)
        .map(|index| {
            let mut source = source.clone();
            source.source_id = format!("source:{index}");
            source.unifi_camera_id = Some(format!("camera:{index}"));
            source
        })
        .collect();
    let mut rows = manifest
        .sources
        .iter()
        .map(|source| row(&source.source_id, Path::new("/private/export.json"), EXPORT))
        .collect::<Test<Vec<_>>>()?;
    assert_eq!(
        parse_bindings(&manifest, &document(&manifest, &rows)?)?
            .sources
            .len(),
        64
    );
    rows.push(rows[0].clone());
    assert!(parse_bindings(&manifest, &document(&manifest, &rows)?).is_err());
    rows.truncate(63);
    let missing = parse_bindings(&manifest, &document(&manifest, &rows)?)
        .err()
        .ok_or("missing source accepted")?;
    assert_eq!(missing.source_index, Some(63));
    Ok(())
}

#[test]
fn lexical_destination_and_credential_overlap_refuse_without_file_access() -> Test {
    let mut manifest = manifest()?;
    let options = options(Path::new("/not-created-private-fixture"));
    for path in [
        options.archive_root.join("export.json"),
        options.pins_root.join("export.json"),
    ] {
        let document = document(&manifest, &[row("source:front", &path, EXPORT)?])?;
        let parsed = parse_bindings(&manifest, &document)?;
        let error = check_paths(&manifest, &parsed, &options)
            .err()
            .ok_or("overlapping path accepted")?;
        assert_eq!(error.source_index, Some(0));
    }
    let private_path = PathBuf::from("/not-created-private-fixture/credential");
    manifest.sources[0].authentication = Some(fss_reference::site::SiteAuthentication {
        credential_file: private_path.clone(),
        realm: "fixture".to_owned(),
        legacy_md5: false,
        legacy_no_qop: false,
    });
    let parsed = parse_bindings(
        &manifest,
        &document(&manifest, &[row("source:front", &private_path, EXPORT)?])?,
    )?;
    assert!(check_paths(&manifest, &parsed, &options).is_err());
    Ok(())
}

#[cfg(target_os = "linux")]
mod native {
    use super::*;
    use std::cell::Cell;
    use std::fs::{self, DirBuilder, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Test<Self> {
            let path = std::env::temp_dir().canonicalize()?.join(format!(
                "fss-site-unifi-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            DirBuilder::new().mode(0o700).create(&path)?;
            for name in ["archives", "pins"] {
                DirBuilder::new().mode(0o700).create(path.join(name))?;
            }
            Ok(Self(path))
        }
        fn file(&self, name: &str, bytes: &[u8]) -> Test<PathBuf> {
            let path = self.0.join(name);
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            file.write_all(bytes)?;
            Ok(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    // Exercise the real protected-file and compiler owners under a finite fixture
    // callback. The separate runtime-wrapper contract below exercises actual Cx
    // ownership when the complete runtime is available; this helper does not claim it.
    fn owned_plan(
        manifest: &SiteManifest,
        receipts: &[SiteProbeReceipt],
        options: &SitePlanOptions,
        bytes: &[u8],
    ) -> Result<SitePlan, SitePlanError> {
        let bindings = parse_bindings(manifest, bytes)?;
        check_paths(manifest, &bindings, options)?;
        let remaining = Cell::new(MAX_READ_OPERATIONS);
        compile_owned(manifest, receipts, options, &bindings, &|| {
            let budget = remaining
                .get()
                .checked_sub(1)
                .ok_or("fixture read budget")?;
            remaining.set(budget);
            Ok(())
        })
    }

    #[test]
    fn protected_plan_uses_actual_lease_identity_and_replacement_changes_approval() -> Test {
        let fixture = Fixture::new()?;
        let path = fixture.file("export.json", EXPORT)?;
        let manifest = manifest()?;
        let receipts = receipts(&manifest)?;
        let options = options(&fixture.0);
        let bytes = document(&manifest, &[row("source:front", &path, EXPORT)?])?;
        let first = owned_plan(&manifest, &receipts, &options, &bytes)?;
        let second = owned_plan(&manifest, &receipts, &options, &bytes)?;
        assert_eq!(first.approval(), second.approval());
        let bindings = parse_bindings(&manifest, &bytes)?;
        let lease = private_file::InputLease::open(&path, &|| Ok(()))?;
        let fingerprint = lease.fingerprint();
        let exact = site_plan::compile_with_unifi(
            &manifest,
            &receipts,
            &options,
            &[SiteUnifiInput {
                source_id: "source:front",
                spec: &bindings.sources[0].spec,
                input: ProtectedUnifiInput {
                    bytes: lease.bytes(),
                    fingerprint: &fingerprint,
                },
            }],
        )?;
        assert_eq!(first.approval(), exact.approval());
        drop(lease);
        let replacement = fixture.file("replacement.json", EXPORT)?;
        fs::rename(replacement, &path)?;
        let changed = owned_plan(&manifest, &receipts, &options, &bytes)?;
        assert_ne!(first.approval(), changed.approval());
        let rendered = changed.render_json();
        for canary in [
            "PRIVATE_STREAM_CAPABILITY_CANARY",
            "PRIVATE_CAMERA_ID_CANARY",
            "PRIVATE_CAMERA_NAME_CANARY",
        ] {
            assert!(!rendered.contains(canary));
        }
        assert_eq!(fs::read_dir(&options.archive_root)?.count(), 0);
        assert_eq!(fs::read_dir(&options.pins_root)?.count(), 0);
        Ok(())
    }

    #[test]
    fn private_permissions_aliases_and_wrong_digests_never_release_a_plan() -> Test {
        let fixture = Fixture::new()?;
        let path = fixture.file("export.json", EXPORT)?;
        let manifest = manifest()?;
        let receipts = receipts(&manifest)?;
        let options = options(&fixture.0);
        let check = |path: &Path, expected: &[u8]| -> Test<SitePlanError> {
            let bytes = document(&manifest, &[row("source:front", path, expected)?])?;
            owned_plan(&manifest, &receipts, &options, &bytes)
                .err()
                .ok_or_else(|| "unsafe protected input was accepted".into())
        };
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        assert_eq!(check(&path, EXPORT)?.source_index, Some(0));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let link = fixture.0.join("link.json");
        symlink(&path, &link)?;
        assert_eq!(check(&link, EXPORT)?.source_index, Some(0));
        let hardlink = fixture.0.join("hardlink.json");
        fs::hard_link(&path, &hardlink)?;
        assert_eq!(check(&path, EXPORT)?.source_index, Some(0));
        fs::remove_file(hardlink)?;
        let error = check(&path, b"different expected export")?;
        assert_eq!(
            error.reason,
            "protected export digest does not match its binding"
        );
        assert!(!format!("{error:?}").contains("export.json"));
        Ok(())
    }

    #[test]
    fn final_revalidation_refuses_a_file_changed_after_compilation() -> Test {
        let fixture = Fixture::new()?;
        let path = fixture.file("export.json", EXPORT)?;
        let manifest = manifest()?;
        let receipts = receipts(&manifest)?;
        let options = options(&fixture.0);
        let bindings = parse_bindings(
            &manifest,
            &document(&manifest, &[row("source:front", &path, EXPORT)?])?,
        )?;
        let boundaries = Cell::new(0);
        compile_owned(&manifest, &receipts, &options, &bindings, &|| {
            boundaries.set(boundaries.get() + 1);
            Ok(())
        })?;
        let final_check = boundaries.get() - 3;
        boundaries.set(0);
        let result = compile_owned(&manifest, &receipts, &options, &bindings, &|| {
            boundaries.set(boundaries.get() + 1);
            if boundaries.get() == final_check {
                OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .and_then(|mut file| file.write_all(b" "))
                    .map_err(|_| "fixture write")?;
            }
            Ok(())
        });
        let error = result.err().ok_or("changed export was released")?;
        assert_eq!(error.source_index, Some(0));
        assert_eq!(error.reason, "protected export changed before plan release");
        Ok(())
    }

    #[test]
    fn canonical_destination_alias_and_revoked_read_owner_refuse_without_output() -> Test {
        let fixture = Fixture::new()?;
        let path = fixture.file("export.json", EXPORT)?;
        let manifest = manifest()?;
        let receipts = receipts(&manifest)?;
        let bindings = parse_bindings(
            &manifest,
            &document(&manifest, &[row("source:front", &path, EXPORT)?])?,
        )?;
        let mut options = options(&fixture.0);
        let alias = fixture.0.join("archive-alias");
        symlink(&fixture.0, &alias)?;
        options.archive_root = alias;
        check_paths(&manifest, &bindings, &options)?;
        let error = compile_owned(&manifest, &receipts, &options, &bindings, &|| Ok(()))
            .err()
            .ok_or("canonical destination alias was accepted")?;
        assert_eq!(
            error.reason,
            "private export overlaps a canonical destination namespace"
        );
        let denied = compile_owned(&manifest, &receipts, &options, &bindings, &|| {
            Err("fixture revoked")
        })
        .err()
        .ok_or("revoked read owner was accepted")?;
        assert_eq!(denied.reason, "private input read authority expired");
        Ok(())
    }

    #[test]
    fn aggregate_export_reservation_stops_before_opening_an_over_budget_source() -> Test {
        let fixture = Fixture::new()?;
        let mut padded = EXPORT.to_vec();
        padded.resize(private_file::MAX_FILE_BYTES, b' ');
        let path = fixture.file("bounded.json", &padded)?;
        let mut manifest = manifest()?;
        let original = manifest.sources[0].clone();
        manifest.sources = (0..33)
            .map(|index| {
                let mut source = original.clone();
                source.source_id = format!("source:{index}");
                source
            })
            .collect();
        let rows = manifest
            .sources
            .iter()
            .map(|source| row(&source.source_id, &path, &padded))
            .collect::<Test<Vec<_>>>()?;
        let bindings = parse_bindings(&manifest, &document(&manifest, &rows)?)?;
        let error = compile_owned(&manifest, &[], &options(&fixture.0), &bindings, &|| Ok(()))
            .err()
            .ok_or("aggregate protected byte limit was ignored")?;
        assert_eq!(error.source_index, Some(32));
        assert_eq!(
            error.reason,
            "aggregate private input reservation exhausted"
        );
        Ok(())
    }

    #[test]
    fn runtime_owner_wrapper_matches_protected_compilation() -> Test {
        let fixture = Fixture::new()?;
        let path = fixture.file("export.json", EXPORT)?;
        let manifest = manifest()?;
        let receipts = receipts(&manifest)?;
        let options = options(&fixture.0);
        let bytes = document(&manifest, &[row("source:front", &path, EXPORT)?])?;
        let expected = owned_plan(&manifest, &receipts, &options, &bytes)?;
        let actual = compile_from_bindings(&manifest, &receipts, &options, &bytes)?;
        assert_eq!(actual.approval(), expected.approval());
        assert_eq!(actual.render_json(), expected.render_json());
        Ok(())
    }
}
