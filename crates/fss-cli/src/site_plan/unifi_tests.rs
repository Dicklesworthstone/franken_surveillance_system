#![forbid(unsafe_code)]
//! Pure compiler contracts with actual protected-file observations from synthetic fixtures.

use super::*;
use crate::capture_plan::prepare_unifi;
use fss_reference::site::{PaymentMask, parse_probe_receipts};
use fss_reference::unifi::TransportChoice;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::sync::atomic::{AtomicU64, Ordering};

#[allow(dead_code, unused_imports)]
#[path = "../bin/fss-onvif/private_file.rs"]
mod private_file;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
const CAMERA: &str = "PRIVATE_CAMERA_ID_CANARY";
const HIGH: &str = "/PRIVATE_HIGH_CAPABILITY_CANARY?opaque=%4a";
const MEDIUM: &str = "/PRIVATE_MEDIUM_CAPABILITY_CANARY";
const PACKAGE: &str = "/PRIVATE_PACKAGE_CAPABILITY_CANARY";
const EXPORT: &[u8] = br#"{"camera":{"id":"PRIVATE_CAMERA_ID_CANARY","name":"PRIVATE_CAMERA_NAME_CANARY","hasPackageCamera":true},"streams":{"high":"rtsps://192.0.2.7:7441/PRIVATE_HIGH_CAPABILITY_CANARY?enableSrtp","medium":"rtsps://192.0.2.7:7441/PRIVATE_MEDIUM_CAPABILITY_CANARY?enableSrtp","package":"rtsps://192.0.2.7:7441/PRIVATE_PACKAGE_CAPABILITY_CANARY?enableSrtp"},"rtsp":{"high":"rtsp://192.0.2.7:7447/PRIVATE_HIGH_CAPABILITY_CANARY?opaque=%4a","medium":"rtsp://192.0.2.7:7447/PRIVATE_MEDIUM_CAPABILITY_CANARY","package":"rtsp://192.0.2.7:7447/PRIVATE_PACKAGE_CAPABILITY_CANARY","low":null}}"#;

struct Fixture {
    directory: PathBuf,
    lease: private_file::InputLease,
    fingerprint: [u8; 88],
    spec: UnifiSourceSpec,
    manifest: SiteManifest,
    receipts: Vec<SiteProbeReceipt>,
    options: SitePlanOptions,
}

impl Fixture {
    fn new() -> Test<Self> {
        Self::with_export(EXPORT)
    }

    fn with_export(bytes: &[u8]) -> Test<Self> {
        let directory = std::env::temp_dir().canonicalize()?.join(format!(
            "fss-site-unifi-compiler-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&directory)?;
        let source_file = directory.join("export.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&source_file)?;
        file.write_all(bytes)?;
        drop(file);
        let lease = private_file::InputLease::open(&source_file, &|| Ok(()))?;
        let fingerprint = lease.fingerprint();
        let mut manifest = SiteManifest::parse(include_str!(
            "../../../../fixtures/site_probe/manifest.v1.json"
        ))?;
        let source = &mut manifest.sources[0];
        source.kind = SourceKind::UnifiProtect;
        source.peer = "192.0.2.7:7447".parse()?;
        source.authority = source.peer.to_string();
        source.presentation = None;
        source.control_root = None;
        source.unifi_camera_id = Some(CAMERA.to_owned());
        let source = &manifest.sources[0];
        manifest.validate()?;
        let mut receipt =
            parse_probe_receipts(include_bytes!("../../../../fixtures/site/probes.v1.json"))?
                .remove(0);
        receipt.site_id = manifest.site_id.clone();
        receipt.source_id = source.source_id.clone();
        receipt.source_generation = source.generation;
        receipt.peer = source.peer;
        receipt.authority = source.authority.clone();
        receipt.presentation = HIGH.to_owned();
        receipt.control_root = HIGH.split('?').next().ok_or("fixture path")?.to_owned();
        receipt.manifest_digest = manifest.digest()?;
        receipt.validate_for(&manifest)?;
        let spec = UnifiSourceSpec {
            source: source_file,
            expected: ContentDigest::sha256(bytes),
            quality: ProtectQuality::High,
            transport: TransportChoice::OperatorRtsp,
            peer: receipt.peer,
        };
        Ok(Self {
            options: SitePlanOptions {
                epoch: 19,
                archive_root: directory.join("archives-not-created"),
                pins_root: directory.join("pins-not-created"),
                principal: "principal:local-operator".to_owned(),
                stop_after_pictures: 3,
            },
            directory,
            lease,
            fingerprint,
            spec,
            manifest,
            receipts: vec![receipt],
        })
    }

    fn input(&self) -> SiteUnifiInput<'_> {
        SiteUnifiInput {
            source_id: &self.manifest.sources[0].source_id,
            spec: &self.spec,
            input: ProtectedUnifiInput {
                bytes: self.lease.bytes(),
                fingerprint: &self.fingerprint,
            },
        }
    }

    fn compile(&self) -> Result<SitePlan, SitePlanError> {
        compile_with_unifi(
            &self.manifest,
            &self.receipts,
            &self.options,
            &[self.input()],
        )
    }

    fn rebind(&mut self) -> Test {
        let digest = self.manifest.digest()?;
        for receipt in &mut self.receipts {
            receipt.manifest_digest = digest;
        }
        Ok(())
    }

    fn select(&mut self, quality: ProtectQuality, path: &str) {
        self.spec.quality = quality;
        self.receipts[0].presentation = path.to_owned();
        self.receipts[0].control_root = path.split('?').next().unwrap_or(path).to_owned();
    }

    fn add_direct_jpeg(&mut self) -> Test {
        let mut source = self.manifest.sources[0].clone();
        source.source_id = "source:jpeg".to_owned();
        source.kind = SourceKind::Rtsp;
        source.peer = "192.0.2.8:554".parse()?;
        source.authority = source.peer.to_string();
        source.presentation = Some("/jpeg".to_owned());
        source.control_root = Some("/jpeg".to_owned());
        source.unifi_camera_id = None;
        let mut receipt = self.receipts[0].clone();
        receipt.source_id = source.source_id.clone();
        receipt.peer = source.peer;
        receipt.authority = source.authority.clone();
        receipt.presentation = "/jpeg".to_owned();
        receipt.control_root = "/jpeg".to_owned();
        receipt.codec = ProbeCodec::Jpeg;
        receipt.payload_type = 26;
        receipt.parameter_set_digests.clear();
        self.manifest.sources.push(source);
        self.receipts.push(receipt);
        self.rebind()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn option<'a>(source: &'a SiteSourcePlan, key: &str) -> Test<&'a str> {
    source
        .argv()
        .windows(2)
        .find(|pair| pair[0] == key)
        .map(|pair| pair[1].as_str())
        .ok_or_else(|| format!("missing native option {key}").into())
}

#[test]
fn protected_site_approval_and_preview_equal_the_actual_native_unifi_planner() -> Test {
    let fixture = Fixture::new()?;
    let plan = fixture.compile()?;
    let source = &plan.sources()[0];
    assert_eq!(source.argv()[0], "from-unifi");
    let start = source
        .argv()
        .iter()
        .position(|value| value == "--root")
        .ok_or("native arguments")?;
    let native_args = source.argv()[start..]
        .iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
    let native = prepare_unifi(&fixture.spec, fixture.input().input, &native_args)?;
    assert_eq!(source.native_approval(), native.approval);
    assert_eq!(source.native_preview(), native.preview);
    assert_eq!(fixture.compile()?.approval(), plan.approval());
    assert!(!fixture.options.archive_root.exists());
    assert!(!fixture.options.pins_root.exists());
    let text = format!("{} {plan:?} {source:?}", plan.render_json());
    for canary in [
        CAMERA,
        "PRIVATE_CAMERA_NAME_CANARY",
        "PRIVATE_HIGH_CAPABILITY_CANARY",
        "PRIVATE_MEDIUM_CAPABILITY_CANARY",
        "PRIVATE_PACKAGE_CAPABILITY_CANARY",
        "rtsps://",
    ] {
        assert!(!text.contains(canary));
    }
    for private in [
        "--authority",
        "--presentation",
        "--control-root",
        "--approve",
    ] {
        assert!(!source.argv().iter().any(|value| value == private));
    }
    fixture.lease.revalidate(&|| Ok(()))?;
    Ok(())
}

#[test]
fn missing_extra_duplicate_and_foreign_peer_inputs_refuse_atomically() -> Test {
    let fixture = Fixture::new()?;
    assert!(compile(&fixture.manifest, &fixture.receipts, &fixture.options).is_err());
    assert!(
        compile_with_unifi(
            &fixture.manifest,
            &fixture.receipts,
            &fixture.options,
            &[fixture.input(), fixture.input()]
        )
        .is_err()
    );
    let mut extra = fixture.input();
    extra.source_id = "source:foreign";
    assert!(
        compile_with_unifi(
            &fixture.manifest,
            &fixture.receipts,
            &fixture.options,
            &[extra]
        )
        .is_err()
    );
    let mut peer = fixture.spec.clone();
    peer.peer = "192.0.2.9:7447".parse()?;
    let mut input = fixture.input();
    input.spec = &peer;
    let error = compile_with_unifi(
        &fixture.manifest,
        &fixture.receipts,
        &fixture.options,
        &[input],
    )
    .err()
    .ok_or("foreign peer accepted")?;
    assert_eq!(error.source_index, Some(0));
    assert!(!format!("{error:?}").contains("192.0.2.9"));
    Ok(())
}

#[test]
fn camera_digest_private_route_and_stale_manifest_must_all_agree() -> Test {
    for change in 0..5 {
        let mut fixture = Fixture::new()?;
        match change {
            0 => {
                fixture.manifest.sources[0].unifi_camera_id = Some("camera:foreign".to_owned());
                fixture.rebind()?;
            }
            1 => fixture.spec.expected = ContentDigest::sha256(b"different protected export"),
            2 => {
                fixture.receipts[0].presentation = "/PRIVATE_ROUTE_MISMATCH_CANARY".to_owned();
                fixture.receipts[0].control_root = "/PRIVATE_ROUTE_MISMATCH_CANARY".to_owned();
            }
            3 => fixture.manifest.generation += 1,
            _ => fixture.receipts[0].control_root = "/".to_owned(),
        }
        let error = fixture
            .compile()
            .err()
            .ok_or("mismatched input was accepted")?;
        assert_eq!(error.source_index, Some(0));
        for canary in [CAMERA, "camera:foreign", "PRIVATE_ROUTE_MISMATCH_CANARY"] {
            assert!(!format!("{error:?} {error}").contains(canary));
        }
    }
    Ok(())
}

#[test]
fn disabled_missing_and_secure_only_streams_never_fall_back() -> Test {
    let mut fixture = Fixture::new()?;
    fixture.spec.quality = ProtectQuality::Low;
    assert_eq!(
        fixture
            .compile()
            .err()
            .ok_or("disabled quality accepted")?
            .reason,
        "ERR-CAPTURE-UNIFI-STREAM-DISABLED-001"
    );
    fixture.spec.quality = ProtectQuality::High;
    fixture.spec.transport = TransportChoice::Published;
    assert_eq!(
        fixture
            .compile()
            .err()
            .ok_or("RTSPS was downgraded")?
            .reason,
        "ERR-CAPTURE-UNIFI-TRANSPORT-001"
    );
    let absent = String::from_utf8(EXPORT.to_vec())?.replace(
        "\"medium\":\"rtsp://192.0.2.7:7447/PRIVATE_MEDIUM_CAPABILITY_CANARY\",",
        "",
    );
    let mut missing = Fixture::with_export(absent.as_bytes())?;
    missing.select(ProtectQuality::Medium, MEDIUM);
    assert_eq!(
        missing
            .compile()
            .err()
            .ok_or("missing quality accepted")?
            .reason,
        "ERR-CAPTURE-UNIFI-STREAM-MISSING-001"
    );
    Ok(())
}

#[test]
fn package_is_a_distinct_view_and_main_quality_preserves_stable_identity() -> Test {
    let mut fixture = Fixture::new()?;
    let high = fixture.compile()?;
    fixture.select(ProtectQuality::Medium, MEDIUM);
    let medium = fixture.compile()?;
    fixture.select(ProtectQuality::Package, PACKAGE);
    let package = fixture.compile()?;
    for key in ["--sensor-id", "--stream-id", "--ingress"] {
        assert_eq!(
            option(&high.sources()[0], key)?,
            option(&medium.sources()[0], key)?
        );
        assert_ne!(
            option(&high.sources()[0], key)?,
            option(&package.sources()[0], key)?
        );
    }
    assert_ne!(high.approval(), medium.approval());
    assert_ne!(medium.approval(), package.approval());
    assert_ne!(
        option(&high.sources()[0], "--root")?,
        option(&package.sources()[0], "--root")?
    );
    assert_ne!(
        option(&high.sources()[0], "--pins")?,
        option(&package.sources()[0], "--pins")?
    );
    Ok(())
}

#[test]
fn mixed_jpeg_and_unifi_site_uses_both_exact_native_planners_or_refuses_everything() -> Test {
    let mut fixture = Fixture::new()?;
    fixture.add_direct_jpeg()?;
    let plan = fixture.compile()?;
    assert_eq!(plan.sources().len(), 2);
    assert_eq!(plan.sources()[0].argv()[0], "from-unifi");
    assert_eq!(plan.sources()[1].argv()[0], "jpeg");
    let native_args = plan.sources()[1].argv()[1..]
        .iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
    let native = prepare_jpeg(&native_args)?;
    assert_eq!(plan.sources()[1].native_approval(), native.approval);
    assert_eq!(plan.sources()[1].native_preview(), native.preview);
    fixture.manifest.sources[1].retain_originals = false;
    fixture.rebind()?;
    assert_eq!(
        fixture
            .compile()
            .err()
            .ok_or("partial site accepted")?
            .source_index,
        Some(1)
    );
    Ok(())
}

#[test]
fn resolved_private_and_direct_routes_use_the_existing_normalized_collision_rule() -> Test {
    let mut fixture = Fixture::new()?;
    fixture.add_direct_jpeg()?;
    let first = fixture.manifest.sources[0].clone();
    let direct = &mut fixture.manifest.sources[1];
    direct.peer = first.peer;
    direct.authority = first.authority;
    direct.presentation = Some(HIGH.replace("%4a", "%4A"));
    direct.control_root = Some(HIGH.split('?').next().ok_or("fixture path")?.to_owned());
    fixture.receipts[1].peer = direct.peer;
    fixture.receipts[1].authority = direct.authority.clone();
    fixture.receipts[1].presentation = direct.presentation.clone().ok_or("fixture path")?;
    fixture.receipts[1].control_root = direct.control_root.clone().ok_or("fixture path")?;
    fixture.rebind()?;
    let error = fixture
        .compile()
        .err()
        .ok_or("duplicate resolved footage was accepted")?;
    assert_eq!(
        error.reason,
        "resolved source routes collide or violate the site contract"
    );
    assert!(!format!("{error:?}").contains("PRIVATE_HIGH_CAPABILITY_CANARY"));
    Ok(())
}

#[test]
fn ownership_retention_and_payment_protection_are_never_inferred_from_vendor_metadata() -> Test {
    for change in 0..4 {
        let mut fixture = Fixture::new()?;
        match change {
            0 => fixture.manifest.sources[0].owner_authorized = false,
            1 => fixture.manifest.sources[0].retain_originals = false,
            2 => fixture.manifest.sources[0].plaintext = false,
            _ => fixture.manifest.sources[0].payment_masks.push(PaymentMask {
                x: 0,
                y: 0,
                width: 10_000,
                height: 10_000,
            }),
        }
        fixture.rebind()?;
        assert_eq!(
            fixture
                .compile()
                .err()
                .ok_or("missing source permission accepted")?
                .source_index,
            Some(0)
        );
    }
    Ok(())
}

#[test]
fn same_export_bytes_on_a_new_file_change_the_native_and_site_approvals() -> Test {
    let mut fixture = Fixture::new()?;
    let before = fixture.compile()?;
    let path = fixture.directory.join("replacement.json");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(EXPORT)?;
    drop(file);
    fs::rename(path, &fixture.spec.source)?;
    fixture.lease = private_file::InputLease::open(&fixture.spec.source, &|| Ok(()))?;
    let fingerprint = fixture.lease.fingerprint();
    assert_ne!(fixture.fingerprint, fingerprint);
    fixture.fingerprint = fingerprint;
    let after = fixture.compile()?;
    assert_ne!(
        before.sources()[0].native_approval(),
        after.sources()[0].native_approval()
    );
    assert_ne!(before.approval(), after.approval());
    Ok(())
}

#[test]
fn selected_unifi_and_direct_sources_preserve_their_exact_native_plans() -> Test {
    let mut fixture = Fixture::new()?;
    fixture.add_direct_jpeg()?;
    let whole = fixture.compile()?;
    let selected_unifi = compile_selected_with_unifi(
        &fixture.manifest,
        &fixture.receipts[..1],
        &fixture.options,
        &[fixture.manifest.sources[0].source_id.clone()],
        &[fixture.input()],
    )?;
    assert_eq!(selected_unifi.sources(), &whole.sources()[..1]);
    assert!(selected_unifi.render_json().contains(SELECTED_UNIFI_POLICY));
    assert_ne!(selected_unifi.approval(), whole.approval());
    let selected_direct = compile_selected(
        &fixture.manifest,
        &fixture.receipts[1..],
        &fixture.options,
        &[fixture.manifest.sources[1].source_id.clone()],
    )?;
    assert_eq!(selected_direct.sources(), &whole.sources()[1..]);
    assert_eq!(selected_direct.sources()[0].source_index(), 1);
    for plan in [&selected_unifi, &selected_direct] {
        for canary in [CAMERA, HIGH, MEDIUM, PACKAGE] {
            assert!(!format!("{} {plan:?}", plan.render_json()).contains(canary));
        }
    }
    Ok(())
}

#[test]
fn selected_inventory_refuses_missing_and_unselected_protected_inputs() -> Test {
    let mut fixture = Fixture::new()?;
    fixture.add_direct_jpeg()?;
    assert!(
        compile_selected(
            &fixture.manifest,
            &fixture.receipts[..1],
            &fixture.options,
            &[fixture.manifest.sources[0].source_id.clone()],
        )
        .is_err()
    );
    let error = compile_selected_with_unifi(
        &fixture.manifest,
        &fixture.receipts[1..],
        &fixture.options,
        &[fixture.manifest.sources[1].source_id.clone()],
        &[fixture.input()],
    )
    .err()
    .ok_or("unselected private input accepted")?;
    assert_eq!(error.source_index, Some(0));
    assert_eq!(error.reason, "protected input names an unselected source");
    Ok(())
}

#[test]
fn selected_private_route_cannot_collide_with_an_unselected_manifest_route() -> Test {
    let mut fixture = Fixture::new()?;
    fixture.add_direct_jpeg()?;
    let first = fixture.manifest.sources[0].clone();
    let direct = &mut fixture.manifest.sources[1];
    direct.peer = first.peer;
    direct.authority = first.authority;
    direct.presentation = Some(HIGH.replace("%4a", "%4A"));
    direct.control_root = Some(HIGH.split('?').next().ok_or("fixture path")?.to_owned());
    fixture.rebind()?;
    let error = compile_selected_with_unifi(
        &fixture.manifest,
        &fixture.receipts[..1],
        &fixture.options,
        &[fixture.manifest.sources[0].source_id.clone()],
        &[fixture.input()],
    )
    .err()
    .ok_or("selected resolved route collided with unselected source")?;
    assert_eq!(
        error.reason,
        "resolved source routes collide or violate the site contract"
    );
    assert!(!format!("{error:?}").contains("PRIVATE_HIGH_CAPABILITY_CANARY"));
    Ok(())
}
