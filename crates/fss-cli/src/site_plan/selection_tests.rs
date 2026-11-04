#![forbid(unsafe_code)]
//! Exact selected inventory, native-planner equivalence and full-manifest safety contracts.

use super::*;
use fss_reference::site::{PaymentMask, SiteAuthentication, SiteZone, parse_probe_receipts};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    manifest: SiteManifest,
    receipts: Vec<SiteProbeReceipt>,
    options: SitePlanOptions,
}
impl Fixture {
    fn new() -> Test<Self> {
        Ok(Self {
            manifest: SiteManifest::parse(include_str!(
                "../../../../fixtures/site/manifest.v1.json"
            ))?,
            receipts: parse_probe_receipts(include_bytes!(
                "../../../../fixtures/site/probes.v1.json"
            ))?,
            options: SitePlanOptions {
                epoch: 19,
                archive_root: PathBuf::from("/site-selection-test/archives"),
                pins_root: PathBuf::from("/site-selection-test/pins"),
                principal: "principal:local-operator".to_owned(),
                stop_after_pictures: 3,
            },
        })
    }

    fn ids(&self, indices: &[usize]) -> Vec<String> {
        indices
            .iter()
            .map(|index| self.manifest.sources[*index].source_id.clone())
            .collect()
    }

    fn select(&self, indices: &[usize]) -> Result<SitePlan, SitePlanError> {
        let receipts = indices
            .iter()
            .map(|index| self.receipts[*index].clone())
            .collect::<Vec<_>>();
        compile_selected(&self.manifest, &receipts, &self.options, &self.ids(indices))
    }

    fn rebind(&mut self) -> Test {
        let digest = self.manifest.digest()?;
        for receipt in &mut self.receipts {
            receipt.manifest_digest = digest;
        }
        Ok(())
    }
}

#[test]
fn one_selected_source_preserves_its_exact_native_plan_and_original_ordinal() -> Test {
    let fixture = Fixture::new()?;
    let whole = compile(&fixture.manifest, &fixture.receipts, &fixture.options)?;
    let selected = fixture.select(&[1])?;
    assert_eq!(selected.sources(), &whole.sources()[1..]);
    assert_eq!(selected.sources()[0].source_index(), 1);
    assert_ne!(selected.approval(), whole.approval());
    let report = selected.render_json();
    for field in [
        "\"schema\":\"fss.site_capture_plan.v2\"",
        "\"selection_mode\":\"explicit\"",
        "\"manifest_source_count\":2",
        "\"source_count\":1",
        "\"selected_source_ids\":[\"source:back\"]",
        "\"unselected_source_ids\":[\"source:front\"]",
    ] {
        assert!(report.contains(field), "missing selected inventory field");
    }
    assert!(report.contains(&fixture.manifest.digest()?.to_text()));
    assert!(!whole.render_json().contains("selection_mode"));
    assert!(whole.render_json().contains(SITE_PLAN_SCHEMA));
    Ok(())
}

#[test]
fn explicit_selection_is_order_independent_and_domain_separated_even_for_all_sources() -> Test {
    let fixture = Fixture::new()?;
    let ordered = fixture.select(&[0, 1])?;
    let reversed = fixture.select(&[1, 0])?;
    assert_eq!(ordered, reversed);
    assert_eq!(
        validate_selected_sources(&fixture.manifest, &fixture.ids(&[1, 0]))?,
        vec![0, 1]
    );
    let whole = compile(&fixture.manifest, &fixture.receipts, &fixture.options)?;
    assert_eq!(ordered.sources(), whole.sources());
    assert_ne!(ordered.approval(), whole.approval());
    assert!(
        ordered
            .render_json()
            .contains("\"unselected_source_ids\":[]")
    );
    assert_ne!(
        fixture.select(&[0])?.approval(),
        fixture.select(&[1])?.approval()
    );
    Ok(())
}

#[test]
fn empty_duplicate_foreign_and_overbound_selections_refuse_without_echoing_ids() -> Test {
    let fixture = Fixture::new()?;
    const PRIVATE: &str = "source:PRIVATE_SELECTION_CANARY";
    for ids in [
        Vec::new(),
        fixture.ids(&[0, 0]),
        vec![PRIVATE.to_owned()],
        fixture.ids(&[0, 1, 0]),
    ] {
        let error = compile_selected(&fixture.manifest, &[], &fixture.options, &ids)
            .err()
            .ok_or("invalid selection accepted")?;
        assert_eq!(error.code, ERR_SITE_PLAN);
        assert!(!format!("{error} {error:?}").contains(PRIVATE));
    }
    Ok(())
}

#[test]
fn selected_receipt_inventory_is_exact_and_every_supplied_receipt_is_checked() -> Test {
    let fixture = Fixture::new()?;
    let ids = fixture.ids(&[1]);
    let selected = fixture.receipts[1].clone();
    let mut foreign = selected.clone();
    foreign.source_id = "source:foreign".to_owned();
    let mut stale = selected.clone();
    stale.manifest_digest = ContentDigest::sha256(b"stale manifest");
    let mut wrong_route = selected.clone();
    wrong_route.presentation = "/unobserved-route".to_owned();
    let mut bad_cadence = selected.clone();
    bad_cadence.frame_duration_ticks += 1;
    for receipts in [
        Vec::new(),
        vec![fixture.receipts[0].clone()],
        fixture.receipts.clone(),
        vec![selected.clone(), selected],
        vec![foreign],
        vec![stale],
        vec![wrong_route],
        vec![bad_cadence],
    ] {
        assert!(compile_selected(&fixture.manifest, &receipts, &fixture.options, &ids).is_err());
    }
    let duplicate = vec![fixture.receipts[0].clone(), fixture.receipts[0].clone()];
    assert!(
        compile_selected(
            &fixture.manifest,
            &duplicate,
            &fixture.options,
            &fixture.ids(&[0, 1])
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn explicitly_excluded_ineligible_sources_do_not_block_the_selected_camera() -> Test {
    for change in 0..7 {
        let mut fixture = Fixture::new()?;
        let source = &mut fixture.manifest.sources[0];
        match change {
            0 => source.owner_authorized = false,
            1 => source.plaintext = false,
            2 => source.retain_originals = false,
            3 => source.payment_masks.push(PaymentMask {
                x: 0,
                y: 0,
                width: 10_000,
                height: 10_000,
            }),
            4 => source.zones.push(SiteZone {
                zone_id: "zone:payment".to_owned(),
                kind: "lane_pay".to_owned(),
                vertices: vec![[0, 0], [10_000, 0], [10_000, 10_000]],
            }),
            5 => {
                source.kind = SourceKind::Onvif;
                source.presentation = None;
                source.control_root = None;
                source.onvif_service_path = Some("/onvif/device_service".to_owned());
            }
            _ => {
                source.kind = SourceKind::UnifiProtect;
                source.presentation = None;
                source.control_root = None;
                source.unifi_camera_id = Some("camera:protected".to_owned());
            }
        }
        fixture.rebind()?;
        fixture.manifest.validate()?;
        assert_eq!(fixture.select(&[1])?.sources()[0].source_index(), 1);
        assert!(
            fixture.select(&[0]).is_err(),
            "selected ineligible source accepted"
        );
        assert!(compile(&fixture.manifest, &fixture.receipts, &fixture.options).is_err());
    }
    Ok(())
}

#[test]
fn excluding_a_source_cannot_hide_invalid_full_manifest_geometry_or_duplicate_routes() -> Test {
    let mut fixture = Fixture::new()?;
    fixture.manifest.sources[0].zones.push(SiteZone {
        zone_id: "zone:crossed".to_owned(),
        kind: "queue".to_owned(),
        vertices: vec![[0, 0], [10_000, 10_000], [0, 10_000], [10_000, 0]],
    });
    assert!(fixture.select(&[1]).is_err());

    let mut fixture = Fixture::new()?;
    let mut duplicate = fixture.manifest.sources[1].clone();
    duplicate.source_id = fixture.manifest.sources[0].source_id.clone();
    fixture.manifest.sources[0] = duplicate;
    assert!(fixture.select(&[1]).is_err());
    Ok(())
}

#[test]
fn unselected_credentials_still_exclude_every_capture_output_namespace() -> Test {
    let mut fixture = Fixture::new()?;
    fixture.manifest.sources[0].authentication = Some(SiteAuthentication {
        credential_file: fixture.options.archive_root.join("private-credential"),
        realm: "fixture-realm".to_owned(),
        legacy_md5: false,
        legacy_no_qop: false,
    });
    fixture.rebind()?;
    let error = fixture
        .select(&[1])
        .err()
        .ok_or("credential collision accepted")?;
    assert_eq!(error.source_index, Some(0));
    assert!(error.reason.contains("credential references"));
    Ok(())
}

#[test]
fn changes_to_unselected_manifest_sources_invalidate_receipts_and_selected_approvals() -> Test {
    let mut fixture = Fixture::new()?;
    let before = fixture.select(&[1])?;
    fixture.manifest.sources[0].rights_verdict_ref = "fldt:rights:changed".to_owned();
    assert!(fixture.select(&[1]).is_err());
    fixture.rebind()?;
    let after = fixture.select(&[1])?;
    assert_ne!(before.approval(), after.approval());
    assert_ne!(
        before.sources()[0].native_approval(),
        after.sources()[0].native_approval()
    );
    Ok(())
}

#[test]
fn later_native_refusal_does_not_return_a_successful_selected_prefix() -> Test {
    let mut fixture = Fixture::new()?;
    fixture.options.stop_after_pictures = 4096;
    fixture.receipts[1].frame_duration_ticks = 90_000;
    fixture.receipts[1].last_rtp_timestamp = fixture.receipts[1]
        .first_rtp_timestamp
        .wrapping_add(270_000);
    fixture.receipts[1].validate_for(&fixture.manifest)?;
    assert_eq!(fixture.select(&[0])?.sources().len(), 1);
    let error = fixture
        .select(&[0, 1])
        .err()
        .ok_or("partial selected plan accepted")?;
    assert_eq!(error.source_index, Some(1));
    assert!(error.reason.contains("deadline ceiling"));
    Ok(())
}

#[test]
fn selected_jpeg_uses_the_original_native_plan_and_binds_the_reserved_journal_parent() -> Test {
    let mut fixture = Fixture::new()?;
    fixture.receipts = parse_probe_receipts(include_bytes!(
        "../../../../fixtures/site/probes-avc-jpeg.v1.json"
    ))?;
    let whole = compile(&fixture.manifest, &fixture.receipts, &fixture.options)?;
    let selected = fixture.select(&[1])?;
    assert_eq!(selected.sources(), &whole.sources()[1..]);
    assert_eq!(selected.sources()[0].argv()[0], "jpeg");
    assert!(selected.render_json().contains(SELECTED_JPEG_POLICY));
    fixture.options.pins_root = PathBuf::from("/site-selection-test/other-pins");
    assert_ne!(selected.approval(), fixture.select(&[1])?.approval());
    Ok(())
}
