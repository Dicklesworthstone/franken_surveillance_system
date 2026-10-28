#![forbid(unsafe_code)]
//! Real source/root/ledger custody and cold replay of owner-imported vendor notifications.
//! These deterministic fixtures do not establish live-device or Profile M qualification.

use std::fs;
use std::path::PathBuf;

use fss_core::{
    BudgetVector, CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest,
    ContextAuthority, LedgerAnchor, OperationId, Plane, ProvenanceClass, RootAuthoritySpec,
    SensorId, TimestampNs,
};
use fss_publication::{LedgerCutPoint, SlotName};
use fss_reference::onvif::metadata::{
    Interpretation, MetadataError, PARSER_GENERATION, PARSER_GENERATION_V1, PullPointAcquisition,
    RECIPE_DOMAIN, RECIPE_DOMAIN_V1, RetainedMetadata, STAGE_METADATA_PUBLISH, SourceBinding,
    retain, retain_pullpoint, retain_with_interpretation,
};
use fss_reference::onvif::wire::PropertyOperation;
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

const SITE: &str = "site:onvif-metadata-test";
const PREFIX: &str = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:e="http://www.onvif.org/ver10/events/wsdl" xmlns:n="http://docs.oasis-open.org/wsn/b-2" xmlns:t="http://www.onvif.org/ver10/schema" xmlns:topic="http://www.onvif.org/ver10/topics"><s:Body><e:PullMessagesResponse><e:CurrentTime>2026-10-27T00:00:01Z</e:CurrentTime><e:TerminationTime>2026-10-27T00:01:01Z</e:TerminationTime>"#;
const SUFFIX: &str = "</e:PullMessagesResponse></s:Body></s:Envelope>";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..64 {
            let path = std::env::temp_dir().join(format!(
                "fss-onvif-metadata-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("owned fixture directory attempts exhausted".into())
    }

    fn cx(&self) -> Test<ReplayCx> {
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:onvif-metadata-test".into(),
            operation_id: OperationId::parse("operation:onvif-metadata-test")?,
            principal: "operator:onvif-metadata-test".into(),
            capabilities: vec![fss_reference::ADP_REPLAY_ROW_ID.into()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(8 * 1024 * 1024)
                .storage_operations(1024)
                .build()?,
            privacy_scope: "privacy:fixture".into(),
            retention_scope: "retention:fixture".into(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?;
        Ok(ReplayCx::from_context_authority_read_only(
            &authority,
            self.0.clone(),
        )?)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn binding() -> Test<SourceBinding> {
    Ok(SourceBinding {
        sensor_id: SensorId::parse("sensor:front")?,
        device_generation: ContentDigest::sha256(b"device-config-1"),
        profile_generation: ContentDigest::sha256(b"profile-config-1"),
        profile_token: "main".into(),
        receive_interval: CaptureInterval::new(TimestampNs(100), TimestampNs(110))?,
    })
}

fn notification(operation: &str, extra: &str) -> String {
    format!(
        r#"<n:NotificationMessage><n:Topic Dialect="http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet">topic:RuleEngine/CellMotionDetector/Motion</n:Topic><n:Message><t:Message UtcTime="2026-10-27T00:00:00.123Z" PropertyOperation="{operation}"><t:Source><t:SimpleItem Name="VideoSourceConfigurationToken" Value="front"/></t:Source><t:Key><t:SimpleItem Name="Rule" Value="motion-rule"/></t:Key><t:Data><t:SimpleItem Name="IsMotion" Value="false"/>{extra}</t:Data></t:Message></n:Message></n:NotificationMessage>"#
    )
}

fn source(notifications: &str) -> Vec<u8> {
    format!("{PREFIX}{notifications}{SUFFIX}").into_bytes()
}

fn root_path(deployment: &ReferenceDeployment, retained: &RetainedMetadata) -> PathBuf {
    deployment
        .publisher()
        .root_dir()
        .join("roots")
        .join(format!(
            "onvif-metadata-{}.root",
            &retained.identity().to_text()[7..]
        ))
}

/// Independently encoded v1 bytes; the new parser and writer never construct this fixture.
struct LegacyFixture {
    source: &'static [u8],
    recipe: &'static str,
    projection: &'static str,
    manifest: &'static str,
    identity: &'static str,
    root: &'static str,
    source_digest: &'static str,
}

macro_rules! legacy_fixture {
    ($name:literal, $identity:literal, $root:literal, $source:literal) => {
        LegacyFixture {
            source: include_bytes!(concat!(
                "../../../fixtures/onvif-metadata-v1/",
                $name,
                ".xml"
            )),
            recipe: include_str!(concat!(
                "../../../fixtures/onvif-metadata-v1/",
                $name,
                ".recipe.hex"
            )),
            projection: include_str!(concat!(
                "../../../fixtures/onvif-metadata-v1/",
                $name,
                ".projection.hex"
            )),
            manifest: include_str!(concat!(
                "../../../fixtures/onvif-metadata-v1/",
                $name,
                ".manifest.hex"
            )),
            identity: $identity,
            root: $root,
            source_digest: $source,
        }
    };
}

const LEGACY_ANALYTICS: LegacyFixture = legacy_fixture!(
    "legacy_analytics",
    "9fe0e220b7cd98d0e3550b8773b67ddcc40c3ea4ce36f599fd27bad448b4e0b6",
    "be036ca5f079efcc8366899e593c1a9ce022580622356f1e1665397f3e3de39a",
    "546235d441a940aebf49d171832017a544170d055e84dbf648c43af63b13adc7"
);
const LEGACY_INVALID_TIME: LegacyFixture = legacy_fixture!(
    "legacy_opaque_invalid_time",
    "abdaa3a034b8dc78924d73e459dc297e135f5db8bfe3dd4895a8d1c46c61b086",
    "7afd2bd1ffec2d2f74a0990fe651b96635e011552495e816625396727da6fdbe",
    "cae17b1fd0cab60c8dca431559bcf0e40a3f050fd295039b015ee5764de34523"
);
const LEGACY_SUPPORTED_ANALYTICS: LegacyFixture = legacy_fixture!(
    "legacy_supported_analytics",
    "ec73678b94d180d3c84dad93179d3f8d83307b6981dc7def602bb7cf6aecac03",
    "5b11a9108d25d5a995d0200ddc483dac8a72ed6ba71ee46dbedef8d7c9013305",
    "c9ed70601060d2248d4e0b09f9dfb13a440e1fa41fddaf1f6493cd3d3e104f83"
);
const LEGACY_PROJECTION: &str = "72cbcc587675d80c11226e0b01c337114f9c9a2d84b973e0592002f868c5a4cb";

fn fixture_digest(hex: &str) -> Test<ContentDigest> {
    Ok(ContentDigest::parse(&format!("sha256:{hex}"))?)
}

fn fixture_bytes(hex: &str) -> Test<Vec<u8>> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid hexadecimal compatibility fixture".into());
    }
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}

fn publish_fixture_bytes(
    deployment: &mut ReferenceDeployment,
    source: &[u8],
    recipe: &[u8],
    projection: &[u8],
    cx: &ReplayCx,
) -> Test<(ContentDigest, ContentDigest, LedgerAnchor, Vec<u8>)> {
    let identity = ContentDigest::sha256(recipe);
    let slot = SlotName::parse(&format!("onvif-metadata-{}", &identity.to_text()[7..]))?;
    let staged = deployment.stage_and_publish(&slot, &[recipe, source, projection], cx)?;
    let manifest_bytes = staged.manifest.canonical_bytes();
    let receipt =
        deployment.publish_and_commit(&slot, &staged.manifest, binding()?.receive_interval, cx)?;
    Ok((identity, receipt.root, receipt.anchor, manifest_bytes))
}

fn publish_legacy_fixture(
    deployment: &mut ReferenceDeployment,
    fixture: &LegacyFixture,
    cx: &ReplayCx,
) -> Test<(ContentDigest, ContentDigest, LedgerAnchor)> {
    let recipe = fixture_bytes(fixture.recipe)?;
    let projection = fixture_bytes(fixture.projection)?;
    assert_eq!(
        ContentDigest::sha256(&recipe),
        fixture_digest(fixture.identity)?
    );
    assert_eq!(
        ContentDigest::sha256(&projection),
        fixture_digest(LEGACY_PROJECTION)?
    );
    assert_eq!(
        ContentDigest::sha256(fixture.source),
        fixture_digest(fixture.source_digest)?
    );
    let (identity, root, anchor, manifest) =
        publish_fixture_bytes(deployment, fixture.source, &recipe, &projection, cx)?;
    assert_eq!(root, fixture_digest(fixture.root)?);
    assert_eq!(manifest, fixture_bytes(fixture.manifest)?);
    Ok((identity, root, anchor))
}

#[test]
fn native_cold_reopen_verifies_raw_source_and_vendor_cognition() -> Test {
    let directory = Directory::new("cold")?;
    let cx = directory.cx()?;
    let xml = source(&notification("Changed", ""));
    let owner = binding()?;
    let (identity, root, anchor) = {
        let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
        let retained = retain(&mut deployment, owner.clone(), &xml, &cx)?;
        assert_eq!(retained.source_digest(), ContentDigest::sha256(&xml));
        assert_eq!(retained.source_bytes(), xml.len());
        assert_eq!(retained.binding(), &owner);
        assert_eq!(retained.plane(), Plane::Cognition);
        assert_eq!(retained.provenance(), ProvenanceClass::VendorClaimed);
        assert_eq!(retained.document().notifications.len(), 1);
        assert_eq!(deployment.ledger().batches().len(), 1);
        let delta = &deployment.ledger().batches()[0].deltas[0];
        assert_eq!(delta.family, "local_root_reachability");
        assert_eq!(delta.validity, owner.receive_interval);
        assert_eq!(
            deployment
                .publisher()
                .spool()
                .read_bounded(retained.source_digest(), xml.len())?,
            xml
        );
        (
            retained.identity(),
            retained.publication_root(),
            retained.authority_anchor().clone(),
        )
    };
    drop(xml);
    let deployment = ReferenceDeployment::reopen(&directory.0, SITE, &cx)?;
    let retained = RetainedMetadata::open(&deployment, identity, Some(root), &cx)?;
    assert_eq!(retained.authority_anchor(), &anchor);
    let claim = &retained.document().notifications[0];
    assert_eq!(claim.property_operation, Some(PropertyOperation::Changed));
    assert_eq!(claim.utc_time, "2026-10-27T00:00:00.123Z");
    assert_eq!(
        claim.data.as_ref().ok_or("data")?.simple_items[0].value,
        "false"
    );
    assert!(
        RetainedMetadata::open(
            &deployment,
            identity,
            Some(ContentDigest::sha256(b"wrong root")),
            &cx
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn exact_retry_preserves_one_root_and_original_anchor() -> Test {
    let directory = Directory::new("retry")?;
    let cx = directory.cx()?;
    let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
    let xml = source(&notification("Initialized", ""));
    let first = retain(&mut deployment, binding()?, &xml, &cx)?;
    let second = retain(&mut deployment, binding()?, &xml, &cx)?;
    assert_eq!(first.identity(), second.identity());
    assert_eq!(first.publication_root(), second.publication_root());
    assert_eq!(first.authority_anchor(), second.authority_anchor());
    assert_eq!(deployment.ledger().batches().len(), 1);
    assert_eq!(deployment.publisher().visible_roots().count(), 1);
    Ok(())
}

#[test]
fn repeated_backfilled_claims_keep_order_and_generation_scoped_identity() -> Test {
    let directory = Directory::new("duplicates")?;
    let cx = directory.cx()?;
    let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
    let claim = notification("Changed", "");
    let xml = source(&format!("{claim}{claim}"));
    let first = retain(&mut deployment, binding()?, &xml, &cx)?;
    assert_eq!(first.document().notifications.len(), 2);
    assert_eq!(first.notification_digest(0)?, first.notification_digest(1)?);
    let mut later = binding()?;
    later.receive_interval = CaptureInterval::new(TimestampNs(200), TimestampNs(210))?;
    let second = retain(&mut deployment, later.clone(), &xml, &cx)?;
    assert_ne!(first.identity(), second.identity());
    assert_eq!(
        first.notification_digest(0)?,
        second.notification_digest(0)?
    );
    later.profile_generation = ContentDigest::sha256(b"changed-profile");
    let changed = retain(&mut deployment, later, &xml, &cx)?;
    assert_ne!(
        first.notification_digest(0)?,
        changed.notification_digest(0)?
    );
    assert_eq!(deployment.ledger().batches().len(), 3);
    Ok(())
}

#[test]
fn empty_poll_and_false_deleted_values_create_only_source_custody() -> Test {
    let directory = Directory::new("absence")?;
    let cx = directory.cx()?;
    let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
    let empty = retain(&mut deployment, binding()?, &source(""), &cx)?;
    assert!(empty.document().notifications.is_empty());
    let deleted = retain(
        &mut deployment,
        binding()?,
        &source(&notification("Deleted", "")),
        &cx,
    )?;
    assert_eq!(
        deleted.document().notifications[0].property_operation,
        Some(PropertyOperation::Deleted)
    );
    for batch in deployment.ledger().batches() {
        assert_eq!(batch.deltas.len(), 1);
        assert_eq!(batch.deltas[0].family, "local_root_reachability");
    }
    Ok(())
}

#[test]
fn opaque_complex_fields_are_retained_without_collapsing_distinct_occurrences() -> Test {
    let directory = Directory::new("opaque")?;
    let cx = directory.cx()?;
    let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
    let claim = notification(
        "Changed",
        r#"<t:ElementItem Name="VendorShape"><v:Shape xmlns:v="urn:vendor" private="value"/></t:ElementItem>"#,
    );
    let xml = source(&format!("{claim}{claim}"));
    let retained = retain(&mut deployment, binding()?, &xml, &cx)?;
    assert_eq!(
        retained.document().notifications[0]
            .data
            .as_ref()
            .ok_or("data")?
            .element_items,
        vec!["VendorShape".to_owned()]
    );
    assert_ne!(
        retained.notification_digest(0)?,
        retained.notification_digest(1)?
    );
    assert_eq!(
        deployment
            .publisher()
            .spool()
            .read_bounded(retained.source_digest(), xml.len())?,
        xml
    );
    Ok(())
}

#[test]
fn malformed_source_and_invalid_owner_binding_publish_nothing() -> Test {
    let directory = Directory::new("malformed")?;
    let cx = directory.cx()?;
    let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
    assert!(retain(&mut deployment, binding()?, b"<!DOCTYPE x><x/>", &cx).is_err());
    let mut bad = binding()?;
    bad.profile_token = "private\ncontrol".into();
    assert!(matches!(
        retain(&mut deployment, bad, &source(""), &cx),
        Err(MetadataError::InvalidBinding)
    ));
    assert!(deployment.ledger().batches().is_empty());
    assert_eq!(deployment.publisher().visible_roots().count(), 0);
    Ok(())
}

#[test]
fn missing_source_refuses_read_and_retry_without_repairing_evidence() -> Test {
    let directory = Directory::new("missing")?;
    let cx = directory.cx()?;
    let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
    let xml = source(&notification("Changed", ""));
    let retained = retain(&mut deployment, binding()?, &xml, &cx)?;
    let path = deployment
        .publisher()
        .spool()
        .object_path(retained.source_digest());
    fs::remove_file(&path)?;
    assert!(RetainedMetadata::open(&deployment, retained.identity(), None, &cx).is_err());
    assert!(retain(&mut deployment, binding()?, &xml, &cx).is_err());
    assert!(
        !path.exists(),
        "retry must not replace missing original custody"
    );
    assert_eq!(deployment.ledger().batches().len(), 1);
    Ok(())
}

#[test]
fn cancellation_before_publication_leaves_no_authority_and_exact_retry_can_resume() -> Test {
    let directory = Directory::new("cancel")?;
    let cx = directory.cx()?;
    let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
    let xml = source(&notification("Changed", ""));
    cx.set_cancel_at_checkpoint(STAGE_METADATA_PUBLISH);
    assert!(matches!(
        retain(&mut deployment, binding()?, &xml, &cx),
        Err(MetadataError::Cancelled)
    ));
    assert!(deployment.ledger().batches().is_empty());
    assert_eq!(deployment.publisher().visible_roots().count(), 0);
    let retry_cx = directory.cx()?;
    let retained = retain(&mut deployment, binding()?, &xml, &retry_cx)?;
    assert_eq!(retained.document().notifications.len(), 1);
    assert_eq!(deployment.ledger().batches().len(), 1);
    Ok(())
}

#[test]
fn root_durable_ledger_interruption_is_not_success_and_retry_completes_exact_root() -> Test {
    let directory = Directory::new("interrupted")?;
    let cx = directory.cx()?;
    let xml = source(&notification("Changed", ""));
    let (identity, root) = {
        let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
        deployment.inject_ledger_crash_at(LedgerCutPoint::AfterRootDurable);
        assert!(retain(&mut deployment, binding()?, &xml, &cx).is_err());
        assert!(deployment.ledger().batches().is_empty());
        let visible = deployment
            .publisher()
            .visible_roots()
            .next()
            .ok_or("durable root")?;
        let hex = visible
            .slot
            .as_str()
            .strip_prefix("onvif-metadata-")
            .ok_or("slot")?;
        (
            ContentDigest::parse(&format!("sha256:{hex}"))?,
            visible.root,
        )
    };
    let mut deployment = ReferenceDeployment::reopen(&directory.0, SITE, &cx)?;
    assert!(RetainedMetadata::open(&deployment, identity, Some(root), &cx).is_err());
    let retained = retain(&mut deployment, binding()?, &xml, &cx)?;
    assert_eq!(retained.identity(), identity);
    assert_eq!(retained.publication_root(), root);
    assert_eq!(deployment.ledger().batches().len(), 1);
    Ok(())
}

#[test]
fn wrong_deployment_and_revoked_context_are_refused() -> Test {
    let directory = Directory::new("authority")?;
    let other = Directory::new("other-authority")?;
    let cx = directory.cx()?;
    let wrong = other.cx()?;
    let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
    let xml = source("");
    assert!(matches!(
        retain(&mut deployment, binding()?, &xml, &wrong),
        Err(MetadataError::Authority)
    ));
    assert!(deployment.ledger().batches().is_empty());
    let retained = retain(&mut deployment, binding()?, &xml, &cx)?;
    assert!(matches!(
        RetainedMetadata::open(&deployment, retained.identity(), None, &wrong),
        Err(MetadataError::Authority)
    ));
    cx.drain_and_finalize();
    assert!(matches!(
        RetainedMetadata::open(&deployment, retained.identity(), None, &cx),
        Err(MetadataError::Authority)
    ));
    Ok(())
}

#[test]
fn cancellation_after_commit_preserves_success_and_cold_verifiable_custody() -> Test {
    let directory = Directory::new("post-commit")?;
    let cx = directory.cx()?;
    let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
    cx.set_cancel_at_checkpoint("onvif_metadata:committed");
    let retained = retain(&mut deployment, binding()?, &source(""), &cx)?;
    assert_eq!(deployment.ledger().batches().len(), 1);
    assert!(!cx.io_authority().is_valid());
    drop(deployment);
    let fresh = directory.cx()?;
    let deployment = ReferenceDeployment::reopen(&directory.0, SITE, &fresh)?;
    let reopened = RetainedMetadata::open(
        &deployment,
        retained.identity(),
        Some(retained.publication_root()),
        &fresh,
    )?;
    assert_eq!(reopened.authority_anchor(), retained.authority_anchor());
    Ok(())
}

#[test]
fn vanished_root_record_is_detected_with_an_already_open_owner() -> Test {
    let directory = Directory::new("root-live")?;
    let cx = directory.cx()?;
    let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
    let xml = source("");
    let retained = retain(&mut deployment, binding()?, &xml, &cx)?;
    let root = root_path(&deployment, &retained);
    fs::remove_file(&root)?;
    assert!(RetainedMetadata::open(&deployment, retained.identity(), None, &cx).is_err());
    assert!(retain(&mut deployment, binding()?, &xml, &cx).is_err());
    assert!(!root.exists());
    assert_eq!(deployment.ledger().batches().len(), 1);
    Ok(())
}

#[test]
fn published_missing_root_and_source_are_never_recreated_after_restart() -> Test {
    for remove_source in [false, true] {
        let directory = Directory::new(if remove_source {
            "lost-both"
        } else {
            "lost-root"
        })?;
        let cx = directory.cx()?;
        let xml = source(&notification("Changed", ""));
        let (root, original) = {
            let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
            let retained = retain(&mut deployment, binding()?, &xml, &cx)?;
            (
                root_path(&deployment, &retained),
                deployment
                    .publisher()
                    .spool()
                    .object_path(retained.source_digest()),
            )
        };
        fs::remove_file(&root)?;
        if remove_source {
            fs::remove_file(&original)?;
        }
        // Either deployment admission or the importer must refuse damaged prior custody.
        if let Ok(mut deployment) = ReferenceDeployment::reopen(&directory.0, SITE, &cx) {
            assert!(retain(&mut deployment, binding()?, &xml, &cx).is_err());
            assert_eq!(deployment.ledger().batches().len(), 1);
        }
        assert!(!root.exists());
        if remove_source {
            assert!(!original.exists());
        }
    }
    Ok(())
}

#[test]
fn frozen_v1_bytes_cold_reopen_with_exact_identity_root_and_owner_lineage() -> Test {
    let directory = Directory::new("v1-golden")?;
    let cx = directory.cx()?;
    let (identity, root, anchor) = {
        let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
        publish_legacy_fixture(&mut deployment, &LEGACY_ANALYTICS, &cx)?
    };
    let deployment = ReferenceDeployment::reopen(&directory.0, SITE, &cx)?;
    let retained = RetainedMetadata::open(&deployment, identity, Some(root), &cx)?;
    assert_eq!(
        retained.identity(),
        fixture_digest(LEGACY_ANALYTICS.identity)?
    );
    assert_eq!(
        retained.publication_root(),
        fixture_digest(LEGACY_ANALYTICS.root)?
    );
    assert_eq!(
        retained.projection_digest(),
        fixture_digest(LEGACY_PROJECTION)?
    );
    assert_eq!(
        retained.source_digest(),
        fixture_digest(LEGACY_ANALYTICS.source_digest)?
    );
    assert_eq!(retained.source_bytes(), LEGACY_ANALYTICS.source.len());
    assert_eq!(retained.interpretation(), Interpretation::EventsV1);
    assert_eq!(retained.parser_generation(), PARSER_GENERATION_V1);
    assert_eq!(retained.binding(), &binding()?);
    assert_eq!(retained.authority_anchor(), &anchor);
    assert_eq!(retained.plane(), Plane::Cognition);
    assert_eq!(retained.provenance(), ProvenanceClass::VendorClaimed);
    assert!(retained.document().notifications.is_empty());
    assert!(retained.document().analytics_frames.is_empty());
    assert_eq!(retained.document().unsupported_sections, 1);
    assert!(retained.document().has_unsupported_content());
    assert_eq!(deployment.ledger().batches().len(), 1);
    assert_eq!(
        deployment.ledger().batches()[0].deltas[0].validity,
        binding()?.receive_interval
    );
    Ok(())
}

#[test]
fn legacy_opaque_analytics_remain_readable_when_v2_semantics_refuse() -> Test {
    for (label, fixture) in [
        ("v1-opaque-time", &LEGACY_INVALID_TIME),
        ("v1-opaque-shape", &LEGACY_ANALYTICS),
    ] {
        let directory = Directory::new(label)?;
        let cx = directory.cx()?;
        let (identity, root, anchor) = {
            let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
            publish_legacy_fixture(&mut deployment, fixture, &cx)?
        };
        let mut deployment = ReferenceDeployment::reopen(&directory.0, SITE, &cx)?;
        let old = RetainedMetadata::open(&deployment, identity, Some(root), &cx)?;
        assert_eq!(old.parser_generation(), PARSER_GENERATION_V1);
        assert_eq!(old.authority_anchor(), &anchor);
        assert!(old.document().analytics_frames.is_empty());
        assert_eq!(old.document().unsupported_sections, 1);
        assert!(matches!(
            retain(&mut deployment, binding()?, fixture.source, &cx),
            Err(MetadataError::Wire(_))
        ));
        assert_eq!(deployment.ledger().batches().len(), 1);
        assert_eq!(deployment.publisher().visible_roots().count(), 1);
        let retried = retain_with_interpretation(
            &mut deployment,
            binding()?,
            fixture.source,
            Interpretation::EventsV1,
            &cx,
        )?;
        assert_eq!(retried.identity(), identity);
        assert_eq!(retried.publication_root(), root);
        assert_eq!(retried.authority_anchor(), &anchor);
        assert_eq!(deployment.ledger().batches().len(), 1);
    }
    Ok(())
}

#[test]
fn v2_analytics_reinterpretation_preserves_v1_and_binds_each_owner_generation() -> Test {
    let directory = Directory::new("v2-reinterpret")?;
    let cx = directory.cx()?;
    let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
    let fixture = &LEGACY_SUPPORTED_ANALYTICS;
    let (old_identity, old_root, old_anchor) =
        publish_legacy_fixture(&mut deployment, fixture, &cx)?;
    let current = retain(&mut deployment, binding()?, fixture.source, &cx)?;
    assert_eq!(current.interpretation(), Interpretation::AnalyticsV2);
    assert_eq!(current.parser_generation(), PARSER_GENERATION);
    assert_eq!(current.binding(), &binding()?);
    assert_eq!(
        current.source_digest(),
        fixture_digest(fixture.source_digest)?
    );
    assert_ne!(current.identity(), old_identity);
    assert_ne!(current.publication_root(), old_root);
    assert_ne!(
        current.projection_digest(),
        fixture_digest(LEGACY_PROJECTION)?
    );
    assert_eq!(current.document().unsupported_sections, 0);
    assert!(!current.document().has_unsupported_content());
    assert_eq!(current.document().analytics_frames.len(), 1);
    let frame = &current.document().analytics_frames[0];
    assert_eq!(frame.utc_time, "2026-10-27T00:00:00Z");
    assert!(frame.source.is_none());
    assert!(frame.transformation.is_none());
    assert_eq!(frame.objects.len(), 1);
    assert_eq!(frame.objects[0].object_id, "17");
    let appearance = frame.objects[0].appearance.as_ref().ok_or("appearance")?;
    let shape = appearance.shape.as_ref().ok_or("shape")?;
    assert_eq!(shape.bounding_box.left.as_str(), "0.1");
    assert_eq!(shape.center_of_gravity.x.as_str(), "0.25");
    let candidate = &appearance.class.as_ref().ok_or("class")?.candidates[0];
    assert_eq!(candidate.label, "Human");
    assert_eq!(
        candidate.likelihood.as_ref().map(|value| value.as_str()),
        Some("0.8")
    );
    assert_eq!(current.plane(), Plane::Cognition);
    assert_eq!(current.provenance(), ProvenanceClass::VendorClaimed);
    let frame_identity = current.analytics_frame_digest(0)?;
    let retry = retain(&mut deployment, binding()?, fixture.source, &cx)?;
    assert_eq!(retry.identity(), current.identity());
    assert_eq!(retry.publication_root(), current.publication_root());
    assert_eq!(retry.projection_digest(), current.projection_digest());
    assert_eq!(retry.authority_anchor(), current.authority_anchor());
    assert_eq!(retry.analytics_frame_digest(0)?, frame_identity);
    assert_eq!(deployment.ledger().batches().len(), 2);
    for coordinate in 0..4 {
        let mut other = binding()?;
        match coordinate {
            0 => other.device_generation = ContentDigest::sha256(b"device-config-2"),
            1 => other.profile_generation = ContentDigest::sha256(b"profile-config-2"),
            2 => other.profile_token = "alternate-profile".into(),
            _ => other.sensor_id = SensorId::parse("sensor:back")?,
        }
        let changed = retain(&mut deployment, other, fixture.source, &cx)?;
        assert_eq!(changed.source_digest(), current.source_digest());
        assert_ne!(changed.identity(), current.identity());
        assert_ne!(changed.analytics_frame_digest(0)?, frame_identity);
    }
    drop(deployment);
    let deployment = ReferenceDeployment::reopen(&directory.0, SITE, &cx)?;
    let old = RetainedMetadata::open(&deployment, old_identity, Some(old_root), &cx)?;
    let reopened = RetainedMetadata::open(
        &deployment,
        current.identity(),
        Some(current.publication_root()),
        &cx,
    )?;
    assert_eq!(old.authority_anchor(), &old_anchor);
    assert_eq!(old.projection_digest(), fixture_digest(LEGACY_PROJECTION)?);
    assert!(old.document().analytics_frames.is_empty());
    assert_eq!(old.document().unsupported_sections, 1);
    assert_eq!(reopened.authority_anchor(), current.authority_anchor());
    assert_eq!(reopened.projection_digest(), current.projection_digest());
    assert_eq!(reopened.analytics_frame_digest(0)?, frame_identity);
    assert_eq!(reopened.document(), current.document());
    Ok(())
}

#[test]
fn mixed_unknown_or_falsely_upgraded_versions_refuse_even_with_valid_custody() -> Test {
    for (label, domain, generation) in [
        ("v1-domain-v2-parser", RECIPE_DOMAIN_V1, PARSER_GENERATION),
        ("v2-domain-v1-parser", RECIPE_DOMAIN, PARSER_GENERATION_V1),
        (
            "unknown-parser",
            RECIPE_DOMAIN,
            "gen:fss1:unregistered-parser",
        ),
        (
            "unknown-domain",
            "fss.onvif_vendor_event_import.v999",
            PARSER_GENERATION,
        ),
        ("v2-tuple-v1-projection", RECIPE_DOMAIN, PARSER_GENERATION),
    ] {
        let directory = Directory::new(label)?;
        let cx = directory.cx()?;
        let fixture = &LEGACY_SUPPORTED_ANALYTICS;
        let projection = fixture_bytes(fixture.projection)?;
        let owner = binding()?;
        let mut recipe = CanonicalEncoder::new();
        recipe.text(domain);
        recipe.text(generation);
        recipe.text("owner_supplied_file");
        recipe.text(SITE);
        recipe.text(owner.sensor_id.as_str());
        recipe.digest(owner.device_generation);
        recipe.digest(owner.profile_generation);
        recipe.text(&owner.profile_token);
        recipe.i128(owner.receive_interval.earliest.0);
        recipe.i128(owner.receive_interval.latest.0);
        recipe.digest(ContentDigest::sha256(fixture.source));
        recipe.u64(fixture.source.len() as u64);
        recipe.digest(ContentDigest::sha256(&projection));
        let recipe = recipe.finish_checked()?;
        let (identity, root) = {
            let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
            let (identity, root, _, _) =
                publish_fixture_bytes(&mut deployment, fixture.source, &recipe, &projection, &cx)?;
            (identity, root)
        };
        let deployment = ReferenceDeployment::reopen(&directory.0, SITE, &cx)?;
        assert!(matches!(
            RetainedMetadata::open(&deployment, identity, Some(root), &cx),
            Err(MetadataError::Custody)
        ));
        assert_eq!(deployment.ledger().batches().len(), 1);
    }
    Ok(())
}

#[test]
fn nested_opaque_analytics_bind_notifications_to_the_complete_original_source() -> Test {
    let directory = Directory::new("analytics-opaque-identity")?;
    let cx = directory.cx()?;
    let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
    let claim = notification("Changed", "");
    let xml = |value: &str| {
        format!(
            r#"<t:MetadataStream xmlns:t="http://www.onvif.org/ver10/schema" xmlns:n="http://docs.oasis-open.org/wsn/b-2" xmlns:topic="http://www.onvif.org/ver10/topics" xmlns:v="urn:vendor"><t:VideoAnalytics><t:Frame UtcTime="2026-10-27T00:00:00Z"><t:Extension><v:Opaque>{value}</v:Opaque></t:Extension></t:Frame></t:VideoAnalytics><t:Event>{claim}{claim}</t:Event></t:MetadataStream>"#
        )
        .into_bytes()
    };
    let first = retain(&mut deployment, binding()?, &xml("private-a"), &cx)?;
    let second = retain(&mut deployment, binding()?, &xml("private-b"), &cx)?;
    assert_eq!(first.document().unsupported_sections, 0);
    assert!(first.document().has_unsupported_content());
    assert_eq!(first.document().notifications.len(), 2);
    assert_eq!(first.document().analytics_frames.len(), 1);
    assert_eq!(
        first.document().analytics_frames[0].unsupported_extensions,
        1
    );
    assert_eq!(first.projection_digest(), second.projection_digest());
    assert_ne!(first.source_digest(), second.source_digest());
    assert_ne!(first.notification_digest(0)?, first.notification_digest(1)?);
    assert_ne!(
        first.notification_digest(0)?,
        second.notification_digest(0)?
    );
    assert_ne!(
        first.analytics_frame_digest(0)?,
        second.analytics_frame_digest(0)?
    );
    Ok(())
}

#[test]
fn damaged_v2_analytics_source_or_projection_refuses_without_repair() -> Test {
    for damage_projection in [false, true] {
        let directory = Directory::new(if damage_projection {
            "v2-corrupt-projection"
        } else {
            "v2-corrupt-source"
        })?;
        let cx = directory.cx()?;
        let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
        let retained = retain(
            &mut deployment,
            binding()?,
            LEGACY_SUPPORTED_ANALYTICS.source,
            &cx,
        )?;
        let path = deployment
            .publisher()
            .spool()
            .object_path(if damage_projection {
                retained.projection_digest()
            } else {
                retained.source_digest()
            });
        let mut corrupted = fs::read(&path)?;
        *corrupted.first_mut().ok_or("nonempty fixture")? ^= 1;
        fs::write(&path, &corrupted)?;
        assert!(RetainedMetadata::open(&deployment, retained.identity(), None, &cx).is_err());
        assert!(
            retain(
                &mut deployment,
                binding()?,
                LEGACY_SUPPORTED_ANALYTICS.source,
                &cx,
            )
            .is_err()
        );
        assert_eq!(fs::read(&path)?, corrupted);
        assert_eq!(deployment.ledger().batches().len(), 1);
        drop(deployment);
        if let Ok(deployment) = ReferenceDeployment::reopen(&directory.0, SITE, &cx) {
            assert!(
                RetainedMetadata::open(
                    &deployment,
                    retained.identity(),
                    Some(retained.publication_root()),
                    &cx,
                )
                .is_err()
            );
        }
        assert_eq!(fs::read(&path)?, corrupted);
    }
    Ok(())
}

#[test]
fn retry_refuses_a_root_previously_ledgered_with_a_different_receive_interval() -> Test {
    let template = Directory::new("wrong-validity-template")?;
    let template_cx = template.cx()?;
    let mut original = ReferenceDeployment::open(&template.0, SITE, &template_cx)?;
    let xml = source(&notification("Changed", ""));
    let retained = retain(&mut original, binding()?, &xml, &template_cx)?;
    let recipe = original.publisher().spool().read_bounded(
        retained.identity(),
        fss_reference::onvif::metadata::MAX_RECIPE_BYTES,
    )?;
    let projection = original.publisher().spool().read_bounded(
        retained.projection_digest(),
        fss_reference::onvif::metadata::MAX_PROJECTION_BYTES,
    )?;
    let slot = fss_publication::SlotName::parse(&format!(
        "onvif-metadata-{}",
        &retained.identity().to_text()[7..]
    ))?;
    let directory = Directory::new("wrong-validity")?;
    let cx = directory.cx()?;
    let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
    let staged = deployment.stage_and_publish(
        &slot,
        &[recipe.as_slice(), xml.as_slice(), projection.as_slice()],
        &cx,
    )?;
    assert_eq!(staged.manifest.root(), retained.publication_root());
    deployment.publish_and_commit(
        &slot,
        &staged.manifest,
        CaptureInterval::new(TimestampNs(900), TimestampNs(910))?,
        &cx,
    )?;
    assert!(matches!(
        RetainedMetadata::open(&deployment, retained.identity(), None, &cx),
        Err(MetadataError::Custody)
    ));
    assert!(matches!(
        retain(&mut deployment, binding()?, &xml, &cx),
        Err(MetadataError::Custody)
    ));
    assert_eq!(deployment.ledger().batches().len(), 1);
    Ok(())
}

#[test]
fn file_import_v1_identity_and_mode_remain_compatible() -> Test {
    let directory = Directory::new("v1-identity")?;
    let cx = directory.cx()?;
    let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
    let retained = retain_with_interpretation(
        &mut deployment,
        binding()?,
        &source(""),
        Interpretation::EventsV1,
        &cx,
    )?;
    assert_eq!(
        retained.identity().to_text(),
        "sha256:9c33dec96c55c2f08f6fe1cafec4505ff509d4784777d5ed437d1d822c1f87fe"
    );
    assert_eq!(retained.source_mode(), "owner_supplied_file");
    assert!(retained.pullpoint_acquisition().is_none());
    let reopened = RetainedMetadata::open(&deployment, retained.identity(), None, &cx)?;
    assert_eq!(reopened.identity(), retained.identity());
    assert_eq!(reopened.source_mode(), "owner_supplied_file");
    Ok(())
}

fn subscription_source() -> Vec<u8> {
    br#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:e="http://www.onvif.org/ver10/events/wsdl" xmlns:w="http://www.w3.org/2005/08/addressing" xmlns:n="http://docs.oasis-open.org/wsn/b-2"><s:Header><w:Action s:mustUnderstand="1">http://www.onvif.org/ver10/events/wsdl/EventPortType/CreatePullPointSubscriptionResponse</w:Action></s:Header><s:Body><e:CreatePullPointSubscriptionResponse><e:SubscriptionReference><w:Address>http://192.0.2.4/onvif/subscription?Idx=7</w:Address></e:SubscriptionReference><n:CurrentTime>2026-10-27T00:00:00Z</n:CurrentTime><n:TerminationTime>2026-10-27T00:02:00Z</n:TerminationTime></e:CreatePullPointSubscriptionResponse></s:Body></s:Envelope>"#.to_vec()
}

fn pullpoint_acquisition(subscription: &[u8]) -> PullPointAcquisition {
    PullPointAcquisition {
        approval: ContentDigest::sha256(b"owner-approved-pullpoint-plan"),
        event_route: ContentDigest::sha256(b"exact-event-service-route"),
        subscription_route: ContentDigest::sha256(b"exact-subscription-route"),
        subscription_source: ContentDigest::sha256(subscription),
        subscription_source_bytes: subscription.len(),
        pull_index: 0,
        started_ns: 1_000,
        completed_ns: 1_010,
        client_authenticated: true,
        message_id: "urn:fss:onvif:pull-0".to_owned(),
        subscription_message_id: "urn:fss:onvif:create-0".to_owned(),
        subscription_started_ns: 900,
        subscription_completed_ns: 990,
    }
}

#[test]
fn live_pullpoint_cold_reopen_retains_subscription_source_and_distinct_source_mode() -> Test {
    let directory = Directory::new("pullpoint-cold")?;
    let cx = directory.cx()?;
    let xml = source(&notification("Changed", ""));
    let subscription = subscription_source();
    let acquisition = pullpoint_acquisition(&subscription);
    let (identity, root, anchor) = {
        let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
        let imported = retain(&mut deployment, binding()?, &xml, &cx)?;
        let live = retain_pullpoint(
            &mut deployment,
            binding()?,
            &xml,
            acquisition.clone(),
            &subscription,
            &cx,
        )?;
        assert_ne!(live.identity(), imported.identity());
        assert_eq!(live.source_mode(), "onvif_pullpoint");
        assert_eq!(live.interpretation(), Interpretation::EventsV1);
        assert_eq!(live.parser_generation(), PARSER_GENERATION_V1);
        assert_eq!(imported.interpretation(), Interpretation::AnalyticsV2);
        assert_eq!(imported.source_mode(), "owner_supplied_file");
        assert_eq!(live.pullpoint_acquisition(), Some(&acquisition));
        assert_eq!(live.document(), imported.document());
        assert_eq!(live.plane(), Plane::Cognition);
        assert_eq!(live.provenance(), ProvenanceClass::VendorClaimed);
        let slot = fss_publication::SlotName::parse(&format!(
            "onvif-metadata-{}",
            &live.identity().to_text()[7..]
        ))?;
        assert_eq!(
            deployment
                .publisher()
                .root_closure(&slot)
                .ok_or("closure")?
                .len(),
            5
        );
        assert_eq!(
            deployment.publisher().spool().read_bounded(
                acquisition.subscription_source,
                acquisition.subscription_source_bytes
            )?,
            subscription
        );
        let retry = retain_pullpoint(
            &mut deployment,
            binding()?,
            &xml,
            acquisition.clone(),
            &subscription,
            &cx,
        )?;
        assert_eq!(retry.identity(), live.identity());
        assert_eq!(retry.authority_anchor(), live.authority_anchor());
        assert_eq!(deployment.ledger().batches().len(), 2);
        (
            live.identity(),
            live.publication_root(),
            live.authority_anchor().clone(),
        )
    };
    let deployment = ReferenceDeployment::reopen(&directory.0, SITE, &cx)?;
    let live = RetainedMetadata::open(&deployment, identity, Some(root), &cx)?;
    assert_eq!(live.pullpoint_acquisition(), Some(&acquisition));
    assert_eq!(live.authority_anchor(), &anchor);
    assert_eq!(live.source_mode(), "onvif_pullpoint");
    Ok(())
}

#[test]
fn changed_poll_occurrence_changes_live_identity_without_discarding_duplicates() -> Test {
    let directory = Directory::new("pullpoint-occurrence")?;
    let cx = directory.cx()?;
    let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
    let claim = notification("Changed", "");
    let xml = source(&format!("{claim}{claim}"));
    let subscription = subscription_source();
    let first_acquisition = pullpoint_acquisition(&subscription);
    let first = retain_pullpoint(
        &mut deployment,
        binding()?,
        &xml,
        first_acquisition.clone(),
        &subscription,
        &cx,
    )?;
    let mut second_acquisition = first_acquisition;
    second_acquisition.pull_index = 1;
    second_acquisition.message_id = "urn:fss:onvif:pull-1".to_owned();
    second_acquisition.started_ns = 1_020;
    second_acquisition.completed_ns = 1_030;
    let mut second_binding = binding()?;
    second_binding.receive_interval = CaptureInterval::new(TimestampNs(120), TimestampNs(130))?;
    let second = retain_pullpoint(
        &mut deployment,
        second_binding,
        &xml,
        second_acquisition,
        &subscription,
        &cx,
    )?;
    assert_ne!(first.identity(), second.identity());
    assert_eq!(first.document().notifications.len(), 2);
    assert_eq!(second.document().notifications.len(), 2);
    assert_eq!(
        first.notification_digest(0)?,
        second.notification_digest(0)?
    );
    assert_eq!(deployment.ledger().batches().len(), 2);
    Ok(())
}

#[test]
fn missing_or_corrupt_subscription_source_refuses_cold_read_and_retry_without_repair() -> Test {
    for remove in [false, true] {
        let directory = Directory::new(if remove {
            "pullpoint-missing"
        } else {
            "pullpoint-corrupt"
        })?;
        let cx = directory.cx()?;
        let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
        let xml = source("");
        let subscription = subscription_source();
        let acquisition = pullpoint_acquisition(&subscription);
        let live = retain_pullpoint(
            &mut deployment,
            binding()?,
            &xml,
            acquisition.clone(),
            &subscription,
            &cx,
        )?;
        let path = deployment
            .publisher()
            .spool()
            .object_path(acquisition.subscription_source);
        if remove {
            fs::remove_file(&path)?;
        } else {
            fs::write(&path, b"corrupted subscription custody")?;
        }
        assert!(RetainedMetadata::open(&deployment, live.identity(), None, &cx).is_err());
        assert!(
            retain_pullpoint(
                &mut deployment,
                binding()?,
                &xml,
                acquisition,
                &subscription,
                &cx
            )
            .is_err()
        );
        assert_eq!(deployment.ledger().batches().len(), 1);
        if remove {
            assert!(!path.exists());
        } else {
            assert_eq!(fs::read(&path)?, b"corrupted subscription custody");
        }
    }
    Ok(())
}

#[test]
fn malformed_or_mismatched_live_acquisition_publishes_nothing() -> Test {
    let directory = Directory::new("pullpoint-refusals")?;
    let cx = directory.cx()?;
    let mut deployment = ReferenceDeployment::open(&directory.0, SITE, &cx)?;
    let xml = source("");
    let subscription = subscription_source();
    let acquisition = pullpoint_acquisition(&subscription);
    let mut wrong_digest = acquisition.clone();
    wrong_digest.subscription_source = ContentDigest::sha256(b"different source");
    let mut wrong_size = acquisition.clone();
    wrong_size.subscription_source_bytes += 1;
    let mut backwards = acquisition.clone();
    backwards.completed_ns = backwards.started_ns - 1;
    let mut wrong_span = acquisition.clone();
    wrong_span.completed_ns += 1;
    let mut backwards_create = acquisition.clone();
    backwards_create.subscription_completed_ns = backwards_create.subscription_started_ns - 1;
    let mut late_create = acquisition.clone();
    late_create.subscription_completed_ns = late_create.started_ns + 1;
    let mut missing_id = acquisition.clone();
    missing_id.message_id.clear();
    let mut same_id = acquisition.clone();
    same_id.message_id = same_id.subscription_message_id.clone();
    let mut invalid_id = acquisition.clone();
    invalid_id.subscription_message_id = "urn:invalid id".to_owned();
    let mut long_id = acquisition.clone();
    long_id.message_id = format!("urn:{}", "x".repeat(253));
    for bad in [
        wrong_digest,
        wrong_size,
        backwards,
        wrong_span,
        backwards_create,
        late_create,
        missing_id,
        same_id,
        invalid_id,
        long_id,
    ] {
        assert!(
            retain_pullpoint(&mut deployment, binding()?, &xml, bad, &subscription, &cx).is_err()
        );
    }
    let not_subscription = source("");
    assert!(
        retain_pullpoint(
            &mut deployment,
            binding()?,
            &xml,
            pullpoint_acquisition(&not_subscription),
            &not_subscription,
            &cx
        )
        .is_err()
    );
    let stream = br#"<t:MetadataStream xmlns:t="http://www.onvif.org/ver10/schema"><t:Event/></t:MetadataStream>"#;
    assert!(
        retain_pullpoint(
            &mut deployment,
            binding()?,
            stream,
            acquisition,
            &subscription,
            &cx
        )
        .is_err()
    );
    // Explicit reply correlation must survive cold-source validation; neither
    // import may claim a response that names a different logical request.
    let wrong_poll = String::from_utf8(xml.clone())?.replace(
        "<s:Body>",
        "<s:Header><w:RelatesTo xmlns:w=\"http://www.w3.org/2005/08/addressing\">urn:fss:onvif:wrong-pull</w:RelatesTo></s:Header><s:Body>",
    );
    assert!(
        retain_pullpoint(
            &mut deployment,
            binding()?,
            wrong_poll.as_bytes(),
            pullpoint_acquisition(&subscription),
            &subscription,
            &cx,
        )
        .is_err()
    );
    let wrong_create = String::from_utf8(subscription.clone())?.replace(
        "</s:Header>",
        "<w:RelatesTo>urn:fss:onvif:wrong-create</w:RelatesTo></s:Header>",
    );
    assert!(
        retain_pullpoint(
            &mut deployment,
            binding()?,
            &xml,
            pullpoint_acquisition(wrong_create.as_bytes()),
            wrong_create.as_bytes(),
            &cx,
        )
        .is_err()
    );
    assert!(deployment.ledger().batches().is_empty());
    assert_eq!(deployment.publisher().visible_roots().count(), 0);
    Ok(())
}
