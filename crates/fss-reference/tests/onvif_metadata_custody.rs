#![forbid(unsafe_code)]
//! Real source/root/ledger custody and cold replay of owner-imported vendor notifications.
//! These deterministic fixtures do not establish live-device or Profile M qualification.

use std::fs;
use std::path::PathBuf;

use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, OperationId, Plane,
    ProvenanceClass, RootAuthoritySpec, SensorId, TimestampNs,
};
use fss_publication::LedgerCutPoint;
use fss_reference::onvif::metadata::{
    MetadataError, RetainedMetadata, STAGE_METADATA_PUBLISH, SourceBinding, retain,
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
    assert_eq!(first.notification_digest(0)?, second.notification_digest(0)?);
    later.profile_generation = ContentDigest::sha256(b"changed-profile");
    let changed = retain(&mut deployment, later, &xml, &cx)?;
    assert_ne!(first.notification_digest(0)?, changed.notification_digest(0)?);
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
    assert!(!path.exists(), "retry must not replace missing original custody");
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
        let directory = Directory::new(if remove_source { "lost-both" } else { "lost-root" })?;
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
