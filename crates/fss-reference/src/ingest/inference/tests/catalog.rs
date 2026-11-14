#![forbid(unsafe_code)]

use super::immutable::{Fixture, snapshot};
use super::*;
use crate::agent_report_catalog::{
    ReportCatalogError, ReportCatalogFamily, ReportCatalogFilter, ReportCatalogLimits,
    ReportCatalogRequest, query_report_catalog,
};
use crate::retained_source::ImmutableRetainedSource;

fn request() -> TestResult<ReportCatalogRequest> {
    Ok(ReportCatalogRequest {
        filter: ReportCatalogFilter {
            family: Some(ReportCatalogFamily::ModelInvocationReceipt),
            ..ReportCatalogFilter::default()
        },
        principal: fss_core::PrincipalId::parse("principal:model-test")?,
        max_entries: 16,
        expected_anchor: None,
        continuation: None,
    })
}

#[test]
fn another_model_receipt_producer_coexists_without_becoming_a_native_run() -> TestResult {
    use crate::executor_activity::{
        ActivityExecutorModel, ActivityFrameBinding, ActivityThresholdPolicy,
        retain_executor_result,
    };
    use fss_codec_mjpeg::color::{RgbDecodeLimits, decode_rgb};

    let mut f = Fixture::new("catalog-other-model-producer")?;
    let frame = RecordedFrame::open(&f.deployment, &f.request, &f.cx)?;
    let decoded = decode_rgb(
        JPEG,
        ContentDigest::sha256(JPEG).bytes(),
        ComponentInterpretation::Grayscale,
        RgbDecodeLimits::default(),
        &mut DecodeBudget::new(100_000_000),
    )?;
    let binding = || ActivityFrameBinding {
        pixels: decoded.pixels(),
        receipt: decoded.receipt(),
        source_digest: ContentDigest::sha256(JPEG),
        capsule: frame.receipt().capsule(),
    };
    let executor = ActivityExecutorModel::load_committed(&ScalarExecCx::new())?;
    let (result, receipt) = executor.invoke(
        &frame.receipt().capsule().sensor_id,
        binding(),
        binding(),
        &ActivityThresholdPolicy::reference()?,
        budget(),
        "job:catalog:other-producer",
        &ScalarExecCx::new(),
    )?;
    let retained = retain_executor_result(
        &mut f.deployment,
        &result,
        &receipt,
        frame.receipt().capsule().capture,
        &f.cx,
    )?;
    let before = snapshot(f.deployment.root())?;
    let limits = ReportCatalogLimits::default();
    let catalog = query_report_catalog(f.deployment.root(), &request()?, limits, &f.cx, &|| false)?;
    assert_eq!(catalog.scanned_reports, 1);
    assert_eq!(catalog.rows.len(), 1);
    assert_eq!(
        catalog.rows[0]
            .model_run
            .as_ref()
            .ok_or("model metadata missing")?
            .run_identity,
        f.run.identity()
    );
    assert_ne!(
        catalog.rows[0].record_digest,
        ContentDigest::sha256(&retained.receipt_json)
    );
    assert_eq!(snapshot(f.deployment.root())?, before);

    // The same payload cannot be smuggled past native verification by putting an unrelated
    // object name under a native completion batch. Namespace detection covers the batch too.
    let suffix = hex(ContentDigest::sha256(b"wrong-native-producer"));
    f.deployment.append_batch(
        BatchId::parse(format!("batch:model-run:{suffix}"))?,
        vec![EvidenceDelta {
            delta_id: format!("delta:executor-receipt:{suffix}"),
            family: "model_invocation_receipt".to_owned(),
            object_id: ObjectId::parse(format!("object:executor-receipt:{suffix}"))?,
            prior_generation: None,
            new_generation: 1,
            validity: frame.receipt().capsule().capture,
            plane: Plane::Cognition,
            payload_digest: ContentDigest::sha256(&retained.receipt_json),
            witness_digest: Some(retained.root),
            operation_id: None,
        }],
        vec![ContentDigest::sha256(&retained.receipt_json), retained.root],
        &f.cx,
    )?;
    assert!(matches!(
        query_report_catalog(f.deployment.root(), &request()?, limits, &f.cx, &|| false),
        Err(ReportCatalogError::InvalidRecord)
    ));
    Ok(())
}

#[test]
fn metadata_catalog_binds_the_actual_frame_completion_before_filtering() -> TestResult {
    let mut f = Fixture::new("catalog-frame-binding")?;
    let limits = ReportCatalogLimits::default();
    let baseline =
        query_report_catalog(f.deployment.root(), &request()?, limits, &f.cx, &|| false)?;
    assert_eq!(baseline.rows.len(), 1);
    let row = &baseline.rows[0];
    let metadata = row.model_run.as_ref().ok_or("model metadata missing")?;
    assert_eq!(metadata.run_identity, f.run.identity());
    assert_eq!(metadata.import_identity, f.request.import_identity);
    assert_eq!(metadata.authority_anchor, *f.run.authority_anchor());
    assert_eq!(row.report_digest, row.record_digest);
    assert_eq!(
        row.record_digest,
        ContentDigest::sha256(&f.run.receipt_bytes()?)
    );

    // Publish a structurally coherent receipt/root/delta with a false source-completion anchor.
    // Its historical runtime gives it a separate run key; a hash-only metadata reader would
    // accept every byte. Native frame authority must still reject the false provenance.
    let frame = RecordedFrame::open(&f.deployment, &f.request, &f.cx)?;
    let mut forged = f.run.receipt.clone();
    forged.runtime = ContentDigest::sha256(b"catalog incompatible historical fixture");
    forged.source_anchor = f.deployment.current_anchor().clone();
    assert_ne!(forged.source_anchor, *frame.authority_anchor());
    let encoded = forged.encoded()?;
    let record_digest = f.deployment.publisher_mut().stage_object(&encoded)?;
    f.deployment.publisher_mut().verify_object(record_digest)?;
    let manifest = forged.manifest()?;
    let target = slot(forged.identity())?;
    f.deployment
        .publisher_mut()
        .stage_manifest(&target, &manifest)?;
    f.deployment.publish_and_commit(
        &target,
        &manifest,
        frame.receipt().capsule().capture,
        &f.cx,
    )?;
    let mut children = manifest.children().to_vec();
    children.push(manifest.root());
    f.deployment.append_batch(
        batch_id(forged.identity())?,
        vec![forged.delta(&frame, manifest.root())?],
        children,
        &f.cx,
    )?;
    let before = snapshot(f.deployment.root())?;
    let source = ImmutableRetainedSource::open(f.deployment.root(), limits.read, &f.cx)?;
    assert!(RecordedInferenceMetadata::read(&source, record_digest, &f.cx).is_err());
    let mut unrelated = request()?;
    unrelated.filter.family = Some(ReportCatalogFamily::PackageZoneReport);
    assert!(matches!(
        query_report_catalog(f.deployment.root(), &unrelated, limits, &f.cx, &|| false),
        Err(ReportCatalogError::InvalidRecord)
    ));
    assert_eq!(snapshot(f.deployment.root())?, before);
    Ok(())
}

#[test]
fn committed_import_deletion_refuses_metadata_before_any_bytes_are_unlinked() -> TestResult {
    use crate::deletion::{STAGE_DELETION_RECORD_APPENDED, commit_deletion, plan_deletion};
    let mut f = Fixture::new("catalog-deleted-import")?;
    let read_cx = context(f.deployment.root())?;
    let encoded = f.run.receipt_bytes()?;
    let record_digest = ContentDigest::sha256(&encoded);
    let plan = plan_deletion(&f.deployment, f.request.import_identity, &f.cx)?;
    assert!(plan.blockers.is_empty());
    f.cx.set_cancel_at_checkpoint(STAGE_DELETION_RECORD_APPENDED);
    assert!(
        commit_deletion(
            &mut f.deployment,
            plan.digest()?,
            plan.approval_digest("principal:model-test")?,
            "principal:model-test",
            &f.cx,
        )
        .is_err()
    );
    // The metadata bytes still exist: refusal follows committed deletion authority, not a
    // missing-file accident or opportunistic repair/recovery during the read.
    assert_eq!(
        fs::read(f.deployment.publisher().spool().object_path(record_digest))?,
        encoded
    );
    let before = snapshot(f.deployment.root())?;
    let limits = ReportCatalogLimits::default();
    let source = ImmutableRetainedSource::open(f.deployment.root(), limits.read, &read_cx)?;
    assert!(RecordedInferenceMetadata::read(&source, record_digest, &read_cx).is_err());
    let catalog =
        query_report_catalog(f.deployment.root(), &request()?, limits, &read_cx, &|| {
            false
        })?;
    assert!(catalog.rows.is_empty());
    assert_eq!(snapshot(f.deployment.root())?, before);
    Ok(())
}

#[test]
fn metadata_cancellation_at_native_boundaries_is_typed_and_never_mutates() -> TestResult {
    for stage in [
        "recorded_decode:metadata_complete",
        "recorded_inference:metadata_complete",
    ] {
        let f = Fixture::new(&format!("catalog-cancel-{stage}"))?;
        let before = snapshot(f.deployment.root())?;
        f.cx.set_cancel_at_checkpoint(stage);
        assert!(matches!(
            query_report_catalog(
                f.deployment.root(),
                &request()?,
                ReportCatalogLimits::default(),
                &f.cx,
                &|| false
            ),
            Err(ReportCatalogError::Cancelled)
        ));
        assert_eq!(snapshot(f.deployment.root())?, before);
    }
    Ok(())
}
