#![forbid(unsafe_code)]
//! Completed scalar invocations remain metadata-discoverable across every public transport.

use super::*;
use std::collections::BTreeSet;

use fss_core::{ContentDigest, Generation};
use fss_model_ir::{AttributeMap, GraphNode, ModelIrGraph, ModelIrVersion, OpCode, TensorPort};
use fss_reference::ingest::RetainedReadLimits;
use fss_reference::ingest::inference::{
    RecordedInference, RecordedInferenceMetadata, RecordedModel,
};
use fss_reference::ingest::recorded_decode::{
    ComponentInterpretation, DecodeBudget, DecodeLimits, RecordedDecodeRequest, RecordedFrame,
};
use fss_reference::{ExecBudget, ReferenceDeployment, ScalarExecCx};
use fss_tensor::{DType, Shape};

fn scalar_fixture(label: &str) -> Test<(Fixture, RecordedInferenceMetadata, Vec<PathBuf>)> {
    let fixture = Fixture::new(label)?;
    let cx = support::context(&fixture.source.root)?;
    let mut deployment = ReferenceDeployment::open(&fixture.source.root, support::SITE, &cx)?;
    let request = RecordedDecodeRequest {
        import_identity: fixture.source.import,
        segment_index: 0,
        interpretation: ComponentInterpretation::YCbCr,
        read_limits: RetainedReadLimits::default(),
        decode_limits: DecodeLimits::default(),
    };
    let frame = RecordedFrame::decode_and_publish(
        &mut deployment,
        &request,
        &mut DecodeBudget::new(100_000_000),
        &cx,
    )?;
    let [width, height] = frame.receipt().dimensions();
    let shape = Shape::new(vec![1, 1, height as usize, width as usize])?;
    let graph = ModelIrGraph::new_validated(
        "model:catalog-scalar-fixture",
        ModelIrVersion::V1,
        Generation(3),
        vec![
            TensorPort::new("image", DType::F32, shape.clone(), Generation(3))?,
            TensorPort::new("parameter", DType::F32, Shape::new(vec![1])?, Generation(3))?,
        ],
        vec![TensorPort::new("result", DType::F32, shape, Generation(3))?],
        vec![GraphNode::new(
            "node:0",
            OpCode::Add,
            "numeric metadata fixture, not a trained detector",
            vec!["image".into(), "parameter".into()],
            vec!["result".into()],
            AttributeMap::new(),
        )?],
    )?;
    let model = RecordedModel::publish(
        &graph,
        "image",
        true,
        BTreeMap::from([("parameter".into(), vec![0.25])]),
    )?;
    let scalar = ScalarExecCx::new();
    let run = RecordedInference::run_and_publish(
        &mut deployment,
        &request,
        &model,
        ExecBudget::new(100_000_000, 64 * 1024 * 1024),
        &scalar,
        &cx,
    )?;
    let record_digest = ContentDigest::sha256(&run.receipt_bytes()?);
    let metadata = RecordedInferenceMetadata::read(&deployment, record_digest, &cx)?;
    assert_eq!(metadata.run_identity, run.identity());
    assert_ne!(metadata.run_identity, metadata.record_digest);
    let removable = vec![
        fixture.source.chunk.clone(),
        deployment.publisher().spool().object_path(model.digest()),
        deployment
            .publisher()
            .spool()
            .object_path(ContentDigest::sha256(run.output_bytes())),
        deployment
            .publisher()
            .spool()
            .object_path(ContentDigest::sha256(frame.pixels())),
    ];
    drop(deployment);
    scalar.drain_and_finalize();
    cx.drain_and_finalize();
    Ok((fixture, metadata, removable))
}

fn payload_path(root: &Path, digest: ContentDigest) -> PathBuf {
    let hex: String = digest
        .bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    root.join("objects")
        .join(LOCAL_SPOOL_DIR)
        .join(SPOOL_OBJECTS_DIR)
        .join(hex)
}

#[test]
fn scalar_receipts_expose_real_handles_and_native_run_selection_without_payload_grants() -> Test {
    let (fixture, metadata, removable) = scalar_fixture("catalog-scalar-transports")?;
    let before = tree(&fixture.source.root)?;
    let selected = cli(&fixture, &[("--family", "model_invocation_receipt")])?;
    assert_eq!(selected.1, ExitIdentity::SUCCESS, "{}", selected.0);
    same_mcp(
        &fixture,
        r#", "family":"model_invocation_receipt""#,
        &selected,
    )?;
    let envelope = parse(&selected.0)?;
    let mut rows = projected_reports(&envelope)?;
    assert_eq!(rows.len(), 1);
    let row = rows
        .remove(&(
            "model_invocation_receipt".into(),
            metadata.record_digest.to_text(),
        ))
        .ok_or("stored scalar invocation receipt")?;
    for (key, expected) in [
        ("report_digest", metadata.record_digest.to_text()),
        ("record_digest", metadata.record_digest.to_text()),
        ("provenance_root", metadata.publication_root.to_text()),
        ("publication_slot", metadata.publication_slot.to_string()),
    ] {
        assert_eq!(field(&row, key)?.text(), Some(expected.as_str()), "{key}");
    }
    for (key, expected) in [
        ("metadata_availability", "verified"),
        ("source_payload_availability", "unknown"),
        ("source_reconstruction", "not_performed"),
        ("tensor_payload_verification", "not_performed"),
        ("model_execution", "not_performed"),
    ] {
        assert_eq!(field(&row, key)?.text(), Some(expected), "{key}");
    }
    assert!(field(&row, "qsr_eligibility").is_err());
    let model_run = field(&row, "model_run")?;
    assert_eq!(model_run.object().ok_or("model run metadata")?.len(), 7);
    for (key, expected) in [
        ("run_identity", metadata.run_identity.to_text()),
        (
            "executor_profile_digest",
            metadata.executor_profile_digest.to_text(),
        ),
        ("model_digest", metadata.model_digest.to_text()),
        ("frame_root", metadata.frame_root.to_text()),
        ("import_identity", fixture.source.import.to_text()),
        ("segment_index", "0".into()),
        ("interpretation", "ycbcr".into()),
    ] {
        assert_eq!(
            field(model_run, key)?.text(),
            Some(expected.as_str()),
            "{key}"
        );
    }

    let cognitive = field(&envelope, "payload")?;
    let handles = field(cognitive, "evidenceHandles")?
        .array()
        .ok_or("handles")?;
    assert_eq!(
        handles.len(),
        2,
        "one receipt handle and one publication root"
    );
    let expected_handles = BTreeSet::from([
        metadata.record_digest.to_text(),
        metadata.publication_root.to_text(),
    ]);
    let mut actual_handles = BTreeSet::new();
    for handle in handles {
        let digest = field(handle, "objectDigest")?
            .text()
            .ok_or("object digest")?;
        assert!(actual_handles.insert(digest.to_owned()));
        assert!(payload_path(&fixture.source.root, ContentDigest::parse(digest)?).is_file());
        assert_eq!(field(handle, "availability")?.text(), Some("available"));
        assert_eq!(field(handle, "hydration")?.text(), Some("H0"));
        assert_eq!(
            field(handle, "requiredCapability")?.text(),
            Some("CAP-AGENT-QUERY-001")
        );
    }
    assert_eq!(actual_handles, expected_handles);
    assert!(
        !selected
            .0
            .contains(&format!("fss://proof/{}", metadata.run_identity))
    );
    let propositions = field(field(cognitive, "epistemic")?, "propositions")?
        .array()
        .ok_or("propositions")?;
    let proposition = propositions
        .iter()
        .find(|value| {
            field(value, "statement")
                .ok()
                .and_then(Value::text)
                .is_some_and(|statement| statement.starts_with("Retained report metadata: "))
        })
        .ok_or("model metadata proposition")?;
    let evidence = field(proposition, "evidence")?
        .array()
        .ok_or("metadata evidence")?;
    assert_eq!(
        evidence.len(),
        2,
        "receipt aliases must not duplicate evidence"
    );
    assert_eq!(
        evidence
            .iter()
            .map(|value| value.text().map(str::to_owned).ok_or("evidence digest"))
            .collect::<Result<BTreeSet<_>, _>>()?,
        expected_handles,
    );

    // The semantic run identity is a usable native selector, never a content-addressed blob.
    let run_identity = field(model_run, "run_identity")?
        .text()
        .ok_or("run identity")?;
    let mut native_read = Command::new(env!("CARGO_BIN_EXE_fss-infer"));
    native_read
        .arg("read")
        .arg("--root")
        .arg(&fixture.source.root)
        .args([
            "--site",
            support::SITE,
            "--import-id",
            field(model_run, "import_identity")?
                .text()
                .ok_or("import identity")?,
            "--segment",
            field(model_run, "segment_index")?
                .text()
                .ok_or("segment index")?,
            "--interpretation",
            field(model_run, "interpretation")?
                .text()
                .ok_or("interpretation")?,
            "--run-id",
            run_identity,
        ]);
    let restored = native_read.output()?;
    assert!(
        restored.status.success(),
        "{}",
        String::from_utf8_lossy(&restored.stderr)
    );
    assert!(
        String::from_utf8(restored.stdout)?
            .lines()
            .any(|line| line == format!("run_identity={run_identity}"))
    );
    assert_eq!(tree(&fixture.source.root)?, before);

    // Discovery proves the receipt/publication closure, not current model/tensor/media custody.
    for path in removable.into_iter().collect::<BTreeSet<_>>() {
        fs::remove_file(path)?;
    }
    let missing_payloads = tree(&fixture.source.root)?;
    assert_eq!(
        cli(&fixture, &[("--family", "model_invocation_receipt")])?,
        selected
    );
    same_mcp(
        &fixture,
        r#", "family":"model_invocation_receipt""#,
        &selected,
    )?;
    let unavailable = native_read.output()?;
    assert!(!unavailable.status.success());
    assert!(unavailable.stdout.is_empty());
    assert_eq!(tree(&fixture.source.root)?, missing_payloads);
    Ok(())
}

#[test]
fn corrupt_model_receipts_refuse_the_complete_catalog_even_when_family_is_excluded() -> Test {
    let (fixture, metadata, _) = scalar_fixture("catalog-scalar-corrupt")?;
    fs::write(
        payload_path(&fixture.source.root, metadata.record_digest),
        b"corrupt excluded scalar receipt",
    )?;
    let before = tree(&fixture.source.root)?;
    let refused = cli(&fixture, &[("--family", "package_zone_report")])?;
    assert_eq!(refused.1, ExitIdentity::AGENT_REFUSED);
    same_mcp(&fixture, r#", "family":"package_zone_report""#, &refused)?;
    assert!(!refused.0.contains("claim:report-catalog:"));
    assert_eq!(tree(&fixture.source.root)?, before);
    Ok(())
}
