#![forbid(unsafe_code)]
//! Real retained imports, privacy policy, sealed extraction and CLI boundaries.
//! Original paired JPEGs encode a synthetic plane; this tests composition, not calibration.

use super::*;
use crate::matching::fixtures::{HEIGHT, LEFT, RIGHT, WIDTH, package, rig_document};
use fss_cli::json_input::{Value, parse};
use fss_cli::json_output::{array, object, string};
use fss_core::{CanonicalEncode, LedgerAnchor, SensorCapsule, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::{CaptureHint, FileIngestAdapter, FileIngestRequest};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:retained-match-tests";
const PRINCIPAL: &str = "principal:retained-match-tests";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> TestResult<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-retained-match-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("fixture directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn checked<T>(value: Result<T>) -> TestResult<T> {
    value.map_err(|error| format!("{}: {}", error.code, error.detail).into())
}
fn h(value: impl AsRef<[u8]>) -> ContentDigest {
    ContentDigest::sha256(value.as_ref())
}
fn pin(value: ContentDigest) -> String {
    string(&value.to_text())
}
fn json(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.clone(),
        Value::Text(value) => string(value),
        Value::Array(values) => array(&values.iter().map(json).collect::<Vec<_>>()),
        Value::Object(values) => object(
            &values
                .iter()
                .map(|(key, value)| (key.as_str(), json(value)))
                .collect::<Vec<_>>(),
        ),
    }
}
fn field<'a>(value: &'a Value, path: &[&str]) -> TestResult<&'a Value> {
    let Some((key, rest)) = path.split_first() else {
        return Ok(value);
    };
    let next = match value {
        Value::Object(values) => values.get(*key).ok_or("missing report field")?,
        Value::Array(values) => values
            .get(key.parse::<usize>()?)
            .ok_or("missing report row")?,
        _ => return Err("expected report container".into()),
    };
    field(next, rest)
}
fn put(value: &mut Value, path: &[&str], replacement: Value) -> TestResult {
    let Some((key, rest)) = path.split_first() else {
        *value = replacement;
        return Ok(());
    };
    let next = match value {
        Value::Object(values) => values.get_mut(*key).ok_or("missing fixture field")?,
        Value::Array(values) => values
            .get_mut(key.parse::<usize>()?)
            .ok_or("missing fixture row")?,
        _ => return Err("expected fixture container".into()),
    };
    put(next, rest, replacement)
}
fn context(root: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:retained-match-tests".into(),
        operation_id: OperationId::parse("operation:retained-match-tests")?,
        principal: PRINCIPAL.into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(SOURCE_BYTES)
            .storage_operations(65_536)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: h(SITE),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

struct Fixture {
    directory: Directory,
    options: Options,
    document: Value,
    imports: Vec<ContentDigest>,
    capsules: Vec<SensorCapsule>,
    original_chunks: Vec<PathBuf>,
    capsule_files: Vec<PathBuf>,
    head: LedgerAnchor,
}
impl Fixture {
    fn new(label: &str) -> TestResult<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let cx = context(&root)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut imports = Vec::new();
        let mut capsules = Vec::new();
        let mut original_chunks = Vec::new();
        let mut capsule_files = Vec::new();
        for (index, bytes) in [LEFT, RIGHT].into_iter().enumerate() {
            let id = index + 1;
            let original = directory.0.join(format!("source-{id}.mjpeg"));
            fs::write(&original, bytes)?;
            let imported = FileIngestAdapter::ingest(
                FileIngestRequest::new(
                    &original,
                    SensorId::parse(format!("sensor:retained-match-{id}"))?,
                    StreamId::parse(format!("stream:retained-match-{id}:g1"))?,
                )
                .with_receive_time(TimestampNs(1500))
                .with_capture_hint(CaptureHint::new(TimestampNs(1050), 50, 30.0)?),
                &cx,
                &mut deployment,
            )?;
            fs::remove_file(original)?;
            let retained = RetainedFileImport::open(
                &deployment,
                imported.import_identity,
                RetainedReadLimits::default(),
                &cx,
            )?;
            assert_eq!(retained.manifest().format, "mjpeg");
            assert_eq!(retained.manifest().segment_spans.len(), 1);
            let capsule = retained_source_capsule(&deployment, &retained, 0)?;
            assert_eq!(capsule.source_digest, h(bytes));
            assert_eq!(
                [capsule.capture.earliest.0, capsule.capture.latest.0],
                [1000, 1100]
            );
            original_chunks.push(
                deployment
                    .publisher()
                    .spool()
                    .object_path(retained.manifest().ordered_chunks[0]),
            );
            capsule_files.push(
                deployment
                    .publisher()
                    .spool()
                    .object_path(h(capsule.try_canonical_bytes()?)),
            );
            imports.push(imported.import_identity);
            capsules.push(capsule);
        }
        let twin_data = package();
        let rig_data = rig_document(&twin_data);
        let view = |index: usize| -> TestResult<String> {
            let id = index + 1;
            let capsule = &capsules[index];
            Ok(object(&[
                ("camera", id.to_string()),
                (
                    "image_domain_digest",
                    pin(h(format!("retained undistorted fixture mode {id}"))),
                ),
                (
                    "mapping_basis",
                    pin(h(format!("retained fixture camera mapping {id}"))),
                ),
                ("sigma_pixels", "0.5".into()),
                (
                    "source",
                    object(&[
                        ("codec", string("jpeg")),
                        ("import_identity", pin(imports[index])),
                        ("segment", "0".into()),
                        ("capsule_digest", pin(h(capsule.try_canonical_bytes()?))),
                        ("encoded_source_digest", pin(capsule.source_digest)),
                        ("sensor_id", string(capsule.sensor_id.as_str())),
                        ("component_interpretation", string("grayscale")),
                    ]),
                ),
                (
                    "alignment",
                    object(&[
                        ("import_identity", pin(imports[index])),
                        ("stream_id", string(capsule.stream_id.as_str())),
                        ("clock_basis", string(capsule.clock_basis.as_str())),
                        ("offset_ns", "[-10,10]".into()),
                        (
                            "basis",
                            pin(h(format!("declared additive clock mapping {id}"))),
                        ),
                    ]),
                ),
            ]))
        };
        let query_data = object(&[
            ("schema", string(input::SCHEMA)), ("camera_rig_digest", pin(h(&rig_data))),
            ("privacy_domain", "9".into()), ("clock", "11".into()),
            ("clock_evidence", pin(h("declared retained common clock"))),
            ("association_basis", pin(h("declared stationary source plane"))),
            ("reference_time_ns", "1050".into()), ("max_capture_span_ns", "200".into()),
            ("motion", string("static_during_capture_hull")),
            ("left", view(0)?), ("right", view(1)?),
            ("extraction", r#"{"threshold":20,"maximum_features":32,"separation":6}"#.into()),
            ("matching", r#"{"maximum_hamming_distance":0,"ratio_percent":80,"maximum_epipolar_distance_pixels":0.000001}"#.into()),
            ("triangulation", r#"{"min_views":2,"max_outliers":0,"max_reprojection_pixels":0.01}"#.into()),
        ]);
        let twin = directory.0.join("property.fsstwin");
        let rig = directory.0.join("rig.json");
        let query = directory.0.join("query.json");
        fs::write(&twin, &twin_data)?;
        fs::write(&rig, &rig_data)?;
        fs::write(&query, &query_data)?;
        let document = parse(&query_data)?;
        let head = deployment.current_anchor().clone();
        drop(deployment);
        cx.drain_and_finalize();
        Ok(Self {
            options: Options {
                root,
                site: SITE.into(),
                principal: PRINCIPAL.into(),
                twin,
                rig,
                query,
                report_out: Some(directory.0.join("report.json")),
                expected_input: Some(h(&query_data)),
                expected_anchor: Some(anchor_digest(&head)),
                work: DEFAULT_WORK,
                timeout: Duration::from_secs(30),
                report_bytes: MAX_REPORT_BYTES,
            },
            directory,
            document,
            imports,
            capsules,
            original_chunks,
            capsule_files,
            head,
        })
    }
    fn set_query(&mut self, document: &Value) -> TestResult {
        let text = json(document);
        fs::write(&self.options.query, &text)?;
        self.options.expected_input = Some(h(text));
        Ok(())
    }
    fn head(&self) -> TestResult<LedgerAnchor> {
        let cx = context(&self.options.root)?;
        let deployment = ReferenceDeployment::reopen(&self.options.root, SITE, &cx)?;
        let head = deployment.current_anchor().clone();
        drop(deployment);
        cx.drain_and_finalize();
        Ok(head)
    }
    fn refused(&self) -> TestResult {
        let mut stdout = Vec::new();
        assert!(execute(&self.options, &mut stdout).is_err());
        assert!(stdout.is_empty());
        assert!(
            !self
                .options
                .report_out
                .as_ref()
                .ok_or("report output")?
                .exists()
        );
        Ok(())
    }
    fn query(&self) -> TestResult<input::Query> {
        checked(input::parse(
            &fs::read(&self.options.query)?,
            h(fs::read(&self.options.rig)?),
        ))
    }
}

#[test]
fn retained_jpegs_produce_source_bound_points_and_a_private_complete_report() -> TestResult {
    let mut f = Fixture::new("complete")?;
    assert!(!f.directory.0.join("source-1.mjpeg").exists());
    assert!(!f.directory.0.join("source-2.mjpeg").exists());
    let mut stdout = Vec::new();
    assert!(checked(execute(&f.options, &mut stdout))?); // main maps true to exit 0.
    let path = f.options.report_out.as_ref().ok_or("report output")?;
    assert_eq!(fs::read(path)?, stdout);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
    }
    let text = std::str::from_utf8(&stdout)?;
    let value = parse(text)?;
    assert_eq!(
        field(&value, &["schema"])?.text(),
        Some("fss.scene_feature_match_retained.v1")
    );
    let analysis = field(&value, &["report", "analysis"])?;
    assert_eq!(
        field(analysis, &["source_provenance"])?.text(),
        Some("verified_retained_native_frames")
    );
    assert_eq!(field(analysis, &["outcome"])?.text(), Some("reconstructed"));
    assert_eq!(
        field(analysis, &["physical_identity_established"])?.boolean(),
        Some(false)
    );
    assert_eq!(
        field(analysis, &["capture_hull_ns", "0"])?.text(),
        Some("990")
    );
    assert_eq!(
        field(analysis, &["capture_hull_ns", "1"])?.text(),
        Some("1110")
    );
    let hypotheses = field(analysis, &["hypotheses"])?
        .array()
        .ok_or("hypotheses")?;
    assert!(hypotheses.len() >= 8);
    for hypothesis in hypotheses {
        let Value::Number(depth) = field(hypothesis, &["estimate", "position", "2"])? else {
            return Err("point depth".into());
        };
        // The independent original fixture has baseline 1, focal length 160, disparity 16.
        assert!((depth.parse::<f64>()? - 10.0).abs() < 1e-8);
    }
    let views = field(analysis, &["views"])?.array().ok_or("views")?;
    assert_eq!(views.len(), 2);
    for (index, view) in views.iter().enumerate() {
        let original = &f.capsules[index];
        assert_eq!(
            field(view, &["source", "import_identity"])?.text(),
            Some(f.imports[index].to_text().as_str())
        );
        assert_eq!(
            field(view, &["source", "capsule_digest"])?.text(),
            Some(h(original.try_canonical_bytes()?).to_text().as_str())
        );
        assert_eq!(
            field(view, &["source", "encoded_source_digest"])?.text(),
            Some(original.source_digest.to_text().as_str())
        );
        assert_eq!(
            field(view, &["source", "capsule", "sensor_id"])?.text(),
            Some(original.sensor_id.as_str())
        );
        assert_eq!(
            field(view, &["source", "capsule", "clock_basis"])?.text(),
            Some(original.clock_basis.as_str())
        );
        assert_eq!(
            field(view, &["source", "capsule", "capture_ns", "0"])?.text(),
            Some("1000")
        );
        assert_eq!(
            field(view, &["source", "capsule", "capture_ns", "1"])?.text(),
            Some("1100")
        );
        assert_eq!(
            field(view, &["source", "decode_publication_root", "state"])?.text(),
            Some("available")
        );
        assert_eq!(
            field(view, &["source", "mask_policy", "state"])?.text(),
            Some("no_current_policy")
        );
    }
    let raw_body = text
        .trim_end()
        .strip_suffix('}')
        .ok_or("report wrapper")?
        .split_once(",\"report\":")
        .ok_or("report member")?
        .1;
    assert_eq!(
        field(&value, &["report_digest"])?.text(),
        Some(h(raw_body).to_text().as_str())
    );
    assert_eq!(
        field(
            &value,
            &[
                "report",
                "cost",
                "source_bytes",
                "includes_final_revalidation"
            ]
        )?
        .boolean(),
        Some(true)
    );
    let after = f.head()?;
    assert_ne!(
        after, f.head,
        "first native JPEG decoding must publish its retained derivatives"
    );
    assert_eq!(
        field(analysis, &["anchor_digest"])?.text(),
        Some(anchor_digest(&after).to_text().as_str())
    );
    f.options.report_out = None;
    f.options.expected_anchor = Some(anchor_digest(&after));
    let mut replay = Vec::new();
    assert!(checked(execute(&f.options, &mut replay))?);
    let repeated = parse(std::str::from_utf8(&replay)?)?;
    assert_eq!(
        field(analysis, &["association_evidence"])?,
        field(&repeated, &["report", "analysis", "association_evidence"])?
    );
    assert_eq!(
        field(analysis, &["hypotheses"])?,
        field(&repeated, &["report", "analysis", "hypotheses"])?
    );
    assert_eq!(f.head()?, after);
    Ok(())
}

#[test]
fn mismatched_source_pins_refuse_before_any_jpeg_derivative_publication() -> TestResult {
    let mut f = Fixture::new("preflight")?;
    for (path, value) in [
        (
            vec!["left", "source", "capsule_digest"],
            Value::Text(h("wrong capsule").to_text()),
        ),
        (
            vec!["right", "source", "encoded_source_digest"],
            Value::Text(h("wrong original bytes").to_text()),
        ),
        (
            vec!["right", "source", "sensor_id"],
            Value::Text("sensor:unbound".into()),
        ),
        (
            vec!["right", "alignment", "stream_id"],
            Value::Text("stream:other-generation".into()),
        ),
        (
            vec!["right", "alignment", "clock_basis"],
            Value::Text("device_monotonic".into()),
        ),
    ] {
        let mut document = f.document.clone();
        put(&mut document, &path, value)?;
        f.set_query(&document)?;
        f.refused()?;
        assert_eq!(
            f.head()?,
            f.head,
            "preflight changed authority for {path:?}"
        );
    }
    Ok(())
}

#[test]
fn missing_and_corrupt_original_custody_is_refused_without_repair() -> TestResult {
    let f = Fixture::new("missing-source")?;
    for path in [&f.original_chunks[0], &f.capsule_files[0]] {
        let original = fs::read(path)?;
        let mut corrupt = original.clone();
        *corrupt.last_mut().ok_or("empty original custody object")? ^= 1;
        fs::write(path, &corrupt)?;
        f.refused()?;
        assert_eq!(fs::read(path)?, corrupt);
        fs::remove_file(path)?;
        f.refused()?;
        assert!(!path.exists());
        fs::write(path, original)?;
        assert_eq!(f.head()?, f.head);
    }
    Ok(())
}

#[test]
fn current_privacy_can_remove_all_correspondences_and_produces_complete_exit_three() -> TestResult {
    let mut f = Fixture::new("privacy")?;
    let cx = context(&f.options.root)?;
    let mut deployment = ReferenceDeployment::reopen(&f.options.root, SITE, &cx)?;
    let policy = PrivacyMaskPolicy::new(
        f.capsules[0].sensor_id.clone(),
        [WIDTH, HEIGHT],
        &[[0, 0, WIDTH, HEIGHT]],
    )?;
    let approved = preview_mask(&deployment, &policy)?.approval;
    declare_mask(&mut deployment, &policy, approved, &cx)?;
    let masked_head = deployment.current_anchor().clone();
    drop(deployment);
    cx.drain_and_finalize();
    f.refused()?; // stale expected anchor still identifies the unmasked authority tip.
    assert_eq!(f.head()?, masked_head);
    f.options.expected_anchor = Some(anchor_digest(&masked_head));
    let mut stdout = Vec::new();
    assert!(!checked(execute(&f.options, &mut stdout))?); // main maps false to exit 3.
    let report = parse(std::str::from_utf8(&stdout)?)?;
    let analysis = field(&report, &["report", "analysis"])?;
    assert_eq!(
        field(analysis, &["outcome"])?.text(),
        Some("no_reconstruction")
    );
    assert_eq!(field(analysis, &["counts", "solved"])?.integer(), Some(0));
    assert_eq!(
        field(analysis, &["views", "0", "selection", "selected"])?.integer(),
        Some(0)
    );
    assert_eq!(
        field(analysis, &["views", "0", "source", "mask_policy", "digest"])?.text(),
        Some(policy.digest().to_text().as_str())
    );
    assert_eq!(
        field(analysis, &["views", "0", "source", "encoded_source_digest"])?.text(),
        Some(f.capsules[0].source_digest.to_text().as_str())
    );
    assert!(
        !field(analysis, &["feature_outcomes"])?
            .array()
            .ok_or("feature outcomes")?
            .is_empty()
    );
    assert_eq!(
        stdout,
        fs::read(f.options.report_out.as_ref().ok_or("report output")?)?
    );
    Ok(())
}

#[test]
fn sealed_feature_revalidation_detects_source_loss_and_new_current_privacy() -> TestResult {
    for privacy in [false, true] {
        let f = Fixture::new(if privacy {
            "revalidate-privacy"
        } else {
            "revalidate-source"
        })?;
        let query = f.query()?;
        let cx = context(&f.options.root)?;
        let mut deployment = ReferenceDeployment::reopen(&f.options.root, SITE, &cx)?;
        let reads = RecordedFeatureReadBudget::new(SOURCE_BYTES);
        let mut jpeg = DecodeBudget::new(JPEG_WORK);
        let mut video = RecordedVideoDecodeBudget::new(VIDEO_BYTES + VIDEO_LUMA);
        let mut work = WorkBudget::new(DEFAULT_WORK);
        let owner = extract_recorded_features(
            &mut deployment,
            &RecordedFeatureRequest {
                source: source(&query.views[0]),
                image_domain: query.views[0].image_domain_digest,
                extraction: query.extraction,
            },
            &reads,
            &mut jpeg,
            &mut video,
            &mut work,
            &cx,
        )?;
        assert!(!owner.frame().features().is_empty());
        let used = reads.used();
        owner.revalidate(&deployment, &cx, &mut work)?;
        assert!(
            reads.used() > used,
            "final verification must consume the same source allowance"
        );
        if privacy {
            let policy = PrivacyMaskPolicy::new(
                f.capsules[0].sensor_id.clone(),
                [WIDTH, HEIGHT],
                &[[0, 0, WIDTH, HEIGHT]],
            )?;
            let approved = preview_mask(&deployment, &policy)?.approval;
            declare_mask(&mut deployment, &policy, approved, &cx)?;
        } else {
            fs::remove_file(&f.original_chunks[0])?;
        }
        assert!(owner.revalidate(&deployment, &cx, &mut work).is_err());
        drop(deployment);
        cx.drain_and_finalize();
        assert!(
            !f.options
                .report_out
                .as_ref()
                .ok_or("report output")?
                .exists()
        );
    }
    Ok(())
}

#[test]
fn cancellation_deadline_work_and_report_limits_release_no_partial_output() -> TestResult {
    let f = Fixture::new("cancel")?;
    let cx = context(&f.options.root)?;
    cx.request_cancellation();
    assert!(analyze(&f.options, &f.options.root, &cx).is_err());
    cx.drain_and_finalize();
    assert_eq!(f.head()?, f.head);
    for case in 0..3 {
        let mut f = Fixture::new(&format!("limits-{case}"))?;
        match case {
            0 => f.options.timeout = Duration::ZERO,
            1 => f.options.work = 1,
            _ => f.options.report_bytes = 1024,
        }
        f.refused()?;
        if case < 2 {
            assert_eq!(f.head()?, f.head);
        }
        // A late report bound may leave completed JPEG derivatives, but never a partial report.
    }
    Ok(())
}

#[test]
fn exhausted_original_read_allowance_refuses_before_native_publication() -> TestResult {
    let f = Fixture::new("source-budget")?;
    let query = f.query()?;
    let cx = context(&f.options.root)?;
    let mut deployment = ReferenceDeployment::reopen(&f.options.root, SITE, &cx)?;
    let reads = RecordedFeatureReadBudget::new(0);
    let result = extract_recorded_features(
        &mut deployment,
        &RecordedFeatureRequest {
            source: source(&query.views[0]),
            image_domain: query.views[0].image_domain_digest,
            extraction: query.extraction,
        },
        &reads,
        &mut DecodeBudget::new(JPEG_WORK),
        &mut RecordedVideoDecodeBudget::new(VIDEO_BYTES + VIDEO_LUMA),
        &mut WorkBudget::new(DEFAULT_WORK),
        &cx,
    );
    assert!(result.is_err());
    assert_eq!(deployment.current_anchor(), &f.head);
    drop(deployment);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn existing_outputs_and_symlinks_are_rejected_before_source_work() -> TestResult {
    let f = Fixture::new("exclusive-output")?;
    let output = f.options.report_out.as_ref().ok_or("report output")?;
    let sentinel = b"existing report remains untouched";
    fs::write(output, sentinel)?;
    let mut stdout = Vec::new();
    assert!(execute(&f.options, &mut stdout).is_err());
    assert!(stdout.is_empty());
    assert_eq!(fs::read(output)?, sentinel);
    assert_eq!(f.head()?, f.head);
    #[cfg(unix)]
    {
        fs::remove_file(output)?;
        let destination = f.directory.0.join("existing-target");
        fs::write(&destination, sentinel)?;
        std::os::unix::fs::symlink(&destination, output)?;
        assert!(execute(&f.options, &mut stdout).is_err());
        assert_eq!(fs::read(&destination)?, sentinel);
        assert!(fs::symlink_metadata(output)?.file_type().is_symlink());
        assert_eq!(f.head()?, f.head);
    }
    Ok(())
}

#[test]
fn stdout_failure_preserves_the_completed_private_report() -> TestResult {
    struct RefuseStdout;
    impl Write for RefuseStdout {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "test closed stdout",
            ))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let f = Fixture::new("stdout-failure")?;
    assert!(execute(&f.options, &mut RefuseStdout).is_err());
    let bytes = fs::read(f.options.report_out.as_ref().ok_or("report output")?)?;
    assert!(bytes.ends_with(b"\n"));
    let report = parse(std::str::from_utf8(&bytes)?)?;
    assert_eq!(
        field(&report, &["report", "analysis", "outcome"])?.text(),
        Some("reconstructed")
    );
    Ok(())
}
