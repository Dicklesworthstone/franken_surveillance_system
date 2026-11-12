#![forbid(unsafe_code)]
//! Exercise admission through real completed imports, including aggregate exhaustion.

use super::*;
use crate::ingest::{
    CaptureHint, FileFormatHint, FileIngestAdapter, FileIngestRequest,
};
use crate::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, OperationId, StreamId};
use fss_object::SPOOL_OBJECT_HEADER_LEN;
use std::fs;
use std::path::PathBuf;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Directory(PathBuf);

impl Directory {
    fn new(label: &str) -> TestResult<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-retention-metadata-{label}-{}-{attempt}",
                std::process::id(),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("test directory capacity".into())
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    deployment: ReferenceDeployment,
    cx: ReplayCx,
    directory: Directory,
}

impl Fixture {
    fn new(label: &str) -> TestResult<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:retention-metadata".to_owned(),
            operation_id: OperationId::parse("operation:retention-metadata")?,
            principal: "principal:retention-metadata".to_owned(),
            capabilities: ["ADP-REPLAY-001", "ADP-FILE-001"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(64 * 1024 * 1024)
                .storage_operations(8192)
                .build()?,
            privacy_scope: "privacy:retention-metadata".to_owned(),
            retention_scope: "retention:explicit-owner-request".to_owned(),
            anchor_universe: ContentDigest::sha256(b"site:retention-metadata"),
            generation: 1,
        })?;
        let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
        let deployment = ReferenceDeployment::open(&root, "site:retention-metadata", &cx)?;
        Ok(Self {
            deployment,
            cx,
            directory,
        })
    }

    fn ingest(&mut self, name: &str, gray: u8) -> TestResult<ContentDigest> {
        let path = self.directory.0.join(format!("{name}.mjpeg"));
        fs::write(
            &path,
            encode_jpeg(
                16,
                16,
                &[gray; 256],
                &JpegConfig {
                    quality: 90,
                    subsampling: Subsampling::Grayscale,
                    restart_interval: 0,
                    custom_markers: Vec::new(),
                },
            )?,
        )?;
        let input = FileIngestRequest::new(
            path,
            SensorId::parse("sensor:metadata")?,
            StreamId::parse(format!("stream:{name}"))?,
        )
        .with_receive_time(TimestampNs(2000))
        .with_format_hint(FileFormatHint::JpegStream)
        .with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 1.0)?);
        Ok(FileIngestAdapter::ingest(input, &self.cx, &mut self.deployment)?.import_identity)
    }
}

fn request() -> TestResult<RetentionRequest> {
    Ok(RetentionRequest::new(
        SensorId::parse("sensor:metadata")?,
        100,
        CaptureInterval::new(TimestampNs(1000), TimestampNs(1010))?,
    )?)
}

fn is_metadata_bound<T>(result: Result<T, DeletionError>) -> bool {
    matches!(
        result,
        Err(DeletionError::Bound {
            limit: "retention_metadata_bytes"
        })
    )
}

#[test]
fn smaller_manifest_allowance_and_zero_budget_refuse_before_followup_reads() -> TestResult {
    let mut f = Fixture::new("manifest")?;
    let identity = f.ingest("one", 40)?;
    let retained = RetainedFileImport::open(
        &f.deployment,
        identity,
        RetainedReadLimits::default(),
        &f.cx,
    )?;
    let manifest_bytes = retained.manifest().canonical_bytes().len();
    let anchor = f.deployment.current_anchor().clone();
    let state = f.deployment.publisher().spool().state(retained.manifest_digest());
    f.deployment
        .publisher_mut()
        .tighten_read_budget(u64::MAX, u64::MAX)?;

    // This is a valid retained manifest. Its narrower owner allowance must reach the spool,
    // before either decode or the root/custody verification reads can start.
    assert!(is_metadata_bound(assess_age_retention_with_metadata_limit(
        &f.deployment,
        &request()?,
        &f.cx,
        manifest_bytes as u64 - 1,
    )));
    let used = f.deployment.publisher().spool().read_budget_usage();
    assert_eq!(used.used_read_attempts, 1);
    assert_eq!(
        used.used_bytes,
        SPOOL_OBJECT_HEADER_LEN as u64 + manifest_bytes as u64,
    );
    assert!(is_metadata_bound(assess_age_retention_with_metadata_limit(
        &f.deployment,
        &request()?,
        &f.cx,
        0,
    )));
    assert_eq!(f.deployment.publisher().spool().read_budget_usage(), used);

    // Refusal neither rewrites authority nor poisons a valid object's ordinary read.
    assert_eq!(f.deployment.current_anchor(), &anchor);
    assert_eq!(f.deployment.publisher().spool().state(retained.manifest_digest()), state);
    let (again, actual_bytes) = RetainedFileImport::open_with_manifest_limit(
        &f.deployment,
        identity,
        RetainedReadLimits::default(),
        manifest_bytes,
        &f.cx,
    )?;
    assert_eq!(again, retained);
    assert_eq!(actual_bytes, manifest_bytes);
    Ok(())
}

#[test]
fn cumulative_limit_covers_every_import_and_bounds_the_last_capsule_read() -> TestResult {
    let mut f = Fixture::new("cumulative")?;
    f.ingest("one", 40)?;
    f.ingest("two", 80)?;
    let request = request()?;
    let baseline = assess_age_retention(&f.deployment, &request, &f.cx)?;
    assert_eq!(baseline.selection.candidates().len(), 2);
    assert_eq!(baseline.capsules, 2);
    f.deployment
        .publisher_mut()
        .tighten_read_budget(u64::MAX, u64::MAX)?;
    let exact = assess_age_retention_with_metadata_limit(
        &f.deployment,
        &request,
        &f.cx,
        baseline.metadata_bytes,
    )?;
    let first = f.deployment.publisher().spool().read_budget_usage();
    assert_eq!(exact, baseline);

    assert!(is_metadata_bound(assess_age_retention_with_metadata_limit(
        &f.deployment,
        &request,
        &f.cx,
        baseline.metadata_bytes - 1,
    )));
    let second = f.deployment.publisher().spool().read_budget_usage();
    assert_eq!(
        second.used_read_attempts - first.used_read_attempts,
        first.used_read_attempts,
    );
    // Both assessments reach the same final capsule. The refused attempt reserves one byte
    // less before I/O; charging only after an ordinary full read would spend identical bytes.
    assert_eq!(
        second.used_bytes - first.used_bytes + 1,
        first.used_bytes,
    );
    assert_eq!(
        assess_age_retention(&f.deployment, &request, &f.cx)?,
        baseline,
    );
    Ok(())
}
