//! Shared deployment and synthetic-scene helpers for the detector-cascade contracts.
//! Only APIs that existed before the cascade are used here, so the no-detector golden test can
//! run unchanged against the pre-cascade tree.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::{CaptureHint, FileFormatHint, FileIngestAdapter, FileIngestRequest};
use fss_reference::{ReferenceDeployment, ReplayCx};

pub type TestResult<T = ()> = Result<T, Box<dyn Error>>;

pub const SITE: &str = "site:cascade";

pub struct OwnedDirectory(pub PathBuf);
impl OwnedDirectory {
    pub fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-cascade-{name}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(std::io::Error::other("test directory capacity").into())
    }
}
impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A fresh deployment with its owner context.
pub struct Fixture {
    pub directory: OwnedDirectory,
    pub cx: ReplayCx,
    pub deployment: ReferenceDeployment,
}

fn context(root: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:cascade".into(),
        operation_id: OperationId::parse("operation:cascade")?,
        principal: "principal:cascade".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(256 * 1024 * 1024)
            .storage_operations(65_536)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    authority.validate()?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

impl Fixture {
    pub fn new(name: &str) -> TestResult<Self> {
        let directory = OwnedDirectory::new(name)?;
        let root = directory.0.join("deployment");
        let cx = context(&root)?;
        let deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        Ok(Self {
            directory,
            cx,
            deployment,
        })
    }

    /// Imports `bytes` as one recording; `capture_start_ns` adds an operator capture hint
    /// (1 ms uncertainty, 10 fps).
    pub fn ingest(
        &mut self,
        sensor: &str,
        bytes: &[u8],
        format: FileFormatHint,
        capture_start_ns: Option<i128>,
    ) -> TestResult<ContentDigest> {
        let path = self
            .directory
            .0
            .join(format!("{}.bin", sensor.replace(':', "-")));
        fs::write(&path, bytes)?;
        let mut request = FileIngestRequest::new(
            path.clone(),
            SensorId::parse(sensor)?,
            StreamId::parse(format!("stream:{}", sensor.replace(':', "-")))?,
        )
        .with_receive_time(TimestampNs(10_000_000_000_000))
        .with_format_hint(format);
        if let Some(start) = capture_start_ns {
            request =
                request.with_capture_hint(CaptureHint::new(TimestampNs(start), 1_000_000, 10.0)?);
        }
        let identity =
            FileIngestAdapter::ingest(request, &self.cx, &mut self.deployment)?.import_identity;
        fs::remove_file(path)?;
        Ok(identity)
    }
}
