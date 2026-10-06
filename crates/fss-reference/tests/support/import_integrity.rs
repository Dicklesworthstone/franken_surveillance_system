#![forbid(unsafe_code)]
//! Test-owned deployments and byte-for-byte mutation checks.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec, SensorId,
    StreamId, TimestampNs,
};
use fss_reference::ingest::{FileFormatHint, FileIngestRequest};
use fss_reference::{ADP_FILE_ROW_ID, ADP_REPLAY_ROW_ID, ReplayCx, ReplayIoAuthority};

pub type TestResult<T = ()> = Result<T, Box<dyn Error>>;

pub fn cx(label: &str) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: format!("trace:import-integrity-{label}"),
        operation_id: OperationId::parse(format!("operation:import-integrity-{label}"))?,
        principal: format!("operator:import-integrity-{label}"),
        capabilities: vec![
            ADP_FILE_ROW_ID.to_owned(),
            ADP_REPLAY_ROW_ID.to_owned(),
            "adp:file:001".to_owned(),
        ],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".to_owned(),
        retention_scope: "retention:ephemeral".to_owned(),
        anchor_universe: ContentDigest::sha256(b"import-integrity-test-universe"),
        generation: 1,
    })?;
    let io_root = directory(&format!("cx-{label}"))?;
    Ok(ReplayCx::new(ReplayIoAuthority::from_context_authority(
        &authority, io_root,
    )?))
}

pub fn directory(label: &str) -> TestResult<PathBuf> {
    let base = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    // Atomic directory creation avoids destructive cleanup and collisions across parallel tests.
    for attempt in 0..128 {
        let path = base.join(format!(
            "fss-import-integrity-{label}-{}-{attempt}",
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err("test directory reservation exhausted".into())
}

pub fn request() -> TestResult<FileIngestRequest> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("repository root unavailable")?;
    Ok(FileIngestRequest::new(
        root.join("tests/fixtures/media/h264/clean.264"),
        SensorId::parse("sensor:integrity-camera")?,
        StreamId::parse("stream:integrity-recording")?,
    )
    .with_format_hint(FileFormatHint::AnnexB)
    .with_receive_time(TimestampNs(2_000_000_000)))
}

pub fn snapshot(root: &Path) -> TestResult<BTreeMap<PathBuf, Vec<u8>>> {
    fn visit(
        root: &Path,
        path: &Path,
        out: &mut BTreeMap<PathBuf, Vec<u8>>,
    ) -> TestResult {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                visit(root, &entry.path(), out)?;
            } else if kind.is_file() {
                out.insert(entry.path().strip_prefix(root)?.to_owned(), fs::read(entry.path())?);
            } else {
                return Err("unexpected non-regular test deployment entry".into());
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out)?;
    Ok(out)
}

/// Locate an exact test-owned object by its retained payload, without depending on spool paths
/// or hard-coding its on-disk header or trailer. Match the complete contiguous payload.
pub fn object_file(root: &Path, payload: &[u8]) -> TestResult<PathBuf> {
    if payload.is_empty() {
        return Err("cannot locate an empty test payload".into());
    }
    let matches: Vec<_> = snapshot(root)?
        .into_iter()
        .filter(|(_, bytes)| bytes.windows(payload.len()).any(|window| window == payload))
        .map(|(path, _)| root.join(path))
        .collect();
    match matches.as_slice() {
        [path] => Ok(path.clone()),
        _ => Err("expected exactly one retained object with this payload".into()),
    }
}
