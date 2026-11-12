#![forbid(unsafe_code)]
//! Shared checks over real native imports; no source reconstruction is implied by discovery.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::{ContentDigest, PrincipalId};
use fss_reference::agent_footage::{
    DeploymentFootageQuery, FootageQueryFilter, FootageQueryLimits, FootageQueryRequest,
    query_footage,
};
use fss_reference::ingest::RetainedFileImport;

pub type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub fn request() -> Test<FootageQueryRequest> {
    Ok(FootageQueryRequest {
        filter: FootageQueryFilter::default(),
        principal: PrincipalId::parse("principal:native-footage-reader")?,
        max_entries: 32,
        expected_anchor: None,
        continuation: None,
    })
}

pub fn query(root: &Path) -> Test<DeploymentFootageQuery> {
    Ok(query_footage(
        root,
        &request()?,
        &FootageQueryLimits::default(),
        &mut |_| true,
    )?)
}

pub fn snapshot(root: &Path) -> Test<BTreeMap<PathBuf, Vec<u8>>> {
    fn walk(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, Vec<u8>>) -> Test {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                walk(root, &path, result)?;
            } else if entry.file_type()?.is_file() {
                result.insert(path.strip_prefix(root)?.to_path_buf(), fs::read(path)?);
            }
        }
        Ok(())
    }
    let mut result = BTreeMap::new();
    walk(root, root, &mut result)?;
    Ok(result)
}

pub fn object_path(root: &Path, digest: ContentDigest) -> Test<PathBuf> {
    let text = digest.to_text();
    Ok(root.join("objects/spool/objects").join(
        text.strip_prefix("sha256:")
            .ok_or("SHA-256 object required")?,
    ))
}

pub fn mark_tombstone(root: &Path, digest: ContentDigest) -> Test {
    // Even an incomplete local marker must deny a read; it never proves completed deletion.
    fs::write(
        root.join("objects/tombstones").join(format!(
            "{}.tomb",
            digest.to_text().replacen(':', "-", 1)
        )),
        b"interrupted native-origin deletion",
    )?;
    Ok(())
}

pub fn assert_metadata(
    root: &Path,
    retained: &RetainedFileImport,
    origin: ContentDigest,
) -> Test<DeploymentFootageQuery> {
    let before = snapshot(root)?;
    let result = query(root)?;
    assert_eq!(result, query(root)?);
    assert_eq!(snapshot(root)?, before, "discovery must not recover or write");
    assert!(!result.snapshot.doctor_inspected);
    assert_eq!(result.other_adapter_imports, 0);
    let manifest = retained.manifest();
    assert!(!manifest.segment_spans.is_empty());
    assert!(manifest.segment_spans.len() <= 32);
    assert_eq!(result.scanned_capsules, manifest.segment_spans.len());
    assert_eq!(result.rows.len(), manifest.segment_spans.len());
    for (row, segment) in result.rows.iter().zip(&manifest.segment_spans) {
        assert_eq!(row.import_identity, retained.import_identity());
        assert_eq!(row.import_root, retained.import_root());
        assert_eq!(row.manifest_digest, retained.manifest_digest());
        assert_eq!(row.adapter_id, manifest.adapter_id);
        assert_eq!(row.adapter_generation, manifest.adapter_generation);
        assert_eq!(row.declared_origin_digest, Some(origin));
        assert_eq!(row.capture_time_label, manifest.capture_time_label);
        assert_eq!(row.segment_index, segment.segment_index as u64);
        assert_eq!(row.source_offset, segment.offset);
        assert_eq!(row.source_len, segment.len);
        assert_eq!(row.capsule.capsule_id, segment.capsule_id);
        assert_eq!(row.capsule.source_digest, segment.segment_sha256);
        assert_eq!(row.capsule.gap_before, segment.gap_before);
    }
    let epistemic = result.epistemic();
    assert!(epistemic.propositions.iter().any(|p| {
        p.statement.contains("adapter_origin_verification=not_performed")
            && p.statement.contains("source_payload_availability=unknown")
    }));
    assert!(epistemic.propositions.iter().any(|p| {
        p.state == fss_core::KnowledgeState::Unknown
            && p.statement.contains("No source-media or adapter-origin proof bytes were read.")
    }));
    Ok(result)
}
