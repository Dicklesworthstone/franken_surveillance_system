#![forbid(unsafe_code)]
//! Shared current-owner filesystem admission for exact retained campaign attempts.

use super::import_plan;
use fss_geometry::WorkBudget;
use fss_reference::rtsp::campaign_history::VerifiedCampaignHistory;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy)]
pub(super) struct Errors {
    pub request: &'static str,
    pub source: &'static str,
    pub limit: &'static str,
}

fn boundary(
    owner: &dyn Fn() -> Result<(), &'static str>,
    work: &mut WorkBudget<'_>,
    errors: Errors,
) -> Result<(), &'static str> {
    owner()?;
    work.charge(128).map_err(|_| errors.limit)
}

/// Resolve existing ancestors without creating missing attempt stores. The caller's current
/// owner reaches every metadata observation. Missing paths remain metadata, never media evidence.
fn resolved(
    path: &Path,
    owner: &dyn Fn() -> Result<(), &'static str>,
    work: &mut WorkBudget<'_>,
    errors: Errors,
) -> Result<PathBuf, &'static str> {
    let mut candidate = path;
    let mut missing = Vec::new();
    for _ in 0..=2048 {
        boundary(owner, work, errors)?;
        match std::fs::symlink_metadata(candidate) {
            Ok(_) => {
                boundary(owner, work, errors)?;
                let mut resolved = candidate.canonicalize().map_err(|_| errors.request)?;
                owner()?;
                for component in missing.iter().rev() {
                    resolved.push(component);
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(candidate.file_name().ok_or(errors.request)?.to_owned());
                candidate = candidate.parent().ok_or(errors.request)?;
            }
            Err(_) => return Err(errors.request),
        }
    }
    Err(errors.limit)
}

/// The caller first validates its exact pure history mapping/destination. Protect every frozen
/// custody path, including unobserved successors, plus any separately approved input files.
pub(super) fn check(
    root: &Path,
    history_root: &Path,
    history: &VerifiedCampaignHistory,
    children: &[Option<import_plan::Options>],
    input_files: &[PathBuf],
    owner: &dyn Fn() -> Result<(), &'static str>,
    work: &mut WorkBudget<'_>,
    errors: Errors,
) -> Result<Vec<PathBuf>, &'static str> {
    let mut paths = vec![root.to_path_buf(), history_root.to_path_buf()];
    for attempt in &history.plan().attempts {
        paths.push(PathBuf::from(&attempt.archive_path));
        paths.push(PathBuf::from(&attempt.pins_path));
        if let Some(source) = &attempt.source {
            paths.push(PathBuf::from(&source.path));
        }
    }
    paths.extend_from_slice(input_files);
    let canonical = paths
        .iter()
        .map(|path| resolved(path, owner, work, errors))
        .collect::<Result<Vec<_>, _>>()?;
    for (index, left) in canonical.iter().enumerate() {
        for right in &canonical[index + 1..] {
            if left.starts_with(right) || right.starts_with(left) {
                return Err(errors.request);
            }
        }
    }
    let mut archives = Vec::new();
    for (child, recorded) in children.iter().zip(history.attempts()) {
        let Some(child) = child else { continue };
        if child.archive != Path::new(&recorded.attempt.archive_path) {
            return Err(errors.request);
        }
        for name in ["", "spool", "roots", "tombstones"] {
            boundary(owner, work, errors)?;
            if !std::fs::symlink_metadata(child.archive.join(name))
                .is_ok_and(|metadata| metadata.file_type().is_dir())
            {
                return Err(errors.source);
            }
            owner()?;
        }
        archives.push(child.archive.clone());
    }
    Ok(archives)
}
