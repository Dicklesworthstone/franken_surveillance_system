#![forbid(unsafe_code)]
//! Resolve all five possible resources before a camera or destination can be mutated.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use fss_geometry::WorkBudget;

use super::plan::Options;
use super::{LIMIT, PATH};

fn boundary(
    owner: &dyn Fn() -> Result<(), &'static str>,
    work: &mut WorkBudget<'_>,
) -> Result<(), &'static str> {
    owner()?;
    work.charge(128).map_err(|_| LIMIT)
}

fn directory(
    path: &Path,
    fresh: bool,
    owner: &dyn Fn() -> Result<(), &'static str>,
    work: &mut WorkBudget<'_>,
) -> Result<PathBuf, &'static str> {
    boundary(owner, work)?;
    let metadata = std::fs::symlink_metadata(path);
    owner()?;
    match metadata {
        Ok(metadata) if !fresh && metadata.is_dir() && !metadata.file_type().is_symlink() => {
            boundary(owner, work)?;
            let resolved = std::fs::canonicalize(path).map_err(|_| PATH)?;
            owner()?;
            Ok(resolved)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            let parent = path.parent().ok_or(PATH)?;
            boundary(owner, work)?;
            let metadata = std::fs::metadata(parent).map_err(|_| PATH)?;
            owner()?;
            if !metadata.is_dir() {
                return Err(PATH);
            }
            boundary(owner, work)?;
            let parent = std::fs::canonicalize(parent).map_err(|_| PATH)?;
            owner()?;
            Ok(parent.join(path.file_name().ok_or(PATH)?))
        }
        _ => Err(PATH),
    }
}

fn file(
    path: &Path,
    owner: &dyn Fn() -> Result<(), &'static str>,
    work: &mut WorkBudget<'_>,
) -> Result<PathBuf, &'static str> {
    boundary(owner, work)?;
    let metadata = std::fs::symlink_metadata(path).map_err(|_| PATH)?;
    owner()?;
    if !metadata.file_type().is_file() {
        return Err(PATH);
    }
    boundary(owner, work)?;
    let resolved = std::fs::canonicalize(path).map_err(|_| PATH)?;
    owner()?;
    Ok(resolved)
}

pub(super) fn check(
    options: &Options,
    owner: &dyn Fn() -> Result<(), &'static str>,
    work: &mut WorkBudget<'_>,
) -> Result<(), &'static str> {
    // Existing capture/pin roots refuse even if a prior run completed perfectly. An offline
    // analysis continuation is a different operation; it never opens another camera session.
    let mut paths = vec![
        directory(&options.capture.root, true, owner, work)?,
        directory(&options.capture.pins, true, owner, work)?,
        directory(&options.root, false, owner, work)?,
        file(&options.package, owner, work)?,
    ];
    if let Some(auth) = &options.capture.authentication {
        paths.push(file(&auth.credential_file, owner, work)?);
    }
    for (index, left) in paths.iter().enumerate() {
        if paths[index + 1..]
            .iter()
            .any(|right| left.starts_with(right) || right.starts_with(left))
        {
            return Err(PATH);
        }
    }
    owner()
}
