#![forbid(unsafe_code)]
//! Resolve all resources and refuse any existing archive before camera contact.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use fss_geometry::WorkBudget;

use super::plan::Options;
use super::{LIMIT, PATH};

fn boundary(
    check: &dyn Fn() -> Result<(), &'static str>,
    work: &mut WorkBudget<'_>,
) -> Result<(), &'static str> {
    check()?;
    work.charge(128).map_err(|_| LIMIT)
}

fn directory(
    path: &Path,
    fresh: bool,
    check: &dyn Fn() -> Result<(), &'static str>,
    work: &mut WorkBudget<'_>,
) -> Result<PathBuf, &'static str> {
    boundary(check, work)?;
    let metadata = std::fs::symlink_metadata(path);
    check()?;
    match metadata {
        Ok(metadata) if !fresh && metadata.file_type().is_dir() => {
            boundary(check, work)?;
            let resolved = path.canonicalize().map_err(|_| PATH)?;
            check()?;
            Ok(resolved)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            boundary(check, work)?;
            let parent = path
                .parent()
                .ok_or(PATH)?
                .canonicalize()
                .map_err(|_| PATH)?;
            check()?;
            boundary(check, work)?;
            if !std::fs::metadata(&parent).map_err(|_| PATH)?.is_dir() {
                return Err(PATH);
            }
            check()?;
            Ok(parent.join(path.file_name().ok_or(PATH)?))
        }
        _ => Err(PATH),
    }
}

pub(super) fn check(
    options: &Options,
    check: &dyn Fn() -> Result<(), &'static str>,
    work: &mut WorkBudget<'_>,
) -> Result<(), &'static str> {
    let source = directory(&options.capture.root, true, check, work)?;
    let destination = directory(&options.analysis.root, false, check, work)?;
    boundary(check, work)?;
    if !std::fs::symlink_metadata(&options.analysis.package).is_ok_and(|m| m.file_type().is_file())
    {
        return Err(PATH);
    }
    boundary(check, work)?;
    let package = options.analysis.package.canonicalize().map_err(|_| PATH)?;
    check()?;
    let paths = [source, destination, package];
    for (index, left) in paths.iter().enumerate() {
        if paths[index + 1..]
            .iter()
            .any(|right| left.starts_with(right) || right.starts_with(left))
        {
            return Err(PATH);
        }
    }
    check()
}
