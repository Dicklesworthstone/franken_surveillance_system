#![forbid(unsafe_code)]
//! Explicit current-owner read of one bounded, digest-pinned local native RGB package.

use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_reference::ingest::rgb_package::MAX_RGB_PACKAGE_BYTES;
use std::io::Read;
use std::path::Path;

const SOURCE: &str = "ERR-RTSP-CAMPAIGN-SENTINEL-PACKAGE-001";
const LIMIT: &str = "ERR-RTSP-CAMPAIGN-SENTINEL-LIMIT-001";

pub(super) fn read(
    path: &Path,
    expected: ContentDigest,
    owner: &dyn Fn() -> Result<(), &'static str>,
    work: &mut WorkBudget<'_>,
) -> Result<Vec<u8>, &'static str> {
    owner()?;
    work.charge(128).map_err(|_| LIMIT)?;
    let metadata = std::fs::symlink_metadata(path).map_err(|_| SOURCE)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_RGB_PACKAGE_BYTES as u64 {
        return Err(SOURCE);
    }
    owner()?;
    work.charge(128).map_err(|_| LIMIT)?;
    let mut file = std::fs::File::open(path).map_err(|_| SOURCE)?;
    owner()?;
    let opened = file.metadata().map_err(|_| SOURCE)?;
    if !opened.is_file() || opened.len() != metadata.len() {
        return Err(SOURCE);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
            return Err(SOURCE);
        }
    }
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        owner()?;
        let maximum = chunk.len().min(MAX_RGB_PACKAGE_BYTES + 1 - bytes.len());
        if maximum == 0 {
            return Err(LIMIT);
        }
        work.charge(maximum as u64).map_err(|_| LIMIT)?;
        let count = file.read(&mut chunk[..maximum]).map_err(|_| SOURCE)?;
        owner()?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..count]);
        if bytes.len() > MAX_RGB_PACKAGE_BYTES {
            return Err(LIMIT);
        }
    }
    owner()?;
    if ContentDigest::sha256(&bytes) != expected {
        return Err(SOURCE);
    }
    Ok(bytes)
}
