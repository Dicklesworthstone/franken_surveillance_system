#![forbid(unsafe_code)]
//! Explicit, create-only temporary image output for the isolated Linux lab.
use fss_core::ContentDigest;
use std::{
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

pub fn validate(path: &Path) -> Result<(), &'static str> {
    if path.parent() != Some(Path::new("/tmp")) {
        return Err("snapshot output must be directly under /tmp");
    }
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("invalid snapshot output")?;
    if !name.starts_with("fss-unifi-snapshot-")
        || !name.ends_with(".jpg")
        || name.len() > 120
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err("invalid snapshot output");
    }
    Ok(())
}

/// Write and read back exact JPEG bytes; a failure can leave the newly created file.
pub fn save(path: &Path, image: &[u8], digest: [u8; 32]) -> Result<(), &'static str> {
    validate(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(0o400000)
        .open(path)
        .map_err(|_| "snapshot output create refused")?;
    let metadata = file
        .metadata()
        .map_err(|_| "snapshot output inspection failed")?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.mode() & 0o077 != 0 {
        return Err("snapshot output not private");
    }
    file.write_all(image)
        .map_err(|_| "snapshot output write failed")?;
    file.sync_all().map_err(|_| "snapshot output sync failed")?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| "snapshot output readback failed")?;
    let mut readback = Vec::new();
    file.take((image.len() as u64) + 1)
        .read_to_end(&mut readback)
        .map_err(|_| "snapshot output readback failed")?;
    let matches =
        readback.len() == image.len() && ContentDigest::sha256(&readback).bytes() == digest;
    readback.fill(0);
    if !matches {
        return Err("snapshot output readback mismatch");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn output_refuses_unscoped_or_existing_files() -> Result<(), Box<dyn std::error::Error>> {
        assert!(validate(Path::new("/tmp/other.jpg")).is_err());
        assert!(validate(Path::new("/tmp/subdir/fss-unifi-snapshot-x.jpg")).is_err());
        let path = Path::new("/tmp").join(format!(
            "fss-unifi-snapshot-test-{}.jpg",
            std::process::id()
        ));
        let bytes = b"synthetic fixture bytes";
        save(&path, bytes, ContentDigest::sha256(bytes).bytes())?;
        assert!(save(&path, bytes, ContentDigest::sha256(bytes).bytes()).is_err());
        assert_eq!(std::fs::read(&path)?, bytes);
        std::fs::remove_file(path)?;
        Ok(())
    }
}
