#![forbid(unsafe_code)]
//! Exclusive publication of bytes released by the independent retrieval verifier.
//! The output's parent is pinned by descriptor; no caller can export arbitrary bytes.

use super::*;
use fss_core::ContentDigest;
use fss_object::uploader::{RetrievalOutcome, VerifiedRetrievalBytes};

#[derive(Clone, Copy, Debug, Default)]
pub(in super::super) struct RestoreOutputState {
    pub created: bool,
    pub verified: bool,
    pub durable: bool,
    pub bytes: u64,
    pub digest: Option<ContentDigest>,
}

impl ScopedS3Io {
    fn restore_path(&self) -> io::Result<&Path> {
        self.restore_output
            .as_ref()
            .map(|(path, _)| path.as_path())
            .ok_or_else(denied)
    }

    // Receipt cleanup has a separate lifetime. It must not extend media export authority.
    fn restore_admit(&self, bytes: u64, operations: u64) -> io::Result<()> {
        let (path, deadline) = self.restore_output.as_ref().ok_or_else(denied)?;
        if self.now()? >= *deadline {
            return Err(denied());
        }
        self.admit(RuntimeGrant::ObjectStage, path, bytes, operations)?;
        if self.now()? >= *deadline {
            return Err(denied());
        }
        Ok(())
    }

    pub(in super::super) fn preflight_restore_output(&self) -> io::Result<()> {
        let path = self.restore_path()?;
        self.restore_admit(0, 0)?;
        if self
            .inspect(path, RuntimeGrant::ObjectStage, path, true)?
            .is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "restoration output must be a new file",
            ));
        }
        let parent = path.parent().ok_or_else(denied)?;
        let metadata = self
            .inspect(parent, RuntimeGrant::ObjectStage, path, false)?
            .ok_or_else(denied)?;
        directory_identity(&metadata)?;
        self.restore_admit(0, 0)
    }

    fn restore_parent_unchanged(
        &self,
        parent: &Path,
        pinned: &File,
        expected: Identity,
    ) -> io::Result<()> {
        let path = self.restore_path()?;
        self.restore_admit(0, 1)?;
        if directory_identity(&pinned.metadata().map_err(native)?)? != expected {
            return Err(changed());
        }
        let named = self
            .inspect(parent, RuntimeGrant::ObjectStage, path, false)?
            .ok_or_else(changed)?;
        if directory_identity(&named)? != expected {
            return Err(changed());
        }
        self.restore_admit(0, 0)
    }

    fn restore_stamp(&self, file: &File, expected: Identity) -> io::Result<Stamp> {
        let path = self.restore_path()?;
        self.restore_admit(0, 1)?;
        let opened = file.metadata().map_err(native)?;
        let named = self
            .inspect(path, RuntimeGrant::ObjectStage, path, false)?
            .ok_or_else(changed)?;
        let opened_stamp = private_stamp(&opened)?;
        if opened_stamp.identity != expected || private_stamp(&named)? != opened_stamp {
            return Err(changed());
        }
        self.restore_admit(0, 0)?;
        Ok(opened_stamp)
    }

    /// A failed publication may leave a private partial file. Never delete, truncate, or reuse it.
    /// The state separately records creation, exact readback, and confirmed file/parent durability.
    pub(in super::super) fn write_restored_object(
        &self,
        object: &VerifiedRetrievalBytes,
        state: &mut RestoreOutputState,
    ) -> io::Result<()> {
        if state.created || state.verified || state.durable {
            return Err(denied());
        }
        let bytes = object.bytes();
        let receipt = object.receipt();
        if receipt.outcome() != RetrievalOutcome::Verified
            || bytes.is_empty()
            || bytes.len() as u64 > MAX_SOURCE_BYTES
            || bytes.len() as u64 != receipt.expected_bytes()
        {
            return Err(denied());
        }
        self.preflight_restore_output()?;
        let path = self.restore_path()?;
        let parent = path.parent().ok_or_else(denied)?;
        let parent_metadata = self
            .inspect(parent, RuntimeGrant::ObjectStage, path, false)?
            .ok_or_else(denied)?;
        let parent_identity = directory_identity(&parent_metadata)?;
        self.restore_admit(0, 1)?;
        let pinned_parent = nofollow_options()?
            .read(true)
            .open(parent)
            .map_err(native)?;
        self.restore_parent_unchanged(parent, &pinned_parent, parent_identity)?;
        // Reserve the full write and independent readback, including EOF, before creation.
        let io_bytes = (bytes.len() as u64)
            .checked_mul(2)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(limit)?;
        self.restore_admit(io_bytes, 1)?;
        // Resolve the final component against the held directory, not a replaceable pathname.
        let pinned_path = PathBuf::from(format!("/proc/self/fd/{}", descriptor(&pinned_parent)?))
            .join(path.file_name().ok_or_else(denied)?);
        let mut file = nofollow_options()?
            .read(true)
            .write(true)
            .create_new(true)
            .open(&pinned_path)
            .map_err(native)?;
        state.created = true;
        self.restore_admit(0, 1)?;
        let opened_identity = identity(&file.metadata().map_err(native)?)?;
        self.restore_parent_unchanged(parent, &pinned_parent, parent_identity)?;
        self.restore_stamp(&file, opened_identity)?;

        let mut offset = 0;
        let mut interrupted = 0;
        while offset < bytes.len() {
            let end = offset.saturating_add(READ_CHUNK).min(bytes.len());
            self.restore_admit(0, 1)?;
            match file.write(&bytes[offset..end]) {
                Ok(0) => return Err(changed()),
                Ok(count) => {
                    offset += count;
                    interrupted = 0;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted && interrupted < 8 => {
                    interrupted += 1;
                }
                Err(error) => return Err(native(error)),
            }
            self.restore_admit(0, 0)?;
        }
        self.restore_admit(0, 1)?;
        file.sync_all().map_err(native)?;
        let before = self.restore_stamp(&file, opened_identity)?;
        if before.len != bytes.len() as u64 {
            return Err(changed());
        }
        self.restore_admit(0, 1)?;
        file.seek(SeekFrom::Start(0)).map_err(native)?;
        // Readback scratch is bounded independently of the retained object's size.
        let mut scratch = buffer((bytes.len() as u64).clamp(1, READ_CHUNK as u64))?;
        offset = 0;
        interrupted = 0;
        while offset < bytes.len() {
            let take = scratch.0.len().min(bytes.len() - offset);
            self.restore_admit(0, 1)?;
            match file.read(&mut scratch.0[..take]) {
                Ok(0) => return Err(changed()),
                Ok(count) => {
                    if scratch.0[..count] != bytes[offset..offset + count] {
                        return Err(changed());
                    }
                    offset += count;
                    interrupted = 0;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted && interrupted < 8 => {
                    interrupted += 1;
                }
                Err(error) => return Err(native(error)),
            }
            self.restore_admit(0, 0)?;
        }
        interrupted = 0;
        loop {
            self.restore_admit(0, 1)?;
            match file.read(&mut scratch.0[..1]) {
                Ok(0) => break,
                Ok(_) => return Err(changed()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted && interrupted < 8 => {
                    interrupted += 1;
                }
                Err(error) => return Err(native(error)),
            }
        }
        if self.restore_stamp(&file, opened_identity)? != before {
            return Err(changed());
        }
        self.restore_parent_unchanged(parent, &pinned_parent, parent_identity)?;
        state.verified = true;
        state.bytes = bytes.len() as u64;
        state.digest = Some(receipt.expected_digest());

        self.restore_admit(0, 1)?;
        pinned_parent.sync_all().map_err(native)?;
        let final_check = (|| {
            self.restore_parent_unchanged(parent, &pinned_parent, parent_identity)?;
            if self.restore_stamp(&file, opened_identity)? != before {
                return Err(changed());
            }
            self.restore_admit(0, 0)
        })();
        if let Err(error) = final_check {
            state.verified = false;
            state.bytes = 0;
            state.digest = None;
            return Err(error);
        }
        state.durable = true;
        Ok(())
    }
}

fn directory_identity(metadata: &Metadata) -> io::Result<Identity> {
    if !metadata.is_dir() {
        return Err(denied());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(Identity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    Err(denied())
}

fn private_stamp(metadata: &Metadata) -> io::Result<Stamp> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(denied());
        }
    }
    stamp(metadata)
}
