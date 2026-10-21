#![forbid(unsafe_code)]
//! Bounded private operator metadata. Every native boundary asks its request owner.
//! Output is create-only; input identity/permissions are checked around each read.

use std::path::{Component, Path, PathBuf};

pub(crate) const MAX_FILE_BYTES: usize = 262_144;
const MAX_IO_CALLS: usize = 1024;
const FILE: &str = "ERR-ONVIF-PRIVATE-FILE-001";

pub(crate) fn absolute_path(text: &str) -> Result<PathBuf, &'static str> {
    let path = PathBuf::from(text);
    if text.is_empty()
        || text.len() > 4096
        || text.chars().any(char::is_control)
        || !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
        || text.split('/').any(|part| matches!(part, "." | ".."))
    {
        return Err(FILE);
    }
    Ok(path)
}

#[cfg(target_os = "linux")]
mod native {
    use super::*;
    use std::fs::{self, File, Metadata, OpenOptions};
    use std::io::{ErrorKind, Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    const OPEN_FLAGS: i32 = 0o4000 | 0o400000; // O_NONBLOCK | O_NOFOLLOW, Linux ABI.

    #[derive(Clone, Copy, Eq, PartialEq)]
    struct Identity {
        device: u64,
        inode: u64,
        mode: u32,
        owner: u32,
        group: u32,
        links: u64,
        length: u64,
        modified: (i64, i64),
        changed: (i64, i64),
    }
    fn identity(meta: &Metadata) -> Result<Identity, &'static str> {
        if !meta.is_file()
            || meta.mode() & 0o077 != 0
            || meta.mode() & 0o400 == 0
            || meta.nlink() != 1
            || meta.len() == 0
            || meta.len() > MAX_FILE_BYTES as u64
        {
            return Err(FILE);
        }
        Ok(Identity {
            device: meta.dev(),
            inode: meta.ino(),
            mode: meta.mode(),
            owner: meta.uid(),
            group: meta.gid(),
            links: meta.nlink(),
            length: meta.len(),
            modified: (meta.mtime(), meta.mtime_nsec()),
            changed: (meta.ctime(), meta.ctime_nsec()),
        })
    }

    pub(crate) struct InputLease {
        path: PathBuf,
        file: File,
        identity: Identity,
        bytes: Vec<u8>,
    }
    impl InputLease {
        pub(crate) fn open(
            path: &Path,
            check: &impl Fn() -> Result<(), &'static str>,
        ) -> Result<Self, &'static str> {
            check()?;
            if fs::canonicalize(path).map_err(|_| FILE)? != path {
                return Err(FILE);
            }
            check()?;
            let before = identity(&fs::symlink_metadata(path).map_err(|_| FILE)?)?;
            check()?;
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(OPEN_FLAGS)
                .open(path)
                .map_err(|_| FILE)?;
            check()?;
            if identity(&file.metadata().map_err(|_| FILE)?)? != before {
                return Err(FILE);
            }
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(before.length as usize + 1)
                .map_err(|_| FILE)?;
            let mut chunk = [0_u8; 4096];
            let mut ended = false;
            for _ in 0..MAX_IO_CALLS {
                check()?;
                match file.read(&mut chunk) {
                    Ok(0) => {
                        ended = true;
                        break;
                    }
                    Ok(count) => {
                        if bytes
                            .len()
                            .checked_add(count)
                            .is_none_or(|n| n > MAX_FILE_BYTES)
                        {
                            return Err(FILE);
                        }
                        bytes.extend_from_slice(&chunk[..count]);
                    }
                    Err(error) if error.kind() == ErrorKind::Interrupted => {}
                    Err(_) => return Err(FILE),
                }
                check()?;
            }
            if !ended || bytes.len() != before.length as usize {
                return Err(FILE);
            }
            let result = Self {
                path: path.to_owned(),
                file,
                identity: before,
                bytes,
            };
            result.revalidate(check)?;
            Ok(result)
        }

        pub(crate) fn bytes(&self) -> &[u8] {
            &self.bytes
        }

        /// Stable identity for approval across separate preview/execution processes.
        /// Access time is deliberately excluded because reading is not a change.
        pub(crate) fn fingerprint(&self) -> [u8; 88] {
            let identity = self.identity;
            let values = [
                identity.device,
                identity.inode,
                u64::from(identity.mode),
                u64::from(identity.owner),
                u64::from(identity.group),
                identity.links,
                identity.length,
                identity.modified.0 as u64,
                identity.modified.1 as u64,
                identity.changed.0 as u64,
                identity.changed.1 as u64,
            ];
            let mut bytes = [0_u8; 88];
            for (chunk, value) in bytes.chunks_exact_mut(8).zip(values) {
                chunk.copy_from_slice(&value.to_be_bytes());
            }
            bytes
        }

        pub(crate) fn revalidate(
            &self,
            check: &impl Fn() -> Result<(), &'static str>,
        ) -> Result<(), &'static str> {
            check()?;
            if identity(&self.file.metadata().map_err(|_| FILE)?)? != self.identity {
                return Err(FILE);
            }
            check()?;
            if identity(&fs::symlink_metadata(&self.path).map_err(|_| FILE)?)? != self.identity {
                return Err(FILE);
            }
            check()?;
            if fs::canonicalize(&self.path).map_err(|_| FILE)? != self.path {
                return Err(FILE);
            }
            check()
        }
    }
    impl Drop for InputLease {
        fn drop(&mut self) {
            self.bytes.fill(0);
        }
    }

    /// Parent identity is pinned before network work; the file is created only after
    /// the complete response has been validated. Incomplete writes remain private.
    pub(crate) struct Output {
        path: PathBuf,
        parent_path: PathBuf,
        parent: File,
        identity: (u64, u64),
    }
    impl Output {
        pub(crate) fn prepare(
            path: &Path,
            check: &impl Fn() -> Result<(), &'static str>,
        ) -> Result<Self, &'static str> {
            let parent_path = path.parent().ok_or(FILE)?.to_owned();
            check()?;
            if fs::canonicalize(&parent_path).map_err(|_| FILE)? != parent_path {
                return Err(FILE);
            }
            check()?;
            let parent = OpenOptions::new()
                .read(true)
                .custom_flags(OPEN_FLAGS)
                .open(&parent_path)
                .map_err(|_| FILE)?;
            check()?;
            let meta = parent.metadata().map_err(|_| FILE)?;
            if !meta.is_dir() || meta.mode() & 0o022 != 0 {
                return Err(FILE);
            }
            check()?;
            match fs::symlink_metadata(path) {
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                _ => return Err(FILE),
            }
            let result = Self {
                path: path.to_owned(),
                parent_path,
                parent,
                identity: (meta.dev(), meta.ino()),
            };
            result.check(check)?;
            Ok(result)
        }

        fn check(&self, check: &impl Fn() -> Result<(), &'static str>) -> Result<(), &'static str> {
            check()?;
            let meta = fs::symlink_metadata(&self.parent_path).map_err(|_| FILE)?;
            if !meta.is_dir()
                || meta.mode() & 0o022 != 0
                || (meta.dev(), meta.ino()) != self.identity
            {
                return Err(FILE);
            }
            check()?;
            if fs::canonicalize(&self.parent_path).map_err(|_| FILE)? != self.parent_path {
                return Err(FILE);
            }
            check()
        }

        fn check_file(
            &self,
            file: &File,
            check: &impl Fn() -> Result<(), &'static str>,
        ) -> Result<(), &'static str> {
            self.check(check)?;
            let opened = file.metadata().map_err(|_| FILE)?;
            check()?;
            let named = fs::symlink_metadata(&self.path).map_err(|_| FILE)?;
            for metadata in [&opened, &named] {
                if !metadata.is_file()
                    || metadata.mode() & 0o077 != 0
                    || metadata.mode() & 0o400 == 0
                    || metadata.nlink() != 1
                    || metadata.len() > MAX_FILE_BYTES as u64
                {
                    return Err(FILE);
                }
            }
            if (opened.dev(), opened.ino()) != (named.dev(), named.ino()) {
                return Err(FILE);
            }
            check()
        }

        pub(crate) fn write(
            &self,
            bytes: &[u8],
            check: &impl Fn() -> Result<(), &'static str>,
        ) -> Result<(), &'static str> {
            if bytes.is_empty() || bytes.len() > MAX_FILE_BYTES {
                return Err(FILE);
            }
            self.check(check)?;
            let pinned = PathBuf::from(format!("/proc/self/fd/{}", self.parent.as_raw_fd()))
                .join(self.path.file_name().ok_or(FILE)?);
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(OPEN_FLAGS)
                .open(pinned)
                .map_err(|_| FILE)?;
            let mut written = 0;
            for _ in 0..MAX_IO_CALLS {
                self.check_file(&file, check)?;
                if written == bytes.len() {
                    break;
                }
                let end = (written + 4096).min(bytes.len());
                match file.write(&bytes[written..end]) {
                    Ok(0) => return Err(FILE),
                    Ok(count) => written += count,
                    Err(error) if error.kind() == ErrorKind::Interrupted => {}
                    Err(_) => return Err(FILE),
                }
            }
            if written != bytes.len() {
                return Err(FILE);
            }
            self.check_file(&file, check)?;
            file.sync_all().map_err(|_| FILE)?;
            self.check_file(&file, check)?;
            self.parent.sync_all().map_err(|_| FILE)?;
            self.check_file(&file, check)?;
            let opened = identity(&file.metadata().map_err(|_| FILE)?)?;
            check()?;
            if opened != identity(&fs::symlink_metadata(&self.path).map_err(|_| FILE)?)? {
                return Err(FILE);
            }
            if opened.length != bytes.len() as u64 {
                return Err(FILE);
            }
            // A completed operator output means the retained file can be read back
            // exactly, not merely that write syscalls accepted the intended bytes.
            let verified = InputLease::open(&self.path, check)?;
            if verified.bytes() != bytes {
                return Err(FILE);
            }
            verified.revalidate(check)?;
            self.check_file(&file, check)?;
            check()
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod native {
    use super::*;
    pub(crate) struct InputLease;
    impl InputLease {
        pub(crate) fn open(
            _: &Path,
            check: &impl Fn() -> Result<(), &'static str>,
        ) -> Result<Self, &'static str> {
            check()?;
            Err(FILE)
        }
        pub(crate) fn bytes(&self) -> &[u8] {
            &[]
        }
        pub(crate) fn fingerprint(&self) -> [u8; 88] {
            [0_u8; 88]
        }
        pub(crate) fn revalidate(
            &self,
            check: &impl Fn() -> Result<(), &'static str>,
        ) -> Result<(), &'static str> {
            check()?;
            Err(FILE)
        }
    }
    pub(crate) struct Output;
    impl Output {
        pub(crate) fn prepare(
            _: &Path,
            check: &impl Fn() -> Result<(), &'static str>,
        ) -> Result<Self, &'static str> {
            check()?;
            Err(FILE)
        }
        pub(crate) fn write(
            &self,
            _: &[u8],
            check: &impl Fn() -> Result<(), &'static str>,
        ) -> Result<(), &'static str> {
            check()?;
            Err(FILE)
        }
    }
}

pub(crate) use native::{InputLease, Output};

#[cfg(all(test, target_os = "linux"))]
#[path = "private_file_tests.rs"]
mod tests;
