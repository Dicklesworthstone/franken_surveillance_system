#![forbid(unsafe_code)]
//! A fixed set of held directory descriptors owns every destination name until activation.
//!
//! The supported Linux writers use /proc/self/fd as the existing export-package writer does.
//! User paths never enter that namespace. All names remain create-only and each directory's
//! original identity is rechecked; parent replacement cannot redirect an original byte.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, DirEntry, File, FileType, Metadata, OpenOptions, ReadDir, TryLockError};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use fss_object::SpoolIo;

use super::{directory, regular, same_file};
use crate::deployment_backup::{BackupError, Result};

// Linux UAPI values differ for these two supported native architectures. See the identical
// tables and rationale in ingest/file_adapter.rs and fss-export-package/file.rs.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod flags {
    pub const DIRECTORY: i32 = 0o200_000;
    pub const NOFOLLOW: i32 = 0o400_000;
}
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod flags {
    pub const DIRECTORY: i32 = 0o40_000;
    pub const NOFOLLOW: i32 = 0o100_000;
}

fn supported() -> Result<()> {
    if cfg!(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )) {
        Ok(())
    } else {
        Err(BackupError::Unsupported("pinned_directory_platform"))
    }
}
fn identity(metadata: &Metadata) -> Result<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok((metadata.dev(), metadata.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Err(BackupError::Unsupported("file_identity_platform"))
    }
}
fn flags(options: &mut OpenOptions, is_directory: bool) {
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(
            0o4_000 | flags::NOFOLLOW | if is_directory { flags::DIRECTORY } else { 0 },
        );
    }
    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    let _ = (options, is_directory);
}
fn name(path: &Path) -> Result<&OsStr> {
    match path.components().next_back() {
        Some(Component::Normal(name)) => Ok(name),
        _ => Err(BackupError::InvalidPath),
    }
}

#[derive(Debug)]
struct DirectoryPin {
    path: PathBuf,
    file: File,
    identity: (u64, u64),
}
impl DirectoryPin {
    fn open(path: PathBuf, opened_path: &Path) -> Result<Self> {
        supported()?;
        let before = fs::symlink_metadata(opened_path)?;
        if !before.is_dir() {
            return Err(BackupError::InvalidPath);
        }
        let mut options = OpenOptions::new();
        options.read(true);
        flags(&mut options, true);
        let file = options.open(opened_path)?;
        if !file.metadata()?.is_dir() || identity(&before)? != identity(&file.metadata()?)? {
            return Err(BackupError::Changed);
        }
        let pin = Self {
            path,
            file,
            identity: identity(&before)?,
        };
        pin.check()?;
        Ok(pin)
    }
    fn check(&self) -> Result<()> {
        let observed = fs::symlink_metadata(&self.path)?;
        if !observed.is_dir()
            || observed.file_type().is_symlink()
            || identity(&observed)? != self.identity
            || identity(&self.file.metadata()?)? != self.identity
        {
            return Err(BackupError::Changed);
        }
        Ok(())
    }
    fn descriptor_path(&self) -> Result<PathBuf> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let path = PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()));
            if identity(&fs::metadata(&path)?)? != self.identity {
                return Err(BackupError::Changed);
            }
            Ok(path)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(BackupError::Unsupported("pinned_directory_platform"))
        }
    }
    fn held(&self, child: &OsStr) -> Result<PathBuf> {
        let path = Path::new(child);
        if path.components().count() != 1 || name(path)? != child {
            return Err(BackupError::InvalidPath);
        }
        Ok(self.descriptor_path()?.join(child))
    }
}

/// Only the fixed current-profile directories are created; the map never grows during copying.
#[derive(Debug)]
pub(in crate::deployment_backup) struct WriteTree {
    directories: BTreeMap<PathBuf, DirectoryPin>,
    root: PathBuf,
}
impl WriteTree {
    pub(in crate::deployment_backup) fn reserve(
        root: &Path,
        gate: &dyn Fn() -> Result<()>,
    ) -> Result<Self> {
        gate()?;
        supported()?;
        let parent_path = directory(root.parent().ok_or(BackupError::InvalidPath)?)?;
        let parent = DirectoryPin::open(parent_path.clone(), &parent_path)?;
        let mut tree = Self {
            directories: BTreeMap::from([(parent_path, parent)]),
            root: root.to_path_buf(),
        };
        tree.create_directory(root, gate)?;
        Ok(tree)
    }
    pub(in crate::deployment_backup) fn check(&self) -> Result<()> {
        for pin in self.directories.values() {
            pin.check()?;
        }
        Ok(())
    }
    fn parent(&self, path: &Path) -> Result<&DirectoryPin> {
        self.directories
            .get(path.parent().ok_or(BackupError::InvalidPath)?)
            .ok_or(BackupError::InvalidPath)
    }
    pub(in crate::deployment_backup) fn create_directory(
        &mut self,
        path: &Path,
        gate: &dyn Fn() -> Result<()>,
    ) -> Result<()> {
        gate()?;
        self.check()?;
        if self.directories.len() >= 16 || !path.starts_with(&self.root) {
            return Err(BackupError::InvalidPath);
        }
        let parent = self.parent(path)?;
        let held = parent.held(name(path)?)?;
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&held).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                BackupError::DestinationExists
            } else {
                error.into()
            }
        })?;
        let pin = DirectoryPin::open(path.to_path_buf(), &held)?;
        parent.file.sync_all()?;
        self.directories.insert(path.to_path_buf(), pin);
        self.check()?;
        gate()
    }
    pub(in crate::deployment_backup) fn write_new(
        &self,
        path: &Path,
        bytes: &[u8],
        gate: &dyn Fn() -> Result<()>,
    ) -> Result<File> {
        self.write_new_before_open(path, bytes, gate, &|| Ok(()))
    }
    fn write_new_before_open(
        &self,
        path: &Path,
        bytes: &[u8],
        gate: &dyn Fn() -> Result<()>,
        before_open: &dyn Fn() -> Result<()>,
    ) -> Result<File> {
        gate()?;
        self.check()?;
        let parent = self.parent(path)?;
        let held = parent.held(name(path)?)?;
        before_open()?;
        // Even a substitution immediately after the identity check cannot redirect this open:
        // the kernel resolves its parent through the still-held original directory descriptor.
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        flags(&mut options, false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&held).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                BackupError::DestinationExists
            } else {
                error.into()
            }
        })?;
        regular(&file.metadata()?)?;
        self.check()?;
        let mut at = 0;
        let mut interruptions = 0;
        while at < bytes.len() {
            gate()?;
            self.check()?;
            let end = at.saturating_add(65_536).min(bytes.len());
            match file.write(&bytes[at..end]) {
                Ok(0) => return Err(BackupError::Io(io::ErrorKind::WriteZero)),
                Ok(n) => at += n,
                Err(error) if error.kind() == io::ErrorKind::Interrupted && interruptions < 8 => {
                    interruptions += 1
                }
                Err(error) => return Err(error.into()),
            }
        }
        gate()?;
        self.check()?;
        file.sync_all()?;
        parent.file.sync_all()?;
        let before = file.metadata()?;
        regular(&before)?;
        if !same_file(&before, &fs::symlink_metadata(held)?) {
            return Err(BackupError::Changed);
        }
        self.check()?;
        Ok(file)
    }
    pub(in crate::deployment_backup) fn open_read(&self, path: &Path) -> Result<File> {
        self.check()?;
        let held = self.parent(path)?.held(name(path)?)?;
        let before = fs::symlink_metadata(&held)?;
        regular(&before)?;
        let mut options = OpenOptions::new();
        options.read(true);
        flags(&mut options, false);
        let file = options.open(&held)?;
        regular(&file.metadata()?)?;
        if !same_file(&before, &file.metadata()?) {
            return Err(BackupError::Changed);
        }
        self.check()?;
        Ok(file)
    }
    pub(in crate::deployment_backup) fn sync_directory(
        &self,
        path: &Path,
        gate: &dyn Fn() -> Result<()>,
    ) -> Result<()> {
        gate()?;
        self.check()?;
        self.directories
            .get(path)
            .ok_or(BackupError::InvalidPath)?
            .file
            .sync_all()?;
        Ok(())
    }
    pub(in crate::deployment_backup) fn remove_marker(
        &self,
        path: &Path,
        gate: &dyn Fn() -> Result<()>,
    ) -> Result<()> {
        gate()?;
        self.check()?;
        let parent = self.parent(path)?;
        fs::remove_file(parent.held(name(path)?)?)?;
        // Removal is the activation point. Complete durability with the already-held directory
        // descriptions, without a cancellable path reopen or re-admission of a replacement.
        parent
            .file
            .sync_all()
            .map_err(|_| BackupError::Indeterminate)?;
        self.directories
            .get(self.root.parent().ok_or(BackupError::InvalidPath)?)
            .ok_or(BackupError::InvalidPath)?
            .file
            .sync_all()
            .map_err(|_| BackupError::Indeterminate)?;
        self.check().map_err(|_| BackupError::Indeterminate)
    }
    pub(in crate::deployment_backup) fn held_file_path(&self, file: &File) -> Result<PathBuf> {
        self.check()?;
        regular(&file.metadata()?)?;
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
            if identity(&fs::metadata(&path)?)? != identity(&file.metadata()?)? {
                return Err(BackupError::Changed);
            }
            Ok(path)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(BackupError::Unsupported("pinned_directory_platform"))
        }
    }
    fn resolve(&self, path: &Path) -> Result<PathBuf> {
        self.check()?;
        if let Some(pin) = self.directories.get(path) {
            return pin.descriptor_path();
        }
        if let Ok(parent) = self.parent(path) {
            return parent.held(name(path)?);
        }
        // read_dir yields entry paths beneath its descriptor spelling; those names still map
        // to the exact admitted directory, never to arbitrary /proc caller input.
        for pin in self.directories.values() {
            let held = pin.descriptor_path()?;
            if path == held {
                return Ok(held);
            }
            if path.parent() == Some(held.as_path()) {
                return pin.held(name(path)?);
            }
        }
        Err(BackupError::InvalidPath)
    }
    fn directory_metadata(&self, path: &Path) -> Result<Option<Metadata>> {
        if let Some(pin) = self.directories.get(path) {
            pin.check()?;
            return Ok(Some(pin.file.metadata()?));
        }
        for pin in self.directories.values() {
            if path == pin.descriptor_path()? {
                pin.check()?;
                return Ok(Some(pin.file.metadata()?));
            }
        }
        Ok(None)
    }
}

/// Capability for the already-admitted destination directories during synchronous native spool
/// staging. The borrowed caller checks its live BackupAuthority/Cx before and after each native
/// operation; these methods keep every native internal path tied to those physical directories.
#[derive(Debug)]
pub(in crate::deployment_backup) struct PinnedSpoolIo {
    tree: Arc<WriteTree>,
}
impl PinnedSpoolIo {
    pub(in crate::deployment_backup) fn new(tree: Arc<WriteTree>) -> Self {
        Self { tree }
    }
    fn resolve(&self, path: &Path) -> io::Result<PathBuf> {
        self.tree.resolve(path).map_err(as_io)
    }
    fn deny<T>(&self) -> io::Result<T> {
        Err(io::ErrorKind::PermissionDenied.into())
    }
}
fn as_io(_: BackupError) -> io::Error {
    io::ErrorKind::PermissionDenied.into()
}
impl SpoolIo for PinnedSpoolIo {
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        self.tree.check().map_err(as_io)?;
        if self.tree.directories.contains_key(path) {
            Ok(())
        } else {
            self.deny()
        }
    }
    fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.symlink_metadata(path)
    }
    fn symlink_metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.tree.check().map_err(as_io)?;
        if let Some(metadata) = self.tree.directory_metadata(path).map_err(as_io)? {
            return Ok(metadata);
        }
        let metadata = fs::symlink_metadata(self.resolve(path)?)?;
        if metadata.is_file() {
            regular(&metadata).map_err(as_io)?;
        }
        Ok(metadata)
    }
    fn open_lock(&self, path: &Path) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        flags(&mut options, false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(self.resolve(path)?)?;
        regular(&file.metadata()?).map_err(as_io)?;
        Ok(file)
    }
    fn try_lock(&self, file: &File) -> std::result::Result<(), TryLockError> {
        file.try_lock()
    }
    fn create_dir(&self, path: &Path) -> io::Result<()> {
        self.tree.check().map_err(as_io)?;
        // Native open probes each required subdirectory with create_dir before checking its
        // metadata. They already exist under our held pins; no new native directory is allowed.
        if self.tree.directories.contains_key(path) {
            Err(io::ErrorKind::AlreadyExists.into())
        } else {
            self.deny()
        }
    }
    fn read_dir(&self, path: &Path) -> io::Result<ReadDir> {
        fs::read_dir(self.resolve(path)?)
    }
    fn next_dir_entry(&self, entries: &mut ReadDir) -> Option<io::Result<DirEntry>> {
        if let Err(error) = self.tree.check() {
            return Some(Err(as_io(error)));
        }
        entries.next()
    }
    fn entry_file_type(&self, entry: &DirEntry) -> io::Result<FileType> {
        self.tree.check().map_err(as_io)?;
        entry.file_type()
    }
    fn create_new(&self, path: &Path) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        flags(&mut options, false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(self.resolve(path)?)
    }
    fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<usize> {
        self.tree.check().map_err(as_io)?;
        file.write(bytes)
    }
    fn sync_file(&self, file: &File) -> io::Result<()> {
        self.tree.check().map_err(as_io)?;
        file.sync_all()
    }
    fn open_read(&self, path: &Path) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.read(true);
        flags(&mut options, false);
        let file = options.open(self.resolve(path)?)?;
        regular(&file.metadata()?).map_err(as_io)?;
        Ok(file)
    }
    fn read_bounded(&self, file: &mut File, limit: u64) -> io::Result<Vec<u8>> {
        self.tree.check().map_err(as_io)?;
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 65_536];
        let mut left = limit;
        let mut interruptions = 0;
        while left > 0 {
            self.tree.check().map_err(as_io)?;
            let n = left.min(buffer.len() as u64) as usize;
            match file.read(&mut buffer[..n]) {
                Ok(0) => break,
                Ok(n) => {
                    bytes.extend_from_slice(&buffer[..n]);
                    left -= n as u64;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted && interruptions < 8 => {
                    interruptions += 1
                }
                Err(error) => return Err(error),
            }
        }
        Ok(bytes)
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        // Adapt the native spool's promotion to create-only link + unlink. An occupied target
        // is never overwritten. If unlink fails after installing the target, the spool's
        // existing indeterminate-promotion path preserves the incomplete restoration marker.
        if !from.parent().is_some_and(|p| p.ends_with("spool/staging"))
            || !to.parent().is_some_and(|p| p.ends_with("spool/objects"))
        {
            return self.deny();
        }
        let source = self.resolve(from)?;
        let target = self.resolve(to)?;
        fs::hard_link(&source, target)?;
        fs::remove_file(source)
    }
    fn remove_file(&self, path: &Path) -> io::Result<()> {
        fs::remove_file(self.resolve(path)?)
    }
    fn sync_directory(&self, path: &Path) -> io::Result<()> {
        self.tree.check().map_err(as_io)?;
        if let Some(pin) = self.tree.directories.get(path) {
            return pin.file.sync_all();
        }
        self.deny()
    }
    fn hard_link(&self, from: &Path, to: &Path) -> io::Result<()> {
        fs::hard_link(self.resolve(from)?, self.resolve(to)?)
    }
}

#[cfg(all(
    test,
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    #[test]
    fn parent_replaced_after_admission_never_redirects_original_output()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let base = std::env::temp_dir().join(format!("fss-backup-pin-race-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir(&base)?;
        let root = base.join("selected");
        let outside = base.join("outside");
        fs::create_dir(&outside)?;
        let tree = WriteTree::reserve(&root, &|| Ok(()))?;
        let moved = base.join("old-selected");
        let result = tree.write_new_before_open(
            &root.join("original"),
            b"private original bytes",
            &|| Ok(()),
            &|| {
                fs::rename(&root, &moved)?;
                symlink(&outside, &root)?;
                Ok(())
            },
        );
        assert!(matches!(result, Err(BackupError::Changed)));
        assert!(fs::read_dir(&outside)?.next().is_none());
        // The descriptor can only create in the original private directory; the following
        // identity check refuses before even the first original byte is written there.
        assert_eq!(fs::metadata(moved.join("original"))?.len(), 0);
        assert!(
            tree.write_new(&root.join("later-original"), b"later", &|| Ok(()))
                .is_err()
        );
        assert!(fs::read_dir(&outside)?.next().is_none());
        drop(tree);
        fs::remove_dir_all(base)?;
        Ok(())
    }
}
