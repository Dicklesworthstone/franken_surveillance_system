#![forbid(unsafe_code)]
//! Protected, create-only bundle publication. A completion name is the last visible root.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use fss_core::{CanonicalEncoder, ContentDigest};

use super::RunResult;

const IO_CHUNK: usize = 64 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_INTERRUPTS: usize = 8;
const MAX_MEDIA_BYTES: usize = 64 * 1024 * 1024;
const MAX_METADATA_BYTES: usize = 512 * 1024;

#[derive(Debug)]
pub(super) enum FileError {
    Unsupported,
    InvalidOutput,
    Conflict,
    /// No completion is claimed. A private, partial output directory may exist.
    Incomplete,
    /// Completion may already be visible. Inspect/verify instead of assuming rollback.
    PublicationIndeterminate,
    Io(io::Error),
}

impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unsupported => "original_media_file_platform_unsupported",
            Self::InvalidOutput => "output_requires_protected_directory_outside_deployment",
            Self::Conflict => "output_conflict_incomplete_or_identity_changed",
            Self::Incomplete => "export_incomplete_private_output_may_exist_without_COMPLETE",
            Self::PublicationIndeterminate => {
                "export_publication_indeterminate_verify_COMPLETE_before_retry"
            }
            Self::Io(_) => "original_media_file_io_refused",
        })
    }
}
impl std::error::Error for FileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}
impl From<io::Error> for FileError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod open_flags {
    pub const O_NONBLOCK: i32 = 0o4_000;
    pub const O_DIRECTORY: i32 = 0o200_000;
    pub const O_NOFOLLOW: i32 = 0o400_000;
}
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod open_flags {
    pub const O_NONBLOCK: i32 = 0o4_000;
    pub const O_DIRECTORY: i32 = 0o40_000;
    pub const O_NOFOLLOW: i32 = 0o100_000;
}

fn supported() -> bool {
    cfg!(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
}

fn open_read(path: &Path, directory: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(
            open_flags::O_NONBLOCK
                | open_flags::O_NOFOLLOW
                | if directory {
                    open_flags::O_DIRECTORY
                } else {
                    0
                },
        );
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if metadata.is_dir() != directory || (!directory && !metadata.is_file()) {
        return Err(io::Error::other("regular file or directory required"));
    }
    Ok(file)
}

fn identity(metadata: &Metadata) -> Result<(u64, u64), FileError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok((metadata.dev(), metadata.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Err(FileError::Unsupported)
    }
}

fn protected_directory(metadata: &Metadata, private: bool) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.is_dir() && metadata.mode() & if private { 0o077 } else { 0o022 } == 0
    }
    #[cfg(not(unix))]
    {
        let _ = (metadata, private);
        false
    }
}

fn held_path(file: &File, expected: (u64, u64), name: &OsStr) -> Result<PathBuf, FileError> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let directory = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
        if identity(&fs::metadata(&directory)?)? != expected {
            return Err(FileError::Conflict);
        }
        Ok(directory.join(name))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (file, expected, name);
        Err(FileError::Unsupported)
    }
}

/// Read one opened regular file, with a strict allocation bound and stable named identity.
pub(super) fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, FileError> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(FileError::Conflict);
    }
    let mut file = open_read(path, false)?;
    let before = file.metadata()?;
    if before.len() > maximum as u64 {
        return Err(FileError::Conflict);
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    let named = fs::symlink_metadata(path)?;
    if bytes.len() > maximum
        || bytes.len() as u64 != before.len()
        || !named.file_type().is_file()
        || identity(&named)? != identity(&before)?
        || file.metadata()?.len() != before.len()
    {
        return Err(FileError::Conflict);
    }
    Ok(bytes)
}

pub(super) struct Target {
    path: PathBuf,
    name: OsString,
    parent: File,
    parent_identity: (u64, u64),
}

impl Target {
    pub(super) fn new(path: &Path, deployment: &Path) -> Result<Self, FileError> {
        if !supported() {
            return Err(FileError::Unsupported);
        }
        if path.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES {
            return Err(FileError::InvalidOutput);
        }
        let name = match path.components().next_back() {
            Some(Component::Normal(name)) => name.to_owned(),
            _ => return Err(FileError::InvalidOutput),
        };
        let parent_path = fs::canonicalize(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?;
        let deployment = fs::canonicalize(deployment)?;
        let path = parent_path.join(&name);
        if path.starts_with(&deployment)
            || deployment.starts_with(&path)
            || path.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES
        {
            return Err(FileError::InvalidOutput);
        }
        let parent = open_read(&parent_path, true)?;
        if !protected_directory(&parent.metadata()?, false) {
            return Err(FileError::InvalidOutput);
        }
        let parent_identity = identity(&parent.metadata()?)?;
        let target = Self {
            path,
            name,
            parent,
            parent_identity,
        };
        target.check_current()?;
        Ok(target)
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn binding(&self) -> Result<ContentDigest, FileError> {
        self.check_current()?;
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.original_media_export_destination.v1");
        encoder.text(std::env::consts::OS);
        encoder.bytes(self.path.as_os_str().as_encoded_bytes());
        encoder.u64(self.parent_identity.0);
        encoder.u64(self.parent_identity.1);
        let bytes = encoder
            .finish_checked()
            .map_err(|_| FileError::InvalidOutput)?;
        Ok(ContentDigest::sha256(&bytes))
    }

    fn held_path(&self) -> Result<PathBuf, FileError> {
        held_path(&self.parent, self.parent_identity, &self.name)
    }

    fn check_current(&self) -> Result<(), FileError> {
        let metadata = fs::symlink_metadata(self.path.parent().ok_or(FileError::InvalidOutput)?)?;
        if !metadata.file_type().is_dir()
            || !protected_directory(&metadata, false)
            || identity(&metadata)? != self.parent_identity
            || identity(&self.parent.metadata()?)? != self.parent_identity
        {
            return Err(FileError::Conflict);
        }
        Ok(())
    }
}

/// A directory descriptor pins all package reads and writes to the same directory inode.
pub(super) struct Input {
    path: PathBuf,
    directory: File,
    identity: (u64, u64),
}

impl Input {
    fn from_target(target: &Target) -> Result<Self, FileError> {
        target.check_current()?;
        // Never resolve the public parent path again after mkdir. Its held descriptor is
        // the approval-bound parent even if another process renames the directory.
        let path = target.held_path()?;
        let before = fs::symlink_metadata(&path)?;
        if !before.file_type().is_dir() {
            return Err(FileError::Conflict);
        }
        let directory = open_read(&path, true)?;
        let directory_identity = identity(&directory.metadata()?)?;
        if directory_identity != identity(&before)? {
            return Err(FileError::Conflict);
        }
        let input = Self {
            path: target.path.clone(),
            directory,
            identity: directory_identity,
        };
        target.check_current()?;
        input.private()?;
        Ok(input)
    }

    pub(super) fn open(path: &Path) -> Result<Self, FileError> {
        if !supported() {
            return Err(FileError::Unsupported);
        }
        if !fs::symlink_metadata(path)?.file_type().is_dir() {
            return Err(FileError::Conflict);
        }
        let path = fs::canonicalize(path)?;
        let directory = open_read(&path, true)?;
        let identity = identity(&directory.metadata()?)?;
        let input = Self {
            path,
            directory,
            identity,
        };
        input.check_current()?;
        Ok(input)
    }

    fn path(&self, name: &str) -> Result<PathBuf, FileError> {
        if !matches!(
            Path::new(name).components().next(),
            Some(Component::Normal(_))
        ) || Path::new(name).components().count() != 1
        {
            return Err(FileError::InvalidOutput);
        }
        held_path(&self.directory, self.identity, OsStr::new(name))
    }

    pub(super) fn read(&self, name: &str, maximum: usize) -> Result<Vec<u8>, FileError> {
        self.check_current()?;
        read_bounded(&self.path(name)?, maximum)
    }

    pub(super) fn media(&self, maximum: usize) -> Result<(String, Vec<u8>), FileError> {
        let mut selected = None;
        for name in ["source.mp4", "source.mjpeg"] {
            match fs::symlink_metadata(self.path(name)?) {
                Ok(_) if selected.is_some() => return Err(FileError::Conflict),
                Ok(_) => selected = Some(name),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        let name = selected.ok_or(FileError::Conflict)?;
        Ok((name.to_owned(), self.read(name, maximum)?))
    }

    pub(super) fn check_current(&self) -> Result<(), FileError> {
        let named = fs::symlink_metadata(&self.path)?;
        if !named.file_type().is_dir()
            || identity(&named)? != self.identity
            || identity(&self.directory.metadata()?)? != self.identity
        {
            return Err(FileError::Conflict);
        }
        Ok(())
    }

    fn private(&self) -> Result<(), FileError> {
        if !protected_directory(&self.directory.metadata()?, true) {
            return Err(FileError::Conflict);
        }
        self.check_current()
    }
}

pub(super) struct Receipt {
    pub(super) already_present: bool,
}

fn write_file(
    input: &Input,
    name: &str,
    bytes: &[u8],
    checkpoint: &mut impl FnMut(&'static str) -> RunResult<()>,
) -> RunResult<File> {
    checkpoint("original_media:file_create")?;
    input.private()?;
    let path = input.path(name)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path)?;
    let mut remaining = bytes;
    let mut interruptions = 0;
    while !remaining.is_empty() {
        checkpoint("original_media:file_write")?;
        let part = &remaining[..remaining.len().min(IO_CHUNK)];
        match file.write(part) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
            Ok(written) => {
                remaining = &remaining[written..];
                interruptions = 0;
            }
            Err(error)
                if error.kind() == io::ErrorKind::Interrupted && interruptions < MAX_INTERRUPTS =>
            {
                interruptions += 1;
            }
            Err(error) => return Err(error.into()),
        }
    }
    checkpoint("original_media:file_sync")?;
    file.sync_all()?;
    file.seek(SeekFrom::Start(0))?;
    verify_file(&mut file, bytes, checkpoint)?;
    let named = fs::symlink_metadata(&path)?;
    if !named.file_type().is_file() || identity(&named)? != identity(&file.metadata()?)? {
        return Err(FileError::Conflict.into());
    }
    Ok(file)
}

fn verify_file(
    file: &mut File,
    bytes: &[u8],
    checkpoint: &mut impl FnMut(&'static str) -> RunResult<()>,
) -> RunResult<()> {
    if file.metadata()?.len() != bytes.len() as u64 {
        return Err(FileError::Conflict.into());
    }
    let mut buffer = [0u8; IO_CHUNK];
    for expected in bytes.chunks(IO_CHUNK) {
        checkpoint("original_media:file_readback")?;
        let mut position = 0;
        let mut interruptions = 0;
        while position < expected.len() {
            match file.read(&mut buffer[position..expected.len()]) {
                Ok(0) => return Err(FileError::Conflict.into()),
                Ok(read) => {
                    position += read;
                    interruptions = 0;
                }
                Err(error)
                    if error.kind() == io::ErrorKind::Interrupted
                        && interruptions < MAX_INTERRUPTS =>
                {
                    interruptions += 1;
                }
                Err(error) => return Err(error.into()),
            }
        }
        if buffer[..expected.len()] != *expected {
            return Err(FileError::Conflict.into());
        }
    }
    if file.metadata()?.len() != bytes.len() as u64 {
        return Err(FileError::Conflict.into());
    }
    Ok(())
}

fn verify_existing(
    target: &Target,
    files: &[(&str, &[u8])],
    complete: &[u8],
    checkpoint: &mut impl FnMut(&'static str) -> RunResult<()>,
) -> RunResult<Receipt> {
    let input = Input::from_target(target)?;
    input.private()?;
    let mut allowed = files.iter().map(|(name, _)| *name).collect::<Vec<_>>();
    allowed.extend(["COMPLETE.json.pending", "COMPLETE.json"]);
    // An existing unrelated directory, partial export, extra object or symlink is never adopted.
    let entries = fs::read_dir(held_path(&input.directory, input.identity, OsStr::new(""))?)?;
    let mut count = 0;
    let mut pending_present = false;
    for entry in entries.take(allowed.len() + 1) {
        count += 1;
        let entry = entry?;
        pending_present |= entry.file_name() == "COMPLETE.json.pending";
        if !entry.file_type()?.is_file()
            || !entry
                .file_name()
                .to_str()
                .is_some_and(|name| allowed.contains(&name))
        {
            return Err(FileError::Conflict.into());
        }
    }
    if count != allowed.len() - usize::from(!pending_present) {
        return Err(FileError::Conflict.into());
    }
    for (name, bytes) in files
        .iter()
        .copied()
        .chain(pending_present.then_some(("COMPLETE.json.pending", complete)))
        .chain([("COMPLETE.json", complete)])
    {
        checkpoint("original_media:file_retry")?;
        let path = input.path(name)?;
        let mut file = open_read(&path, false)?;
        verify_file(&mut file, bytes, checkpoint)?;
        file.sync_all()?;
        let named = fs::symlink_metadata(&path)?;
        if !named.file_type().is_file() || identity(&named)? != identity(&file.metadata()?)? {
            return Err(FileError::Conflict.into());
        }
    }
    checkpoint("original_media:file_publish")?;
    input.directory.sync_all()?;
    target.parent.sync_all()?;
    input.private()?;
    target.check_current()?;
    Ok(Receipt {
        already_present: true,
    })
}

/// Each payload is create-only, synced and verified through its original handle. The completion
/// hard link is create-only too. Errors after visibility preserve uncertainty, never imply deletion.
pub(super) fn publish(
    target: &Target,
    files: &[(&str, &[u8])],
    complete: &[u8],
    mut checkpoint: impl FnMut(&'static str) -> RunResult<()>,
) -> RunResult<Receipt> {
    if files.len() != 4
        || complete.is_empty()
        || complete.len() > MAX_METADATA_BYTES
        || !matches!(files[0].0, "source.mp4" | "source.mjpeg")
        || files[0].1.is_empty()
        || files[0].1.len() > MAX_MEDIA_BYTES
        || files[1].0 != "record.canonical"
        || files[2].0 != "manifest.canonical"
        || files[3].0 != "record.json"
        || files[1..]
            .iter()
            .any(|(_, bytes)| bytes.is_empty() || bytes.len() > MAX_METADATA_BYTES)
    {
        return Err(FileError::InvalidOutput.into());
    }
    target.check_current()?;
    checkpoint("original_media:file_begin")?;
    match fs::symlink_metadata(target.held_path()?) {
        Ok(_) => return verify_existing(target, files, complete, &mut checkpoint),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(target.held_path()?)
        .map_err(|_| FileError::Incomplete)?;
    // After mkdir, preserve partial output on any refusal. No broad remove_dir_all rollback.
    checkpoint("original_media:directory_created").map_err(|_| FileError::Incomplete)?;
    let input = Input::from_target(target).map_err(|_| FileError::Incomplete)?;
    let staged = (|| -> RunResult<File> {
        input.private()?;
        for (name, bytes) in files {
            write_file(&input, name, bytes, &mut checkpoint)?;
        }
        let completion = write_file(&input, "COMPLETE.json.pending", complete, &mut checkpoint)?;
        input.directory.sync_all()?;
        target.parent.sync_all()?;
        target.check_current()?;
        input.private()?;
        checkpoint("original_media:file_publish")?;
        // The checkpoint may reopen authority and perform bounded reads: recheck destination
        // identities afterwards, immediately before the namespace publication.
        target.check_current()?;
        input.private()?;
        let pending = fs::symlink_metadata(input.path("COMPLETE.json.pending")?)?;
        if !pending.file_type().is_file()
            || identity(&pending)? != identity(&completion.metadata()?)?
        {
            return Err(FileError::Conflict.into());
        }
        Ok(completion)
    })();
    let completion = staged.map_err(|_| FileError::Incomplete)?;
    let pending = input.path("COMPLETE.json.pending")?;
    let final_path = input.path("COMPLETE.json")?;
    fs::hard_link(pending, &final_path).map_err(|_| FileError::PublicationIndeterminate)?;
    // No cancellation failure after the root is visible. Lost acknowledgements require verification.
    let named =
        fs::symlink_metadata(final_path).map_err(|_| FileError::PublicationIndeterminate)?;
    if !named.file_type().is_file()
        || identity(&named).ok() != completion.metadata().ok().and_then(|m| identity(&m).ok())
        || input.directory.sync_all().is_err()
        || target.parent.sync_all().is_err()
        || input.private().is_err()
        || target.check_current().is_err()
    {
        return Err(FileError::PublicationIndeterminate.into());
    }
    Ok(Receipt {
        already_present: false,
    })
}

#[cfg(test)]
#[path = "file/tests.rs"]
mod tests;
