#![forbid(unsafe_code)]
//! Create-only publication of a complete package. Linux x86-64/aarch64 only for writing:
//! a held directory descriptor pins every temporary/final name through /proc/self/fd.
//! Offline bounded reads remain available on other platforms.

use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{CanonicalEncoder, ContentDigest};
use fss_reference::export_package::{MAX_PACKAGE_BYTES, PackageScope, PreparedPackage};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
const MAX_PATH_BYTES: usize = 4096;

#[derive(Debug)]
pub(super) enum FileError {
    Unsupported,
    InvalidOutput,
    Conflict,
    Cancelled,
    /// A complete final file may be visible; do not claim rollback or automatic removal.
    PublicationIndeterminate,
    Io(io::Error),
}
impl FileError {
    pub(super) const fn reason(&self) -> &'static str {
        match self {
            Self::Unsupported => "package_publication_unsupported_platform",
            Self::InvalidOutput => {
                "output_requires_protected_existing_directory_outside_deployment"
            }
            Self::Conflict => "output_exists_or_identity_changed",
            Self::Cancelled => "package_file_cancelled_before_publication",
            Self::PublicationIndeterminate => {
                "package_file_publication_indeterminate_verify_before_retry"
            }
            Self::Io(_) => "package_file_io_refused",
        }
    }
}
impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
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

fn supported_writer() -> bool {
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
        // Linux UAPI asm-generic/fcntl.h: O_NONBLOCK, O_NOFOLLOW, O_DIRECTORY.
        // No foreign runtime or unsafe syscall wrapper is added. Restrict these ABI constants
        // to the two explicitly supported Linux architectures.
        options.custom_flags((1 << 11) | (1 << 17) | if directory { 1 << 16 } else { 0 });
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if metadata.is_dir() != directory || (!directory && !metadata.is_file()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "regular file or directory required",
        ));
    }
    Ok(file)
}

/// Read from one opened regular file, never allocate from an unchecked file length.
pub(super) fn read_bounded(path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "regular non-symlink file required",
        ));
    }
    let file = open_read(path, false)?;
    if file.metadata()?.len() > maximum as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeds byte bound",
        ));
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeds byte bound",
        ));
    }
    Ok(bytes)
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
fn protected_directory(metadata: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.is_dir() && metadata.mode() & 0o022 == 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}

#[derive(Debug)]
pub(super) struct Target {
    path: PathBuf,
    name: OsString,
    parent: File,
    parent_identity: (u64, u64),
}
impl Target {
    pub(super) fn new(path: &Path, deployment_root: &Path) -> Result<Self, FileError> {
        if !supported_writer() {
            return Err(FileError::Unsupported);
        }
        if path.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES {
            return Err(FileError::InvalidOutput);
        }
        let name = match path.components().next_back() {
            Some(Component::Normal(name)) => name.to_owned(),
            _ => return Err(FileError::InvalidOutput),
        };
        let raw_parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent_path = fs::canonicalize(raw_parent)?;
        let deployment = fs::canonicalize(deployment_root)?;
        if parent_path.starts_with(&deployment) {
            return Err(FileError::InvalidOutput);
        }
        let path = parent_path.join(&name);
        if path.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES {
            return Err(FileError::InvalidOutput);
        }
        let parent = open_read(&parent_path, true)?;
        if !protected_directory(&parent.metadata()?) {
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

    fn held_path(&self, name: &std::ffi::OsStr) -> Result<PathBuf, FileError> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let directory = PathBuf::from(format!("/proc/self/fd/{}", self.parent.as_raw_fd()));
            if identity(&fs::metadata(&directory)?)? != self.parent_identity {
                return Err(FileError::Conflict);
            }
            Ok(directory.join(name))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = name;
            Err(FileError::Unsupported)
        }
    }

    fn check_current(&self) -> Result<(), FileError> {
        let parent_path = self.path.parent().ok_or(FileError::InvalidOutput)?;
        let metadata = fs::symlink_metadata(parent_path)?;
        if !metadata.file_type().is_dir()
            || !protected_directory(&metadata)
            || identity(&metadata)? != self.parent_identity
            || identity(&self.parent.metadata()?)? != self.parent_identity
        {
            return Err(FileError::Conflict);
        }
        Ok(())
    }

    /// Exact approval binds the immutable package, actor, recipient/time, OS path and actual
    /// destination directory. Replacing a directory at the same name invalidates the approval.
    pub(super) fn approval(
        &self,
        package: &PreparedPackage,
        scope: &PackageScope,
        actor: &str,
        site: &str,
    ) -> Result<ContentDigest, FileError> {
        self.check_current()?;
        let mut e = CanonicalEncoder::new();
        e.text("fss.export_package_file_approval.v1");
        e.digest(package.verified().root());
        e.digest(package.verified().package_digest());
        e.text(actor);
        e.text(site);
        e.text(&scope.recipient);
        e.i128(scope.attested_now.earliest.0);
        e.i128(scope.attested_now.latest.0);
        e.text(std::env::consts::OS);
        e.bytes(self.path.as_os_str().as_encoded_bytes());
        e.u64(self.parent_identity.0);
        e.u64(self.parent_identity.1);
        let bytes = e.finish_checked().map_err(|_| FileError::InvalidOutput)?;
        Ok(ContentDigest::sha256(&bytes))
    }

    fn existing(&self, bytes: &[u8]) -> Result<bool, FileError> {
        let path = self.held_path(&self.name)?;
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
            Ok(meta) if !meta.file_type().is_file() => return Err(FileError::Conflict),
            Ok(_) => {}
        }
        let mut file = open_read(&path, false)?;
        let original = identity(&file.metadata()?)?;
        if file.metadata()?.len() != bytes.len() as u64 {
            return Err(FileError::Conflict);
        }
        let mut retained = Vec::new();
        (&mut file)
            .take(MAX_PACKAGE_BYTES as u64 + 1)
            .read_to_end(&mut retained)?;
        if retained != bytes {
            return Err(FileError::Conflict);
        }
        file.sync_all()?;
        self.parent.sync_all()?;
        let named = fs::symlink_metadata(&path)?;
        if !named.file_type().is_file() || identity(&named)? != original {
            return Err(FileError::Conflict);
        }
        self.check_current()?;
        Ok(true)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FileReceipt {
    pub(super) already_present: bool,
    pub(super) temporary_cleanup_pending: bool,
}

struct Temporary<'a> {
    target: &'a Target,
    path: PathBuf,
    file: File,
}
impl Temporary<'_> {
    fn remove_own_name(&self) -> bool {
        let same = fs::symlink_metadata(&self.path).ok().is_some_and(|meta| {
            meta.file_type().is_file()
                && identity(&meta).ok() == self.file.metadata().ok().and_then(|m| identity(&m).ok())
        });
        same && fs::remove_file(&self.path).is_ok()
    }
    fn cleanup_pending(&self) -> bool {
        let cleaned = self.remove_own_name();
        let synced = self.target.parent.sync_all().is_ok();
        !cleaned || !synced
    }
}
impl Drop for Temporary<'_> {
    fn drop(&mut self) {
        if self.remove_own_name() {
            let _ = self.target.parent.sync_all();
        }
    }
}

/// The final path is linked only after complete write, file sync and readback. Hard-link creation
/// is no-replace: neither a file, directory nor a dangling symlink can be overwritten.
/// After final-name visibility, failures are indeterminate, never reported as rolled back.
pub(super) fn publish(
    target: &Target,
    bytes: &[u8],
    mut checkpoint: impl FnMut(&'static str) -> Result<(), FileError>,
) -> Result<FileReceipt, FileError> {
    if bytes.is_empty() || bytes.len() > MAX_PACKAGE_BYTES {
        return Err(FileError::InvalidOutput);
    }
    target.check_current()?;
    checkpoint("export_package:file_begin")?;
    if target.existing(bytes)? {
        return Ok(FileReceipt {
            already_present: true,
            temporary_cleanup_pending: false,
        });
    }
    let mut temporary = None;
    for _ in 0..64 {
        let ordinal = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let name = OsString::from(format!(
            ".fss-export-package-{}-{ordinal}.tmp",
            std::process::id()
        ));
        let path = target.held_path(&name)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => {
                temporary = Some(Temporary { target, path, file });
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    let mut temporary = temporary.ok_or(FileError::Conflict)?;
    checkpoint("export_package:file_staged")?;
    temporary.file.write_all(bytes)?;
    checkpoint("export_package:file_written")?;
    temporary.file.sync_all()?;
    temporary.file.seek(SeekFrom::Start(0))?;
    let mut readback = Vec::new();
    (&mut temporary.file)
        .take(MAX_PACKAGE_BYTES as u64 + 1)
        .read_to_end(&mut readback)?;
    if readback != bytes {
        return Err(FileError::Conflict);
    }
    target.check_current()?;
    checkpoint("export_package:file_publish")?;
    if identity(&fs::symlink_metadata(&temporary.path)?)? != identity(&temporary.file.metadata()?)?
    {
        return Err(FileError::Conflict);
    }
    let output = target.held_path(&target.name)?;
    match fs::hard_link(&temporary.path, &output) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if target.existing(bytes)? {
                return Ok(FileReceipt {
                    already_present: true,
                    temporary_cleanup_pending: temporary.cleanup_pending(),
                });
            }
            return Err(FileError::Conflict);
        }
        // A filesystem can lose the acknowledgement of a namespace mutation. Do not infer
        // that an error proves the final name absent; a later exact retry verifies it.
        Err(_) => return Err(FileError::PublicationIndeterminate),
    }
    // No cancellation check after visibility. All failures below preserve uncertainty.
    let final_meta =
        fs::symlink_metadata(&output).map_err(|_| FileError::PublicationIndeterminate)?;
    let owned_meta = temporary
        .file
        .metadata()
        .map_err(|_| FileError::PublicationIndeterminate)?;
    if !final_meta.file_type().is_file()
        || identity(&final_meta).ok() != identity(&owned_meta).ok()
        || target.parent.sync_all().is_err()
        || target.check_current().is_err()
    {
        return Err(FileError::PublicationIndeterminate);
    }
    Ok(FileReceipt {
        already_present: false,
        temporary_cleanup_pending: temporary.cleanup_pending(),
    })
}

#[cfg(test)]
#[path = "file/tests.rs"]
mod tests;
