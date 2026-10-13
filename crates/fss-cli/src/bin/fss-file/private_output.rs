#![forbid(unsafe_code)]
//! Shared request-owned path admission for private, create-only operator exports.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use fss_reference::ReplayCx;

fn refused(message: &'static str) -> io::Error {
    io::Error::other(message)
}
fn checkpoint(cx: &ReplayCx) -> io::Result<()> {
    cx.checkpoint("file_cli:private_export")
        .map_err(|_| refused("private export cancelled"))
}

/// Pins the canonical parent, not an output file. Creation remains lazy and exclusive.
/// Linux creates relative to the pinned directory handle; other targets retain the
/// protected-directory boundary and verify parent identity around each operation.
pub(crate) struct PrivateOutputPath {
    parent_path: PathBuf,
    root: PathBuf,
    name: OsString,
    #[cfg(unix)]
    parent: File,
    #[cfg(unix)]
    identity: (u64, u64),
}
impl PrivateOutputPath {
    pub(crate) fn prepare(path: &Path, root: &Path, cx: &ReplayCx) -> io::Result<Self> {
        checkpoint(cx)?;
        let root = fs::canonicalize(root)?;
        let parent_path = fs::canonicalize(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?;
        let name = path
            .file_name()
            .ok_or_else(|| refused("output filename required"))?
            .to_owned();
        let destination = parent_path.join(&name);
        if parent_path.starts_with(&root) || root.starts_with(&destination) {
            return Err(refused("exports must be outside the deployment"));
        }
        match fs::symlink_metadata(&destination) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            _ => return Err(refused("export destination must be absent")),
        }
        #[cfg(unix)]
        let parent = File::open(&parent_path)?;
        #[cfg(unix)]
        let identity = {
            use std::os::unix::fs::MetadataExt;
            let metadata = parent.metadata()?;
            if !metadata.is_dir() {
                return Err(refused("output parent must be a directory"));
            }
            (metadata.dev(), metadata.ino())
        };
        let result = Self {
            parent_path,
            root,
            name,
            #[cfg(unix)]
            parent,
            #[cfg(unix)]
            identity,
        };
        result.check(cx)?;
        Ok(result)
    }

    pub(crate) fn destination(&self) -> PathBuf {
        self.parent_path.join(&self.name)
    }

    pub(crate) fn check(&self, cx: &ReplayCx) -> io::Result<()> {
        checkpoint(cx)?;
        let metadata = fs::symlink_metadata(&self.parent_path)?;
        if !metadata.is_dir()
            || fs::canonicalize(&self.parent_path)? != self.parent_path
            || self.parent_path.starts_with(&self.root)
        {
            return Err(refused("export parent changed"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if (metadata.dev(), metadata.ino()) != self.identity {
                return Err(refused("export parent identity changed"));
            }
        }
        Ok(())
    }

    pub(crate) fn create(&self, cx: &ReplayCx) -> io::Result<File> {
        self.check(cx)?;
        #[cfg(target_os = "linux")]
        let destination = {
            use std::os::fd::AsRawFd;
            PathBuf::from(format!("/proc/self/fd/{}", self.parent.as_raw_fd())).join(&self.name)
        };
        #[cfg(not(target_os = "linux"))]
        let destination = self.destination();
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(destination)?;
        self.check_file(&file, cx)?;
        Ok(file)
    }

    fn check_file(&self, file: &File, cx: &ReplayCx) -> io::Result<()> {
        self.check(cx)?;
        let actual = fs::symlink_metadata(self.destination())?;
        let opened = file.metadata()?;
        if !actual.is_file() || !opened.is_file() {
            return Err(refused("export file identity changed"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if (actual.dev(), actual.ino()) != (opened.dev(), opened.ino()) {
                return Err(refused("export file identity changed"));
            }
        }
        Ok(())
    }

    /// Sync the created file and its parent before reporting a successful file export.
    pub(crate) fn sync(&self, file: &File, cx: &ReplayCx) -> io::Result<()> {
        self.check_file(file, cx)?;
        file.sync_all()?;
        #[cfg(unix)]
        self.parent.sync_all()?;
        self.check_file(file, cx)?;
        checkpoint(cx)
    }
}
