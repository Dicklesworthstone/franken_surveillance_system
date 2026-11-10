#![forbid(unsafe_code)]
//! Pinned private output for create-once delivery and read-only reconciliation.
//!
//! A preexisting pathname is not a delivery receipt. The caller must prove a durable
//! matching attempt before opening it for reconciliation; this owner never overwrites it.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use fss_core::{CanonicalEncoder, ContentDigest};
use fss_reference::ReplayCx;

fn refused(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn checkpoint(cx: &ReplayCx) -> io::Result<()> {
    cx.checkpoint("review_delivery:destination")
        .map_err(|_| refused("review delivery cancelled"))
}

/// Holds the destination's protected directory throughout creation or verification.
pub(super) struct Destination {
    parent_path: PathBuf,
    root: PathBuf,
    name: OsString,
    parent: File,
    #[cfg(unix)]
    identity: (u64, u64),
    binding: ContentDigest,
}

impl Destination {
    pub(super) fn prepare(path: &Path, root: &Path, cx: &ReplayCx) -> io::Result<Self> {
        checkpoint(cx)?;
        if !cfg!(target_os = "linux") {
            return Err(refused(
                "private review delivery requires Linux directory handles",
            ));
        }
        let root = fs::canonicalize(root)?;
        let parent_path = fs::canonicalize(
            path.parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?;
        let name = path
            .file_name()
            .ok_or_else(|| refused("review output filename required"))?
            .to_owned();
        let destination = parent_path.join(&name);
        if parent_path.starts_with(&root) || root.starts_with(&destination) {
            return Err(refused("review output must be outside the deployment"));
        }
        let mut opening = OpenOptions::new();
        opening.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opening.custom_flags(
                nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY | nix::libc::O_NONBLOCK,
            );
        }
        let parent = opening.open(&parent_path)?;
        let metadata = parent.metadata()?;
        if !metadata.is_dir() {
            return Err(refused("review output parent must be a directory"));
        }
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.review_media_cli_destination.v1");
        encoder.bytes(destination.as_os_str().as_encoded_bytes());
        #[cfg(unix)]
        let identity = {
            use std::os::unix::fs::MetadataExt;
            if metadata.mode() & 0o022 != 0 {
                return Err(refused(
                    "review output parent must forbid group and world writes",
                ));
            }
            encoder.u64(metadata.dev());
            encoder.u64(metadata.ino());
            (metadata.dev(), metadata.ino())
        };
        let value = Self {
            parent_path,
            root,
            name,
            parent,
            #[cfg(unix)]
            identity,
            binding: ContentDigest::sha256(
                &encoder
                    .finish_checked()
                    .map_err(|_| refused("review destination binding exceeds its bound"))?,
            ),
        };
        value.check(cx)?;
        // Refuse special files and links before an intent or output can be created.
        value.exists(cx)?;
        Ok(value)
    }

    pub(super) fn binding(&self) -> ContentDigest {
        self.binding
    }

    fn held_path(&self) -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            PathBuf::from(format!("/proc/self/fd/{}", self.parent.as_raw_fd())).join(&self.name)
        }
        #[cfg(not(target_os = "linux"))]
        self.parent_path.join(&self.name)
    }

    pub(super) fn check(&self, cx: &ReplayCx) -> io::Result<()> {
        checkpoint(cx)?;
        let metadata = fs::symlink_metadata(&self.parent_path)?;
        let held = self.parent.metadata()?;
        if !metadata.is_dir()
            || !held.is_dir()
            || fs::canonicalize(&self.parent_path)? != self.parent_path
            || self.parent_path.starts_with(&self.root)
        {
            return Err(refused("review output parent changed"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.mode() & 0o022 != 0
                || held.mode() & 0o022 != 0
                || (metadata.dev(), metadata.ino()) != self.identity
                || (held.dev(), held.ino()) != self.identity
            {
                return Err(refused(
                    "review output parent identity or protection changed",
                ));
            }
        }
        Ok(())
    }

    /// Check existence without following links or opening a device, socket or FIFO.
    pub(super) fn exists(&self, cx: &ReplayCx) -> io::Result<bool> {
        self.check(cx)?;
        match fs::symlink_metadata(self.held_path()) {
            Ok(metadata) => {
                private_regular(&metadata)?;
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Used only for a newly committed attempt. Existing bytes are never truncated.
    pub(super) fn create(&self, cx: &ReplayCx) -> io::Result<File> {
        self.check(cx)?;
        let mut opening = OpenOptions::new();
        opening.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opening.mode(0o600);
            opening.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
        }
        let file = opening.open(self.held_path())?;
        self.check_file(&file, cx)?;
        Ok(file)
    }

    /// Used only after proving the exact durable attempt; it cannot create or modify a file.
    pub(super) fn open_existing(&self, cx: &ReplayCx) -> io::Result<File> {
        if !self.exists(cx)? {
            return Err(refused(
                "recorded review delivery has no file; its outcome is indeterminate",
            ));
        }
        let mut opening = OpenOptions::new();
        opening.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opening.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
        }
        let file = opening.open(self.held_path())?;
        self.check_file(&file, cx)?;
        Ok(file)
    }

    pub(super) fn check_file(&self, file: &File, cx: &ReplayCx) -> io::Result<()> {
        self.check(cx)?;
        let named = fs::symlink_metadata(self.held_path())?;
        let opened = file.metadata()?;
        private_regular(&named)?;
        private_regular(&opened)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if (named.dev(), named.ino()) != (opened.dev(), opened.ino()) {
                return Err(refused("review output file identity changed"));
            }
        }
        Ok(())
    }

    pub(super) fn sync(&self, file: &File, cx: &ReplayCx) -> io::Result<()> {
        self.check_file(file, cx)?;
        file.sync_all()?;
        self.parent.sync_all()?;
        self.check_file(file, cx)
    }
}

fn private_regular(metadata: &fs::Metadata) -> io::Result<()> {
    if !metadata.is_file() {
        return Err(refused("review output must be a private regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o7777 != 0o600 || metadata.nlink() != 1 {
            return Err(refused(
                "review output must have mode 0600 and exactly one link",
            ));
        }
    }
    Ok(())
}
