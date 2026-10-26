#![forbid(unsafe_code)]
//! A fresh private staging directory owns exactly one source file and its cleanup.

use super::{CANCELLED, STORAGE};
use fss_reference::ReplayCx;
use std::fs::{DirBuilder, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub(super) struct Source {
    path: PathBuf,
    directory: PathBuf,
    removed: bool,
}

impl Source {
    pub(super) fn new(bytes: &[u8], cx: &ReplayCx) -> Result<Self, &'static str> {
        cx.checkpoint("onvif-before-staging-location")
            .map_err(|_| CANCELLED)?;
        let temp = std::env::temp_dir();
        for attempt in 0..100 {
            cx.checkpoint("onvif-before-staging-directory")
                .map_err(|_| CANCELLED)?;
            let directory = temp.join(format!(
                "fss-onvif-snapshot-{}-{attempt}",
                std::process::id()
            ));
            let mut builder = DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&directory) {
                Ok(()) => {
                    let source = Self {
                        path: directory.join("source.jpg"),
                        directory,
                        removed: false,
                    };
                    cx.checkpoint("onvif-before-staging-file")
                        .map_err(|_| CANCELLED)?;
                    let mut options = OpenOptions::new();
                    options.write(true).create_new(true);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt;
                        options.mode(0o600);
                    }
                    let mut file = options.open(&source.path).map_err(|_| STORAGE)?;
                    for chunk in bytes.chunks(16384) {
                        cx.checkpoint("onvif-before-staging-write")
                            .map_err(|_| CANCELLED)?;
                        file.write_all(chunk).map_err(|_| STORAGE)?;
                        cx.checkpoint("onvif-after-staging-write")
                            .map_err(|_| CANCELLED)?;
                    }
                    cx.checkpoint("onvif-before-staging-flush")
                        .map_err(|_| CANCELLED)?;
                    file.flush().map_err(|_| STORAGE)?;
                    drop(file);
                    cx.checkpoint("onvif-staging-complete")
                        .map_err(|_| CANCELLED)?;
                    return Ok(source);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(STORAGE),
            }
        }
        Err(STORAGE)
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn close(&mut self) -> Result<(), &'static str> {
        if !self.removed {
            std::fs::remove_file(&self.path).map_err(|_| STORAGE)?;
            std::fs::remove_dir(&self.directory).map_err(|_| STORAGE)?;
            self.removed = true;
        }
        Ok(())
    }
}

impl Drop for Source {
    fn drop(&mut self) {
        if !self.removed {
            // Cleanup of the exact owned objects remains permitted after cancellation.
            // Never recursively remove a directory or reuse an existing source file.
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_dir(&self.directory);
        }
    }
}
