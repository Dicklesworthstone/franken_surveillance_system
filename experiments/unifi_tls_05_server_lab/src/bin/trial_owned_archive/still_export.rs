#![forbid(unsafe_code)]
//! One explicitly requested laboratory export, drained independently of capture.

use asupersync::Cx;
use fss_core::{BudgetVector, RuntimeGrant};
use fss_reference::unifi_direct::{archive, metered::MeteredClock, video_still::ArchivedStill};
use fss_runtime::{
    drained_blocking::{self, Drained},
    execution::TaskCx,
};
use rustix::fs::{self as rfs, AtFlags, Mode, OFlags};
use std::{
    fs::File,
    io::Write,
    os::unix::fs::MetadataExt,
    path::{Component, Path},
    sync::Arc,
};

pub(super) type Job = Box<dyn FnOnce(Cx) -> Outcome + Send + 'static>;
pub(super) type Worker = Drained<Job, Outcome>;

#[derive(Debug)]
pub(super) enum Outcome {
    /// The final name was linked and the directory synced.
    Published,
    /// The final name was linked, but later cleanup or sync needs inspection.
    PublishedNeedsInspection,
    /// No final name was created and the staging name was removed.
    Refused,
    /// No final name was created, but staging cleanup needs inspection.
    StagingNeedsInspection,
    /// Linking may have taken effect; retain staging for reconciliation.
    LinkNeedsInspection,
}

pub(super) fn valid_path(path: &Path) -> bool {
    path.is_absolute()
        && path.file_name().is_some()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

// Resolve every component without following symlinks, retaining the exact
// directory handle for staging, publication and sync. This prevents path
// redirection after opening; a renamed directory can still change its visible
// pathname, which callers must treat as a separate namespace concern.
fn open_private_parent(path: &Path) -> std::io::Result<File> {
    let parent = path.parent().ok_or(std::io::ErrorKind::InvalidInput)?;
    let mut directory = File::open("/")?;
    for component in parent.components() {
        match component {
            Component::RootDir => (),
            Component::Normal(name) => {
                let fd = rfs::openat(
                    &directory,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )?;
                directory = File::from(fd);
            }
            _ => return Err(std::io::ErrorKind::InvalidInput.into()),
        }
    }
    let meta = directory.metadata()?;
    if !meta.is_dir() || meta.mode() & 0o077 != 0 {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    Ok(directory)
}

/// Admit the exact source and destination before scheduling bounded I/O.
pub(super) fn start<'scope, 'task>(
    task: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    source_resource: &str,
    destination: &Path,
    still: &ArchivedStill,
    read: Arc<dyn archive::ReadAuthority + Send + Sync>,
) -> Result<Worker, &'static str> {
    if !valid_path(destination) || !clock.matches(task, cx) {
        return Err("invalid still export binding");
    }
    let target_resource = destination
        .to_str()
        .ok_or("still export path is not UTF-8")?;
    let pin = still.pin();
    if !read.permits(pin.retention, pin.root) {
        return Err("still export read denied");
    }
    let now = clock.now().map_err(|_| "still export clock unavailable")?;
    task.checkpoint_for(
        RuntimeGrant::ReadMedia,
        source_resource,
        now,
        &BudgetVector::ZERO,
    )
    .map_err(|_| "still export read unavailable")?;
    let bytes = still.still().jpeg().bytes();
    let mut cost = BudgetVector::ZERO;
    cost.bytes = u64::try_from(bytes.len()).map_err(|_| "still export size unavailable")?;
    cost.storage_operations = 6;
    task.checkpoint_for(RuntimeGrant::ObjectStage, target_resource, now, &cost)
        .map_err(|_| "still export staging unavailable")?;
    task.checkpoint_for(
        RuntimeGrant::ObjectPublish,
        target_resource,
        now,
        &BudgetVector::ZERO,
    )
    .map_err(|_| "still export publication unavailable")?;
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len())
        .map_err(|_| "still export allocation refused")?;
    copy.extend_from_slice(bytes);
    let destination = destination.to_path_buf();
    let job: Job =
        Box::new(move |child| write_one(&child, &destination, &copy, pin, read.as_ref()));
    drained_blocking::start(cx, job).map_err(|_| "still export worker unavailable")
}

fn write_one(
    cx: &Cx,
    destination: &Path,
    bytes: &[u8],
    pin: archive::UnknownTimePin,
    read: &dyn archive::ReadAuthority,
) -> Outcome {
    let allowed = || !cx.is_cancel_requested() && read.permits(pin.retention, pin.root);
    if !allowed() {
        return Outcome::Refused;
    }
    let Ok(parent) = open_private_parent(destination) else {
        return Outcome::Refused;
    };
    let Some(name) = destination.file_name() else {
        return Outcome::Refused;
    };
    let mut stage_name = std::ffi::OsString::from(".fss-still-stage-");
    stage_name.push(std::process::id().to_string());
    stage_name.push("-");
    stage_name.push(name);
    let Ok(fd) = rfs::openat(
        &parent,
        &stage_name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    ) else {
        return Outcome::Refused;
    };
    let mut file = File::from(fd);
    let staged = (|| -> std::io::Result<bool> {
        for chunk in bytes.chunks(64 * 1024) {
            if !allowed() {
                return Ok(false);
            }
            file.write_all(chunk)?;
        }
        file.sync_all()?;
        if !allowed() {
            return Ok(false);
        }
        Ok(true)
    })();
    if !matches!(staged, Ok(true)) {
        drop(file);
        return if rfs::unlinkat(&parent, &stage_name, AtFlags::empty()).is_ok() {
            Outcome::Refused
        } else {
            Outcome::StagingNeedsInspection
        };
    }
    let linked = rfs::linkat(&parent, &stage_name, &parent, name, AtFlags::empty());
    if let Err(error) = linked {
        // An error can be ambiguous on a remote filesystem. An existing final
        // name is a definite conflict only when it is a different inode from
        // this still-open staging file; otherwise preserve the staging name.
        let conflict = error == rustix::io::Errno::EXIST
            && file
                .metadata()
                .ok()
                .zip(rfs::statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW).ok())
                .is_some_and(|(source, target)| {
                    source.dev() != target.st_dev as u64 || source.ino() != target.st_ino as u64
                });
        drop(file);
        return if conflict {
            if rfs::unlinkat(&parent, &stage_name, AtFlags::empty()).is_ok() {
                Outcome::Refused
            } else {
                Outcome::StagingNeedsInspection
            }
        } else {
            Outcome::LinkNeedsInspection
        };
    }
    drop(file);
    let removed = rfs::unlinkat(&parent, &stage_name, AtFlags::empty()).is_ok();
    let synced = parent.sync_all().is_ok();
    if removed && synced {
        Outcome::Published
    } else {
        Outcome::PublishedNeedsInspection
    }
}
