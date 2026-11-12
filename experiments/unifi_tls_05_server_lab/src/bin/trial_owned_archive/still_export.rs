#![forbid(unsafe_code)]
//! One explicitly requested laboratory export, drained independently of capture.

use asupersync::Cx;
use fss_core::{BudgetVector, RuntimeGrant};
use fss_reference::unifi_direct::{archive, metered::MeteredClock, video_still::ArchivedStill};
use fss_runtime::{
    drained_blocking::{self, Drained},
    execution::TaskCx,
};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
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
    let Some(parent) = destination.parent() else {
        return Outcome::Refused;
    };
    let Ok(meta) = fs::symlink_metadata(parent) else {
        return Outcome::Refused;
    };
    if !meta.is_dir() || meta.mode() & 0o077 != 0 {
        return Outcome::Refused;
    }
    let Some(name) = destination.file_name() else {
        return Outcome::Refused;
    };
    let mut stage_name = std::ffi::OsString::from(".fss-still-stage-");
    stage_name.push(std::process::id().to_string());
    stage_name.push("-");
    stage_name.push(name);
    let stage: PathBuf = parent.join(stage_name);
    let Ok(mut file) = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&stage)
    else {
        return Outcome::Refused;
    };
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
        return if fs::remove_file(&stage).is_ok() {
            Outcome::Refused
        } else {
            Outcome::StagingNeedsInspection
        };
    }
    let linked = fs::hard_link(&stage, destination);
    if let Err(error) = linked {
        // An error can be ambiguous on a remote filesystem. An existing final
        // name is a definite conflict only when it is a different inode from
        // this still-open staging file; otherwise preserve the staging name.
        let conflict = error.kind() == std::io::ErrorKind::AlreadyExists
            && file
                .metadata()
                .ok()
                .zip(fs::symlink_metadata(destination).ok())
                .is_some_and(|(source, target)| {
                    source.dev() != target.dev() || source.ino() != target.ino()
                });
        drop(file);
        return if conflict {
            if fs::remove_file(&stage).is_ok() {
                Outcome::Refused
            } else {
                Outcome::StagingNeedsInspection
            }
        } else {
            Outcome::LinkNeedsInspection
        };
    }
    drop(file);
    let removed = fs::remove_file(&stage).is_ok();
    let synced = fs::File::open(parent)
        .and_then(|dir| dir.sync_all())
        .is_ok();
    if removed && synced {
        Outcome::Published
    } else {
        Outcome::PublishedNeedsInspection
    }
}
