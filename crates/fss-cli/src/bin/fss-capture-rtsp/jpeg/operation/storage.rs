#![forbid(unsafe_code)]
//! The existing root-last datagram store; no second packet format or opaque raw-TCP archive.

use super::*;
use fss_publication::{LocalRootPublisher, PublishCancellation, PublishCutPoint};
use fss_reference::rtsp::datagram_archive::DatagramArchive;
use fss_reference::rtsp::framed::RtspWireFrame;

pub(super) struct Cancellation<'a> {
    pub(super) owner: &'a dyn Owner,
    pub(super) write: bool,
}
impl PublishCancellation for Cancellation<'_> {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        self.owner
            .checkpoint(if self.write {
                Effect::StorageWrite
            } else {
                Effect::StorageRead
            })
            .is_err()
    }
}

pub(super) fn open(
    options: &Options,
    owner: &dyn Owner,
) -> Result<LocalRootPublisher, &'static str> {
    owner.checkpoint(Effect::StorageWrite)?;
    // Ordinary recovery uses locks, holds, temporary cleanup and fsync. Both modes
    // authorize these metadata effects; replay never creates its source root.
    if options.replay.is_some() {
        let metadata =
            std::fs::symlink_metadata(&options.root).map_err(|_| "ERR-CAPTURE-RTSP-ROOT-001")?;
        owner.checkpoint(Effect::StorageWrite)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("ERR-CAPTURE-RTSP-ROOT-001");
        }
    } else {
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&options.root)
            .map_err(|_| "ERR-CAPTURE-RTSP-ROOT-001")?;
        owner.checkpoint(Effect::StorageWrite)?;
    }
    let publisher =
        LocalRootPublisher::open(&options.root, options.storage).map_err(|_| STORAGE)?;
    owner.checkpoint(Effect::StorageWrite)?;
    Ok(publisher)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn retain(
    frame: &RtspWireFrame,
    archive: &mut DatagramArchive,
    publisher: &mut LocalRootPublisher,
    owner: &dyn Owner,
    work: &mut WorkBudget<'_>,
    report: &mut Report,
    out: &mut dyn Write,
) -> Result<(), &'static str> {
    owner.checkpoint(Effect::StorageWrite)?;
    let plan = archive.prepare_frame(frame, work).map_err(|_| STORAGE)?;
    // Any failure after this point keeps both the last acknowledged pin and the
    // exact possibly-published candidate. Never retry it or silently skip an ordinal.
    report.pending = Some(plan.pin());
    let receipt = archive
        .publish(&plan, publisher, &Cancellation { owner, write: true }, work)
        .map_err(|_| STORAGE)?;
    report.pin = Some(receipt.record.pin);
    report.pending = None;
    owner.checkpoint(Effect::StorageWrite)?;
    report.emit(
        owner,
        out,
        "source_published",
        report::record(receipt.record),
    )
}
