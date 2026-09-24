#![forbid(unsafe_code)]
#![allow(dead_code)]
//! Shared real-storage fixtures for the HEVC archive contract suites.

use crate::hevc_catalog_support as fixture;
use fss_core::ContentDigest;
use fss_object::SpoolLimits;
use fss_publication::{
    LocalPublicationLimits, LocalPublicationState, LocalRootPublisher, NeverCancel,
    PublishCancellation, PublishCutPoint, SlotName,
};
use fss_reference::rtsp::recording::hevc::PreparedHevcRecording;
use fss_reference::rtsp::recording::local::{RecordingProgress, RecordingPublication};
use fss_reference::rtsp::recording_archive::{ArchiveLimits, hevc::HevcArchiveNamespace};
use fss_reference::rtsp::recording_catalog::hevc::local::HevcCatalogPublication;
use fss_reference::rtsp::recording_catalog::hevc::{HevcCatalogBuilder, HevcRecordingCatalog};
use fss_reference::rtsp::recording_catalog::local::CatalogProgress;
use std::path::{Path, PathBuf};

pub type Error = Box<dyn std::error::Error>;
pub type TestResult = Result<(), Error>;
pub fn limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        64,
        512,
        16,
        512,
        SpoolLimits::new(512, 64 * 1024 * 1024, 1024 * 1024, 1024),
    )
}
pub fn archive_limits() -> ArchiveLimits {
    ArchiveLimits {
        max_windows: 32,
        max_pages: 32,
        max_scan_roots: 256,
        windows_per_page: 2,
    }
}
pub fn fresh(name: &str) -> Result<PathBuf, Error> {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("hevc_archive_contract")
        .join(name);
    match std::fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(root)
}
pub fn namespace() -> Result<HevcArchiveNamespace, Error> {
    Ok(HevcArchiveNamespace::new(fixture::scope()?)?)
}
pub fn publish_window(
    p: &mut LocalRootPublisher,
    slot: &SlotName,
    w: &PreparedHevcRecording,
) -> TestResult {
    let mut job =
        RecordingPublication::new(w.publication_plan(), p, slot.clone(), w.byte_len(), 1000)?;
    for at in 0..4 {
        assert!(matches!(
            job.step(at, &NeverCancel)?,
            RecordingProgress::ChildStaged { .. }
        ));
    }
    let RecordingProgress::Published(receipt) = job.step(4, &NeverCancel)? else {
        return Err("missing recording publication receipt".into());
    };
    assert_eq!(receipt.claims.local, LocalPublicationState::Durable);
    Ok(())
}
pub fn page(
    ns: &HevcArchiveNamespace,
    first: usize,
    windows: &[PreparedHevcRecording],
) -> Result<HevcRecordingCatalog, Error> {
    let mut builder = HevcCatalogBuilder::new(ns.scope().clone())?;
    for (offset, w) in windows.iter().enumerate() {
        builder.push(&ns.window_slot(first + offset)?, w)?;
    }
    Ok(builder.prepare()?)
}
pub fn publish_page(
    p: &mut LocalRootPublisher,
    ns: &HevcArchiveNamespace,
    first: usize,
    catalog: &HevcRecordingCatalog,
) -> TestResult {
    let mut job =
        HevcCatalogPublication::new(catalog, p, ns.page_slot(first)?, catalog.byte_len(), 1000)?;
    for at in 0..catalog.entries().len() as u64 {
        assert!(matches!(
            job.step(at, &NeverCancel)?,
            CatalogProgress::WindowVerified { .. }
        ));
    }
    let at = catalog.entries().len() as u64;
    assert!(matches!(
        job.step(at, &NeverCancel)?,
        CatalogProgress::IndexStaged { .. }
    ));
    assert!(matches!(
        job.step(at + 1, &NeverCancel)?,
        CatalogProgress::Published(_)
    ));
    Ok(())
}
pub fn seed(
    name: &str,
    indexed: usize,
) -> Result<
    (
        PathBuf,
        LocalRootPublisher,
        HevcArchiveNamespace,
        Vec<PreparedHevcRecording>,
    ),
    Error,
> {
    let root = fresh(name)?;
    let mut p = LocalRootPublisher::open(&root, limits())?;
    let ns = namespace()?;
    let windows = [0, 90_000, 180_000]
        .into_iter()
        .map(fixture::window)
        .collect::<Result<Vec<_>, _>>()?;
    for (ordinal, w) in windows.iter().enumerate() {
        publish_window(&mut p, &ns.window_slot(ordinal)?, w)?;
    }
    for ordinal in 0..indexed {
        let catalog = page(&ns, ordinal, &windows[ordinal..ordinal + 1])?;
        publish_page(&mut p, &ns, ordinal, &catalog)?;
    }
    Ok((root, p, ns, windows))
}
pub fn corrupt(root: &Path, digest: ContentDigest) -> TestResult {
    let text = digest.to_text();
    let hex = text.strip_prefix("sha256:").ok_or("not SHA-256")?;
    let path = root.join("spool").join("objects").join(hex);
    let mut bytes = std::fs::read(&path)?;
    *bytes.last_mut().ok_or("empty object")? ^= 1;
    std::fs::write(path, bytes)?;
    Ok(())
}
pub struct Stop;
impl PublishCancellation for Stop {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        true
    }
}
pub struct Probe {
    pub calls: std::cell::Cell<usize>,
    pub stop_at: usize,
}
impl PublishCancellation for Probe {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        let n = self.calls.get() + 1;
        self.calls.set(n);
        n == self.stop_at
    }
}
