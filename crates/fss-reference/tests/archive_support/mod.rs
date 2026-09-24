#![forbid(unsafe_code)]
#![allow(dead_code)]
#[path = "../collector_support/mod.rs"]
mod fixture;
pub use fixture::{Error, TestResult};
use fss_core::ContentDigest;
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel, SlotName};
use fss_reference::rtsp::recording::PreparedRecording;
use fss_reference::rtsp::recording::local::{RecordingPublication, RecordingProgress};
use fss_reference::rtsp::recording_collector::CollectorLimits;
use fss_reference::rtsp::recording_catalog::{CatalogScope, CatalogWindow, prepare_catalog};
use fss_reference::rtsp::recording_catalog::local::{CatalogPublication, CatalogProgress};
use fss_reference::rtsp::recording_archive::ArchiveNamespace;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);

pub fn namespace() -> Result<ArchiveNamespace, Error> {
    Ok(ArchiveNamespace::new(CatalogScope { recording: fixture::scope()?,
        decode_clock: ContentDigest::try_sha256(b"archive-fixture-decode")?, time_scale: 90_000 })?)
}
pub fn owner_limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(256, 512, 64, 512,
        SpoolLimits::new(1024, 64 * 1024 * 1024, 1024 * 1024, 2048))
}
pub fn owner(name: &str) -> Result<(std::path::PathBuf, LocalRootPublisher), Error> {
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("archive-{name}-{}-{}",
        std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
    if path.exists() { return Err("test directory already exists; refusing to replace retained data".into()); }
    Ok((path.clone(), LocalRootPublisher::open(path, owner_limits())?))
}
pub fn window(seq: u64, dts: u64) -> Result<PreparedRecording, Error> {
    let mut c = fixture::collector(CollectorLimits::default())?;
    let sample = fixture::sample(seq, 90_000 + seq as u32 * 3600, true, seq.is_multiple_of(2))?;
    sample.source(&mut c, 1)?; fixture::accepted(c.push_picture(sample.timed(dts), 1))?;
    c.seal(2)?; c.take_ready().ok_or_else(|| "fixture produced no recording".into())
}
pub fn publish_window(p: &mut LocalRootPublisher, slot: &SlotName, w: &PreparedRecording) -> TestResult {
    let mut job = RecordingPublication::new(w, p, slot.clone(), w.byte_len(), 100)?;
    for now in 0..4 { assert!(matches!(job.step(now, &NeverCancel)?, RecordingProgress::ChildStaged { .. })); }
    assert!(matches!(job.step(4, &NeverCancel)?, RecordingProgress::Published(_)));
    Ok(())
}
pub fn publish_page(p: &mut LocalRootPublisher, ns: &ArchiveNamespace, first: usize,
    windows: &[(&SlotName, &PreparedRecording)]) -> TestResult
{
    let selected: Vec<_> = windows.iter().map(|(slot, recording)| CatalogWindow { slot, recording }).collect();
    let c = prepare_catalog(ns.scope().clone(), &selected)?;
    let mut job = CatalogPublication::new(&c, p, ns.page_slot(first)?, c.byte_len(), 100)?;
    for now in 0..windows.len() + 1 { let _ = job.step(now as u64, &NeverCancel)?; }
    assert!(matches!(job.step(windows.len() as u64 + 1, &NeverCancel)?, CatalogProgress::Published(_)));
    Ok(())
}
