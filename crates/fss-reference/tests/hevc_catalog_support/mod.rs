#![forbid(unsafe_code)]
#![allow(dead_code)]

use crate::hevc_recording_support as source;
use fss_core::{CanonicalEncoder, ContentDigest};
use fss_object::ObjectManifest;
use fss_publication::SlotName;
use fss_reference::rtsp::recording::PreparedRecording;
use fss_reference::rtsp::recording::hevc::{PreparedHevcRecording, prepare_hevc_recording};
use fss_reference::rtsp::recording_catalog::CatalogScope;

pub type Error = Box<dyn std::error::Error>;
pub fn scope() -> Result<CatalogScope, Error> {
    Ok(CatalogScope {
        recording: source::scope()?,
        decode_clock: ContentDigest::sha256(b"explicit-hevc-decode-epoch"),
        time_scale: 90_000,
    })
}
pub fn window(base: u64) -> Result<PreparedHevcRecording, Error> {
    let mut timings = source::timings(4);
    for t in &mut timings {
        t.decode_time += base;
    }
    Ok(prepare_hevc_recording(
        scope()?.recording,
        &source::configuration()?,
        90_000,
        &timings,
        &source::borrowed(&source::packets()?),
    )?)
}
pub fn slot(n: usize) -> Result<SlotName, Error> {
    Ok(SlotName::parse(&format!("hevc-window-{n:03}"))?)
}

/// Independent canonical encoder for adversarial/golden catalog tests. This is
/// not a public unchecked construction path into the production catalog type.
pub fn index(
    domain: &str,
    basis: &CatalogScope,
    windows: &[(&SlotName, &PreparedRecording)],
    reported_roots: Option<&[ContentDigest]>,
) -> Result<Vec<u8>, Error> {
    index_with_bytes(domain, basis, windows, reported_roots, None)
}
pub fn index_with_bytes(
    domain: &str,
    basis: &CatalogScope,
    windows: &[(&SlotName, &PreparedRecording)],
    reported_roots: Option<&[ContentDigest]>,
    reported_bytes: Option<usize>,
) -> Result<Vec<u8>, Error> {
    let mut e = CanonicalEncoder::new();
    e.text(domain);
    e.u64(1);
    e.text(basis.recording.sensor.as_str());
    e.text(basis.recording.stream.as_str());
    e.u64(basis.recording.generation);
    e.digest(basis.recording.anchor);
    e.digest(basis.recording.receive_clock);
    e.digest(basis.decode_clock);
    e.u32(basis.time_scale);
    e.u64(windows.len() as u64);
    for (i, (slot, plan)) in windows.iter().enumerate() {
        let s = plan.summary();
        e.text(slot.as_str());
        e.digest(reported_roots.map_or(s.root, |roots| roots[i]));
        e.u64(s.decode_interval.start);
        e.u64(s.decode_interval.end);
        e.u64(s.packets as u64);
        e.u64(s.samples as u64);
        e.u64(s.nals as u64);
        e.u64(reported_bytes.unwrap_or(plan.byte_len()) as u64);
        for (_, d, _) in plan.children() {
            e.digest(d);
        }
    }
    let mut bytes = e.finish_checked()?;
    let checksum = ContentDigest::sha256(&bytes);
    bytes.push(1);
    bytes.extend_from_slice(&checksum.bytes());
    Ok(bytes)
}
pub fn manifest(
    kind: &str,
    index: &[u8],
    windows: &[&PreparedRecording],
    roots: Option<&[ContentDigest]>,
) -> Result<ObjectManifest, Error> {
    let mut children = Vec::new();
    for (i, plan) in windows.iter().enumerate() {
        children.push(roots.map_or(plan.manifest().root(), |r| r[i]));
        children.extend(plan.children().map(|(_, d, _)| d));
    }
    children.sort_unstable();
    children.dedup();
    Ok(ObjectManifest::new(
        kind,
        children,
        Some(ContentDigest::sha256(index)),
    )?)
}
