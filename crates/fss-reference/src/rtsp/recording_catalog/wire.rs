#![forbid(unsafe_code)]

use super::*;
use fss_core::{CanonicalDecoder, CanonicalEncoder, ContractError, SensorId, StreamId};

const VERSION: u64 = 1;
const CHECKSUM_BYTES: usize = 33;

pub(super) fn encode(scope: &CatalogScope, entries: &[CatalogEntry], family: CatalogFamily) -> Result<Vec<u8>> {
    let mut out = CanonicalEncoder::new();
    out.text(family.domain()); out.u64(VERSION);
    out.text(scope.recording.sensor.as_str()); out.text(scope.recording.stream.as_str());
    out.u64(scope.recording.generation); out.digest(scope.recording.anchor);
    out.digest(scope.recording.receive_clock); out.digest(scope.decode_clock); out.u32(scope.time_scale);
    out.u64(entries.len() as u64);
    for e in entries {
        out.text(e.slot.as_str()); out.digest(e.root);
        out.u64(e.interval.start); out.u64(e.interval.end);
        out.u64(e.packets as u64); out.u64(e.samples as u64); out.u64(e.nals as u64); out.u64(e.bytes as u64);
        for d in e.objects { out.digest(d); }
    }
    let mut bytes = out.finish_checked().map_err(|_| CatalogError::Limit)?;
    if bytes.len() > MAX_CATALOG_BYTES - CHECKSUM_BYTES { return Err(CatalogError::Limit); }
    let checksum = digest(&bytes)?;
    bytes.try_reserve_exact(CHECKSUM_BYTES).map_err(|_| CatalogError::Limit)?;
    bytes.push(1); bytes.extend_from_slice(&checksum.bytes());
    Ok(bytes)
}

pub(super) fn decode(bytes: &[u8], family: CatalogFamily) -> Result<(CatalogScope, Vec<CatalogEntry>)> {
    if bytes.len() > MAX_CATALOG_BYTES { return Err(CatalogError::Limit); }
    let body_end = bytes.len().checked_sub(CHECKSUM_BYTES).ok_or(CatalogError::Malformed)?;
    let mut trailer = CanonicalDecoder::new(&bytes[body_end..]);
    if trailer.digest().map_err(bad)? != digest(&bytes[..body_end])? { return Err(CatalogError::Digest); }
    trailer.ensure_finished().map_err(bad)?;
    let mut d = CanonicalDecoder::new(&bytes[..body_end]);
    if d.text().map_err(bad)? != family.domain() || d.u64().map_err(bad)? != VERSION { return Err(CatalogError::Malformed); }
    // text() borrows input. Parse only bounded identifiers, never allocate an
    // attacker-declared count/length before validating it against the page budget.
    let sensor = SensorId::parse(d.text().map_err(bad)?).map_err(bad)?;
    let stream = StreamId::parse(d.text().map_err(bad)?).map_err(bad)?;
    let generation = d.u64().map_err(bad)?;
    let anchor = d.digest().map_err(bad)?;
    let receive_clock = d.digest().map_err(bad)?;
    let decode_clock = d.digest().map_err(bad)?;
    let time_scale = d.u32().map_err(bad)?;
    let count = usize::try_from(d.u64().map_err(bad)?).map_err(|_| CatalogError::Limit)?;
    if count == 0 || count > MAX_CATALOG_WINDOWS { return Err(CatalogError::Limit); }
    let mut entries = bounded_vec(count)?;
    for _ in 0..count {
        let slot = SlotName::parse(d.text().map_err(bad)?).map_err(|_| CatalogError::Malformed)?;
        let root = d.digest().map_err(bad)?;
        let start = d.u64().map_err(bad)?; let end = d.u64().map_err(bad)?;
        let packets = count_field(&mut d)?; let samples = count_field(&mut d)?;
        let nals = count_field(&mut d)?; let bytes = count_field(&mut d)?;
        let objects = [d.digest().map_err(bad)?, d.digest().map_err(bad)?,
            d.digest().map_err(bad)?, d.digest().map_err(bad)?];
        entries.push(CatalogEntry { slot, root, interval: start..end, packets, samples, nals, bytes, objects });
    }
    d.ensure_finished().map_err(bad)?;
    Ok((CatalogScope { recording: RecordingScope { sensor, stream, generation, anchor, receive_clock },
        decode_clock, time_scale }, entries))
}
fn count_field(d: &mut CanonicalDecoder<'_>) -> Result<usize> {
    usize::try_from(d.u64().map_err(bad)?).map_err(|_| CatalogError::Limit)
}
fn bad(_: ContractError) -> CatalogError { CatalogError::Malformed }
