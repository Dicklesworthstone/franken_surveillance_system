#![forbid(unsafe_code)]
//! Version-one canonical recipe and complete result. Recovery rebuilds and compares every byte.

use super::*;
use fss_core::{CanonicalDecoder, CanonicalEncode, CanonicalEncoder};

const MAGIC: &[u8] = b"FSSPZNR1";
pub(super) fn config_bytes(config: &PackageZoneConfig) -> Vec<u8> {
    let mut e = CanonicalEncoder::new();
    e.text(PACKAGE_ZONE_CONFIG_DOMAIN);
    e.u64(config.maximum_sample_gap_ns);
    e.bool(config.dwell.is_some());
    if let Some(dwell) = config.dwell {
        e.u64(dwell.minimum_duration_ns);
        e.u64(dwell.minimum_observations as u64);
    }
    e.u64(config.zones.len() as u64);
    for zone in &config.zones {
        e.text(&zone.id);
        for n in [zone.x, zone.y, zone.width, zone.height, zone.margin] {
            e.u32(n);
        }
    }
    e.finish()
}
fn config_decode(bytes: &[u8]) -> Result<PackageZoneConfig> {
    if bytes.len() > 4096 {
        return Err(PackageZoneError::Limit);
    }
    let mut d = CanonicalDecoder::new(bytes);
    if d.text().map_err(source)? != PACKAGE_ZONE_CONFIG_DOMAIN {
        return Err(PackageZoneError::Mismatch);
    }
    let maximum_sample_gap_ns = d.u64().map_err(source)?;
    let dwell = if d.bool().map_err(source)? {
        Some(PackageZoneDwell {
            minimum_duration_ns: d.u64().map_err(source)?,
            minimum_observations: usize::try_from(d.u64().map_err(source)?)
                .map_err(|_| PackageZoneError::Limit)?,
        })
    } else {
        None
    };
    let count = d.u64().map_err(source)?;
    if count == 0 || count > MAX_PACKAGE_ZONES as u64 {
        return Err(PackageZoneError::Limit);
    }
    let mut zones = Vec::new();
    for _ in 0..count {
        zones.push(PackageZone {
            id: text(&mut d, 64)?,
            x: d.u32().map_err(source)?,
            y: d.u32().map_err(source)?,
            width: d.u32().map_err(source)?,
            height: d.u32().map_err(source)?,
            margin: d.u32().map_err(source)?,
        });
    }
    d.ensure_finished().map_err(source)?;
    let config = PackageZoneConfig {
        maximum_sample_gap_ns,
        dwell,
        zones,
    };
    if config_bytes(&config) != bytes {
        return Err(PackageZoneError::Mismatch);
    }
    Ok(config)
}
fn text(d: &mut CanonicalDecoder<'_>, maximum: usize) -> Result<String> {
    let value = d.text().map_err(source)?;
    if value.is_empty() || value.len() > maximum {
        return Err(PackageZoneError::Limit);
    }
    Ok(value.to_owned())
}
pub(super) struct Recipe {
    pub site: String,
    pub detection: ContentDigest,
    pub analysis: ContentDigest,
    pub label: String,
    pub tracking: PackageTrackingConfig,
    pub config: PackageZoneConfig,
}
pub(super) fn recipe(bytes: &[u8]) -> Result<Recipe> {
    if bytes.len() > MAX_PACKAGE_ZONE_REPORT_BYTES {
        return Err(PackageZoneError::Limit);
    }
    let mut d = CanonicalDecoder::new(bytes);
    if d.bytes().map_err(source)? != MAGIC
        || d.u32().map_err(source)? != 1
        || d.text().map_err(source)? != PACKAGE_ZONE_REPORT_DOMAIN
    {
        return Err(PackageZoneError::Mismatch);
    }
    let site = text(&mut d, 256)?;
    let detection = d.digest().map_err(source)?;
    let analysis = d.digest().map_err(source)?;
    let label = text(&mut d, 512)?;
    let tracking = PackageTrackingConfig {
        confirmation_hits: d.u32().map_err(source)?,
        maximum_missed_frames: d.u32().map_err(source)?,
        minimum_iou_ppm: d.u32().map_err(source)?,
    };
    let config = config_decode(d.bytes().map_err(source)?)?;
    // The complete rebuilt encoding below owns all remaining fields and rejects trailing,
    // missing, reordered or altered cells. This prefix never authorizes a partial result.
    Ok(Recipe {
        site,
        detection,
        analysis,
        label,
        tracking,
        config,
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn encode(
    site: &str,
    analysis: &PackageAnalysisReport,
    config: &PackageZoneConfig,
    capture_label: &str,
    clock: ClockBasis,
    privacy: &MaskBinding,
    frames: &[PackageZoneFrame],
    cells: &[PackageZoneCell],
    events: &[PackageZoneEvent],
) -> Result<Vec<u8>> {
    let mut e = CanonicalEncoder::new();
    e.bytes(MAGIC);
    e.u32(1);
    e.text(PACKAGE_ZONE_REPORT_DOMAIN);
    e.text(site);
    e.digest(analysis.retained().record().report_digest);
    e.digest(analysis.digest());
    e.text(analysis.label());
    let tracking = analysis.config();
    e.u32(tracking.confirmation_hits);
    e.u32(tracking.maximum_missed_frames);
    e.u32(tracking.minimum_iou_ppm);
    e.bytes(&config_bytes(config));
    e.digest(analysis.retained().root());
    e.digest(analysis.retained().record().import_root);
    analysis
        .retained()
        .authority_anchor()
        .encode_canonical(&mut e);
    e.text(capture_label);
    e.text(clock.as_str());
    e.digest(privacy.digest());
    e.bool(privacy.generation().is_some());
    if let Some(generation) = privacy.generation() {
        e.u64(generation);
    }
    e.u64(frames.len() as u64);
    for frame in frames {
        e.u64(frame.segment);
        e.digest(frame.capsule_digest);
        frame.capture.encode_canonical(&mut e);
        e.u32(frame.dimensions[0]);
        e.u32(frame.dimensions[1]);
        e.bool(frame.time_reliable);
        e.bool(frame.source_boundary);
    }
    e.u64(cells.len() as u64);
    for cell in cells {
        e.digest(cell.track);
        e.u64(cell.zone as u64);
        e.u64(cell.frame as u64);
        e.text(cell.relation.as_str());
        e.bool(cell.sample_confirmed);
        e.bool(cell.detection_row.is_some());
        if let Some(row) = cell.detection_row {
            e.u64(row);
        }
        e.bool(cell.bounds.is_some());
        if let Some(bounds) = cell.bounds {
            for n in bounds {
                e.u32(n);
            }
        }
        e.bool(cell.clipped);
    }
    e.u64(events.len() as u64);
    for event in events {
        e.text(event.kind.as_str());
        e.digest(event.track);
        e.u64(event.zone as u64);
        e.bool(event.from_frame.is_some());
        if let Some(frame) = event.from_frame {
            e.u64(frame as u64);
        }
        e.u64(event.at_frame as u64);
        e.u64(event.through_frame as u64);
        e.u64(event.observations as u64);
        for duration in [event.minimum_duration_ns, event.maximum_duration_ns] {
            e.bool(duration.is_some());
            if let Some(value) = duration {
                e.text(&value.to_string());
            }
        }
    }
    let bytes = e.finish_checked().map_err(source)?;
    if bytes.len() > MAX_PACKAGE_ZONE_REPORT_BYTES {
        return Err(PackageZoneError::Limit);
    }
    Ok(bytes)
}
