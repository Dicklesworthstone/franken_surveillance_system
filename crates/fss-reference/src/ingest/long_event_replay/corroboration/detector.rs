#![forbid(unsafe_code)]
//! Inspect the ground-selected detector closure without executing a model or trusting its scores.

use std::collections::BTreeMap;

use fss_core::{CanonicalDecoder, ContentDigest};

use crate::ReplayCx;
use crate::ingest::long_watch::detector::{
    LongWatchDetectorRecipe, MAX_OUTCOME_BYTES, RetainedClass, RetainedInventory,
    retained_inventory,
};
use crate::ingest::recorded_corroboration::streaming::LongCorroborationRecipe;

use super::super::watch::{digest, health, trace};
use super::super::{LongEventReplayError as Error, LongEventReplayLimits, Result, SourceBinding};

pub(super) struct RetainedDetector {
    pub(super) recipe: LongWatchDetectorRecipe,
    pub(super) inventory: RetainedInventory,
    pub(super) outcome: ContentDigest,
    pub(super) admitted: [u64; 2],
    pub(super) head_work: [u64; 2],
    attempts: u64,
    completed: u64,
}

pub(super) fn extensions(
    d: &mut CanonicalDecoder<'_>,
    index: usize,
    segments: usize,
    owner: &LongCorroborationRecipe,
    limits: &LongEventReplayLimits,
    cx: &ReplayCx,
) -> Result<(bool, Option<RetainedDetector>, Option<Vec<u8>>)> {
    trace(d, segments, owner.limits().maximum_trace_bytes, cx)?;
    let mut tag = if d.remaining() == 0 {
        None
    } else {
        Some(d.text()?)
    };
    let screened = tag == Some("sensor_health");
    if screened {
        health(d, segments, owner.limits().maximum_pixel_samples)?;
        tag = if d.remaining() == 0 {
            None
        } else {
            Some(d.text()?)
        };
    }
    let retained = match (tag, owner.detector_recipe()) {
        (None | Some("geometry_support"), None) => None,
        (Some("detector_cascade"), Some(expected)) => {
            let recipe = LongWatchDetectorRecipe::from_bytes(d.bytes()?)?;
            if recipe.to_bytes() != expected.to_bytes() {
                return Err(Error::InvalidRecord);
            }
            recipe.validate_within(&limits.execution, &limits.detector)?;
            let outcome = d.bytes()?;
            if outcome.len() > MAX_OUTCOME_BYTES {
                return Err(Error::Limit);
            }
            let inventory = retained_inventory(outcome)?;
            if inventory.recipe != recipe.digest()
                || inventory.import_identity != owner.plan().cameras[index].import_identity
            {
                return Err(Error::InvalidRecord);
            }
            let mut counters = CanonicalDecoder::new(outcome);
            counters.text()?;
            for _ in 0..3 {
                digest(&mut counters)?;
            }
            if counters.u64()? > owner.limits().maximum_source_chunk_bytes
                || counters.u64()? > owner.limits().decode.jpeg_work_units
                || counters.u64()? > owner.limits().maximum_pixel_samples
            {
                return Err(Error::Limit);
            }
            let attempts = counters.u64()?;
            let completed = counters.u64()?;
            if d.text()? != "global_detector_budget" || d.u64()? != index as u64 {
                return Err(Error::InvalidRecord);
            }
            let admitted = [d.u64()?, d.u64()?];
            let head_work = [d.u64()?, d.u64()?];
            if admitted[0] > admitted[1]
                || admitted[1] > recipe.config().max_inferences as u64
                || head_work[0] > head_work[1]
                || head_work[1] > recipe.package_limits().detection_work_units
                || attempts > admitted[1] - admitted[0]
                || completed > attempts
            {
                return Err(Error::InvalidRecord);
            }
            tag = if d.remaining() == 0 {
                None
            } else {
                Some(d.text()?)
            };
            Some(RetainedDetector {
                recipe,
                inventory,
                outcome: ContentDigest::sha256(outcome),
                admitted,
                head_work,
                attempts,
                completed,
            })
        }
        _ => return Err(Error::UnsupportedProfile),
    };
    let geometry = match (tag, owner.geometry_recipe()) {
        (None, None) => None,
        (Some("geometry_support"), Some(_)) => {
            let bytes = d.bytes()?;
            if bytes.len() > crate::ingest::recorded_corroboration::streaming::geometry::MAX_GEOMETRY_RECEIPT_BYTES {
                return Err(Error::Limit);
            }
            Some(bytes.to_vec())
        }
        _ => return Err(Error::UnsupportedProfile),
    };
    d.ensure_finished()?;
    Ok((screened, retained, geometry))
}

/// Validate source associations and the accounting claims exposed by each canonical class
/// record. Tensor values, track geometry and inference correctness still require native replay.
pub(super) fn bind_inventory(
    retained: &RetainedDetector,
    source: &mut SourceBinding,
    zones: usize,
    objects: &BTreeMap<ContentDigest, Vec<u8>>,
) -> Result<()> {
    let mut groups: BTreeMap<(u64, u64, usize, usize), Vec<&RetainedClass>> = BTreeMap::new();
    let mut segments = BTreeMap::new();
    let mut engine = None;
    let mut generation = None;
    for class in &retained.inventory.classes {
        if class.zone >= zones
            || class.track == 0
            || class.entry_position >= source.count
            || class.position >= source.count
            || class.segment >= source.count
        {
            return Err(Error::InvalidRecord);
        }
        digest_binding(&mut source.capsule_bindings, class.segment, class.capsule)?;
        let record = objects.get(&class.digest).ok_or(Error::InvalidRecord)?;
        let mut d = CanonicalDecoder::new(record);
        if d.text()? != "fss.detector_class_evidence.v1" {
            return Err(Error::UnsupportedProfile);
        }
        let actual_engine = digest(&mut d)?;
        if engine
            .replace(actual_engine)
            .is_some_and(|old| old != actual_engine)
            || digest(&mut d)? != retained.recipe.package_digest()
        {
            return Err(Error::InvalidRecord);
        }
        let actual_generation = d.text()?;
        if actual_generation.is_empty()
            || actual_generation.len() > 256
            || generation
                .replace(actual_generation.to_owned())
                .is_some_and(|old| old != actual_generation)
            || digest(&mut d)? != source.import_identity
            || d.u64()? != class.track
            || d.u64()? != class.segment as u64
        {
            return Err(Error::InvalidRecord);
        }
        let reason = d.u8()?;
        if reason
            != if class.position == class.entry_position {
                0
            } else {
                2
            }
        {
            return Err(Error::InvalidRecord);
        }
        let mut bounds = [0_i64; 4];
        for value in &mut bounds {
            *value = i64::try_from(d.i128()?).map_err(|_| Error::InvalidRecord)?;
        }
        if bounds[2] <= 0 || bounds[3] <= 0 {
            return Err(Error::InvalidRecord);
        }
        let status = d.u8()?;
        match status {
            0 => {
                for _ in 0..5 {
                    digest(&mut d)?;
                }
            }
            1 => {}
            2 => {
                if d.text()?.len() > 256 {
                    return Err(Error::Limit);
                }
            }
            _ => return Err(Error::InvalidRecord),
        }
        if segments
            .insert(class.segment, status)
            .is_some_and(|old| old != status)
        {
            return Err(Error::InvalidRecord);
        }
        let outcome = d.u8()?;
        if class.supports != (outcome == 0) {
            return Err(Error::InvalidRecord);
        }
        match (status, outcome) {
            (0, 0) => {
                d.u64()?;
                d.u64()?;
                if d.text()?.len() > 1024 {
                    return Err(Error::Limit);
                }
                let score = f32::from_bits(d.u32()?);
                if !score.is_finite() || !(0.0..=1.0).contains(&score) {
                    return Err(Error::InvalidRecord);
                }
                for _ in 0..4 {
                    d.u32()?;
                }
                if d.u32()? > 1_000_000 {
                    return Err(Error::InvalidRecord);
                }
            }
            (0, 1) => {
                d.u64()?;
            }
            (1, 2) => {}
            (2, 3) => {
                if d.text()?.len() > 256 {
                    return Err(Error::Limit);
                }
            }
            _ => return Err(Error::InvalidRecord),
        }
        if d.text()? != "uncalibrated" {
            return Err(Error::InvalidRecord);
        }
        d.ensure_finished()?;
        groups
            .entry((class.epoch, class.track, class.zone, class.entry_position))
            .or_default()
            .push(class);
    }
    if groups.len() > 64 {
        return Err(Error::Limit);
    }
    for values in groups.values() {
        if values.len() > retained.recipe.config().frames_per_track
            || values[0].position != values[0].entry_position
            || values
                .windows(2)
                .any(|pair| pair[0].position >= pair[1].position)
        {
            return Err(Error::InvalidRecord);
        }
    }
    let admitted = segments.values().filter(|&&status| status != 1).count() as u64;
    let completed = segments.values().filter(|&&status| status == 0).count() as u64;
    if admitted != retained.admitted[1] - retained.admitted[0]
        || completed != retained.completed
        || completed > retained.attempts
    {
        return Err(Error::InvalidRecord);
    }
    Ok(())
}

pub(super) fn digest_binding(
    bindings: &mut BTreeMap<usize, ContentDigest>,
    segment: usize,
    capsule: ContentDigest,
) -> Result<()> {
    super::super::valid_digest(capsule)?;
    if bindings
        .insert(segment, capsule)
        .is_some_and(|previous| previous != capsule)
    {
        return Err(Error::InvalidRecord);
    }
    Ok(())
}
