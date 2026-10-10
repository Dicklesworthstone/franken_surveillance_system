#![forbid(unsafe_code)]
//! Verify the retained two-camera recipe and exact publication closures before native replay.

use std::collections::{BTreeMap, BTreeSet};
use fss_core::{
    CanonicalDecode, CanonicalDecoder, ContentDigest, EventHypothesis, EventState,
    EvidenceClass, EvidenceEdgeRelation, LedgerAnchor, SensorId,
};
use crate::ingest::recorded_corroboration::streaming::{
    LongCorroborationRecipe, MAX_LONG_CORROBORATION_RECIPE_BYTES,
    CAMERA_DOMAIN, POLICY,
};
use crate::ingest::sensor_health::{policy_bytes, policy_digest};
use crate::ingest::RetainedFileImport;
use crate::ingest::recorded_watch::{WatchPlan, WatchZone};
use crate::{ReferenceDeployment, ReplayCx};
use super::watch::{count, digest, media_format, privacy_generation, site, trace_and_health};
use super::{
    LoadedProfile, LongDwellLimits, LongEventReplayError as Error, LongEventReplayLimits,
    LongEventReplayRecipe, MAX_LONG_DWELL_FRAMES, MAX_LONG_EVENT_ANALYSIS_BYTES,
    MAX_MANIFEST_BYTES, MetadataReader, Result, SourceBinding, manifest, published_root, slot,
};

fn values(limits: &LongDwellLimits) -> [u64; 26] {
    let decode = &limits.decode;
    [
        decode.read_limits.max_source_bytes, decode.read_limits.max_chunk_bytes,
        decode.read_limits.max_segment_bytes, decode.jpeg_limits.maximum_bytes as u64,
        u64::from(decode.jpeg_limits.maximum_dimension), decode.jpeg_limits.maximum_pixels as u64,
        decode.jpeg_limits.maximum_markers as u64, decode.jpeg_work_units,
        u64::from(decode.h264_limits.max_width), u64::from(decode.h264_limits.max_height),
        u64::from(decode.h264_limits.max_macroblocks), decode.h264_limits.max_pictures,
        decode.h264_limits.max_nal_bytes as u64, u64::from(decode.h264_limits.max_slices_per_picture),
        u64::from(decode.h264_limits.max_reference_frames), u64::from(decode.h265_limits.max_width),
        u64::from(decode.h265_limits.max_height), decode.h265_limits.max_luma_samples,
        decode.h265_limits.max_pictures, decode.h265_limits.max_nal_bytes as u64,
        u64::from(decode.h265_limits.max_slices_per_picture),
        u64::from(decode.h265_limits.max_dpb_pictures),
        limits.maximum_source_chunk_bytes, limits.maximum_pixel_samples,
        limits.maximum_assignment_work, limits.maximum_trace_bytes as u64,
    ]
}
fn admit(recipe: &LongCorroborationRecipe, limits: &LongEventReplayLimits) -> Result<()> {
    if values(recipe.limits()).into_iter().zip(values(&limits.execution))
        .any(|(required, ceiling)| required > ceiling) {
        return Err(Error::Limit);
    }
    Ok(())
}

fn association(
    bytes: &[u8], recipe: &LongCorroborationRecipe, event: &EventHypothesis,
) -> Result<[ContentDigest; 2]> {
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != "fss.long_corroboration_association.v1" || digest(&mut d)? != recipe.digest() {
        return Err(Error::InvalidRecord);
    }
    let zone = d.text()?;
    if event.zone_ids != [zone] || !recipe.plan().zones.iter().any(|z| z.zone_id == zone) {
        return Err(Error::InvalidRecord);
    }
    let _left_entry = digest(&mut d)?;
    let _right_entry = digest(&mut d)?;
    if d.u64()? != recipe.plan().gates.time_gate_ns
        || d.u64()? != recipe.plan().gates.distance_gate.to_bits() || d.i128()? < 0 {
        return Err(Error::InvalidRecord);
    }
    let distance = f64::from_bits(d.u64()?);
    let score = f64::from_bits(d.u64()?);
    if !distance.is_finite() || distance < 0.0 || !score.is_finite() {
        return Err(Error::InvalidRecord);
    }
    if !recipe.dependencies().is_empty() {
        let _assessment = digest(&mut d)?;
    }
    if d.text()? != "streaming-source-analysis" || d.u64()? != 2 {
        return Err(Error::InvalidRecord);
    }
    let roots = [digest(&mut d)?, digest(&mut d)?];
    d.ensure_finished()?;
    if roots[0] == roots[1] { return Err(Error::InvalidRecord); }
    Ok(roots)
}

fn camera(
    deployment: &ReferenceDeployment, index: usize, root: ContentDigest,
    recipe: &LongCorroborationRecipe, top_objects: &BTreeMap<ContentDigest, Vec<u8>>,
    limits: &LongEventReplayLimits, reader: &mut MetadataReader, cx: &ReplayCx,
) -> Result<(ContentDigest, SourceBinding)> {
    let root_bytes = top_objects.get(&root).ok_or(Error::InvalidRecord)?;
    let shared = manifest(root_bytes, "recorded-long-corroboration-camera-v1", 7, false)?;
    let mut objects = BTreeMap::new();
    let mut selected = None;
    for &child in shared.children() {
        let bytes = match top_objects.get(&child) {
            Some(bytes) => bytes.clone(),
            None => reader.read(deployment, child, MAX_LONG_EVENT_ANALYSIS_BYTES, cx)?,
        };
        if CanonicalDecoder::new(&bytes).text().ok() == Some(CAMERA_DOMAIN) && selected.replace(child).is_some() {
            return Err(Error::InvalidRecord);
        }
        objects.insert(child, bytes);
    }
    let analysis_digest = selected.ok_or(Error::InvalidRecord)?;
    if published_root(deployment, &slot("lc-a", analysis_digest)?)? != root {
        return Err(Error::AuthorityChanged);
    }
    let analysis = objects.get(&analysis_digest).ok_or(Error::InvalidRecord)?;
    let mut d = CanonicalDecoder::new(analysis);
    if d.text()? != CAMERA_DOMAIN || digest(&mut d)? != ContentDigest::sha256(POLICY)
        || site(&mut d)? != deployment.site_lineage() || digest(&mut d)? != recipe.digest()
        || d.text()? != recipe.plan().cameras[index].name {
        return Err(Error::InvalidRecord);
    }
    let import_identity = digest(&mut d)?;
    if import_identity != recipe.plan().cameras[index].import_identity {
        return Err(Error::InvalidRecord);
    }
    let import_root = digest(&mut d)?;
    let manifest_digest = digest(&mut d)?;
    let anchor = LedgerAnchor::decode_canonical(&mut d)?;
    if anchor.site_lineage != deployment.site_lineage() { return Err(Error::InvalidRecord); }
    let sensor = SensorId::parse(d.text()?)?;
    let format = media_format(d.text()?)?;
    let watch_plan_digest = digest(&mut d)?;
    if digest(&mut d)? != recipe.plan().cameras[index].homography.digest() {
        return Err(Error::InvalidRecord);
    }
    let privacy_digest = digest(&mut d)?;
    let privacy_generation = privacy_generation(&mut d)?;
    let masked_count = count(&mut d, recipe.plan().zones.len())?;
    let mut masked = BTreeSet::new();
    for _ in 0..masked_count {
        let zone = d.text()?;
        if !recipe.plan().zones.iter().any(|z| z.zone_id == zone) || !masked.insert(zone.to_owned()) {
            return Err(Error::InvalidRecord);
        }
    }
    let retained = RetainedFileImport::open(deployment, import_identity, limits.execution.decode.read_limits, cx)?;
    let segments = retained.manifest().segment_spans.len();
    if segments == 0 || segments > MAX_LONG_DWELL_FRAMES { return Err(Error::Limit); }
    let watch_plan = WatchPlan {
        import_identity, interpretation: recipe.plan().interpretation, first_segment: 0,
        segment_count: segments,
        zones: vec![WatchZone { zone_id: "ground-observer".to_owned(), x: 0, y: 0, width: 1, height: 1 }],
        detector: recipe.plan().detector, tracker: recipe.plan().tracker,
    };
    if watch_plan_digest != watch_plan.digest() { return Err(Error::InvalidRecord); }
    let screened = trace_and_health(
        &mut d, segments, recipe.limits().maximum_trace_bytes,
        recipe.limits().maximum_pixel_samples, cx,
    )?;
    if screened != recipe.health_screened() { return Err(Error::InvalidRecord); }
    let privacy = crate::ingest::privacy_mask::current_mask(deployment, &sensor)
        .map_err(crate::ingest::recorded_decode::RecordedDecodeError::from)?;
    if privacy.digest() != privacy_digest || privacy.generation() != privacy_generation {
        return Err(Error::PrivacyChanged);
    }
    let sensor_digest = ContentDigest::sha256(sensor.as_str().as_bytes());
    if objects.get(&sensor_digest).map(Vec::as_slice) != Some(sensor.as_str().as_bytes())
        || objects.get(&ContentDigest::sha256(POLICY)).map(Vec::as_slice) != Some(POLICY)
        || objects.get(&recipe.digest()).map(Vec::as_slice) != Some(recipe.to_bytes().as_slice()) {
        return Err(Error::InvalidRecord);
    }
    let mut expected = BTreeSet::from([
        import_root, recipe.digest(), analysis_digest, sensor_digest, ContentDigest::sha256(POLICY),
    ]);
    if let Some(policy) = privacy.policy() {
        if objects.get(&policy.digest()).map(Vec::as_slice) != Some(policy.to_bytes().as_slice()) {
            return Err(Error::InvalidRecord);
        }
        expected.insert(policy.digest());
    }
    if screened {
        if objects.get(&policy_digest()).map(Vec::as_slice) != Some(policy_bytes()) {
            return Err(Error::InvalidRecord);
        }
        expected.insert(policy_digest());
    }
    if shared.children().iter().copied().collect::<BTreeSet<_>>() != expected {
        return Err(Error::InvalidRecord);
    }
    Ok((analysis_digest, SourceBinding {
        import_identity, import_root, manifest: manifest_digest, anchor, sensor,
        privacy: privacy_digest, privacy_generation, media_format: format, first: 0, count: segments,
        capsule_bindings: BTreeMap::new(),
    }))
}

pub(super) fn load(
    deployment: &ReferenceDeployment, event: &EventHypothesis, identity: ContentDigest,
    provenance_root: ContentDigest, limits: &LongEventReplayLimits,
    reader: &mut MetadataReader, cx: &ReplayCx,
) -> Result<LoadedProfile> {
    if !matches!(event.state, EventState::Witnessed | EventState::Corroborated) || !event.model_receipts.is_empty() {
        return Err(Error::UnsupportedProfile);
    }
    let provenance_slot = slot("lc", identity)?;
    let root_bytes = reader.read(deployment, provenance_root, MAX_MANIFEST_BYTES, cx)?;
    let proof = manifest(&root_bytes, provenance_slot.as_str(), 128, true)?;
    let metadata = reader.read(deployment, proof.metadata_digest().ok_or(Error::InvalidRecord)?, 4096, cx)?;
    let mut d = CanonicalDecoder::new(&metadata);
    if d.bytes()? != b"FSSLCRR1" || d.u32()? != 1 || d.text()? != "fss.long_corroboration_proposal.v1"
        || digest(&mut d)? != ContentDigest::sha256(POLICY) || digest(&mut d)? != identity
        || digest(&mut d)? != event.revision_digest() {
        return Err(Error::InvalidRecord);
    }
    d.ensure_finished()?;
    let mut objects = BTreeMap::new();
    for &child in proof.children() {
        objects.insert(child, reader.read(deployment, child, MAX_LONG_EVENT_ANALYSIS_BYTES, cx)?);
    }
    let association_bytes = objects.get(&identity).ok_or(Error::InvalidRecord)?;
    let mut prefix = CanonicalDecoder::new(association_bytes);
    if prefix.text()? != "fss.long_corroboration_association.v1" {
        return Err(Error::UnsupportedProfile);
    }
    let recipe_digest = digest(&mut prefix)?;
    let recipe_bytes = reader.read(deployment, recipe_digest, MAX_LONG_CORROBORATION_RECIPE_BYTES, cx)?;
    let recipe = LongCorroborationRecipe::from_retained_bytes(&recipe_bytes, recipe_digest)?;
    admit(&recipe, limits)?;
    let roots = association(association_bytes, &recipe, event)?;
    let mut sources = Vec::with_capacity(2);
    let mut analyses = Vec::with_capacity(2);
    for (index, root) in roots.iter().enumerate() {
        let (analysis, source) = camera(deployment, index, *root, &recipe, &objects, limits, reader, cx)?;
        let sensor_digest = ContentDigest::sha256(source.sensor.as_str().as_bytes());
        if !event.evidence.iter().any(|item| item.digest == analysis && item.class == EvidenceClass::Derived
            && item.relation == EvidenceEdgeRelation::RequiredBy && !item.supports
            && item.identity_digest == Some(sensor_digest)) {
            return Err(Error::InvalidRecord);
        }
        analyses.push(analysis);
        sources.push(source);
    }
    Ok(LoadedProfile {
        recipe: LongEventReplayRecipe::Corroboration(recipe), analysis_roots: roots.to_vec(),
        analysis_digests: analyses, sources,
    })
}
