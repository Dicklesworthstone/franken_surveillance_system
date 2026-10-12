#![forbid(unsafe_code)]
//! Verify the retained two-camera recipe and exact publication closures before native replay.

use super::watch::{count, digest, media_format, privacy_generation, site};
use super::{
    LoadedProfile, LongDwellLimits, LongEventReplayError as Error, LongEventReplayLimits,
    LongEventReplayRecipe, MAX_LONG_DWELL_FRAMES, MAX_LONG_EVENT_ANALYSIS_BYTES,
    MAX_MANIFEST_BYTES, MetadataReader, Result, SourceBinding, manifest, published_root, slot,
};
use crate::ingest::RetainedFileImport;
use crate::ingest::recorded_corroboration::CorroborationDependencyReport;
use crate::ingest::recorded_corroboration::streaming::{
    CAMERA_DOMAIN, LongCorroborationGeometry, LongCorroborationRecipe,
    MAX_LONG_CORROBORATION_RECIPE_BYTES, POLICY,
};
use crate::ingest::recorded_watch::{WatchPlan, WatchZone};
use crate::ingest::rgb_package::MAX_RGB_PACKAGE_BYTES;
use crate::ingest::sensor_health::{policy_bytes, policy_digest};
use crate::{ReferenceDeployment, ReplayCx};
use fss_core::{
    CanonicalDecode, CanonicalDecoder, CaptureInterval, ContentDigest, EventEvidence,
    EventHypothesis, EventState, EvidenceClass, EvidenceEdgeRelation, LedgerAnchor, SensorId,
};
use std::collections::{BTreeMap, BTreeSet};

mod detector;
use detector::{RetainedDetector, digest_binding};

fn values(limits: &LongDwellLimits) -> [u64; 26] {
    let decode = &limits.decode;
    [
        decode.read_limits.max_source_bytes,
        decode.read_limits.max_chunk_bytes,
        decode.read_limits.max_segment_bytes,
        decode.jpeg_limits.maximum_bytes as u64,
        u64::from(decode.jpeg_limits.maximum_dimension),
        decode.jpeg_limits.maximum_pixels as u64,
        decode.jpeg_limits.maximum_markers as u64,
        decode.jpeg_work_units,
        u64::from(decode.h264_limits.max_width),
        u64::from(decode.h264_limits.max_height),
        u64::from(decode.h264_limits.max_macroblocks),
        decode.h264_limits.max_pictures,
        decode.h264_limits.max_nal_bytes as u64,
        u64::from(decode.h264_limits.max_slices_per_picture),
        u64::from(decode.h264_limits.max_reference_frames),
        u64::from(decode.h265_limits.max_width),
        u64::from(decode.h265_limits.max_height),
        decode.h265_limits.max_luma_samples,
        decode.h265_limits.max_pictures,
        decode.h265_limits.max_nal_bytes as u64,
        u64::from(decode.h265_limits.max_slices_per_picture),
        u64::from(decode.h265_limits.max_dpb_pictures),
        limits.maximum_source_chunk_bytes,
        limits.maximum_pixel_samples,
        limits.maximum_assignment_work,
        limits.maximum_trace_bytes as u64,
    ]
}
fn admit(recipe: &LongCorroborationRecipe, limits: &LongEventReplayLimits) -> Result<()> {
    if values(recipe.limits())
        .into_iter()
        .zip(values(&limits.execution))
        .any(|(required, ceiling)| required > ceiling)
    {
        return Err(Error::Limit);
    }
    if let Some(detector) = recipe.detector_recipe() {
        detector.validate_within(&limits.execution, &limits.detector)?;
    }
    Ok(())
}

struct Association {
    roots: [ContentDigest; 2],
    entries: [ContentDigest; 2],
    classes: [Vec<ContentDigest>; 2],
    dependencies: Option<ContentDigest>,
    zone: String,
}

fn association(
    bytes: &[u8],
    recipe: &LongCorroborationRecipe,
    event: &EventHypothesis,
) -> Result<Association> {
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != "fss.long_corroboration_association.v1" || digest(&mut d)? != recipe.digest() {
        return Err(Error::InvalidRecord);
    }
    let zone = d.text()?;
    if event.zone_ids != [zone] || !recipe.plan().zones.iter().any(|z| z.zone_id == zone) {
        return Err(Error::InvalidRecord);
    }
    let entries = [digest(&mut d)?, digest(&mut d)?];
    if d.u64()? != recipe.plan().gates.time_gate_ns
        || d.u64()? != recipe.plan().gates.distance_gate.to_bits()
        || d.i128()? < 0
    {
        return Err(Error::InvalidRecord);
    }
    let distance = f64::from_bits(d.u64()?);
    let score = f64::from_bits(d.u64()?);
    if !distance.is_finite()
        || distance < 0.0
        || distance > recipe.plan().gates.distance_gate
        || !score.is_finite()
    {
        return Err(Error::InvalidRecord);
    }
    let mut classes = [Vec::new(), Vec::new()];
    if let Some(detector) = recipe.detector_recipe() {
        if digest(&mut d)? != detector.digest() {
            return Err(Error::InvalidRecord);
        }
        for selected in &mut classes {
            let count = count(&mut d, detector.config().frames_per_track)?;
            if count == 0 {
                return Err(Error::InvalidRecord);
            }
            for _ in 0..count {
                selected.push(digest(&mut d)?);
            }
        }
    }
    let dependencies = if recipe.dependencies().is_empty() {
        None
    } else {
        Some(digest(&mut d)?)
    };
    if d.text()? != "streaming-source-analysis" || d.u64()? != 2 {
        return Err(Error::InvalidRecord);
    }
    let roots = [digest(&mut d)?, digest(&mut d)?];
    d.ensure_finished()?;
    if roots[0] == roots[1] || entries[0] == entries[1] {
        return Err(Error::InvalidRecord);
    }
    Ok(Association {
        roots,
        entries,
        classes,
        dependencies,
        zone: zone.to_owned(),
    })
}

struct CameraBinding {
    analysis: ContentDigest,
    source: SourceBinding,
    detector: Option<RetainedDetector>,
    masked: BTreeSet<String>,
    geometry_blocked: BTreeSet<String>,
}

#[allow(clippy::too_many_arguments)]
fn camera(
    deployment: &ReferenceDeployment,
    index: usize,
    root: ContentDigest,
    recipe: &LongCorroborationRecipe,
    objects: &mut BTreeMap<ContentDigest, Vec<u8>>,
    limits: &LongEventReplayLimits,
    reader: &mut MetadataReader,
    cx: &ReplayCx,
    geometry: Option<&LongCorroborationGeometry>,
) -> Result<CameraBinding> {
    let root_bytes = objects.get(&root).ok_or(Error::InvalidRecord)?;
    let shared = manifest(
        root_bytes,
        "recorded-long-corroboration-camera-v1",
        7 + 3 + 2 + 64 * 8,
        false,
    )?;
    let mut selected = None;
    for &child in shared.children() {
        if let std::collections::btree_map::Entry::Vacant(entry) = objects.entry(child) {
            // The identical package belongs to both camera closures but is fetched and charged
            // once. Each verified digest retains one immutable copy for this inspection.
            entry.insert(reader.read(deployment, child, MAX_RGB_PACKAGE_BYTES, cx)?);
        }
        let bytes = objects.get(&child).ok_or(Error::InvalidRecord)?;
        if CanonicalDecoder::new(bytes).text().ok() == Some(CAMERA_DOMAIN)
            && selected.replace(child).is_some()
        {
            return Err(Error::InvalidRecord);
        }
    }
    let analysis_digest = selected.ok_or(Error::InvalidRecord)?;
    if published_root(deployment, &slot("lc-a", analysis_digest)?)? != root {
        return Err(Error::AuthorityChanged);
    }
    let analysis = objects.get(&analysis_digest).ok_or(Error::InvalidRecord)?;
    if analysis.len() > MAX_LONG_EVENT_ANALYSIS_BYTES {
        return Err(Error::Limit);
    }
    let mut d = CanonicalDecoder::new(analysis);
    if d.text()? != CAMERA_DOMAIN
        || digest(&mut d)? != ContentDigest::sha256(POLICY)
        || site(&mut d)? != deployment.site_lineage()
        || digest(&mut d)? != recipe.digest()
        || d.text()? != recipe.plan().cameras[index].name
    {
        return Err(Error::InvalidRecord);
    }
    let import_identity = digest(&mut d)?;
    if import_identity != recipe.plan().cameras[index].import_identity {
        return Err(Error::InvalidRecord);
    }
    let import_root = digest(&mut d)?;
    let manifest_digest = digest(&mut d)?;
    let anchor = LedgerAnchor::decode_canonical(&mut d)?;
    if anchor.site_lineage != deployment.site_lineage() {
        return Err(Error::InvalidRecord);
    }
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
        if !recipe.plan().zones.iter().any(|z| z.zone_id == zone) || !masked.insert(zone.to_owned())
        {
            return Err(Error::InvalidRecord);
        }
    }
    let retained = RetainedFileImport::open(
        deployment,
        import_identity,
        limits.execution.decode.read_limits,
        cx,
    )?;
    let segments = retained.manifest().segment_spans.len();
    if segments == 0 || segments > MAX_LONG_DWELL_FRAMES {
        return Err(Error::Limit);
    }
    let watch_plan = WatchPlan {
        import_identity,
        interpretation: recipe.plan().interpretation,
        first_segment: 0,
        segment_count: segments,
        zones: vec![WatchZone {
            zone_id: "ground-observer".to_owned(),
            x: 0,
            y: 0,
            width: 1,
            height: 1,
        }],
        detector: recipe.plan().detector,
        tracker: recipe.plan().tracker,
    };
    if watch_plan_digest != watch_plan.digest() {
        return Err(Error::InvalidRecord);
    }
    let (screened, detector, geometry_receipt) =
        detector::extensions(&mut d, index, segments, recipe, limits, cx)?;
    if screened != recipe.health_screened() {
        return Err(Error::InvalidRecord);
    }
    let privacy = crate::ingest::privacy_mask::current_mask(deployment, &sensor)
        .map_err(crate::ingest::recorded_decode::RecordedDecodeError::from)?;
    if privacy.digest() != privacy_digest || privacy.generation() != privacy_generation {
        return Err(Error::PrivacyChanged);
    }
    let geometry_blocked = match (geometry, geometry_receipt) {
        (Some(geometry), Some(bytes)) => {
            let assessment =
                geometry.verify_assessment(recipe.plan(), index, &sensor, &privacy, &bytes, cx)?;
            assessment
                .blocked
                .into_iter()
                .map(|index| recipe.plan().zones[index].zone_id.clone())
                .collect()
        }
        (None, None) => BTreeSet::new(),
        _ => return Err(Error::InvalidRecord),
    };
    let sensor_digest = ContentDigest::sha256(sensor.as_str().as_bytes());
    if objects.get(&sensor_digest).map(Vec::as_slice) != Some(sensor.as_str().as_bytes())
        || objects
            .get(&ContentDigest::sha256(POLICY))
            .map(Vec::as_slice)
            != Some(POLICY)
        || objects.get(&recipe.digest()).map(Vec::as_slice) != Some(recipe.to_bytes().as_slice())
    {
        return Err(Error::InvalidRecord);
    }
    let mut expected = BTreeSet::from([
        import_root,
        recipe.digest(),
        analysis_digest,
        sensor_digest,
        ContentDigest::sha256(POLICY),
    ]);
    if let Some(geometry) = recipe.geometry_recipe() {
        expected.extend(
            geometry
                .archive_objects()
                .into_iter()
                .map(|(digest, _)| digest),
        );
    }
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
    let mut source = SourceBinding {
        import_identity,
        import_root,
        manifest: manifest_digest,
        anchor,
        sensor,
        privacy: privacy_digest,
        privacy_generation,
        media_format: format,
        first: 0,
        count: segments,
        capsule_bindings: BTreeMap::new(),
        capture_bindings: BTreeMap::new(),
    };
    if let Some(detector) = &detector {
        let component = detector.recipe.digest();
        if objects.get(&component).map(Vec::as_slice) != Some(detector.recipe.to_bytes().as_slice())
            || !objects.contains_key(&detector.recipe.package_digest())
            || !objects.contains_key(&detector.outcome)
        {
            return Err(Error::InvalidRecord);
        }
        detector::bind_inventory(detector, &mut source, recipe.plan().zones.len(), objects)?;
        expected.extend([
            component,
            detector.recipe.package_digest(),
            detector.outcome,
        ]);
        expected.extend(detector.inventory.classes.iter().map(|class| class.digest));
    }
    if shared.children().iter().copied().collect::<BTreeSet<_>>() != expected {
        return Err(Error::InvalidRecord);
    }
    Ok(CameraBinding {
        analysis: analysis_digest,
        source,
        detector,
        masked,
        geometry_blocked,
    })
}

struct EntryBinding {
    track_key: u64,
    local_track: u64,
    epoch: u64,
    position: usize,
    segment: usize,
    capsule: ContentDigest,
    capture: CaptureInterval,
}

fn entry(
    bytes: &[u8],
    index: usize,
    root: ContentDigest,
    zone: &str,
    recipe: &LongCorroborationRecipe,
    camera: &mut CameraBinding,
) -> Result<EntryBinding> {
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != "fss.long_corroboration_observation.v1"
        || digest(&mut d)? != root
        || d.text()? != recipe.plan().cameras[index].name
        || digest(&mut d)? != recipe.plan().cameras[index].homography.digest()
        || d.text()? != zone
        || camera.masked.contains(zone)
        || camera.geometry_blocked.contains(zone)
    {
        return Err(Error::InvalidRecord);
    }
    let track_key = d.u64()?;
    let local_track = d.u64()?;
    let epoch = d.u64()?;
    let position = count(&mut d, camera.source.count - 1)?;
    let segment = count(&mut d, camera.source.count - 1)?;
    let capsule = digest(&mut d)?;
    let _luma = digest(&mut d)?;
    let capture = CaptureInterval::decode_canonical(&mut d)?;
    if !d.bool()? || local_track == 0 {
        return Err(Error::InvalidRecord);
    }
    let mut bounds = [0_i64; 4];
    for value in &mut bounds {
        *value = i64::try_from(d.i128()?).map_err(|_| Error::InvalidRecord)?;
    }
    if bounds[2] <= 0
        || bounds[3] <= 0
        || !f64::from_bits(d.u64()?).is_finite()
        || !f64::from_bits(d.u64()?).is_finite()
    {
        return Err(Error::InvalidRecord);
    }
    d.ensure_finished()?;
    digest_binding(&mut camera.source.capsule_bindings, segment, capsule)?;
    if camera
        .source
        .capture_bindings
        .insert(segment, capture)
        .is_some_and(|previous| previous != capture)
    {
        return Err(Error::InvalidRecord);
    }
    Ok(EntryBinding {
        track_key,
        local_track,
        epoch,
        position,
        segment,
        capsule,
        capture,
    })
}

fn object_bytes(objects: &BTreeMap<ContentDigest, Vec<u8>>, bytes: &[u8]) -> Result<ContentDigest> {
    let identity = ContentDigest::sha256(bytes);
    if objects.get(&identity).map(Vec::as_slice) != Some(bytes) {
        return Err(Error::InvalidRecord);
    }
    Ok(identity)
}

/// Reconstruct declared common causes from the retained source identities. Class annotations
/// never add a supporting domain or another policy edge.
fn dependencies(
    recipe: &LongCorroborationRecipe,
    association: &Association,
    cameras: &[CameraBinding],
    objects: &BTreeMap<ContentDigest, Vec<u8>>,
    proof: &mut BTreeSet<ContentDigest>,
    evidence: &mut Vec<EventEvidence>,
) -> Result<Vec<String>> {
    let Some(identity) = association.dependencies else {
        return Ok(cameras
            .iter()
            .map(|camera| {
                format!(
                    "recorded-sensor:{}",
                    super::hex(ContentDigest::sha256(
                        camera.source.sensor.as_str().as_bytes()
                    ))
                )
            })
            .collect());
    };
    let assessment = CorroborationDependencyReport::from_bytes(
        objects.get(&identity).ok_or(Error::InvalidRecord)?,
    )?;
    if assessment.declarations() != recipe.dependencies() || assessment.cameras().len() != 2 {
        return Err(Error::InvalidRecord);
    }
    proof.insert(object_bytes(objects, &recipe.dependencies().to_bytes())?);
    proof.insert(identity);
    let mut domains = Vec::with_capacity(2);
    for (index, camera) in cameras.iter().enumerate() {
        let retained = assessment
            .cameras()
            .iter()
            .find(|value| value.camera == recipe.plan().cameras[index].name)
            .ok_or(Error::InvalidRecord)?;
        if retained.sensor_digest != ContentDigest::sha256(camera.source.sensor.as_str().as_bytes())
            || retained.import_identity != camera.source.import_identity
            || retained.import_root != camera.source.import_root
        {
            return Err(Error::InvalidRecord);
        }
        domains.push(retained.support_domain.clone());
    }
    for (domain, bytes) in assessment.cause_records()? {
        let identity = object_bytes(objects, &bytes)?;
        proof.insert(identity);
        evidence.push(EventEvidence {
            digest: identity,
            class: if domain.starts_with("recorded-sensor:") {
                EvidenceClass::Derived
            } else {
                EvidenceClass::Assertion
            },
            failure_domain: domain,
            supports: false,
            relation: EvidenceEdgeRelation::RequiredBy,
            capsule_digest: None,
            identity_digest: None,
        });
    }
    evidence.push(EventEvidence {
        digest: identity,
        class: EvidenceClass::Assertion,
        failure_domain: format!("recorded-dependencies:{}", super::hex(identity)),
        supports: false,
        relation: EvidenceEdgeRelation::RequiredBy,
        capsule_digest: None,
        identity_digest: None,
    });
    Ok(domains)
}

pub(super) fn load(
    deployment: &ReferenceDeployment,
    event: &EventHypothesis,
    identity: ContentDigest,
    provenance_root: ContentDigest,
    limits: &LongEventReplayLimits,
    reader: &mut MetadataReader,
    cx: &ReplayCx,
) -> Result<LoadedProfile> {
    if !matches!(
        event.state,
        EventState::Witnessed | EventState::Corroborated
    ) || !event.model_receipts.is_empty()
    {
        return Err(Error::UnsupportedProfile);
    }
    let provenance_slot = slot("lc", identity)?;
    let root_bytes = reader.read(deployment, provenance_root, MAX_MANIFEST_BYTES, cx)?;
    let proof = manifest(&root_bytes, provenance_slot.as_str(), 128, true)?;
    let metadata = reader.read(
        deployment,
        proof.metadata_digest().ok_or(Error::InvalidRecord)?,
        4096,
        cx,
    )?;
    let mut d = CanonicalDecoder::new(&metadata);
    if d.bytes()? != b"FSSLCRR1"
        || d.u32()? != 1
        || d.text()? != "fss.long_corroboration_proposal.v1"
        || digest(&mut d)? != ContentDigest::sha256(POLICY)
        || digest(&mut d)? != identity
        || digest(&mut d)? != event.revision_digest()
    {
        return Err(Error::InvalidRecord);
    }
    d.ensure_finished()?;
    let mut objects = BTreeMap::new();
    for &child in proof.children() {
        objects.insert(
            child,
            reader.read(deployment, child, MAX_LONG_EVENT_ANALYSIS_BYTES, cx)?,
        );
    }
    let association_bytes = objects.get(&identity).ok_or(Error::InvalidRecord)?;
    let mut prefix = CanonicalDecoder::new(association_bytes);
    if prefix.text()? != "fss.long_corroboration_association.v1" {
        return Err(Error::UnsupportedProfile);
    }
    let recipe_digest = digest(&mut prefix)?;
    let recipe_bytes = reader.read(
        deployment,
        recipe_digest,
        MAX_LONG_CORROBORATION_RECIPE_BYTES,
        cx,
    )?;
    let recipe = LongCorroborationRecipe::from_retained_bytes(&recipe_bytes, recipe_digest)?;
    admit(&recipe, limits)?;
    let association = association(association_bytes, &recipe, event)?;
    let geometry = if let Some(geometry) = recipe.geometry_recipe() {
        for (digest, maximum) in geometry.archive_objects() {
            if let std::collections::btree_map::Entry::Vacant(entry) = objects.entry(digest) {
                entry.insert(reader.read(deployment, digest, maximum, cx)?);
            }
        }
        Some(LongCorroborationGeometry::from_retained_objects(
            recipe.plan(),
            geometry,
            &objects,
        )?)
    } else {
        None
    };
    let mut cameras = Vec::with_capacity(2);
    for (index, root) in association.roots.iter().enumerate() {
        cameras.push(camera(
            deployment,
            index,
            *root,
            &recipe,
            &mut objects,
            limits,
            reader,
            cx,
            geometry.as_ref(),
        )?);
    }
    if cameras[0].source.sensor == cameras[1].source.sensor {
        return Err(Error::InvalidRecord);
    }
    if let Some(geometry) = &geometry {
        geometry.check_current(
            deployment,
            recipe.plan(),
            &[
                cameras[0].source.sensor.clone(),
                cameras[1].source.sensor.clone(),
            ],
            cx,
        )?;
    }
    let mut evidence = vec![EventEvidence {
        digest: identity,
        class: EvidenceClass::Derived,
        failure_domain: format!("cross-camera-association:{}", super::hex(recipe.digest())),
        supports: false,
        relation: EvidenceEdgeRelation::DerivedFrom,
        capsule_digest: None,
        identity_digest: None,
    }];
    let mut expected = BTreeSet::from([
        identity,
        object_bytes(&objects, POLICY)?,
        proof.metadata_digest().ok_or(Error::InvalidRecord)?,
    ]);
    expected.extend(association.roots);
    let domains = dependencies(
        &recipe,
        &association,
        &cameras,
        &objects,
        &mut expected,
        &mut evidence,
    )?;
    let mut entries = Vec::with_capacity(2);
    let mut prior_admitted = 0;
    let mut prior_head_work = 0;
    for (index, camera) in cameras.iter_mut().enumerate() {
        let entry_digest = association.entries[index];
        let entry = entry(
            objects.get(&entry_digest).ok_or(Error::InvalidRecord)?,
            index,
            association.roots[index],
            &association.zone,
            &recipe,
            camera,
        )?;
        let sensor = object_bytes(&objects, camera.source.sensor.as_str().as_bytes())?;
        expected.extend([
            camera.analysis,
            entry_digest,
            sensor,
            camera.source.import_root,
            entry.capsule,
        ]);
        evidence.push(EventEvidence {
            digest: camera.analysis,
            class: EvidenceClass::Derived,
            failure_domain: domains[index].clone(),
            supports: false,
            relation: EvidenceEdgeRelation::RequiredBy,
            capsule_digest: None,
            identity_digest: Some(sensor),
        });
        evidence.push(EventEvidence {
            digest: entry_digest,
            class: EvidenceClass::Derived,
            failure_domain: domains[index].clone(),
            supports: true,
            relation: EvidenceEdgeRelation::Supports,
            capsule_digest: Some(entry.capsule),
            identity_digest: Some(sensor),
        });
        if let Some(detector) = &camera.detector {
            if detector.admitted[0] != prior_admitted || detector.head_work[0] != prior_head_work {
                return Err(Error::InvalidRecord);
            }
            prior_admitted = detector.admitted[1];
            prior_head_work = detector.head_work[1];
            let selected = detector
                .inventory
                .classes
                .iter()
                .filter(|class| {
                    class.epoch == entry.epoch
                        && class.track == entry.local_track
                        && class.entry_position == entry.position
                        && recipe.plan().zones[class.zone].zone_id == association.zone
                })
                .collect::<Vec<_>>();
            if selected
                .iter()
                .map(|class| class.digest)
                .collect::<Vec<_>>()
                != association.classes[index]
                || selected.first().is_none_or(|class| {
                    class.position != entry.position
                        || class.segment != entry.segment
                        || class.capsule != entry.capsule
                })
            {
                return Err(Error::InvalidRecord);
            }
            expected.extend(selected.iter().map(|class| class.digest));
        }
        entries.push(entry);
    }
    evidence.sort_by_key(|item| item.digest);
    let state = if domains[0] == domains[1] {
        EventState::Witnessed
    } else {
        EventState::Corroborated
    };
    let action = if state == EventState::Corroborated {
        crate::ReferencePolicyAction::PrepareAlert
    } else {
        crate::ReferencePolicyAction::Hold
    };
    let tracks = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            format!(
                "track:{}:{}",
                recipe.plan().cameras[index].name,
                entry.track_key
            )
        })
        .collect::<BTreeSet<_>>();
    if event.evidence != evidence
        || event.state != state
        || event.track_ids.iter().cloned().collect::<BTreeSet<_>>() != tracks
        || event.interval
            != CaptureInterval::new(
                entries[0].capture.earliest.min(entries[1].capture.earliest),
                entries[0].capture.latest.max(entries[1].capture.latest),
            )?
        || event.probability != fss_core::ProbabilityInterval::new(0.0, 1.0)?
        || event.decision_path
            != crate::policy::zone_entry_decision_path(&event.event_id, &evidence, state, action)
        || proof.children().iter().copied().collect::<BTreeSet<_>>() != expected
    {
        return Err(Error::InvalidRecord);
    }
    let analyses = cameras.iter().map(|camera| camera.analysis).collect();
    let sources = cameras.into_iter().map(|camera| camera.source).collect();
    Ok(LoadedProfile {
        recipe: LongEventReplayRecipe::Corroboration(recipe),
        analysis_roots: association.roots.to_vec(),
        analysis_digests: analyses,
        sources,
    })
}
