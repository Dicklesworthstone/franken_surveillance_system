#![forbid(unsafe_code)]
//! Provenance decoding, import projection, failure-domain grouping, and receipt sealing for H2.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest, EvidenceEdgeRelation,
    LedgerAnchor,
};
use fss_reference::ReplayCx;
use fss_reference::agent_orient::RetainedEvent;
use fss_reference::ingest::privacy_mask::current_mask;
use fss_reference::ingest::recorded_decode::retained_source_capsule;
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits};
use fss_reference::retained_source::{ImmutableRetainedSource, RetainedSource};

use super::h2::{
    H2FailureDomainCluster, H2HydrationAnswer, H2HydrationReceipt, H2ModelReceiptProjection,
    H2ObservationBox, H2TrackTrajectory, zero_h2_budget,
};
use super::{CAP_AGENT_HYDRATE_H2, H2_PAYLOAD_SCHEMA, H2_RECEIPT_DOMAIN, HydrationError};

const WATCH_OBSERVATION_DOMAIN: &str = "fss.recorded_watch_observation.v1";
const CASCADE_EVIDENCE_DOMAIN: &str = "fss.detector_class_evidence.v1";
const MAX_PROVENANCE_OBJECT_BYTES: usize = 64 * 1024;

pub(super) fn build_import_h2(
    owner: &ImmutableRetainedSource<'_>,
    cx: &ReplayCx,
    import_id: ContentDigest,
    anchor_token: &str,
) -> Result<H2HydrationAnswer, HydrationError> {
    let retained = RetainedFileImport::open(owner, import_id, RetainedReadLimits::default(), cx)
        .map_err(|error| {
            if error.stable_id() == Some("ERR-EVIDENCE-DELETED-001") {
                HydrationError::EvidenceDeleted("import is covered by a committed deletion".into())
            } else {
                HydrationError::NotFound(format!("retained import unavailable: {error}"))
            }
        })?;
    let snapshot = owner.snapshot();
    let privacy_binding = if !retained.manifest().segment_spans.is_empty() {
        let capsule = retained_source_capsule(owner, &retained, 0).map_err(|error| {
            HydrationError::CustodyFailure(format!("capsule read failed: {error}"))
        })?;
        let mask = current_mask(owner, &capsule.sensor_id).map_err(|error| {
            HydrationError::PrivacyRefused {
                error_id: error.stable_id(),
                detail: error.to_string(),
            }
        })?;
        Some(mask.label().to_owned())
    } else {
        None
    };

    let mut trajectories = Vec::new();
    let mut model_receipts = Vec::new();
    let mut failure_domains = Vec::new();
    let mut zone_ids = BTreeSet::new();
    let mut declared_track_ids = BTreeSet::new();
    for event in &snapshot.events {
        let (event_trajs, event_models) = extract_event_provenance(owner, event);
        let matching_trajs: Vec<H2TrackTrajectory> = event_trajs
            .into_iter()
            .filter(|t| t.import_identity == import_id)
            .collect();
        if !matching_trajs.is_empty() {
            trajectories.extend(matching_trajs);
            model_receipts.extend(event_models);
            zone_ids.extend(event.event.zone_ids.iter().cloned());
            declared_track_ids.extend(event.event.track_ids.iter().cloned());
            let (domains, _) = build_failure_domains(event, false);
            failure_domains.extend(domains);
        }
    }
    let observation_count: usize = trajectories.iter().map(|t| t.observations.len()).sum();
    let receipt = seal_h2_receipt(
        &snapshot.anchor,
        &import_id.to_text(),
        retained.import_root(),
        None,
        trajectories.len(),
        observation_count,
        model_receipts.len(),
        failure_domains.len(),
        false,
    );
    let receipt_digest_text = receipt.receipt_digest.to_text();
    let placeholder_budget = zero_h2_budget()?;

    Ok(H2HydrationAnswer {
        anchor: snapshot.anchor.clone(),
        anchor_token: anchor_token.to_owned(),
        observed_at_ns: snapshot.latest_evidence_time.0,
        target_label: format!("import:{}", import_id.to_text()),
        zone_ids: zone_ids.into_iter().collect(),
        declared_track_ids: declared_track_ids.into_iter().collect(),
        trajectories,
        model_receipts,
        failure_domains,
        independent_supporting_clusters: 0,
        corroboration_satisfied: false,
        graph_neighborhood: None,
        import_privacy_binding: privacy_binding,
        receipt,
        budget: placeholder_budget,
        proof_pointers: vec![
            retained.import_root().to_text(),
            retained.manifest_digest().to_text(),
            receipt_digest_text,
        ],
        warnings: vec![
            "H2 import projection: no raw media decoded; privacy binding reflects active policy at anchor."
                .to_owned(),
        ],
    })
}

/// Decodes retained watch observations (`fss.recorded_watch_observation.v1`) and detector class
/// evidence (`fss.detector_class_evidence.v1`) referenced by `retained.event.evidence`.
pub(crate) fn extract_event_provenance(
    owner: &dyn RetainedSource,
    retained: &RetainedEvent,
) -> (Vec<H2TrackTrajectory>, Vec<H2ModelReceiptProjection>) {
    let mut by_track: BTreeMap<(u64, ContentDigest, ContentDigest), Vec<H2ObservationBox>> =
        BTreeMap::new();
    let mut models = Vec::new();
    for edge in &retained.event.evidence {
        let Ok(bytes) = owner.read_object_bounded(edge.digest, MAX_PROVENANCE_OBJECT_BYTES) else {
            continue;
        };
        if let Some((import_id, plan_digest, track_id, obs)) = decode_watch_observation(&bytes) {
            by_track
                .entry((track_id, import_id, plan_digest))
                .or_default()
                .push(obs);
        } else if let Some(model) = decode_cascade_evidence(edge.digest, &bytes) {
            models.push(model);
        }
    }
    let trajectories = by_track
        .into_iter()
        .map(
            |((track_id, import_identity, plan_digest), mut observations)| {
                observations.sort_by_key(|o| o.segment_index);
                H2TrackTrajectory {
                    track_id,
                    import_identity,
                    plan_digest,
                    observations,
                }
            },
        )
        .collect();
    (trajectories, models)
}

pub(crate) fn decode_watch_observation(
    bytes: &[u8],
) -> Option<(ContentDigest, ContentDigest, u64, H2ObservationBox)> {
    let mut d = CanonicalDecoder::new(bytes);
    if d.text().ok()? != WATCH_OBSERVATION_DOMAIN {
        return None;
    }
    let import_identity = d.digest().ok()?;
    let plan_digest = d.digest().ok()?;
    let segment_index = d.u64().ok()?;
    let capsule_digest = d.digest().ok()?;
    let luma_digest = d.digest().ok()?;
    let track_id = d.u64().ok()?;
    let mut bbox = [0_i64; 4];
    for slot in &mut bbox {
        *slot = i64::try_from(d.i128().ok()?).ok()?;
    }
    d.ensure_finished().ok()?;
    Some((
        import_identity,
        plan_digest,
        track_id,
        H2ObservationBox {
            segment_index,
            capsule_digest,
            luma_digest,
            bbox,
        },
    ))
}

fn decode_cascade_evidence(
    digest: ContentDigest,
    bytes: &[u8],
) -> Option<H2ModelReceiptProjection> {
    let mut d = CanonicalDecoder::new(bytes);
    if d.text().ok()? != CASCADE_EVIDENCE_DOMAIN {
        return None;
    }
    let _cascade_digest = d.digest().ok()?;
    let package_digest = d.digest().ok()?;
    let generation = d.text().ok()?.to_owned();
    let _import_id = d.digest().ok()?;
    let _track_id = d.u64().ok()?;
    let _segment = d.u64().ok()?;
    let _reason_tag = d.u8().ok()?;
    for _ in 0..4 {
        let _ = d.i128().ok()?;
    }
    match d.u8().ok()? {
        0 => {
            for _ in 0..5 {
                let _ = d.digest().ok()?;
            }
        }
        1 => {}
        2 => {
            let _ = d.text().ok()?;
        }
        _ => return None,
    }
    let (label, score_ppm, detection_box) = match d.u8().ok()? {
        0 => {
            let _row = d.u64().ok()?;
            let _class_idx = d.u64().ok()?;
            let label = d.text().ok()?.to_owned();
            let score = f32::from_bits(d.u32().ok()?);
            let mut b = [0_u32; 4];
            for slot in &mut b {
                *slot = d.u32().ok()?;
            }
            let _iou_ppm = d.u32().ok()?;
            let ppm = if score.is_finite() {
                ((f64::from(score).clamp(0.0, 1.0)) * 1_000_000.0).round() as u32
            } else {
                0
            };
            (Some(label), Some(ppm), Some(b))
        }
        _ => (None, None, None),
    };
    Some(H2ModelReceiptProjection {
        receipt_digest: digest,
        model_id: format!("package:{}", package_digest.to_text()),
        model_generation: generation,
        label,
        uncalibrated_score_ppm: score_ppm,
        detection_box,
        calibrated: false,
        score_provenance:
            "Uncalibrated detector cascade output; no score calibration artifact is applied."
                .to_owned(),
    })
}

pub(super) fn build_failure_domains(
    retained: &RetainedEvent,
    calibrated: bool,
) -> (Vec<H2FailureDomainCluster>, usize) {
    let mut grouped: BTreeMap<String, H2FailureDomainCluster> = BTreeMap::new();
    for edge in &retained.event.evidence {
        let entry = grouped
            .entry(edge.failure_domain.clone())
            .or_insert_with(|| H2FailureDomainCluster {
                failure_domain: edge.failure_domain.clone(),
                supporting_edges: 0,
                contradicting_edges: 0,
                derived_edges: 0,
                required_by_edges: 0,
                calibrated,
                llr_millibans: None,
                llr_status: if calibrated {
                    "calibration_generation_present_external_fusion_required"
                } else {
                    "uncalibrated_no_score_calibration_artifact"
                },
                capsule_digests: Vec::new(),
            });
        match edge.relation {
            EvidenceEdgeRelation::Supports => entry.supporting_edges += 1,
            EvidenceEdgeRelation::Contradicts | EvidenceEdgeRelation::Invalidates => {
                entry.contradicting_edges += 1;
            }
            EvidenceEdgeRelation::DerivedFrom => entry.derived_edges += 1,
            EvidenceEdgeRelation::RequiredBy => entry.required_by_edges += 1,
            _ => {}
        }
        if let Some(cap) = edge.capsule_digest
            && !entry.capsule_digests.contains(&cap)
        {
            entry.capsule_digests.push(cap);
        }
    }
    let mut clusters: Vec<H2FailureDomainCluster> = grouped.into_values().collect();
    for cluster in &mut clusters {
        cluster.capsule_digests.sort();
    }
    let independent_supporting = clusters.iter().filter(|c| c.supporting_edges > 0).count();
    (clusters, independent_supporting)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn seal_h2_receipt(
    anchor: &LedgerAnchor,
    target_id: &str,
    subject_digest: ContentDigest,
    subgraph_digest: Option<ContentDigest>,
    track_count: usize,
    observation_count: usize,
    model_receipt_count: usize,
    failure_domain_count: usize,
    calibrated: bool,
) -> H2HydrationReceipt {
    let mut proj = CanonicalEncoder::new();
    proj.text(H2_PAYLOAD_SCHEMA);
    proj.text(target_id);
    proj.digest(subject_digest);
    proj.u64(track_count as u64);
    proj.u64(observation_count as u64);
    proj.u64(model_receipt_count as u64);
    proj.u64(failure_domain_count as u64);
    proj.bool(calibrated);
    let projection_digest = ContentDigest::sha256(&proj.finish());

    let mut enc = CanonicalEncoder::new();
    enc.text(H2_RECEIPT_DOMAIN);
    anchor.encode_canonical(&mut enc);
    enc.text(target_id);
    enc.digest(subject_digest);
    enc.digest(projection_digest);
    enc.bool(subgraph_digest.is_some());
    if let Some(sub) = subgraph_digest {
        enc.digest(sub);
    }
    enc.u64(track_count as u64);
    enc.u64(observation_count as u64);
    enc.u64(model_receipt_count as u64);
    enc.u64(failure_domain_count as u64);
    enc.bool(calibrated);
    enc.text(CAP_AGENT_HYDRATE_H2);
    let receipt_digest = ContentDigest::sha256(&enc.finish());

    H2HydrationReceipt {
        receipt_digest,
        projection_digest,
        subgraph_digest,
        track_count,
        observation_count,
        model_receipt_count,
        failure_domain_count,
        calibrated,
        capability: CAP_AGENT_HYDRATE_H2,
    }
}
