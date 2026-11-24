#![forbid(unsafe_code)]
//! Deterministic JSON payload renderers for H2 analytic and H3 visual hydration projections.

use fss_core::ContentDigest;

use super::h2::H2HydrationAnswer;
use super::h3::{H3FrameReceipt, H3HydrationAnswer};
use super::{CropBox, H2_PAYLOAD_SCHEMA, H2_RECEIPT_DOMAIN, H3_PAYLOAD_SCHEMA, H3_RECEIPT_DOMAIN};
use crate::json_output::{array, object, string, strings};

pub(super) fn render_h2_answer_json(answer: &H2HydrationAnswer) -> String {
    let trajectories_json: Vec<String> = answer
        .trajectories
        .iter()
        .map(|traj| {
            let obs: Vec<String> = traj
                .observations
                .iter()
                .map(|o| {
                    object(&[
                        ("segmentIndex", o.segment_index.to_string()),
                        ("capsuleDigest", string(&o.capsule_digest.to_text())),
                        ("lumaDigest", string(&o.luma_digest.to_text())),
                        (
                            "bbox",
                            format!("[{},{},{},{}]", o.bbox[0], o.bbox[1], o.bbox[2], o.bbox[3]),
                        ),
                    ])
                })
                .collect();
            object(&[
                ("trackId", traj.track_id.to_string()),
                ("importIdentity", string(&traj.import_identity.to_text())),
                ("planDigest", string(&traj.plan_digest.to_text())),
                ("observations", array(&obs)),
            ])
        })
        .collect();
    let receipts_json: Vec<String> = answer
        .model_receipts
        .iter()
        .map(|rec| {
            object(&[
                ("receiptDigest", string(&rec.receipt_digest.to_text())),
                ("modelId", string(&rec.model_id)),
                ("modelGeneration", string(&rec.model_generation)),
                (
                    "label",
                    rec.label
                        .as_deref()
                        .map_or_else(|| "null".to_owned(), string),
                ),
                (
                    "uncalibratedScorePpm",
                    rec.uncalibrated_score_ppm
                        .map_or_else(|| "null".to_owned(), |v| v.to_string()),
                ),
                (
                    "detectionBox",
                    rec.detection_box.map_or_else(
                        || "null".to_owned(),
                        |b| format!("[{},{},{},{}]", b[0], b[1], b[2], b[3]),
                    ),
                ),
                ("calibrated", rec.calibrated.to_string()),
                ("scoreProvenance", string(&rec.score_provenance)),
            ])
        })
        .collect();
    let domains_json: Vec<String> = answer
        .failure_domains
        .iter()
        .map(|dom| {
            object(&[
                ("failureDomain", string(&dom.failure_domain)),
                ("supportingEdges", dom.supporting_edges.to_string()),
                ("contradictingEdges", dom.contradicting_edges.to_string()),
                ("derivedEdges", dom.derived_edges.to_string()),
                ("requiredByEdges", dom.required_by_edges.to_string()),
                ("calibrated", dom.calibrated.to_string()),
                (
                    "llrMillibans",
                    dom.llr_millibans
                        .map_or_else(|| "null".to_owned(), |r| format!("[{},{}]", r[0], r[1])),
                ),
                ("llrStatus", string(dom.llr_status)),
                (
                    "capsuleDigests",
                    strings(
                        dom.capsule_digests
                            .iter()
                            .copied()
                            .map(ContentDigest::to_text),
                    ),
                ),
            ])
        })
        .collect();
    let graph_json = answer.graph_neighborhood.as_ref().map_or_else(
        || "null".to_owned(),
        |g| {
            object(&[
                ("centerEntityId", string(&g.center_entity_id)),
                ("radiusHops", g.radius_hops.to_string()),
                ("nodeCount", g.node_count.to_string()),
                ("edgeCount", g.edge_count.to_string()),
                ("subgraphDigest", string(&g.subgraph_digest.to_text())),
                ("artifactDigest", string(&g.artifact_digest.to_text())),
                ("maskedAttributes", strings(g.masked_attributes.iter())),
            ])
        },
    );
    let receipt_json = object(&[
        ("schema", string(H2_RECEIPT_DOMAIN)),
        (
            "receiptDigest",
            string(&answer.receipt.receipt_digest.to_text()),
        ),
        (
            "projectionDigest",
            string(&answer.receipt.projection_digest.to_text()),
        ),
        (
            "subgraphDigest",
            answer
                .receipt
                .subgraph_digest
                .map_or_else(|| "null".to_owned(), |d| string(&d.to_text())),
        ),
        ("trackCount", answer.receipt.track_count.to_string()),
        (
            "observationCount",
            answer.receipt.observation_count.to_string(),
        ),
        (
            "modelReceiptCount",
            answer.receipt.model_receipt_count.to_string(),
        ),
        (
            "failureDomainCount",
            answer.receipt.failure_domain_count.to_string(),
        ),
        ("calibrated", answer.receipt.calibrated.to_string()),
        ("capability", string(answer.receipt.capability)),
    ]);
    object(&[
        ("schema", string(H2_PAYLOAD_SCHEMA)),
        ("level", string("H2")),
        ("anchorToken", string(&answer.anchor_token)),
        ("target", string(&answer.target_label)),
        ("zoneIds", strings(answer.zone_ids.iter())),
        (
            "declaredTrackIds",
            strings(answer.declared_track_ids.iter()),
        ),
        ("trackTrajectories", array(&trajectories_json)),
        ("modelReceipts", array(&receipts_json)),
        ("failureDomains", array(&domains_json)),
        (
            "independentSupportingClusters",
            answer.independent_supporting_clusters.to_string(),
        ),
        (
            "corroborationSatisfied",
            answer.corroboration_satisfied.to_string(),
        ),
        ("calibrated", answer.receipt.calibrated.to_string()),
        ("graphNeighborhood", graph_json),
        (
            "importPrivacyBinding",
            answer
                .import_privacy_binding
                .as_deref()
                .map_or_else(|| "null".to_owned(), string),
        ),
        ("receipt", receipt_json),
        ("budget", answer.budget.to_json()),
        ("rawMediaDisclosed", "false".to_owned()),
        ("effectAuthority", "false".to_owned()),
    ])
}

pub(super) fn render_h3_frame_receipt_json(receipt: &H3FrameReceipt) -> String {
    object(&[
        ("schema", string(H3_RECEIPT_DOMAIN)),
        ("receiptDigest", string(&receipt.receipt_digest.to_text())),
        ("segmentIndex", receipt.segment_index.to_string()),
        (
            "sourceImportId",
            string(&receipt.source_import_id.to_text()),
        ),
        (
            "sourceCapsuleDigest",
            string(&receipt.source_capsule_digest.to_text()),
        ),
        ("sensorId", string(&receipt.sensor_id)),
        ("privacyMaskBinding", string(receipt.privacy_mask_binding)),
        (
            "privacyMaskBindingDigest",
            string(&receipt.privacy_mask_binding_digest.to_text()),
        ),
        (
            "privacyMaskPolicyDigest",
            receipt
                .privacy_mask_policy_digest
                .map_or_else(|| "null".to_owned(), |d| string(&d.to_text())),
        ),
        (
            "privacyMaskGeneration",
            receipt
                .privacy_mask_generation
                .map_or_else(|| "null".to_owned(), |g| g.to_string()),
        ),
        (
            "appliedRedactionTransform",
            string(receipt.applied_redaction_transform),
        ),
        ("unmaskedAccess", string(receipt.unmasked_access)),
        (
            "sourceDimensions",
            format!(
                "[{},{}]",
                receipt.source_dimensions[0], receipt.source_dimensions[1]
            ),
        ),
        (
            "cropBox",
            receipt
                .crop_box
                .as_ref()
                .map_or_else(|| "null".to_owned(), CropBox::to_json),
        ),
        ("width", receipt.width.to_string()),
        ("height", receipt.height.to_string()),
        ("outputBytes", receipt.output_bytes.to_string()),
        (
            "outputJpegSha256",
            string(&receipt.output_jpeg_sha256.to_text()),
        ),
        (
            "encoderReceiptDigest",
            string(&receipt.encoder_receipt_digest.to_text()),
        ),
    ])
}

pub(super) fn render_h3_answer_json(answer: &H3HydrationAnswer) -> String {
    let frames_json: Vec<String> = answer
        .frames
        .iter()
        .map(|frame| {
            object(&[
                ("segmentIndex", frame.segment_index.to_string()),
                ("mimeType", string("image/jpeg")),
                ("jpegBase64", string(&frame.jpeg_base64)),
                ("receipt", frame.receipt.to_json()),
            ])
        })
        .collect();
    object(&[
        ("schema", string(H3_PAYLOAD_SCHEMA)),
        ("level", string("H3")),
        ("anchorToken", string(&answer.anchor_token)),
        ("target", string(&answer.target_label)),
        (
            "limits",
            object(&[
                ("maxH3Frames", answer.limits.max_h3_frames.to_string()),
                ("maxH3Bytes", answer.limits.max_h3_bytes.to_string()),
                ("maxDimension", answer.limits.max_dimension.to_string()),
            ]),
        ),
        ("totalOutputBytes", answer.total_output_bytes.to_string()),
        ("receiptDigest", string(&answer.receipt_digest.to_text())),
        ("frames", array(&frames_json)),
        ("budget", answer.budget.to_json()),
        ("unmaskedAccess", string("refused")),
        ("effectAuthority", "false".to_owned()),
    ])
}
