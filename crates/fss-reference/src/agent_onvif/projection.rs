#![forbid(unsafe_code)]
//! Complete, redacted semantic rows for the canonical read-only ONVIF query.
//!
//! Row admission is shared with the native owner. All selected source dispositions,
//! frame barriers, occurrences and analysis relations are represented or the request
//! refuses; this projection never selects a favorable subset of vendor evidence.

use fss_core::{
    ContentDigest, EnvelopeCoverage, EnvelopeEpistemic, EnvelopeProposition, KnowledgeState,
};

use super::{DeploymentOnvifQuery, OnvifAnalysisResult, OnvifQueryRequest, OnvifReadResult};
use crate::onvif::metadata::lifecycle::contract::{LifecycleEndpointState, LifecycleOccurrenceRef};
use crate::onvif::metadata::tracks::contract::TrackFrameReference;
use crate::onvif::metadata::zones::contract::{ZoneRelation, ZoneTransitionKind};

/// Count every disclosed data row before rendering. Fixed scope/privacy statements do
/// not count, just as in existing record queries. Overflow is a complete refusal.
pub(super) fn entry_count(native: &OnvifReadResult) -> usize {
    let mut count = native
        .sources
        .len()
        .saturating_add(native.tracks.frames.len())
        .saturating_add(native.tracks.occurrences.len())
        .saturating_add(native.tracks.tracklets.len());
    match &native.analysis {
        OnvifAnalysisResult::Tracks => {}
        OnvifAnalysisResult::Lifecycle {
            report, documents, ..
        } => {
            count = count
                .saturating_add(documents.len())
                .saturating_add(report.operations.len())
                .saturating_add(report.behaviours.len())
                .saturating_add(report.reuses.len());
            for operation in &report.operations {
                for endpoint in operation.from.iter().chain(&operation.to) {
                    count = count
                        .saturating_add(1)
                        .saturating_add(endpoint.observations.len());
                }
            }
        }
        OnvifAnalysisResult::Zones(report) => {
            count = count
                .saturating_add(report.policy.zones.len())
                .saturating_add(report.cells.len())
                .saturating_add(report.frame_samples.len())
                .saturating_add(report.transitions.len());
        }
    }
    count
}

fn digest(value: Option<ContentDigest>) -> String {
    value.map_or_else(|| "unavailable".to_owned(), ContentDigest::to_text)
}

fn ordinal(value: Option<usize>) -> String {
    value.map_or_else(|| "none".to_owned(), |value| value.to_string())
}

fn locator(frame: &TrackFrameReference) -> String {
    format!(
        "frame_ordinal={}, source_identity={}, source_root={}, source_digest={}, document_index={}, frame_index={}, frame_digest={}, scope={}",
        frame.ordinal,
        frame.source_identity,
        frame.source_root,
        frame.source_digest,
        frame.document_index,
        frame.frame_index,
        frame.frame_digest,
        frame.scope
    )
}

fn occurrence(reference: &LifecycleOccurrenceRef) -> String {
    format!(
        "basis={}, occurrence_ordinal={}, occurrence_identity={}, tracklet_identity={}, frame_ordinal={}, object_index={}",
        reference.basis.as_str(),
        reference.occurrence_ordinal,
        reference.occurrence_identity,
        reference.tracklet_identity,
        reference.frame_ordinal,
        reference.object_index
    )
}

fn support_state(state: LifecycleEndpointState) -> KnowledgeState {
    match state {
        LifecycleEndpointState::Observed => KnowledgeState::Known,
        LifecycleEndpointState::Unresolved => KnowledgeState::Unknown,
        LifecycleEndpointState::Conflicted => KnowledgeState::Conflicted,
    }
}

fn push(
    rows: &mut Vec<EnvelopeProposition>,
    id: String,
    statement: String,
    state: KnowledgeState,
    provenance: &str,
    evidence: &[ContentDigest],
) {
    rows.push(EnvelopeProposition {
        id: format!("claim:onvif:{id}"),
        statement,
        state,
        provenance: provenance.to_owned(),
        evidence: evidence.iter().map(|digest| digest.to_text()).collect(),
    });
}

impl DeploymentOnvifQuery {
    /// Bounded record-level facts. A known vendor declaration is not a known fact
    /// about the physical world; relationship support and physical truth stay distinct.
    #[must_use]
    pub fn epistemic(&self, request: &OnvifQueryRequest) -> EnvelopeEpistemic {
        let native = &self.native;
        let tracks = &native.tracks;
        let mut rows = Vec::with_capacity(entry_count(native).saturating_add(3));
        let analysis = match &native.analysis {
            OnvifAnalysisResult::Tracks => "tracks",
            OnvifAnalysisResult::Lifecycle { .. } => "lifecycle",
            OnvifAnalysisResult::Zones(_) => "zones",
        };
        push(
            &mut rows,
            "selection".to_owned(),
            format!(
                "Verified ordered ONVIF source metadata and recomputed {analysis} under its exact frozen contracts: sources={}, frames={}, object_occurrences={}, vendor_tracklets={}, complete_semantic_rows={}, requested_max_entries={}, tracklet_report={}, native_decision={}. All selected semantic rows are disclosed; no continuation or hidden result truncation.",
                native.sources.len(),
                tracks.frames.len(),
                tracks.occurrences.len(),
                tracks.tracklets.len(),
                entry_count(native),
                request.max_entries,
                tracks.report_digest,
                native.decision_digest
            ),
            KnowledgeState::Known,
            "derived",
            &[native.decision_digest, tracks.report_digest],
        );
        push(&mut rows, "physical-observability".to_owned(),
            "These are vendor declarations and derived comparisons over retained metadata. Physical identity, motion, occupancy, sensor coverage, physical absence, trustworthy capture time and independent corroboration remain unknown. An empty frame or successful empty analysis is not an absence certificate. No event or effect authority is created.".to_owned(),
            KnowledgeState::Unknown, "derived", &[]);
        push(&mut rows, "vendor-values".to_owned(),
            "Vendor ObjectId spellings, module labels, UUID values, UTC values, geometry and appearance values are withheld. Exact source/frame/object references, conservative barriers, relationship states and operator-supplied zone policy remain visible. This H0 query neither exposes original bytes nor grants hydration authority.".to_owned(),
            KnowledgeState::Redacted, "derived", &[]);

        for (index, source) in native.sources.iter().enumerate() {
            push(
                &mut rows,
                format!("source:{index}"),
                format!(
                    "Verified source metadata: source_ordinal={index}, kind={}, identity={}, root={}, scope={}, source_digest={}, native_source_digest={}, interpretation_digest={}, parser_generation={}, acquisition_mode={}, publication_epoch={}, publication_sequence={}, publication_state_root={}, documents={}, analytics_frames={}, empty_analytics_documents={}, rejected_documents={}, uninterpreted_documents={}, source_processing_complete={}. Completion describes retained processing only.",
                    source.pin.kind(),
                    source.pin.identity(),
                    source.pin.root(),
                    source.scope,
                    source.source_digest,
                    digest(source.native_source_digest),
                    source.interpretation_digest,
                    source.parser_generation,
                    source.source_mode,
                    source.publication_anchor.ledger_epoch,
                    source.publication_anchor.commit_sequence,
                    source.publication_anchor.state_root,
                    source.documents,
                    source.analytics_frames,
                    source.empty_analytics_documents,
                    source.rejected_documents,
                    source.uninterpreted_documents,
                    source.source_processing_complete
                ),
                KnowledgeState::Known,
                "derived",
                &[
                    source.pin.root(),
                    source.source_digest,
                    source.interpretation_digest,
                ],
            );
        }
        for frame in &tracks.frames {
            let barriers = frame
                .barriers
                .iter()
                .map(|reason| reason.as_str())
                .collect::<Vec<_>>()
                .join(",");
            let mut statement = format!(
                "Derived source-frame summary over vendor declarations: {}, module_digest={}, frame_transform_digest={}, occurrence_start={}, occurrence_count={}, tracklet_barriers=[{barriers}]. Vendor labels and time are redacted; zero occurrences are not physical absence.",
                locator(&frame.reference),
                digest(frame.module_digest),
                frame.transformation_digest,
                frame.occurrence_start,
                frame.occurrence_count
            );
            if let OnvifAnalysisResult::Lifecycle { report, .. } = &native.analysis {
                if let Some(lifecycle) = report.frames.get(frame.reference.ordinal) {
                    let boundaries = lifecycle
                        .barriers
                        .iter()
                        .map(|reason| reason.as_str())
                        .collect::<Vec<_>>()
                        .join(",");
                    statement.push_str(&format!(
                        " Additive lifecycle frame: section_index={}, section_child_index={}, object_tree_child_index={}, operation_start={}, operation_count={}, behaviour_start={}, behaviour_count={}, lifecycle_barriers=[{boundaries}]. Known lifecycle declarations do not merge the frozen tracklets.",
                        lifecycle.section_index, lifecycle.section_child_index, ordinal(lifecycle.object_tree_child_index),
                        lifecycle.operation_start, lifecycle.operation_count, lifecycle.behaviour_start, lifecycle.behaviour_count));
                }
            }
            push(
                &mut rows,
                format!("frame:{}", frame.reference.ordinal),
                statement,
                KnowledgeState::Known,
                "derived",
                &[frame.reference.source_digest, frame.reference.frame_digest],
            );
        }
        for (index, object) in tracks.occurrences.iter().enumerate() {
            push(
                &mut rows,
                format!("occurrence:{index}"),
                format!(
                    "Retained vendor object occurrence: ordinal={index}, identity={}, tracklet_identity={}, frame_ordinal={}, original_object_index={}, object_transform_digest={}. The original vendor identifier, label, time and appearance values are redacted.",
                    object.identity,
                    object.tracklet_identity,
                    object.frame_ordinal,
                    object.object_index,
                    object.transformation_digest
                ),
                KnowledgeState::Known,
                "vendor_claimed",
                &[object.identity, tracks.report_digest],
            );
        }
        for (index, track) in tracks.tracklets.iter().enumerate() {
            push(
                &mut rows,
                format!("tracklet:{index}"),
                format!(
                    "Derived vendor-ID episode: identity={}, scope={}, module_digest={}, vendor_key_digest={}, occurrence_indices=[{}], start_reasons=[{}], end_reasons=[{}]. This groups only the named retained vendor declarations; it establishes no physical identity or track continuity outside these occurrences.",
                    track.identity,
                    track.scope,
                    digest(track.module_digest),
                    track.vendor_key_digest,
                    track
                        .occurrence_indices
                        .iter()
                        .map(usize::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                    track
                        .start_reasons
                        .iter()
                        .map(|reason| reason.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                    track
                        .end_reasons
                        .iter()
                        .map(|reason| reason.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                ),
                KnowledgeState::Known,
                "derived",
                &[track.identity, tracks.report_digest],
            );
        }

        match &native.analysis {
            OnvifAnalysisResult::Tracks => {}
            OnvifAnalysisResult::Lifecycle {
                report,
                documents,
                documents_digest,
            } => {
                for (index, document) in documents.iter().enumerate() {
                    push(
                        &mut rows,
                        format!("lifecycle-document:{index}"),
                        format!(
                            "Lifecycle interpretation disposition: source_ordinal={}, identity={}, root={}, document_index={}, xml_digest={}, source_bytes={}, parser_generation={}, container={:?}, state={}, original_parse_error={}, frame_start={}, frames={}, objects={}, operations={}, references={}, unsupported_sections={}, uninterpreted_frames={}. Skipped or rejected input remains explicit and supplies no fabricated observations.",
                            document.source_ordinal,
                            document.pin.identity(),
                            document.pin.root(),
                            ordinal(document.document_index),
                            digest(document.source_digest),
                            document.source_bytes,
                            document.parser_generation,
                            document.format,
                            document.state.as_str(),
                            document.original_parse_error.unwrap_or("none"),
                            document.frame_start,
                            document.frames,
                            document.objects,
                            document.operations,
                            document.references,
                            document.unsupported_sections,
                            document.uninterpreted_frames
                        ),
                        KnowledgeState::Known,
                        "derived",
                        &[document.pin.root(), *documents_digest],
                    );
                }
                for (index, operation) in report.operations.iter().enumerate() {
                    push(
                        &mut rows,
                        format!("lifecycle-operation:{index}"),
                        format!(
                            "Vendor lifecycle declaration: identity={}, frame_ordinal={}, operation_index={}, tree_child_index={}, kind={}, support_state={}, from_endpoints={}, to_endpoints={}, unsupported_extensions={}. Record support does not prove physical identity and never joins frozen tracklets.",
                            operation.identity,
                            operation.frame_ordinal,
                            operation.operation_index,
                            operation.tree_child_index,
                            operation.kind.as_str(),
                            operation.state.as_str(),
                            operation.from.len(),
                            operation.to.len(),
                            operation.unsupported_extensions
                        ),
                        support_state(operation.state),
                        "vendor_claimed",
                        &[operation.identity, report.report_digest],
                    );
                    for (side, endpoints) in [("from", &operation.from), ("to", &operation.to)] {
                        for (endpoint_index, endpoint) in endpoints.iter().enumerate() {
                            push(
                                &mut rows,
                                format!("lifecycle-endpoint:{index}:{side}:{endpoint_index}"),
                                format!(
                                    "Lifecycle endpoint: operation={}, side={side}, endpoint_index={endpoint_index}, support_state={}, integer_id_present={}, uuid_present={}, unsupported_extensions={}, observed_references={}, issues=[{}]. Integer and UUID values are redacted; UUIDs are never matched.",
                                    operation.identity,
                                    endpoint.state.as_str(),
                                    endpoint.reference.object_id.is_some(),
                                    endpoint.reference.uuid.is_some(),
                                    endpoint.reference.unsupported_extensions,
                                    endpoint.observations.len(),
                                    endpoint
                                        .issues
                                        .iter()
                                        .map(|issue| issue.as_str())
                                        .collect::<Vec<_>>()
                                        .join(",")
                                ),
                                support_state(endpoint.state),
                                "derived",
                                &[operation.identity, report.report_digest],
                            );
                            for (reference_index, reference) in
                                endpoint.observations.iter().enumerate()
                            {
                                push(
                                    &mut rows,
                                    format!(
                                        "lifecycle-support:{index}:{side}:{endpoint_index}:{reference_index}"
                                    ),
                                    format!(
                                        "Exact original support for lifecycle operation={}, side={side}, endpoint_index={endpoint_index}: {}.",
                                        operation.identity,
                                        occurrence(reference)
                                    ),
                                    KnowledgeState::Known,
                                    "derived",
                                    &[
                                        reference.occurrence_identity,
                                        reference.tracklet_identity,
                                        report.report_digest,
                                    ],
                                );
                            }
                        }
                    }
                }
                for (index, behaviour) in report.behaviours.iter().enumerate() {
                    push(
                        &mut rows,
                        format!("lifecycle-behaviour:{index}"),
                        format!(
                            "Vendor Behaviour declaration: identity={}, {}, frame_child_index={}, idle={}, removed={}, support_state={}, integer_id_present={}, uuid_present={}, reference_unsupported_extensions={}, unsupported_extensions={}, issues=[{}]. Idle and Removed remain distinct vendor claims, without a physical motion or absence conclusion. UUIDs are never matched or disclosed.",
                            behaviour.identity,
                            occurrence(&behaviour.occurrence),
                            behaviour.frame_child_index,
                            behaviour.idle,
                            behaviour.removed,
                            behaviour.state.as_str(),
                            behaviour.reference.object_id.is_some(),
                            behaviour.reference.uuid.is_some(),
                            behaviour.reference.unsupported_extensions,
                            behaviour.unsupported_extensions,
                            behaviour
                                .issues
                                .iter()
                                .map(|issue| issue.as_str())
                                .collect::<Vec<_>>()
                                .join(",")
                        ),
                        support_state(behaviour.state),
                        "vendor_claimed",
                        &[
                            behaviour.identity,
                            behaviour.occurrence.occurrence_identity,
                            report.report_digest,
                        ],
                    );
                }
                for (index, reuse) in report.reuses.iter().enumerate() {
                    push(
                        &mut rows,
                        format!("lifecycle-reuse:{index}"),
                        format!(
                            "Conflicting vendor local-ID reuse: identity={}, deleted_by_operation={}, deleted_at_frame={}, {}. A prior Delete and later occurrence conflict under this bounded interpretation; no entity identity is inferred.",
                            reuse.identity,
                            reuse.deleted_by_operation,
                            reuse.deleted_at_frame,
                            occurrence(&reuse.occurrence)
                        ),
                        KnowledgeState::Conflicted,
                        "derived",
                        &[
                            reuse.identity,
                            reuse.deleted_by_operation,
                            reuse.occurrence.occurrence_identity,
                            report.report_digest,
                        ],
                    );
                }
            }
            OnvifAnalysisResult::Zones(report) => {
                for (index, zone) in report.policy.zones.iter().enumerate() {
                    push(
                        &mut rows,
                        format!("zone-policy:{index}"),
                        format!(
                            "Explicit operator zone: index={index}, id={}, coordinates=raw_vendor_object_millionths, scope={}, module_digest={}, frame_transform_digest={}, object_transform_digest={}, min=[{},{}], max=[{},{}], margin={}, policy_digest={}. These are declared raw coordinates, without image, pixel or world calibration.",
                            zone.id,
                            zone.scope,
                            zone.module_digest,
                            zone.frame_transform_digest,
                            zone.object_transform_digest,
                            zone.min[0],
                            zone.min[1],
                            zone.max[0],
                            zone.max[1],
                            zone.margin,
                            report.policy_digest
                        ),
                        KnowledgeState::Known,
                        "derived",
                        &[report.policy_digest],
                    );
                }
                for (index, cell) in report.cells.iter().enumerate() {
                    push(
                        &mut rows,
                        format!("zone-cell:{index}"),
                        format!(
                            "Derived comparison of vendor box and operator zone: zone_index={}, occurrence_index={}, frame_ordinal={}, relation={}, unavailable_reason={}. The complete occurrence/zone matrix includes uncertainty; unavailable is never outside or absence.",
                            cell.zone_index,
                            cell.occurrence_index,
                            cell.frame_ordinal,
                            cell.relation.as_str(),
                            cell.reason.map_or("none", |reason| reason.as_str())
                        ),
                        match cell.relation {
                            ZoneRelation::Unavailable => KnowledgeState::NotObservable,
                            ZoneRelation::Boundary => KnowledgeState::Unknown,
                            _ => KnowledgeState::Known,
                        },
                        "derived",
                        &[report.report_digest, tracks.report_digest],
                    );
                }
                for (index, sample) in report.frame_samples.iter().enumerate() {
                    push(
                        &mut rows,
                        format!("zone-frame:{index}"),
                        format!(
                            "Complete vendor-frame zone summary: zone_index={}, frame_ordinal={}, basis_unavailable={}, inside={}, outside={}, boundary={}, unavailable={}. Zero observations certify no physical occupancy or absence.",
                            sample.zone_index,
                            sample.frame_ordinal,
                            sample
                                .basis_unavailable
                                .map_or("none", |reason| reason.as_str()),
                            sample.inside,
                            sample.outside,
                            sample.boundary,
                            sample.unavailable
                        ),
                        if sample.basis_unavailable.is_some() {
                            KnowledgeState::NotObservable
                        } else {
                            KnowledgeState::Known
                        },
                        "derived",
                        &[report.report_digest],
                    );
                }
                for (index, transition) in report.transitions.iter().enumerate() {
                    push(
                        &mut rows,
                        format!("zone-transition:{index}"),
                        format!(
                            "Derived change between vendor observations: zone_index={}, tracklet_identity={}, kind={}, previous_occurrence={}, occurrence={}. No path, crossing time, dwell, physical motion or continuity beyond the frozen tracklet is inferred.",
                            transition.zone_index,
                            transition.tracklet_identity,
                            transition.kind.as_str(),
                            ordinal(transition.previous_occurrence),
                            transition.occurrence
                        ),
                        if transition.kind == ZoneTransitionKind::ObservationInterrupted {
                            KnowledgeState::NotObservable
                        } else {
                            KnowledgeState::Known
                        },
                        "derived",
                        &[transition.tracklet_identity, report.report_digest],
                    );
                }
            }
        }
        EnvelopeEpistemic {
            propositions: rows,
            assumptions: vec![
                "The principal is an operator-supplied audit label, not authentication; no effect, disclosure expansion or source hydration authority is conferred.".to_owned(),
                "Original source custody and current deletion restrictions are verified; vendor timestamps, ObjectId relationships, geometry and behaviour remain claims from the source.".to_owned(),
                "All selected semantic rows are present. Original XML, packet bytes, untyped extension values and lexical vendor values are intentionally not disclosed; their source references remain exact.".to_owned(),
            ],
            invalidators: vec!["Any authority/effect prefix, deletion restriction, source/root/closure, frozen interpretation, input ordering, policy or allowance change requires a new complete query.".to_owned()],
        }
    }

    /// Exhaustion of explicitly pinned metadata, never physical-world completeness.
    #[must_use]
    pub fn coverage(&self) -> EnvelopeCoverage {
        EnvelopeCoverage {
            authorized_domain: vec!["the ordered exact ONVIF XML/RTP source pins under the current deployment's read and deletion restrictions".to_owned()],
            observed_domain: vec!["all source dispositions, original frame/object handles, conservative grouping barriers and selected bounded analysis rows".to_owned()],
            not_observable_domain: vec!["physical identity, activity, occupancy, coverage and absence; independent corroboration, trustworthy capture clocks, calibrated geometry, other sources and live device state".to_owned()],
            omitted_count: 0,
            omission_reasons: vec!["Original source bytes, lexical vendor values, UUID values and opaque extension payloads are outside this redacted semantic projection; no selected semantic row was truncated.".to_owned()],
            stop_reason: "explicit_pinned_sources_exhausted".to_owned(),
        }
    }
}
