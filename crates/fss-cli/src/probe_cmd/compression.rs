#![forbid(unsafe_code)]
//! Lossless packaging witness for the admitted cognitive projection, not raw source compression.

use std::collections::BTreeSet;

use fss_core::{
    CanonicalEncode, Completeness, CompressionCompleteness, CompressionLossClass,
    CompressionStopReason, CompressionTransform, CompressionTransformKind, ContextItem,
    CriticalPreservation, EnvelopeCoverage, EnvelopeEpistemic, KnowledgeState,
    SemanticCompressionReceipt, SemanticContextPack, SemanticContextPackPublishParams,
};
use fss_reference::deployment_session::probe::ProbeContext;

use super::ProbeArgs;
use crate::agent_json::{self, EvidenceHandle};
use crate::orient_cmd::request_identity;

/// Every supplied cognitive item is included. Source selection and native/H0 omissions retain
/// their own explicit qualifications; this receipt never claims to reconstruct those sources.
pub(super) fn package(
    args: &ProbeArgs,
    context: &ProbeContext,
    epistemic: &EnvelopeEpistemic,
    coverage: &EnvelopeCoverage,
    handles: &[EvidenceHandle],
    warnings: &[String],
) -> Result<(SemanticContextPack, SemanticCompressionReceipt), Box<dyn std::error::Error>> {
    let capsule = context.oriented.orientation.capsule();
    let frame = capsule.frame.frame_digest()?;
    let basis = BTreeSet::from([frame.to_text()]);
    let mut items = Vec::new();
    for proposition in &epistemic.propositions {
        let mut evidence: BTreeSet<_> = proposition.evidence.iter().cloned().collect();
        // Provenance is an orthogonal field in the cognitive contract, not an observation claim.
        evidence.insert(format!("provenance:{}", proposition.provenance));
        items.push(ContextItem {
            item_id: proposition.id.clone(),
            kind: "admitted_cognitive_proposition".to_owned(),
            epistemic_state: proposition.state,
            content: proposition.statement.clone(),
            basis: evidence,
            expansion_handles: BTreeSet::new(),
        });
    }
    let mut append = |kind: &str, values: &[String], state: KnowledgeState| {
        for (index, text) in values.iter().enumerate() {
            items.push(ContextItem {
                item_id: format!("probe-pack:{kind}:{index}"),
                kind: kind.to_owned(),
                epistemic_state: state,
                content: text.clone(),
                basis: basis.clone(),
                expansion_handles: BTreeSet::new(),
            });
        }
    };
    append(
        "recorded_assumption",
        &epistemic.assumptions,
        KnowledgeState::Unknown,
    );
    append(
        "recorded_invalidation",
        &epistemic.invalidators,
        KnowledgeState::Known,
    );
    append("protected_warning", warnings, KnowledgeState::Known);
    append(
        "protected_contradiction",
        &context.oriented.orientation.contradictions,
        KnowledgeState::Conflicted,
    );
    for (kind, values) in [
        ("authorized_projection_scope", &coverage.authorized_domain),
        ("observed_projection_scope", &coverage.observed_domain),
        ("not_observable_scope", &coverage.not_observable_domain),
        ("source_projection_omission", &coverage.omission_reasons),
    ] {
        append(kind, values, KnowledgeState::Known);
    }
    append(
        "projection_stop",
        &[format!(
            "{}; source-projection omitted count {} (not a count of items omitted by this packaging step)",
            coverage.stop_reason, coverage.omitted_count
        )],
        KnowledgeState::Known,
    );
    append(
        "unresolved_obligation",
        &capsule
            .obligations
            .iter()
            .map(|id| id.as_str().to_owned())
            .collect::<Vec<_>>(),
        KnowledgeState::Known,
    );
    for (index, handle) in handles.iter().enumerate() {
        items.push(ContextItem {
            item_id: format!("probe-pack:custody-handle:{index}"),
            kind: "admitted_custody_metadata".to_owned(),
            epistemic_state: KnowledgeState::Known,
            content: format!(
                "Handle {}; kind {}; level {}; permitted levels {:?}; privacy {}; availability {}; required capability {:?}; quoted cost {}",
                handle.handle_id,
                handle.kind,
                handle.hydration,
                handle.allowed_hydration,
                handle.privacy_class,
                handle.availability,
                handle.required_capability,
                agent_json::budget(&handle.estimated_cost),
            ),
            basis: BTreeSet::from([handle.object_digest.to_text()]),
            expansion_handles: BTreeSet::new(),
        });
    }
    let input = request_identity("fss.cli.retained_probe_context.v1", |e| {
        e.digest(args.digest());
        e.digest(frame);
        e.digest(context.oriented.journal_root);
        e.u64(items.len() as u64);
        for item in &items {
            item.encode_canonical(e);
        }
    });
    let pack = SemanticContextPack::publish(SemanticContextPackPublishParams {
        pack_id: format!("context-pack:probe:{input}"),
        contract_basis: capsule.contract_basis.clone(),
        mission_id: capsule.mission_id.clone(),
        session_id: capsule.session_id.clone(),
        view_id: args.request.view.id().to_owned(),
        anchor: capsule.anchor.clone(),
        situation_fingerprint: frame,
        items,
        compression_receipt_id: format!("compression:probe:{input}"),
        continuation: None,
        created_at: capsule.created_at,
    })?;
    let selected_classes: BTreeSet<_> = pack.items.iter().map(|item| item.kind.clone()).collect();
    let receipt = SemanticCompressionReceipt {
        receipt_id: pack.compression_receipt_id.clone(),
        source_anchor: pack.anchor.clone(),
        view_id: pack.view_id.clone(),
        target_tokens: u64::from(args.request.view.maximum_tokens()),
        completeness: selected_classes
            .iter()
            .map(|domain| CompressionCompleteness {
                domain: domain.clone(),
                state: Completeness::Complete,
                omitted_count: 0,
            })
            .collect(),
        selected_classes,
        omitted_classes: BTreeSet::new(),
        transforms: vec![CompressionTransform {
            kind: CompressionTransformKind::Select,
            scope: "already-admitted cognitive propositions, protected metadata and custody handles".to_owned(),
            loss_class: CompressionLossClass::Lossless,
            details: Some("Every input item is included; no ranking, deduplication or omission. This packaging receipt does not certify the earlier native/source projection or recover upstream omissions.".to_owned()),
        }],
        critical_preservation: CriticalPreservation {
            known_critical_items: pack.items.len() as u64,
            omitted_critical_items: 0,
            omitted_invalidations: 0,
            omitted_contradictions: 0,
        },
        actual_tokens: pack.token_count,
        actual_bytes: pack.encoded_bytes(),
        expansion_handles: Vec::new(),
        selection_frontier_digest: Some(input),
        stop_reason: CompressionStopReason::Complete,
        output_digest: pack.pack_digest,
    };
    receipt.validate_for(&pack)?;
    Ok((pack, receipt))
}
