//! End-to-end deterministic virtual capture through custody and authority publication.

use fss_core::{
    BatchId, CanonicalEncode, CaptureInterval, ContentDigest, EvidenceDelta, LedgerAnchor,
    ObjectId, Plane,
};
use fss_ledger::DurableReferenceLedger;
use fss_object::{InMemoryObjectStore, ObjectManifest};
use fss_publication::AuthorityPublisher;

use crate::{
    DeliveryContinuity, DeliveryPacket, DeliveryPlan, DeliveryTrace, ReferenceError, SourcePacket,
    SourceTrace, VirtualCameraSpec, generate_source,
};

/// Receipt binding virtual source truth, delivery truth, object closure, and authority history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceCaptureReceipt {
    /// Root manifest for the complete capture object graph.
    pub capture_root: ContentDigest,
    /// Root manifest for immutable source packet custody.
    pub source_root: ContentDigest,
    /// Root manifest for delivered transport bytes and ordered trace.
    pub delivery_root: ContentDigest,
    /// Exact retained continuity/integrity witness object.
    pub continuity_digest: ContentDigest,
    /// Canonical authority anchor after publication.
    pub authority_anchor: LedgerAnchor,
    /// Number of objects reachable from the capture root.
    pub closure_object_count: usize,
    /// Number of source packets.
    pub source_packet_count: usize,
    /// Number of delivered copies.
    pub delivered_packet_count: usize,
}

/// Complete reference capture retained for deterministic tests and replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceCapture {
    /// Publication receipt.
    pub receipt: ReferenceCaptureReceipt,
    /// Exact packet stream before delivery faults.
    pub source_packets: Vec<SourcePacket>,
    /// Exact packet copies after delivery faults.
    pub delivery_packets: Vec<DeliveryPacket>,
    /// Explicit loss/duplicate/reorder/corruption witness.
    pub continuity: DeliveryContinuity,
}

/// Executes one deterministic virtual capture.
///
/// The delivery plan is validated before object mutation. Source bytes are then retained first,
/// followed by transport observations and their ordered trace. The capture root publishes only
/// after every referenced object is verified. Finally the authority ledger names that exact root
/// through `fss-publication`.
pub fn run_reference_capture(
    spec: &VirtualCameraSpec,
    plan: &DeliveryPlan,
    objects: &mut InMemoryObjectStore,
    ledger: &mut DurableReferenceLedger,
) -> Result<ReferenceCapture, ReferenceError> {
    spec.validate()?;
    plan.validate_against(spec.packet_count)?;
    let source_packets = generate_source(spec)?;

    for packet in &source_packets {
        let stored = objects.put_verified(&packet.bytes)?;
        if stored != packet.digest {
            return Err(ReferenceError::DigestMismatch);
        }
    }
    let source_trace = SourceTrace::from_packets(spec, &source_packets);
    let source_trace_digest = objects.put_verified(&source_trace.canonical_bytes())?;
    let source_manifest = ObjectManifest::new(
        "virtual-source-session",
        source_packets.iter().map(|packet| packet.digest),
        Some(source_trace_digest),
    )?;
    let source_root = objects.publish_manifest(source_manifest)?.root;

    let (delivery_packets, continuity) = plan.apply(&source_packets)?;
    for delivery in &delivery_packets {
        let stored = objects.put_verified(&delivery.bytes)?;
        if stored != delivery.observed_digest {
            return Err(ReferenceError::DigestMismatch);
        }
    }
    let delivery_trace = DeliveryTrace::from_packets(&delivery_packets);
    let delivery_trace_digest = objects.put_verified(&delivery_trace.canonical_bytes())?;
    let delivery_manifest = ObjectManifest::new(
        "virtual-delivery-session",
        delivery_packets
            .iter()
            .map(|delivery| delivery.observed_digest),
        Some(delivery_trace_digest),
    )?;
    let delivery_root = objects.publish_manifest(delivery_manifest)?.root;

    let continuity_digest = objects.put_verified(&continuity.canonical_bytes())?;
    let capture_manifest = ObjectManifest::new(
        "virtual-capture-session",
        [source_root, delivery_root],
        Some(continuity_digest),
    )?;
    let capture_root = objects.publish_manifest(capture_manifest)?.root;
    let closure_object_count = objects.verify_closure(capture_root)?;

    let first = source_packets
        .first()
        .ok_or(ReferenceError::InvalidSpec("packet_count"))?;
    let last = source_packets
        .last()
        .ok_or(ReferenceError::InvalidSpec("packet_count"))?;
    let validity = CaptureInterval::new(first.capture.earliest, last.capture.latest)?;

    let capture_identity = ContentDigest::sha256(spec.capture_id.as_str().as_bytes());
    let delta = EvidenceDelta {
        delta_id: format!("delta:virtual-capture:{capture_identity}"),
        family: "virtual_capture".to_owned(),
        object_id: ObjectId::parse(format!("object:virtual-capture:{capture_identity}"))?,
        prior_generation: None,
        new_generation: 1,
        validity,
        plane: Plane::Authority,
        payload_digest: capture_root,
        witness_digest: Some(continuity_digest),
        operation_id: None,
    };

    let authority_anchor = {
        let mut publisher = AuthorityPublisher::new(objects, ledger);
        let batch = publisher.prepare_batch(
            BatchId::parse(format!("batch:virtual-capture:{capture_identity}"))?,
            vec![delta],
            [capture_root],
        )?;
        publisher.append(batch)?
    };

    Ok(ReferenceCapture {
        receipt: ReferenceCaptureReceipt {
            capture_root,
            source_root,
            delivery_root,
            continuity_digest,
            authority_anchor,
            closure_object_count,
            source_packet_count: source_packets.len(),
            delivered_packet_count: delivery_packets.len(),
        },
        source_packets,
        delivery_packets,
        continuity,
    })
}
