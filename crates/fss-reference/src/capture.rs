//! End-to-end deterministic virtual capture through custody and authority publication.

use std::collections::BTreeMap;

use fss_core::{
    BatchId, CanonicalEncode, CaptureInterval, ContentDigest, EvidenceDelta, LedgerAnchor,
    ObjectId, Plane,
};
use fss_ledger::DurableReferenceLedger;
use fss_object::{InMemoryObjectStore, ObjectManifest};
use fss_publication::AuthorityPublisher;

use crate::{
    DeliveryContinuity, DeliveryPacket, DeliveryPlan, DeliveryTrace, ReferenceError, SourcePacket,
    SourceTrace, VirtualCameraSpec, VirtualClock, VirtualSource,
};

/// Typed source-level fault schedule that can be injected into virtual camera capture.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SourceFaultSchedule {
    /// Injected indeterminate read faults indexed by 1-based packet sequence.
    pub indeterminate: BTreeMap<u64, String>,
    /// Injected unobservable read faults indexed by 1-based packet sequence.
    pub unobservable: BTreeMap<u64, String>,
    /// Injected operational execution failures indexed by 1-based packet sequence.
    pub execution_failures: BTreeMap<u64, String>,
}

impl SourceFaultSchedule {
    /// Creates an empty fault schedule.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Injects an indeterminate read fault at 1-based `sequence`.
    pub fn inject_indeterminate(&mut self, sequence: u64, reason: impl Into<String>) {
        self.indeterminate.insert(sequence, reason.into());
    }

    /// Injects an unobservable read fault at 1-based `sequence`.
    pub fn inject_unobservable(&mut self, sequence: u64, reason: impl Into<String>) {
        self.unobservable.insert(sequence, reason.into());
    }

    /// Injects an operational execution failure at 1-based `sequence`.
    pub fn inject_execution_failure(&mut self, sequence: u64, reason: impl Into<String>) {
        self.execution_failures.insert(sequence, reason.into());
    }

    /// Applies this fault schedule to a mutable virtual source instance.
    pub fn apply_to(&self, source: &mut VirtualSource) {
        for (&seq, reason) in &self.indeterminate {
            source.inject_indeterminate_read(seq, reason.clone());
        }
        for (&seq, reason) in &self.unobservable {
            source.inject_unobservable_read(seq, reason.clone());
        }
        for (&seq, reason) in &self.execution_failures {
            source.inject_execution_failure(seq, reason.clone());
        }
    }
}

/// Provenance metadata emitted upon reference capture completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceCaptureReceipt {
    /// Merkle root of the capture session manifest.
    pub capture_root: ContentDigest,
    /// Merkle root of raw retained source bytes.
    pub source_root: ContentDigest,
    /// Merkle root of observed delivery packets.
    pub delivery_root: ContentDigest,
    /// Content digest of the transport continuity witness.
    pub continuity_digest: ContentDigest,
    /// Anchor published into authority storage.
    pub authority_anchor: LedgerAnchor,
    /// Total objects reachable from the capture root.
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
    /// Mutated virtual clock carrying time progression after capture.
    pub clock: VirtualClock,
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
    let mut clock = VirtualClock::from_spec(spec);
    run_reference_capture_with_clock(spec, &mut clock, None, plan, objects, ledger)
}

/// Executes one deterministic virtual capture driven by an explicit [`VirtualClock`] time authority.
///
/// If `source_faults` are provided, they are injected into the source before packet generation.
/// Mutates `clock` in place to reflect the advanced timeline and PRNG state at the end of the capture.
pub fn run_reference_capture_with_clock(
    spec: &VirtualCameraSpec,
    clock: &mut VirtualClock,
    source_faults: Option<&SourceFaultSchedule>,
    plan: &DeliveryPlan,
    objects: &mut InMemoryObjectStore,
    ledger: &mut DurableReferenceLedger,
) -> Result<ReferenceCapture, ReferenceError> {
    let mut source = VirtualSource::with_clock(spec.clone(), clock.clone())?;
    if let Some(faults) = source_faults {
        faults.apply_to(&mut source);
    }
    let capture = run_reference_capture_with_source(&mut source, plan, objects, ledger)?;
    *clock = source.into_clock();
    Ok(capture)
}

/// Executes one deterministic virtual capture driven by an explicit [`VirtualSource`].
pub fn run_reference_capture_with_source(
    source: &mut VirtualSource,
    plan: &DeliveryPlan,
    objects: &mut InMemoryObjectStore,
    ledger: &mut DurableReferenceLedger,
) -> Result<ReferenceCapture, ReferenceError> {
    let spec = source.spec().clone();
    spec.validate()?;
    plan.validate_against(spec.packet_count)?;
    let source_packets = source.generate_packets()?;

    for packet in &source_packets {
        let stored = objects.put_verified(&packet.bytes)?;
        if stored != packet.digest {
            return Err(ReferenceError::DigestMismatch);
        }
    }
    let source_trace = SourceTrace::from_packets(&spec, &source_packets);
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
    let mut unique_delivery_digests: Vec<_> = delivery_packets
        .iter()
        .map(|delivery| delivery.observed_digest)
        .collect();
    unique_delivery_digests.sort_unstable();
    unique_delivery_digests.dedup();
    let delivery_manifest = ObjectManifest::new(
        "virtual-delivery-session",
        unique_delivery_digests,
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
        clock: source.clock().clone(),
    })
}
