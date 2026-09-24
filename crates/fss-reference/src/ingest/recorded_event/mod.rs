#![forbid(unsafe_code)]
//! Durable unresolved events from exact retained detector/association reports.
//!
//! This boundary records candidates, not calibrated presence, physical identity, arrival,
//! departure, or alert authority. It replays the report, roots its complete provenance, then
//! delegates event publication to the deployment's existing guarded event owner.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use fss_core::event::EventDecodeError;
use fss_core::{
    BatchId, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaptureInterval,
    ContentDigest, ContractError, DecisionPath, EventEvidence, EventHypothesis, EventId, EventKind,
    EventState, EvidenceClass, EvidenceEdgeRelation, LedgerAnchor, ObjectId, Plane,
    ProbabilityInterval,
};
use fss_object::{ObjectError, ObjectManifest, SpoolError};
use fss_publication::{LocalPublicationError, SlotName};

use super::analysis::{AnalysisBudget, AnalysisError, AnalysisLimits, AnalysisReport};
use crate::{
    ReferenceDeployment, ReferenceError, ReferencePolicyAction, ReferencePolicyDecision, ReplayCx,
};

/// Event schema permits 64 model receipts; this boundary never silently drops a frame.
pub const MAX_RECORDED_EVENT_FRAMES: usize = 64;
/// Failure injection / cancellation boundary after provenance, before event authority.
pub const STAGE_RECORDED_EVENT_COMMIT: &str = "recorded_event:commit";
const POLICY: &[u8] =
    b"fss.recorded_event_policy.v1:uncalibrated:unclassified:indeterminate:hold:full-prefix-only";
const PROOF_DOMAIN: &str = "fss.recorded_event_provenance.v1";

/// An event, source, replay, capacity, or optimistic-publication refusal.
#[derive(Debug)]
pub enum RecordedEventError {
    /// No observed row in the report supports the selected local track hypothesis.
    TrackUnavailable,
    /// The requested event does not exist in this deployment.
    Unavailable,
    /// A selected report or encoded object exceeds this boundary's hard ceiling.
    Limit,
    /// Stored provenance or canonical event bytes disagree.
    Mismatch,
    /// The event was independently changed, or new input rewrites/drops earlier history.
    Conflict,
    /// The exact proposal approved by the operator is no longer the publishable proposal.
    StaleProposal,
    /// Owner cancellation; committed provenance can remain, but no event success is invented.
    Cancelled,
    /// Existing analysis owner refused source recovery, detection, or association.
    Analysis(AnalysisError),
    /// Shared canonical validation failed.
    Contract(ContractError),
    /// The event owner's schema or lineage rules refused the revision.
    Event(EventDecodeError),
    /// Guarded deployment publication failed.
    Reference(ReferenceError),
    /// Object graph construction failed.
    Object(ObjectError),
    /// Root-last publication failed.
    Publication(LocalPublicationError),
    /// Retained custody could not be read or verified.
    Spool(SpoolError),
}
impl fmt::Display for RecordedEventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TrackUnavailable => "selected track has no observed row in this report",
            Self::Unavailable => "recorded event unavailable",
            Self::Limit => "recorded event bound exceeded",
            Self::Mismatch => "recorded event provenance mismatch",
            Self::Conflict => {
                "recorded event changed or analysis history is not an exact extension"
            }
            Self::StaleProposal => "recorded event proposal changed; prepare and review again",
            Self::Cancelled => "recorded event owner cancelled",
            Self::Analysis(_) => "recorded event source analysis refused",
            Self::Contract(_) | Self::Event(_) => "recorded event contract refused",
            Self::Reference(_) | Self::Object(_) | Self::Publication(_) | Self::Spool(_) => {
                "recorded event storage refused"
            }
        })
    }
}
impl Error for RecordedEventError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Analysis(e) => Some(e),
            Self::Contract(e) => Some(e),
            Self::Event(e) => Some(e),
            Self::Reference(e) => Some(e),
            Self::Object(e) => Some(e),
            Self::Publication(e) => Some(e),
            Self::Spool(e) => Some(e),
            _ => None,
        }
    }
}
macro_rules! conversion {
    ($source:ty, $variant:ident) => {
        impl From<$source> for RecordedEventError {
            fn from(e: $source) -> Self {
                Self::$variant(e)
            }
        }
    };
}
conversion!(AnalysisError, Analysis);
conversion!(ContractError, Contract);
conversion!(EventDecodeError, Event);
conversion!(ReferenceError, Reference);
conversion!(ObjectError, Object);
conversion!(LocalPublicationError, Publication);
conversion!(SpoolError, Spool);
type Result<T> = std::result::Result<T, RecordedEventError>;

fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<()> {
    cx.checkpoint(stage)
        .map_err(|_| RecordedEventError::Cancelled)
}
fn hex(d: ContentDigest) -> String {
    d.bytes().iter().map(|b| format!("{b:02x}")).collect()
}
fn event_id(track: ContentDigest) -> Result<EventId> {
    Ok(EventId::parse(format!("event:recorded:{}", hex(track)))?)
}
fn proof_slot(track: ContentDigest, report: ContentDigest) -> Result<SlotName> {
    let mut e = CanonicalEncoder::new();
    e.text(PROOF_DOMAIN);
    e.digest(track);
    e.digest(report);
    SlotName::parse(&format!(
        "re-{}",
        hex(ContentDigest::sha256(&e.finish_checked()?))
    ))
    .map_err(|_| RecordedEventError::Mismatch)
}
fn bounded_limits(limits: &AnalysisLimits) -> AnalysisLimits {
    let mut limits = limits.clone();
    limits.maximum_frames = limits.maximum_frames.min(MAX_RECORDED_EVENT_FRAMES);
    limits
}
fn read_verified(deployment: &ReferenceDeployment, digest: ContentDigest) -> Result<Vec<u8>> {
    let bytes = deployment.publisher().spool().read(digest)?;
    if ContentDigest::sha256(&bytes) != digest {
        return Err(RecordedEventError::Mismatch);
    }
    Ok(bytes)
}

#[derive(Clone, Debug)]
struct Provenance {
    slot: SlotName,
    manifest: ObjectManifest,
    objects: BTreeMap<ContentDigest, Vec<u8>>,
    event: EventHypothesis,
}
fn insert(objects: &mut BTreeMap<ContentDigest, Vec<u8>>, bytes: Vec<u8>) -> ContentDigest {
    let digest = ContentDigest::sha256(&bytes);
    objects.insert(digest, bytes);
    digest
}

fn provenance(
    deployment: &ReferenceDeployment,
    report: &AnalysisReport,
    track: ContentDigest,
    cx: &ReplayCx,
) -> Result<Provenance> {
    if report.observations().len() > MAX_RECORDED_EVENT_FRAMES {
        return Err(RecordedEventError::Limit);
    }
    let mut objects = BTreeMap::new();
    insert(&mut objects, report.encoded().to_vec());
    let policy = insert(&mut objects, POLICY.to_vec());
    let mut children = BTreeSet::new();
    let mut receipts = BTreeSet::new();
    let mut evidence = Vec::new();
    let mut interval: Option<CaptureInterval> = None;
    let mut observed = false;
    for entry in report.observations() {
        checkpoint(cx, "recorded_event:provenance")?;
        let detection = entry.detection();
        let update = entry.tracking();
        // The report owner already revalidated this exact run. Retain its actual receipt and
        // complete graph, not a relabeled detector report in the model-receipt field.
        let target = BatchId::parse(format!("batch:model-run:{}", hex(detection.run_identity())))?;
        let batch = deployment
            .ledger()
            .batches()
            .iter()
            .find(|b| b.batch_id == target)
            .ok_or(RecordedEventError::Mismatch)?;
        if batch.deltas.len() != 1 {
            return Err(RecordedEventError::Mismatch);
        }
        let delta = &batch.deltas[0];
        if delta.family != "model_invocation_receipt" || delta.plane != Plane::Cognition {
            return Err(RecordedEventError::Mismatch);
        }
        children.insert(delta.witness_digest.ok_or(RecordedEventError::Mismatch)?);
        children.insert(delta.payload_digest);
        receipts.insert(delta.payload_digest);
        children.insert(detection.frame_root());
        let detection_bytes = detection.encoded().map_err(AnalysisError::from)?;
        insert(&mut objects, detection_bytes);
        let update_digest = insert(&mut objects, update.encoded().map_err(AnalysisError::from)?);
        let capsule_digest = insert(&mut objects, update.capsule.try_canonical_bytes()?);
        let sensor_digest = insert(
            &mut objects,
            update.capsule.sensor_id.as_str().as_bytes().to_vec(),
        );
        let selected = update.tracks.iter().find(|t| t.id == track);
        let retired = update.retired.iter().any(|t| t.id == track);
        if selected.is_some() || retired {
            observed |= selected.is_some_and(|t| t.observed_row.is_some());
            let window = update.capsule.capture;
            interval = Some(match interval {
                Some(old) => CaptureInterval::new(
                    old.earliest.min(window.earliest),
                    old.latest.max(window.latest),
                )?,
                None => window,
            });
            evidence.push(EventEvidence {
                digest: update_digest,
                class: EvidenceClass::Derived,
                failure_domain: format!("recorded-sensor:{}", hex(sensor_digest)),
                supports: false,
                relation: EvidenceEdgeRelation::DerivedFrom,
                capsule_digest: Some(capsule_digest),
                identity_digest: Some(sensor_digest),
            });
        }
    }
    if !observed {
        return Err(RecordedEventError::TrackUnavailable);
    }
    let interval = interval.ok_or(RecordedEventError::TrackUnavailable)?;
    let mut e = CanonicalEncoder::new();
    e.bytes(b"FSSREVT1");
    e.u32(1);
    e.text(PROOF_DOMAIN);
    e.digest(policy);
    e.digest(track);
    e.digest(report.digest());
    let metadata = insert(&mut objects, e.finish_checked()?);
    children.extend(objects.keys().copied());
    children.remove(&metadata);
    let slot = proof_slot(track, report.digest())?;
    let manifest = ObjectManifest::new(slot.as_str(), children, Some(metadata))?;
    evidence.sort_by_key(|e| e.digest);
    let event = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_owned(), event_id: event_id(track)?, revision: 1,
        supersedes: None, state: EventState::Indeterminate, kind: EventKind::Unclassified,
        interval, uncertainty_reason: Some("Uncalibrated local association; capture bounds are evidence windows, not physical arrival or departure.".to_owned()),
        zone_ids: Vec::new(), track_ids: vec![hex(track)], probability: ProbabilityInterval::new(0.0, 1.0)?,
        evidence, model_receipts: receipts.into_iter().collect(),
        decision_path: DecisionPath {
            policy_generation: policy, fingerprint: manifest.root(), abstained: true,
            abstention_reason: Some("Retain and investigate. No calibrated physical-presence, identity, absence, corroboration or alert decision is authorized.".to_owned()),
        },
    };
    event.validate()?;
    Ok(Provenance {
        slot,
        manifest,
        objects,
        event,
    })
}

fn event_manifest(event: &EventHypothesis) -> Result<ObjectManifest> {
    Ok(ObjectManifest::new(
        "event-revision",
        event.model_receipts.iter().copied(),
        Some(ContentDigest::sha256(&event.try_canonical_bytes()?)),
    )?)
}

// Read the current event through its authoritative object revision, never an unanchored file.
// Historical revisions are checked with the event owner's full chain verifier.
fn load_event(
    deployment: &ReferenceDeployment,
    id: &EventId,
    cx: &ReplayCx,
) -> Result<Option<(EventHypothesis, ContentDigest, LedgerAnchor)>> {
    let object = ObjectId::parse(format!("object:event:{}", id.as_str()))?;
    let Some(current) = deployment.ledger().current().objects.get(&object) else {
        return Ok(None);
    };
    let mut chain = Vec::new();
    let mut latest = None;
    for batch in deployment.ledger().batches() {
        for delta in &batch.deltas {
            if delta.family != "event_revision" || delta.object_id != object {
                continue;
            }
            checkpoint(cx, "recorded_event:lineage")?;
            if chain.len() >= fss_core::event::MAX_LINEAGE_DEPTH {
                return Err(RecordedEventError::Limit);
            }
            let root_bytes = read_verified(deployment, delta.payload_digest)?;
            let manifest = ObjectManifest::from_canonical_bytes(&root_bytes)?;
            let payload = manifest
                .metadata_digest()
                .ok_or(RecordedEventError::Mismatch)?;
            let bytes = read_verified(deployment, payload)?;
            let event = EventHypothesis::from_canonical_bytes(&bytes)?;
            event.validate()?;
            if event.event_id != *id
                || event.revision != delta.new_generation
                || delta.prior_generation != event.revision.checked_sub(1).filter(|n| *n != 0)
                || delta.plane != Plane::Authority
                || delta.validity != event.interval
                || delta.witness_digest != Some(event.revision_digest())
                || event_manifest(&event)?.canonical_bytes() != root_bytes
                || !batch.children.contains(&delta.payload_digest)
            {
                return Err(RecordedEventError::Mismatch);
            }
            if delta.new_generation == current.generation
                && delta.payload_digest == current.payload_digest
            {
                latest = Some((
                    event.clone(),
                    delta.payload_digest,
                    batch.new_anchor.clone(),
                ));
            }
            chain.push(event);
        }
    }
    EventHypothesis::verify_chain(&chain)?;
    let latest = latest.ok_or(RecordedEventError::Mismatch)?;
    if chain.last() != Some(&latest.0) {
        return Err(RecordedEventError::Mismatch);
    }
    Ok(Some(latest))
}

/// Complete event and reconstruction report recovered from current event authority and custody.
#[derive(Clone, Debug)]
pub struct RecordedEvent {
    event: EventHypothesis,
    root: ContentDigest,
    anchor: LedgerAnchor,
    report: AnalysisReport,
    track: ContentDigest,
}
impl RecordedEvent {
    /// Reopen and independently rebuild the detector/association evidence behind an event.
    /// Original input/model/report export files are unnecessary. A superseding owner decision
    /// outside this narrow unresolved-candidate policy is refused, never silently downgraded.
    pub fn open(
        deployment: &ReferenceDeployment,
        id: &EventId,
        limits: &AnalysisLimits,
        budget: &mut AnalysisBudget,
        cx: &ReplayCx,
    ) -> Result<Self> {
        checkpoint(cx, "recorded_event:open")?;
        let (event, root, anchor) =
            load_event(deployment, id, cx)?.ok_or(RecordedEventError::Unavailable)?;
        if event.decision_path.policy_generation != ContentDigest::sha256(POLICY) {
            return Err(RecordedEventError::Conflict);
        }
        let root_bytes = read_verified(deployment, event.decision_path.fingerprint)?;
        let proof = ObjectManifest::from_canonical_bytes(&root_bytes)?;
        let metadata = proof
            .metadata_digest()
            .ok_or(RecordedEventError::Mismatch)?;
        let bytes = read_verified(deployment, metadata)?;
        if bytes.len() > 1024 {
            return Err(RecordedEventError::Limit);
        }
        let mut d = CanonicalDecoder::new(&bytes);
        if d.bytes()? != b"FSSREVT1"
            || d.u32()? != 1
            || d.text()? != PROOF_DOMAIN
            || d.digest()? != ContentDigest::sha256(POLICY)
        {
            return Err(RecordedEventError::Mismatch);
        }
        let track = d.digest()?;
        let report_digest = d.digest()?;
        d.ensure_finished()?;
        let report_bytes = read_verified(deployment, report_digest)?;
        let report = AnalysisReport::verify(
            deployment,
            &report_bytes,
            report_digest,
            &bounded_limits(limits),
            budget,
            cx,
        )?;
        let mut rebuilt = provenance(deployment, &report, track, cx)?;
        rebuilt.event.revision = event.revision;
        rebuilt.event.supersedes = event.supersedes;
        if rebuilt.event != event
            || rebuilt.manifest.canonical_bytes() != root_bytes
            || deployment
                .publisher()
                .root(&rebuilt.slot)
                .is_none_or(|r| r.root != proof.root())
        {
            return Err(RecordedEventError::Mismatch);
        }
        for (digest, bytes) in &rebuilt.objects {
            checkpoint(cx, "recorded_event:verify")?;
            if read_verified(deployment, *digest)? != *bytes {
                return Err(RecordedEventError::Mismatch);
            }
        }
        Ok(Self {
            event,
            root,
            anchor,
            report,
            track,
        })
    }
    /// Existing canonical event schema; candidates remain indeterminate and unclassified.
    pub fn event(&self) -> &EventHypothesis {
        &self.event
    }
    /// Canonical event revision graph, not the separate provenance root.
    pub fn root(&self) -> ContentDigest {
        self.root
    }
    /// Original final event-completion anchor, even after unrelated commits.
    pub fn authority_anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
    /// Exact retained reconstruction report, including misses, resets, and ambiguities.
    pub fn report(&self) -> &AnalysisReport {
        &self.report
    }
    /// Local hypothesis identity; never a biometric or physical identity claim.
    pub fn track(&self) -> ContentDigest {
        self.track
    }
}

/// Read-only preparation of one exact event revision. Private fields prevent caller relabeling.
#[derive(Clone, Debug)]
pub struct RecordedEventProposal {
    report: AnalysisReport,
    track: ContentDigest,
    proof: Provenance,
    digest: ContentDigest,
}
impl RecordedEventProposal {
    /// Recompute a report and prepare a new event or an exact full-history extension.
    /// Existing evidence cannot be dropped/reordered, and externally adjudicated events are
    /// never overwritten. No objects, ledger batches, alerts, or other effects are written.
    pub fn prepare(
        deployment: &ReferenceDeployment,
        report_bytes: &[u8],
        report_digest: ContentDigest,
        track: ContentDigest,
        limits: &AnalysisLimits,
        budget: &mut AnalysisBudget,
        cx: &ReplayCx,
    ) -> Result<Self> {
        checkpoint(cx, "recorded_event:prepare")?;
        let report = AnalysisReport::verify(
            deployment,
            report_bytes,
            report_digest,
            &bounded_limits(limits),
            budget,
            cx,
        )?;
        let mut proof = provenance(deployment, &report, track, cx)?;
        let object = ObjectId::parse(format!("object:event:{}", proof.event.event_id.as_str()))?;
        if deployment.ledger().current().objects.contains_key(&object) {
            let prior = RecordedEvent::open(deployment, &proof.event.event_id, limits, budget, cx)?;
            if prior.report.encoded() == report.encoded() {
                proof.event = prior.event;
            } else {
                if !report
                    .plan()
                    .frames()
                    .starts_with(prior.report.plan().frames())
                    || report.observations().len() <= prior.report.observations().len()
                {
                    return Err(RecordedEventError::Conflict);
                }
                for (old, new) in prior
                    .report
                    .observations()
                    .iter()
                    .zip(report.observations())
                {
                    if old.detection().encoded().map_err(AnalysisError::from)?
                        != new.detection().encoded().map_err(AnalysisError::from)?
                        || old.tracking().encoded().map_err(AnalysisError::from)?
                            != new.tracking().encoded().map_err(AnalysisError::from)?
                    {
                        return Err(RecordedEventError::Conflict);
                    }
                }
                proof.event.revision = prior
                    .event
                    .revision
                    .checked_add(1)
                    .ok_or(RecordedEventError::Limit)?;
                proof.event.supersedes = Some(prior.event.revision_digest());
                if proof.event.revision as usize > fss_core::event::MAX_LINEAGE_DEPTH {
                    return Err(RecordedEventError::Limit);
                }
            }
        }
        proof.event.validate()?;
        let mut e = CanonicalEncoder::new();
        e.text("fss.recorded_event_proposal.v1");
        e.digest(proof.event.revision_digest());
        e.digest(proof.manifest.root());
        let digest = ContentDigest::sha256(&e.finish_checked()?);
        Ok(Self {
            report,
            track,
            proof,
            digest,
        })
    }
    /// Exact approval identity, including the event predecessor and complete evidence root.
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// Canonical event proposed, without creating authority.
    pub fn event(&self) -> &EventHypothesis {
        &self.proof.event
    }
    /// Provenance graph root to be retained before the event becomes authoritative.
    pub fn provenance_root(&self) -> ContentDigest {
        self.proof.manifest.root()
    }

    /// Revalidate the exact approval, retain complete provenance root-last, then call the
    /// deployment's guarded event publisher. Exact retries keep the same revision and anchor.
    /// A pre-event failure can leave a provenance root, but never claims event completion.
    pub fn publish(
        &self,
        deployment: &mut ReferenceDeployment,
        expected: ContentDigest,
        limits: &AnalysisLimits,
        budget: &mut AnalysisBudget,
        cx: &ReplayCx,
    ) -> Result<RecordedEvent> {
        checkpoint(cx, "recorded_event:revalidate")?;
        if expected != self.digest {
            return Err(RecordedEventError::StaleProposal);
        }
        let fresh = Self::prepare(
            deployment,
            self.report.encoded(),
            self.report.digest(),
            self.track,
            limits,
            budget,
            cx,
        )?;
        if fresh.digest != expected {
            return Err(RecordedEventError::StaleProposal);
        }
        let existing_root = deployment
            .publisher()
            .root(&fresh.proof.slot)
            .map(|root| root.root);
        if existing_root.is_some_and(|root| root != fresh.proof.manifest.root()) {
            return Err(RecordedEventError::Mismatch);
        }
        for bytes in fresh.proof.objects.values() {
            checkpoint(cx, "recorded_event:stage")?;
            let digest = deployment.publisher_mut().stage_object(bytes)?;
            deployment.publisher_mut().verify_object(digest)?;
        }
        for digest in fresh.proof.manifest.children() {
            checkpoint(cx, "recorded_event:closure")?;
            deployment.publisher_mut().verify_object(*digest)?;
        }
        // The publisher refuses restaging an already visible slot. A previous attempt may
        // have committed this exact prerequisite root without completing event authority.
        // Reuse it only after the full closure above has been revalidated; the existing
        // root/ledger coordinator finishes any owed reachability without duplicate history.
        if existing_root.is_none() {
            deployment
                .publisher_mut()
                .stage_manifest(&fresh.proof.slot, &fresh.proof.manifest)?;
        }
        deployment.publish_and_commit(
            &fresh.proof.slot,
            &fresh.proof.manifest,
            fresh.proof.event.interval,
            cx,
        )?;
        checkpoint(cx, STAGE_RECORDED_EVENT_COMMIT)?;
        let receipt = deployment.publish_event(
            &ReferencePolicyDecision {
                event: fresh.proof.event.clone(),
                action: ReferencePolicyAction::Hold,
            },
            cx,
        )?;
        // Infallible only after the guarded event authority commit.
        cx.checkpoint_post_commit("recorded_event:complete");
        Ok(RecordedEvent {
            event: fresh.proof.event,
            root: receipt.event_root,
            anchor: receipt.authority_anchor,
            report: fresh.report,
            track: fresh.track,
        })
    }
}

#[cfg(test)]
mod tests;
