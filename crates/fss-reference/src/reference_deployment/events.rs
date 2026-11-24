#![forbid(unsafe_code)]
//! Policy evaluation, event revision publication, and event authority readback for [`super::ReferenceDeployment`].

use fss_core::{
    BatchId, CanonicalDecode, CanonicalEncode, CanonicalEncoder, ContentDigest, ContractError,
    EventHypothesis, EventId, EvidenceDelta, ObjectId, Plane,
};
use fss_ledger::DurableReferenceLedger;
use fss_object::ObjectManifest;
use fss_publication::{AuthorityPublisher, LocalPublicationError};

use super::ReferenceDeployment;
use super::constants::{STAGE_EVALUATE_POLICY, STAGE_PUBLISH_EVENT};
use crate::adapter_replay::ReplayCx;
use crate::error::ReferenceError;
use crate::ingest::source_coverage::SourceCoverageRecord;
use crate::policy::{
    ReferenceEventReceipt, ReferenceModelObservation, ReferencePolicyDecision,
    evaluate_unknown_presence, evaluate_unknown_presence_over_coverage,
};

struct StagedEventRevision {
    event_root: ContentDigest,
    event_object_digest: ContentDigest,
    event_revision_digest: ContentDigest,
}

fn authority_predecessor(
    ledger: &DurableReferenceLedger,
    object_id: &ObjectId,
) -> Result<(Option<u64>, Option<ContentDigest>), ReferenceError> {
    let Some(current) = ledger.current().objects.get(object_id) else {
        return Ok((None, None));
    };

    let revision_digest = ledger
        .batches()
        .iter()
        .rev()
        .find_map(|batch| {
            batch
                .deltas
                .iter()
                .find(|delta| {
                    delta.object_id == *object_id
                        && delta.family == "event_revision"
                        && delta.new_generation == current.generation
                        && delta.payload_digest == current.payload_digest
                })
                .and_then(|delta| delta.witness_digest)
        })
        .ok_or(ContractError::SupersessionMismatch)?;

    Ok((Some(current.generation), Some(revision_digest)))
}

impl ReferenceDeployment {
    /// Evaluates unknown presence policy over model observations.
    pub fn evaluate_policy(
        &self,
        event_id: EventId,
        observations: Vec<ReferenceModelObservation>,
        cx: &ReplayCx,
    ) -> Result<ReferencePolicyDecision, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_EVALUATE_POLICY,
            });
        }
        evaluate_unknown_presence(event_id, observations)
    }

    /// Evaluates unknown presence policy over the model observations of a source coverage
    /// record's frames ([`evaluate_unknown_presence_over_coverage`], fss-f8jls).
    pub fn evaluate_policy_over_coverage(
        &self,
        event_id: EventId,
        observations: Vec<ReferenceModelObservation>,
        record: &SourceCoverageRecord,
        cx: &ReplayCx,
    ) -> Result<ReferencePolicyDecision, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_EVALUATE_POLICY,
            });
        }
        evaluate_unknown_presence_over_coverage(event_id, observations, record)
    }

    /// Publishes a reference event decision into authority.
    pub fn publish_event(
        &mut self,
        decision: &ReferencePolicyDecision,
        cx: &ReplayCx,
    ) -> Result<ReferenceEventReceipt, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_PUBLISH_EVENT,
            });
        }
        decision.event.validate()?;
        let event_name = decision.event.event_id.as_str();
        let object_id = ObjectId::parse(format!("object:event:{event_name}"))?;
        let (prior_generation, predecessor) = authority_predecessor(&self.ledger, &object_id)?;
        let candidate_revision_digest = decision.event.revision_digest();

        // Sensor tamper is sticky across the lineage (fss-2uftm), recomputed from the revisions
        // this deployment's ledger published and its spool holds, exactly as
        // `publish_reference_event` does. It applies to idempotent retries too: an exact retry of
        // a revision that drops an unretired tamper is still refused.
        let prior_events = self.prior_event_revisions(&object_id, decision.event.revision)?;
        let prior_tamper = fss_core::event::compute_sensor_tamper_status(prior_events.iter(), None);
        let mut combined_tamper = prior_tamper.clone();
        fss_core::event::apply_revision_tamper_step(&mut combined_tamper, &decision.event)?;
        if decision
            .event
            .evidence
            .iter()
            .any(|evidence| evidence.reports_integrity_restoration())
            && prior_tamper.open_tamper_records.is_empty()
        {
            return Err(ContractError::EvidenceRequired.into());
        }
        let prior_revision_encodings: Vec<Vec<u8>> = prior_events
            .iter()
            .map(crate::alert::event_revision_encoding)
            .collect();

        if predecessor == Some(candidate_revision_digest) {
            let (committed_anchor, payload_digest) = self
                .ledger
                .batches()
                .iter()
                .rev()
                .find_map(|batch| {
                    batch
                        .deltas
                        .iter()
                        .find(|delta| {
                            delta.object_id == object_id
                                && delta.family == "event_revision"
                                && delta.new_generation == decision.event.revision
                                && delta.witness_digest == Some(candidate_revision_digest)
                        })
                        .map(|delta| (batch.new_anchor.clone(), delta.payload_digest))
                })
                .ok_or(ContractError::SupersessionMismatch)?;

            let staged = self.stage_event_revision(decision)?;
            if staged.event_root != payload_digest {
                return Err(ContractError::SupersessionMismatch.into());
            }
            self.publisher.verify_object(staged.event_root)?;
            self.stage_tamper_status(&combined_tamper)?;

            return Ok(ReferenceEventReceipt {
                event_root: staged.event_root,
                event_object_digest: staged.event_object_digest,
                event_revision_digest: staged.event_revision_digest,
                authority_anchor: committed_anchor,
                lineage_tamper_status: combined_tamper,
                prior_revision_encodings,
            });
        }

        if decision.event.supersedes != predecessor {
            return Err(ContractError::SupersessionMismatch.into());
        }

        let staged = self.stage_event_revision(decision)?;
        self.stage_tamper_status(&combined_tamper)?;

        let delta = EvidenceDelta {
            delta_id: format!("delta:event:{event_name}:{}", decision.event.revision),
            family: "event_revision".to_owned(),
            object_id,
            prior_generation,
            new_generation: decision.event.revision,
            validity: decision.event.interval,
            plane: Plane::Authority,
            payload_digest: staged.event_root,
            witness_digest: Some(staged.event_revision_digest),
            operation_id: None,
        };
        // The accumulated tamper status is witnessed in the same batch; alert preparation,
        // dispatch and situation compilation cross-check it against their own recomputation.
        let tamper_delta = EvidenceDelta {
            delta_id: format!(
                "delta:event:{event_name}:tamper:{}",
                decision.event.revision
            ),
            family: "sensor_tamper_status".to_owned(),
            object_id: ObjectId::parse(format!("object:event:{event_name}:tamper"))?,
            prior_generation,
            new_generation: decision.event.revision,
            validity: decision.event.interval,
            plane: Plane::Authority,
            payload_digest: staged.event_root,
            witness_digest: Some(combined_tamper.canonical_digest()),
            operation_id: None,
        };

        let authority_anchor = {
            let mut publisher = AuthorityPublisher::new(&self.publisher, &mut self.ledger);
            let batch = publisher.prepare_batch(
                BatchId::parse(format!(
                    "batch:event:{event_name}:{}",
                    decision.event.revision
                ))?,
                vec![delta, tamper_delta],
                [staged.event_root],
            )?;
            publisher.append(batch)?
        };
        Ok(ReferenceEventReceipt {
            event_root: staged.event_root,
            event_object_digest: staged.event_object_digest,
            event_revision_digest: staged.event_revision_digest,
            authority_anchor,
            lineage_tamper_status: combined_tamper,
            prior_revision_encodings,
        })
    }

    /// Reads the event's current authoritative revision and a receipt for it, without writing.
    ///
    /// The revision is the one the ledger's current event object names: its `event_revision`
    /// delta at the current generation and payload, decoded from the spool and required to hash to
    /// the delta's witness. The receipt's anchor is the anchor of the batch that published it, and
    /// its lineage tamper status is recomputed from every revision the ledger published. A later
    /// consumer (alert preparation) cross-checks all of it against the ledger again; the receipt
    /// is never authority by itself.
    pub fn current_event_authority(
        &self,
        event_id: &EventId,
    ) -> Result<(EventHypothesis, ReferenceEventReceipt), ReferenceError> {
        let object_id = ObjectId::parse(format!("object:event:{}", event_id.as_str()))?;
        let current = self
            .ledger
            .current()
            .objects
            .get(&object_id)
            .ok_or(ContractError::NotFound)?;
        let (anchor, event_root, witness) = self
            .ledger
            .batches()
            .iter()
            .rev()
            .find_map(|batch| {
                batch
                    .deltas
                    .iter()
                    .find(|delta| {
                        delta.object_id == object_id
                            && delta.family == "event_revision"
                            && delta.new_generation == current.generation
                            && delta.payload_digest == current.payload_digest
                    })
                    .map(|delta| {
                        (
                            batch.new_anchor.clone(),
                            delta.payload_digest,
                            delta.witness_digest,
                        )
                    })
            })
            .ok_or(ContractError::SupersessionMismatch)?;
        let spool = self.publisher.spool();
        let manifest_bytes = spool
            .read(event_root)
            .map_err(|error| ReferenceError::from(LocalPublicationError::Spool(error)))?;
        let manifest = ObjectManifest::from_canonical_bytes(&manifest_bytes)?;
        let event_object_digest = manifest
            .metadata_digest()
            .ok_or(ContractError::EvidenceRequired)?;
        let event_bytes = spool
            .read(event_object_digest)
            .map_err(|error| ReferenceError::from(LocalPublicationError::Spool(error)))?;
        let event = EventHypothesis::from_canonical_bytes(&event_bytes)?;
        let event_revision_digest = event.revision_digest();
        if witness != Some(event_revision_digest) || event.event_id != *event_id {
            return Err(ContractError::SupersessionMismatch.into());
        }
        let prior = self.prior_event_revisions(&object_id, event.revision)?;
        let lineage_tamper_status = fss_core::event::compute_sensor_tamper_status(
            prior.iter().chain(std::iter::once(&event)),
            None,
        );
        let receipt = ReferenceEventReceipt {
            event_root,
            event_object_digest,
            event_revision_digest,
            authority_anchor: anchor,
            lineage_tamper_status,
            prior_revision_encodings: prior
                .iter()
                .map(crate::alert::event_revision_encoding)
                .collect(),
        };
        Ok((event, receipt))
    }

    /// Every earlier revision of the event `object_id`, oldest first, read back from this
    /// deployment's spool through the `event_revision` deltas its ledger committed.
    fn prior_event_revisions(
        &self,
        object_id: &ObjectId,
        current_revision: u64,
    ) -> Result<Vec<EventHypothesis>, ReferenceError> {
        let spool = self.publisher.spool();
        let read = |digest: ContentDigest| {
            spool
                .read(digest)
                .map_err(|error| ReferenceError::from(LocalPublicationError::Spool(error)))
        };
        let mut prior = Vec::new();
        for batch in self.ledger.batches() {
            for delta in &batch.deltas {
                if delta.object_id == *object_id && delta.family == "event_revision" {
                    let manifest =
                        ObjectManifest::from_canonical_bytes(&read(delta.payload_digest)?)?;
                    let payload = manifest
                        .metadata_digest()
                        .or_else(|| manifest.children().first().copied())
                        .ok_or(ContractError::EvidenceRequired)?;
                    let revision = EventHypothesis::from_canonical_bytes(&read(payload)?)?;
                    if revision.revision < current_revision {
                        prior.push(revision);
                    }
                }
            }
        }
        prior.sort_by_key(|revision| revision.revision);
        prior.dedup_by_key(|revision| revision.revision);
        Ok(prior)
    }

    /// Stages the canonical encoding of `status` in the spool; its digest must be the status
    /// witness digest, or the publication fails closed.
    fn stage_tamper_status(
        &mut self,
        status: &fss_core::SensorTamperStatus,
    ) -> Result<(), ReferenceError> {
        let mut encoder = CanonicalEncoder::new();
        status.encode_canonical(&mut encoder);
        let staged = self.publisher.stage_object(&encoder.finish())?;
        if staged != status.canonical_digest() {
            return Err(ContractError::DigestMismatch.into());
        }
        Ok(())
    }

    fn stage_event_revision(
        &mut self,
        decision: &ReferencePolicyDecision,
    ) -> Result<StagedEventRevision, ReferenceError> {
        for model_receipt in &decision.event.model_receipts {
            self.publisher.verify_object(*model_receipt)?;
        }
        let event_bytes = decision.event.canonical_bytes();
        let event_object_digest = self.publisher.stage_object(&event_bytes)?;
        let mut revision_encoder = CanonicalEncoder::new();
        revision_encoder.text("fss.canonical.v1");
        revision_encoder.text("fss.event_hypothesis.v1");
        decision.event.encode_canonical(&mut revision_encoder);
        let event_revision_digest = self.publisher.stage_object(&revision_encoder.finish())?;
        let event_manifest = ObjectManifest::new(
            "event-revision",
            decision.event.model_receipts.iter().copied(),
            Some(event_object_digest),
        )?;
        let manifest_bytes = event_manifest.canonical_bytes();
        let event_root = self.publisher.stage_object(&manifest_bytes)?;
        Ok(StagedEventRevision {
            event_root,
            event_object_digest,
            event_revision_digest,
        })
    }
}
