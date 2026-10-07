#![forbid(unsafe_code)]
//! Read back package candidates through event authority and their exact retained proof graph.

use fss_core::CanonicalDecode;

use super::*;

// Match the event-review surface's bounded history envelope. These limits apply before any
// model or source reconstruction; package source/report work has its own narrower ceilings.
const MAX_LEDGER_BATCHES: usize = 65_536;
const MAX_HISTORY_BYTES: usize = 32 * 1024 * 1024;

/// Published package candidate and its independently rebuilt retained analysis.
#[derive(Clone, Debug)]
pub struct PackageEvent {
    receipt: PackageEventReceipt,
    report: PackageAnalysisReport,
}

impl PackageEvent {
    /// Reopens the current package event, verifies its complete authoritative revision chain,
    /// and rebuilds its exact source-backed package analysis and provenance graph.
    ///
    /// This is a read: it never repairs missing evidence, runs the model, republishes an event,
    /// or needs the original source/model/report files. A later decision outside this candidate
    /// policy is refused rather than overwritten or presented as its earlier unresolved state.
    pub fn open(deployment: &ReferenceDeployment, id: &EventId, cx: &ReplayCx) -> Result<Self> {
        checkpoint(cx, "package_event:read")?;
        let (event, root, anchor) =
            load_authority(deployment, id, cx)?.ok_or(PackageEventError::EventUnavailable)?;
        if event.decision_path.policy_generation != ContentDigest::sha256(POLICY) {
            return Err(PackageEventError::Conflict);
        }
        let bytes = read_verified(deployment, event.decision_path.fingerprint)?;
        let manifest = ObjectManifest::from_canonical_bytes(&bytes)?;
        let metadata = manifest
            .metadata_digest()
            .ok_or(PackageEventError::Mismatch)?;
        let bytes = read_verified(deployment, metadata)?;
        if bytes.len() > 1024 {
            return Err(PackageEventError::Limit);
        }
        let mut decoder = CanonicalDecoder::new(&bytes);
        if decoder.bytes()? != b"FSSPEVT1"
            || decoder.u32()? != 1
            || decoder.text()? != PROVENANCE_DOMAIN
            || decoder.digest()? != ContentDigest::sha256(POLICY)
        {
            return Err(PackageEventError::Mismatch);
        }
        let track = decoder.digest()?;
        let report_digest = decoder.digest()?;
        decoder.ensure_finished()?;
        let report_bytes = read_verified(deployment, report_digest)?;
        let report = PackageAnalysisReport::verify(deployment, &report_bytes, report_digest, cx)?;
        let proof = provenance(&report, track)?;
        if proof.event != event {
            return Err(PackageEventError::Conflict);
        }
        verify_provenance(deployment, &proof, cx)?;
        Ok(Self {
            receipt: PackageEventReceipt {
                event,
                event_root: root,
                authority_anchor: anchor,
                provenance_root: proof.manifest.root(),
                report_digest,
                track,
            },
            report,
        })
    }

    /// Exact immutable event; remains unclassified, indeterminate and uncalibrated.
    #[must_use]
    pub fn event(&self) -> &EventHypothesis {
        &self.receipt.event
    }

    /// Canonical event revision root, distinct from the provenance root.
    #[must_use]
    pub fn root(&self) -> ContentDigest {
        self.receipt.event_root
    }

    /// Original event-publication anchor, preserved across unrelated commits and exact retries.
    #[must_use]
    pub fn authority_anchor(&self) -> &LedgerAnchor {
        &self.receipt.authority_anchor
    }

    /// Exact report rebuilt from retained detections, capsules, source bytes and tracker policy.
    #[must_use]
    pub fn report(&self) -> &PackageAnalysisReport {
        &self.report
    }

    /// Local track hypothesis, never a physical or biometric identity.
    #[must_use]
    pub fn track(&self) -> ContentDigest {
        self.receipt.track
    }
}

/// Check the current ledger object and every actual event revision. Do not deduplicate, sort or
/// skip inconsistent revisions: each must be the exact next extension of its predecessor.
fn load_authority(
    deployment: &ReferenceDeployment,
    id: &EventId,
    cx: &ReplayCx,
) -> Result<Option<(EventHypothesis, ContentDigest, LedgerAnchor)>> {
    if deployment.ledger().batches().len() > MAX_LEDGER_BATCHES {
        return Err(PackageEventError::Limit);
    }
    let object = ObjectId::parse(format!("object:event:{}", id.as_str()))?;
    let Some(current) = deployment.ledger().current().objects.get(&object) else {
        return Ok(None);
    };
    let mut chain = Vec::new();
    let mut latest = None;
    let mut used = 0_usize;
    for batch in deployment.ledger().batches() {
        checkpoint(cx, "package_event:read_history")?;
        for delta in &batch.deltas {
            if delta.object_id != object {
                continue;
            }
            if delta.family != "event_revision" || delta.plane != Plane::Authority {
                return Err(PackageEventError::Mismatch);
            }
            if chain.len() >= fss_core::event::MAX_LINEAGE_DEPTH {
                return Err(PackageEventError::Limit);
            }
            let root_bytes = read_verified(deployment, delta.payload_digest)?;
            used = used
                .checked_add(root_bytes.len())
                .ok_or(PackageEventError::Limit)?;
            if used > MAX_HISTORY_BYTES {
                return Err(PackageEventError::Limit);
            }
            let manifest = ObjectManifest::from_canonical_bytes(&root_bytes)?;
            let metadata = manifest
                .metadata_digest()
                .ok_or(PackageEventError::Mismatch)?;
            let bytes = read_verified(deployment, metadata)?;
            used = used
                .checked_add(bytes.len())
                .ok_or(PackageEventError::Limit)?;
            if used > MAX_HISTORY_BYTES {
                return Err(PackageEventError::Limit);
            }
            let event = EventHypothesis::from_canonical_bytes(&bytes)?;
            let expected_manifest = ObjectManifest::new(
                "event-revision",
                event.model_receipts.iter().copied(),
                Some(ContentDigest::sha256(&event.try_canonical_bytes()?)),
            )?;
            if event.event_id != *id
                || event.revision != chain.len() as u64 + 1
                || delta.new_generation != event.revision
                || delta.prior_generation != event.revision.checked_sub(1).filter(|n| *n != 0)
                || delta.validity != event.interval
                || delta.witness_digest != Some(event.revision_digest())
                || expected_manifest.canonical_bytes() != root_bytes
                || !batch.children.contains(&delta.payload_digest)
            {
                return Err(PackageEventError::Mismatch);
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
    let latest = latest.ok_or(PackageEventError::Mismatch)?;
    if chain.last() != Some(&latest.0) {
        return Err(PackageEventError::Mismatch);
    }
    Ok(Some(latest))
}

fn verify_provenance(
    deployment: &ReferenceDeployment,
    proof: &Provenance,
    cx: &ReplayCx,
) -> Result<()> {
    checkpoint(cx, "package_event:read_provenance")?;
    if deployment
        .publisher()
        .root(&proof.slot)
        .is_none_or(|r| r.root != proof.manifest.root())
        || read_verified(deployment, proof.manifest.root())? != proof.manifest.canonical_bytes()
    {
        return Err(PackageEventError::Mismatch);
    }
    for (digest, bytes) in &proof.objects {
        checkpoint(cx, "package_event:read_provenance_object")?;
        if read_verified(deployment, *digest)? != *bytes {
            return Err(PackageEventError::Mismatch);
        }
    }
    // Source/import and retained-detection subgraphs were already validated while rebuilding
    // the report; re-read every direct child as well, including referenced source capsules.
    for digest in proof.manifest.children() {
        checkpoint(cx, "package_event:read_provenance_child")?;
        if !proof.objects.contains_key(digest) {
            read_verified(deployment, *digest)?;
        }
    }
    Ok(())
}

/// Reuse the already reconstructed report during prepare/publish, but never substitute a
/// matching ledger witness for verification of the retained event and provenance bytes.
pub(super) fn existing_receipt(
    deployment: &ReferenceDeployment,
    proof: &Provenance,
    report_digest: ContentDigest,
    track: ContentDigest,
    cx: &ReplayCx,
) -> Result<Option<PackageEventReceipt>> {
    let Some((event, root, anchor)) = load_authority(deployment, &proof.event.event_id, cx)? else {
        return Ok(None);
    };
    if event != proof.event {
        return Err(PackageEventError::Conflict);
    }
    verify_provenance(deployment, proof, cx)?;
    Ok(Some(PackageEventReceipt {
        event,
        event_root: root,
        authority_anchor: anchor,
        provenance_root: proof.manifest.root(),
        report_digest,
        track,
    }))
}
