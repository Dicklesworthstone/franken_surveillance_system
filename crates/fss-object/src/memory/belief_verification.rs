#![forbid(unsafe_code)]
//! Published-manifest graph custody and bounded canonical belief intake.
//!
//! This child of the store owner can distinguish never-published opaque payloads from invalidated
//! published manifests without inferring type from byte signatures or exposing a mutable registry.

use fss_core::belief_verification::graph::{
    BeliefGraphError, BeliefGraphFailure, BeliefGraphRequest, BeliefGraphUsage,
    RetainedBeliefGraph, VerifiedBeliefGraph, verify_derived_belief_graph,
};
use fss_core::belief_verification::{BeliefEvidenceReadError, RegisteredBeliefDeriver};
use fss_core::{CanonicalDecode, CanonicalDecoder, ContentDigest, DerivedBelief, ReferenceLedger};

use super::InMemoryObjectStore;
use crate::{ObjectManifest, ObjectState};

impl RetainedBeliefGraph for InMemoryObjectStore {
    fn belief_children(
        &self,
        digest: ContentDigest,
        verified_bytes: &[u8],
        max_children: usize,
    ) -> Result<Vec<ContentDigest>, BeliefEvidenceReadError> {
        // A former manifest is never reclassified as an opaque leaf after deletion invalidates
        // its closure. Its own bytes may still be verified, but its publication is not usable.
        if self.invalidated_manifests.contains_key(&digest) {
            return Err(BeliefEvidenceReadError::NotVerified);
        }
        let object = self.objects.get(&digest).ok_or(BeliefEvidenceReadError::Missing)?;
        match object.state {
            ObjectState::Tombstoned => return Err(BeliefEvidenceReadError::Missing),
            ObjectState::Staged => return Err(BeliefEvidenceReadError::NotVerified),
            ObjectState::Verified => {}
        }
        let retained = object.bytes.as_deref().ok_or(BeliefEvidenceReadError::Corrupt)?;
        if retained != verified_bytes || ContentDigest::sha256(verified_bytes) != digest {
            return Err(BeliefEvidenceReadError::Corrupt);
        }
        let Some(published) = self.visible_manifests.get(&digest) else {
            // Exact resident bytes that happen to encode a manifest are still an opaque leaf.
            // Publication, not a parser guess, is the graph owner's type authority.
            return Ok(Vec::new());
        };
        // Reject before the canonical decoder allocates its edge list. Equality below also
        // checks the cached publication against the rehashed bytes and its complete typed body.
        if published.children().len() > max_children {
            return Err(BeliefEvidenceReadError::LimitExceeded);
        }
        // Also preflight the count in the actual bytes; a damaged publication cache with a
        // smaller edge list must not let the decoder allocate beyond the request's allowance.
        let mut prefix = CanonicalDecoder::new(verified_bytes);
        prefix.text().map_err(|_| BeliefEvidenceReadError::Corrupt)?;
        prefix.text().map_err(|_| BeliefEvidenceReadError::Corrupt)?;
        let encoded_children = usize::try_from(
            prefix.u64().map_err(|_| BeliefEvidenceReadError::Corrupt)?,
        ).map_err(|_| BeliefEvidenceReadError::LimitExceeded)?;
        if encoded_children > max_children {
            return Err(BeliefEvidenceReadError::LimitExceeded);
        }
        let decoded = ObjectManifest::from_canonical_bytes(verified_bytes)
            .map_err(|_| BeliefEvidenceReadError::Corrupt)?;
        if decoded.root() != digest || &decoded != published {
            return Err(BeliefEvidenceReadError::Corrupt);
        }
        Ok(decoded.children().to_vec())
    }
}

impl InMemoryObjectStore {
    /// Decodes one complete saved belief and verifies its current, selected published graphs.
    ///
    /// The authority object selection, graph/cancellation budget and registered engine must be
    /// verifier-owned, never reconstructed from the offered conclusion. The input byte ceiling is
    /// checked before decoding allocates. Malformed/truncated/trailing input and cancellation
    /// return no decoded belief or partial proof. The complete selected closures, including unused
    /// metadata and siblings, pass custody and native graph verification before the engine runs.
    ///
    /// No object is staged, verified, repaired, published or deleted as a side effect. Saved
    /// manifests must already have been explicitly restored/published by their own authority;
    /// decode does not restore graph publication. The returned proof borrows this store, ledger
    /// and engine, keeping their mutable owners out of scope while it is used.
    ///
    /// Admission/decode failures retain zero graph usage. Graph refusals retain their cumulative
    /// logical usage, which is distinct from native engine execution and physical I/O costs.
    /// This is the in-memory reference owner, not a persistent deployment or effect interface.
    pub fn decode_and_verify_belief_graph<'a>(
        &'a self,
        encoded: &[u8],
        ledger: &'a ReferenceLedger,
        engine: &'a (impl RegisteredBeliefDeriver + ?Sized),
        request: BeliefGraphRequest<'_>,
        max_encoded_bytes: usize,
    ) -> Result<VerifiedBeliefGraph<'a>, BeliefGraphFailure> {
        let refuse = |reason| BeliefGraphFailure { reason, usage: BeliefGraphUsage::default() };
        if (request.cancelled)() {
            return Err(refuse(BeliefGraphError::Cancelled));
        }
        if encoded.len() > max_encoded_bytes {
            return Err(refuse(BeliefGraphError::Limit("encoded bytes")));
        }
        let offered = DerivedBelief::from_canonical_bytes(encoded)
            .map_err(|error| refuse(BeliefGraphError::from(error)))?;
        verify_derived_belief_graph(&offered, ledger, self, engine, request)
    }
}

#[cfg(test)]
mod tests;
