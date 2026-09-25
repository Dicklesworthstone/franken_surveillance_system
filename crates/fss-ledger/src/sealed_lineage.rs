//! The sealed publication-lineage namespace of the authority ledger (fss-1s6ac).
//!
//! The authority ledger carries the situation-publication lineage (one object per subject) and its
//! proof markers. Before fss-1s6ac any holder of a ledger handle could append a well-formed batch
//! writing those objects, so a raw write could displace a lineage basis, plant a junk first entry,
//! or pair an entry with a proof marker that pre-empted a genuine first proof. The namespace is now
//! sealed:
//!
//! - [`crate::DurableReferenceLedger::append`] refuses every batch with a delta in the namespace
//!   ([`is_sealed_lineage_delta`]) with `ERR-LEDGER-SEALED-NAMESPACE-001`;
//! - the one writer, `fss_reference::record_reference_publication`, validates the publication (sealed,
//!   compiled against this very store, continuing the latest recorded publication) and appends
//!   through the gated entry point, which accepts only a batch made entirely of namespace deltas
//!   that carries its own [`lineage_write_seal`] as a child root;
//! - readers credit a namespace write only inside a batch that [`is_sealed_lineage_batch`] accepts
//!   and refuse, typed, a lineage that holds any other write (a raw batch that predates the gate or
//!   bytes written to the journal file directly).
//!
//! The write seal is an unkeyed digest: it marks a batch that came through the gate and binds its
//! exact content, but a party that writes journal bytes directly can compute it. That party is
//! outside this boundary (see `SECURITY.md`).

use fss_core::{
    BatchId, CanonicalEncode, CanonicalEncoder, ContentDigest, EvidenceDelta, EvidenceDeltaBatch,
};

/// Registered stable error ID for a batch writing the sealed lineage namespace outside the gate.
pub const ERR_LEDGER_SEALED_NAMESPACE_001: &str = "ERR-LEDGER-SEALED-NAMESPACE-001";

/// Digest domain of a lineage write seal.
pub const LINEAGE_WRITE_SEAL_DOMAIN: &str = "fss.reference_lineage_write_seal.v1";

/// Families of the sealed lineage namespace.
pub const SEALED_LINEAGE_FAMILIES: [&str; 2] = [
    "situation_publication_lineage",
    "situation_publication_lineage_proof",
];

/// Object-identity prefix of the sealed lineage namespace; it covers both the lineage objects
/// (`object:situation-lineage:`) and the proof markers (`object:situation-lineage-proof:`).
pub const SEALED_LINEAGE_OBJECT_PREFIX: &str = "object:situation-lineage";

/// Returns whether `delta` writes the sealed lineage namespace: a lineage family, or any family
/// writing a lineage or proof-marker object.
#[must_use]
pub fn is_sealed_lineage_delta(delta: &EvidenceDelta) -> bool {
    SEALED_LINEAGE_FAMILIES.contains(&delta.family.as_str())
        || delta
            .object_id
            .as_str()
            .starts_with(SEALED_LINEAGE_OBJECT_PREFIX)
}

/// The write seal of a lineage batch `batch_id` holding `deltas` (in batch order).
#[must_use]
pub fn lineage_write_seal(batch_id: &BatchId, deltas: &[EvidenceDelta]) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(LINEAGE_WRITE_SEAL_DOMAIN);
    encoder.text(batch_id.as_str());
    encoder.u64(deltas.len() as u64);
    for delta in deltas {
        delta.encode_canonical(&mut encoder);
    }
    ContentDigest::sha256(&encoder.finish())
}

/// Returns whether `batch` is a sealed lineage batch: non-empty, every delta in the sealed
/// namespace, and its own write seal among its child roots.
#[must_use]
pub fn is_sealed_lineage_batch(batch: &EvidenceDeltaBatch) -> bool {
    !batch.deltas.is_empty()
        && batch.deltas.iter().all(is_sealed_lineage_delta)
        && batch
            .children
            .contains(&lineage_write_seal(&batch.batch_id, &batch.deltas))
}

/// The first delta of `batch` in the sealed lineage namespace, if any.
#[must_use]
pub fn first_sealed_lineage_delta(batch: &EvidenceDeltaBatch) -> Option<&EvidenceDelta> {
    batch
        .deltas
        .iter()
        .find(|delta| is_sealed_lineage_delta(delta))
}
