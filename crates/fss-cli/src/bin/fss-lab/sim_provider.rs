#![forbid(unsafe_code)]
//! Durable record of the laboratory's simulated alert provider (fss-2h5zq.15).
//!
//! `ReferenceAlertProvider` lives in memory and starts empty on every `ReferenceDeployment`
//! open, so a separate `fss-lab recover` process would find nothing to reconcile against. The
//! lab therefore keeps the simulated provider's own side of every dispatch on disk: after each
//! `ReferenceDeployment::dispatch_alert`, and before the lab's dispatch step returns (an injected
//! crash after a lost acknowledgement included), what the provider now holds for the intent is
//! appended to `<root>/effects/simulated_provider.fssj`, an `fss_ledger` journal whose append
//! syncs the record body before its commit trailer. Records are canonical
//! `fss.lab.simulated_provider.v1` encodings, append-only and deterministic: the nonce and
//! receipt are exactly the in-memory provider's.
//!
//! `fss-lab recover --reconcile-effects` reads only this record. It is labelled simulated in
//! every report: it is the lab's deterministic provider, never a real vendor, and nothing here
//! talks to one.
//!
//! # No-Claim
//!
//! The record is written after the in-memory provider accepted the message and before the lab
//! step returns, in the same process. A process death between those two points would lose the
//! provider's side of the dispatch; the operation would then stay indeterminate, which is the
//! conservative outcome. In-process injection never exercises that window.

use std::fs;
use std::path::{Path, PathBuf};

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    EffectIntent,
};
use fss_reference::{
    IncompleteTailPolicy, Journal, ProviderFailureReceipt, ProviderObservationReceipt,
    ReferenceAlertProvider, ReferenceProviderBehavior, inspect_journal,
};

/// Record path, relative to the deployment root.
pub const SIMULATED_PROVIDER_RELATIVE_PATH: &str = "effects/simulated_provider.fssj";

/// Canonical encoding domain of one record (registries/DIGEST_DOMAINS.md
/// `SCHEMA-DOMAIN-LAB-SIMULATED-PROVIDER-001`).
pub const SIMULATED_PROVIDER_DOMAIN: &str = "fss.lab.simulated_provider.v1";

/// Journal record kind of an observation record.
pub const SIMULATED_PROVIDER_RECORD_KIND: u16 = 1;

/// Upper bound on the record file read by one load.
pub const MAX_RECORD_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Label every report carries next to anything read from this record.
pub const SIMULATED_LABEL: &str =
    "simulated: the lab's deterministic alert provider record, not a real vendor";

/// Domain the provider's receipts bind the dispatched intent under (alert.rs).
const EFFECT_PROOF_DOMAIN: &str = "fss.effect_proof.v1";

/// What the simulated provider holds for one intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationKind {
    /// The provider created the message and the caller received the acknowledgement.
    Delivered,
    /// The provider created the message but the caller lost the acknowledgement.
    DeliveredAckLost,
    /// The provider proved the request failed before any message was created.
    Failed,
}

impl ObservationKind {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::DeliveredAckLost => "delivered_ack_lost",
            Self::Failed => "failed",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Delivered => 1,
            Self::DeliveredAckLost => 2,
            Self::Failed => 3,
        }
    }

    const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Delivered),
            2 => Some(Self::DeliveredAckLost),
            3 => Some(Self::Failed),
            _ => None,
        }
    }
}

/// One durable simulated-provider observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderObservation {
    /// Provider instance identity.
    pub provider_id: String,
    /// What the provider holds.
    pub kind: ObservationKind,
    /// The exact dispatched intent.
    pub intent: EffectIntent,
    /// Provider-generated nonce of the receipt.
    pub provider_nonce: ContentDigest,
    /// Digest of the dispatched intent under `fss.effect_proof.v1`.
    pub message_digest: ContentDigest,
    /// Provider error code of a failure; empty for a delivery.
    pub error_code: String,
}

impl ProviderObservation {
    /// Canonical record bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(SIMULATED_PROVIDER_DOMAIN);
        encoder.text(&self.provider_id);
        encoder.tag(self.kind.tag());
        self.intent.encode_canonical(&mut encoder);
        encoder.digest(self.provider_nonce);
        encoder.digest(self.message_digest);
        encoder.text(&self.error_code);
        encoder.finish()
    }

    /// Decodes one record, refusing trailing bytes, an unknown kind, or an error code that does
    /// not match the kind.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut decoder = CanonicalDecoder::new(bytes);
        let refuse = |e: fss_core::ContractError| format!("simulated provider record: {e}");
        if decoder.text().map_err(refuse)? != SIMULATED_PROVIDER_DOMAIN {
            return Err("simulated provider record: wrong domain".to_owned());
        }
        let provider_id = decoder.text().map_err(refuse)?.to_owned();
        let kind = ObservationKind::from_tag(decoder.tag().map_err(refuse)?)
            .ok_or("simulated provider record: unknown kind")?;
        let intent = EffectIntent::decode_canonical(&mut decoder).map_err(refuse)?;
        let provider_nonce = decoder.digest().map_err(refuse)?;
        let message_digest = decoder.digest().map_err(refuse)?;
        let error_code = decoder.text().map_err(refuse)?.to_owned();
        decoder.ensure_finished().map_err(refuse)?;
        if (kind == ObservationKind::Failed) == error_code.is_empty() {
            return Err("simulated provider record: error code does not match the kind".to_owned());
        }
        Ok(Self {
            provider_id,
            kind,
            intent,
            provider_nonce,
            message_digest,
            error_code,
        })
    }

    /// The provider's receipt digest: the proof a reconciliation binds.
    #[must_use]
    pub fn proof_digest(&self) -> ContentDigest {
        match self.kind {
            ObservationKind::Failed => ProviderFailureReceipt {
                provider_nonce: self.provider_nonce,
                message_digest: self.message_digest,
                error_code: self.error_code.clone(),
            }
            .receipt_digest(),
            ObservationKind::Delivered | ObservationKind::DeliveredAckLost => {
                ProviderObservationReceipt {
                    provider_nonce: self.provider_nonce,
                    message_digest: self.message_digest,
                }
                .receipt_digest()
            }
        }
    }

    /// Whether this record is about exactly `intent`: the same intent and the provider's message
    /// digest of it.
    #[must_use]
    pub fn matches(&self, intent: &EffectIntent) -> bool {
        self.intent == *intent
            && self.message_digest == intent.canonical_digest(EFFECT_PROOF_DOMAIN)
    }
}

/// Record path under `root`.
#[must_use]
pub fn record_path(root: &Path) -> PathBuf {
    root.join(SIMULATED_PROVIDER_RELATIVE_PATH)
}

/// Loads every committed observation, in append order. An absent record is empty. Only committed
/// records count: an incomplete final record never committed, so it is no observation.
pub fn load(root: &Path) -> Result<Vec<ProviderObservation>, String> {
    let path = record_path(root);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    if !metadata.file_type().is_file() {
        return Err(format!(
            "{}: the simulated provider record is not a regular file",
            path.display()
        ));
    }
    if metadata.len() > MAX_RECORD_FILE_BYTES {
        return Err(format!(
            "{}: {} bytes exceed the {MAX_RECORD_FILE_BYTES}-byte bound",
            path.display(),
            metadata.len()
        ));
    }
    let report = inspect_journal(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    report
        .records()
        .iter()
        .map(|record| {
            if record.kind() == SIMULATED_PROVIDER_RECORD_KIND {
                ProviderObservation::decode(record.payload())
            } else {
                Err(format!(
                    "{}: record {} has unknown kind {}",
                    path.display(),
                    record.sequence(),
                    record.kind()
                ))
            }
        })
        .collect()
}

/// Appends `observation` durably unless an identical record already exists; returns whether a
/// record was written. A different record under the same idempotency key is refused, never
/// overwritten.
pub fn append(root: &Path, observation: &ProviderObservation) -> Result<bool, String> {
    for existing in load(root)? {
        if existing.intent.idempotency_key == observation.intent.idempotency_key {
            return if existing == *observation {
                Ok(false)
            } else {
                Err(format!(
                    "simulated provider record already holds a different observation for {}",
                    observation.intent.idempotency_key.as_str()
                ))
            };
        }
    }
    let path = record_path(root);
    let mut journal = Journal::open(&path, IncompleteTailPolicy::Reject)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    journal
        .append(
            SIMULATED_PROVIDER_RECORD_KIND,
            &observation.canonical_bytes(),
        )
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(true)
}

/// Records what the in-memory simulated `provider` holds for `intent` after a dispatch made
/// with `behavior`. Nothing is recorded when the provider holds nothing (the dispatch never
/// reached it). Returns the recorded kind.
pub fn persist_dispatch(
    root: &Path,
    provider: &ReferenceAlertProvider,
    intent: &EffectIntent,
    behavior: ReferenceProviderBehavior,
) -> Result<Option<ObservationKind>, String> {
    let observation =
        if let Some(failure) = provider.lookup_failure(intent).map_err(|e| e.to_string())? {
            ProviderObservation {
                provider_id: provider.provider_id().to_owned(),
                kind: ObservationKind::Failed,
                intent: intent.clone(),
                provider_nonce: failure.provider_nonce,
                message_digest: failure.message_digest,
                error_code: failure.error_code,
            }
        } else if let Some(receipt) = provider.lookup(intent).map_err(|e| e.to_string())? {
            ProviderObservation {
                provider_id: provider.provider_id().to_owned(),
                kind: if behavior == ReferenceProviderBehavior::LoseAckAfterDelivery {
                    ObservationKind::DeliveredAckLost
                } else {
                    ObservationKind::Delivered
                },
                intent: intent.clone(),
                provider_nonce: receipt.provider_nonce,
                message_digest: receipt.message_digest,
                error_code: String::new(),
            }
        } else {
            return Ok(None);
        };
    append(root, &observation)?;
    Ok(Some(observation.kind))
}

#[cfg(test)]
mod tests {
    use super::{ObservationKind, ProviderObservation, append, load, record_path};
    use fss_core::{CanonicalEncode, ContentDigest, EffectIntent, IdempotencyKey, OperationId};

    struct Scratch(std::path::PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Result<Self, String> {
            for n in 0..100 {
                let dir = std::env::temp_dir()
                    .join(format!("fss-lab-simprov-{tag}-{}-{n}", std::process::id()));
                match std::fs::create_dir(&dir) {
                    Ok(()) => {
                        std::fs::create_dir(dir.join("effects")).map_err(|e| e.to_string())?;
                        return Ok(Self(dir));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e.to_string()),
                }
            }
            Err("temporary directory capacity".to_owned())
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn observation(key: &str, kind: ObservationKind) -> Result<ProviderObservation, String> {
        let intent = EffectIntent {
            operation_id: OperationId::parse("op:test:1").map_err(|e| e.to_string())?,
            idempotency_key: IdempotencyKey::parse(key).map_err(|e| e.to_string())?,
            effect_class: "alert.notify".to_owned(),
            request_digest: ContentDigest::sha256(b"request"),
            precondition_digest: ContentDigest::sha256(b"precondition"),
        };
        Ok(ProviderObservation {
            provider_id: "alert:site:test".to_owned(),
            kind,
            message_digest: intent.canonical_digest("fss.effect_proof.v1"),
            intent,
            provider_nonce: ContentDigest::sha256(b"nonce"),
            error_code: if kind == ObservationKind::Failed {
                "failed_before_delivery".to_owned()
            } else {
                String::new()
            },
        })
    }

    #[test]
    fn records_round_trip_append_only_and_refuse_conflicts() -> Result<(), String> {
        let root = Scratch::new("rt")?;
        assert!(load(&root.0)?.is_empty());
        assert!(!record_path(&root.0).exists());
        let delivered = observation("idemp:a", ObservationKind::DeliveredAckLost)?;
        let failed = observation("idemp:b", ObservationKind::Failed)?;
        assert_eq!(
            ProviderObservation::decode(&delivered.canonical_bytes())?,
            delivered
        );
        assert!(append(&root.0, &delivered)?);
        assert!(append(&root.0, &failed)?);
        // An identical record is not written twice.
        assert!(!append(&root.0, &delivered)?);
        assert_eq!(load(&root.0)?, vec![delivered.clone(), failed.clone()]);
        // A different observation under a recorded key is refused, never overwritten.
        let conflicting = observation("idemp:a", ObservationKind::Delivered)?;
        assert!(append(&root.0, &conflicting).is_err());
        assert_eq!(load(&root.0)?.len(), 2);
        assert!(delivered.matches(&delivered.intent));
        assert_ne!(delivered.proof_digest(), failed.proof_digest());
        Ok(())
    }

    #[test]
    fn malformed_records_are_refused() -> Result<(), String> {
        let good = observation("idemp:a", ObservationKind::Delivered)?;
        let mut bytes = good.canonical_bytes();
        bytes.push(0);
        assert!(ProviderObservation::decode(&bytes).is_err());
        // A delivery may not carry an error code.
        let mut bad = good;
        bad.error_code = "x".to_owned();
        assert!(ProviderObservation::decode(&bad.canonical_bytes()).is_err());
        Ok(())
    }
}
