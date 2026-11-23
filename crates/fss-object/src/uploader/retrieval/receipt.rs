#![forbid(unsafe_code)]
//! Strict, payload-free evidence for one independent byte verification attempt.

use super::*;

/// Maximum canonical receipt size, independent of media length.
pub const MAX_RETRIEVAL_RECEIPT_BYTES: usize = 64 * 1024;
const DOMAIN: &str = "fss.multipart_retrieval_observation.v1";
const OBSERVED_DOMAIN: &str = "fss.multipart_retrieval_observation.v2";

impl RetrievalReceipt {
    /// Strict canonical decoding rejects trailing, truncated or excessive input.
    /// Consumers still bind source pins to independently trusted custody.
    pub fn decode(bytes: &[u8]) -> Result<Self, MultipartError> {
        if bytes.len() > MAX_RETRIEVAL_RECEIPT_BYTES {
            return Err(MultipartError::InvalidCheckpoint);
        }
        let mut d = CanonicalDecoder::new(bytes);
        let observed = match d.text().map_err(checkpoint_error)? {
            DOMAIN => false,
            OBSERVED_DOMAIN => true,
            _ => return Err(MultipartError::InvalidCheckpoint),
        };
        let source_pin = UploadJournalPin {
            sequence: d.u64().map_err(checkpoint_error)?,
            root: d.digest().map_err(checkpoint_error)?,
        };
        let source_operation =
            OperationId::parse(d.text().map_err(checkpoint_error)?).map_err(checkpoint_error)?;
        let completion_digest = d.digest().map_err(checkpoint_error)?;
        let completion_observation = if observed {
            Some((
                d.digest().map_err(checkpoint_error)?,
                d.digest().map_err(checkpoint_error)?,
            ))
        } else {
            None
        };
        let origin = d.digest().map_err(checkpoint_error)?;
        let intent_digest = d.digest().map_err(checkpoint_error)?;
        let plan_digest = d.digest().map_err(checkpoint_error)?;
        let manifest_root = d.digest().map_err(checkpoint_error)?;
        let expected_digest = d.digest().map_err(checkpoint_error)?;
        let expected_bytes = d.u64().map_err(checkpoint_error)?;
        let expected_parts = d.u64().map_err(checkpoint_error)?;
        let authority = ContextAuthority::decode_canonical(&mut d).map_err(checkpoint_error)?;
        let started_at = TimestampNs(d.i128().map_err(checkpoint_error)?);
        let observed_at = TimestampNs(d.i128().map_err(checkpoint_error)?);
        let consumed = <BudgetVector as CanonicalDecode>::decode_canonical(&mut d)
            .map_err(checkpoint_error)?;
        let outcome = match d.u8().map_err(checkpoint_error)? {
            0 => RetrievalOutcome::NotObserved,
            1 => RetrievalOutcome::Unknown,
            2 => RetrievalOutcome::Mismatch,
            3 => RetrievalOutcome::Verified,
            _ => return Err(MultipartError::InvalidCheckpoint),
        };
        let attempted_ranges = d.u64().map_err(checkpoint_error)?;
        let bytes_read = d.u64().map_err(checkpoint_error)?;
        let verified_parts = d.u64().map_err(checkpoint_error)?;
        d.ensure_finished().map_err(checkpoint_error)?;
        let receipt = Self {
            source_pin,
            source_operation,
            completion_digest,
            completion_observation,
            origin,
            intent_digest,
            plan_digest,
            manifest_root,
            expected_digest,
            expected_bytes,
            expected_parts,
            authority,
            started_at,
            observed_at,
            consumed,
            outcome,
            attempted_ranges,
            bytes_read,
            verified_parts,
        };
        if receipt.encode()? != bytes {
            return Err(MultipartError::InvalidCheckpoint);
        }
        Ok(receipt)
    }
}

impl RetrievalReceipt {
    /// Exact unchanged source journal head.
    #[must_use]
    pub const fn source_pin(&self) -> UploadJournalPin {
        self.source_pin
    }
    /// Exact completion inventory, established locally or by the pinned observer.
    #[must_use]
    pub const fn completion_digest(&self) -> ContentDigest {
        self.completion_digest
    }
    /// Independently pinned completion observation; absent for a locally completed upload.
    #[must_use]
    pub fn completion_observation_digest(&self) -> Option<ContentDigest> {
        self.completion_observation.map(|value| value.0)
    }
    /// Original indeterminate closure proof, retained without replacement.
    #[must_use]
    pub fn indeterminate_receipt_digest(&self) -> Option<ContentDigest> {
        self.completion_observation.map(|value| value.1)
    }
    /// Stable journal custody origin signed before upload.
    #[must_use]
    pub const fn origin(&self) -> ContentDigest {
        self.origin
    }
    /// Original immutable upload intent.
    #[must_use]
    pub const fn intent_digest(&self) -> ContentDigest {
        self.intent_digest
    }
    /// Original immutable chunk plan.
    #[must_use]
    pub const fn plan_digest(&self) -> ContentDigest {
        self.plan_digest
    }
    /// Original manifest identity, not graph closure proof.
    #[must_use]
    pub const fn manifest_root(&self) -> ContentDigest {
        self.manifest_root
    }
    /// Independent whole-object digest, verified only on Verified outcome.
    #[must_use]
    pub const fn expected_digest(&self) -> ContentDigest {
        self.expected_digest
    }
    /// Exact required complete object length.
    #[must_use]
    pub const fn expected_bytes(&self) -> u64 {
        self.expected_bytes
    }
    /// Original acknowledged part count.
    #[must_use]
    pub const fn expected_parts(&self) -> u64 {
        self.expected_parts
    }
    /// Fresh read reservation time.
    #[must_use]
    pub const fn started_at(&self) -> TimestampNs {
        self.started_at
    }
    /// Last observed boundary, including failed checkpoints.
    #[must_use]
    pub const fn observed_at(&self) -> TimestampNs {
        self.observed_at
    }
    /// Fresh work admitted, including failed reads.
    #[must_use]
    pub const fn consumed(&self) -> BudgetVector {
        self.consumed
    }
    /// Complete, inconclusive, mismatching or undispatched read outcome.
    #[must_use]
    pub const fn outcome(&self) -> RetrievalOutcome {
        self.outcome
    }
    /// Separately admitted ranges, without retries.
    #[must_use]
    pub const fn attempted_ranges(&self) -> u64 {
        self.attempted_ranges
    }
    /// Exact-length bytes hashed; partial bytes prove no complete retrieval.
    #[must_use]
    pub const fn bytes_read(&self) -> u64 {
        self.bytes_read
    }
    /// Parts whose computed checksum matched original evidence.
    #[must_use]
    pub const fn verified_parts(&self) -> u64 {
        self.verified_parts
    }

    /// Original upload operation, never reactivated.
    #[must_use]
    pub fn source_operation(&self) -> &OperationId {
        &self.source_operation
    }
    /// New read operation, distinct from the upload.
    #[must_use]
    pub fn operation(&self) -> &OperationId {
        &self.authority.operation_id
    }
    /// Complete inert identity/privacy/retention/authority recipe.
    #[must_use]
    pub fn authority(&self) -> &ContextAuthority {
        &self.authority
    }
    /// Separate read ceiling; original upload work is unaffected.
    #[must_use]
    pub const fn budget(&self) -> BudgetVector {
        self.authority.budgets
    }
    /// Identity of the complete scoped receipt.
    pub fn digest(&self) -> Result<ContentDigest, MultipartError> {
        Ok(ContentDigest::sha256(&self.encode()?))
    }

    /// Canonical bounded bytes contain no paths, provider tokens, credentials or media.
    pub fn encode(&self) -> Result<Vec<u8>, MultipartError> {
        self.validate()?;
        let mut e = CanonicalEncoder::new();
        e.text(if self.completion_observation.is_some() {
            OBSERVED_DOMAIN
        } else {
            DOMAIN
        });
        e.u64(self.source_pin.sequence);
        e.digest(self.source_pin.root);
        e.text(self.source_operation.as_str());
        e.digest(self.completion_digest);
        if let Some((observation, indeterminate)) = self.completion_observation {
            e.digest(observation);
            e.digest(indeterminate);
        }
        for digest in [
            self.origin,
            self.intent_digest,
            self.plan_digest,
            self.manifest_root,
            self.expected_digest,
        ] {
            e.digest(digest);
        }
        e.u64(self.expected_bytes);
        e.u64(self.expected_parts);
        self.authority.encode_canonical(&mut e);
        e.i128(self.started_at.0);
        e.i128(self.observed_at.0);
        self.consumed.encode_canonical(&mut e);
        e.u8(match self.outcome {
            RetrievalOutcome::NotObserved => 0,
            RetrievalOutcome::Unknown => 1,
            RetrievalOutcome::Mismatch => 2,
            RetrievalOutcome::Verified => 3,
        });
        e.u64(self.attempted_ranges);
        e.u64(self.bytes_read);
        e.u64(self.verified_parts);
        let bytes = e.finish_checked().map_err(checkpoint_error)?;
        if bytes.len() > MAX_RETRIEVAL_RECEIPT_BYTES {
            return Err(MultipartError::InvalidCheckpoint);
        }
        Ok(bytes)
    }
}

/// Byte verification is separate from completion and archive publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetrievalOutcome {
    /// No range was admitted; the historical upload is unchanged.
    NotObserved,
    /// A range was admitted but complete verification did not finish.
    Unknown,
    /// Returned length or computed bytes contradicted independent evidence.
    Mismatch,
    /// All original parts and the independent whole-object digest matched.
    Verified,
}

/// Immutable byte observation, not encryption, graph closure, replica or future
/// availability evidence. Decoding creates inert evidence, never live authority.
#[derive(Clone, Debug, PartialEq)]
pub struct RetrievalReceipt {
    pub(super) source_pin: UploadJournalPin,
    pub(super) source_operation: OperationId,
    pub(super) completion_digest: ContentDigest,
    pub(super) completion_observation: Option<(ContentDigest, ContentDigest)>,
    pub(super) origin: ContentDigest,
    pub(super) intent_digest: ContentDigest,
    pub(super) plan_digest: ContentDigest,
    pub(super) manifest_root: ContentDigest,
    pub(super) expected_digest: ContentDigest,
    pub(super) expected_bytes: u64,
    pub(super) expected_parts: u64,
    pub(super) authority: ContextAuthority,
    pub(super) started_at: TimestampNs,
    pub(super) observed_at: TimestampNs,
    pub(super) consumed: BudgetVector,
    pub(super) outcome: RetrievalOutcome,
    pub(super) attempted_ranges: u64,
    pub(super) bytes_read: u64,
    pub(super) verified_parts: u64,
}

impl RetrievalReceipt {
    pub(super) fn validate(&self) -> Result<(), MultipartError> {
        self.authority.validate().map_err(checkpoint_error)?;
        if self.source_pin.sequence == 0
            || self
                .completion_observation
                .is_some_and(|(observation, indeterminate)| {
                    !good_digest(observation) || !good_digest(indeterminate)
                })
            || ![
                self.source_pin.root,
                self.completion_digest,
                self.origin,
                self.intent_digest,
                self.plan_digest,
                self.manifest_root,
                self.expected_digest,
            ]
            .into_iter()
            .all(good_digest)
            || self.source_operation == self.authority.operation_id
            || self.authority.capabilities() != reader_capabilities()
            || self.authority.cancellation_reason.is_some()
            || self
                .authority
                .deadline
                .is_none_or(|at| at <= self.started_at)
            || self.started_at > self.observed_at
            || !(1..=MAX_RETRIEVAL_BYTES).contains(&self.expected_bytes)
            || !(1..=10_000).contains(&self.expected_parts)
            || self.expected_parts > self.expected_bytes
            || self.bytes_read > self.expected_bytes
            || self.verified_parts > self.expected_parts
            || self.verified_parts > self.attempted_ranges
            || self.attempted_ranges
                > self.expected_bytes.div_ceil(MAX_RETRIEVAL_RANGE_BYTES) + self.expected_parts
            || self.bytes_read
                > self
                    .attempted_ranges
                    .saturating_mul(MAX_RETRIEVAL_RANGE_BYTES)
            || !self.consumed.is_valid()
            || !self.consumed.fits_within(self.authority.budgets)
            || self.consumed.storage_operations != self.attempted_ranges
            || self.consumed.bytes < self.bytes_read
            || (self.outcome == RetrievalOutcome::NotObserved) != (self.attempted_ranges == 0)
            || (self.outcome == RetrievalOutcome::Verified
                && (self.bytes_read != self.expected_bytes
                    || self.verified_parts != self.expected_parts
                    || self
                        .authority
                        .deadline
                        .is_none_or(|at| self.observed_at >= at)))
        {
            return Err(MultipartError::InvalidCheckpoint);
        }
        Ok(())
    }
}
