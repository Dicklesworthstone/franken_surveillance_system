//! Exact content-bound continuation cursors and deterministic bounded streams.

use core::fmt;

use crate::{
    CanonicalEncode, CanonicalEncoder, ContentDigest, ContractBasis, ContractError, LedgerAnchor,
    RecoveryClass, SessionId, TimestampNs,
};

/// Semantic stream resumed by a continuation cursor.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ContinuationScope {
    /// Optional detail omitted from a semantic context pack.
    ContextExpansion,
    /// Detail backing one meaningful-delta pulse.
    MeaningfulDelta,
    /// A long-lived mission follow stream.
    FollowStream,
    /// Child roots required to hydrate a handoff.
    HandoffHydration,
    /// A bounded investigation-result stream.
    Investigation,
}

impl ContinuationScope {
    /// Returns the stable schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ContextExpansion => "context_expansion",
            Self::MeaningfulDelta => "meaningful_delta",
            Self::FollowStream => "follow_stream",
            Self::HandoffHydration => "handoff_hydration",
            Self::Investigation => "investigation",
        }
    }
}

impl CanonicalEncode for ContinuationScope {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
    }
}

/// Stable continuation failures with explicit retry/rebase guidance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContinuationError {
    /// Shared semantic contract failure.
    Contract(ContractError),
    /// The cursor expired and must be rebased from current authority.
    Expired,
    /// The cursor belongs to another stream, session, view, or source root.
    WrongStream,
    /// Resume position or anchor did not advance monotonically.
    NonMonotone,
    /// Resume position exceeds the immutable stream bound.
    OutOfRange,
}

impl ContinuationError {
    /// Returns a stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Contract(error) => error.code(),
            Self::Expired => "continuation_expired",
            Self::WrongStream => "continuation_wrong_stream",
            Self::NonMonotone => "continuation_non_monotone",
            Self::OutOfRange => "continuation_out_of_range",
        }
    }

    /// Returns deterministic recovery guidance.
    #[must_use]
    pub const fn recovery(&self) -> RecoveryClass {
        match self {
            Self::Contract(ContractError::StaleAnchor) | Self::Expired | Self::WrongStream => {
                RecoveryClass::RebaseRequired
            }
            Self::Contract(ContractError::DigestMismatch) => RecoveryClass::RebaseRequired,
            Self::Contract(_) | Self::NonMonotone | Self::OutOfRange => {
                RecoveryClass::NeverUnchanged
            }
        }
    }
}

impl fmt::Display for ContinuationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ContinuationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::Expired | Self::WrongStream | Self::NonMonotone | Self::OutOfRange => None,
        }
    }
}

impl From<ContractError> for ContinuationError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}

/// Exact immutable cursor naming the next unread position of one source-rooted stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContinuationCursor {
    /// Stable token form, derived from the complete cursor body.
    pub cursor_id: String,
    /// Semantic stream class.
    pub scope: ContinuationScope,
    /// Stable stream identity.
    pub stream_id: String,
    /// Exact semantic contract universe.
    pub contract_basis: ContractBasis,
    /// Owning session.
    pub session_id: SessionId,
    /// Registered view identity.
    pub view_id: String,
    /// Authority anchor at stream creation.
    pub basis_anchor: LedgerAnchor,
    /// Authority anchor through which this cursor is known complete.
    pub resume_anchor: LedgerAnchor,
    /// Digest of the complete immutable ordered stream.
    pub source_digest: ContentDigest,
    /// Zero-based next unread entry position.
    pub position: u64,
    /// Exclusive immutable upper bound.
    pub upper_bound: u64,
    /// Selection/comparison witness binding cursor semantics.
    pub selection_witness: ContentDigest,
    /// Digest of the immediate predecessor cursor, when advanced.
    pub predecessor_digest: Option<ContentDigest>,
    /// Deterministic issue time.
    pub issued_at: TimestampNs,
    /// Expiry time after which rebasing is required.
    pub expires_at: TimestampNs,
    /// Digest of the complete cursor body.
    pub cursor_digest: ContentDigest,
}

impl ContinuationCursor {
    /// Publishes an exact cursor after validating all monotonic bounds.
    #[allow(clippy::too_many_arguments)]
    pub fn publish(
        scope: ContinuationScope,
        stream_id: impl Into<String>,
        contract_basis: ContractBasis,
        session_id: SessionId,
        view_id: impl Into<String>,
        basis_anchor: LedgerAnchor,
        resume_anchor: LedgerAnchor,
        source_digest: ContentDigest,
        position: u64,
        upper_bound: u64,
        selection_witness: ContentDigest,
        predecessor_digest: Option<ContentDigest>,
        issued_at: TimestampNs,
        expires_at: TimestampNs,
    ) -> Result<Self, ContinuationError> {
        let mut cursor = Self {
            cursor_id: String::new(),
            scope,
            stream_id: stream_id.into(),
            contract_basis,
            session_id,
            view_id: view_id.into(),
            basis_anchor,
            resume_anchor,
            source_digest,
            position,
            upper_bound,
            selection_witness,
            predecessor_digest,
            issued_at,
            expires_at,
            cursor_digest: ContentDigest::sha256(b"unpublished-continuation"),
        };
        cursor.validate_body()?;
        cursor.cursor_digest = cursor.computed_digest();
        cursor.cursor_id = format!("continuation:{}", cursor.cursor_digest);
        Ok(cursor)
    }

    /// Recomputes the body digest with identity fields omitted.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        self.encode_body(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }

    /// Verifies content identity, monotonic bounds, and expiry at a supplied time.
    pub fn validate_at(&self, now: TimestampNs) -> Result<(), ContinuationError> {
        self.validate_body()?;
        if self.cursor_digest != self.computed_digest()
            || self.cursor_id != format!("continuation:{}", self.cursor_digest)
        {
            return Err(ContractError::DigestMismatch.into());
        }
        if now < self.issued_at {
            return Err(ContractError::InvertedTimeInterval.into());
        }
        if now > self.expires_at {
            return Err(ContinuationError::Expired);
        }
        Ok(())
    }

    /// Returns the stable token carried by response and delta envelopes.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.cursor_id
    }

    /// Returns true when the cursor has consumed the complete bounded stream.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.position == self.upper_bound
    }

    /// Advances within the same immutable stream while linking the predecessor cursor.
    pub fn advance(
        &self,
        new_position: u64,
        new_resume_anchor: LedgerAnchor,
        selection_witness: ContentDigest,
        issued_at: TimestampNs,
        expires_at: TimestampNs,
    ) -> Result<Self, ContinuationError> {
        self.validate_at(issued_at)?;
        if new_resume_anchor.site_lineage != self.resume_anchor.site_lineage
            || new_resume_anchor.ledger_epoch != self.resume_anchor.ledger_epoch
            || new_position > self.upper_bound
            || new_resume_anchor.commit_sequence < self.resume_anchor.commit_sequence
            || (new_resume_anchor.commit_sequence == self.resume_anchor.commit_sequence
                && new_position <= self.position)
        {
            return Err(if new_position > self.upper_bound {
                ContinuationError::OutOfRange
            } else {
                ContinuationError::NonMonotone
            });
        }
        Self::publish(
            self.scope,
            self.stream_id.clone(),
            self.contract_basis.clone(),
            self.session_id.clone(),
            self.view_id.clone(),
            self.basis_anchor.clone(),
            new_resume_anchor,
            self.source_digest,
            new_position,
            self.upper_bound,
            selection_witness,
            Some(self.cursor_digest),
            issued_at,
            expires_at,
        )
    }

    fn validate_body(&self) -> Result<(), ContinuationError> {
        if self.stream_id.is_empty()
            || self.view_id.is_empty()
            || self.contract_basis.semantic_protocol != "fss/1"
            || self.position > self.upper_bound
            || self.basis_anchor.site_lineage != self.resume_anchor.site_lineage
            || self.basis_anchor.ledger_epoch != self.resume_anchor.ledger_epoch
            || self.resume_anchor.commit_sequence < self.basis_anchor.commit_sequence
            || self.expires_at <= self.issued_at
        {
            return Err(ContractError::InvalidAnchorSuccessor.into());
        }
        Ok(())
    }

    fn encode_body(&self, encoder: &mut CanonicalEncoder) {
        encoder.text("fss.continuation_cursor.v1");
        self.scope.encode_canonical(encoder);
        encoder.text(&self.stream_id);
        self.contract_basis.encode_canonical(encoder);
        self.session_id.encode_canonical(encoder);
        encoder.text(&self.view_id);
        self.basis_anchor.encode_canonical(encoder);
        self.resume_anchor.encode_canonical(encoder);
        encoder.digest(self.source_digest);
        encoder.u64(self.position);
        encoder.u64(self.upper_bound);
        encoder.digest(self.selection_witness);
        match self.predecessor_digest {
            Some(value) => {
                encoder.bool(true);
                encoder.digest(value);
            }
            None => encoder.bool(false),
        }
        self.issued_at.encode_canonical(encoder);
        self.expires_at.encode_canonical(encoder);
    }
}

impl CanonicalEncode for ContinuationCursor {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.encode_body(encoder);
        encoder.digest(self.cursor_digest);
    }
}

/// One immutable item in a continuation stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContinuationEntry {
    /// Contiguous zero-based sequence.
    pub sequence: u64,
    /// Stable semantic class.
    pub class: String,
    /// Digest of the immutable payload or referenced semantic object.
    pub payload_digest: ContentDigest,
    /// Whether omission would violate a hard safety or correctness clamp.
    pub critical: bool,
}

impl ContinuationEntry {
    /// Constructs one bounded stream entry.
    pub fn new(
        sequence: u64,
        class: impl Into<String>,
        payload_digest: ContentDigest,
        critical: bool,
    ) -> Result<Self, ContinuationError> {
        let entry = Self {
            sequence,
            class: class.into(),
            payload_digest,
            critical,
        };
        if entry.class.is_empty() {
            return Err(ContractError::EvidenceRequired.into());
        }
        Ok(entry)
    }
}

impl CanonicalEncode for ContinuationEntry {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.sequence);
        encoder.text(&self.class);
        encoder.digest(self.payload_digest);
        encoder.bool(self.critical);
    }
}

/// Immutable deterministic stream serving exact bounded pages by cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContinuationStream {
    /// Stable stream identity.
    pub stream_id: String,
    /// Semantic stream class.
    pub scope: ContinuationScope,
    /// Exact semantic contract universe.
    pub contract_basis: ContractBasis,
    /// Owning session.
    pub session_id: SessionId,
    /// Registered view identity.
    pub view_id: String,
    /// Authority anchor at stream creation.
    pub anchor: LedgerAnchor,
    /// Canonically ordered immutable entries.
    pub entries: Vec<ContinuationEntry>,
    /// Maximum entries returned per page.
    pub page_size: u32,
    /// Selection/comparison witness for the complete stream.
    pub selection_witness: ContentDigest,
    /// Issue time shared by every deterministic page cursor.
    pub issued_at: TimestampNs,
    /// Stream expiry.
    pub expires_at: TimestampNs,
    /// Digest of the complete immutable ordered stream.
    pub source_digest: ContentDigest,
}

impl ContinuationStream {
    /// Publishes a bounded immutable stream after sorting and validating contiguous entries.
    #[allow(clippy::too_many_arguments)]
    pub fn publish(
        stream_id: impl Into<String>,
        scope: ContinuationScope,
        contract_basis: ContractBasis,
        session_id: SessionId,
        view_id: impl Into<String>,
        anchor: LedgerAnchor,
        mut entries: Vec<ContinuationEntry>,
        page_size: u32,
        selection_witness: ContentDigest,
        issued_at: TimestampNs,
        expires_at: TimestampNs,
    ) -> Result<Self, ContinuationError> {
        entries.sort_by_key(|entry| entry.sequence);
        for (index, entry) in entries.iter().enumerate() {
            if entry.sequence != index as u64 {
                return Err(ContractError::NonCanonicalOrdering.into());
            }
        }
        let mut stream = Self {
            stream_id: stream_id.into(),
            scope,
            contract_basis,
            session_id,
            view_id: view_id.into(),
            anchor,
            entries,
            page_size,
            selection_witness,
            issued_at,
            expires_at,
            source_digest: ContentDigest::sha256(b"unpublished-continuation-stream"),
        };
        stream.validate_body()?;
        stream.source_digest = stream.computed_source_digest();
        Ok(stream)
    }

    /// Returns the exact initial cursor.
    pub fn initial_cursor(&self) -> Result<ContinuationCursor, ContinuationError> {
        self.validate_body()?;
        ContinuationCursor::publish(
            self.scope,
            self.stream_id.clone(),
            self.contract_basis.clone(),
            self.session_id.clone(),
            self.view_id.clone(),
            self.anchor.clone(),
            self.anchor.clone(),
            self.source_digest,
            0,
            self.entries.len() as u64,
            self.selection_witness,
            None,
            self.issued_at,
            self.expires_at,
        )
    }

    /// Reads one deterministic page and returns the exact next cursor when entries remain.
    pub fn read_page(
        &self,
        cursor: &ContinuationCursor,
        now: TimestampNs,
    ) -> Result<ContinuationPage, ContinuationError> {
        self.validate_body()?;
        cursor.validate_at(now)?;
        if cursor.scope != self.scope
            || cursor.stream_id != self.stream_id
            || cursor.contract_basis != self.contract_basis
            || cursor.session_id != self.session_id
            || cursor.view_id != self.view_id
            || cursor.basis_anchor != self.anchor
            || cursor.resume_anchor != self.anchor
            || cursor.source_digest != self.source_digest
            || cursor.upper_bound != self.entries.len() as u64
            || cursor.selection_witness != self.selection_witness
        {
            return Err(ContinuationError::WrongStream);
        }
        let start = usize::try_from(cursor.position)
            .map_err(|_| ContinuationError::OutOfRange)?;
        if start > self.entries.len() {
            return Err(ContinuationError::OutOfRange);
        }
        let end = start
            .saturating_add(self.page_size as usize)
            .min(self.entries.len());
        let entries = self.entries[start..end].to_vec();
        let next_cursor = if end < self.entries.len() {
            Some(cursor.advance(
                end as u64,
                self.anchor.clone(),
                self.selection_witness,
                self.issued_at,
                self.expires_at,
            )?)
        } else {
            None
        };
        let mut page = ContinuationPage {
            stream_id: self.stream_id.clone(),
            cursor_digest: cursor.cursor_digest,
            entries,
            next_cursor,
            page_digest: ContentDigest::sha256(b"unpublished-continuation-page"),
        };
        page.page_digest = page.computed_digest();
        Ok(page)
    }

    /// Recomputes the immutable stream root.
    #[must_use]
    pub fn computed_source_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.continuation_stream.v1");
        encoder.text(&self.stream_id);
        self.scope.encode_canonical(&mut encoder);
        self.contract_basis.encode_canonical(&mut encoder);
        self.session_id.encode_canonical(&mut encoder);
        encoder.text(&self.view_id);
        self.anchor.encode_canonical(&mut encoder);
        encoder.u64(self.entries.len() as u64);
        for entry in &self.entries {
            entry.encode_canonical(&mut encoder);
        }
        encoder.u32(self.page_size);
        encoder.digest(self.selection_witness);
        self.issued_at.encode_canonical(&mut encoder);
        self.expires_at.encode_canonical(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }

    /// Verifies the complete immutable stream root and bounds.
    pub fn verify(&self) -> Result<(), ContinuationError> {
        self.validate_body()?;
        if self.source_digest != self.computed_source_digest() {
            return Err(ContractError::DigestMismatch.into());
        }
        Ok(())
    }

    fn validate_body(&self) -> Result<(), ContinuationError> {
        if self.stream_id.is_empty()
            || self.view_id.is_empty()
            || self.contract_basis.semantic_protocol != "fss/1"
            || self.page_size == 0
            || self.expires_at <= self.issued_at
        {
            return Err(ContractError::EvidenceRequired.into());
        }
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.sequence != index as u64 || entry.class.is_empty() {
                return Err(ContractError::NonCanonicalOrdering.into());
            }
        }
        Ok(())
    }
}

/// One exact deterministic page produced from a continuation cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContinuationPage {
    /// Stable stream identity.
    pub stream_id: String,
    /// Cursor consumed to produce this page.
    pub cursor_digest: ContentDigest,
    /// Contiguous entries returned.
    pub entries: Vec<ContinuationEntry>,
    /// Exact next cursor, absent at end of stream.
    pub next_cursor: Option<ContinuationCursor>,
    /// Digest of the complete page.
    pub page_digest: ContentDigest,
}

impl ContinuationPage {
    /// Recomputes the page digest with the digest field omitted.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.continuation_page.v1");
        encoder.text(&self.stream_id);
        encoder.digest(self.cursor_digest);
        encoder.u64(self.entries.len() as u64);
        for entry in &self.entries {
            entry.encode_canonical(&mut encoder);
        }
        match &self.next_cursor {
            Some(cursor) => {
                encoder.bool(true);
                cursor.encode_canonical(&mut encoder);
            }
            None => encoder.bool(false),
        }
        ContentDigest::sha256(&encoder.finish())
    }

    /// Verifies page identity.
    pub fn verify(&self) -> Result<(), ContinuationError> {
        if self.stream_id.is_empty() || self.page_digest != self.computed_digest() {
            return Err(ContractError::DigestMismatch.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basis() -> ContractBasis {
        ContractBasis::from_registry_bytes(
            b"schemas",
            b"operations",
            b"views",
            b"capabilities",
            b"errors",
            b"costs",
            "fss:test",
            None,
        )
    }

    fn stream() -> Result<ContinuationStream, ContinuationError> {
        ContinuationStream::publish(
            "stream:test",
            ContinuationScope::MeaningfulDelta,
            basis(),
            SessionId::parse("session:test")?,
            "AVIEW-001",
            LedgerAnchor::genesis("site:test"),
            vec![
                ContinuationEntry::new(0, "first", ContentDigest::sha256(b"first"), true)?,
                ContinuationEntry::new(1, "second", ContentDigest::sha256(b"second"), false)?,
                ContinuationEntry::new(2, "third", ContentDigest::sha256(b"third"), false)?,
            ],
            2,
            ContentDigest::sha256(b"selection"),
            TimestampNs(10),
            TimestampNs(100),
        )
    }

    #[test]
    fn replaying_the_same_cursor_returns_the_same_page() -> Result<(), ContinuationError> {
        let stream = stream()?;
        let cursor = stream.initial_cursor()?;
        let first = stream.read_page(&cursor, TimestampNs(20))?;
        let replay = stream.read_page(&cursor, TimestampNs(20))?;
        assert_eq!(first, replay);
        assert_eq!(first.entries.len(), 2);
        let next = first.next_cursor.ok_or(ContinuationError::OutOfRange)?;
        assert_eq!(next.predecessor_digest, Some(cursor.cursor_digest));
        let terminal = stream.read_page(&next, TimestampNs(20))?;
        assert_eq!(terminal.entries.len(), 1);
        assert!(terminal.next_cursor.is_none());
        first.verify()?;
        terminal.verify()
    }

    #[test]
    fn tampering_and_cross_stream_reuse_fail_closed() -> Result<(), ContinuationError> {
        let stream = stream()?;
        let mut cursor = stream.initial_cursor()?;
        cursor.position = 1;
        assert!(matches!(
            stream.read_page(&cursor, TimestampNs(20)),
            Err(ContinuationError::Contract(ContractError::DigestMismatch))
        ));

        let other = ContinuationStream::publish(
            "stream:other",
            ContinuationScope::MeaningfulDelta,
            basis(),
            SessionId::parse("session:test")?,
            "AVIEW-001",
            LedgerAnchor::genesis("site:test"),
            Vec::new(),
            1,
            ContentDigest::sha256(b"selection"),
            TimestampNs(10),
            TimestampNs(100),
        )?;
        let valid = stream.initial_cursor()?;
        assert_eq!(
            other.read_page(&valid, TimestampNs(20)),
            Err(ContinuationError::WrongStream)
        );
        Ok(())
    }

    #[test]
    fn expiry_and_nonmonotone_advance_require_rebase() -> Result<(), ContinuationError> {
        let stream = stream()?;
        let cursor = stream.initial_cursor()?;
        assert_eq!(
            stream.read_page(&cursor, TimestampNs(101)),
            Err(ContinuationError::Expired)
        );
        assert_eq!(
            cursor.advance(
                0,
                cursor.resume_anchor.clone(),
                cursor.selection_witness,
                TimestampNs(20),
                TimestampNs(100),
            ),
            Err(ContinuationError::NonMonotone)
        );
        assert_eq!(ContinuationError::Expired.recovery(), RecoveryClass::RebaseRequired);
        Ok(())
    }
}
