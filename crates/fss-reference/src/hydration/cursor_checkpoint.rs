//! Bounded replay protection snapshots. No artifact or original-source payload is serialized.

use fss_core::{CanonicalDecoder, CanonicalEncoder};

use super::{ContentDigest, ContractError, HydrationError, IssuedCursorRecord,
    ReferenceHydrationCatalog, SessionId, TimestampNs};
use std::collections::BTreeMap;

const DOMAIN: &str = "fss.hydration_cursor_checkpoint.v1";
pub(crate) const MAX_RECORDS: usize = 65_536;
const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_TEXT: usize = 4_096;

/// Validated metadata only. Its checksum proves integrity, not authority to issue cursors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CursorCheckpoint {
    pub(crate) captured_at: TimestampNs,
    records: BTreeMap<ContentDigest, IssuedCursorRecord>,
}

impl CursorCheckpoint {
    pub(crate) fn decode(bytes: &[u8], max_bytes: usize, max_records: usize)
        -> Result<Self, HydrationError>
    {
        if bytes.len() > max_bytes.min(MAX_BYTES) {
            return Err(HydrationError::CapacityExceeded);
        }
        let mut outer = CanonicalDecoder::new(bytes);
        let body = outer.bytes()?;
        if outer.digest()? != ContentDigest::sha256(body) {
            return Err(ContractError::DigestMismatch.into());
        }
        outer.ensure_finished()?;
        let mut decoder = CanonicalDecoder::new(body);
        if decoder.text()? != DOMAIN {
            return Err(ContractError::GenerationConflict.into());
        }
        let captured_at = TimestampNs(decoder.i128()?);
        let count = usize::try_from(decoder.u64()?)
            .map_err(|_| HydrationError::CapacityExceeded)?;
        if count > max_records.min(MAX_RECORDS) || count > decoder.remaining() / 67 {
            return Err(HydrationError::CapacityExceeded);
        }
        let mut records = BTreeMap::new();
        let mut prior = None;
        for _ in 0..count {
            let cursor_digest = decoder.digest()?;
            if prior.is_some_and(|digest| digest >= cursor_digest) {
                return Err(ContractError::NonCanonicalOrdering.into());
            }
            prior = Some(cursor_digest);
            let session = decoder.text()?;
            let handle = decoder.text()?;
            if !valid_text(session) || !valid_text(handle) {
                return Err(ContractError::InvalidIdentifier.into());
            }
            let record = IssuedCursorRecord {
                cursor_digest,
                session_id: SessionId::parse(session)?,
                handle_id: handle.to_owned(),
                expires_at: TimestampNs(decoder.i128()?),
                next_ordinal: decoder.u8()?,
                consumed: decoder.bool()?,
            };
            if !(1..=4).contains(&record.next_ordinal) {
                return Err(HydrationError::WrongContinuation);
            }
            records.insert(cursor_digest, record);
        }
        decoder.ensure_finished()?;
        Ok(Self { captured_at, records })
    }

    fn encode(&self, max_bytes: usize) -> Result<Vec<u8>, HydrationError> {
        let ceiling = max_bytes.min(MAX_BYTES);
        // Account for both length prefixes, time, count, and the checksum before allocation.
        let mut length = 8 + 8 + DOMAIN.len() + 16 + 8 + 33;
        if self.records.len() > MAX_RECORDS {
            return Err(HydrationError::CapacityExceeded);
        }
        for record in self.records.values() {
            if !valid_text(record.session_id.as_str()) || !valid_text(&record.handle_id)
                || !(1..=4).contains(&record.next_ordinal)
            {
                return Err(HydrationError::WrongContinuation);
            }
            length = length.checked_add(67 + record.session_id.as_str().len() + record.handle_id.len())
                .ok_or(HydrationError::CapacityExceeded)?;
        }
        if length > ceiling {
            return Err(HydrationError::CapacityExceeded);
        }
        let mut encoder = CanonicalEncoder::new();
        encoder.text(DOMAIN);
        encoder.i128(self.captured_at.0);
        encoder.u64(self.records.len() as u64);
        for record in self.records.values() {
            encoder.digest(record.cursor_digest);
            encoder.text(record.session_id.as_str());
            encoder.text(&record.handle_id);
            encoder.i128(record.expires_at.0);
            encoder.u8(record.next_ordinal);
            encoder.bool(record.consumed);
        }
        let body = encoder.finish_checked()?;
        let mut outer = CanonicalEncoder::new();
        outer.bytes(&body);
        outer.digest(ContentDigest::sha256(&body));
        Ok(outer.finish_checked()?)
    }

    /// A later snapshot cannot forget live records, alter issuance, or undo consumption.
    pub(crate) fn validate_successor(&self, prior: &Self) -> Result<(), HydrationError> {
        if self.captured_at < prior.captured_at {
            return Err(ContractError::StaleAnchor.into());
        }
        self.validate_resident(&prior.records)
    }

    fn validate_resident(&self, resident: &BTreeMap<ContentDigest, IssuedCursorRecord>)
        -> Result<(), HydrationError>
    {
        for (digest, old) in resident {
            match self.records.get(digest) {
                Some(new) if same_issuance(old, new) && (!old.consumed || new.consumed) => {}
                None if old.expires_at <= self.captured_at => {}
                _ => return Err(HydrationError::WrongContinuation),
            }
        }
        Ok(())
    }
}

impl ReferenceHydrationCatalog {
    /// Exports bounded, checksummed issuance/consumption metadata without copying payloads.
    ///
    /// `now` is the authority owner's trusted nondecreasing clock. This does not persist data.
    /// A durable owner must commit this snapshot atomically with disclosure charges before
    /// releasing a response, and retain the exact latest checkpoint identity across recovery.
    pub fn checkpoint_cursors(&self, now: TimestampNs, max_bytes: usize)
        -> Result<Vec<u8>, HydrationError>
    {
        CursorCheckpoint { captured_at: now, records: self.issued_cursors.clone() }.encode(max_bytes)
    }

    /// Restores replay protection from a trusted latest checkpoint, without restoring grants.
    ///
    /// This is an authority-owned recovery boundary, NOT a request-facing import operation.
    /// A checksum is not authorization: only the owning durable journal may select these bytes.
    /// Current descriptors, artifacts, source custody, session authority, and leases must still
    /// be rebuilt and revalidated by their existing owners. No source payload is restored.
    /// Resident consumed records cannot become active; unjournaled live records cause refusal.
    /// All validation and allocation precede mutation. `now` cannot precede capture time.
    pub fn restore_cursor_checkpoint(&mut self, bytes: &[u8], max_bytes: usize, now: TimestampNs)
        -> Result<(), HydrationError>
    {
        let checkpoint = CursorCheckpoint::decode(bytes, max_bytes, self.limits.max_issued_cursors)?;
        if now < checkpoint.captured_at {
            return Err(ContractError::StaleAnchor.into());
        }
        checkpoint.validate_resident(&self.issued_cursors)?;
        self.issued_cursors = checkpoint.records;
        Ok(())
    }
}

fn valid_text(text: &str) -> bool {
    !text.is_empty() && text.len() <= MAX_TEXT && !text.bytes().any(|b| b.is_ascii_control())
}

fn same_issuance(a: &IssuedCursorRecord, b: &IssuedCursorRecord) -> bool {
    a.cursor_digest == b.cursor_digest && a.session_id == b.session_id
        && a.handle_id == b.handle_id && a.expires_at == b.expires_at
        && a.next_ordinal == b.next_ordinal
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn catalog(consumed: bool) -> Result<ReferenceHydrationCatalog, HydrationError> {
        let mut catalog = ReferenceHydrationCatalog::new();
        let digest = ContentDigest::sha256(b"issued cursor");
        catalog.issued_cursors.insert(digest, IssuedCursorRecord {
            cursor_digest: digest, session_id: SessionId::parse("session:checkpoint")?,
            handle_id: "handle:checkpoint".to_owned(), expires_at: TimestampNs(100),
            next_ordinal: 3, consumed,
        });
        Ok(catalog)
    }

    #[test]
    fn deterministic_roundtrip_preserves_consumed_tombstones_without_payloads() -> TestResult {
        for consumed in [false, true] {
            let catalog = catalog(consumed)?;
            let bytes = catalog.checkpoint_cursors(TimestampNs(20), 4096)?;
            assert_eq!(bytes, catalog.checkpoint_cursors(TimestampNs(20), 4096)?);
            let mut recovered = ReferenceHydrationCatalog::new();
            recovered.restore_cursor_checkpoint(&bytes, 4096, TimestampNs(21))?;
            assert_eq!(catalog.issued_cursors, recovered.issued_cursors);
            assert_eq!(recovered.stored_payload_bytes(), 0);
            assert!(recovered.descriptors.is_empty());
            assert!(recovered.source_bindings.is_empty());
        }
        Ok(())
    }

    #[test]
    fn every_truncation_corruption_and_trailing_byte_is_rejected() -> TestResult {
        let bytes = catalog(true)?.checkpoint_cursors(TimestampNs(20), 4096)?;
        for end in 0..bytes.len() {
            assert!(CursorCheckpoint::decode(&bytes[..end], 4096, 10).is_err());
        }
        for index in 0..bytes.len() {
            let mut corrupt = bytes.clone(); corrupt[index] ^= 1;
            assert!(CursorCheckpoint::decode(&corrupt, 4096, 10).is_err());
        }
        let mut trailing = bytes; trailing.push(0);
        assert!(CursorCheckpoint::decode(&trailing, 4096, 10).is_err());
        Ok(())
    }

    #[test]
    fn rollback_rebinding_and_live_record_omission_leave_catalog_unchanged() -> TestResult {
        let mut resident = catalog(true)?;
        let before = resident.issued_cursors.clone();
        let active = catalog(false)?.checkpoint_cursors(TimestampNs(20), 4096)?;
        assert!(resident.restore_cursor_checkpoint(&active, 4096, TimestampNs(21)).is_err());
        let empty = ReferenceHydrationCatalog::new().checkpoint_cursors(TimestampNs(20), 4096)?;
        assert!(resident.restore_cursor_checkpoint(&empty, 4096, TimestampNs(21)).is_err());
        let mut rebound = catalog(true)?;
        for record in rebound.issued_cursors.values_mut() { record.handle_id.push_str(":other"); }
        let changed = rebound.checkpoint_cursors(TimestampNs(20), 4096)?;
        assert!(resident.restore_cursor_checkpoint(&changed, 4096, TimestampNs(21)).is_err());
        assert_eq!(resident.issued_cursors, before);
        Ok(())
    }

    #[test]
    fn capture_clock_capacity_and_expired_retirement_are_explicit() -> TestResult {
        let mut catalog = catalog(true)?;
        let bytes = catalog.checkpoint_cursors(TimestampNs(20), 4096)?;
        assert!(catalog.checkpoint_cursors(TimestampNs(20), bytes.len() - 1).is_err());
        assert!(catalog.restore_cursor_checkpoint(&bytes, 4096, TimestampNs(19)).is_err());
        assert!(CursorCheckpoint::decode(&bytes, 4096, 0).is_err());
        let prior = CursorCheckpoint::decode(&bytes, 4096, 10)?;
        let empty = ReferenceHydrationCatalog::new().checkpoint_cursors(TimestampNs(100), 4096)?;
        let successor = CursorCheckpoint::decode(&empty, 4096, 10)?;
        successor.validate_successor(&prior)?;
        assert!(prior.validate_successor(&successor).is_err());
        catalog.restore_cursor_checkpoint(&empty, 4096, TimestampNs(100))?;
        assert_eq!(catalog.issued_cursor_count(), 0);
        Ok(())
    }
}
