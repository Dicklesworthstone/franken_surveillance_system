#![forbid(unsafe_code)]
//! Source custody is pinned at registration, not only when a later disclosure happens.
//! Uses the same sole-writer journal and append reconciliation as charged disclosures.

use super::*;
use crate::SourceObjectBinding;
use fss_core::{ContractError, HandleAvailability};

const DOMAIN: &str = "fss.reference_source_registration.v1";

/// Acknowledgement that one exact custody requirement reached the existing protected journal.
///
/// This is neither a disclosure admission nor a read grant. No payload, session charge or cursor
/// is created by registration. Retain the journal root independently for cold recovery.
#[derive(Debug)]
pub struct JournaledSourceBinding {
    /// Freshly checked binding metadata; source bytes are not retained here.
    pub binding: SourceObjectBinding,
    /// Exact authority-projected descriptor whose requirement was committed.
    pub descriptor_digest: ContentDigest,
    /// Owner-supplied time committed for this registration.
    pub registered_at: TimestampNs,
    /// Confirmed journal root after registration. It is not an authentication token.
    pub committed_root: ContentDigest,
}

impl DurableDisclosureStore {
    /// Checks live custody and commits its requirement BEFORE acknowledging registration.
    ///
    /// This authority-owned operation may run before any session or disclosure exists. It pins
    /// only the selected descriptor, not other volatile bindings in the catalog. Session state,
    /// charges, active/consumed cursors and old custody requirements remain unchanged. The clock
    /// must not precede the last registration/disclosure or the descriptor's publication time;
    /// unavailable or expired sources are not admitted.
    ///
    /// Every retry rechecks custody and appends a bounded registration record, even when its
    /// requirement is already pinned. The supplied reader owns source budgets and cancellation.
    /// Append uncertainty fences the owner; reconciliation installs only the committed requirement,
    /// never replays source I/O or acknowledges a discarded binding. An absent source need not be
    /// reconstructed to reopen, but later reconstruction must meet the saved requirement.
    pub fn bind_source_object_durable(
        &mut self,
        handle: &str,
        descriptor_digest: ContentDigest,
        publication_root: ContentDigest,
        reader: &dyn PublishedSourceReader,
        now: TimestampNs,
    ) -> Result<JournaledSourceBinding, DisclosureError> {
        self.sessions.preflight()?;
        self.synchronize_catalog(Some(now))?;
        // Refuse known-full journals before asking the source owner to spend any native work.
        // Exact payload capacity is checked again by commit_candidate after encoding.
        super::super::check_capacity(
            self.sessions.journal.committed_len(),
            self.sessions.records,
            0,
            self.sessions.limits,
        )?;
        let descriptor = self.catalog.current_descriptor(handle)
            .filter(|descriptor| descriptor.descriptor_digest == descriptor_digest)
            .ok_or(HydrationError::DescriptorNotFound)?;
        if now < descriptor.published_at {
            return Err(HydrationError::Contract(ContractError::StaleAnchor).into());
        }
        if descriptor.availability_at(now) != HandleAvailability::Available {
            return Err(HydrationError::LevelUnavailable.into());
        }

        let mut prior = self.catalog_history()?;
        let mut catalog = self.catalog.clone();
        let binding = catalog.bind_source_object(
            handle, descriptor_digest, publication_root, reader,
        ).map_err(|error| DisclosureError::Source(SessionSourceHydrationError::Source(error)))?;
        let binding_digest = binding.custody_binding_digest();
        let cursors = CursorCheckpoint::register_source(
            prior.as_ref(), descriptor_digest, binding_digest, now, MAX_RECORD_BYTES,
        )?;
        // This also applies the catalog's own metadata ceiling and checks reconstructed sources.
        // It is staged; none of these requirements or bindings escape if persistence fails.
        catalog.restore_cursor_checkpoint(&cursors, MAX_RECORD_BYTES, now)?;
        let memory = self.sessions.memory.clone();
        let checkpoint = memory.checkpoint(self.sessions.limits.max_checkpoint_bytes)
            .map_err(DurableSessionError::from)?;
        let payload = encode_registration(
            self.sessions.checkpoint_digest,
            checkpoint.as_bytes(),
            &cursors,
            descriptor_digest,
            binding_digest,
            now,
        )?;
        restore_record(
            &payload, ContentDigest::sha256(&payload), Some(&memory),
            &mut prior, self.sessions.limits,
        )?;
        self.sessions.commit_candidate(PendingSession {
            memory,
            checkpoint,
            coordination: None,
            record: Some((SESSION_CHECKPOINT_RECORD_KIND, payload)),
        })?;
        self.catalog = catalog;
        Ok(JournaledSourceBinding {
            binding,
            descriptor_digest,
            registered_at: now,
            committed_root: self.committed_root(),
        })
    }

    fn catalog_history(&self) -> Result<Option<CursorCheckpoint>, DisclosureError> {
        let report = read_report(self.sessions.path(), self.sessions.limits)?;
        if report.last_root() != self.committed_root() || report.incomplete_tail().is_some() {
            return Err(DurableSessionError::RootMismatch.into());
        }
        let record = report.records().iter().rev().find(|record| {
            record.kind() == SESSION_CHECKPOINT_RECORD_KIND && has_catalog_snapshot(record.payload())
        });
        match record {
            Some(record) => {
                let (bytes, _) = catalog_snapshot(record.payload(), self.sessions.limits)?;
                Ok(Some(CursorCheckpoint::decode(bytes, MAX_RECORD_BYTES, MAX_RECORDS)?))
            }
            None => Ok(None),
        }
    }
}

struct SavedRegistration<'a> {
    before: ContentDigest,
    session_checkpoint: &'a [u8],
    cursors: &'a [u8],
    descriptor: ContentDigest,
    binding: ContentDigest,
    observed_at: TimestampNs,
}

pub(super) fn is_record(payload: &[u8]) -> bool {
    let mut prefix = CanonicalEncoder::new();
    prefix.text(DOMAIN);
    payload.starts_with(&prefix.finish())
}

pub(super) fn has_catalog_snapshot(payload: &[u8]) -> bool {
    is_record(payload) || super::is_record(payload)
}

/// The caller has already validated the journal; return the latest catalog checkpoint regardless
/// of whether it accompanied a charged disclosure or an uncharged source registration.
pub(super) fn catalog_snapshot(
    payload: &[u8],
    limits: DurableSessionLimits,
) -> Result<(&[u8], TimestampNs), DurableSessionError> {
    if is_record(payload) {
        let saved = decode_registration(payload, limits)?;
        Ok((saved.cursors, saved.observed_at))
    } else {
        let saved = super::decode(payload, limits)?;
        Ok((saved.cursors, saved.admission.observed_at))
    }
}

fn encode_registration(
    before: ContentDigest,
    checkpoint: &[u8],
    cursors: &[u8],
    descriptor: ContentDigest,
    binding: ContentDigest,
    observed_at: TimestampNs,
) -> Result<Vec<u8>, DurableSessionError> {
    // Fixed framing: domain length, three digests, two byte lengths, and one timestamp.
    let length = (8 + DOMAIN.len() + 3 * 33 + 2 * 8 + 16)
        .checked_add(checkpoint.len())
        .and_then(|length| length.checked_add(cursors.len()))
        .ok_or(DurableSessionError::CapacityExceeded)?;
    if length > MAX_RECORD_BYTES {
        return Err(DurableSessionError::CapacityExceeded);
    }
    let mut encoder = CanonicalEncoder::new();
    encoder.text(DOMAIN);
    encoder.digest(before);
    encoder.bytes(checkpoint);
    encoder.bytes(cursors);
    encoder.digest(descriptor);
    encoder.digest(binding);
    encoder.i128(observed_at.0);
    Ok(encoder.finish_checked()?)
}

fn decode_registration(
    payload: &[u8],
    limits: DurableSessionLimits,
) -> Result<SavedRegistration<'_>, DurableSessionError> {
    if payload.len() > MAX_RECORD_BYTES {
        return Err(DurableSessionError::CapacityExceeded);
    }
    let mut decoder = CanonicalDecoder::new(payload);
    if decoder.text()? != DOMAIN {
        return Err(DurableSessionError::InvalidHistory);
    }
    let before = decoder.digest()?;
    let session_checkpoint = decoder.bytes()?;
    if session_checkpoint.len() > limits.max_checkpoint_bytes {
        return Err(DurableSessionError::CapacityExceeded);
    }
    let cursors = decoder.bytes()?;
    let descriptor = decoder.digest()?;
    let binding = decoder.digest()?;
    let observed_at = TimestampNs(decoder.i128()?);
    decoder.ensure_finished()?;
    Ok(SavedRegistration { before, session_checkpoint, cursors, descriptor, binding, observed_at })
}

pub(super) fn restore_record(
    payload: &[u8],
    digest: ContentDigest,
    previous: Option<&ReferenceSessionStore>,
    cursor_history: &mut Option<CursorCheckpoint>,
    limits: DurableSessionLimits,
) -> Result<ReferenceSessionStore, DurableSessionError> {
    if ContentDigest::sha256(payload) != digest {
        return Err(DurableSessionError::RootMismatch);
    }
    let saved = decode_registration(payload, limits)?;
    let previous = previous.ok_or(DurableSessionError::InvalidHistory)?;
    let checkpoint = previous.checkpoint(limits.max_checkpoint_bytes)?;
    // No session is invented to disguise a registration as a zero-token disclosure. Compare
    // complete session bytes: even clock, grant, alias, or closed-session changes are forbidden.
    if saved.before != checkpoint.digest() || saved.session_checkpoint != checkpoint.as_bytes() {
        return Err(DurableSessionError::InvalidHistory);
    }
    let cursors = CursorCheckpoint::decode(saved.cursors, MAX_RECORD_BYTES, MAX_RECORDS)
        .map_err(|_| DurableSessionError::InvalidHistory)?;
    if cursors.captured_at != saved.observed_at {
        return Err(DurableSessionError::InvalidHistory);
    }
    cursors.validate_source_registration(cursor_history.as_ref(), saved.descriptor, saved.binding)
        .map_err(|_| DurableSessionError::InvalidHistory)?;
    *cursor_history = Some(cursors);
    Ok(previous.clone())
}

#[cfg(test)]
mod tests;
