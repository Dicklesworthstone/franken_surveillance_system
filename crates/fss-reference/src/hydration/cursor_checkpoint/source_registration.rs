#![forbid(unsafe_code)]
//! A registration may add exactly one immutable custody requirement and change no cursor.

use super::*;

impl CursorCheckpoint {
    fn with_registered_source(
        prior: Option<&Self>,
        descriptor: ContentDigest,
        binding: ContentDigest,
        now: TimestampNs,
    ) -> Result<Self, HydrationError> {
        if prior.is_some_and(|old| now < old.captured_at) {
            return Err(ContractError::StaleAnchor.into());
        }
        let mut next = prior.cloned().unwrap_or_else(|| Self {
            captured_at: now,
            records: BTreeMap::new(),
            source_requirements: BTreeMap::new(),
        });
        match next.source_requirements.get(&descriptor) {
            Some(old) if *old != binding => return Err(ContractError::DigestMismatch.into()),
            None if next.source_requirements.len() >= MAX_SOURCE_BINDINGS => {
                return Err(HydrationError::CapacityExceeded);
            }
            _ => {}
        }
        next.captured_at = now;
        next.source_requirements.insert(descriptor, binding);
        Ok(next)
    }

    /// Produces the exact one-binding transition without importing other volatile bindings.
    pub(crate) fn register_source(
        prior: Option<&Self>,
        descriptor: ContentDigest,
        binding: ContentDigest,
        now: TimestampNs,
        max_bytes: usize,
    ) -> Result<Vec<u8>, HydrationError> {
        Self::with_registered_source(prior, descriptor, binding, now)?.encode(max_bytes)
    }

    /// A source-registration envelope authorizes no session or cursor mutation, even retirement
    /// of expired cursors. All previous source requirements survive byte-for-byte.
    pub(crate) fn validate_source_registration(
        &self,
        prior: Option<&Self>,
        descriptor: ContentDigest,
        binding: ContentDigest,
    ) -> Result<(), HydrationError> {
        let expected = Self::with_registered_source(prior, descriptor, binding, self.captured_at)?;
        if *self != expected {
            return Err(HydrationError::WrongContinuation);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type Value = Result<(), Box<dyn std::error::Error>>;

    fn digest(text: &[u8]) -> ContentDigest { ContentDigest::sha256(text) }

    fn checkpoint() -> Result<CursorCheckpoint, HydrationError> {
        let bytes = CursorCheckpoint::register_source(
            None, digest(b"descriptor"), digest(b"binding"), TimestampNs(10), 4096,
        )?;
        CursorCheckpoint::decode(&bytes, 4096, 8)
    }

    #[test]
    fn first_registration_and_exact_retry_have_no_cursor_effects() -> Value {
        let prior = checkpoint()?;
        prior.validate_source_registration(None, digest(b"descriptor"), digest(b"binding"))?;
        let encoded = CursorCheckpoint::register_source(
            Some(&prior), digest(b"descriptor"), digest(b"binding"), TimestampNs(11), 4096,
        )?;
        let next = CursorCheckpoint::decode(&encoded, 4096, 8)?;
        next.validate_source_registration(Some(&prior), digest(b"descriptor"), digest(b"binding"))?;
        assert_eq!(next.source_requirements, prior.source_requirements);
        assert!(next.records.is_empty());
        assert_eq!(next.captured_at, TimestampNs(11));
        Ok(())
    }

    #[test]
    fn changed_omitted_or_unrequested_source_requirements_refuse() -> Value {
        let prior = checkpoint()?;
        let descriptor = digest(b"second descriptor");
        let binding = digest(b"second binding");
        let bytes = CursorCheckpoint::register_source(Some(&prior), descriptor, binding, TimestampNs(20), 4096)?;
        let next = CursorCheckpoint::decode(&bytes, 4096, 8)?;
        for case in 0..4 {
            let mut forged = next.clone();
            match case {
                0 => { forged.source_requirements.remove(&digest(b"descriptor")); }
                1 => { forged.source_requirements.insert(digest(b"descriptor"), binding); }
                2 => { forged.source_requirements.insert(digest(b"third descriptor"), binding); }
                _ => { forged.source_requirements.remove(&descriptor); }
            }
            assert!(forged.validate_source_registration(Some(&prior), descriptor, binding).is_err());
        }
        assert!(CursorCheckpoint::register_source(
            Some(&prior), digest(b"descriptor"), binding, TimestampNs(20), 4096,
        ).is_err());
        Ok(())
    }

    #[test]
    fn registration_cannot_issue_consume_or_retire_even_expired_cursors() -> Value {
        let mut prior = checkpoint()?;
        let cursor = digest(b"cursor");
        prior.records.insert(cursor, IssuedCursorRecord {
            cursor_digest: cursor,
            session_id: SessionId::parse("session:registration")?,
            handle_id: "handle:registration".to_owned(),
            expires_at: TimestampNs(11),
            next_ordinal: 3,
            consumed: false,
        });
        let bytes = CursorCheckpoint::register_source(
            Some(&prior), digest(b"descriptor"), digest(b"binding"), TimestampNs(20), 4096,
        )?;
        let next = CursorCheckpoint::decode(&bytes, 4096, 8)?;
        next.validate_source_registration(Some(&prior), digest(b"descriptor"), digest(b"binding"))?;
        for case in 0..3 {
            let mut forged = next.clone();
            match case {
                0 => { forged.records.clear(); }
                1 => { forged.records.get_mut(&cursor).ok_or("no cursor")?.consumed = true; }
                _ => {
                    let mut extra = forged.records.get(&cursor).ok_or("no cursor")?.clone();
                    extra.cursor_digest = digest(b"extra");
                    forged.records.insert(extra.cursor_digest, extra);
                }
            }
            assert!(forged.validate_source_registration(Some(&prior), digest(b"descriptor"), digest(b"binding")).is_err());
        }
        assert!(next.validate_source_registration(None, digest(b"descriptor"), digest(b"binding")).is_err());
        Ok(())
    }

    #[test]
    fn exact_size_and_monotone_clock_refuse_without_changing_prior_state() -> Value {
        let prior = checkpoint()?;
        let before = prior.clone();
        let bytes = CursorCheckpoint::register_source(
            Some(&prior), digest(b"descriptor"), digest(b"binding"), TimestampNs(20), 4096,
        )?;
        assert!(CursorCheckpoint::register_source(
            Some(&prior), digest(b"descriptor"), digest(b"binding"), TimestampNs(20), bytes.len() - 1,
        ).is_err());
        assert_eq!(CursorCheckpoint::register_source(
            Some(&prior), digest(b"descriptor"), digest(b"binding"), TimestampNs(20), bytes.len(),
        )?, bytes);
        assert!(CursorCheckpoint::register_source(
            Some(&prior), digest(b"descriptor"), digest(b"binding"), TimestampNs(9), 4096,
        ).is_err());
        assert_eq!(prior, before);
        Ok(())
    }
}
