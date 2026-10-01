#![forbid(unsafe_code)]
//! Cold reconciliation of ONE independently saved original-read publication.
//!
//! A key is not source evidence or publication authority. Recovery requires the exact original
//! bytes AND canonical read metadata to have been staged already. It re-verifies every prior
//! root, rejects other pending/later work in this namespace, and uses the existing root-last
//! publisher. No camera is opened, no read is replayed, and no completion/coverage is invented.

use super::*;

const KEY_DOMAIN: &str = "fss.http_wire_recovery_key.v1";
/// Hard bound checked before decoding or allocating a textual recovery key.
pub const MAX_HTTP_WIRE_RECOVERY_KEY_BYTES: usize = 1024;

/// An immutable original-read descriptor to preserve BEFORE attempting publication.
///
/// All fields are private. The expected root commits to the complete read metadata, including
/// its predecessor, receive-admission time and original source digest. Deserializing a key does
/// not prove that the described read happened; `inspect`/`recover` require its staged custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpWireRecoveryKey {
    scope: HttpWireScope,
    entry: Entry,
}

/// What was verified at inspection, never a lease on the subsequent state of storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpWireRecoveryState {
    /// Original bytes and read metadata exist; the intended root is not yet visible.
    Staged,
    /// The exact intended root is already durable, including a lost successful reply.
    Durable,
}
impl HttpWireRecoveryState {
    /// Stable diagnostic spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::Durable => "durable",
        }
    }
}

impl HttpWireRecoveryKey {
    /// Bind a recorder's actual prepared read to its independently saved before/after pins.
    /// Performs no I/O. Preserve the result outside the recording process before committing.
    pub fn new(
        scope: HttpWireScope,
        prior: HttpWirePin,
        wire: HttpWireReceipt,
        expected: HttpWirePin,
    ) -> Result<Self, HttpArchiveError> {
        let scope_digest = scope.digest()?;
        let digests = [prior.scope, prior.head, expected.scope, expected.head];
        if digests
            .iter()
            .any(|d| d.algorithm() != DigestAlgorithm::Sha256 || d.bytes() == [0; 32])
            || prior.scope != scope_digest
            || expected.scope != scope_digest
            || wire.basis != scope.stream
            || wire.sha256 == [0; 32]
            || prior.reads >= MAX_HTTP_WIRE_READS as u64
            || expected.reads != prior.reads + 1
            || prior.bytes != wire.range[0]
            || expected.bytes != wire.range[1]
            || wire.range[1] <= wire.range[0]
            || wire.range[1] > MAX_BYTES
            || wire.range[1] - wire.range[0] > MAX_READ as u64
            || (prior.reads == 0 && (prior.bytes != 0 || prior.head != scope_digest))
            || (prior.reads > 0 && prior.bytes == 0)
        {
            return Err(HttpArchiveError::Source);
        }
        let entry = Entry {
            prior,
            wire,
            root: expected.head,
        };
        if entry.manifest()?.root() != expected.head || entry.pin() != expected {
            return Err(HttpArchiveError::Source);
        }
        Ok(Self { scope, entry })
    }

    /// Exact source and original-header/media retention interpretation; not an access grant.
    pub fn scope(&self) -> HttpWireScope {
        self.scope
    }
    /// Last prefix acknowledged before this publication attempt.
    pub fn prior_pin(&self) -> HttpWirePin {
        self.entry.prior
    }
    /// Exact prefix the interrupted publication intended to make durable.
    pub fn expected_pin(&self) -> HttpWirePin {
        self.entry.pin()
    }
    /// Original read identity and RECEIVE admission, never a camera capture timestamp.
    pub fn wire(&self) -> HttpWireReceipt {
        self.entry.wire
    }

    /// Canonical descriptor bytes. Includes no response headers, image bytes or credentials.
    pub fn to_bytes(&self) -> Result<Vec<u8>, HttpArchiveError> {
        let mut e = CanonicalEncoder::new();
        e.text(KEY_DOMAIN);
        e.digest(sha(self.scope.receive_clock));
        e.digest(sha(self.scope.retention_evidence));
        e.bytes(&self.entry.metadata()?);
        e.digest(self.entry.root);
        let bytes = e.finish_checked().map_err(|_| HttpArchiveError::Metadata)?;
        if bytes.len() > MAX_HTTP_WIRE_RECOVERY_KEY_BYTES {
            return Err(HttpArchiveError::Limit);
        }
        Ok(bytes)
    }

    /// Decode an exact bounded descriptor. Unknown versions, trailing bytes and noncanonical
    /// encodings fail closed. A valid descriptor is not proof of staged or durable custody.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HttpArchiveError> {
        if bytes.len() > MAX_HTTP_WIRE_RECOVERY_KEY_BYTES {
            return Err(HttpArchiveError::Limit);
        }
        let parsed = (|| -> Result<Self, fss_core::ContractError> {
            let mut d = CanonicalDecoder::new(bytes);
            if d.text()? != KEY_DOMAIN {
                return Err(fss_core::ContractError::InvalidIdentifier);
            }
            let receive_clock = d.digest()?;
            let retention_evidence = d.digest()?;
            let metadata = d.bytes()?;
            if metadata.len() > MAX_METADATA
                || receive_clock.algorithm() != DigestAlgorithm::Sha256
                || retention_evidence.algorithm() != DigestAlgorithm::Sha256
            {
                return Err(fss_core::ContractError::InvalidIdentifier);
            }
            let root = d.digest()?;
            d.ensure_finished()?;
            let entry = Entry::decode(metadata, root)
                .map_err(|_| fss_core::ContractError::InvalidIdentifier)?;
            let scope = HttpWireScope {
                stream: entry.wire.basis,
                receive_clock: receive_clock.bytes(),
                retention_evidence: retention_evidence.bytes(),
            };
            let reads = entry
                .prior
                .reads
                .checked_add(1)
                .ok_or(fss_core::ContractError::InvalidIdentifier)?;
            let expected = HttpWirePin {
                scope: entry.prior.scope,
                head: root,
                reads,
                bytes: entry.wire.range[1],
            };
            Self::new(scope, entry.prior, entry.wire, expected)
                .map_err(|_| fss_core::ContractError::InvalidIdentifier)
        })()
        .map_err(|_| HttpArchiveError::Metadata)?;
        if parsed.to_bytes()? != bytes {
            return Err(HttpArchiveError::Metadata);
        }
        Ok(parsed)
    }

    /// Identity of the canonical descriptor, not an approval or authenticity assertion.
    pub fn digest(&self) -> Result<ContentDigest, HttpArchiveError> {
        Ok(ContentDigest::sha256(&self.to_bytes()?))
    }

    /// Lossless ASCII interchange for the command line and a prepared JSONL row.
    pub fn to_text(&self) -> Result<String, HttpArchiveError> {
        let bytes = self.to_bytes()?;
        let mut text = String::with_capacity(4 + bytes.len() * 2);
        text.push_str("hex:");
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in bytes {
            text.push(char::from(HEX[usize::from(byte >> 4)]));
            text.push(char::from(HEX[usize::from(byte & 15)]));
        }
        Ok(text)
    }

    /// Strict lowercase hex with a fixed pre-allocation bound; no whitespace or alternate forms.
    pub fn from_text(text: &str) -> Result<Self, HttpArchiveError> {
        if text.len() > 4 + MAX_HTTP_WIRE_RECOVERY_KEY_BYTES * 2 {
            return Err(HttpArchiveError::Limit);
        }
        let digits = text
            .strip_prefix("hex:")
            .ok_or(HttpArchiveError::Metadata)?
            .as_bytes();
        if digits.is_empty() || digits.len() % 2 != 0 {
            return Err(HttpArchiveError::Metadata);
        }
        let digit = |b: u8| -> Result<u8, HttpArchiveError> {
            match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                _ => Err(HttpArchiveError::Metadata),
            }
        };
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(digits.len() / 2)
            .map_err(|_| HttpArchiveError::Limit)?;
        for pair in digits.chunks_exact(2) {
            bytes.push(digit(pair[0])? * 16 + digit(pair[1])?);
        }
        Self::from_bytes(&bytes)
    }

    // Read everything again on every admission. A previous inspection is never used as a grant.
    fn prepare_recovery(
        &self,
        p: &LocalRootPublisher,
        limits: HttpArchiveLimits,
        cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>,
    ) -> Result<(HttpWireArchive, Vec<u8>, HttpWireRecoveryState), HttpArchiveError> {
        probe(cancel)?;
        budget.charge(4096)?;
        let mut archive = HttpWireArchive::new(self.scope, limits)?;
        archive.ready(p)?;
        let expected = self.expected_pin();
        if expected.reads > limits.maximum_reads as u64 || expected.bytes > limits.maximum_bytes {
            return Err(HttpArchiveError::Limit);
        }
        let slot = archive.slot(expected.reads)?;
        // Only the exact pending ordinal may exist beyond the prior prefix. Broken roots,
        // indeterminate visibility markers, foreign temps and later roots remain refusals.
        archive.inventory(
            p,
            self.entry.prior.reads,
            expected.reads,
            Some(&slot),
            cancel,
            budget,
        )?;
        archive
            .entries
            .try_reserve_exact(self.entry.prior.reads as usize)
            .map_err(|_| HttpArchiveError::Limit)?;
        for ordinal in 1..=self.entry.prior.reads {
            let prior_slot = archive.slot(ordinal)?;
            let root = p
                .root(&prior_slot)
                .ok_or(HttpArchiveError::NotDurable)?
                .root;
            let (entry, _) = archive.read_entry(p, &prior_slot, root, cancel, budget)?;
            archive.validate_next(entry.wire)?;
            if entry.prior != archive.pin() {
                return Err(HttpArchiveError::Sequence);
            }
            archive.entries.push(entry);
        }
        if archive.pin() != self.entry.prior {
            return Err(HttpArchiveError::Sequence);
        }
        archive.validate_next(self.entry.wire)?;
        let state = match p.root(&slot) {
            None => HttpWireRecoveryState::Staged,
            Some(root)
                if root.root == expected.head && root.state == LocalPublicationState::Staged =>
            {
                HttpWireRecoveryState::Staged
            }
            Some(root)
                if root.root == expected.head && root.state == LocalPublicationState::Durable =>
            {
                // Reverify the complete existing object, not merely the in-memory root table.
                let (entry, _) = archive.read_entry(p, &slot, expected.head, cancel, budget)?;
                if entry != self.entry {
                    return Err(HttpArchiveError::Sequence);
                }
                HttpWireRecoveryState::Durable
            }
            Some(_) => return Err(HttpArchiveError::Sequence),
        };
        // Both existed BEFORE every native publisher crash cut. In particular, recovery must
        // not create read metadata from a caller-supplied descriptor when that metadata is absent.
        let metadata = self.entry.metadata()?;
        let retained = archive.read_object(
            p,
            ContentDigest::sha256(&metadata),
            MAX_METADATA,
            cancel,
            budget,
        )?;
        if retained != metadata {
            return Err(HttpArchiveError::Metadata);
        }
        let bytes =
            archive.read_object(p, sha(self.entry.wire.sha256), MAX_READ, cancel, budget)?;
        if bytes.len() as u64 != self.entry.wire.range[1] - self.entry.wire.range[0] {
            return Err(HttpArchiveError::Source);
        }
        // Even a not-yet-visible target cannot be resurrected after a tombstone.
        budget.charge(p.limits().max_tombstones as u64 + 1)?;
        if p.tombstones().any(|digest| *digest == expected.head) {
            return Err(HttpArchiveError::Tombstoned);
        }
        probe(cancel)?;
        budget.charge(0)?;
        Ok((archive, bytes, state))
    }

    /// Inspect staged/durable custody without staging, unlinking, publishing or network I/O.
    /// Opening the publisher itself still has its documented recovery/locking/sync behavior.
    /// An exact orphan temp is inspected by the publisher at commit, not discarded here.
    pub fn inspect(
        &self,
        p: &LocalRootPublisher,
        limits: HttpArchiveLimits,
        cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>,
    ) -> Result<HttpWireRecoveryState, HttpArchiveError> {
        self.prepare_recovery(p, limits, cancel, budget)
            .map(|(_, _, state)| state)
    }

    /// Reconcile exactly this one source read using only already-staged original custody.
    ///
    /// The caller must independently authorize the effect. Fresh current storage authority,
    /// source hashes, predecessor chain and namespace checks precede every write. The normal
    /// publisher revalidates references at its commit point and reconciles only its exact temp.
    /// Repeating a successfully completed recovery yields the same pin; a later read refuses.
    /// Success is original-read durability, NOT parser acknowledgement, capture resumption,
    /// HTTP/MIME completion, a decoded frame, a canonical event or a coverage witness.
    pub fn recover(
        &self,
        p: &mut LocalRootPublisher,
        limits: HttpArchiveLimits,
        cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>,
    ) -> Result<HttpWirePublication, HttpArchiveError> {
        let (mut archive, bytes, _) = self.prepare_recovery(p, limits, cancel, budget)?;
        let plan = archive.prepare_bytes(self.entry.wire, &bytes, budget)?;
        if plan.pin() != self.expected_pin() {
            return Err(HttpArchiveError::Source);
        }
        archive.publish(&plan, p, cancel, budget)
    }
}

#[cfg(test)]
mod tests;
