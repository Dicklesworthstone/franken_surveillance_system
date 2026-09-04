use std::collections::BTreeMap;
use std::fmt;

use crate::digest::{CanonicalWriter, Digest, DigestError, domain_digest};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceKey {
    pub sensor: String,
    pub sequence: u64,
}

impl SourceKey {
    #[must_use]
    pub fn new(sensor: impl Into<String>, sequence: u64) -> Self {
        Self {
            sensor: sensor.into(),
            sequence,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceState {
    Staged,
    Verified,
    Published,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedSource {
    pub key: SourceKey,
    pub digest: Digest,
    pub bytes: Vec<u8>,
    pub publication_root: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceEntry {
    digest: Digest,
    bytes: Vec<u8>,
    state: SourceState,
    publication_root: Option<Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpoolError {
    Digest(DigestError),
    DuplicateKeyConflict(SourceKey),
    Missing(SourceKey),
    NotVerified(SourceKey),
    NotPublished(SourceKey),
    Corrupt(SourceKey),
    CounterOverflow,
}

impl fmt::Display for SpoolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Digest(error) => write!(formatter, "digest failure: {error}"),
            Self::DuplicateKeyConflict(key) => write!(
                formatter,
                "source key {}:{} was reused with different bytes",
                key.sensor, key.sequence
            ),
            Self::Missing(key) => write!(
                formatter,
                "source {}:{} is not staged",
                key.sensor, key.sequence
            ),
            Self::NotVerified(key) => write!(
                formatter,
                "source {}:{} is not verified",
                key.sensor, key.sequence
            ),
            Self::NotPublished(key) => write!(
                formatter,
                "source {}:{} is not root-published",
                key.sensor, key.sequence
            ),
            Self::Corrupt(key) => write!(
                formatter,
                "source {}:{} no longer matches its staged digest",
                key.sensor, key.sequence
            ),
            Self::CounterOverflow => formatter.write_str("source publication counter overflow"),
        }
    }
}

impl std::error::Error for SpoolError {}

impl From<DigestError> for SpoolError {
    fn from(error: DigestError) -> Self {
        Self::Digest(error)
    }
}

#[derive(Debug, Clone)]
pub struct SourceSpool {
    entries: BTreeMap<SourceKey, SourceEntry>,
    root: Digest,
    published_count: u64,
}

impl Default for SourceSpool {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            root: Digest::ZERO,
            published_count: 0,
        }
    }
}

impl SourceSpool {
    #[must_use]
    pub const fn root(&self) -> Digest {
        self.root
    }

    #[must_use]
    pub const fn published_count(&self) -> u64 {
        self.published_count
    }

    pub fn stage(&mut self, key: SourceKey, bytes: Vec<u8>) -> Result<Digest, SpoolError> {
        let digest = domain_digest("fss-source-object-v1", &bytes)?;
        if let Some(existing) = self.entries.get(&key) {
            if existing.digest == digest && existing.bytes == bytes {
                return Ok(existing.digest);
            }
            return Err(SpoolError::DuplicateKeyConflict(key));
        }
        self.entries.insert(
            key,
            SourceEntry {
                digest,
                bytes,
                state: SourceState::Staged,
                publication_root: None,
            },
        );
        Ok(digest)
    }

    pub fn verify(&mut self, key: &SourceKey) -> Result<Digest, SpoolError> {
        let entry = self
            .entries
            .get_mut(key)
            .ok_or_else(|| SpoolError::Missing(key.clone()))?;
        let observed = domain_digest("fss-source-object-v1", &entry.bytes)?;
        if observed != entry.digest {
            return Err(SpoolError::Corrupt(key.clone()));
        }
        if entry.state == SourceState::Staged {
            entry.state = SourceState::Verified;
        }
        Ok(entry.digest)
    }

    pub fn publish(&mut self, key: &SourceKey) -> Result<Digest, SpoolError> {
        if let Some(entry) = self.entries.get(key) {
            if entry.state == SourceState::Published {
                return entry
                    .publication_root
                    .ok_or_else(|| SpoolError::NotPublished(key.clone()));
            }
            if entry.state != SourceState::Verified {
                return Err(SpoolError::NotVerified(key.clone()));
            }
        } else {
            return Err(SpoolError::Missing(key.clone()));
        }

        let next_count = self
            .published_count
            .checked_add(1)
            .ok_or(SpoolError::CounterOverflow)?;
        let digest = self
            .entries
            .get(key)
            .ok_or_else(|| SpoolError::Missing(key.clone()))?
            .digest;
        let mut writer = CanonicalWriter::new("fss-source-publication-root-v1")?;
        writer.push_digest(self.root);
        writer.push_u64(next_count);
        writer.push_str(&key.sensor)?;
        writer.push_u64(key.sequence);
        writer.push_digest(digest);
        let root = writer.digest()?;

        let entry = self
            .entries
            .get_mut(key)
            .ok_or_else(|| SpoolError::Missing(key.clone()))?;
        entry.state = SourceState::Published;
        entry.publication_root = Some(root);
        self.root = root;
        self.published_count = next_count;
        Ok(root)
    }

    pub fn ingest(
        &mut self,
        key: SourceKey,
        bytes: Vec<u8>,
    ) -> Result<PublishedSource, SpoolError> {
        self.stage(key.clone(), bytes)?;
        self.verify(&key)?;
        self.publish(&key)?;
        self.read(&key)
    }

    pub fn read(&self, key: &SourceKey) -> Result<PublishedSource, SpoolError> {
        let entry = self
            .entries
            .get(key)
            .ok_or_else(|| SpoolError::Missing(key.clone()))?;
        if entry.state != SourceState::Published {
            return Err(SpoolError::NotPublished(key.clone()));
        }
        let observed = domain_digest("fss-source-object-v1", &entry.bytes)?;
        if observed != entry.digest {
            return Err(SpoolError::Corrupt(key.clone()));
        }
        Ok(PublishedSource {
            key: key.clone(),
            digest: entry.digest,
            bytes: entry.bytes.clone(),
            publication_root: entry
                .publication_root
                .ok_or_else(|| SpoolError::NotPublished(key.clone()))?,
        })
    }

    pub fn state(&self, key: &SourceKey) -> Result<SourceState, SpoolError> {
        self.entries
            .get(key)
            .map(|entry| entry.state)
            .ok_or_else(|| SpoolError::Missing(key.clone()))
    }

    pub fn inject_corruption(&mut self, key: &SourceKey) -> Result<(), SpoolError> {
        let entry = self
            .entries
            .get_mut(key)
            .ok_or_else(|| SpoolError::Missing(key.clone()))?;
        if entry.bytes.is_empty() {
            entry.bytes.push(1);
        } else {
            entry.bytes[0] ^= 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{SourceKey, SourceSpool, SourceState, SpoolError};

    #[test]
    fn staged_bytes_are_not_visible_before_root_publication() {
        let mut spool = SourceSpool::default();
        let key = SourceKey::new("cam-a", 1);
        spool.stage(key.clone(), b"frame".to_vec()).expect("stage");
        assert!(matches!(spool.read(&key), Err(SpoolError::NotPublished(_))));
        spool.verify(&key).expect("verify");
        assert!(matches!(spool.read(&key), Err(SpoolError::NotPublished(_))));
        spool.publish(&key).expect("publish");
        assert_eq!(spool.read(&key).expect("read").bytes, b"frame");
    }

    #[test]
    fn corruption_prevents_verification_and_reads() {
        let mut spool = SourceSpool::default();
        let staged = SourceKey::new("cam-a", 1);
        spool
            .stage(staged.clone(), b"frame".to_vec())
            .expect("stage");
        spool.inject_corruption(&staged).expect("corrupt");
        assert!(matches!(spool.verify(&staged), Err(SpoolError::Corrupt(_))));

        let published = SourceKey::new("cam-a", 2);
        spool
            .ingest(published.clone(), b"frame-two".to_vec())
            .expect("ingest");
        spool.inject_corruption(&published).expect("corrupt");
        assert!(matches!(
            spool.read(&published),
            Err(SpoolError::Corrupt(_))
        ));
    }

    #[test]
    fn publication_is_idempotent_and_ordered() {
        let mut spool = SourceSpool::default();
        let first = SourceKey::new("cam-a", 1);
        let second = SourceKey::new("cam-b", 1);
        spool.stage(first.clone(), b"one".to_vec()).expect("stage");
        spool.verify(&first).expect("verify");
        let first_root = spool.publish(&first).expect("publish");
        assert_eq!(first_root, spool.publish(&first).expect("republish"));
        assert_eq!(spool.published_count(), 1);
        spool.ingest(second, b"two".to_vec()).expect("second");
        assert_eq!(spool.published_count(), 2);
        assert_ne!(first_root, spool.root());
        assert_eq!(spool.state(&first).expect("state"), SourceState::Published);
    }

    #[test]
    fn key_reuse_with_different_bytes_fails() {
        let mut spool = SourceSpool::default();
        let key = SourceKey::new("cam-a", 1);
        spool.stage(key.clone(), b"one".to_vec()).expect("stage");
        assert!(matches!(
            spool.stage(key, b"two".to_vec()),
            Err(SpoolError::DuplicateKeyConflict(_))
        ));
    }
}
