#![forbid(unsafe_code)]

//! Exact typed custody for partitioned imports. Parts remain independently ledgered
//! roots; adding native child edges would flatten their payloads into one publication
//! batch and defeat the source owner's bounded partition protocol. The inventory is
//! itself a direct checkpoint child, and its canonical digest references participate
//! in the existing deletion/hold closure walker.

use super::*;
use crate::ingest::file_publication::MAX_FILE_PUBLICATION_PARTS;

#[derive(Debug)]
pub(super) struct SourceClosure {
    bytes: Vec<u8>,
    digest: ContentDigest,
}

impl SourceClosure {
    pub(super) fn for_import(source: &RetainedFileImport, cx: &ReplayCx) -> Result<Option<Self>> {
        let parts = &source.manifest().part_roots;
        if parts.is_empty() {
            return Ok(None);
        }
        if parts.len() > MAX_FILE_PUBLICATION_PARTS {
            return Err(WatchError::Limit);
        }
        let mut e = CanonicalEncoder::new();
        e.text(SOURCE_CLOSURE_DOMAIN);
        e.digest(source.import_identity());
        e.digest(source.import_root());
        e.digest(source.manifest_digest());
        e.u64(parts.len() as u64);
        for part in parts {
            checkpoint(cx, "incremental_dwell:source_closure")?;
            validate_digest(*part)?;
            e.digest(*part);
        }
        let bytes = e.finish_checked()?;
        if bytes.len() > MAX_SOURCE_CLOSURE_BYTES {
            return Err(WatchError::Limit);
        }
        let digest = ContentDigest::sha256(&bytes);
        Ok(Some(Self { bytes, digest }))
    }

    pub(super) const fn digest(&self) -> ContentDigest {
        self.digest
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn verify(&self, deployment: &ReferenceDeployment, cx: &ReplayCx) -> Result<()> {
        checkpoint(cx, "incremental_dwell:verify_source_closure")?;
        let actual = deployment
            .publisher()
            .spool()
            .read_bounded(self.digest, self.bytes.len())?;
        if actual != self.bytes {
            return Err(WatchError::Conflict);
        }
        Ok(())
    }
}
