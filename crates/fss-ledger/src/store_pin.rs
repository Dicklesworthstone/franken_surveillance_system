//! Store identity pins: which durable file a handle actually reads and writes (fss-1s6ac).
//!
//! A byte copy of a journal reproduces every committed root, anchor, and state root exactly, so no
//! byte-level commitment can tell the copy from the original. What a copy cannot reproduce is the
//! filesystem identity of the original file: the device and inode it lives on and, where the
//! platform reports it, its birth time. A store pin is a digest over that identity and the store's
//! role, taken from the open file descriptor when the handle opens.
//!
//! Consumers that let a store vouch for something (publication lineage, obligation discharge)
//! compare the pin a compile path recorded with the pin of the store they are handed, and refuse a
//! mismatch. A handle whose path no longer names the file it opened (the file was renamed away or
//! another file was moved onto its path) is reported through [`pin_is_current`].
//!
//! # Threat model (not overclaimed)
//!
//! The pin distinguishes files, not histories. It defeats a byte copy of a store being presented
//! in place of the original to a consumer holding evidence compiled against the original, and the
//! converse. It does not stop a party with write access to the original file from rewriting it in
//! place (same inode), and a copy that later replaces the original on a fresh boot cannot be told
//! from a genuine restore: it simply becomes a different store, and evidence compiled against the
//! original is refused against it. Backup and restore, copying a deployment to another volume,
//! and any repair that rewrites the file under a new inode therefore change the pin.
//! Platforms that report no file identity (non-Unix) yield no pin, and pinned operations refuse.

use std::fs::Metadata;
use std::path::Path;
use std::time::UNIX_EPOCH;

use fss_core::{CanonicalEncoder, ContentDigest};

/// Digest domain of a durable store pin.
pub const STORE_PIN_DOMAIN: &str = "fss.durable_store_pin.v1";

/// Role of the authority ledger journal in a store pin.
pub const STORE_ROLE_AUTHORITY_LEDGER: &str = "authority_ledger";

/// Role of the durable effect journal in a store pin.
pub const STORE_ROLE_EFFECT_JOURNAL: &str = "effect_journal";

#[cfg(unix)]
fn file_identity(metadata: &Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn file_identity(_metadata: &Metadata) -> Option<(u64, u64)> {
    None
}

/// The store pin of the file described by `metadata` in `role`, or `None` when the platform
/// reports no file identity.
#[must_use]
pub fn store_pin_of(role: &str, metadata: &Metadata) -> Option<ContentDigest> {
    let (device, inode) = file_identity(metadata)?;
    let mut encoder = CanonicalEncoder::new();
    encoder.text(STORE_PIN_DOMAIN);
    encoder.text(role);
    encoder.u64(device);
    encoder.u64(inode);
    // The birth time separates a later file that reuses a freed inode number.
    match metadata
        .created()
        .ok()
        .and_then(|created| created.duration_since(UNIX_EPOCH).ok())
    {
        Some(born) => {
            encoder.bool(true);
            encoder.u64(born.as_secs());
            encoder.u32(born.subsec_nanos());
        }
        None => encoder.bool(false),
    }
    Some(ContentDigest::sha256(&encoder.finish()))
}

/// The store pin of the file `path` names now in `role`, or `None` when it cannot be read or the
/// platform reports no file identity.
#[must_use]
pub fn store_pin_at(role: &str, path: &Path) -> Option<ContentDigest> {
    std::fs::metadata(path)
        .ok()
        .and_then(|metadata| store_pin_of(role, &metadata))
}

/// Returns whether `pin` is present and `path` still names the file it was taken from.
#[must_use]
pub fn pin_is_current(role: &str, path: &Path, pin: Option<ContentDigest>) -> bool {
    pin.is_some() && store_pin_at(role, path) == pin
}
