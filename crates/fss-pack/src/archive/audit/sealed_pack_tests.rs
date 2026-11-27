#![forbid(unsafe_code)]

use fss_core::{Sha256Hasher, sha256};

use super::verify_sealed_pack_bytes;
use crate::error::PackError;
use crate::format::{PackFooterEntry, PackId, encode_record_into, encode_sealed_footer};

const PACK: PackId = PackId::new(1, 7);

fn records() -> (Vec<u8>, Vec<PackFooterEntry>) {
    let mut bytes = Vec::new();
    let mut entries = Vec::new();
    for payload in [b"first".as_slice(), b"second", b"third"] {
        let entry = PackFooterEntry {
            sha256: sha256(payload),
            offset: bytes.len() as u64,
            len: payload.len() as u64,
            kind: 3,
            flags: 1,
        };
        let _ = encode_record_into(entry.flags, entry.kind, entry.sha256, payload, &mut bytes);
        entries.push(entry);
    }
    (bytes, entries)
}

// Recompute the whole-pack digest for each test: the outer checksum alone is
// valid even when the footer fails to index the authenticated record stream.
fn seal(mut bytes: Vec<u8>, entries: &[PackFooterEntry]) -> Result<Vec<u8>, PackError> {
    let mut hasher = Sha256Hasher::new();
    hasher.update(&bytes);
    let (footer, _) = encode_sealed_footer(entries, bytes.len() as u64, hasher)?;
    bytes.extend_from_slice(&footer);
    Ok(bytes)
}

#[test]
fn complete_index_preserves_canonical_restore_order() -> Result<(), PackError> {
    let (bytes, mut entries) = records();
    let (_, verified) = verify_sealed_pack_bytes(PACK, &seal(bytes.clone(), &entries)?)?;
    entries.sort_unstable();
    assert_eq!(verified.len(), entries.len());
    for (record, entry) in verified.iter().zip(entries) {
        assert_eq!(record.digest, entry.digest());
        assert_eq!(record.object_kind, entry.kind);
        assert_eq!(record.flags, entry.flags);
        assert_eq!(
            sha256(&bytes[record.payload_start..record.payload_end]),
            entry.sha256
        );
    }
    Ok(())
}

#[test]
fn checksum_valid_pack_requires_complete_exact_record_inventory() -> Result<(), PackError> {
    let (bytes, entries) = records();
    for missing in 0..entries.len() {
        let mut incomplete = entries.clone();
        incomplete.remove(missing);
        assert!(matches!(
            verify_sealed_pack_bytes(PACK, &seal(bytes.clone(), &incomplete)?),
            Err(PackError::CorruptPack { .. })
        ));
    }
    for flags in [false, true] {
        let mut mislabeled = entries.clone();
        if flags {
            mislabeled[0].flags ^= 1;
        } else {
            mislabeled[0].kind ^= 1;
        }
        assert!(matches!(
            verify_sealed_pack_bytes(PACK, &seal(bytes.clone(), &mislabeled)?),
            Err(PackError::CorruptPack { .. })
        ));
    }
    let mut overlapping = entries;
    overlapping[1].offset -= 1;
    assert!(matches!(
        verify_sealed_pack_bytes(PACK, &seal(bytes, &overlapping)?),
        Err(PackError::CorruptPack { .. })
    ));
    Ok(())
}
