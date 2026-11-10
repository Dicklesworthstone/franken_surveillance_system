#![forbid(unsafe_code)]
//! A content-valid catalog producer can still lie about native descriptors.

use super::*;
use fss_core::{CanonicalDecoder, CanonicalEncoder};

fn overstate_first_descriptor(index: &[u8], changed_field: usize) -> Test<Vec<u8>> {
    let mut decoder = CanonicalDecoder::new(&index[..index.len() - 33]);
    let mut encoder = CanonicalEncoder::new();
    encoder.text(decoder.text()?);
    encoder.u64(decoder.u64()?);
    encoder.text(decoder.text()?);
    encoder.text(decoder.text()?);
    encoder.u64(decoder.u64()?);
    for _ in 0..3 {
        encoder.digest(decoder.digest()?);
    }
    encoder.u32(decoder.u32()?);
    let count = decoder.u64()?;
    encoder.u64(count);
    for ordinal in 0..count {
        encoder.text(decoder.text()?);
        encoder.digest(decoder.digest()?);
        for field in 0..6 {
            let value = decoder.u64()?;
            encoder.u64(value + u64::from(ordinal == 0 && field == changed_field));
        }
        for _ in 0..4 {
            encoder.digest(decoder.digest()?);
        }
    }
    decoder.ensure_finished()?;
    let mut bytes = encoder.finish_checked()?;
    let checksum = ContentDigest::sha256(&bytes);
    bytes.push(1);
    bytes.extend_from_slice(&checksum.bytes());
    Ok(bytes)
}

fn forged_catalog(f: &mut Fixture, changed_field: usize) -> Test {
    let original = ObjectManifest::from_canonical_bytes(
        f.originals.get(&f.request.root).ok_or("catalog root")?,
    )?;
    let metadata = original.metadata_digest().ok_or("catalog index")?;
    let bytes = overstate_first_descriptor(
        f.originals.get(&metadata).ok_or("catalog index bytes")?,
        changed_field,
    )?;
    let forged = ObjectManifest::new(
        original.kind(),
        original
            .children()
            .iter()
            .copied()
            .filter(|digest| *digest != metadata),
        Some(ContentDigest::sha256(&bytes)),
    )?;
    // This is a structurally valid producer publication with exact content checksums.
    // Its selected original window remains unmodified and independently verifiable.
    let publisher = f.source.as_mut().ok_or("archive")?;
    publisher.stage_object(&bytes)?;
    let slot = SlotName::parse("misdescribed-catalog")?;
    publisher.stage_manifest(&slot, &forged)?;
    publisher.publish(&slot, &forged)?;
    f.request.root = forged.root();
    f.request.slot = slot;
    Ok(())
}

#[test]
fn canonical_overstated_sample_or_nal_count_cannot_be_treated_as_a_maximum() -> Test {
    for field in [3, 4] {
        let mut f = Fixture::avc(&format!("query-descriptor-{field}"), 4, 0, false)?;
        forged_catalog(&mut f, field)?;
        // The metadata owner truthfully reports an unhydrated producer descriptor. Both false
        // values remain below admission ceilings; a bounds-only native check would accept them.
        let plan = preview(&f, 0..1)?;
        assert_eq!(plan.windows().len(), 1);
        if field == 3 {
            assert_eq!(plan.frames(), 5);
        }
        let before = integrity::snapshot(&f.directory.0.join("destination"))?;
        let refused = acquire(&mut f, &plan).expect_err("exact descriptor mismatch");
        assert!(matches!(
            refused.reason,
            RtspQueryImportError::Import(RtspImportError::Invalid(_))
        ));
        assert!(refused.completed.is_empty());
        assert_eq!(refused.next_window, 0);
        assert!(!refused.current_import_may_be_durable);
        assert_eq!(
            integrity::snapshot(&f.directory.0.join("destination"))?,
            before
        );
    }
    Ok(())
}
