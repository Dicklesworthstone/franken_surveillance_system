#![forbid(unsafe_code)]
//! Exact production delivery metadata, compiled without a runtime. These tests establish
//! canonical identity and decoder behavior only; they do not simulate file or ledger custody.

#[path = "../../fss-reference/src/review_media/delivery/wire.rs"]
mod delivery_wire;

use delivery_wire::{
    Completion, MAX_DELIVERY_RECORD_BYTES, ReviewDeliveryFileIdentity, ReviewDeliveryRecord,
    ReviewDeliveryState, delivery_identity,
};
use fss_core::{
    CanonicalEncoder, CaptureInterval, ContentDigest, DigestAlgorithm, LedgerAnchor, PrincipalId,
    TimestampNs,
};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn started() -> Test<ReviewDeliveryRecord> {
    let site = "site:delivery-wire";
    let recipient = PrincipalId::parse("principal:delivery-reader")?;
    let root = ContentDigest::sha256(b"retained review root");
    let record = ContentDigest::sha256(b"retained review record");
    let media = ContentDigest::sha256(b"screened media bytes");
    let destination = ContentDigest::sha256(b"held private parent and exact leaf");
    let mut value = ReviewDeliveryRecord {
        identity: delivery_identity(site, &recipient, root, record, media, 20, destination),
        site: site.into(),
        recipient,
        review_root: root,
        review_record: record,
        media_digest: media,
        media_bytes: 20,
        destination,
        reader_authority: ContentDigest::sha256(b"principal/privacy/retention/site/generation"),
        started_at: CaptureInterval::new(TimestampNs(20), TimestampNs(30))?,
        basis: LedgerAnchor::genesis(site),
        completion: None,
        wire: Vec::new(),
    };
    value.seal()?;
    Ok(value)
}

fn verified() -> Test<ReviewDeliveryRecord> {
    let mut value = started()?;
    value.completion = Some(Completion {
        started_record: value.digest(),
        now: CaptureInterval::new(TimestampNs(40), TimestampNs(50))?,
        file: ReviewDeliveryFileIdentity {
            device: 12,
            inode: 456,
        },
        modified: (10, 123),
        changed: (11, 456),
    });
    value.basis.commit_sequence = 1;
    value.seal()?;
    Ok(value)
}

#[test]
fn started_and_verified_records_round_trip_without_exposing_media_or_paths() -> Test {
    let start = started()?;
    let end = verified()?;
    assert_eq!(start.state(), ReviewDeliveryState::Started);
    assert_eq!(start.verified_at(), None);
    assert_eq!(start.verified_file(), None);
    assert_eq!(end.state(), ReviewDeliveryState::Verified);
    assert_eq!(
        end.verified_at(),
        Some(CaptureInterval::new(TimestampNs(40), TimestampNs(50))?)
    );
    assert_eq!(
        end.verified_file(),
        Some(ReviewDeliveryFileIdentity {
            device: 12,
            inode: 456
        })
    );
    assert_eq!(start.identity(), end.identity());
    assert_ne!(start.digest(), end.digest());
    assert_eq!(
        end.completion
            .as_ref()
            .ok_or("missing completion")?
            .started_record,
        start.digest()
    );
    for value in [&start, &end] {
        let decoded = ReviewDeliveryRecord::from_bytes(value.to_bytes(), value.digest())?;
        assert_eq!(&decoded, value);
        assert_eq!(decoded.review_root(), start.review_root);
        assert_eq!(decoded.review_record_digest(), start.review_record);
        assert_eq!(decoded.media_digest(), start.media_digest);
        assert_eq!(decoded.media_bytes(), 20);
        assert_eq!(decoded.recipient(), &start.recipient);
        assert_eq!(decoded.destination_binding(), start.destination);
        assert_eq!(decoded.started_at(), start.started_at);
        assert!(
            !value
                .to_bytes()
                .windows(20)
                .any(|w| w == b"screened media bytes")
        );
        assert!(
            !value
                .to_bytes()
                .windows(19)
                .any(|w| w == b"held private parent")
        );
    }
    Ok(())
}

#[test]
fn identity_binds_every_delivery_target_coordinate_but_not_current_time() -> Test {
    let value = started()?;
    let other = ContentDigest::sha256(b"different");
    let another_reader = PrincipalId::parse("principal:another-reader")?;
    for identity in [
        delivery_identity(
            "site:other",
            &value.recipient,
            value.review_root,
            value.review_record,
            value.media_digest,
            value.media_bytes,
            value.destination,
        ),
        delivery_identity(
            &value.site,
            &another_reader,
            value.review_root,
            value.review_record,
            value.media_digest,
            value.media_bytes,
            value.destination,
        ),
        delivery_identity(
            &value.site,
            &value.recipient,
            other,
            value.review_record,
            value.media_digest,
            value.media_bytes,
            value.destination,
        ),
        delivery_identity(
            &value.site,
            &value.recipient,
            value.review_root,
            other,
            value.media_digest,
            value.media_bytes,
            value.destination,
        ),
        delivery_identity(
            &value.site,
            &value.recipient,
            value.review_root,
            value.review_record,
            other,
            value.media_bytes,
            value.destination,
        ),
        delivery_identity(
            &value.site,
            &value.recipient,
            value.review_root,
            value.review_record,
            value.media_digest,
            value.media_bytes + 1,
            value.destination,
        ),
        delivery_identity(
            &value.site,
            &value.recipient,
            value.review_root,
            value.review_record,
            value.media_digest,
            value.media_bytes,
            other,
        ),
    ] {
        assert_ne!(identity, value.identity());
    }
    let mut retried = verified()?;
    retried.completion.as_mut().ok_or("missing completion")?.now =
        CaptureInterval::new(TimestampNs(60), TimestampNs(70))?;
    retried.seal()?;
    assert_eq!(retried.identity(), value.identity());
    assert_ne!(retried.digest(), verified()?.digest());
    Ok(())
}

#[test]
fn rehashed_malformed_metadata_never_passes_the_production_decoder() -> Test {
    for value in [started()?, verified()?] {
        for end in 0..value.to_bytes().len() {
            let truncated = &value.to_bytes()[..end];
            assert!(
                ReviewDeliveryRecord::from_bytes(truncated, ContentDigest::sha256(truncated))
                    .is_err()
            );
        }
        let mut extra = value.to_bytes().to_vec();
        extra.push(0);
        assert!(ReviewDeliveryRecord::from_bytes(&extra, ContentDigest::sha256(&extra)).is_err());
        assert!(
            ReviewDeliveryRecord::from_bytes(
                value.to_bytes(),
                ContentDigest::sha256(b"wrong expected digest")
            )
            .is_err()
        );
        let mut wrong_identity = value.to_bytes().to_vec();
        let digest = value.identity().bytes();
        let offset = wrong_identity
            .windows(digest.len())
            .position(|w| w == digest)
            .ok_or("identity absent")?;
        wrong_identity[offset] ^= 1;
        assert!(
            ReviewDeliveryRecord::from_bytes(
                &wrong_identity,
                ContentDigest::sha256(&wrong_identity)
            )
            .is_err()
        );
        let mut wrong_profile = value.to_bytes().to_vec();
        let offset = wrong_profile
            .windows(8)
            .position(|w| w == b"readback")
            .ok_or("profile absent")?;
        wrong_profile[offset] = b'x';
        assert!(
            ReviewDeliveryRecord::from_bytes(&wrong_profile, ContentDigest::sha256(&wrong_profile))
                .is_err()
        );
    }
    let oversized = vec![0; MAX_DELIVERY_RECORD_BYTES + 1];
    assert!(
        ReviewDeliveryRecord::from_bytes(&oversized, ContentDigest::sha256(&oversized)).is_err()
    );
    Ok(())
}

#[test]
fn temporal_size_site_and_digest_invariants_fail_before_canonical_publication() -> Test {
    for bytes in [0, 64 * 1024 * 1024 + 1, u64::MAX] {
        let mut value = started()?;
        value.media_bytes = bytes;
        value.identity = delivery_identity(
            &value.site,
            &value.recipient,
            value.review_root,
            value.review_record,
            value.media_digest,
            bytes,
            value.destination,
        );
        assert!(value.seal().is_err());
    }
    for digest in [
        ContentDigest::new(DigestAlgorithm::Sha256, [0; 32]),
        ContentDigest::new(DigestAlgorithm::Blake3, [1; 32]),
        ContentDigest::sha256(b"laboratory").with_laboratory(true),
    ] {
        let mut value = started()?;
        value.reader_authority = digest;
        assert!(value.seal().is_err());
    }
    let mut value = started()?;
    value.basis.site_lineage = "site:other".into();
    assert!(value.seal().is_err());
    let mut value = verified()?;
    value.completion.as_mut().ok_or("missing completion")?.now =
        CaptureInterval::new(TimestampNs(10), TimestampNs(50))?;
    assert!(value.seal().is_err());
    let mut value = verified()?;
    value.completion.as_mut().ok_or("missing completion")?.now =
        CaptureInterval::new(TimestampNs(20), TimestampNs(29))?;
    assert!(value.seal().is_err());
    Ok(())
}

#[test]
fn encoded_file_timestamps_preserve_identity_and_reject_invalid_clock_fields() -> Test {
    let value = verified()?;
    let mut needle = CanonicalEncoder::new();
    needle.i128(10);
    needle.u32(123);
    let needle = needle.finish();
    let offset = value
        .to_bytes()
        .windows(needle.len())
        .position(|w| w == needle)
        .ok_or("file timestamp absent")?;
    for (seconds, nanos) in [(10, 1_000_000_000_u32), (i128::MAX, 123_u32)] {
        let mut invalid = CanonicalEncoder::new();
        invalid.i128(seconds);
        invalid.u32(nanos);
        let invalid = invalid.finish();
        assert_eq!(needle.len(), invalid.len());
        let mut bytes = value.to_bytes().to_vec();
        bytes[offset..offset + invalid.len()].copy_from_slice(&invalid);
        assert!(ReviewDeliveryRecord::from_bytes(&bytes, ContentDigest::sha256(&bytes)).is_err());
    }
    let mut changed = value.clone();
    changed
        .completion
        .as_mut()
        .ok_or("missing completion")?
        .modified
        .1 += 1;
    changed.seal()?;
    assert_eq!(changed.identity(), value.identity());
    assert_ne!(changed.digest(), value.digest());
    assert!(ReviewDeliveryRecord::from_bytes(changed.to_bytes(), value.digest()).is_err());
    Ok(())
}
