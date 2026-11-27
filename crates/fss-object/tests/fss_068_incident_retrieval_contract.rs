#![forbid(unsafe_code)]
//! Contract & fault suite for `FSS-068` (`fss-x4a.13.8`): deterministic incident archive retrieval
//! and independent verification without reading local raw source.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    Generation, TimestampNs,
};
use fss_object::ObjectManifest;
use fss_object::closure::CustodyLevel;
use fss_object::encryption::{CipherSuite, EncryptionContextManifest};
use fss_object::incident_retrieval::{
    IncidentRetrievalAuthority, IncidentRetrievalError, IncidentRetrievalReceipt,
    IncidentRetrievalStatus, RetrievedObjectRecord, verify_incident_retrieval,
};

type TestResult = Result<(), Box<dyn Error>>;

fn leaf_record(payload: &[u8], custody: CustodyLevel) -> (ContentDigest, RetrievedObjectRecord) {
    let digest = ContentDigest::sha256(payload);
    (
        digest,
        RetrievedObjectRecord {
            digest,
            bytes: payload.to_vec(),
            observed_custody: custody,
            is_manifest: false,
            tombstoned: false,
            indeterminate_remote_state: false,
        },
    )
}

fn manifest_record(
    manifest: &ObjectManifest,
    custody: CustodyLevel,
) -> (ContentDigest, RetrievedObjectRecord) {
    let bytes = manifest.canonical_bytes();
    let digest = manifest.root();
    (
        digest,
        RetrievedObjectRecord {
            digest,
            bytes,
            observed_custody: custody,
            is_manifest: true,
            tombstoned: false,
            indeterminate_remote_state: false,
        },
    )
}

fn make_authority(
    allowed_roots: impl IntoIterator<Item = ContentDigest>,
    floor: CustodyLevel,
) -> IncidentRetrievalAuthority {
    IncidentRetrievalAuthority {
        incident_id: "inc:2026-driveway-007".to_owned(),
        principal_id: "owner:primary-operator".to_owned(),
        authority_grant_digest: ContentDigest::sha256(b"grant:incident-read-007"),
        generation: Generation(4),
        allowed_incident_roots: allowed_roots.into_iter().collect::<BTreeSet<_>>(),
        required_custody_floor: floor,
        max_objects: 256,
        max_bytes: 16 * 1024 * 1024,
    }
}

#[test]
fn fss_068_verified_nested_incident_retrieval_encryption_coverage_and_canonical_roundtrip()
-> TestResult {
    let (c0_digest, c0_rec) =
        leaf_record(b"encrypted-chunk-0-ciphertext", CustodyLevel::Retrievable);
    let (c1_digest, c1_rec) =
        leaf_record(b"encrypted-chunk-1-ciphertext", CustodyLevel::Retrievable);
    let (meta_digest, meta_rec) =
        leaf_record(b"incident-event-metadata-json", CustodyLevel::Retrievable);

    let seg_manifest = ObjectManifest::new("segment", [c0_digest, c1_digest], None)?;
    let (seg_digest, seg_rec) = manifest_record(&seg_manifest, CustodyLevel::Retrievable);

    let root_manifest = ObjectManifest::new("incident", [seg_digest], Some(meta_digest))?;
    let (root_digest, root_rec) = manifest_record(&root_manifest, CustodyLevel::Retrievable);

    let enc_ctx = EncryptionContextManifest::genesis(
        CipherSuite::ChaCha20Poly1305,
        "kms:site-home:key-v4",
        [0x42; 16],
        vec![c0_digest, c1_digest, meta_digest],
    )?;

    let mut store = BTreeMap::new();
    store.insert(c0_digest, c0_rec);
    store.insert(c1_digest, c1_rec);
    store.insert(meta_digest, meta_rec);
    store.insert(seg_digest, seg_rec);
    store.insert(root_digest, root_rec);

    let auth = make_authority([root_digest], CustodyLevel::Retrievable);
    let receipt = verify_incident_retrieval(
        &auth,
        root_digest,
        &store,
        Some(&enc_ctx),
        TimestampNs(1_700_000_000_000),
        || false,
    )?;

    assert_eq!(
        receipt.status,
        IncidentRetrievalStatus::VerifiedRetrievableComplete
    );
    assert_eq!(receipt.verified_objects.len(), 5);
    assert!(receipt.verified_bytes > 0);
    assert!(!receipt.read_local_source);
    assert_eq!(receipt.encryption_context_digest, Some(enc_ctx.digest()));
    assert!(receipt.missing_digests.is_empty());
    assert!(receipt.corrupt_digests.is_empty());
    assert!(receipt.below_custody_floor_digests.is_empty());
    assert!(receipt.tombstoned_digests.is_empty());
    assert!(receipt.indeterminate_digests.is_empty());
    assert!(receipt.uncovered_encryption_digests.is_empty());
    assert!(receipt.verify_digest());

    // Canonical binary round-trip.
    let mut enc = CanonicalEncoder::new();
    receipt.encode_canonical(&mut enc);
    let bytes = enc.finish();
    let decoded = IncidentRetrievalReceipt::decode_canonical(&mut CanonicalDecoder::new(&bytes))?;
    assert_eq!(decoded, receipt);

    println!(
        "CAPLOG {{\"step\":\"fss_068_incident_verified\",\"objects\":{},\"bytes\":{},\"status\":\"{}\",\"verdict\":\"ok\"}}",
        receipt.verified_objects.len(),
        receipt.verified_bytes,
        receipt.status.as_str()
    );
    Ok(())
}

#[test]
fn fss_068_preserves_authority_custody_floor_corruption_indeterminate_budget_cancel_and_tamper()
-> TestResult {
    let (c0_digest, c0_rec) = leaf_record(b"chunk-good-0", CustodyLevel::Retrievable);
    let (c1_digest, mut c1_rec) = leaf_record(b"chunk-bad-1", CustodyLevel::Retrievable);
    let root_manifest = ObjectManifest::new("incident", [c0_digest, c1_digest], None)?;
    let (root_digest, root_rec) = manifest_record(&root_manifest, CustodyLevel::Retrievable);

    // 1. Authority-before-read: unauthorized root NEVER expands or touches objects!
    let unauth = make_authority(
        [ContentDigest::sha256(b"other-root")],
        CustodyLevel::Retrievable,
    );
    let r_unauth = verify_incident_retrieval(
        &unauth,
        root_digest,
        &BTreeMap::new(),
        None,
        TimestampNs(100),
        || false,
    )?;
    assert_eq!(r_unauth.status, IncidentRetrievalStatus::UnauthorizedScope);
    assert!(r_unauth.verified_objects.is_empty());
    assert_eq!(r_unauth.verified_bytes, 0);
    assert!(r_unauth.missing_digests.is_empty());

    let auth = make_authority([root_digest], CustodyLevel::Retrievable);

    // 2. Corrupt byte payload (independent SHA-256 mismatch) preserves valid partial sibling!
    c1_rec.bytes[0] ^= 0xFF;
    let mut store_corrupt = BTreeMap::new();
    store_corrupt.insert(root_digest, root_rec.clone());
    store_corrupt.insert(c0_digest, c0_rec.clone());
    store_corrupt.insert(c1_digest, c1_rec);
    let r_corrupt = verify_incident_retrieval(
        &auth,
        root_digest,
        &store_corrupt,
        None,
        TimestampNs(200),
        || false,
    )?;
    assert_eq!(
        r_corrupt.status,
        IncidentRetrievalStatus::PartialCorruptOrMissing
    );
    assert_eq!(r_corrupt.verified_objects.len(), 2); // root + c0 preserved!
    assert_eq!(r_corrupt.corrupt_digests, vec![c1_digest]);

    // 3. Custody floor non-collapse: Replicated object does NOT satisfy Retrievable!
    let (_, mut c1_repl) = leaf_record(b"chunk-bad-1", CustodyLevel::Replicated);
    let mut store_floor = BTreeMap::new();
    store_floor.insert(root_digest, root_rec.clone());
    store_floor.insert(c0_digest, c0_rec.clone());
    store_floor.insert(c1_digest, c1_repl.clone());
    let r_floor = verify_incident_retrieval(
        &auth,
        root_digest,
        &store_floor,
        None,
        TimestampNs(300),
        || false,
    )?;
    assert_eq!(
        r_floor.status,
        IncidentRetrievalStatus::PartialCorruptOrMissing
    );
    assert_eq!(r_floor.below_custody_floor_digests, vec![c1_digest]);

    // 4. Indeterminate remote observation stays IndeterminateRemoteObservation (never upgraded!).
    c1_repl.observed_custody = CustodyLevel::Retrievable;
    c1_repl.indeterminate_remote_state = true;
    store_floor.insert(c1_digest, c1_repl);
    let r_indet = verify_incident_retrieval(
        &auth,
        root_digest,
        &store_floor,
        None,
        TimestampNs(400),
        || false,
    )?;
    assert_eq!(
        r_indet.status,
        IncidentRetrievalStatus::IndeterminateRemoteObservation
    );
    assert_eq!(r_indet.indeterminate_digests, vec![c1_digest]);
    assert_eq!(r_indet.verified_objects.len(), 2);

    // 5. Uncovered encryption leaf refused!
    let (_, c1_good) = leaf_record(b"chunk-bad-1", CustodyLevel::Retrievable);
    let mut store_full = BTreeMap::new();
    store_full.insert(root_digest, root_rec);
    store_full.insert(c0_digest, c0_rec);
    store_full.insert(c1_digest, c1_good);
    let partial_enc = EncryptionContextManifest::genesis(
        CipherSuite::Aes256Gcm,
        "kms:key-v4",
        [0x11; 16],
        vec![c0_digest], // c1_digest omitted!
    )?;
    let r_uncovered = verify_incident_retrieval(
        &auth,
        root_digest,
        &store_full,
        Some(&partial_enc),
        TimestampNs(500),
        || false,
    )?;
    assert_eq!(
        r_uncovered.status,
        IncidentRetrievalStatus::PartialCorruptOrMissing
    );
    assert_eq!(r_uncovered.uncovered_encryption_digests, vec![c1_digest]);

    // 6. Hard object budget ceiling & cooperative cancellation.
    let mut tiny_auth = auth.clone();
    tiny_auth.max_objects = 2;
    assert!(matches!(
        verify_incident_retrieval(
            &tiny_auth,
            root_digest,
            &store_full,
            None,
            TimestampNs(600),
            || false
        ),
        Err(IncidentRetrievalError::BudgetExceeded { objects: 3, .. })
    ));
    assert_eq!(
        verify_incident_retrieval(
            &auth,
            root_digest,
            &store_full,
            None,
            TimestampNs(600),
            || true
        ),
        Err(IncidentRetrievalError::Cancelled)
    );

    // 7. Wire-level forgery claiming VerifiedRetrievableComplete despite missing digest OR
    //    read_local_source == true MUST be rejected even with recomputed SHA-256!
    let mut forged = r_corrupt.clone();
    forged.status = IncidentRetrievalStatus::VerifiedRetrievableComplete;
    forged.receipt_digest = forged.computed_digest();
    let mut bad_enc = CanonicalEncoder::new();
    forged.encode_canonical(&mut bad_enc);
    assert!(
        IncidentRetrievalReceipt::decode_canonical(&mut CanonicalDecoder::new(&bad_enc.finish()))
            .is_err()
    );

    let mut forged_local = r_unauth;
    forged_local.read_local_source = true;
    forged_local.receipt_digest = forged_local.computed_digest();
    let mut bad_enc2 = CanonicalEncoder::new();
    forged_local.encode_canonical(&mut bad_enc2);
    assert!(
        IncidentRetrievalReceipt::decode_canonical(&mut CanonicalDecoder::new(&bad_enc2.finish()))
            .is_err()
    );

    // 8. Non-manifest incident root must be refused as corrupt (cannot bypass manifest closure),
    //    and wire-level forged receipt duplicating a digest across verified & corrupt sets refused!
    let (plain_root_digest, plain_root_rec) = leaf_record(
        b"plain-blob-pretending-to-be-root",
        CustodyLevel::Retrievable,
    );
    let mut plain_store = BTreeMap::new();
    plain_store.insert(plain_root_digest, plain_root_rec);
    let plain_auth = make_authority([plain_root_digest], CustodyLevel::Retrievable);
    let r_plain_root = verify_incident_retrieval(
        &plain_auth,
        plain_root_digest,
        &plain_store,
        None,
        TimestampNs(700),
        || false,
    )?;
    assert_eq!(
        r_plain_root.status,
        IncidentRetrievalStatus::PartialCorruptOrMissing
    );
    assert_eq!(r_plain_root.corrupt_digests, vec![plain_root_digest]);
    assert!(r_plain_root.verified_objects.is_empty());

    let mut forged_overlap = r_corrupt;
    forged_overlap.verified_objects.push(c1_digest);
    forged_overlap.verified_objects.sort_unstable();
    forged_overlap.receipt_digest = forged_overlap.computed_digest();
    let mut bad_enc3 = CanonicalEncoder::new();
    forged_overlap.encode_canonical(&mut bad_enc3);
    assert!(
        IncidentRetrievalReceipt::decode_canonical(&mut CanonicalDecoder::new(&bad_enc3.finish()))
            .is_err()
    );
    Ok(())
}
