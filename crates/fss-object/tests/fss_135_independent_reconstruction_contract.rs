#![forbid(unsafe_code)]
//! Contract & differential tests for `FSS-135` (`fss-x4a.13.19`): independent reconstruction of
//! archive roots from raw manifests, GF(256) repair recovery, and differential cross-check against
//! `FSS-127` `ClosureVerifier`.

use fss_core::{CanonicalEncode, ContentDigest, TimestampNs};
use fss_object::closure::{
    ClosureAuthorityContext, ClosureBudget, ClosureVerdict, ClosureVerifier, CustodyLevel,
};
use fss_object::independent_reconstruct::{
    ATP_INDEPENDENT_RECONSTRUCTION_DOMAIN, ColdArchiveBlobSet, IndependentArchiveReconstructor,
    IndependentReconstructionProof, RECONSTRUCTION_PROOF_MAGIC, RECONSTRUCTION_PROOF_VERSION,
    ReconstructionError, ReconstructionGuidance, ReconstructionVerdict, RepairFallbackBundle,
};
use fss_object::repair_gate::{RepairAuthorityContext, RepairLease, RepairPlan};
use fss_object::{InMemoryObjectStore, ObjectLimits, ObjectManifest};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

#[test]
fn independent_manifest_reconstruction_matches_fss127_and_recovers_erased_child_via_gf256()
-> TestResult {
    // 1. Build a nested 3-level archive graph in `InMemoryObjectStore` to serve as the FSS-127 oracle!
    let mut store = InMemoryObjectStore::new(ObjectLimits::default());
    let chunk_a = b"camera-front-h265-gop-001-bytes-aaa".to_vec();
    let chunk_b = (0..640_u32)
        .map(|i| ((i.wrapping_mul(37).wrapping_add(11)) & 0xFF) as u8)
        .collect::<Vec<u8>>();
    let meta_bytes = b"fss.segment.meta.v1:cam-front:seq1".to_vec();
    let audio_bytes = b"camera-front-pcm-audio-chunk-001".to_vec();

    let d_a = store.put_verified(&chunk_a)?;
    let d_b = store.put_verified(&chunk_b)?;
    let d_meta = store.put_verified(&meta_bytes)?;
    let d_audio = store.put_verified(&audio_bytes)?;

    let sub_manifest = ObjectManifest::new("fss.segment.v1", [d_a, d_b], Some(d_meta))?;
    let sub_bytes = sub_manifest.canonical_bytes();
    let d_sub = store.publish_manifest(sub_manifest)?.root;

    let top_manifest = ObjectManifest::new("fss.archive_root.v1", [d_sub, d_audio], None)?;
    let top_bytes = top_manifest.canonical_bytes();
    let d_top = store.publish_manifest(top_manifest)?.root;

    // 2. Run FSS-127 `ClosureVerifier` on `store` as the differential oracle.
    let basis = ContentDigest::sha256(b"basis:fss135-diff");
    let closure_auth = ClosureAuthorityContext::active_all_edges(basis, 4, 2);
    let closure_witness = ClosureVerifier::verify_closure(
        &store,
        d_top,
        &closure_auth,
        CustodyLevel::Verified,
        ClosureBudget::DEFAULT,
        |_| false,
    )?;
    assert_eq!(closure_witness.verdict, ClosureVerdict::VerifiedComplete);

    // 3. Export ONLY raw immutable bytes into `ColdArchiveBlobSet` — ZERO store metadata!
    //    Deliberately ERASE `chunk_b` and supply ONLY GF(256) repair symbols (missing 2 source symbols)!
    let mut cold = ColdArchiveBlobSet::new();
    assert_eq!(cold.insert_verified_blob(chunk_a), d_a);
    // `chunk_b` deliberately omitted from `cold.blobs`!
    assert_eq!(cold.insert_verified_blob(meta_bytes), d_meta);
    assert_eq!(cold.insert_verified_blob(audio_bytes), d_audio);
    assert_eq!(cold.insert_verified_blob(sub_bytes), d_sub);
    assert_eq!(cold.insert_verified_blob(top_bytes), d_top);

    let repair_plan = RepairPlan::seal(d_top, d_b, chunk_b.len() as u64, 1, basis, 4, 64, 3)?;
    let all_syms = repair_plan.encode_symbols(&chunk_b)?;
    // Lose source ESIs 0 and 4; keep remaining 8 source + 2 repair symbols (= 10 == k).
    let surviving_syms = all_syms
        .into_iter()
        .filter(|s| s.esi != 0 && s.esi != 4)
        .collect();
    let lease = RepairLease {
        lease_id: "lease:reconstruct-135".to_owned(),
        plan_digest: repair_plan.plan_digest,
        fence: 1,
        authority_generation: 4,
        expires_at: TimestampNs(50_000),
        active: true,
    };
    cold.insert_repair_fallback(
        d_b,
        RepairFallbackBundle {
            plan: repair_plan,
            lease,
            min_fence: 1,
            symbols: surviving_syms,
        },
    );

    // 4. Independently reconstruct archive root from raw manifests + GF(256) fallback!
    let auth = RepairAuthorityContext::active(basis, 4, 2);
    let proof = IndependentArchiveReconstructor::reconstruct_root(
        &cold,
        d_top,
        &auth,
        TimestampNs(10_000),
        false,
    )?;
    assert!(proof.is_complete());
    assert_eq!(proof.verdict, ReconstructionVerdict::VerifiedComplete);
    assert_eq!(proof.repaired_member_count, 1);
    assert_eq!(proof.max_observed_depth, 2);
    assert_eq!(
        ATP_INDEPENDENT_RECONSTRUCTION_DOMAIN,
        "fss.atp_independent_reconstruction_proof.v1"
    );

    // 5. Differential proof: exact bottom-up canonical post-order member digests agree 100% with FSS-127!
    let indep_digests: Vec<ContentDigest> =
        proof.ordered_members.iter().map(|m| m.digest).collect();
    let fss127_digests: Vec<ContentDigest> = closure_witness
        .ordered_members
        .iter()
        .map(|m| m.digest)
        .collect();
    assert_eq!(
        indep_digests, fss127_digests,
        "independent manifest reconstruction must match FSS-127 ClosureVerifier post-order bit-identically"
    );
    let repaired_entry = proof
        .ordered_members
        .iter()
        .find(|m| m.digest == d_b)
        .expect("repaired child present");
    assert!(repaired_entry.recovered_via_repair);

    // 6. Wire codec round-trip (`FSSIRP01` v1).
    let wire = proof.to_canonical_bytes()?;
    assert_eq!(&wire[..8], &RECONSTRUCTION_PROOF_MAGIC);
    assert_eq!(
        u32::from_be_bytes([wire[8], wire[9], wire[10], wire[11]]),
        RECONSTRUCTION_PROOF_VERSION
    );
    assert_eq!(
        IndependentReconstructionProof::from_canonical_bytes(&wire)?,
        proof
    );

    emit_caplog(
        "fss135_independent_reconstruction_diff_fss127_and_gf256",
        "bit_identical_post_order_with_fss127_and_gf256_recovery_verified",
        "bit_identical_post_order_with_fss127_and_gf256_recovery_verified",
        "pass",
    );
    Ok(())
}

#[test]
fn missing_blob_corrupt_blob_corrupt_repair_authority_cancel_and_hostile_wire() -> TestResult {
    let basis = ContentDigest::sha256(b"basis:fss135-faults");
    let auth = RepairAuthorityContext::active(basis, 2, 1);

    let leaf_bytes = b"leaf-payload-bytes".to_vec();
    let d_leaf = ContentDigest::sha256(&leaf_bytes);
    let root_manifest = ObjectManifest::new("fss.clip.v1", [d_leaf], None)?;
    let root_bytes = root_manifest.canonical_bytes();
    let d_root = root_manifest.root();

    // 1. Missing child blob (no repair bundle) -> IncompleteMissingBlobs (NEVER VerifiedComplete!).
    let mut missing_cold = ColdArchiveBlobSet::new();
    missing_cold.insert_verified_blob(root_bytes.clone());
    let missing_proof = IndependentArchiveReconstructor::reconstruct_root(
        &missing_cold,
        d_root,
        &auth,
        TimestampNs(1_000),
        false,
    )?;
    assert!(!missing_proof.is_complete());
    assert_eq!(
        missing_proof.verdict,
        ReconstructionVerdict::IncompleteMissingBlobs
    );
    assert_eq!(missing_proof.defects.len(), 1);
    assert_eq!(missing_proof.defects[0].kind, "missing_blob");

    // 2. Corrupt child blob (1-bit flip under claimed digest) -> CorruptOrQuarantined!
    let mut corrupt_cold = ColdArchiveBlobSet::new();
    corrupt_cold.insert_verified_blob(root_bytes);
    let mut bad_leaf = leaf_bytes;
    bad_leaf[0] ^= 0x01;
    corrupt_cold.insert_claimed_blob(d_leaf, bad_leaf);
    let corrupt_proof = IndependentArchiveReconstructor::reconstruct_root(
        &corrupt_cold,
        d_root,
        &auth,
        TimestampNs(2_000),
        false,
    )?;
    assert_eq!(
        corrupt_proof.verdict,
        ReconstructionVerdict::CorruptOrQuarantined
    );
    assert_eq!(corrupt_proof.defects[0].kind, "digest_mismatch");

    // 3. XFER-INV-006: Effect authority escalation and cancellation fail closed.
    let mut escalated = auth.clone();
    escalated.grants_effect_authority = true;
    let esc_err = IndependentArchiveReconstructor::reconstruct_root(
        &corrupt_cold,
        d_root,
        &escalated,
        TimestampNs(2_000),
        false,
    )
    .expect_err("effect escalation must fail closed");
    assert!(matches!(esc_err, ReconstructionError::AuthorityRefused(_)));
    assert_eq!(
        esc_err.guidance(),
        ReconstructionGuidance::ReauthorizeReconstruction
    );
    assert_eq!(
        IndependentArchiveReconstructor::reconstruct_root(
            &corrupt_cold,
            d_root,
            &auth,
            TimestampNs(2_000),
            true,
        ),
        Err(ReconstructionError::Cancelled)
    );

    // 4. Hostile wire decoding on `FSSIRP01`.
    let wire = corrupt_proof.to_canonical_bytes()?;
    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        IndependentReconstructionProof::from_canonical_bytes(&bad_magic),
        Err(ReconstructionError::InvalidMagic)
    );
    let mut bad_ver = wire.clone();
    bad_ver[8..12].copy_from_slice(&9_u32.to_be_bytes());
    assert_eq!(
        IndependentReconstructionProof::from_canonical_bytes(&bad_ver),
        Err(ReconstructionError::UnsupportedVersion { version: 9 })
    );
    assert!(matches!(
        IndependentReconstructionProof::from_canonical_bytes(&wire[..wire.len() - 5]),
        Err(ReconstructionError::MalformedWire(_))
    ));
    let mut bit_flip = wire.clone();
    let last = bit_flip.len() - 1;
    bit_flip[last] ^= 0x01;
    assert_eq!(
        IndependentReconstructionProof::from_canonical_bytes(&bit_flip),
        Err(ReconstructionError::ChecksumMismatch)
    );
    let mut trailing = wire;
    trailing.push(0x01);
    assert!(matches!(
        IndependentReconstructionProof::from_canonical_bytes(&trailing),
        Err(ReconstructionError::MalformedWire(_))
    ));

    emit_caplog(
        "fss135_missing_corrupt_authority_cancel_and_wire",
        "all_independent_reconstruction_faults_and_wire_checks_verified",
        "all_independent_reconstruction_faults_and_wire_checks_verified",
        "pass",
    );
    Ok(())
}
