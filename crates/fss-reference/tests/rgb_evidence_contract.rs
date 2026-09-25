#![forbid(unsafe_code)]
//! RGB evidence envelopes rebuilt from original sources; forged or truncated envelopes are refused.
use fss_codec_mjpeg::DecodeBudget;
use fss_core::ContentDigest;
use fss_reference::ScalarExecCx;
use fss_reference::ingest::model_import::ImportBudget;
use fss_reference::ingest::rgb_detections::RgbDetectionBudget;
use fss_reference::ingest::rgb_evidence::*;
use fss_twin::image_tracking::TrackingAvailability;
mod rgb_evidence_support;
use rgb_evidence_support::privacy_live_support::PrivacyDeployment;
use rgb_evidence_support::*;

#[test]
fn original_sources_rebuild_outputs_after_every_old_runtime_object_is_gone() -> Test {
    let cx = context(&std::env::temp_dir())?;
    let original = capture(1, TrackingAvailability::Available, &cx)?;
    let expected = replay(&original, &cx)?;
    let identity = original.identity();
    let bytes = original.encode(
        RgbEvidenceLimits::default(),
        &mut RgbEvidenceBudget::new(WORK),
        &cx,
    )?;
    drop(original); // Imported model, inputs, execution and original run already dropped by fixture.
    let restored = RgbEvidence::decode(
        &bytes,
        identity,
        RgbEvidenceLimits::default(),
        &mut RgbEvidenceBudget::new(WORK),
        &cx,
    )?;
    let actual = replay(&restored, &cx)?;
    assert_eq!(
        actual.run().inference().identity(),
        expected.run().inference().identity()
    );
    assert_eq!(
        actual.run().report().digest(),
        expected.run().report().digest()
    );
    assert_eq!(
        actual.run().inference().outputs()["head"].values(),
        expected.run().inference().outputs()["head"].values()
    );
    assert_eq!(actual.run().report().detections().len(), 1);
    assert_eq!(restored.jpeg(), jpeg(1));
    assert_eq!(restored.weights(), weights());
    assert_eq!(restored.graph(), graph()?);
    assert_eq!(
        restored.encode(
            RgbEvidenceLimits::default(),
            &mut RgbEvidenceBudget::new(WORK),
            &cx
        )?,
        bytes
    );
    Ok(())
}
#[test]
fn changed_original_source_cannot_hide_behind_valid_envelope_framing() -> Test {
    let cx = context(&std::env::temp_dir())?;
    let e = capture(1, TrackingAvailability::Available, &cx)?;
    let original = e.encode(
        RgbEvidenceLimits::default(),
        &mut RgbEvidenceBudget::new(WORK),
        &cx,
    )?;
    let mut at = 8;
    for _ in 0..5 {
        let len = u64::from_le_bytes(original[at..at + 8].try_into()?) as usize;
        at += 8;
        let mut bad = original.clone();
        bad[at + len - 1] ^= 1;
        assert!(
            RgbEvidence::decode(
                &bad,
                e.identity(),
                RgbEvidenceLimits::default(),
                &mut RgbEvidenceBudget::new(WORK),
                &cx
            )
            .is_err()
        );
        at += len;
    }
    Ok(())
}
#[test]
fn self_consistent_envelope_does_not_certify_a_forged_result_digest() -> Test {
    let privacy = PrivacyDeployment::new("rgb-evidence")?;
    let cx = context(&std::env::temp_dir())?;
    let e = capture(1, TrackingAvailability::Available, &cx)?;
    let mut bytes = e.encode(
        RgbEvidenceLimits::default(),
        &mut RgbEvidenceBudget::new(WORK),
        &cx,
    )?;
    let n = u64::from_le_bytes(bytes[8..16].try_into()?) as usize;
    bytes[16 + n - 1] ^= 1; // Last recipe field is the claimed head result digest, not a source byte.
    let forged = ContentDigest::sha256(&bytes[16..16 + n]);
    let structural = RgbEvidence::decode(
        &bytes,
        forged,
        RgbEvidenceLimits::default(),
        &mut RgbEvidenceBudget::new(WORK),
        &cx,
    )?;
    assert!(matches!(
        structural.replay(
            privacy.mask(),
            limits(),
            &mut RgbEvidenceBudget::new(WORK),
            &mut ImportBudget::new(WORK),
            &mut DecodeBudget::new(WORK),
            &mut RgbDetectionBudget::new(WORK, 32 * 1024 * 1024),
            &cx,
            &ScalarExecCx::new()
        ),
        Err(RgbEvidenceError::Mismatch)
    ));
    Ok(())
}
#[test]
fn all_truncations_suffix_and_unbounded_length_are_refused_before_output() -> Test {
    let cx = context(&std::env::temp_dir())?;
    let e = capture(1, TrackingAvailability::Available, &cx)?;
    let bytes = e.encode(
        RgbEvidenceLimits::default(),
        &mut RgbEvidenceBudget::new(WORK),
        &cx,
    )?;
    for n in 0..bytes.len() {
        assert!(
            RgbEvidence::decode(
                &bytes[..n],
                e.identity(),
                RgbEvidenceLimits::default(),
                &mut RgbEvidenceBudget::new(WORK),
                &cx
            )
            .is_err()
        );
    }
    let mut suffix = bytes.clone();
    suffix.push(0);
    let mut overflow = bytes.clone();
    overflow[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
    for bad in [suffix, overflow] {
        assert!(
            RgbEvidence::decode(
                &bad,
                e.identity(),
                RgbEvidenceLimits::default(),
                &mut RgbEvidenceBudget::new(WORK),
                &cx
            )
            .is_err()
        );
    }
    Ok(())
}
#[test]
fn availability_and_uncertain_capture_intervals_survive_exactly() -> Test {
    let cx = context(&std::env::temp_dir())?;
    for availability in [
        TrackingAvailability::Available,
        TrackingAvailability::Disturbed,
        TrackingAvailability::Unobservable,
    ] {
        let e = capture(2, availability, &cx)?;
        let r = replay(&e, &cx)?;
        assert_eq!(r.admission().availability(), availability);
        assert_eq!(
            r.admission().evidence(),
            ContentDigest::new(fss_core::DigestAlgorithm::Sha256, [5; 32])
        );
        assert_eq!(
            r.admission().source().capture,
            [2_000_000_000, 2_000_000_001]
        );
        assert_eq!(r.run().allowed(), &[1; 128]);
    }
    Ok(())
}
#[test]
fn independent_resource_refusals_do_not_consume_or_change_evidence() -> Test {
    let privacy = PrivacyDeployment::new("rgb-evidence")?;
    let cx = context(&std::env::temp_dir())?;
    let e = capture(1, TrackingAvailability::Available, &cx)?;
    let id = e.identity();
    for stage in 0..4 {
        let mut l = limits();
        if stage == 3 {
            l.run.execution.max_macs = 0;
        }
        assert!(
            e.replay(
                privacy.mask(),
                l,
                &mut RgbEvidenceBudget::new(WORK),
                &mut ImportBudget::new(if stage == 0 { 0 } else { WORK }),
                &mut DecodeBudget::new(if stage == 1 { 0 } else { WORK }),
                &mut RgbDetectionBudget::new(if stage == 2 { 0 } else { WORK }, 32 * 1024 * 1024),
                &cx,
                &ScalarExecCx::new()
            )
            .is_err()
        );
        assert_eq!(e.identity(), id);
        assert_eq!(replay(&e, &cx)?.evidence_identity(), id);
    }
    let cancelled = ScalarExecCx::new();
    cancelled.request_cancellation();
    assert!(
        e.replay(
            privacy.mask(),
            limits(),
            &mut RgbEvidenceBudget::new(WORK),
            &mut ImportBudget::new(WORK),
            &mut DecodeBudget::new(WORK),
            &mut RgbDetectionBudget::new(WORK, 32 * 1024 * 1024),
            &cx,
            &cancelled
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn successful_allowances_do_not_change_envelope_or_replayed_identity() -> Test {
    let privacy = PrivacyDeployment::new("rgb-evidence")?;
    let cx = context(&std::env::temp_dir())?;
    let e = capture(1, TrackingAvailability::Available, &cx)?;
    let mut full = RgbEvidenceBudget::new(WORK);
    let bytes = e.encode(RgbEvidenceLimits::default(), &mut full, &cx)?;
    let exact = RgbEvidenceLimits {
        maximum_bytes: bytes.len(),
        maximum_source_bytes: e.weights().len().max(e.graph().len()).max(e.jpeg().len()),
    };
    assert_eq!(
        e.encode(exact, &mut RgbEvidenceBudget::new(full.used()), &cx)?,
        bytes
    );
    assert!(matches!(
        e.encode(exact, &mut RgbEvidenceBudget::new(full.used() - 1), &cx),
        Err(RgbEvidenceError::BudgetExceeded)
    ));
    let small = RgbEvidenceLimits {
        maximum_bytes: bytes.len() - 1,
        ..exact
    };
    assert!(matches!(
        e.encode(small, &mut RgbEvidenceBudget::new(WORK), &cx),
        Err(RgbEvidenceError::Limit)
    ));
    let a = replay(&e, &cx)?;
    let mut l = limits();
    l.run.execution.max_macs *= 2;
    let b = e.replay(
        privacy.mask(),
        l,
        &mut RgbEvidenceBudget::new(WORK),
        &mut ImportBudget::new(WORK),
        &mut DecodeBudget::new(WORK),
        &mut RgbDetectionBudget::new(WORK, 32 * 1024 * 1024),
        &cx,
        &ScalarExecCx::new(),
    )?;
    assert_eq!(a.run().report().digest(), b.run().report().digest());
    Ok(())
}

fn declare(p: &mut PrivacyDeployment, rectangles: &[[u32; 4]]) -> Test<ContentDigest> {
    use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
    let policy = PrivacyMaskPolicy::new(p.sensor.clone(), [16, 8], rectangles)?;
    let preview = preview_mask(&p.deployment, &policy)?;
    Ok(declare_mask(&mut p.deployment, &policy, preview.approval, &p.cx)?.policy_digest)
}
fn replay_under(
    e: &RgbEvidence,
    privacy: &PrivacyDeployment,
    cx: &fss_reference::ReplayCx,
) -> Result<ReplayedRgbEvidence, RgbEvidenceError> {
    e.replay(
        privacy.mask(),
        limits(),
        &mut RgbEvidenceBudget::new(WORK),
        &mut ImportBudget::new(WORK),
        &mut DecodeBudget::new(WORK),
        &mut RgbDetectionBudget::new(WORK, 32 * 1024 * 1024),
        cx,
        &ScalarExecCx::new(),
    )
}
#[test]
fn evidence_replays_only_under_the_sensors_current_mask_binding() -> Test {
    let cx = context(&std::env::temp_dir())?;
    let mut privacy = PrivacyDeployment::new("rgb-evidence-masked")?;
    // Evidence recorded without a policy keeps its version-1 recipe and replays while the sensor
    // has none; once a policy is retained it is never replayed into unmasked pixels.
    let unmasked = capture(1, TrackingAvailability::Available, &cx)?;
    assert_eq!(unmasked.mask_policy()?, None);
    replay_under(&unmasked, &privacy, &cx)?;
    let policy = declare(&mut privacy, &[[8, 0, 8, 8]])?;
    let refused = replay_under(&unmasked, &privacy, &cx);
    assert!(matches!(
        &refused,
        Err(e) if e.privacy_stable_id() == Some("ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001")
    ));
    // Evidence of a masked frame records the policy (version 2) and replays exactly under it.
    let binding = privacy.mask().resolve()?;
    let masked = capture_with(1, TrackingAvailability::Available, &binding, &cx)?;
    assert_eq!(masked.mask_policy()?, Some(policy));
    assert_ne!(masked.identity(), unmasked.identity());
    let bytes = masked.encode(
        RgbEvidenceLimits::default(),
        &mut RgbEvidenceBudget::new(WORK),
        &cx,
    )?;
    let restored = RgbEvidence::decode(
        &bytes,
        masked.identity(),
        RgbEvidenceLimits::default(),
        &mut RgbEvidenceBudget::new(WORK),
        &cx,
    )?;
    assert_eq!(restored.mask_policy()?, Some(policy));
    let replayed = replay_under(&restored, &privacy, &cx)?;
    assert_eq!(replayed.run().mask_policy(), Some(policy));
    // The replayed model input is the masked frame: pixels x >= 8 hold the fill.
    let image = fss_codec_mjpeg::color::decode_rgb(
        restored.jpeg(),
        ContentDigest::sha256(restored.jpeg()).bytes(),
        fss_codec_mjpeg::ComponentInterpretation::YCbCr,
        Default::default(),
        &mut DecodeBudget::new(WORK),
    )?;
    let mut rgb = image.pixels().to_vec();
    for y in 0..8 {
        for x in 8..16 {
            rgb[(y * 16 + x) * 3..(y * 16 + x) * 3 + 3].copy_from_slice(&[16, 16, 16]);
        }
    }
    assert_eq!(
        replayed.run().inference().decode_receipt().rgb_sha256,
        ContentDigest::sha256(&rgb).bytes()
    );
    // The original JPEG inside the envelope is unmasked source custody.
    assert_eq!(restored.jpeg(), jpeg(1));
    // A later generation supersedes the recorded binding: replay is refused.
    declare(&mut privacy, &[[0, 0, 16, 8]])?;
    assert!(matches!(
        &replay_under(&restored, &privacy, &cx),
        Err(e) if e.privacy_stable_id() == Some("ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001")
    ));
    Ok(())
}
/// The version-1 recipe of a no-policy frame is pinned to its pre-masking bytes.
#[test]
fn no_policy_evidence_recipe_identity_is_unchanged() -> Test {
    let cx = context(&std::env::temp_dir())?;
    let evidence = capture(1, TrackingAvailability::Available, &cx)?;
    assert_eq!(evidence.identity().to_text(), GOLDEN_RECIPE_IDENTITY);
    assert_eq!(evidence.mask_policy()?, None);
    let replayed = replay(&evidence, &cx)?;
    assert_eq!(
        replayed.run().inference().identity().to_text(),
        GOLDEN_INFERENCE_IDENTITY
    );
    Ok(())
}
// Captured from the pre-masking evidence owner at 40bf5a6 (same fixture).
const GOLDEN_RECIPE_IDENTITY: &str =
    "sha256:c7e077c51d2a211a8e8f35e90ca6c1416539f0e26e22c24118906e4c294de24d";
const GOLDEN_INFERENCE_IDENTITY: &str =
    "sha256:6431cf20ff4e54d26531a7b71b34e082c7081f88f3c722e67dbd6eaa3f9cfa2c";
