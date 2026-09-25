#![forbid(unsafe_code)]
//! Full native checker contracts over immutable recorded fixtures.
mod http_check_support;
mod privacy_live_support;
mod privacy_oracle_support;
use fss_publication::{NeverCancel, PublishCancellation, PublishCutPoint};
use fss_reference::ingest::http_replay::check::*;
use http_check_support::*;
use privacy_live_support::PrivacyDeployment;
use privacy_oracle_support::{BLOCK, block_jpeg, declare, retained_luma};

#[test]
fn validates_every_frame_and_reports_native_decode_lineage() -> Test {
    let d = Directory::new()?;
    let f = fixture(&d.0, false, &[JPEG, JPEG])?;
    let p = open(&d.0)?;
    let privacy = PrivacyDeployment::new("http-check")?;
    let report = check_http_recording(
        &p,
        f.request,
        HttpCheckLimits::default(),
        &NeverCancel,
        Some(privacy.mask()),
    )?;
    assert_eq!(report.status, HttpCheckStatus::Complete);
    assert!(report.error.is_none());
    assert_eq!(report.termination_name(), Some("explicit_framing"));
    assert_eq!(report.frames.len(), 2);
    assert!(report.decoder.is_some());
    assert!(report.decode_work > 0);
    for (n, row) in report.frames.iter().enumerate() {
        assert_eq!(row.ordinal, n as u64 + 1);
        assert_eq!(row.bytes, JPEG.len());
        assert_eq!(row.encoded, fss_core::ContentDigest::sha256(JPEG));
        assert_eq!(row.dimensions, Some([17, 13]));
        assert!(row.luma.is_some());
        assert!(row.source_runs > 0);
    }
    assert_ne!(report.frames[0].exposure, report.frames[1].exposure);
    assert_eq!(report.frames[0].luma, report.frames[1].luma);
    assert_eq!(report.position.parsed_bytes, f.request.bytes);
    assert_eq!(p.visible_roots().count(), 1);
    Ok(())
}
#[test]
fn rechunking_preserves_checked_frames_and_ordered_commitment() -> Test {
    let d = Directory::new()?;
    let f = fixture(&d.0, false, &[JPEG, JPEG])?;
    let p = open(&d.0)?;
    let privacy = PrivacyDeployment::new("http-check")?;
    let reference = check_http_recording(
        &p,
        f.request,
        HttpCheckLimits::default(),
        &NeverCancel,
        Some(privacy.mask()),
    )?;
    for read_bytes in [1, 7, 257, 65536] {
        let report = check_http_recording(
            &p,
            f.request,
            HttpCheckLimits {
                read_bytes,
                ..Default::default()
            },
            &NeverCancel,
            Some(privacy.mask()),
        )?;
        assert_eq!(report.status, HttpCheckStatus::Complete);
        assert_eq!(report.frames, reference.frames);
        assert_eq!(report.frame_chain, reference.frame_chain);
    }
    Ok(())
}
#[test]
fn unproved_close_delimitation_remains_partial_after_full_frame_checks() -> Test {
    let d = Directory::new()?;
    let f = fixture(&d.0, true, &[JPEG, JPEG])?;
    let p = open(&d.0)?;
    let privacy = PrivacyDeployment::new("http-check")?;
    let report = check_http_recording(
        &p,
        f.request,
        HttpCheckLimits::default(),
        &NeverCancel,
        Some(privacy.mask()),
    )?;
    assert_eq!(report.status, HttpCheckStatus::PrefixExhausted);
    assert_eq!(report.frames.len(), 2);
    assert!(report.termination.is_none());
    assert!(report.completion_root.is_none());
    assert!(report.error.is_none());
    Ok(())
}
#[test]
fn late_invalid_jpeg_retains_only_prior_fully_checked_rows_and_exact_failure_ordinal() -> Test {
    let d = Directory::new()?;
    let f = fixture(&d.0, false, &[JPEG, b"\xff\xd8\xff\xd9"])?;
    let p = open(&d.0)?;
    let privacy = PrivacyDeployment::new("http-check")?;
    let report = check_http_recording(
        &p,
        f.request,
        HttpCheckLimits::default(),
        &NeverCancel,
        Some(privacy.mask()),
    )?;
    assert_eq!(report.status, HttpCheckStatus::Refused);
    assert!(matches!(
        report.error,
        Some(HttpCheckError::Decode { ordinal: 2, .. })
    ));
    assert_eq!(report.frames.len(), 1);
    assert_eq!(report.frames[0].ordinal, 1);
    assert_eq!(report.position.transferred_frames, 2);
    assert!(report.termination.is_none());
    assert_eq!(p.visible_roots().count(), 1);
    Ok(())
}
#[test]
fn no_decode_is_explicit_and_never_promoted_to_decoded_success() -> Test {
    let d = Directory::new()?;
    let f = fixture(&d.0, false, &[b"\xff\xd8\xff\xd9"])?;
    let p = open(&d.0)?;
    let privacy = PrivacyDeployment::new("http-check")?;
    let request = HttpCheckRequest {
        decode: HttpCheckDecode::None,
        ..f.request
    };
    let report = check_http_recording(
        &p,
        request,
        HttpCheckLimits {
            decode_work: 0,
            ..Default::default()
        },
        &NeverCancel,
        Some(privacy.mask()),
    )?;
    assert_eq!(report.status, HttpCheckStatus::Complete);
    assert_eq!(report.decode_work, 0);
    assert!(report.decoder.is_none());
    assert_eq!(report.frames.len(), 1);
    assert!(report.frames[0].dimensions.is_none());
    assert!(report.frames[0].luma.is_none());
    Ok(())
}
#[test]
fn step_and_decode_pressure_return_typed_refusal_not_empty_scene() -> Test {
    let d = Directory::new()?;
    let f = fixture(&d.0, false, &[JPEG])?;
    let p = open(&d.0)?;
    let privacy = PrivacyDeployment::new("http-check")?;
    let report = check_http_recording(
        &p,
        f.request,
        HttpCheckLimits {
            maximum_steps: 1,
            ..Default::default()
        },
        &NeverCancel,
        Some(privacy.mask()),
    )?;
    assert_eq!(report.status, HttpCheckStatus::Refused);
    assert_eq!(report.error, Some(HttpCheckError::Limit));
    assert_eq!(report.steps, 1);
    assert!(report.frames.is_empty());
    let report = check_http_recording(
        &p,
        f.request,
        HttpCheckLimits {
            decode_work: 0,
            ..Default::default()
        },
        &NeverCancel,
        Some(privacy.mask()),
    )?;
    assert_eq!(report.status, HttpCheckStatus::Refused);
    assert!(matches!(
        report.error,
        Some(HttpCheckError::Decode { ordinal: 1, .. })
    ));
    assert!(report.frames.is_empty());
    assert!(report.termination.is_none());
    Ok(())
}
#[test]
fn corrupted_originals_fail_before_frame_checks_without_repair() -> Test {
    let d = Directory::new()?;
    let f = fixture(&d.0, false, &[JPEG])?;
    let p = open(&d.0)?;
    let privacy = PrivacyDeployment::new("http-check")?;
    let text = f.wire_digest.to_text();
    std::fs::write(
        p.root_dir()
            .join("spool/objects")
            .join(text.strip_prefix("sha256:").ok_or("algorithm")?),
        b"corrupt",
    )?;
    assert!(matches!(
        check_http_recording(
            &p,
            f.request,
            HttpCheckLimits::default(),
            &NeverCancel,
            Some(privacy.mask())
        ),
        Err(HttpCheckError::Archive(_))
    ));
    assert_eq!(p.visible_roots().count(), 1);
    Ok(())
}
#[test]
fn a_requested_but_invalid_terminal_root_never_falls_back_to_prefix_only() -> Test {
    let d = Directory::new()?;
    let f = fixture(&d.0, true, &[JPEG])?;
    let p = open(&d.0)?;
    let privacy = PrivacyDeployment::new("http-check")?;
    let request = HttpCheckRequest {
        completion: Some(fss_core::ContentDigest::sha256(b"wrong end")),
        ..f.request
    };
    assert!(matches!(
        check_http_recording(
            &p,
            request,
            HttpCheckLimits::default(),
            &NeverCancel,
            Some(privacy.mask())
        ),
        Err(HttpCheckError::Completion(_))
    ));
    Ok(())
}
struct Stop;
impl PublishCancellation for Stop {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        true
    }
}
#[test]
fn revoked_original_access_is_rejected_before_replay() -> Test {
    let d = Directory::new()?;
    let f = fixture(&d.0, false, &[JPEG])?;
    let p = open(&d.0)?;
    let privacy = PrivacyDeployment::new("http-check")?;
    assert!(matches!(
        check_http_recording(
            &p,
            f.request,
            HttpCheckLimits::default(),
            &Stop,
            Some(privacy.mask())
        ),
        Err(HttpCheckError::Cancelled)
    ));
    assert_eq!(p.visible_roots().count(), 1);
    Ok(())
}

fn sha(bytes: [u8; 32]) -> fss_core::ContentDigest {
    fss_core::ContentDigest::new(fss_core::DigestAlgorithm::Sha256, bytes)
}
#[test]
fn a_decoding_check_that_names_no_sensor_is_refused_before_reading_originals() -> Test {
    let d = Directory::new()?;
    let f = fixture(&d.0, false, &[JPEG])?;
    let p = open(&d.0)?;
    for decode in [HttpCheckDecode::Grayscale, HttpCheckDecode::YCbCr] {
        let request = HttpCheckRequest {
            decode,
            ..f.request
        };
        let refused =
            check_http_recording(&p, request, HttpCheckLimits::default(), &NeverCancel, None);
        assert!(matches!(
            refused,
            Err(HttpCheckError::Privacy(refusal))
                if refusal.stable_id() == "ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001"
        ));
    }
    // Framing-only checks read no pixels and need no sensor.
    let request = HttpCheckRequest {
        decode: HttpCheckDecode::None,
        ..f.request
    };
    let report = check_http_recording(&p, request, HttpCheckLimits::default(), &NeverCancel, None)?;
    assert_eq!(report.status, HttpCheckStatus::Complete);
    assert_eq!(report.privacy.label(), "no_policy_declared");
    Ok(())
}
#[test]
fn a_masked_sensor_check_digests_only_masked_luma_equal_to_the_retained_decode() -> Test {
    let d = Directory::new()?;
    let (a, b) = (block_jpeg(0)?, block_jpeg(1)?);
    let f = fixture(&d.0, false, &[a.as_slice(), b.as_slice()])?;
    let p = open(&d.0)?;
    let mut privacy = PrivacyDeployment::new("http-check-masked")?;
    let unmasked = check_http_recording(
        &p,
        f.request,
        HttpCheckLimits::default(),
        &NeverCancel,
        Some(privacy.mask()),
    )?;
    assert_eq!(unmasked.privacy.label(), "no_policy_declared");
    // Motion: the two frames differ (only inside the block).
    assert_ne!(unmasked.frames[0].luma, unmasked.frames[1].luma);
    let policy = declare(&mut privacy, [17, 13], &[BLOCK])?;
    let masked = check_http_recording(
        &p,
        f.request,
        HttpCheckLimits::default(),
        &NeverCancel,
        Some(privacy.mask()),
    )?;
    assert_eq!(masked.status, HttpCheckStatus::Complete);
    assert_eq!(masked.privacy.policy_digest(), Some(policy));
    // Motion inside the masked block leaves no trace in the evidence: both digests are equal,
    // and each is the retained-decode masked digest of the same frame.
    assert_eq!(masked.frames[0].luma, masked.frames[1].luma);
    let retained_a = retained_luma(&mut privacy, &a, "a")?;
    let retained_b = retained_luma(&mut privacy, &b, "b")?;
    assert_eq!(masked.frames[0].luma, Some(sha(retained_a)));
    assert_eq!(masked.frames[1].luma, Some(sha(retained_b)));
    assert_ne!(masked.frames[0].luma, unmasked.frames[0].luma);
    // The ordered commitment binds the policy; the source identities are unchanged custody.
    assert_ne!(masked.frame_chain, unmasked.frame_chain);
    for (m, u) in masked.frames.iter().zip(&unmasked.frames) {
        assert_eq!(
            (m.encoded, m.exposure, m.bytes),
            (u.encoded, u.exposure, u.bytes)
        );
    }
    // A policy whose declared resolution differs from the frames is refused, never bypassed.
    declare(&mut privacy, [16, 13], &[BLOCK])?;
    let report = check_http_recording(
        &p,
        f.request,
        HttpCheckLimits::default(),
        &NeverCancel,
        Some(privacy.mask()),
    )?;
    assert_eq!(report.status, HttpCheckStatus::Refused);
    assert!(report.frames.is_empty());
    assert!(matches!(
        report.error,
        Some(HttpCheckError::Privacy(refusal))
            if refusal.stable_id() == "ERR-PRIVACY-MASK-RESOLUTION-001"
    ));
    Ok(())
}
/// No-policy check output is pinned to the bytes produced before live masking existed.
#[test]
fn no_policy_check_digests_and_frame_chain_are_unchanged() -> Test {
    let d = Directory::new()?;
    let f = fixture(&d.0, false, &[JPEG, JPEG])?;
    let p = open(&d.0)?;
    let privacy = PrivacyDeployment::new("http-check-golden")?;
    let report = check_http_recording(
        &p,
        f.request,
        HttpCheckLimits::default(),
        &NeverCancel,
        Some(privacy.mask()),
    )?;
    assert_eq!(report.frames.len(), 2);
    for row in &report.frames {
        assert_eq!(
            row.luma.map(|d| d.to_text()).as_deref(),
            Some(GOLDEN_GRAY_LUMA)
        );
    }
    assert_eq!(report.frame_chain.to_text(), GOLDEN_CHECK_FRAME_CHAIN);
    assert_eq!(report.privacy.label(), "no_policy_declared");
    Ok(())
}
// Captured from the pre-masking checker at 40bf5a6 (same fixture, same limits).
const GOLDEN_GRAY_LUMA: &str =
    "sha256:5875da5ed7274432c2e42d253dae128c4a7d4be02f9122f72f3688a0a0b86f1d";
const GOLDEN_CHECK_FRAME_CHAIN: &str =
    "sha256:9d3bd03bb706e2f42626c778f08208d1e725ca3e94f5cec749d38c3cb7c8f5dd";
