#![forbid(unsafe_code)]
//! Full native checker contracts over immutable recorded fixtures.
mod http_check_support;
use fss_publication::{NeverCancel, PublishCancellation, PublishCutPoint};
use fss_reference::ingest::http_replay::check::*;
use http_check_support::*;

#[test]
fn validates_every_frame_and_reports_native_decode_lineage() -> Test {
    let d = Directory::new()?;
    let f = fixture(&d.0, false, &[JPEG, JPEG])?;
    let p = open(&d.0)?;
    let report = check_http_recording(&p, f.request, HttpCheckLimits::default(), &NeverCancel)?;
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
    let reference = check_http_recording(&p, f.request, HttpCheckLimits::default(), &NeverCancel)?;
    for read_bytes in [1, 7, 257, 65536] {
        let report = check_http_recording(
            &p,
            f.request,
            HttpCheckLimits {
                read_bytes,
                ..Default::default()
            },
            &NeverCancel,
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
    let report = check_http_recording(&p, f.request, HttpCheckLimits::default(), &NeverCancel)?;
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
    let report = check_http_recording(&p, f.request, HttpCheckLimits::default(), &NeverCancel)?;
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
    let report = check_http_recording(
        &p,
        f.request,
        HttpCheckLimits {
            maximum_steps: 1,
            ..Default::default()
        },
        &NeverCancel,
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
    let text = f.wire_digest.to_text();
    std::fs::write(
        p.root_dir()
            .join("spool/objects")
            .join(text.strip_prefix("sha256:").ok_or("algorithm")?),
        b"corrupt",
    )?;
    assert!(matches!(
        check_http_recording(&p, f.request, HttpCheckLimits::default(), &NeverCancel),
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
    let request = HttpCheckRequest {
        completion: Some(fss_core::ContentDigest::sha256(b"wrong end")),
        ..f.request
    };
    assert!(matches!(
        check_http_recording(&p, request, HttpCheckLimits::default(), &NeverCancel),
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
    assert!(matches!(
        check_http_recording(&p, f.request, HttpCheckLimits::default(), &Stop),
        Err(HttpCheckError::Cancelled)
    ));
    assert_eq!(p.visible_roots().count(), 1);
    Ok(())
}
