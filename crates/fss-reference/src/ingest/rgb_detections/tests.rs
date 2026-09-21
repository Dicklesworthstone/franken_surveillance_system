#![forbid(unsafe_code)]
use super::*;
type Test = Result<(), Box<dyn std::error::Error>>;
fn spec() -> RgbDetectionSpec {
    RgbDetectionSpec { model: ContentDigest::sha256(b"numeric-fixture"), output_port: "head".into(),
        labels: vec!["fixture-a".into(), "fixture-b".into()], layout: HeadLayout::Rows,
        boxes: HeadBoxes::PixelCorners, class_score: HeadScore::Probability, objectness: None,
        classes: HeadClasses::Best, minimum_score_ppm: 500_000, nms_iou_ppm: 500_000,
        maximum_rows: 100, maximum_candidates: 100, maximum_detections: 100 }
}
fn geometry() -> ResizeGeometry {
    ResizeGeometry { source_width: 16, source_height: 8, target_width: 8, target_height: 8,
        image_width: 8, image_height: 4, left: 0, top: 2 }
}
fn budget() -> RgbDetectionBudget { RgbDetectionBudget::new(100_000_000, 32 * 1024 * 1024) }
fn decode(rows: &[[f32; 6]], s: RgbDetectionSpec, mask: &[u8]) -> Result<Parts, RgbDetectionError> {
    let mut values: Vec<_> = rows.iter().flat_map(|r| r.iter().copied()).collect();
    let shape = if s.layout == HeadLayout::Channels {
        values = (0..6).flat_map(|c| rows.iter().map(move |r| r[c])).collect();
        [1, 6, rows.len()]
    } else { [1, rows.len(), 6] };
    decode_head(&shape, &values, geometry(), mask, ContentDigest::sha256(mask).bytes(),
        &RgbDetectionContract::new(s)?, &mut budget(), &ScalarExecCx::new())
}
#[test]
fn both_dense_axis_orders_produce_identical_source_proposals() -> Test {
    let rows = [[1.0, 3.0, 3.0, 5.0, 0.8, 0.1], [4.0, 3.0, 6.0, 5.0, 0.1, 0.9]];
    let a = decode(&rows, spec(), &[1; 128])?;
    let b = decode(&rows, RgbDetectionSpec { layout: HeadLayout::Channels, ..spec() }, &[1; 128])?;
    assert_eq!(a.rows, b.rows); assert_eq!(a.candidates, b.candidates);
    assert_eq!(a.detections, b.detections);
    assert_eq!(a.detections[0].class_index(), 1);
    assert_eq!(a.detections[1].bounds(), [512, 512, 1536, 1536]); Ok(())
}
#[test]
fn all_four_box_encodings_agree_after_letterbox_reversal() -> Test {
    let expected = [512, 512, 1536, 1536];
    for (encoding, b) in [(HeadBoxes::PixelCorners, [1.0, 3.0, 3.0, 5.0]),
        (HeadBoxes::PixelCenterSize, [2.0, 4.0, 2.0, 2.0]),
        (HeadBoxes::NormalizedCorners, [0.125, 0.375, 0.375, 0.625]),
        (HeadBoxes::NormalizedCenterSize, [0.25, 0.5, 0.25, 0.25])] {
        let r = decode(&[[b[0], b[1], b[2], b[3], 0.75, 0.25]],
            RgbDetectionSpec { boxes: encoding, ..spec() }, &[1; 128])?;
        assert_eq!(r.detections[0].bounds(), expected); assert!(!r.detections[0].clipped());
    }
    Ok(())
}
#[test]
fn padding_and_clipping_are_explicit_not_phantom_source_boxes() -> Test {
    let r = decode(&[[0.0, 0.0, 8.0, 1.0, 0.8, 0.1], [-1.0, 1.0, 9.0, 7.0, 0.9, 0.1]], spec(), &[1; 128])?;
    assert_eq!(r.rows[0].disposition, HeadRowDisposition::OutsideImage);
    assert_eq!(r.detections.len(), 1); assert!(r.detections[0].clipped());
    assert_eq!(r.detections[0].bounds(), [0, 0, 4096, 2048]); Ok(())
}
#[test]
fn full_pixel_footprint_not_just_center_controls_privacy() -> Test {
    let mut mask = [1; 128]; mask[2 * 16 + 2] = 0;
    let r = decode(&[[1.0, 3.0, 3.0, 5.0, 0.9, 0.1], [4.0, 3.0, 6.0, 5.0, 0.9, 0.1]], spec(), &mask)?;
    assert_eq!(r.rows[0].disposition, HeadRowDisposition::PrivateFootprint);
    assert_eq!(r.detections.len(), 1); assert_eq!(r.detections[0].row(), 1);
    let mut wrong = mask; wrong[0] = 2;
    assert!(matches!(decode(&[], spec(), &wrong), Err(RgbDetectionError::MaskMismatch))); Ok(())
}
#[test]
fn fractional_source_bounds_are_outward_rounded_before_privacy_and_nms() -> Test {
    let r = decode(&[[0.1, 2.1, 0.2, 2.2, 0.9, 0.1]], spec(), &[1; 128])?;
    assert_eq!(r.detections[0].bounds(), [51, 51, 103, 103]);
    let mut mask = [1; 128]; mask[0] = 0;
    let r = decode(&[[0.1, 2.1, 0.2, 2.2, 0.9, 0.1]], spec(), &mask)?;
    assert_eq!(r.rows[0].disposition, HeadRowDisposition::PrivateFootprint); Ok(())
}
#[test]
fn class_aware_nms_retains_all_decisions_and_ties_choose_original_row() -> Test {
    let rows = [[1.0, 3.0, 3.0, 5.0, 0.8, 0.1], [1.0, 3.0, 3.0, 5.0, 0.8, 0.1],
        [1.0, 3.0, 3.0, 5.0, 0.1, 0.8]];
    let r = decode(&rows, spec(), &[1; 128])?;
    assert_eq!(r.candidates.len(), 3); assert_eq!(r.detections.len(), 2);
    assert_eq!(r.candidates[1].suppressed_by, Some(0));
    assert_eq!(r.candidates[2].suppressed_by, None);
    assert_eq!(r.detections.iter().map(|d| d.row()).collect::<Vec<_>>(), [0, 2]); Ok(())
}
#[test]
fn threshold_is_inclusive_and_iou_comparison_is_strict() -> Test {
    let row = [1.0, 3.0, 3.0, 5.0, 0.5, 0.1];
    let r = decode(&[row, row], RgbDetectionSpec { nms_iou_ppm: 1_000_000, ..spec() }, &[1; 128])?;
    assert_eq!(r.detections.len(), 2);
    assert!(!suppresses([0, 0, 512, 512], [0, 0, 256, 512], 500_000));
    assert!(suppresses([0, 0, 512, 512], [0, 0, 256, 512], 499_999)); Ok(())
}
#[test]
fn multilabel_is_explicit_and_best_class_ties_are_deterministic() -> Test {
    let row = [1.0, 3.0, 3.0, 5.0, 0.75, 0.75];
    let best = decode(&[row], spec(), &[1; 128])?;
    assert_eq!(best.detections.len(), 1); assert_eq!(best.detections[0].class_index(), 0);
    let multi = decode(&[row], RgbDetectionSpec { classes: HeadClasses::MultiLabel, ..spec() }, &[1; 128])?;
    assert_eq!(multi.detections.len(), 2);
    assert_eq!(multi.rows[0].disposition, HeadRowDisposition::Candidates(2)); Ok(())
}
#[test]
fn objectness_and_logit_rules_are_not_inferred_or_applied_twice() -> Test {
    let s = RgbDetectionSpec { objectness: Some(HeadScore::Logit), class_score: HeadScore::Logit,
        minimum_score_ppm: 250_000, ..spec() };
    let c = RgbDetectionContract::new(s)?;
    let r = decode_head(&[1, 1, 7], &[1.0, 3.0, 3.0, 5.0, 0.0, 0.0, -100.0], geometry(),
        &[1; 128], ContentDigest::sha256(&[1; 128]).bytes(), &c, &mut budget(), &ScalarExecCx::new())?;
    assert_eq!(r.detections[0].score(), 0.25); assert_eq!(r.detections[0].class_index(), 0);
    let s = RgbDetectionSpec { objectness: Some(HeadScore::Probability), minimum_score_ppm: 500_000, ..spec() };
    let c = RgbDetectionContract::new(s)?;
    let r = decode_head(&[1, 1, 7], &[1.0, 3.0, 3.0, 5.0, 0.25, 0.99, 0.01], geometry(),
        &[1; 128], ContentDigest::sha256(&[1; 128]).bytes(), &c, &mut budget(), &ScalarExecCx::new())?;
    assert!(r.detections.is_empty()); assert_eq!(r.rows[0].disposition, HeadRowDisposition::BelowThreshold); Ok(())
}
#[test]
fn malformed_low_score_rows_and_losing_classes_cannot_hide_behind_filtering() -> Test {
    for row in [[1.0, 3.0, 1.0, 5.0, 0.0, 0.0], [1.0, 3.0, 3.0, 5.0, 0.0, -0.1],
        [1.0, 3.0, 3.0, 5.0, 0.9, f32::NAN], [1.0, 3.0, 3.0, 5.0, 0.9, 1.1],
        [f32::INFINITY, 3.0, 3.0, 5.0, 0.0, 0.0]] {
        assert!(matches!(decode(&[row], spec(), &[1; 128]), Err(RgbDetectionError::InvalidOutput)));
    }
    Ok(())
}
#[test]
fn no_pre_or_post_nms_topk_truncation_occurs() -> Test {
    let row = [1.0, 3.0, 3.0, 5.0, 0.8, 0.1];
    let c = RgbDetectionSpec { maximum_candidates: 1, maximum_detections: 1, ..spec() };
    assert!(matches!(decode(&[row, row], c, &[1; 128]), Err(RgbDetectionError::Limit)));
    let c = RgbDetectionSpec { maximum_detections: 1, nms_iou_ppm: 1_000_000, ..spec() };
    assert!(matches!(decode(&[row, row], c, &[1; 128]), Err(RgbDetectionError::Limit)));
    let r = decode(&[row, row], RgbDetectionSpec { maximum_detections: 1, ..spec() }, &[1; 128])?;
    assert_eq!(r.detections.len(), 1); assert_eq!(r.candidates.len(), 2); Ok(())
}
#[test]
fn shape_mask_scratch_and_cancellation_refusals_are_explicit() -> Test {
    let c = RgbDetectionContract::new(spec())?; let cx = ScalarExecCx::new();
    let mask = [1; 128]; let hash = ContentDigest::sha256(&mask).bytes();
    for shape in [vec![1, 6], vec![2, 1, 6], vec![1, 0, 7]] {
        assert!(matches!(decode_head(&shape, &[], geometry(), &mask, hash, &c, &mut budget(), &cx), Err(RgbDetectionError::InvalidOutput)));
    }
    assert!(matches!(decode_head(&[1, 0, 6], &[], geometry(), &mask, [9; 32], &c,
        &mut budget(), &cx), Err(RgbDetectionError::MaskMismatch)));
    assert!(matches!(decode_head(&[1, 0, 6], &[], geometry(), &mask, hash, &c,
        &mut RgbDetectionBudget::new(1_000_000, 1), &cx), Err(RgbDetectionError::Limit)));
    cx.request_cancellation();
    assert!(matches!(decode_head(&[1, 0, 6], &[], geometry(), &mask, hash, &c,
        &mut budget(), &cx), Err(RgbDetectionError::Cancelled))); Ok(())
}
#[test]
fn every_core_budget_cut_refuses_atomically_and_retry_reproduces() -> Test {
    let values = [1.0, 3.0, 3.0, 5.0, 0.8, 0.1, 1.0, 3.0, 3.0, 5.0, 0.7, 0.1];
    let c = RgbDetectionContract::new(spec())?; let mask = [1; 128];
    let hash = ContentDigest::sha256(&mask).bytes(); let cx = ScalarExecCx::new(); let mut full = budget();
    let expected = decode_head(&[1, 2, 6], &values, geometry(), &mask, hash, &c, &mut full, &cx)?;
    for limit in 0..full.used() {
        let mut cut = RgbDetectionBudget::new(limit, 32 * 1024 * 1024);
        assert!(matches!(decode_head(&[1, 2, 6], &values, geometry(), &mask, hash, &c, &mut cut, &cx),
            Err(RgbDetectionError::BudgetExceeded)));
    }
    let replay = decode_head(&[1, 2, 6], &values, geometry(), &mask, hash, &c, &mut budget(), &cx)?;
    assert_eq!(expected.candidates, replay.candidates); Ok(())
}
#[test]
fn head_capacity_admits_8400_rows_without_mock_topk() -> Test {
    let rows = vec![[1.0, 3.0, 3.0, 5.0, 0.0, 0.0]; 8400];
    let r = decode(&rows, RgbDetectionSpec { maximum_rows: 8400, ..spec() }, &[1; 128])?;
    assert_eq!(r.rows.len(), 8400); assert!(r.detections.is_empty()); Ok(())
}
#[test]
fn contract_identity_binds_interpretation_and_rejects_ambiguous_vocabulary() -> Test {
    let a = RgbDetectionContract::new(spec())?;
    for s in [RgbDetectionSpec { layout: HeadLayout::Channels, ..spec() },
        RgbDetectionSpec { boxes: HeadBoxes::PixelCenterSize, ..spec() },
        RgbDetectionSpec { classes: HeadClasses::MultiLabel, ..spec() },
        RgbDetectionSpec { minimum_score_ppm: 500_001, ..spec() },
        RgbDetectionSpec { maximum_rows: 101, ..spec() },
        RgbDetectionSpec { labels: vec!["other-a".into(), "other-b".into()], ..spec() }] {
        assert_ne!(a.digest(), RgbDetectionContract::new(s)?.digest());
    }
    for s in [RgbDetectionSpec { labels: vec!["same".into(), "same".into()], ..spec() },
        RgbDetectionSpec { maximum_detections: 0, ..spec() },
        RgbDetectionSpec { minimum_score_ppm: 1_000_001, ..spec() }] {
        assert!(matches!(RgbDetectionContract::new(s), Err(RgbDetectionError::InvalidContract)));
    }
    Ok(())
}
