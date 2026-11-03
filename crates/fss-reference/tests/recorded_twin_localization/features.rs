#![forbid(unsafe_code)]
//! Actual retained codec custody -> native corrected features, with no substitute source owner.

use super::*;
use fss_core::{CanonicalEncode, CanonicalEncoder, DigestAlgorithm};
use fss_reference::ingest::twin_localization::features::{
    FEATURE_DOMAIN, RECTIFIED_FEATURE_DOMAIN, RecordedFeatureReadBudget, RecordedFeatureRequest,
    RecordedFeatures, RecordedRectifiedFeatureRequest, STAGE_FEATURE_REVALIDATE,
    extract_recorded_features, extract_recorded_rectified_features,
};

const FEATURE_WORK: u64 = 2_000_000_000;
const FEATURE_READS: u64 = 512 * 1024 * 1024;

fn feature_options() -> ExtractionOptions {
    ExtractionOptions {
        threshold: 20,
        maximum_features: 128,
        separation: 6,
    }
}
fn spec() -> Test<RectificationSpec> {
    let camera = PinholeIntrinsics::new(96, 96, 80., 80., 48., 48.)?;
    Ok(RectificationSpec {
        source: camera,
        target: camera,
        distortion: LensDistortion::BrownConrady {
            radial: [-0.1, 0.001, 0.0001],
            tangential: [0.001, -0.001],
        },
        maximum_radius: 1.,
        source_domain: [31; 32],
        calibration: [41; 32],
        range: LumaRange::Full,
    })
}
fn compile(spec: RectificationSpec) -> Test<RectificationPlan> {
    Ok(RectificationPlan::compile(
        spec,
        &mut WorkBudget::new(FEATURE_WORK),
    )?)
}
fn extract_owned(
    imported: &mut Imported,
    source: RecordedLocalizationSource,
    rectifier: &RectificationPlan,
    reads: &RecordedFeatureReadBudget,
    work: &mut WorkBudget<'_>,
) -> Result<RecordedFeatures, RecordedLocalizationError> {
    extract_recorded_rectified_features(
        &mut imported.deployment,
        &RecordedRectifiedFeatureRequest {
            source,
            rectifier,
            extraction: feature_options(),
        },
        reads,
        &mut DecodeBudget::new(FEATURE_WORK),
        &mut RecordedVideoDecodeBudget::new(FEATURE_WORK),
        work,
        &imported.cx,
    )
}
fn completed(imported: &mut Imported, rectifier: &RectificationPlan) -> Test<RecordedFeatures> {
    let source = jpeg(imported.identity);
    Ok(extract_owned(
        imported,
        source,
        rectifier,
        &RecordedFeatureReadBudget::new(FEATURE_READS),
        &mut WorkBudget::new(FEATURE_WORK),
    )?)
}
fn native_frame(imported: &Imported) -> Test<RecordedFrame> {
    let RecordedLocalizationSource::Jpeg(request) = jpeg(imported.identity) else {
        return Err("JPEG fixture request".into());
    };
    Ok(RecordedFrame::open(
        &imported.deployment,
        &request,
        &imported.cx,
    )?)
}
fn mask(imported: &mut Imported, regions: &[[u32; 4]]) -> Test<PrivacyMaskPolicy> {
    let policy = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:retained-localize")?,
        [96, 96],
        regions,
    )?;
    let approval = preview_mask(&imported.deployment, &policy)?.approval;
    declare_mask(&mut imported.deployment, &policy, approval, &imported.cx)?;
    Ok(policy)
}

#[test]
fn rectified_jpeg_features_match_native_pixel_composition_and_keep_full_lineage() -> Test {
    let mut imported = import("features-brown", JPEG, None)?;
    let plan = compile(spec()?)?;
    let reads = RecordedFeatureReadBudget::new(FEATURE_READS);
    let mut work = WorkBudget::new(FEATURE_WORK);
    let source = jpeg(imported.identity);
    let owner = extract_owned(&mut imported, source, &plan, &reads, &mut work)?;
    assert!(!imported.directory.0.join("original.media").exists());
    assert!(!owner.frame().features().is_empty());
    assert_eq!(owner.geometry_work(), work.used());
    assert!(reads.used() > JPEG.len() as u64);
    let native = native_frame(&imported)?;
    let record = owner.rectification().ok_or("missing corrected lineage")?;
    assert_eq!(record.spec(), plan.spec());
    assert_eq!(record.receipt().map_digest, plan.map_digest());
    assert_eq!(record.receipt().output, owner.frame().identity());
    assert_eq!(record.receipt().output.image_domain, plan.output_domain());
    assert_eq!(
        record.receipt().output.exposure,
        owner.source().exposure.bytes()
    );
    assert_eq!(record.receipt().source.storage, owner.source().luma.bytes());
    assert_eq!(
        record.receipt().source.dimensions,
        owner.source().dimensions
    );
    assert_eq!(record.receipt().allowed_mask, owner.selection().mask_digest);
    assert_eq!(owner.source().encoded_source, ContentDigest::sha256(JPEG));
    assert_eq!(owner.source().decode_receipt, native.receipt().digest()?);
    assert_eq!(owner.native_receipt(), native.receipt().encoded()?);
    assert_eq!(
        owner.source().luma.bytes(),
        native.receipt().codec().luma_sha256
    );
    assert_eq!(owner.capsule(), native.receipt().capsule());

    // Composition oracle uses the independently reopened original native decode, never an
    // owner-supplied feature result or a substitute source/custody implementation.
    let allowed = vec![1; 96 * 96];
    let mut native_work = WorkBudget::new(FEATURE_WORK);
    let raw = RawGrayFrame::new(
        RawFrameIdentity {
            exposure: owner.source().exposure.bytes(),
            storage: owner.source().luma.bytes(),
            allowed_mask: ContentDigest::sha256(&allowed).bytes(),
            image_domain: plan.spec().source_domain,
            calibration: plan.spec().calibration,
            dimensions: [96, 96],
            row_stride: 96,
            range: plan.spec().range,
        },
        native.pixels(),
        &allowed,
        &mut native_work,
    )?;
    let expected = extract_raw_features(&plan, &raw, feature_options(), &mut native_work)?;
    assert_eq!(record.receipt(), expected.rectification);
    assert_eq!(owner.frame().identity(), expected.result.frame.identity());
    assert_eq!(owner.frame().features(), expected.result.frame.features());
    assert_eq!(owner.selection(), expected.result.selection);
    let used = reads.used();
    owner.revalidate(&imported.deployment, &imported.cx, &mut work)?;
    assert!(
        reads.used() > used,
        "revalidation must use the original shared source allowance"
    );
    Ok(())
}

#[test]
fn cropped_output_dimensions_do_not_replace_the_original_decode_identity() -> Test {
    let mut imported = import("features-crop", JPEG, None)?;
    let mut declared = spec()?;
    declared.target = PinholeIntrinsics::new(80, 64, 80., 80., 40., 32.)?;
    let plan = compile(declared)?;
    let owner = completed(&mut imported, &plan)?;
    let record = owner.rectification().ok_or("missing crop lineage")?;
    assert_eq!(owner.source().dimensions, [96, 96]);
    assert_eq!(record.receipt().source.dimensions, [96, 96]);
    assert_eq!(owner.frame().identity().dimensions, [80, 64]);
    assert_eq!(record.receipt().output.dimensions, [80, 64]);
    assert_eq!(owner.frame().identity().image_domain, plan.output_domain());
    assert_ne!(owner.frame().identity().pixels, owner.source().luma.bytes());
    assert_eq!(
        owner.frame().identity().exposure,
        owner.source().exposure.bytes()
    );
    for feature in owner.frame().features() {
        assert!(feature.pixel[0] >= 0. && feature.pixel[0] <= 80.);
        assert!(feature.pixel[1] >= 0. && feature.pixel[1] <= 64.);
    }
    assert!(!owner.frame().features().is_empty());
    Ok(())
}

#[test]
fn replay_and_a_later_jpeg_publication_do_not_stale_the_original_corrected_owner() -> Test {
    let mut imported = import("features-replay", JPEG, None)?;
    let plan = compile(spec()?)?;
    let owner = completed(&mut imported, &plan)?;
    let anchor = imported.deployment.current_anchor().clone();
    let replay = completed(&mut imported, &plan)?;
    assert_eq!(owner.digest(), replay.digest());
    assert_eq!(owner.geometry_work(), replay.geometry_work());
    assert_eq!(owner.rectification(), replay.rectification());
    assert_eq!(owner.frame().features(), replay.frame().features());
    assert_eq!(imported.deployment.current_anchor(), &anchor);

    let path = imported.directory.0.join("other-source.jpg");
    fs::write(&path, QFIX)?;
    let later = FileIngestAdapter::ingest(
        FileIngestRequest::new(
            &path,
            SensorId::parse("sensor:retained-localize-other")?,
            StreamId::parse("stream:retained-localize-other")?,
        )
        .with_receive_time(TimestampNs(2_000_000_000)),
        &imported.cx,
        &mut imported.deployment,
    )?;
    fs::remove_file(path)?;
    let later_source = jpeg(later.import_identity);
    let _ = extract_owned(
        &mut imported,
        later_source,
        &plan,
        &RecordedFeatureReadBudget::new(FEATURE_READS),
        &mut WorkBudget::new(FEATURE_WORK),
    )?;
    assert_ne!(imported.deployment.current_anchor(), &anchor);
    let later_anchor = imported.deployment.current_anchor().clone();
    owner.revalidate(
        &imported.deployment,
        &imported.cx,
        &mut WorkBudget::new(FEATURE_WORK),
    )?;
    assert_eq!(imported.deployment.current_anchor(), &later_anchor);
    Ok(())
}

#[test]
fn current_privacy_is_propagated_before_descriptors_and_invalidates_the_old_owner() -> Test {
    let mut imported = import("features-mask", JPEG, None)?;
    let plan = compile(spec()?)?;
    let before = completed(&mut imported, &plan)?;
    assert!(!before.frame().features().is_empty());
    let policy = mask(&mut imported, &[[0, 0, 96, 96]])?;
    assert!(
        before
            .revalidate(
                &imported.deployment,
                &imported.cx,
                &mut WorkBudget::new(FEATURE_WORK)
            )
            .is_err()
    );
    let masked = completed(&mut imported, &plan)?;
    let record = masked
        .rectification()
        .ok_or("missing masked rectification")?;
    assert!(masked.frame().features().is_empty());
    assert_eq!(masked.selection().tested_centers, 0);
    assert_eq!(masked.selection().selected, 0);
    assert_eq!(record.receipt().allowed_pixels, 0);
    assert_eq!(
        record.receipt().privacy_rejected,
        record.receipt().coverage.mapped
    );
    assert_eq!(
        record.receipt().source.allowed_mask,
        ContentDigest::sha256(&vec![0; 96 * 96]).bytes()
    );
    assert_eq!(masked.source().mask_policy, Some(policy.digest()));
    assert_eq!(
        masked.source().encoded_source,
        before.source().encoded_source
    );
    assert_eq!(masked.source().exposure, before.source().exposure);
    assert_eq!(masked.capsule(), before.capsule());
    assert_ne!(masked.digest(), before.digest());
    Ok(())
}

#[test]
fn source_capsule_and_native_pixel_loss_are_revalidated_without_silent_repair() -> Test {
    let mut imported = import("features-custody", JPEG, None)?;
    let owner = completed(&mut imported, &compile(spec()?)?)?;
    let retained = RetainedFileImport::open(
        &imported.deployment,
        imported.identity,
        RetainedReadLimits::default(),
        &imported.cx,
    )?;
    let digests = [
        retained.manifest().ordered_chunks[0],
        ContentDigest::sha256(&owner.capsule().try_canonical_bytes()?),
        owner.source().luma,
    ];
    let anchor = imported.deployment.current_anchor().clone();
    for digest in digests {
        let path = imported.deployment.publisher().spool().object_path(digest);
        let bytes = fs::read(&path)?;
        let mut corrupted = bytes.clone();
        *corrupted.last_mut().ok_or("empty custody fixture")? ^= 1;
        fs::write(&path, &corrupted)?;
        assert!(
            owner
                .revalidate(
                    &imported.deployment,
                    &imported.cx,
                    &mut WorkBudget::new(FEATURE_WORK)
                )
                .is_err()
        );
        assert_eq!(fs::read(&path)?, corrupted);
        fs::remove_file(&path)?;
        assert!(
            owner
                .revalidate(
                    &imported.deployment,
                    &imported.cx,
                    &mut WorkBudget::new(FEATURE_WORK)
                )
                .is_err()
        );
        assert!(!path.exists());
        fs::write(&path, bytes)?;
        owner.revalidate(
            &imported.deployment,
            &imported.cx,
            &mut WorkBudget::new(FEATURE_WORK),
        )?;
    }
    assert_eq!(imported.deployment.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn actual_native_source_dimensions_must_match_the_precompiled_source_model() -> Test {
    let mut imported = import("features-source-grid", JPEG, None)?;
    let mut declared = spec()?;
    declared.source = PinholeIntrinsics::new(95, 96, 80., 80., 48., 48.)?;
    let plan = compile(declared)?;
    let source = jpeg(imported.identity);
    assert!(matches!(
        extract_owned(
            &mut imported,
            source,
            &plan,
            &RecordedFeatureReadBudget::new(FEATURE_READS),
            &mut WorkBudget::new(FEATURE_WORK)
        ),
        Err(RecordedLocalizationError::SourceMismatch)
    ));
    // The source owner's ordinary JPEG decode may have completed, but no corrected frame
    // with fabricated dimensions can escape. Reopening still reports the real original grid.
    assert_eq!(native_frame(&imported)?.receipt().dimensions(), [96, 96]);
    Ok(())
}

#[test]
fn zero_source_allowance_and_invalid_selection_refuse_before_native_publication() -> Test {
    let mut imported = import("features-early-refusal", JPEG, None)?;
    let plan = compile(spec()?)?;
    let anchor = imported.deployment.current_anchor().clone();
    let source = jpeg(imported.identity);
    assert!(
        extract_owned(
            &mut imported,
            source,
            &plan,
            &RecordedFeatureReadBudget::new(0),
            &mut WorkBudget::new(FEATURE_WORK)
        )
        .is_err()
    );
    assert_eq!(imported.deployment.current_anchor(), &anchor);
    let mut extraction = feature_options();
    extraction.maximum_features = 513;
    assert!(matches!(
        extract_recorded_rectified_features(
            &mut imported.deployment,
            &RecordedRectifiedFeatureRequest {
                source: jpeg(imported.identity),
                rectifier: &plan,
                extraction
            },
            &RecordedFeatureReadBudget::new(FEATURE_READS),
            &mut DecodeBudget::new(FEATURE_WORK),
            &mut RecordedVideoDecodeBudget::new(FEATURE_WORK),
            &mut WorkBudget::new(FEATURE_WORK),
            &imported.cx,
        ),
        Err(RecordedLocalizationError::InvalidRequest)
    ));
    assert_eq!(imported.deployment.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn cumulative_work_and_cancellation_at_initial_and_final_boundaries_return_no_features() -> Test {
    let mut imported = import("features-work", JPEG, None)?;
    let plan = compile(spec()?)?;
    let complete = completed(&mut imported, &plan)?;
    let work = complete.geometry_work();
    assert!(work > 0);
    let source = jpeg(imported.identity);
    let exact = extract_owned(
        &mut imported,
        source.clone(),
        &plan,
        &RecordedFeatureReadBudget::new(FEATURE_READS),
        &mut WorkBudget::new(work),
    )?;
    assert_eq!(exact.digest(), complete.digest());
    assert!(
        extract_owned(
            &mut imported,
            source.clone(),
            &plan,
            &RecordedFeatureReadBudget::new(FEATURE_READS),
            &mut WorkBudget::new(work - 1)
        )
        .is_err()
    );
    let flag = AtomicBool::new(true);
    assert!(
        extract_owned(
            &mut imported,
            source.clone(),
            &plan,
            &RecordedFeatureReadBudget::new(FEATURE_READS),
            &mut WorkBudget::cancellable(FEATURE_WORK, &flag)
        )
        .is_err()
    );
    imported
        .cx
        .set_cancel_at_checkpoint(STAGE_FEATURE_REVALIDATE);
    assert!(matches!(
        extract_owned(
            &mut imported,
            source,
            &plan,
            &RecordedFeatureReadBudget::new(FEATURE_READS),
            &mut WorkBudget::new(FEATURE_WORK)
        ),
        Err(RecordedLocalizationError::Cancelled)
    ));
    Ok(())
}

#[test]
fn corrected_lineage_pins_every_lens_and_image_interpretation_even_for_empty_frames() -> Test {
    let mut imported = import("features-model-identity", JPEG, None)?;
    mask(&mut imported, &[[0, 0, 96, 96]])?;
    let base = spec()?;
    let original = completed(&mut imported, &compile(base)?)?;
    assert!(original.frame().features().is_empty());
    for change in 0..7 {
        let mut changed = base;
        match change {
            0 => changed.calibration[0] ^= 1,
            1 => changed.source_domain[0] ^= 1,
            2 => changed.range = LumaRange::Video,
            3 => changed.maximum_radius = 0.9,
            4 => changed.distortion = LensDistortion::Pinhole,
            5 => changed.target = PinholeIntrinsics::new(80, 64, 80., 80., 40., 32.)?,
            _ => changed.source = PinholeIntrinsics::new(96, 96, 81., 80., 48., 48.)?,
        }
        let plan = compile(changed)?;
        let owner = completed(&mut imported, &plan)?;
        assert!(owner.frame().features().is_empty());
        assert_eq!(owner.source().luma, original.source().luma);
        assert_eq!(owner.source().exposure, original.source().exposure);
        assert_ne!(
            owner.digest(),
            original.digest(),
            "unbound model variant {change}"
        );
        assert_eq!(
            owner.rectification().ok_or("rectification")?.spec(),
            changed
        );
    }
    assert_ne!(RECTIFIED_FEATURE_DOMAIN, FEATURE_DOMAIN);
    Ok(())
}

// Frozen direct-feature v1 wire order, copied from the pre-rectification contract. This is a
// compatibility oracle: changing direct encoding or charging must not pass merely because
// both old and new requests happen to call the same new helper.
fn legacy_inventory(owner: &RecordedFeatures) -> Test<Vec<u8>> {
    let b = owner.source();
    let frame = owner.frame();
    let selection = owner.selection();
    let mut e = CanonicalEncoder::new();
    e.text("fss.recorded_native_features.v1");
    e.text("derived_native_features_no_effect_authority");
    e.text(b.codec);
    for digest in [
        b.import_identity,
        b.import_root,
        b.manifest,
        b.capsule,
        b.encoded_source,
        b.exposure,
        b.luma,
        b.decode_receipt,
        b.mask_binding,
    ] {
        e.digest(digest);
    }
    b.source_anchor.encode_canonical(&mut e);
    for digest in [b.decode_root, b.mask_policy] {
        e.bool(digest.is_some());
        if let Some(digest) = digest {
            e.digest(digest);
        }
    }
    e.u64(b.segment);
    e.u64(b.range_start);
    e.u64(b.range_count);
    for dimension in b.dimensions {
        e.u32(dimension);
    }
    e.bytes(owner.native_receipt());
    e.bytes(&frame.identity().image_domain);
    e.bytes(&frame.descriptor_domain());
    e.bytes(&selection.mask_digest);
    e.u8(selection.threshold);
    e.u32(u32::from(selection.separation));
    for n in [
        selection.maximum_features,
        selection.tested_centers,
        selection.local_maxima,
        selection.selected,
        selection.omitted,
    ] {
        e.u64(n as u64);
    }
    e.u64(frame.features().len() as u64);
    for feature in frame.features() {
        e.u64(feature.id);
        for coordinate in feature.pixel {
            e.u64(coordinate.to_bits());
        }
        for word in feature.descriptor.0 {
            e.u64(word);
        }
    }
    Ok(e.finish())
}

#[test]
fn direct_feature_v1_digest_and_geometry_work_remain_compatible() -> Test {
    let mut imported = import("features-direct-v1", JPEG, None)?;
    let mut work = WorkBudget::new(FEATURE_WORK);
    let owner = extract_recorded_features(
        &mut imported.deployment,
        &RecordedFeatureRequest {
            source: jpeg(imported.identity),
            image_domain: ContentDigest::new(DigestAlgorithm::Sha256, [71; 32]),
            extraction: feature_options(),
        },
        &RecordedFeatureReadBudget::new(FEATURE_READS),
        &mut DecodeBudget::new(FEATURE_WORK),
        &mut RecordedVideoDecodeBudget::new(FEATURE_WORK),
        &mut work,
        &imported.cx,
    )?;
    assert_eq!(owner.rectification(), None);
    let frozen = legacy_inventory(&owner)?;
    assert_eq!(owner.digest(), ContentDigest::sha256(&frozen));
    let frame = native_frame(&imported)?;
    let allowed = vec![1; frame.pixels().len()];
    let mut native_work = WorkBudget::new(FEATURE_WORK);
    let image = GrayImage::new(
        owner.frame().identity(),
        frame.pixels(),
        &allowed,
        &mut native_work,
    )?;
    let expected = extract_gray(&image, feature_options(), &mut native_work)?;
    assert_eq!(expected.frame.features(), owner.frame().features());
    assert_eq!(expected.selection, owner.selection());
    let expected_work = allowed.len() as u64 + native_work.used() + frozen.len() as u64;
    assert_eq!(owner.geometry_work(), expected_work);
    assert_eq!(work.used(), expected_work);
    Ok(())
}

#[test]
fn rectified_avc_and_hevc_keep_selected_coding_identity_and_validate_the_complete_range() -> Test {
    for hevc in [false, true] {
        let mut imported = import(
            if hevc {
                "features-hevc"
            } else {
                "features-avc"
            },
            if hevc { HEVC } else { AVC },
            Some(if hevc {
                FileFormatHint::Hevc
            } else {
                FileFormatHint::AnnexB
            }),
        )?;
        let selected = 1;
        let source;
        let mut expected = None;
        if hevc {
            let request = RecordedH265Request {
                import_identity: imported.identity,
                first_segment: 0,
                segment_count: imported.count,
                interpretation: ComponentInterpretation::YCbCr,
                read_limits: RetainedReadLimits::default(),
                decoder_limits: H265Limits::default(),
            };
            let mut range =
                RecordedH265Range::open(&imported.deployment, request.clone(), &imported.cx)?;
            while let Some(frame) = range.next_frame(&imported.deployment, &imported.cx)? {
                if frame.segment_index() == selected as u64 {
                    expected = Some((
                        frame.dimensions(),
                        frame.receipt().luma_sha256(),
                        frame.receipt().digest(),
                    ));
                }
            }
            source = RecordedLocalizationSource::H265 {
                request,
                segment: selected,
            };
        } else {
            let request = RecordedH264Request {
                import_identity: imported.identity,
                first_segment: 0,
                segment_count: imported.count,
                interpretation: ComponentInterpretation::YCbCr,
                read_limits: RetainedReadLimits::default(),
                decoder_limits: DecoderLimits::default(),
            };
            let mut range =
                RecordedH264Range::open(&imported.deployment, request.clone(), &imported.cx)?;
            while let Some(frame) = range.next_frame(&imported.deployment, &imported.cx)? {
                if frame.segment_index() == selected as u64 {
                    expected = Some((
                        frame.dimensions(),
                        frame.receipt().luma_sha256(),
                        frame.receipt().digest(),
                    ));
                }
            }
            source = RecordedLocalizationSource::H264 {
                request,
                segment: selected,
            };
        }
        let ([width, height], luma, receipt) = expected.ok_or("selected video frame")?;
        let intrinsics = PinholeIntrinsics::new(
            width,
            height,
            80.,
            80.,
            f64::from(width) / 2.,
            f64::from(height) / 2.,
        )?;
        let plan = compile(RectificationSpec {
            source: intrinsics,
            target: intrinsics,
            distortion: LensDistortion::Pinhole,
            maximum_radius: 4.,
            ..spec()?
        })?;
        let anchor = imported.deployment.current_anchor().clone();
        let reads = RecordedFeatureReadBudget::new(FEATURE_READS);
        let owner = extract_owned(
            &mut imported,
            source,
            &plan,
            &reads,
            &mut WorkBudget::new(FEATURE_WORK),
        )?;
        assert_eq!(owner.source().segment, selected as u64);
        assert_eq!(owner.source().range_start, 0);
        assert_eq!(owner.source().range_count, imported.count as u64);
        assert_eq!(owner.source().decode_receipt, receipt);
        assert_eq!(owner.source().luma, luma);
        assert_eq!(owner.source().dimensions, [width, height]);
        assert!(owner.source().decode_root.is_none());
        assert_eq!(
            owner
                .rectification()
                .ok_or("video correction")?
                .receipt()
                .source
                .storage,
            luma.bytes()
        );
        let used = reads.used();
        owner.revalidate(
            &imported.deployment,
            &imported.cx,
            &mut WorkBudget::new(FEATURE_WORK),
        )?;
        assert!(reads.used() > used);
        assert_eq!(imported.deployment.current_anchor(), &anchor);
    }
    Ok(())
}

#[test]
fn a_later_unsupported_video_segment_cannot_release_earlier_corrected_features() -> Test {
    let bytes = [BASELINE, UNSUPPORTED_AVC].concat();
    let mut imported = import("features-video-tail", &bytes, Some(FileFormatHint::AnnexB))?;
    let source = RecordedLocalizationSource::H264 {
        segment: 0,
        request: RecordedH264Request {
            import_identity: imported.identity,
            first_segment: 0,
            segment_count: imported.count,
            interpretation: ComponentInterpretation::YCbCr,
            read_limits: RetainedReadLimits::default(),
            decoder_limits: DecoderLimits::default(),
        },
    };
    let anchor = imported.deployment.current_anchor().clone();
    assert!(matches!(
        extract_owned(
            &mut imported,
            source,
            &compile(spec()?)?,
            &RecordedFeatureReadBudget::new(FEATURE_READS),
            &mut WorkBudget::new(FEATURE_WORK)
        ),
        Err(RecordedLocalizationError::Decode(
            RecordedDecodeError::H264(_)
        ))
    ));
    assert_eq!(imported.deployment.current_anchor(), &anchor);
    Ok(())
}
