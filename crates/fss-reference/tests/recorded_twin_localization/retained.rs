#![forbid(unsafe_code)]
//! Complete retained-input replay; archive files and the original recording are absent.

use super::*;
use fss_geometry::GeometryBasis;
use fss_object::ObjectManifest;
use fss_publication::{LedgerCutPoint, SlotName};
use fss_reference::DeploymentLimits;
use fss_reference::ingest::twin_localization::retained::*;
use fss_twin::ImportExpectation;
use fss_twin::atlas_archive::{ArchiveExpectation, ReferenceProvenance, encode_atlas};

#[path = "archive_fixture.rs"]
mod archive_fixture;

struct Archives {
    twin: Vec<u8>,
    atlas: Vec<u8>,
}
impl Archives {
    fn new(twin: &PropertyTwin, atlas: &LocalizationAtlas) -> Test<Self> {
        let bytes = archive_fixture::twin_archive(&[0.0], None)?;
        assert_eq!(ContentDigest::sha256(&bytes).bytes(), twin.digest());
        let atlas = encode_atlas(
            atlas,
            [7; 32],
            &[ReferenceProvenance {
                reference: 1,
                source_record: [6; 32],
                allowed_mask: [5; 32],
            }],
            &mut WorkBudget::new(2_000_000_000),
        )?;
        Ok(Self { twin: bytes, atlas })
    }
    fn plan(&self, image: RecordedImageMode) -> Test<RetainedLocalizationPlan<'_>> {
        Ok(RetainedLocalizationPlan {
            twin_bytes: &self.twin,
            twin: ImportExpectation {
                package_sha256: ContentDigest::sha256(&self.twin).bytes(),
                source_scene_sha256: [1; 32],
                basis: GeometryBasis::new(9, 4)?,
            },
            atlas_bytes: &self.atlas,
            atlas: ArchiveExpectation {
                package: ContentDigest::sha256(&self.atlas).bytes(),
                provenance: [7; 32],
                descriptor: descriptor_domain(),
            },
            image,
            options: options(),
        })
    }
}

fn retain(
    imported: &mut Imported,
    source: &RecordedLocalizationSource,
    archives: &Archives,
    image: RecordedImageMode,
) -> Test<(RecordedLocalization, RetainedLocalization)> {
    Ok(localize_and_retain(
        &mut imported.deployment,
        source,
        archives.plan(image)?,
        &mut DecodeBudget::new(1_000_000_000),
        &mut RecordedVideoDecodeBudget::new(1_000_000_000),
        &mut WorkBudget::new(2_000_000_000),
        &imported.cx,
    )?)
}
fn read(imported: &Imported, identity: ContentDigest) -> Test<RetainedLocalization> {
    Ok(RetainedLocalization::open(
        &imported.deployment,
        identity,
        RetainedReadLimits::default(),
        &mut WorkBudget::new(2_000_000_000),
        &imported.cx,
    )?)
}
fn storage(deployment: &ReferenceDeployment) -> Vec<ContentDigest> {
    deployment.publisher().spool().digests().collect()
}

#[test]
fn complete_raw_jpeg_package_survives_cold_open_and_retry_and_redecodes_encoded_bytes() -> Test {
    let mut imported = import("package-jpeg", JPEG, None)?;
    let source = jpeg(imported.identity);
    let (twin, atlas, spec) = setup([1; 32])?;
    let archives = Archives::new(&twin, &atlas)?;
    let (result, retained) = retain(
        &mut imported,
        &source,
        &archives,
        RecordedImageMode::Raw(spec),
    )?;
    accurate_candidates(result.result(), 0.05)?;
    let anchor = imported.deployment.current_anchor().clone();
    let objects = storage(&imported.deployment);
    let (_, retry) = retain(
        &mut imported,
        &source,
        &archives,
        RecordedImageMode::Raw(spec),
    )?;
    assert_eq!(retry.identity(), retained.identity());
    assert_eq!(retry.publication_root(), retained.publication_root());
    assert_eq!(imported.deployment.current_anchor(), &anchor);
    assert_eq!(storage(&imported.deployment), objects);
    drop(archives);
    drop(atlas);
    drop(twin);
    drop(imported.deployment);
    imported.deployment =
        ReferenceDeployment::open(&imported.directory.0.join("deployment"), SITE, &imported.cx)?;
    let package = read(&imported, retained.identity())?;
    assert_eq!(package.receipt_bytes(), result.encoded());
    let mut jpeg = DecodeBudget::new(1_000_000_000);
    let replay = package.verify_by_replay(
        &mut imported.deployment,
        GeometryBasis::new(77, 8)?,
        &mut jpeg,
        &mut RecordedVideoDecodeBudget::new(1_000_000_000),
        &mut WorkBudget::new(2_000_000_000),
        &imported.cx,
    )?;
    assert!(
        jpeg.used() > 0,
        "cached luma must not bypass the native JPEG decoder"
    );
    assert_eq!(replay.encoded(), result.encoded());
    accurate_candidates(replay.result(), 0.05)?;
    assert_eq!(imported.deployment.current_anchor(), &anchor);
    assert_eq!(storage(&imported.deployment), objects);
    assert!(
        package
            .verify_by_replay(
                &mut imported.deployment,
                GeometryBasis::new(77, 8)?,
                &mut DecodeBudget::new(0),
                &mut RecordedVideoDecodeBudget::new(1_000_000_000),
                &mut WorkBudget::new(2_000_000_000),
                &imported.cx
            )
            .is_err()
    );
    assert_eq!(imported.deployment.current_anchor(), &anchor);
    assert_eq!(storage(&imported.deployment), objects);
    Ok(())
}

#[test]
fn avc_and_hevc_packages_replay_original_coding_selection_without_publishing_a_decode() -> Test {
    for hevc in [false, true] {
        let mut imported = import(
            if hevc { "package-hevc" } else { "package-avc" },
            if hevc { HEVC } else { AVC },
            Some(if hevc {
                FileFormatHint::Hevc
            } else {
                FileFormatHint::AnnexB
            }),
        )?;
        let (twin, atlas, _) = setup([1; 32])?;
        let archives = Archives::new(&twin, &atlas)?;
        let (source, dimensions) = if hevc {
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
            let frame = range
                .next_frame(&imported.deployment, &imported.cx)?
                .ok_or("HEVC picture")?;
            (
                RecordedLocalizationSource::H265 {
                    request,
                    segment: 1,
                },
                frame.dimensions(),
            )
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
            let frame = range
                .next_frame(&imported.deployment, &imported.cx)?
                .ok_or("AVC picture")?;
            (
                RecordedLocalizationSource::H264 {
                    request,
                    segment: 1,
                },
                frame.dimensions(),
            )
        };
        let [w, h] = dimensions;
        let image = RecordedImageMode::Pinhole(LocalizationCamera {
            intrinsics: PinholeIntrinsics::new(w, h, 80.0, 80.0, w as f64 / 2.0, h as f64 / 2.0)?,
            image_domain: [9; 32],
        });
        let (result, retained) = retain(&mut imported, &source, &archives, image)?;
        assert_eq!(result.source().segment, 1);
        assert!(result.source().decode_root.is_none());
        drop(archives);
        let anchor = imported.deployment.current_anchor().clone();
        let objects = storage(&imported.deployment);
        drop(imported.deployment);
        imported.deployment = ReferenceDeployment::open(
            &imported.directory.0.join("deployment"),
            SITE,
            &imported.cx,
        )?;
        let package = read(&imported, retained.identity())?;
        let mut video = RecordedVideoDecodeBudget::new(1_000_000_000);
        let replay = package.verify_by_replay(
            &mut imported.deployment,
            GeometryBasis::new(81, 2)?,
            &mut DecodeBudget::new(1_000_000_000),
            &mut video,
            &mut WorkBudget::new(2_000_000_000),
            &imported.cx,
        )?;
        assert!(video.used() > 0);
        assert_eq!(replay.encoded(), result.encoded());
        assert_eq!(imported.deployment.current_anchor(), &anchor);
        assert_eq!(storage(&imported.deployment), objects);
    }
    Ok(())
}

#[test]
fn package_inspection_checks_exact_archive_custody_and_current_privacy() -> Test {
    for mask_change in [false, true] {
        let mut imported = import(
            if mask_change {
                "package-mask"
            } else {
                "package-archive"
            },
            JPEG,
            None,
        )?;
        let source = jpeg(imported.identity);
        let (twin, atlas, spec) = setup([1; 32])?;
        let archives = Archives::new(&twin, &atlas)?;
        let (_, package) = retain(
            &mut imported,
            &source,
            &archives,
            RecordedImageMode::Raw(spec),
        )?;
        if mask_change {
            let policy = PrivacyMaskPolicy::new(
                SensorId::parse("sensor:retained-localize")?,
                [96, 96],
                &[[0, 0, 96, 96]],
            )?;
            let approval = preview_mask(&imported.deployment, &policy)?.approval;
            declare_mask(&mut imported.deployment, &policy, approval, &imported.cx)?;
        } else {
            fs::remove_file(
                imported
                    .deployment
                    .publisher()
                    .spool()
                    .object_path(package.atlas_package()),
            )?;
        }
        let anchor = imported.deployment.current_anchor().clone();
        assert!(read(&imported, package.identity()).is_err());
        assert!(
            retain(
                &mut imported,
                &source,
                &archives,
                RecordedImageMode::Raw(spec)
            )
            .is_err()
                || mask_change
        );
        if !mask_change {
            assert_eq!(imported.deployment.current_anchor(), &anchor);
        }
    }
    Ok(())
}

#[test]
fn fully_ledgered_rehashed_forged_candidate_receipt_fails_native_reproduction() -> Test {
    let mut imported = import("package-forged", JPEG, None)?;
    let source = jpeg(imported.identity);
    let (twin, atlas, spec) = setup([1; 32])?;
    let archives = Archives::new(&twin, &atlas)?;
    let (result, package) = retain(
        &mut imported,
        &source,
        &archives,
        RecordedImageMode::Raw(spec),
    )?;
    let mut forged = package.receipt_bytes().to_vec();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    let forged_digest = ContentDigest::sha256(&forged);
    let mut recipe = imported
        .deployment
        .publisher()
        .spool()
        .read_bounded(package.identity(), MAX_PACKAGE_BYTES)?;
    let positions: Vec<_> = recipe
        .windows(32)
        .enumerate()
        .filter_map(|(i, bytes)| (bytes == package.receipt_digest().bytes()).then_some(i))
        .collect();
    assert_eq!(positions.len(), 1);
    recipe[positions[0]..positions[0] + 32].copy_from_slice(&forged_digest.bytes());
    let identity = ContentDigest::sha256(&recipe);
    let original = ObjectManifest::from_canonical_bytes(
        &imported
            .deployment
            .publisher()
            .spool()
            .read_bounded(package.publication_root(), MAX_PACKAGE_BYTES)?,
    )?;
    let children = original
        .children()
        .iter()
        .copied()
        .filter_map(|digest| {
            if digest == package.identity() {
                None
            } else if digest == package.receipt_digest() {
                Some(forged_digest)
            } else {
                Some(digest)
            }
        })
        .collect::<Vec<_>>();
    let slot = SlotName::parse(&format!(
        "recorded-localization-{}",
        &identity.to_text()[7..]
    ))?;
    let manifest = ObjectManifest::new(slot.as_str(), children, Some(identity))?;
    for bytes in [&forged, &recipe] {
        let digest = imported.deployment.publisher_mut().stage_object(bytes)?;
        imported.deployment.publisher_mut().verify_object(digest)?;
    }
    imported
        .deployment
        .publisher_mut()
        .stage_manifest(&slot, &manifest)?;
    let retained = RetainedFileImport::open(
        &imported.deployment,
        imported.identity,
        RetainedReadLimits::default(),
        &imported.cx,
    )?;
    let capsule = retained_source_capsule(
        &imported.deployment,
        &retained,
        result.source().segment as usize,
    )?;
    imported
        .deployment
        .publish_and_commit(&slot, &manifest, capsule.capture, &imported.cx)?;
    let forged_package = read(&imported, identity)?;
    assert_eq!(forged_package.receipt_digest(), forged_digest);
    let anchor = imported.deployment.current_anchor().clone();
    let objects = storage(&imported.deployment);
    assert!(matches!(
        forged_package.verify_by_replay(
            &mut imported.deployment,
            GeometryBasis::new(1, 1)?,
            &mut DecodeBudget::new(1_000_000_000),
            &mut RecordedVideoDecodeBudget::new(1_000_000_000),
            &mut WorkBudget::new(2_000_000_000),
            &imported.cx
        ),
        Err(RecordedLocalizationError::ReplayDiverged)
    ));
    assert_eq!(imported.deployment.current_anchor(), &anchor);
    assert_eq!(storage(&imported.deployment), objects);
    Ok(())
}

#[test]
fn interrupted_root_link_resumes_once_and_incomplete_publication_is_not_readable() -> Test {
    let mut imported = import("package-cut", JPEG, None)?;
    let source = jpeg(imported.identity);
    let (twin, atlas, spec) = setup([1; 32])?;
    let image = RecordedImageMode::Raw(spec);
    localize(&mut imported, &source, &twin, &atlas, image)?; // Complete the independent JPEG lineage first.
    let archives = Archives::new(&twin, &atlas)?;
    let before = imported.deployment.current_anchor().clone();
    imported
        .deployment
        .inject_ledger_crash_at(LedgerCutPoint::AfterRootDurable);
    assert!(retain(&mut imported, &source, &archives, image).is_err());
    assert_eq!(imported.deployment.current_anchor(), &before);
    let cut_root = imported
        .deployment
        .publisher()
        .visible_roots()
        .find(|root| root.slot.as_str().starts_with("recorded-localization-"))
        .ok_or("root reached injected durability boundary")?;
    let identity = ContentDigest::parse(&format!("sha256:{}", &cut_root.slot.as_str()[22..]))?;
    assert!(read(&imported, identity).is_err());
    drop(imported.deployment);
    imported.deployment =
        ReferenceDeployment::open(&imported.directory.0.join("deployment"), SITE, &imported.cx)?;
    let (_, package) = retain(&mut imported, &source, &archives, image)?;
    assert_eq!(package.identity(), identity);
    let anchor = imported.deployment.current_anchor().clone();
    assert_eq!(anchor.commit_sequence, before.commit_sequence + 1);
    read(&imported, identity)?;
    retain(&mut imported, &source, &archives, image)?;
    assert_eq!(imported.deployment.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn partitioned_source_is_refused_before_any_native_work_or_new_object() -> Test {
    let directory = Scratch::new("package-parts")?;
    let root = directory.0.join("deployment");
    let path = directory.0.join("original.jpg");
    fs::write(&path, JPEG)?;
    let cx = context(&root)?;
    let mut deployment = ReferenceDeployment::open_with_limits(
        &root,
        SITE,
        DeploymentLimits {
            manifest_children_max: 8,
            ..DeploymentLimits::standard()
        },
        &cx,
    )?;
    let mut request = FileIngestRequest::new(
        path.clone(),
        SensorId::parse("sensor:retained-localize")?,
        StreamId::parse("stream:retained-localize")?,
    )
    .with_receive_time(TimestampNs(1_000_000_000));
    request.limits.chunk_bytes = 512;
    let receipt = FileIngestAdapter::ingest(request, &cx, &mut deployment)?;
    assert!(!receipt.manifest.part_roots.is_empty());
    fs::remove_file(path)?;
    let (twin, atlas, spec) = setup([1; 32])?;
    let archives = Archives::new(&twin, &atlas)?;
    let anchor = deployment.current_anchor().clone();
    let objects = storage(&deployment);
    let mut jpeg_work = DecodeBudget::new(1_000_000_000);
    let mut video_work = RecordedVideoDecodeBudget::new(1_000_000_000);
    let mut geometry = WorkBudget::new(2_000_000_000);
    assert!(matches!(
        localize_and_retain(
            &mut deployment,
            &jpeg(receipt.import_identity),
            archives.plan(RecordedImageMode::Raw(spec))?,
            &mut jpeg_work,
            &mut video_work,
            &mut geometry,
            &cx
        ),
        Err(RecordedLocalizationError::PartitionedSource)
    ));
    assert_eq!(jpeg_work.used(), 0);
    assert_eq!(video_work.used(), 0);
    assert_eq!(geometry.used(), 0);
    assert_eq!(deployment.current_anchor(), &anchor);
    assert_eq!(storage(&deployment), objects);
    Ok(())
}

#[test]
fn cancellation_at_package_root_boundary_leaves_no_completed_package() -> Test {
    let mut imported = import("package-cancel", JPEG, None)?;
    let source = jpeg(imported.identity);
    let (twin, atlas, spec) = setup([1; 32])?;
    let image = RecordedImageMode::Raw(spec);
    localize(&mut imported, &source, &twin, &atlas, image)?;
    let archives = Archives::new(&twin, &atlas)?;
    let anchor = imported.deployment.current_anchor().clone();
    imported
        .cx
        .set_cancel_at_checkpoint(STAGE_LOCALIZATION_PUBLICATION);
    assert!(retain(&mut imported, &source, &archives, image).is_err());
    assert_eq!(imported.deployment.current_anchor(), &anchor);
    assert!(
        !imported
            .deployment
            .publisher()
            .visible_roots()
            .any(|root| root.slot.as_str().starts_with("recorded-localization-"))
    );
    Ok(())
}
