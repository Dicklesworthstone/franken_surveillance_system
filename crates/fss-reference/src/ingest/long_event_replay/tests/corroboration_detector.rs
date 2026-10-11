#![forbid(unsafe_code)]
//! Complete rehashed custody adversaries over the real bounded two-camera detector owner.

mod capture_binding;

use super::*;
use crate::ScalarExecCx;
use crate::ingest::detector_cascade::CascadeConfig;
use crate::ingest::long_watch::LongWatchDetector;
use crate::ingest::package_detect::PackageDetectLimits;
use crate::ingest::rgb_package::RgbDetectorPackage;
use fss_core::{CanonicalDecoder, CanonicalEncoder};

const PACKAGE: &[u8] = include_bytes!("../../../../../../models/yolox-nano/yolox_nano.fmpk");
const PACKAGE_DIGEST: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";

fn input(f: &mut Fixture) -> Test<CorroborationPlan> {
    let bytes = scene(12, 3, false)?;
    let (left, _) = f.import("east", &bytes, "mjpeg")?;
    let (right, _) = f.import("west", &bytes, "mjpeg")?;
    Ok(corroboration_plan(
        left,
        right,
        [48, 32],
        ComponentInterpretation::Grayscale,
        false,
    ))
}

fn trained(label: &str) -> Test<(Fixture, LongEventReplayInspection)> {
    trained_with_limits(label, PackageDetectLimits::default())
}

fn trained_with_limits(
    label: &str,
    limits: PackageDetectLimits,
) -> Test<(Fixture, LongEventReplayInspection)> {
    let mut f = Fixture::new(label)?;
    let plan = input(&mut f)?;
    let scalar = ScalarExecCx::new();
    let package = RgbDetectorPackage::load(
        PACKAGE,
        ContentDigest::parse(PACKAGE_DIGEST)?,
        1 << 36,
        &f.cx,
        &scalar,
    )?;
    let detector = LongWatchDetector::new(
        &package,
        PACKAGE,
        CascadeConfig {
            frames_per_track: 2,
            max_inferences: 1,
            ..CascadeConfig::default()
        },
        limits,
        &scalar,
    )?;
    let mut report = LongCorroborationReport::analyze_with_detector(
        &f.deployment,
        &plan,
        CorroborationOptions::default(),
        &LongDwellLimits::default(),
        &CorroborationDependencies::default(),
        false,
        &detector,
        &f.cx,
    )?;
    if limits.detection_work_units == 1 {
        assert_eq!(report.detection_head_work_used(), 1);
        assert_eq!(report.inferences_completed(), 0);
    }
    let candidate = report
        .candidates()
        .first()
        .ok_or("trained ground candidate")?;
    let event_id = candidate.event().event_id.clone();
    let approval = candidate.proposal_digest();
    assert_eq!(
        report.publish(&mut f.deployment, &BTreeSet::from([approval]), &f.cx)?,
        1
    );
    scalar.drain_and_finalize();
    let inspection = inspect_long_event(
        &f.deployment,
        &event_id,
        &LongEventReplayLimits::default(),
        &f.cx,
    )?;
    Ok((f, inspection))
}

#[test]
fn model_free_corroboration_retains_pre_extension_canonical_identities() -> Test {
    // Captured from main 7e64ff7 with the pinned native compiler before the detector refactor.
    let mut f = Fixture::new("legacy-identity")?;
    let plan = input(&mut f)?;
    let report = LongCorroborationReport::analyze(
        &f.deployment,
        &plan,
        CorroborationOptions::default(),
        &LongDwellLimits::default(),
        &CorroborationDependencies::default(),
        &f.cx,
    )?;
    let candidate = report.candidates().first().ok_or("legacy candidate")?;
    for (actual, expected) in [
        (
            report.plan_digest(),
            "sha256:ab1f670fc434188494fd8feece776843dd5551154a48a99b3dddba5065e01a6b",
        ),
        (
            report.analysis_digest(),
            "sha256:ca6c22743f31b2f24f53fc60abbf7008267ed332594a8f3fc83b5169879892af",
        ),
        (
            candidate.identity(),
            "sha256:e112ac692fc8212ae539b0d670fb951ecdc306fb477fa14006a90ccf2d0c4432",
        ),
        (
            candidate.event().revision_digest(),
            "sha256:63e27d573d48e14841198fbfb302a0cbab8cf01d2310d6dda3e846554ece6e48",
        ),
        (
            candidate.provenance_root(),
            "sha256:b9c81e52efbd50a4a7d3c967ff3deeb2789f3cd6b6d42b00b34b4067b1307f81",
        ),
    ] {
        assert_eq!(actual, ContentDigest::parse(expected)?);
    }
    Ok(())
}

struct CameraExtension {
    outcome: Vec<u8>,
    outcome_start: usize,
    global_offsets: [usize; 5],
    global_values: [u64; 5],
}

fn extension(bytes: &[u8]) -> Test<CameraExtension> {
    let mut tag = CanonicalEncoder::new();
    tag.text("detector_cascade");
    let tag = tag.finish_checked()?;
    let start = bytes
        .windows(tag.len())
        .position(|window| window == tag)
        .ok_or("camera detector extension")?;
    let mut d = CanonicalDecoder::new(&bytes[start..]);
    assert_eq!(d.text()?, "detector_cascade");
    let _recipe = d.bytes()?;
    let outcome_start = start + d.offset() + 8;
    let outcome = d.bytes()?.to_vec();
    assert_eq!(d.text()?, "global_detector_budget");
    let mut global_offsets = [0; 5];
    let mut global_values = [0; 5];
    for (offset, value) in global_offsets.iter_mut().zip(&mut global_values) {
        *offset = start + d.offset();
        *value = d.u64()?;
    }
    d.ensure_finished()?;
    Ok(CameraExtension {
        outcome,
        outcome_start,
        global_offsets,
        global_values,
    })
}

#[derive(Clone)]
struct ClassBinding {
    position: usize,
    entry_position: usize,
    segment: usize,
    capsule: ContentDigest,
    capsule_offset: usize,
    class_digest: ContentDigest,
}

fn class_bindings(bytes: &[u8]) -> Test<Vec<ClassBinding>> {
    let mut d = CanonicalDecoder::new(bytes);
    assert_eq!(d.text()?, "fss.long_watch_detector_outcome.v1");
    for _ in 0..3 {
        let _ = d.digest()?;
    }
    for _ in 0..5 {
        let _ = d.u64()?;
    }
    let _json = d.bytes()?;
    let count = d.u64()?;
    let mut bindings = Vec::new();
    for _ in 0..count {
        let _epoch = d.u64()?;
        let _track = d.u64()?;
        let _zone = d.u64()?;
        let entry_position = usize::try_from(d.u64()?)?;
        let frames = d.u64()?;
        for _ in 0..frames {
            let position = usize::try_from(d.u64()?)?;
            let segment = usize::try_from(d.u64()?)?;
            let capsule_offset = d.offset();
            let capsule = d.digest()?;
            let _supports = d.bool()?;
            let class_digest = d.digest()?;
            let _record = d.bytes()?;
            bindings.push(ClassBinding {
                position,
                entry_position,
                segment,
                capsule,
                capsule_offset,
                class_digest,
            });
        }
    }
    d.ensure_finished()?;
    Ok(bindings)
}

fn digest_bytes(digest: ContentDigest) -> Vec<u8> {
    let mut e = CanonicalEncoder::new();
    e.digest(digest);
    e.finish()
}

fn replace_digests(bytes: &[u8], replacements: &BTreeMap<ContentDigest, ContentDigest>) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    for (&old, &new) in replacements {
        let old = digest_bytes(old);
        let new = digest_bytes(new);
        let mut at = 0;
        while let Some(offset) = bytes[at..]
            .windows(old.len())
            .position(|window| window == old)
        {
            at += offset;
            bytes[at..at + old.len()].copy_from_slice(&new);
            at += old.len();
        }
    }
    bytes
}

fn retain(f: &mut Fixture, bytes: &[u8]) -> Test<ContentDigest> {
    let digest = f.deployment.publisher_mut().stage_object(bytes)?;
    f.deployment.publisher_mut().verify_object(digest)?;
    Ok(digest)
}

/// Publish a fully rehashed alternate graph through ordinary custody/authority owners. The
/// adversary changes claimed associations/accounting, not any original source bytes or model.
fn rehash_graph(
    f: &mut Fixture,
    original: &LongEventReplayInspection,
    edited: Vec<(ContentDigest, Vec<u8>)>,
    mut replacements: BTreeMap<ContentDigest, ContentDigest>,
) -> Test<(EventId, LongEventReplayPins)> {
    for (old, bytes) in edited {
        replacements.insert(old, retain(f, &bytes)?);
    }
    for (&old_root, &old_analysis) in original
        .analysis_roots()
        .iter()
        .zip(original.analysis_digests())
    {
        let old = ObjectManifest::from_canonical_bytes(
            &f.deployment.publisher().spool().read(old_root)?,
        )?;
        let analysis = replacements
            .get(&old_analysis)
            .copied()
            .unwrap_or(old_analysis);
        let updated = ObjectManifest::new(
            old.kind(),
            old.children()
                .iter()
                .map(|digest| replacements.get(digest).copied().unwrap_or(*digest)),
            None,
        )?;
        if updated.root() != old_root {
            publish_graph(
                &mut f.deployment,
                "lc-a",
                analysis,
                &updated,
                original.event().interval,
                &f.cx,
            )?;
            replacements.insert(old_root, updated.root());
        }
    }
    let old_identity = event_identity(&original.event().event_id, "event:long-corroborated:")?;
    let association = f.deployment.publisher().spool().read(old_identity)?;
    let mut d = CanonicalDecoder::new(&association);
    assert_eq!(d.text()?, "fss.long_corroboration_association.v1");
    let _recipe = d.digest()?;
    let _zone = d.text()?;
    let observations = [d.digest()?, d.digest()?];
    for old in observations {
        let record = f.deployment.publisher().spool().read(old)?;
        let updated = replace_digests(&record, &replacements);
        if updated != record {
            replacements.insert(old, retain(f, &updated)?);
        }
    }
    let association = replace_digests(&association, &replacements);
    let identity = retain(f, &association)?;
    replacements.insert(old_identity, identity);
    let mut event = original.event().clone();
    event.event_id = EventId::parse(format!("event:long-corroborated:{}", hex(identity)))?;
    for edge in &mut event.evidence {
        edge.digest = replacements
            .get(&edge.digest)
            .copied()
            .unwrap_or(edge.digest);
        if let Some(capsule) = edge.capsule_digest {
            edge.capsule_digest = Some(replacements.get(&capsule).copied().unwrap_or(capsule));
        }
    }
    event.evidence.sort_by_key(|edge| edge.digest);
    let action = if event.state == EventState::Corroborated {
        ReferencePolicyAction::PrepareAlert
    } else {
        ReferencePolicyAction::Hold
    };
    event.decision_path = crate::policy::zone_entry_decision_path(
        &event.event_id,
        &event.evidence,
        event.state,
        action,
    );
    event.validate()?;
    replacements.insert(original.event().revision_digest(), event.revision_digest());
    let old_proof = ObjectManifest::from_canonical_bytes(
        &f.deployment
            .publisher()
            .spool()
            .read(original.pins().provenance_root)?,
    )?;
    let old_metadata = old_proof.metadata_digest().ok_or("candidate metadata")?;
    let metadata = replace_digests(
        &f.deployment.publisher().spool().read(old_metadata)?,
        &replacements,
    );
    let metadata = retain(f, &metadata)?;
    let candidate_slot = slot("lc", identity)?;
    let proof = ObjectManifest::new(
        candidate_slot.as_str(),
        old_proof
            .children()
            .iter()
            .filter(|&&digest| digest != old_metadata)
            .map(|digest| replacements.get(digest).copied().unwrap_or(*digest)),
        Some(metadata),
    )?;
    publish_graph(
        &mut f.deployment,
        "lc",
        identity,
        &proof,
        event.interval,
        &f.cx,
    )?;
    f.deployment.publish_event(
        &ReferencePolicyDecision {
            event: event.clone(),
            action,
        },
        &f.cx,
    )?;
    let event_revision = event.revision_digest();
    Ok((
        event.event_id,
        LongEventReplayPins {
            event_revision,
            provenance_root: proof.root(),
        },
    ))
}

#[test]
fn trained_corroboration_cold_replay_requires_model_and_selected_class_custody() -> Test {
    let (f, original) = trained("trained-cold-custody")?;
    let before = f.snapshot();
    let verified = replay_long_event(
        &f.deployment,
        &original.event().event_id,
        original.pins(),
        &LongEventReplayLimits::default(),
        &f.cx,
    )?;
    assert_eq!(verified.frames_replayed(), 24);
    assert_eq!(verified.inspection().pins(), original.pins());
    assert_eq!(f.snapshot(), before);
    let camera = f
        .deployment
        .publisher()
        .spool()
        .read(original.analysis_digests()[0])?;
    let classes = class_bindings(&extension(&camera)?.outcome)?;
    let selected = classes
        .iter()
        .find(|binding| binding.position > binding.entry_position)
        .ok_or("following selected class")?;
    for digest in [ContentDigest::parse(PACKAGE_DIGEST)?, selected.class_digest] {
        let path = f.deployment.publisher().spool().object_path(digest);
        let bytes = fs::read(&path)?;
        fs::remove_file(&path)?;
        assert!(
            inspect_long_event(
                &f.deployment,
                &original.event().event_id,
                &LongEventReplayLimits::default(),
                &f.cx,
            )
            .is_err()
        );
        assert!(
            replay_long_event(
                &f.deployment,
                &original.event().event_id,
                original.pins(),
                &LongEventReplayLimits::default(),
                &f.cx,
            )
            .is_err()
        );
        assert_eq!(f.snapshot(), before);
        fs::write(path, bytes)?;
    }
    let mut denied = LongEventReplayLimits::default();
    denied.detector.detection_work_units -= 1;
    f.cx.set_cancel_at_checkpoint("long_event_replay:execute");
    let refusal = replay_long_event(
        &f.deployment,
        &original.event().event_id,
        original.pins(),
        &denied,
        &f.cx,
    )
    .err()
    .ok_or("narrowed retained reservation was accepted")?;
    assert_eq!(refusal.stable_id(), "ERR-WATCH-LIMIT-001");
    assert!(
        !f.cx.is_cancelled(),
        "denied retained reservations must refuse before native execution"
    );
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn rehashed_ground_entry_and_following_class_reject_another_valid_same_camera_capsule() -> Test {
    let (mut f, original) = trained("trained-capsule-substitution")?;
    let analysis_digest = original.analysis_digests()[0];
    let analysis = f.deployment.publisher().spool().read(analysis_digest)?;
    let ext = extension(&analysis)?;
    let classes = class_bindings(&ext.outcome)?;
    let LongEventReplayRecipe::Corroboration(recipe) = original.recipe() else {
        return Err("corroboration recipe".into());
    };
    let retained = RetainedFileImport::open(
        &f.deployment,
        recipe.plan().cameras[0].import_identity,
        Default::default(),
        &f.cx,
    )?;
    let other = source_capsule(&f.deployment, &retained, 0)?.1;
    for following in [false, true] {
        let binding = classes
            .iter()
            .find(|binding| (binding.position > binding.entry_position) == following)
            .ok_or("selected frame")?;
        assert_ne!(binding.segment, 0);
        assert_ne!(binding.capsule, other);
        let mut outcome = ext.outcome.clone();
        outcome[binding.capsule_offset..binding.capsule_offset + 33]
            .copy_from_slice(&digest_bytes(other));
        let mut edited_analysis = analysis.clone();
        edited_analysis[ext.outcome_start..ext.outcome_start + outcome.len()]
            .copy_from_slice(&outcome);
        let replacements = if following {
            BTreeMap::new()
        } else {
            BTreeMap::from([(binding.capsule, other)])
        };
        let (event, pins) = rehash_graph(
            &mut f,
            &original,
            vec![
                (ContentDigest::sha256(&ext.outcome), outcome),
                (analysis_digest, edited_analysis),
            ],
            replacements,
        )?;
        let before = f.snapshot();
        let current = f.deployment.current_event_authority(&event)?.0;
        let limits = LongEventReplayLimits::default();
        let mut reader = MetadataReader {
            remaining: limits.maximum_metadata_bytes,
            used: 0,
            objects: 0,
        };
        // The complete alternate graph is structurally consistent. Only checking its claimed
        // segment-to-capsule association against retained source authority exposes the lie.
        let loaded = corroboration::load(
            &f.deployment,
            &current,
            event_identity(&event, "event:long-corroborated:")?,
            pins.provenance_root,
            &limits,
            &mut reader,
            &f.cx,
        )?;
        assert_eq!(
            loaded.sources[0].capsule_bindings.get(&binding.segment),
            Some(&other)
        );
        assert!(matches!(
            verify_source_metadata(
                &f.deployment,
                &loaded.sources[0],
                &limits,
                &mut reader,
                &f.cx
            ),
            Err(LongEventReplayError::InvalidRecord)
        ));
        assert!(
            matches!(
                inspect_long_event(
                    &f.deployment,
                    &event,
                    &LongEventReplayLimits::default(),
                    &f.cx,
                ),
                Err(LongEventReplayError::InvalidRecord)
            ),
            "following={following}"
        );
        assert!(
            matches!(
                replay_long_event(
                    &f.deployment,
                    &event,
                    pins,
                    &LongEventReplayLimits::default(),
                    &f.cx,
                ),
                Err(LongEventReplayError::InvalidRecord)
            ),
            "following={following}"
        );
        assert_eq!(f.snapshot(), before);
    }
    Ok(())
}

#[test]
fn rehashed_global_allowance_and_head_work_understatements_cannot_verify() -> Test {
    let mut limits = PackageDetectLimits::default();
    // Spend a nonzero head charge, then refuse the still-incomplete head. That spent work
    // remains bound across cameras and cannot disappear just because no result completed.
    limits.detection_work_units = 1;
    let (mut f, original) = trained_with_limits("trained-global-understatement", limits)?;
    for head in [false, true] {
        let mut edits = Vec::new();
        let mut measured = false;
        for &analysis_digest in original.analysis_digests() {
            let mut analysis = f.deployment.publisher().spool().read(analysis_digest)?;
            let ext = extension(&analysis)?;
            let indices = if head { [3, 4] } else { [1, 2] };
            for index in indices {
                measured |= ext.global_values[index] > 0;
                let at = ext.global_offsets[index];
                analysis[at..at + 8].copy_from_slice(&0_u64.to_be_bytes());
            }
            edits.push((analysis_digest, analysis));
        }
        assert!(measured, "fixture must spend the forged resource");
        let (event, pins) = rehash_graph(&mut f, &original, edits, BTreeMap::new())?;
        let before = f.snapshot();
        match inspect_long_event(
            &f.deployment,
            &event,
            &LongEventReplayLimits::default(),
            &f.cx,
        ) {
            Err(LongEventReplayError::InvalidRecord | LongEventReplayError::Limit) => {}
            Ok(inspected) => {
                assert_eq!(inspected.pins(), pins);
                assert!(
                    matches!(
                        replay_long_event(
                            &f.deployment,
                            &event,
                            pins,
                            &LongEventReplayLimits::default(),
                            &f.cx,
                        ),
                        Err(LongEventReplayError::Diverged)
                    ),
                    "head={head}"
                );
            }
            Err(error) => return Err(error.into()),
        }
        assert_eq!(f.snapshot(), before);
    }
    Ok(())
}
