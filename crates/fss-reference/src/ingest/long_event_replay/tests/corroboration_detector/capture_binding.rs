#![forbid(unsafe_code)]

use super::*;
use fss_core::{CanonicalDecode, CanonicalEncode, CaptureInterval};

fn capture_offset(bytes: &[u8]) -> Test<(usize, CaptureInterval)> {
    let mut d = CanonicalDecoder::new(bytes);
    assert_eq!(d.text()?, "fss.long_corroboration_observation.v1");
    let _root = d.digest()?;
    let _camera = d.text()?;
    let _homography = d.digest()?;
    let _zone = d.text()?;
    for _ in 0..5 {
        let _ = d.u64()?;
    }
    let _capsule = d.digest()?;
    let _luma = d.digest()?;
    let offset = d.offset();
    let capture = CaptureInterval::decode_canonical(&mut d)?;
    Ok((offset, capture))
}

#[test]
fn rehashed_observation_capture_must_match_its_unchanged_source_capsule() -> Test {
    let mut f = Fixture::new("forged-capture-binding")?;
    let (left, _) = f.import("east", &scene(12, 3, false)?, "mjpeg")?;
    let (right, _) = f.import("west", &scene(12, 4, false)?, "mjpeg")?;
    let plan = corroboration_plan(
        left,
        right,
        [48, 32],
        ComponentInterpretation::Grayscale,
        false,
    );
    let mut report = LongCorroborationReport::analyze(
        &f.deployment,
        &plan,
        CorroborationOptions::default(),
        &LongDwellLimits::default(),
        &CorroborationDependencies::default(),
        &f.cx,
    )?;
    let candidate = report.candidates().first().ok_or("ground candidate")?;
    let original_event = candidate.event().event_id.clone();
    let approval = candidate.proposal_digest();
    assert_eq!(
        report.publish(&mut f.deployment, &BTreeSet::from([approval]), &f.cx)?,
        1
    );
    let limits = LongEventReplayLimits::default();
    let original = inspect_long_event(&f.deployment, &original_event, &limits, &f.cx)?;
    let identity = event_identity(&original_event, "event:long-corroborated:")?;
    let association = f.deployment.publisher().spool().read(identity)?;
    let mut d = CanonicalDecoder::new(&association);
    assert_eq!(d.text()?, "fss.long_corroboration_association.v1");
    let _recipe = d.digest()?;
    let _zone = d.text()?;
    let observations = [d.digest()?, d.digest()?];
    let mut east = f.deployment.publisher().spool().read(observations[0])?;
    let west = f.deployment.publisher().spool().read(observations[1])?;
    let (offset, east_capture) = capture_offset(&east)?;
    let (_, west_capture) = capture_offset(&west)?;
    assert!(east_capture.latest < west_capture.earliest);
    // Widen only the east claim inside the existing event union. The event's time interval,
    // both valid capsule digests, source bytes and successful pair gate remain unchanged.
    let forged_capture = CaptureInterval::new(east_capture.earliest, west_capture.latest)?;
    assert_eq!(forged_capture, original.event().interval);
    let capture_bytes = forged_capture.try_canonical_bytes()?;
    east[offset..offset + capture_bytes.len()].copy_from_slice(&capture_bytes);
    let (event_id, pins) = rehash_graph(
        &mut f,
        &original,
        vec![(observations[0], east)],
        BTreeMap::new(),
    )?;
    let before = f.snapshot();
    let (event, _) = f.deployment.current_event_authority(&event_id)?;
    let mut reader = MetadataReader {
        remaining: limits.maximum_metadata_bytes,
        used: 0,
        objects: 0,
    };
    // The entire rehashed event/provenance/association graph is coherent. Refusal must come
    // from comparison with the authority-pinned capsule, not a stale hash or event interval.
    let loaded = corroboration::load(
        &f.deployment,
        &event,
        event_identity(&event_id, "event:long-corroborated:")?,
        pins.provenance_root,
        &limits,
        &mut reader,
        &f.cx,
    )?;
    assert_eq!(loaded.sources[0].capture_bindings.len(), 1);
    assert_eq!(
        loaded.sources[0].capture_bindings.values().next(),
        Some(&forged_capture)
    );
    f.cx.set_cancel_at_checkpoint("long_event_replay:execute");
    assert!(matches!(
        inspect_long_event(&f.deployment, &event_id, &limits, &f.cx),
        Err(LongEventReplayError::InvalidRecord)
    ));
    assert!(matches!(
        replay_long_event(&f.deployment, &event_id, pins, &limits, &f.cx),
        Err(LongEventReplayError::InvalidRecord)
    ));
    assert!(
        !f.cx.is_cancelled(),
        "source timing must refuse before execution"
    );
    assert_eq!(f.snapshot(), before);
    Ok(())
}
