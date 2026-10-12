#![forbid(unsafe_code)]
//! Real recorded coverage whose source chunks live under independent typed file parts.
//! Only the caller's wait clock and an explicit on-disk corruption are test controlled.

#[allow(dead_code)]
#[path = "support/import_integrity.rs"]
mod support;

use std::fs;
use std::path::PathBuf;

use fss_core::{AgentView, MeaningfulDeltaClass, PrincipalId, SensorId, StreamId, TimestampNs};
use fss_object::{ObjectManifest, SPOOL_OBJECT_HEADER_LEN};
use fss_reference::agent_follow::wait::{
    FollowWaitBinding, FollowWaitBoundary, FollowWaitControl, FollowWaitDenial, FollowWaitError,
    FollowWaitWake, MAX_FOLLOW_WAIT_READS, follow_deployment_wait,
};
use fss_reference::agent_follow::{AnchorToken, FollowError, FollowRequest, snapshot_anchor_token};
use fss_reference::agent_orient::{DeploymentReadError, OrientLimits, read_deployment};
use fss_reference::ingest::recorded_coverage::{approval_digest, retain_coverage};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchLimits, WatchPlan, WatchReport, WatchTrackerConfig, WatchZone,
};
use fss_reference::ingest::{
    CaptureHint, FileFormatHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest,
};
use fss_reference::media_fixture::jpeg::{CustomMarker, JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{DeploymentLimits, ReferenceDeployment};
use support::{TestResult, cx, directory, snapshot};

struct Clock {
    expected: FollowWaitBinding,
    elapsed_ms: u64,
    damage: Option<(PathBuf, Vec<u8>)>,
    damage_error: Option<String>,
}

impl FollowWaitControl for Clock {
    fn checkpoint(
        &mut self,
        binding: &FollowWaitBinding,
        _boundary: FollowWaitBoundary,
    ) -> Result<u64, FollowWaitDenial> {
        if binding != &self.expected {
            return Err(FollowWaitDenial::Unauthorized);
        }
        Ok(self.elapsed_ms)
    }

    fn park(&mut self, binding: &FollowWaitBinding, delay_ms: u64) -> Result<(), FollowWaitDenial> {
        self.checkpoint(binding, FollowWaitBoundary::Park)?;
        self.elapsed_ms = self
            .elapsed_ms
            .checked_add(delay_ms)
            .ok_or(FollowWaitDenial::ClockUnavailable)?;
        if let Some((path, bytes)) = self.damage.take()
            && let Err(error) = fs::write(path, bytes)
        {
            self.damage_error = Some(error.to_string());
            return Err(FollowWaitDenial::Unauthorized);
        }
        Ok(())
    }
}

fn quiet_recording() -> TestResult<Vec<u8>> {
    let mut recording = Vec::new();
    let pixels = vec![40_u8; 96 * 48];
    for index in 0..14_u8 {
        // Distinct, image-neutral comments ensure more than eight distinct source chunks.
        // The native decoder still observes exactly the same grayscale image in every frame.
        let config = JpegConfig {
            quality: 90,
            subsampling: Subsampling::Grayscale,
            restart_interval: 0,
            custom_markers: vec![CustomMarker {
                marker: 0xfe,
                payload: vec![index; 1024],
            }],
        };
        recording.extend(encode_jpeg(96, 48, &pixels, &config)?);
    }
    Ok(recording)
}

#[test]
fn quiet_wait_rechecks_a_source_chunk_under_a_later_independent_file_part() -> TestResult {
    let scratch = directory("follow-wait-parts")?;
    let root = scratch.join("deployment");
    let context = cx("follow-wait-parts")?;
    let mut deployment = ReferenceDeployment::open_with_limits(
        &root,
        "site:follow-wait-parts",
        DeploymentLimits {
            manifest_children_max: 8,
            ..DeploymentLimits::standard()
        },
        &context,
    )?;
    let source = scratch.join("quiet.mjpg");
    fs::write(&source, quiet_recording()?)?;
    let receipt = FileIngestAdapter::ingest(
        FileIngestRequest::new(
            &source,
            SensorId::parse("sensor:follow-wait-parts")?,
            StreamId::parse("stream:follow-wait-parts")?,
        )
        .with_format_hint(FileFormatHint::JpegStream)
        .with_limits(FileIngestLimits {
            chunk_bytes: 512,
            ..FileIngestLimits::standard()
        })
        .with_receive_time(TimestampNs(10_000_000_000_000))
        .with_capture_hint(CaptureHint::new(
            TimestampNs(1_000_000_000),
            1_000_000,
            10.0,
        )?),
        &context,
        &mut deployment,
    )?;
    fs::remove_file(source)?;
    assert!(receipt.manifest.part_roots.len() > 1);
    let aggregate = ObjectManifest::from_canonical_bytes(
        &deployment.publisher().spool().read(receipt.import_root)?,
    )?;
    assert_eq!(aggregate.children(), &[receipt.manifest_digest]);
    let mut victim = None;
    for part_root in receipt.manifest.part_roots.iter().skip(1) {
        assert!(!aggregate.children().contains(part_root));
        let part = ObjectManifest::from_canonical_bytes(
            &deployment.publisher().spool().read(*part_root)?,
        )?;
        if let Some(chunk) = part
            .children()
            .iter()
            .find(|chunk| receipt.manifest.ordered_chunks.contains(chunk))
        {
            victim = Some(deployment.publisher().spool().object_path(*chunk));
            break;
        }
    }
    let victim = victim.ok_or("an actual original source chunk must be held by a later part")?;
    let report = WatchReport::analyze(
        &deployment,
        &WatchPlan {
            import_identity: receipt.import_identity,
            interpretation: ComponentInterpretation::Grayscale,
            first_segment: 0,
            segment_count: 14,
            zones: vec![WatchZone {
                zone_id: "door".to_owned(),
                x: 64,
                y: 0,
                width: 32,
                height: 32,
            }],
            detector: WatchDetectorConfig::default(),
            tracker: WatchTrackerConfig::default(),
        },
        &WatchLimits::default(),
        &context,
    )?;
    assert!(report.candidates().is_empty());
    retain_coverage(
        &mut deployment,
        &[report.coverage()],
        approval_digest(&[report.coverage()]),
        &context,
    )?;
    drop(deployment);

    let state = read_deployment(&root, &OrientLimits::default())?;
    let since = AnchorToken::parse(&snapshot_anchor_token(&state)).ok_or("anchor token")?;
    let binding = FollowWaitBinding::new(
        &root,
        since.clone(),
        FollowRequest {
            view: AgentView::Brief,
            principal: PrincipalId::parse("principal:follow-wait-parts")?,
            max_entries: 64,
            continuation: None,
        },
        OrientLimits::default(),
        1_000,
        MAX_FOLLOW_WAIT_READS,
    )?;
    let before = snapshot(&root)?;
    let mut healthy_clock = Clock {
        expected: binding.clone(),
        elapsed_ms: 0,
        damage: None,
        damage_error: None,
    };
    let healthy = follow_deployment_wait(&binding, &mut healthy_clock)
        .map_err(|error| format!("healthy typed-part custody was refused: {error:?}"))?;
    assert_eq!(healthy.wake, FollowWaitWake::DeadlineReached);
    assert_eq!(healthy.progress.completed_parks, 4);
    assert_eq!(healthy.progress.completed_comparisons, 4);
    assert_eq!(healthy.last_follow.delta.classes.len(), 1);
    assert!(
        healthy
            .last_follow
            .delta
            .classes
            .contains(&MeaningfulDeltaClass::NoMeaningfulChange)
    );
    assert!(healthy.last_follow.delta.silence_certificate.is_some());
    assert!(healthy.progress.source_payload_bytes > 0);
    assert_eq!(snapshot(&root)?, before);

    let mut damaged = fs::read(&victim)?;
    let payload_byte = damaged
        .get_mut(SPOOL_OBJECT_HEADER_LEN)
        .ok_or("retained source chunk must have a nonempty payload")?;
    *payload_byte ^= 1;
    let mut expected = before;
    expected.insert(victim.strip_prefix(&root)?.to_path_buf(), damaged.clone());
    let mut clock = Clock {
        expected: binding.clone(),
        elapsed_ms: 0,
        damage: Some((victim, damaged)),
        damage_error: None,
    };
    let failure = follow_deployment_wait(&binding, &mut clock)
        .err()
        .ok_or("a formerly quiet source must fail after its later-part chunk is corrupted")?;
    assert!(
        matches!(
            failure.error,
            FollowWaitError::Follow(FollowError::Read(DeploymentReadError::Corrupt { .. }))
        ),
        "{failure:?}"
    );
    assert!(
        clock.damage.is_none(),
        "the first certified quiet park occurred"
    );
    assert!(clock.damage_error.is_none(), "{:?}", clock.damage_error);
    assert_eq!(failure.progress.elapsed_ms, 250);
    assert_eq!(failure.progress.admitted_reads, 2);
    assert_eq!(failure.progress.completed_comparisons, 2);
    assert_eq!(failure.progress.completed_parks, 1);
    assert!(failure.progress.source_read_attempts > failure.progress.verified_source_reads);
    assert!(failure.progress.source_reserved_bytes <= binding.max_source_envelope_bytes());
    assert_eq!(
        failure.observed_head.as_ref().map(|head| &head.token),
        Some(&since)
    );
    assert_eq!(
        snapshot(&root)?,
        expected,
        "the failed read must not repair custody or write history"
    );
    fs::remove_dir_all(scratch)?;
    Ok(())
}
