#![forbid(unsafe_code)]
//! Actual native live recording -> immutable history -> all owners closed -> whole replay.
//! The synthetic convolution and loopback peer prove composition, not detector quality.
mod http_rgb_evidence_support;
#[allow(dead_code)]
mod http_rgb_recording_support;
#[allow(dead_code)]
mod http_rgb_support;
#[allow(dead_code, clippy::duplicate_mod)]
mod rgb_evidence_support;
#[allow(clippy::duplicate_mod)]
mod rgb_zone_support;

use fss_core::{CaptureInterval, ContentDigest, TimestampNs};
use fss_publication::NeverCancel;
use fss_reference::ingest::http_archive::HttpWirePin;
use fss_reference::ingest::http_camera::rgb::HttpRgbStep;
use fss_reference::ingest::http_rgb_evidence::HttpRgbEvidenceRecording;
use fss_reference::ingest::http_rgb_history::*;
use fss_reference::ingest::http_rgb_history_replay::*;
use fss_reference::ingest::http_rgb_recording::HttpRgbRecordingStep;
use fss_reference::{ReferenceDeployment, ReplayCx, ScalarExecCx};
use fss_twin::image_zones::{ImageZoneBasis, ImageZonePolicy, ImageZoneSpec};
use http_rgb_evidence_support::{
    ArchiveAuthority, Budgets, analyze, evidence, head, imported, next, retention,
};
use http_rgb_recording_support::{Directory, attach, session};
use rgb_evidence_support as fixture;
use rgb_evidence_support::privacy_live_support::PrivacyDeployment;
use rgb_zone_support::{Test, jpeg, tracker, tracking_policy};
use std::cell::Cell;

const SITE: &str = "site:history-replay";
struct Authority {
    session: ContentDigest,
    model: ContentDigest,
    compute: Cell<bool>,
}
impl HistoryAuthority for Authority {
    fn permits(&self, _: HistoryOperation, session: ContentDigest) -> bool {
        session == self.session
    }
}
impl ReplayAuthority for Authority {
    fn permits_replay(&self, session: ContentDigest, model: ContentDigest) -> bool {
        self.compute.get() && session == self.session && model == self.model
    }
}
impl Authority {
    fn access<'a>(&'a self, archive: &'a ArchiveAuthority) -> ReplayAccess<'a> {
        ReplayAccess {
            history: self,
            evidence: archive,
            originals: &NeverCancel,
            execution: self,
        }
    }
}
struct Recorded {
    directory: Directory,
    cx: ReplayCx,
    tip: HttpRgbHistoryTip,
    initial: HttpRgbHistoryTip,
    wire: HttpWirePin,
    authority: Authority,
}

fn record(label: &str, mode: u8, complete_history: bool) -> Test<Recorded> {
    let directory = Directory::new(label)?;
    let cx = fixture::context(&directory.0)?;
    let privacy = PrivacyDeployment::new(label)?;
    let mut b = Budgets::new();
    let graph = fixture::graph()?;
    let weights = fixture::weights();
    let model = imported(&graph, &weights, &cx, &mut b)?;
    let head = head(model.model())?;
    let mut owner = tracker(&head, tracking_policy())?;
    let mut original = directory.open()?;
    let mut wire = http_rgb_support::response(&[jpeg(240), jpeg(240)], mode == 1);
    if mode == 2 {
        // The same native MIME body, but HTTP completion now requires real source EOF.
        let boundary = wire
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or("head")?;
        let header = std::str::from_utf8(&wire[..boundary])?;
        let header = header
            .split("\r\n")
            .filter(|line| !line.to_ascii_lowercase().starts_with("content-length:"))
            .collect::<Vec<_>>()
            .join("\r\n");
        let body = wire[boundary + 4..].to_vec();
        wire = format!("{header}\r\n\r\n").into_bytes();
        wire.extend(body);
    }
    let (capture, camera, mut server) = session(model.model(), &head, &mut owner, wire, 257)?;
    let recording = attach(
        capture,
        &original,
        &camera,
        http_rgb_recording_support::limits(),
    )?;
    let config = HttpRgbHistoryConfig::new(
        HttpRgbHistorySpec {
            source: recording.scope(),
            sensor: privacy.sensor.clone(),
            validity: CaptureInterval::new(TimestampNs(0), TimestampNs(100_000_000_000))?,
            episode: [9; 32],
            head: head.digest(),
            model: model.model().digest(),
            retention: retention(),
            class_index: 0,
            class_selection: ContentDigest::sha256(b"selected numeric-a"),
            tracking: tracking_policy(),
            basis: ImageZoneBasis {
                camera: 1,
                clock: 2,
                image_domain: [3; 32],
                calibration: [4; 32],
                dimensions: [32, 16],
            },
            zone_policy: ImageZonePolicy {
                selection_evidence: [8; 32],
                maximum_sample_gap_ns: 10_000_000_000,
            },
            zones: vec![ImageZoneSpec {
                id: 1,
                vertices: vec![[14, 1], [30, 1], [30, 15], [14, 15]],
                margin: 0,
                dwell_ns: Some(1_000_000_000),
            }],
        },
        &mut b.work,
    )?;
    let authority = Authority {
        session: config.identity(),
        model: model.model().digest(),
        compute: Cell::new(true),
    };
    let archive = ArchiveAuthority::new();
    let mut history = HttpRgbHistory::new(config);
    let initial = history.tip()?;
    let mut deployment = ReferenceDeployment::open(&directory.0.join("derived"), SITE, &cx)?;
    let access = HistoryAccess {
        history: &authority,
        evidence: &archive,
    };
    history.publish(
        initial,
        &mut deployment,
        access,
        HistoryLimits::default(),
        &mut b.copy,
        &mut b.work,
        &cx,
    )?;
    let mut r = HttpRgbEvidenceRecording::attach(recording, http_rgb_evidence_support::limits())
        .map_err(|_| "recording attachment")?;
    for n in 1..=2 {
        assert_eq!(
            next(&mut r, &mut original, &camera, &mut server)?,
            HttpRgbRecordingStep::Analysis(HttpRgbStep::AwaitingContext)
        );
        analyze(&mut r, &original, &camera, n, privacy.mask(), &mut b)?;
        let (e, replay) = evidence(&r, &model, &head, privacy.mask(), &mut b, &cx)?;
        let pin = r.prepare_evidence(
            &e,
            &replay,
            retention(),
            &original,
            archive.access(&camera),
            &mut b.copy,
            &mut b.work,
            &cx,
        )?;
        r.commit_evidence(
            pin,
            &original,
            &mut deployment,
            archive.access(&camera),
            &mut b.work,
            &cx,
        )?;
        history = history.appended(&r, &mut b.work, &cx)?;
        history.publish(
            history.tip()?,
            &mut deployment,
            access,
            HistoryLimits::default(),
            &mut b.copy,
            &mut b.work,
            &cx,
        )?;
        r.take_result(
            pin,
            &original,
            &mut deployment,
            archive.access(&camera),
            &mut b.copy,
            &mut b.work,
            &cx,
        )?;
    }
    let HttpRgbRecordingStep::CompletionPrepared(completion) =
        next(&mut r, &mut original, &camera, &mut server)?
    else {
        return Err("missing actual source completion".into());
    };
    r.commit_completion(completion, &mut original, camera.access(&NeverCancel))?;
    if complete_history {
        history = history.completed(&r, &cx)?;
        history.publish(
            history.tip()?,
            &mut deployment,
            access,
            HistoryLimits::default(),
            &mut b.copy,
            &mut b.work,
            &cx,
        )?;
    }
    let tip = history.tip()?;
    drop(r.retire());
    drop(owner);
    drop(model);
    drop(head);
    drop(graph);
    drop(weights);
    drop(deployment);
    drop(original);
    drop(server);
    drop(privacy);
    Ok(Recorded {
        directory,
        cx,
        tip,
        initial,
        wire: completion.wire,
        authority,
    })
}
fn budget() -> Test<ReplayBudget> {
    Ok(ReplayBudget::new(
        ReplayAllowance::default(),
        32 * 1024 * 1024,
    )?)
}
fn limits() -> ReplayLimits {
    ReplayLimits {
        execution: fixture::limits(),
        originals: http_rgb_evidence_support::limits().source,
        ..ReplayLimits::default()
    }
}

#[test]
fn complete_history_reconstructs_native_stages_after_every_live_owner_closes() -> Test {
    for mode in 0..=2 {
        let recorded = record(&format!("whole-{mode}"), mode, true)?;
        let original = recorded.directory.open()?;
        let mut deployment =
            ReferenceDeployment::reopen(&recorded.directory.0.join("derived"), SITE, &recorded.cx)?;
        let anchor = deployment.current_anchor().clone();
        let auth = ArchiveAuthority::new();
        let mut fingerprint = None;
        for read_bytes in [17, 257] {
            let mut limits = limits();
            limits.parser.read_bytes = read_bytes;
            let mut b = budget()?;
            let result = replay_history(
                &mut deployment,
                ReplaySource {
                    publisher: &original,
                    tip: None,
                },
                recorded.tip,
                ReplayPrivacy::HistoryDeployment,
                limits,
                recorded.authority.access(&auth),
                &mut b,
                &recorded.cx,
                &ScalarExecCx::new(),
            )?;
            assert_eq!(result.status(), ReplayStatus::CompleteVerified);
            assert_eq!(result.frames().len(), 2);
            assert_eq!(
                result
                    .temporal()
                    .ok_or("native temporal owner")?
                    .tracker()
                    .exposure_count(),
                2
            );
            assert_eq!(
                result.frames()[0].pin.encoded,
                result.frames()[1].pin.encoded
            );
            assert_ne!(
                result.frames()[0].pin.exposure,
                result.frames()[1].pin.exposure
            );
            assert_eq!(result.usage().1.inferences, 2);
            assert!(result.usage().1.decode > 0);
            assert!(result.frames().iter().all(|f| f.executed_macs > 0));
            if let Some(prior) = fingerprint {
                assert_eq!(result.digest(), prior);
            }
            fingerprint = Some(result.digest());
            assert_eq!(result.anchor(), &anchor);
            assert_eq!(deployment.current_anchor(), &anchor);
        }
    }
    Ok(())
}

#[test]
fn stale_tip_read_only_authority_and_exhausted_budget_never_return_partial_success() -> Test {
    let recorded = record("whole-refusals", 1, true)?;
    let original = recorded.directory.open()?;
    let mut deployment =
        ReferenceDeployment::reopen(&recorded.directory.0.join("derived"), SITE, &recorded.cx)?;
    let anchor = deployment.current_anchor().clone();
    let auth = ArchiveAuthority::new();
    let mut b = budget()?;
    assert!(matches!(
        replay_history(
            &mut deployment,
            ReplaySource {
                publisher: &original,
                tip: None
            },
            recorded.initial,
            ReplayPrivacy::HistoryDeployment,
            limits(),
            recorded.authority.access(&auth),
            &mut b,
            &recorded.cx,
            &ScalarExecCx::new()
        ),
        Err(ReplayError::StaleSelection)
    ));
    assert_eq!(b.used().inferences, 0);
    recorded.authority.compute.set(false);
    let read = inspect_history(
        &mut deployment,
        recorded.tip.session,
        HistoryLimits::default(),
        &recorded.authority,
        &mut b,
        &recorded.cx,
    )?;
    assert_eq!(read.committed.ok_or("history")?.tip()?, recorded.tip);
    assert!(matches!(
        replay_history(
            &mut deployment,
            ReplaySource {
                publisher: &original,
                tip: None
            },
            recorded.tip,
            ReplayPrivacy::HistoryDeployment,
            limits(),
            recorded.authority.access(&auth),
            &mut b,
            &recorded.cx,
            &ScalarExecCx::new()
        ),
        Err(ReplayError::Denied)
    ));
    assert_eq!(b.used().inferences, 0);
    recorded.authority.compute.set(true);
    auth.reads.set(false);
    assert!(matches!(
        replay_history(
            &mut deployment,
            ReplaySource {
                publisher: &original,
                tip: None
            },
            recorded.tip,
            ReplayPrivacy::HistoryDeployment,
            limits(),
            recorded.authority.access(&auth),
            &mut b,
            &recorded.cx,
            &ScalarExecCx::new()
        ),
        Err(ReplayError::Denied)
    ));
    auth.reads.set(true);
    let mut one = ReplayBudget::new(
        ReplayAllowance {
            inferences: 1,
            ..ReplayAllowance::default()
        },
        32 * 1024 * 1024,
    )?;
    for _ in 0..2 {
        assert!(matches!(
            replay_history(
                &mut deployment,
                ReplaySource {
                    publisher: &original,
                    tip: None
                },
                recorded.tip,
                ReplayPrivacy::HistoryDeployment,
                limits(),
                recorded.authority.access(&auth),
                &mut one,
                &recorded.cx,
                &ScalarExecCx::new()
            ),
            Err(ReplayError::Limit)
        ));
        assert_eq!(
            one.used().inferences,
            1,
            "retry cannot refill the admitted inference"
        );
    }
    let cancelled = ScalarExecCx::new();
    cancelled.request_cancellation();
    assert!(matches!(
        replay_history(
            &mut deployment,
            ReplaySource {
                publisher: &original,
                tip: None
            },
            recorded.tip,
            ReplayPrivacy::HistoryDeployment,
            limits(),
            recorded.authority.access(&auth),
            &mut b,
            &recorded.cx,
            &cancelled
        ),
        Err(ReplayError::Denied)
    ));
    assert_eq!(deployment.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn numerical_prefix_success_does_not_invent_a_committed_source_end() -> Test {
    let recorded = record("whole-prefix", 1, false)?;
    let original = recorded.directory.open()?;
    let mut deployment =
        ReferenceDeployment::reopen(&recorded.directory.0.join("derived"), SITE, &recorded.cx)?;
    let anchor = deployment.current_anchor().clone();
    let auth = ArchiveAuthority::new();
    // Exact final original tip is independently supplied because it may contain reads later
    // than the last frame's historical prefix. No unselected later frame is executed.
    let result = replay_history(
        &mut deployment,
        ReplaySource {
            publisher: &original,
            tip: Some(recorded.wire),
        },
        recorded.tip,
        ReplayPrivacy::HistoryDeployment,
        limits(),
        recorded.authority.access(&auth),
        &mut budget()?,
        &recorded.cx,
        &ScalarExecCx::new(),
    )?;
    assert_eq!(result.status(), ReplayStatus::PrefixVerified);
    assert!(result.completion().is_none());
    assert_eq!(result.frames().len(), 2);
    assert_eq!(deployment.current_anchor(), &anchor);
    Ok(())
}
