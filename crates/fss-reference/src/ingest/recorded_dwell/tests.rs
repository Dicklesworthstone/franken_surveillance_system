#![forbid(unsafe_code)]
//! Real synthetic MJPEG imports through the existing decoder, foreground, tracker and publisher.
use super::*;
use crate::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use crate::ingest::recorded_decode::ComponentInterpretation;
use crate::ingest::recorded_watch::{WatchDetectorConfig, WatchTrackerConfig};
use crate::ingest::{CaptureHint, FileIngestAdapter, FileIngestRequest};
use crate::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, OperationId, StreamId, TimestampNs};
use std::fs;
use std::path::Path;

type Test<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:recorded-dwell";
const SENSOR: &str = "sensor:recorded-dwell";
const FRAMES: usize = 14;
const PERIOD: u64 = 100_000_000;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-dwell-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("dwell test directory bound".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn context(root: &Path) -> Test<ReplayCx> {
    let auth = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:recorded-dwell".into(),
        operation_id: OperationId::parse("operation:recorded-dwell")?,
        principal: "principal:recorded-dwell".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(8192)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(&auth, root.to_path_buf())?)
}
fn scene(missing: Option<usize>, gap: bool) -> Test<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut bytes = Vec::new();
    for index in 0..FRAMES {
        let mut pixels = vec![40_u8; 96 * 48];
        if index >= 3 && missing != Some(index) {
            let left = (index - 3) * 8;
            for y in 8..24 {
                for x in left..left + 16 {
                    pixels[y * 96 + x] = 220;
                }
            }
        }
        if gap && index == 8 {
            bytes.extend_from_slice(b"unframed-source-gap");
        }
        bytes.extend(encode_jpeg(96, 48, &pixels, &config)?);
    }
    Ok(bytes)
}
struct Fixture {
    deployment: ReferenceDeployment,
    cx: ReplayCx,
    plan: WatchPlan,
    _directory: Directory,
}
impl Fixture {
    fn new(label: &str, bytes: &[u8], timing: bool) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let path = directory.0.join("camera.mjpeg");
        fs::write(&path, bytes)?;
        let cx = context(&root)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut request = FileIngestRequest::new(
            path,
            SensorId::parse(SENSOR)?,
            StreamId::parse("stream:recorded-dwell")?,
        )
        .with_receive_time(TimestampNs(10_000_000_000));
        if timing {
            request = request.with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?);
        }
        let import = FileIngestAdapter::ingest(request, &cx, &mut deployment)?;
        let plan = WatchPlan {
            import_identity: import.import_identity,
            interpretation: ComponentInterpretation::Grayscale,
            first_segment: 0,
            segment_count: FRAMES,
            zones: vec![WatchZone {
                zone_id: "yard".into(),
                x: 0,
                y: 0,
                width: 96,
                height: 48,
            }],
            detector: WatchDetectorConfig::default(),
            tracker: WatchTrackerConfig::default(),
        };
        Ok(Self {
            deployment,
            cx,
            plan,
            _directory: directory,
        })
    }
    fn analyze(&self, rule: DwellPolicy) -> Result<DwellReport> {
        DwellReport::analyze(
            &self.deployment,
            &self.plan,
            rule,
            &WatchLimits::default(),
            None,
            WatchOptions::default(),
            &self.cx,
        )
    }
    fn snapshot(&self) -> (fss_core::LedgerAnchor, ContentDigest, usize) {
        (
            self.deployment.current_anchor().clone(),
            self.deployment.effects().last_root(),
            self.deployment.publisher().spool().digests().count(),
        )
    }
}
fn rule() -> DwellPolicy {
    DwellPolicy {
        minimum_duration_ns: 2 * PERIOD,
        maximum_sample_gap_ns: PERIOD,
        minimum_observations: 3,
    }
}

#[test]
fn actual_pixels_produce_dwell_without_changing_default_entry_reports() -> Test {
    let f = Fixture::new("pixels", &scene(None, false)?, true)?;
    let before = f.snapshot();
    let entry = WatchReport::analyze(&f.deployment, &f.plan, &WatchLimits::default(), &f.cx)?;
    let report = f.analyze(rule())?;
    assert_eq!(report.candidates().len(), 1);
    let candidate = &report.candidates()[0];
    let [first, triggered, last] = candidate.segments();
    assert!(first >= 5, "tentative samples must not count");
    assert_eq!(triggered, first + 2);
    assert_eq!(last, FRAMES - 1);
    assert_eq!(candidate.span().trigger_minimum_ns, u128::from(2 * PERIOD));
    assert_eq!(candidate.event().state, EventState::Indeterminate);
    assert_eq!(candidate.event().kind, EventKind::Unclassified);
    assert_eq!(
        candidate.event().probability,
        ProbabilityInterval::new(0.0, 1.0)?
    );
    assert!(candidate.event().decision_path.abstained);
    assert!(candidate.event().evidence.iter().all(|item| !item.supports));
    assert!(!candidate.event().analyze_corroboration().is_corroborated);
    assert_ne!(
        candidate.proposal_digest(),
        entry.candidates()[0].proposal_digest()
    );
    assert_eq!(
        f.analyze(rule())?.to_json(0, None)?,
        report.to_json(0, None)?
    );
    let after = WatchReport::analyze(&f.deployment, &f.plan, &WatchLimits::default(), &f.cx)?;
    assert_eq!(after.to_json(0, None), entry.to_json(0, None));
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn brief_entry_and_sparse_sampling_do_not_qualify_as_dwell() -> Test {
    let f = Fixture::new("short", &scene(None, false)?, true)?;
    let mut long = rule();
    long.minimum_duration_ns = 2_000_000_000;
    assert!(f.analyze(long)?.candidates().is_empty());
    let mut sparse = rule();
    sparse.maximum_sample_gap_ns = PERIOD - 1;
    assert!(f.analyze(sparse)?.candidates().is_empty());
    let normal = f.analyze(rule())?;
    assert_eq!(normal.candidates().len(), 1);
    Ok(())
}

#[test]
fn a_missing_actual_match_breaks_the_episode_even_while_tracker_coasts() -> Test {
    let f = Fixture::new("miss", &scene(Some(8), false)?, true)?;
    let report = f.analyze(rule())?;
    assert!(!report.candidates().is_empty());
    for candidate in report.candidates() {
        let [first, _, last] = candidate.segments();
        assert!(last < 8 || first > 8);
        assert!(candidate.observations.iter().all(|o| o.frame.segment != 8));
    }
    Ok(())
}

#[test]
fn unknown_time_is_refused_and_source_omissions_remain_explicit() -> Test {
    let unknown = Fixture::new("unknown", &scene(None, false)?, false)?;
    let before = unknown.snapshot();
    assert!(matches!(
        unknown.analyze(rule()),
        Err(WatchError::InvalidPlan(_))
    ));
    assert_eq!(unknown.snapshot(), before);
    let gapped = Fixture::new("source-gap", &scene(None, true)?, true)?;
    let report = DwellReport::analyze(
        &gapped.deployment,
        &gapped.plan,
        rule(),
        &WatchLimits::default(),
        None,
        WatchOptions {
            tolerate_decode_refusals: true,
        },
        &gapped.cx,
    )?;
    assert!(report.candidates().is_empty());
    assert!(report.unreliable_time_frames() > 0);
    assert!(
        report
            .to_json(0, None)?
            .contains("\"absence_certifiable\":false")
    );
    Ok(())
}

#[test]
fn mask_generation_change_refuses_old_approval_before_any_new_write() -> Test {
    let mut f = Fixture::new("privacy", &scene(None, false)?, true)?;
    let mut report = f.analyze(rule())?;
    let approval = report.candidates()[0].proposal_digest();
    // The mask need not cover motion: any part of this zone invalidates a whole-zone dwell claim.
    let policy = PrivacyMaskPolicy::new(SensorId::parse(SENSOR)?, [96, 48], &[[80, 40, 8, 8]])?;
    let preview = preview_mask(&f.deployment, &policy)?;
    declare_mask(&mut f.deployment, &policy, preview.approval, &f.cx)?;
    let before = f.snapshot();
    assert!(matches!(
        report.publish(&mut f.deployment, &BTreeSet::from([approval]), &f.cx),
        Err(WatchError::InvalidPlan(_))
    ));
    assert_eq!(f.snapshot(), before);
    let masked = f.analyze(rule())?;
    assert!(masked.candidates().is_empty());
    assert_eq!(masked.masked_zones, 1);
    Ok(())
}

#[test]
fn exact_approval_publishes_only_dwell_and_survives_cold_retry() -> Test {
    let mut f = Fixture::new("publish", &scene(None, false)?, true)?;
    let mut report = f.analyze(rule())?;
    let candidate = &report.candidates()[0];
    let proposal = candidate.proposal_digest();
    let expected = candidate.event().clone();
    let provenance = candidate.provenance_root();
    assert_eq!(
        report.publish(&mut f.deployment, &BTreeSet::from([proposal]), &f.cx)?,
        1
    );
    assert_eq!(
        f.deployment.current_event_authority(&expected.event_id)?.0,
        expected
    );
    assert!(f.deployment.effects().operations().next().is_none());
    let (anchor, effects, _) = f.snapshot();
    let root = f.deployment.root().to_path_buf();
    drop(f.deployment);
    let mut reopened = ReferenceDeployment::reopen(&root, SITE, &f.cx)?;
    let mut retry = DwellReport::analyze(
        &reopened,
        &f.plan,
        rule(),
        &WatchLimits::default(),
        None,
        WatchOptions::default(),
        &f.cx,
    )?;
    assert_eq!(
        retry.candidates()[0].status(),
        WatchStatus::AlreadyPublished
    );
    assert_eq!(retry.candidates()[0].proposal_digest(), proposal);
    assert_eq!(
        retry.publish(&mut reopened, &BTreeSet::from([proposal]), &f.cx)?,
        0
    );
    assert_eq!(reopened.current_anchor(), &anchor);
    assert_eq!(reopened.effects().last_root(), effects);
    let bytes = reopened.publisher().spool().read(provenance)?;
    assert_eq!(
        ObjectManifest::from_canonical_bytes(&bytes)?.root(),
        provenance
    );
    Ok(())
}

#[test]
fn wrong_rule_or_entry_approval_never_authorizes_dwell() -> Test {
    let mut f = Fixture::new("wrong-approval", &scene(None, false)?, true)?;
    let entry = WatchReport::analyze(&f.deployment, &f.plan, &WatchLimits::default(), &f.cx)?;
    let original = f.analyze(rule())?;
    let mut changed_rule = rule();
    changed_rule.minimum_duration_ns += PERIOD;
    let mut changed = f.analyze(changed_rule)?;
    assert_ne!(changed.analysis_digest(), original.analysis_digest());
    let before = f.snapshot();
    for wrong in [
        entry.candidates()[0].proposal_digest(),
        original.candidates()[0].proposal_digest(),
    ] {
        assert!(matches!(
            changed.publish(&mut f.deployment, &BTreeSet::from([wrong]), &f.cx),
            Err(WatchError::StaleApproval(_))
        ));
        assert_eq!(f.snapshot(), before);
    }
    Ok(())
}

#[test]
fn cancellation_after_provenance_has_no_event_until_exact_resume() -> Test {
    let mut f = Fixture::new("resume", &scene(None, false)?, true)?;
    let mut report = f.analyze(rule())?;
    let approval = report.candidates()[0].proposal_digest();
    let event = report.candidates()[0].event().clone();
    f.cx.set_cancel_at_checkpoint("recorded_dwell:commit");
    assert!(
        report
            .publish(&mut f.deployment, &BTreeSet::from([approval]), &f.cx)
            .is_err()
    );
    assert!(f.cx.is_drain_completed());
    let event_object = ObjectId::parse(format!("object:event:{}", event.event_id.as_str()))?;
    assert!(
        !f.deployment
            .ledger()
            .current()
            .objects
            .contains_key(&event_object)
    );
    assert!(f.deployment.effects().operations().next().is_none());
    let root = f.deployment.root().to_path_buf();
    drop(f.deployment);
    let cx = context(&root)?;
    let mut reopened = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    let mut retry = DwellReport::analyze(
        &reopened,
        &f.plan,
        rule(),
        &WatchLimits::default(),
        None,
        WatchOptions::default(),
        &cx,
    )?;
    assert_eq!(retry.candidates()[0].proposal_digest(), approval);
    assert_eq!(
        retry.publish(&mut reopened, &BTreeSet::from([approval]), &cx)?,
        1
    );
    assert_eq!(reopened.current_event_authority(&event.event_id)?.0, event);
    let anchor = reopened.current_anchor().clone();
    assert_eq!(
        retry.publish(&mut reopened, &BTreeSet::from([approval]), &cx)?,
        0
    );
    assert_eq!(reopened.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn cancellation_and_oversized_rerun_hint_return_no_partial_result() -> Test {
    let f = Fixture::new("bounds", &scene(None, false)?, true)?;
    let report = f.analyze(rule())?;
    assert!(matches!(
        report.to_json(0, Some(&"x".repeat(8193))),
        Err(WatchError::Limit)
    ));
    let before = f.snapshot();
    f.cx.request_cancellation();
    assert!(f.analyze(rule()).is_err());
    assert_eq!(f.snapshot(), before);
    Ok(())
}
