#![forbid(unsafe_code)]
//! Virtual time drives real committed roots. The fixture explicitly uses virtual source bytes;
//! it never labels them live capture or executes a physical effect.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::{
    BatchId, CanonicalEncode, CapsuleId, CaptureInterval, ClockBasis, ContentDigest,
    ContextAuthority, EffectIntent, EvidenceDelta, IdempotencyKey, ObjectId, ObligationId,
    OperationId, Plane, RootAuthoritySpec, SensorCapsule, SensorId, SensorSourceBytesSpec,
    StreamId, TimestampNs,
};
use fss_object::ObjectManifest;
use fss_publication::SlotName;

use super::*;
use crate::agent_follow::{follow_deployment, snapshot_anchor_token};
use crate::agent_orient::read_deployment;
use crate::ingest::source_coverage::{
    SourceCoverageInput, build_source_coverage, retain_source_coverage,
};
use crate::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const SITE: &str = "site:follow-wait-unit";

struct Fixture {
    root: PathBuf,
    cx: ReplayCx,
    source_path: Option<PathBuf>,
    children: Vec<ContentDigest>,
}

impl Fixture {
    fn new(tag: &str, covered: bool) -> TestResult<Self> {
        let root =
            std::env::temp_dir().join(format!("fss-follow-wait-{tag}-{}", std::process::id()));
        if root.exists() {
            fs::remove_dir_all(&root)?;
        }
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: format!("trace:follow-wait-{tag}"),
            operation_id: OperationId::parse(format!("operation:follow-wait-{tag}"))?,
            principal: "operator:follow-wait-fixture".to_owned(),
            capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::ZERO,
            privacy_scope: "privacy:internal".to_owned(),
            retention_scope: "retention:ephemeral".to_owned(),
            anchor_universe: ContentDigest::sha256(b"follow-wait-fixture"),
            generation: 1,
        })?;
        let scratch = root.with_extension("cx");
        let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
            &authority, scratch,
        )?);
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut children = Vec::new();
        let mut source_path = None;
        if covered {
            let source = b"explicit virtual quiet source for follow-wait tests";
            let capsule = SensorCapsule::from_source_bytes(SensorSourceBytesSpec {
                capsule_id: CapsuleId::parse("capsule:follow-wait:0")?,
                sensor_id: SensorId::parse("sensor:follow-wait")?,
                stream_id: StreamId::parse("stream:follow-wait")?,
                sequence: 0,
                capture: interval()?,
                receive_time: TimestampNs(5_000),
                clock_basis: ClockBasis::DeviceMonotonic,
                source,
                frame_count: 1,
                gap_before: false,
            })?;
            let source_digest = deployment.stage_payload(source)?;
            children.push(source_digest);
            children.push(deployment.stage_payload(&capsule.canonical_bytes())?);
            source_path = Some(deployment.publisher().spool().object_path(source_digest));
            let record = build_source_coverage(&SourceCoverageInput {
                basis: deployment.current_anchor().clone(),
                interval: interval()?,
                negative_predicate: "no_unknown_person_present",
                authorized_domain: BTreeSet::from(["follow-wait-domain".to_owned()]),
                sources: vec![("follow-wait-domain".to_owned(), &capsule)],
            })?;
            retain_source_coverage(&mut deployment, &record, record.approval_digest(), &cx)?;
            children.extend([record.digest(), record.witness_object()]);
            children.sort_unstable();
            children.dedup();
            let manifest = ObjectManifest::new("follow-wait-quiet", children.clone(), None)?;
            deployment.publish_and_commit(
                &SlotName::parse("quiet")?,
                &manifest,
                interval()?,
                &cx,
            )?;
        }
        drop(deployment);
        Ok(Self {
            root,
            cx,
            source_path,
            children,
        })
    }

    fn token(&self) -> TestResult<AnchorToken> {
        let snapshot = read_deployment(&self.root, &OrientLimits::default())?;
        AnchorToken::parse(&snapshot_anchor_token(&snapshot)).ok_or_else(|| "token parses".into())
    }

    fn binding(&self, wait_ms: u64, max_reads: u32) -> TestResult<FollowWaitBinding> {
        Ok(FollowWaitBinding::new(
            &self.root,
            self.token()?,
            request()?,
            OrientLimits::default(),
            wait_ms,
            max_reads,
        )?)
    }

    fn harmless(&mut self) -> TestResult {
        let mut deployment = ReferenceDeployment::open(&self.root, SITE, &self.cx)?;
        // A real root-last reachability commit over the same already-covered object closure.
        let manifest = ObjectManifest::new("follow-wait-quiet", self.children.clone(), None)?;
        deployment.publish_and_commit(
            &SlotName::parse("quiet-second")?,
            &manifest,
            interval()?,
            &self.cx,
        )?;
        Ok(())
    }

    fn material(&mut self) -> TestResult {
        let mut deployment = ReferenceDeployment::open(&self.root, SITE, &self.cx)?;
        let digest = deployment.stage_payload(b"explicit new unanalysed virtual evidence")?;
        deployment.append_batch(
            BatchId::parse("batch:wait:new-evidence")?,
            vec![EvidenceDelta {
                delta_id: "delta:wait:new-evidence".to_owned(),
                family: "sensor_capsule".to_owned(),
                object_id: ObjectId::parse("object:wait:new-evidence")?,
                prior_generation: None,
                new_generation: 1,
                validity: interval()?,
                plane: Plane::Authority,
                payload_digest: digest,
                witness_digest: None,
                operation_id: None,
            }],
            vec![digest],
            &self.cx,
        )?;
        Ok(())
    }

    fn effect_only(&mut self) -> TestResult {
        let mut deployment = ReferenceDeployment::open(&self.root, SITE, &self.cx)?;
        deployment.effects_mut().prepare(
            EffectIntent {
                operation_id: OperationId::parse("operation:wait:prepared-fixture")?,
                idempotency_key: IdempotencyKey::parse("idempotency:wait:prepared-fixture")?,
                effect_class: "fixture.observe".to_owned(),
                request_digest: ContentDigest::sha256(b"explicit unexecuted fixture intent"),
                precondition_digest: ContentDigest::sha256(b"fixture precondition"),
            },
            ObligationId::parse("obligation:wait:prepared-fixture")?,
            "fixture terminal proof is still required",
            TimestampNs(5_000),
        )?;
        Ok(())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
        let _ = fs::remove_dir_all(self.root.with_extension("cx"));
    }
}

fn interval() -> TestResult<CaptureInterval> {
    Ok(CaptureInterval::new(TimestampNs(0), TimestampNs(5_000))?)
}

fn request() -> TestResult<FollowRequest> {
    Ok(FollowRequest {
        view: AgentView::Brief,
        principal: PrincipalId::parse("principal:follow-wait")?,
        max_entries: 64,
        continuation: None,
    })
}

struct VirtualControl<'a> {
    expected: FollowWaitBinding,
    now: u64,
    reads: u32,
    parks: Vec<u64>,
    action: Option<Box<dyn FnMut() -> TestResult + 'a>>,
    denial: Option<FollowWaitDenial>,
    cancel_after_park: bool,
    short_park: bool,
    action_error: Option<String>,
}

impl<'a> VirtualControl<'a> {
    fn new(binding: &FollowWaitBinding) -> Self {
        Self {
            expected: binding.clone(),
            now: 0,
            reads: 0,
            parks: Vec::new(),
            action: None,
            denial: None,
            cancel_after_park: false,
            short_park: false,
            action_error: None,
        }
    }
}

impl FollowWaitControl for VirtualControl<'_> {
    fn checkpoint(
        &mut self,
        binding: &FollowWaitBinding,
        boundary: FollowWaitBoundary,
    ) -> Result<u64, FollowWaitDenial> {
        assert_eq!(
            binding, &self.expected,
            "every boundary retains exact caller scope"
        );
        if let Some(denial) = self.denial {
            return Err(denial);
        }
        if boundary == FollowWaitBoundary::Read {
            self.reads += 1;
        }
        Ok(self.now)
    }
    fn park(&mut self, binding: &FollowWaitBinding, delay_ms: u64) -> Result<(), FollowWaitDenial> {
        assert_eq!(binding, &self.expected);
        assert!((1..=FOLLOW_WAIT_POLL_MS).contains(&delay_ms));
        assert!(self.now + delay_ms <= binding.wait_ms());
        self.parks.push(delay_ms);
        if !self.short_park {
            self.now += delay_ms;
        }
        if let Some(mut action) = self.action.take() {
            if let Err(error) = action() {
                self.action_error = Some(error.to_string());
                return Err(FollowWaitDenial::Unauthorized);
            }
        }
        if self.cancel_after_park {
            self.denial = Some(FollowWaitDenial::Cancelled);
        }
        Ok(())
    }
}

fn run(
    binding: &FollowWaitBinding,
    control: &mut dyn FollowWaitControl,
) -> TestResult<FollowWaitResult> {
    follow_deployment_wait(binding, control).map_err(|error| format!("{error:?}").into())
}

fn tree(root: &Path) -> TestResult<BTreeMap<PathBuf, Vec<u8>>> {
    fn visit(root: &Path, at: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) -> TestResult {
        for entry in fs::read_dir(at)? {
            let path = entry?.path();
            if path.is_dir() {
                visit(root, &path, out)?;
            } else {
                out.insert(path.strip_prefix(root)?.to_owned(), fs::read(path)?);
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out)?;
    Ok(out)
}

#[test]
fn quiet_deadline_keeps_native_certificate_window_and_counts_all_comparisons() -> TestResult {
    let fixture = Fixture::new("deadline", true)?;
    let binding = fixture.binding(1_000, MAX_FOLLOW_WAIT_READS)?;
    let before = tree(&fixture.root)?;
    let history = DeploymentHistory::read(&fixture.root, &OrientLimits::default())?;
    let initial = follow_deployment(&history, binding.since(), binding.request())?;
    assert!(certified_quiet(&initial), "{:#?}", initial.delta);
    let mut control = VirtualControl::new(&binding);
    let waited = run(&binding, &mut control)?;
    assert_eq!(waited.wake, FollowWaitWake::DeadlineReached);
    assert_eq!(waited.progress.admitted_reads, 4);
    assert_eq!(waited.progress.completed_comparisons, 4);
    assert_eq!(waited.progress.completed_parks, 4);
    assert_eq!(waited.progress.elapsed_ms, 1_000);
    assert_eq!(
        waited.last_follow, initial,
        "wall time never republishes evidence or renews cursors"
    );
    assert_eq!(waited.observed_head.token, *binding.since());
    let one = initial
        .basis
        .consumed
        .checked_add(&initial.result.consumed)?;
    let mut total = BudgetVector::ZERO;
    for _ in 0..4 {
        total = total.checked_add(&one)?;
    }
    assert_eq!(waited.progress.consumed, total);
    assert_eq!(tree(&fixture.root)?, before);
    Ok(())
}

#[test]
fn persisting_coverage_gap_and_initial_material_delta_never_park() -> TestResult {
    let fixture = Fixture::new("gap", false)?;
    let binding = fixture.binding(10_000, MAX_FOLLOW_WAIT_READS)?;
    let mut control = VirtualControl::new(&binding);
    let result = run(&binding, &mut control)?;
    assert_eq!(result.wake, FollowWaitWake::Ready);
    assert!(
        result
            .last_follow
            .delta
            .classes
            .contains(&MeaningfulDeltaClass::CoverageLoss)
    );
    assert!(control.parks.is_empty());
    let mut fixture = Fixture::new("initial-material", true)?;
    let binding = fixture.binding(10_000, MAX_FOLLOW_WAIT_READS)?;
    fixture.material()?;
    let mut control = VirtualControl::new(&binding);
    let result = run(&binding, &mut control)?;
    assert_eq!(result.wake, FollowWaitWake::Ready);
    assert!(!certified_quiet(&result.last_follow));
    assert!(control.parks.is_empty());
    Ok(())
}

#[test]
fn harmless_initial_advance_requires_resnapshot_even_with_native_silence() -> TestResult {
    let mut fixture = Fixture::new("initial-harmless", true)?;
    let binding = fixture.binding(1_000, MAX_FOLLOW_WAIT_READS)?;
    fixture.harmless()?;
    let mut control = VirtualControl::new(&binding);
    let result = run(&binding, &mut control)?;
    assert!(
        certified_quiet(&result.last_follow),
        "{:#?}",
        result.last_follow.delta
    );
    assert_eq!(result.wake, FollowWaitWake::ResnapshotRequired);
    assert_ne!(result.observed_head.token, *binding.since());
    assert!(control.parks.is_empty());
    Ok(())
}

#[test]
fn every_post_park_ledger_or_effect_advance_wakes_before_endpoint_hydration() -> TestResult {
    for (tag, change) in [
        (
            "wake-harmless",
            Fixture::harmless as fn(&mut Fixture) -> TestResult,
        ),
        ("wake-material", Fixture::material),
        ("wake-effect", Fixture::effect_only),
    ] {
        let mut fixture = Fixture::new(tag, true)?;
        let binding = fixture.binding(1_000, MAX_FOLLOW_WAIT_READS)?;
        let original = binding.since().position();
        let mut control = VirtualControl::new(&binding);
        control.action = Some(Box::new(|| change(&mut fixture)));
        let result = run(&binding, &mut control)?;
        assert!(control.action_error.is_none(), "{:?}", control.action_error);
        assert_eq!(result.wake, FollowWaitWake::ResnapshotRequired, "{tag}");
        assert_eq!(result.progress.admitted_reads, 2);
        assert_eq!(
            result.progress.completed_comparisons, 1,
            "new endpoints are never sold as an interval history"
        );
        assert_eq!(result.progress.completed_parks, 1);
        assert!(certified_quiet(&result.last_follow));
        assert_ne!(result.observed_head.token, *binding.since());
        if tag == "wake-effect" {
            assert_eq!(
                result.observed_head.token.position().commit_sequence,
                original.commit_sequence
            );
            assert_ne!(
                result.observed_head.token.position().effect_records,
                original.effect_records
            );
        }
    }
    Ok(())
}

#[test]
fn tamper_or_missing_source_is_never_replaced_by_cached_silence() -> TestResult {
    for (tag, remove) in [("source-missing", true), ("source-tampered", false)] {
        let fixture = Fixture::new(tag, true)?;
        let binding = fixture.binding(1_000, MAX_FOLLOW_WAIT_READS)?;
        let path = fixture.source_path.as_ref().ok_or("source path")?.clone();
        let mut control = VirtualControl::new(&binding);
        control.action = Some(Box::new(move || {
            if remove {
                fs::remove_file(&path)?;
            } else {
                fs::write(&path, b"tampered source bytes")?;
            }
            Ok(())
        }));
        let error = follow_deployment_wait(&binding, &mut control)
            .err()
            .ok_or("source verification must refuse")?;
        assert!(
            matches!(error.error, FollowWaitError::Follow(_)),
            "{error:?}"
        );
        assert_eq!(error.progress.admitted_reads, 2);
        assert_eq!(error.progress.completed_comparisons, 1);
        assert!(error.last_follow.as_ref().is_some_and(certified_quiet));
    }
    Ok(())
}

#[test]
fn explicit_read_budget_and_cancellation_stop_further_io() -> TestResult {
    let fixture = Fixture::new("stop", true)?;
    let binding = fixture.binding(10_000, 2)?;
    let mut control = VirtualControl::new(&binding);
    let result = run(&binding, &mut control)?;
    assert_eq!(result.wake, FollowWaitWake::ReadLimitReached);
    assert_eq!(result.progress.admitted_reads, 2);
    assert_eq!(control.parks.len(), 1);
    let binding = fixture.binding(10_000, MAX_FOLLOW_WAIT_READS)?;
    let mut control = VirtualControl::new(&binding);
    control.cancel_after_park = true;
    let error = follow_deployment_wait(&binding, &mut control)
        .err()
        .ok_or("cancelled")?;
    assert!(matches!(
        error.error,
        FollowWaitError::Denied(FollowWaitDenial::Cancelled)
    ));
    assert_eq!(error.progress.admitted_reads, 1);
    assert_eq!(error.progress.completed_parks, 1);
    assert!(error.progress.consumed.bytes > 0);
    let mut control = VirtualControl::new(&binding);
    control.denial = Some(FollowWaitDenial::Cancelled);
    let error = follow_deployment_wait(&binding, &mut control)
        .err()
        .ok_or("cancelled before read")?;
    assert_eq!(error.progress.admitted_reads, 0);
    assert!(error.observed_head.is_none());
    assert!(control.parks.is_empty());
    Ok(())
}

#[test]
fn invalid_clock_and_wait_with_continuation_are_explicit_refusals() -> TestResult {
    let fixture = Fixture::new("clock", true)?;
    let binding = fixture.binding(1_000, MAX_FOLLOW_WAIT_READS)?;
    let mut control = VirtualControl::new(&binding);
    control.short_park = true;
    let error = follow_deployment_wait(&binding, &mut control)
        .err()
        .ok_or("clock did not advance")?;
    assert!(matches!(error.error, FollowWaitError::InvalidClock));
    assert_eq!(error.progress.admitted_reads, 1);
    let mut request = request()?;
    request.continuation = Some("continuation:unread".to_owned());
    assert!(matches!(
        FollowWaitBinding::new(
            "/does-not-exist",
            fixture.token()?,
            request,
            OrientLimits::default(),
            1_000,
            41
        ),
        Err(FollowWaitError::ContinuationNotAllowed)
    ));
    for (wait_ms, reads) in [(0, 1), (10_001, 1), (1, 0), (1, 42)] {
        assert!(matches!(
            FollowWaitBinding::new(
                "/does-not-exist",
                fixture.token()?,
                self::request()?,
                OrientLimits::default(),
                wait_ms,
                reads
            ),
            Err(FollowWaitError::InvalidBounds)
        ));
    }
    Ok(())
}
