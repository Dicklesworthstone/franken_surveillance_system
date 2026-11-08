#![forbid(unsafe_code)]
//! Native AVC/HEVC recording metadata through the real CLI and protected deployment owner.
//! Synthetic retained windows establish transport/custody wiring only, not camera coverage.

#[path = "../../fss-reference/tests/collector_support/mod.rs"]
mod collector_support;
#[path = "../../fss-reference/tests/hevc_catalog_support/mod.rs"]
mod hevc_catalog_support;
#[path = "../../fss-reference/tests/hevc_recording_support/mod.rs"]
mod hevc_recording_support;
#[path = "../../fss-reference/tests/recording_support/mod.rs"]
mod recording_support;
#[path = "../../fss-reference/tests/recording_clock_contract/support.rs"]
mod clock_support;
#[path = "recording_query_contract/utc.rs"]
mod utc;
#[path = "recording_query_contract/set.rs"]
mod set;
#[path = "recording_query_contract/discover.rs"]
mod discover;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use fss_cli::{ExitIdentity, execute_fss_with_exit, parse_fss_args};
use fss_core::json_input::{Value, parse as parse_json};
use fss_core::{
    AgentView, BudgetVector, CanonicalEncode, CaptureInterval, ContentDigest, ContextAuthority,
    DecisionPath, EventHypothesis, EventId, EventKind, EventState, OperationId, PrincipalId,
    ProbabilityInterval, RootAuthoritySpec, TimestampNs,
};
use fss_object::{HostSpoolIo, ObjectManifest, RecordingSpoolIo, SpoolIoCall, encode_spool_object};
use fss_publication::{SlotName, root_record_bytes};
use fss_reference::agent_follow::{AnchorToken, snapshot_anchor_token};
use fss_reference::agent_orient::{OrientRequest, orient_deployment};
use fss_reference::agent_recording_context::{
    RecordingContextError, RecordingContextLimits, RecordingContextRequest,
    query_recordings_in_deployment,
};
use fss_reference::agent_recordings::{RecordingQueryCodec, RecordingQueryRequest};
use fss_reference::rtsp::recording::PreparedRecording;
use fss_reference::rtsp::recording_catalog::hevc::{HevcCatalogWindow, prepare_hevc_catalog};
use fss_reference::rtsp::recording_catalog::{CatalogScope, CatalogWindow, prepare_catalog};
use fss_reference::rtsp::recording_collector::CollectorLimits;
use fss_reference::{
    ADP_REPLAY_ROW_ID, ReferenceDeployment, ReferencePolicyAction, ReferencePolicyDecision,
    ReplayCx, ReplayIoAuthority,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:recording-query-test";
const PRINCIPAL: &str = "principal:recording-query-test";

struct Fixture {
    directory: PathBuf,
    deployment: PathBuf,
    archive: PathBuf,
    request: RecordingContextRequest,
    metadata: ContentDigest,
    source_leaves: BTreeSet<ContentDigest>,
}
impl Fixture {
    fn new(tag: &str, codec: RecordingQueryCodec) -> TestResult<Self> {
        let mut root = None;
        for attempt in 0..100 {
            let candidate = std::env::temp_dir().join(format!(
                "fss-recording-query-{tag}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => {
                    root = Some(candidate);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        let directory = root.ok_or("temporary fixture directory capacity")?;
        let deployment = directory.join("deployment");
        let archive = directory.join("archive");
        for path in ["roots", "tombstones", "spool/objects"] {
            fs::create_dir_all(archive.join(path))?;
        }
        let (recording, metadata, source_leaves) = prepare_archive(&archive, codec)?;
        let fixture = Self {
            directory,
            deployment,
            archive,
            metadata,
            source_leaves,
            request: RecordingContextRequest {
                recording,
                principal: PrincipalId::parse(PRINCIPAL)?,
                expected_anchor: None,
            },
        };
        let cx = fixture.cx()?;
        drop(ReferenceDeployment::open(&fixture.deployment, SITE, &cx)?);
        Ok(fixture)
    }
    fn cx(&self) -> TestResult<ReplayCx> {
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:recording-query-test".to_owned(),
            operation_id: OperationId::parse("operation:recording-query-test")?,
            principal: "operator:recording-query-test".to_owned(),
            capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::default(),
            privacy_scope: "privacy:internal".to_owned(),
            retention_scope: "retention:ephemeral".to_owned(),
            anchor_universe: ContentDigest::sha256(b"independent-deployment-universe"),
            generation: 1,
        })?;
        Ok(ReplayCx::new(ReplayIoAuthority::from_context_authority(
            &authority,
            self.directory.join("cx"),
        )?))
    }
    fn publish_hypothesis(&self, id: &str) -> TestResult {
        let event = EventHypothesis {
            schema: EventHypothesis::SCHEMA.to_owned(),
            event_id: EventId::parse(id)?,
            revision: 1,
            supersedes: None,
            state: EventState::Hypothesized,
            kind: EventKind::UnknownPresence,
            interval: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
            uncertainty_reason: None,
            zone_ids: vec!["door".to_owned()],
            track_ids: Vec::new(),
            probability: ProbabilityInterval::new(0.0, 1.0)?,
            evidence: Vec::new(),
            model_receipts: Vec::new(),
            decision_path: DecisionPath {
                policy_generation: ContentDigest::sha256(b"fixture-policy"),
                fingerprint: ContentDigest::sha256(id.as_bytes()),
                abstained: true,
                abstention_reason: Some(
                    "synthetic unadjudicated fixture; no sensor evidence".to_owned(),
                ),
            },
        };
        event.verify()?;
        let cx = self.cx()?;
        ReferenceDeployment::open(&self.deployment, SITE, &cx)?.publish_event(
            &ReferencePolicyDecision {
                event,
                action: ReferencePolicyAction::Hold,
            },
            &cx,
        )?;
        Ok(())
    }
    fn args(&self) -> Vec<OsString> {
        let recording = &self.request.recording;
        let scope = &recording.scope;
        let mut values = vec![
            ("--target", "recordings".to_owned()),
            ("--codec", recording.codec.as_str().to_owned()),
            ("--catalog-slot", recording.catalog_slot.as_str().to_owned()),
            ("--catalog-root", recording.catalog_root.to_text()),
            ("--sensor", scope.recording.sensor.as_str().to_owned()),
            ("--stream", scope.recording.stream.as_str().to_owned()),
            ("--generation", scope.recording.generation.to_string()),
            ("--source-anchor", scope.recording.anchor.to_text()),
            ("--receive-clock", scope.recording.receive_clock.to_text()),
            ("--decode-clock", scope.decode_clock.to_text()),
            ("--time-scale", scope.time_scale.to_string()),
            ("--start-tick", recording.interval.start.to_string()),
            ("--end-tick", recording.interval.end.to_string()),
            ("--max-windows", recording.max_windows.to_string()),
            ("--max-hydration-bytes", recording.max_hydration_bytes.to_string()),
            ("--principal", self.request.principal.as_str().to_owned()),
        ];
        if let Some(anchor) = &self.request.expected_anchor {
            values.push(("--anchor", anchor.as_str().to_owned()));
        }
        let mut args = vec![
            "query".into(),
            "--json".into(),
            "--root".into(),
            self.deployment.as_os_str().to_owned(),
            "--archive-root".into(),
            self.archive.as_os_str().to_owned(),
        ];
        for (key, value) in values {
            args.extend([OsString::from(key), OsString::from(value)]);
        }
        args
    }
    fn run(&self) -> TestResult<(String, ExitIdentity)> {
        let args = self.args();
        let answer = execute_fss_with_exit(parse_fss_args(args.clone())?);
        let process = Command::new(env!("CARGO_BIN_EXE_fss")).args(args).output()?;
        assert_eq!(process.status.code(), Some(i32::from(answer.1.code)));
        assert_eq!(String::from_utf8(process.stdout)?, format!("{}\n", answer.0));
        assert!(process.stderr.is_empty());
        parse_json(&answer.0)?;
        Ok(answer)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn object_path(root: &Path, digest: ContentDigest) -> PathBuf {
    root.join("spool/objects").join(digest.to_text().trim_start_matches("sha256:"))
}
fn put(root: &Path, bytes: &[u8]) -> TestResult {
    let digest = ContentDigest::sha256(bytes);
    fs::write(object_path(root, digest), encode_spool_object(digest, bytes)?)?;
    Ok(())
}
fn publish(root: &Path, slot: &SlotName, manifest: &ObjectManifest) -> TestResult {
    put(root, &manifest.canonical_bytes())?;
    fs::write(
        root.join("roots").join(format!("{}.root", slot.as_str())),
        root_record_bytes(slot, manifest.root(), manifest.children().len())?,
    )?;
    Ok(())
}
fn avc_window(sequence: u64, decode_time: u64) -> TestResult<PreparedRecording> {
    let mut collector = collector_support::collector(CollectorLimits::default())?;
    let sample = collector_support::sample(
        sequence,
        90_000 + sequence as u32 * 3600,
        true,
        false,
    )?;
    sample.source(&mut collector, 1)?;
    collector_support::accepted(collector.push_picture(sample.timed(decode_time), 1))?;
    collector.seal(2)?;
    collector.take_ready().ok_or_else(|| "missing AVC window".into())
}
fn prepare_archive(
    root: &Path,
    codec: RecordingQueryCodec,
) -> TestResult<(RecordingQueryRequest, ContentDigest, BTreeSet<ContentDigest>)> {
    let a = SlotName::parse("first-window")?;
    let b = SlotName::parse("second-window")?;
    let (scope, catalog, index, leaves, interval) = match codec {
        RecordingQueryCodec::Avc => {
            let first = avc_window(1, 3600)?;
            let second = avc_window(3, 10800)?;
            let scope = CatalogScope {
                recording: collector_support::scope()?,
                decode_clock: ContentDigest::sha256(b"fixture-avc-decode-clock"),
                time_scale: 90_000,
            };
            let catalog = prepare_catalog(
                scope.clone(),
                &[
                    CatalogWindow { slot: &a, recording: &first },
                    CatalogWindow { slot: &b, recording: &second },
                ],
            )?;
            publish(root, &a, first.manifest())?;
            publish(root, &b, second.manifest())?;
            let leaves = first
                .children()
                .into_iter()
                .chain(second.children())
                .map(|(_, digest, _)| digest)
                .collect();
            (
                scope,
                catalog.manifest().clone(),
                catalog.index_bytes().to_vec(),
                leaves,
                0..18000,
            )
        }
        RecordingQueryCodec::Hevc => {
            let first = hevc_catalog_support::window(1_000)?;
            let second = hevc_catalog_support::window(100_000)?;
            let scope = hevc_catalog_support::scope()?;
            let catalog = prepare_hevc_catalog(
                scope.clone(),
                &[
                    HevcCatalogWindow { slot: &a, recording: &first },
                    HevcCatalogWindow { slot: &b, recording: &second },
                ],
            )?;
            publish(root, &a, first.manifest())?;
            publish(root, &b, second.manifest())?;
            let leaves = first
                .publication_plan()
                .children()
                .into_iter()
                .chain(second.publication_plan().children())
                .map(|(_, digest, _)| digest)
                .collect();
            (
                scope,
                catalog.manifest().clone(),
                catalog.index_bytes().to_vec(),
                leaves,
                0..200_000,
            )
        }
    };
    let slot = SlotName::parse("catalog")?;
    publish(root, &slot, &catalog)?;
    put(root, &index)?;
    Ok((
        RecordingQueryRequest {
            codec,
            scope,
            catalog_slot: slot,
            catalog_root: catalog.root(),
            interval,
            max_windows: 32,
            max_hydration_bytes: 256 * 1024 * 1024,
        },
        ContentDigest::sha256(&index),
        leaves,
    ))
}

fn at<'a>(value: &'a Value, keys: &[&str]) -> TestResult<&'a Value> {
    let mut current = value;
    for key in keys {
        current = current.object().and_then(|o| o.get(*key))
            .ok_or_else(|| format!("missing JSON field {key}"))?;
    }
    Ok(current)
}
fn text_at<'a>(value: &'a Value, keys: &[&str]) -> TestResult<&'a str> {
    at(value, keys)?.text().ok_or_else(|| "expected JSON string".into())
}
fn propositions(value: &Value) -> TestResult<&[Value]> {
    at(value, &["payload", "epistemic", "propositions"])?
        .array().ok_or_else(|| "expected propositions".into())
}
fn proposition<'a>(value: &'a Value, id: &str) -> TestResult<&'a Value> {
    propositions(value)?.iter()
        .find(|p| text_at(p, &["id"]).is_ok_and(|value| value == id))
        .ok_or_else(|| format!("missing proposition {id}").into())
}
fn tree(root: &Path) -> TestResult<BTreeMap<PathBuf, (bool, Vec<u8>)>> {
    let mut pending = vec![root.to_path_buf()];
    let mut tree = BTreeMap::new();
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        let relative = path.strip_prefix(root)?.to_path_buf();
        if metadata.is_dir() {
            tree.insert(relative, (true, Vec::new()));
            for entry in fs::read_dir(path)? {
                pending.push(entry?.path());
            }
        } else if metadata.is_file() {
            tree.insert(relative, (false, fs::read(path)?));
        } else {
            return Err("special file in fixture".into());
        }
    }
    Ok(tree)
}

#[test]
fn actual_avc_and_hevc_cli_return_h0_metadata_gaps_and_independent_current_context() -> TestResult {
    for codec in [RecordingQueryCodec::Avc, RecordingQueryCodec::Hevc] {
        let fixture = Fixture::new(codec.as_str(), codec)?;
        fixture.publish_hypothesis("event:protected-recording-query")?;
        for leaf in &fixture.source_leaves {
            assert!(!object_path(&fixture.archive, *leaf).exists());
        }
        let before = tree(&fixture.directory)?;
        let (output, exit) = fixture.run()?;
        assert_eq!(exit, ExitIdentity::SUCCESS, "{output}");
        assert_eq!(fixture.run()?, (output.clone(), exit));
        let envelope = parse_json(&output)?;
        assert_eq!(text_at(&envelope, &["schema"])?, "fss.agent_response_envelope.v1");
        assert_eq!(text_at(&envelope, &["outcome"])?, "ok");
        assert_eq!(text_at(&envelope, &["principalId"])?, PRINCIPAL);
        assert_eq!(text_at(&envelope, &["epistemicState"])?, "unknown");
        assert_eq!(
            text_at(&envelope, &["payload", "coverage", "stopReason"])?,
            "pinned_catalog_exhausted"
        );
        let handles = at(&envelope, &["payload", "evidenceHandles"])?
            .array().ok_or("evidence handles")?;
        assert_eq!(handles.len(), 3);
        for handle in handles {
            assert_eq!(text_at(handle, &["hydration"])?, "H0");
            assert_eq!(
                at(handle, &["allowedHydration"])?.array().ok_or("allowed hydration")?,
                &[Value::Text("H0".to_owned())]
            );
            assert_eq!(text_at(handle, &["availability"])?, "available");
        }
        assert_eq!(
            text_at(
                proposition(&envelope, "claim:recordings:physical-observability")?,
                &["state"],
            )?,
            "unknown"
        );
        let gaps: Vec<_> = propositions(&envelope)?.iter()
            .filter(|p| text_at(p, &["id"])
                .is_ok_and(|id| id.starts_with("claim:recordings:indexed-gap:")))
            .collect();
        assert_eq!(gaps.len(), 3);
        for gap in gaps {
            assert_eq!(text_at(gap, &["state"])?, "not_observable");
        }
        let query = query_recordings_in_deployment(
            &HostSpoolIo,
            &fixture.deployment,
            &fixture.archive,
            &fixture.request,
            &RecordingContextLimits::default(),
            &|| false,
        )?;
        let orientation = orient_deployment(
            &query.snapshot,
            &OrientRequest {
                view: AgentView::Brief,
                principal: fixture.request.principal.clone(),
                budget_tokens: None,
            },
            &RecordingContextLimits::default().snapshot,
        )?;
        for cell in &orientation.capsule().frame.knowledge_cells {
            let retained = proposition(&envelope, cell.claim_id())?;
            assert_eq!(text_at(retained, &["state"])?, cell.knowledge_state().as_str());
            assert_eq!(text_at(retained, &["statement"])?, cell.disclosable_statement());
        }
        assert!(output.contains("event:protected-recording-query"));
        assert!(output.contains(&query.anchor_token));
        assert_ne!(query.anchor_token, fixture.request.recording.scope.recording.anchor.to_text());
        assert!(output.contains("source_payload_availability=unknown"));
        assert!(!output.contains(fixture.archive.to_str().ok_or("archive UTF-8")?));
        assert_eq!(tree(&fixture.directory)?, before);
    }
    Ok(())
}

#[test]
fn principal_changes_request_and_decision_without_changing_selected_recording_roots() -> TestResult {
    let mut fixture = Fixture::new("principal", RecordingQueryCodec::Avc)?;
    let first = fixture.run()?;
    assert_eq!(first.1, ExitIdentity::SUCCESS, "{}", first.0);
    fixture.request.principal = PrincipalId::parse("principal:second-recording-reader")?;
    let second = fixture.run()?;
    assert_eq!(second.1, ExitIdentity::SUCCESS, "{}", second.0);
    let a = parse_json(&first.0)?;
    let b = parse_json(&second.0)?;
    assert_ne!(text_at(&a, &["requestId"])?, text_at(&b, &["requestId"])?);
    assert_ne!(
        text_at(&a, &["decisionFingerprint"])?,
        text_at(&b, &["decisionFingerprint"])?
    );
    assert_eq!(
        at(&a, &["payload", "evidenceHandles"])?,
        at(&b, &["payload", "evidenceHandles"])?
    );
    assert_eq!(text_at(&b, &["principalId"])?, "principal:second-recording-reader");
    Ok(())
}

#[test]
fn metadata_context_reads_succeed_with_both_writers_locked_and_never_touch_source_leaves()
-> TestResult {
    let fixture = Fixture::new("locked", RecordingQueryCodec::Avc)?;
    let cx = fixture.cx()?;
    let writer = ReferenceDeployment::open(&fixture.deployment, SITE, &cx)?;
    let archive_lock = fs::File::create(fixture.archive.join("LOCK"))?;
    archive_lock.try_lock()?;
    for leaf in &fixture.source_leaves {
        fs::write(
            object_path(&fixture.archive, *leaf),
            b"deliberately corrupt original/derivative/index bytes",
        )?;
    }
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let before = tree(&fixture.directory)?;
    let query = query_recordings_in_deployment(
        &io,
        &fixture.deployment,
        &fixture.archive,
        &fixture.request,
        &RecordingContextLimits::default(),
        &|| false,
    )?;
    assert_eq!(query.native.rows.len(), 2);
    assert!(io.is_read_only());
    assert_eq!(io.call_count(SpoolIoCall::ReadDir), 0);
    assert_eq!(io.call_count(SpoolIoCall::NextDirEntry), 0);
    assert!(query.deployment_bytes_read > 0 && query.deployment_metadata_reads > 0);
    assert_eq!(fixture.run()?.1, ExitIdentity::SUCCESS);
    assert_eq!(tree(&fixture.directory)?, before);
    archive_lock.unlock()?;
    drop(writer);
    Ok(())
}

#[test]
fn missing_corrupt_deleted_and_mismatched_catalogs_refuse_without_a_successful_empty_result()
-> TestResult {
    for fault in ["missing-member", "metadata", "catalog-root", "source-scope", "tombstone"] {
        let mut fixture = Fixture::new(fault, RecordingQueryCodec::Avc)?;
        match fault {
            "missing-member" => fs::remove_file(fixture.archive.join("roots/second-window.root"))?,
            "metadata" => fs::write(object_path(&fixture.archive, fixture.metadata), b"corrupt metadata")?,
            "catalog-root" => fixture.request.recording.catalog_root = ContentDigest::sha256(b"foreign-catalog"),
            "source-scope" => fixture.request.recording.scope.recording.generation += 1,
            _ => {
                let leaf = fixture.source_leaves.first().ok_or("source leaf")?;
                fs::write(
                    fixture.archive.join("tombstones").join(format!(
                        "{}.tomb",
                        leaf.to_text().replacen(':', "-", 1)
                    )),
                    b"deletion present",
                )?;
            }
        }
        let before = tree(&fixture.directory)?;
        let (output, exit) = fixture.run()?;
        assert_eq!(exit, ExitIdentity::AGENT_REFUSED, "{fault}: {output}");
        assert!(!output.contains("claim:recordings:catalog-selection"));
        assert_eq!(tree(&fixture.directory)?, before);
    }
    Ok(())
}

#[test]
fn expected_deployment_anchor_and_mid_query_deployment_changes_refuse() -> TestResult {
    let mut fixture = Fixture::new("stale", RecordingQueryCodec::Avc)?;
    let initial = query_recordings_in_deployment(
        &HostSpoolIo,
        &fixture.deployment,
        &fixture.archive,
        &fixture.request,
        &RecordingContextLimits::default(),
        &|| false,
    )?;
    fixture.request.expected_anchor = Some(
        AnchorToken::parse(&snapshot_anchor_token(&initial.snapshot)).ok_or("anchor token")?,
    );
    fixture.publish_hypothesis("event:recording-query-new-head")?;
    let before = tree(&fixture.directory)?;
    assert_eq!(fixture.run()?.1, ExitIdentity::AGENT_REFUSED);
    assert_eq!(tree(&fixture.directory)?, before);
    fixture.request.expected_anchor = None;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let changed = AtomicBool::new(false);
    let cancelled = || {
        if io.call_count(SpoolIoCall::OpenRead) >= 5
            && !changed.swap(true, Ordering::SeqCst)
        {
            return fixture.publish_hypothesis("event:recording-query-racing-head").is_err();
        }
        false
    };
    let result = query_recordings_in_deployment(
        &io,
        &fixture.deployment,
        &fixture.archive,
        &fixture.request,
        &RecordingContextLimits::default(),
        &cancelled,
    );
    assert!(changed.load(Ordering::SeqCst));
    assert!(
        matches!(result, Err(RecordingContextError::AnchorChanged)),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn context_budgets_share_both_reads_and_invalid_native_allowance_fails_preflight() -> TestResult {
    let fixture = Fixture::new("budgets", RecordingQueryCodec::Avc)?;
    let limits = RecordingContextLimits::default();
    let baseline = query_recordings_in_deployment(
        &HostSpoolIo,
        &fixture.deployment,
        &fixture.archive,
        &fixture.request,
        &limits,
        &|| false,
    )?;
    // The existing deployment reader reserves before probing absent optional files.
    // Keep one byte of probe allowance after the last charged payload.
    let exact = RecordingContextLimits {
        deployment_bytes: baseline.deployment_bytes_read as usize + 1,
        deployment_reads: baseline.deployment_metadata_reads as usize,
        ..limits
    };
    let exact_result = query_recordings_in_deployment(
        &HostSpoolIo,
        &fixture.deployment,
        &fixture.archive,
        &fixture.request,
        &exact,
        &|| false,
    )?;
    assert_eq!(exact_result.native.rows, baseline.native.rows);
    assert_eq!(exact_result.deployment_bytes_read, baseline.deployment_bytes_read);
    assert_eq!(exact_result.deployment_metadata_reads, baseline.deployment_metadata_reads);
    assert_ne!(exact_result.request_digest, baseline.request_digest);
    for lowered in [
        RecordingContextLimits {
            deployment_bytes: baseline.deployment_bytes_read as usize - 1,
            ..exact
        },
        RecordingContextLimits {
            deployment_reads: exact.deployment_reads - 1,
            ..exact
        },
    ] {
        assert!(
            query_recordings_in_deployment(
                &HostSpoolIo,
                &fixture.deployment,
                &fixture.archive,
                &fixture.request,
                &lowered,
                &|| false,
            )
            .is_err()
        );
    }
    let mut invalid = limits;
    invalid.recording.metadata.max_io_calls += 1;
    let result = query_recordings_in_deployment(
        &HostSpoolIo,
        &fixture.directory.join("not-a-deployment"),
        &fixture.archive,
        &fixture.request,
        &invalid,
        &|| false,
    );
    assert!(
        matches!(result, Err(RecordingContextError::Recording(_))),
        "{result:?}"
    );
    assert!(matches!(
        query_recordings_in_deployment(
            &HostSpoolIo,
            &fixture.deployment,
            &fixture.archive,
            &fixture.request,
            &limits,
            &|| true,
        ),
        Err(RecordingContextError::Cancelled)
    ));
    Ok(())
}
