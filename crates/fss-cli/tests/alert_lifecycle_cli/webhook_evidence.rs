#![forbid(unsafe_code)]
//! Cold, metadata-only evidence inspection is a read operation, including after a crash.

use super::*;
use fss_core::{CapsuleId, Generation, ObjectId, SensorId, TombstoneReason, TombstoneRecord};
use fss_ledger::{
    DurableReferenceLedger, HostJournalReadIo, IncompleteTailPolicy, JournalFileMetadata,
    JournalReadIo,
};
use fss_object::{InMemoryObjectStore, ObjectLimits};
use fss_publication::{
    LOCAL_TOMBSTONES_DIR, LocalPublicationError, ROOT_INDETERMINATE_SUFFIX,
    TOMBSTONE_RECORD_SUFFIX, tombstone_record_bytes,
};
use fss_reference::webhook::retained::{
    WebhookRetentionError, read_retained_webhook_evidence_from_root_with_io,
    retain_webhook_evidence,
};
use fss_reference::webhook::{
    WebhookAttempt, WebhookAuthority, WebhookBoundary, WebhookDenial, WebhookEndpoint,
    WebhookLimits, WebhookScope, record_webhook_evidence,
};
use fss_reference::{
    DeliveryPlan, MockModelScript, MockModelSpec, MockSemanticLabel, PrepareAlertParams,
    ReferenceModelObservation, VirtualCameraSpec, execute_mock_model, run_reference_capture,
};

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

const INSPECT: &str = "CAP-AGENT-SITUATION-READ-001";
const COMMIT: &str = "CAP-ALERT-COMMIT-001";
const TARGET: &str = "/wire-fixture-do-not-print";

struct Owner {
    route: ContentDigest,
    journal: PathBuf,
}

impl WebhookAuthority for Owner {
    fn checkpoint(
        &self,
        scope: WebhookScope<'_>,
        _boundary: WebhookBoundary,
        now: u64,
        _deadline: u64,
    ) -> Result<u64, WebhookDenial> {
        if scope.endpoint.digest() == self.route && scope.effect_journal == self.journal {
            Ok(now)
        } else {
            Err(WebhookDenial::Unauthorized)
        }
    }
}

/// Produce a genuine, privately constructed native observation without sending: commit an
/// eligible two-source alert and retire the attempt before its first socket operation.
fn retained_fixture(root: &Path, record: bool) -> TestResult<ContentDigest> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:alert-cli-wire-test".into(),
        operation_id: OperationId::parse("operation:alert-cli-wire-test")?,
        principal: "principal:local-operator".into(),
        capabilities: vec!["ADP-REPLAY-001".into(), INSPECT.into(), COMMIT.into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(8 * 1024 * 1024)
            .storage_operations(8192)
            .build()?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, root.to_path_buf())?;
    let mut deployment = open(root, &cx)?;
    let capture_directory = Directory::new("wire-captures")?;
    let mut captures = DurableReferenceLedger::open(
        &capture_directory.0.join("captures.fssj"),
        "site:alert-cli-fixture-captures",
        IncompleteTailPolicy::Reject,
    )?;
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
    let mut observations = Vec::new();
    for (name, seed) in [("alpha", 111), ("beta", 222)] {
        let camera = VirtualCameraSpec {
            capture_id: CapsuleId::parse(format!("capture:cli:{name}"))?,
            sensor_id: SensorId::parse(format!("sensor:cli:{name}"))?,
            seed,
            packet_count: 2,
            packet_bytes: 32,
            start_ns: 10_000,
            period_ns: 1_000_000,
            uncertainty_ns: 1_000,
        };
        let capture = run_reference_capture(
            &camera,
            &DeliveryPlan::identity(camera.packet_count)?,
            &mut objects,
            &mut captures,
        )?;
        let model = MockModelSpec::new(
            format!("mock:cli:{name}:v1"),
            MockModelScript::Fixed {
                label: MockSemanticLabel::PersonLike,
                probability: ProbabilityInterval::new(0.99, 1.0)?,
            },
        )?;
        let result = execute_mock_model(&model, &capture, &mut objects)?;
        observations.push(ReferenceModelObservation::new(
            result,
            format!("power:cli:{name}"),
            CaptureInterval::new(TimestampNs(10_000), TimestampNs(20_000))?,
        )?);
    }
    let decision = deployment.evaluate_policy(
        EventId::parse("event:cli-wire-evidence")?,
        observations,
        &cx,
    )?;
    for digest in &decision.event.model_receipts {
        assert_eq!(
            deployment.stage_payload(objects.read_verified(*digest)?)?,
            *digest
        );
    }
    let event = deployment.publish_event(&decision, &cx)?;
    let endpoint = WebhookEndpoint::new(
        "127.0.0.1:9".parse()?,
        TARGET,
        ContentDigest::sha256(b"explicit test plaintext approval, no socket call"),
    )?;
    let plan = {
        let (effects, ledger) = deployment.effects_and_ledger();
        effects.prepare_alert(PrepareAlertParams {
            decision: &decision,
            event_receipt: &event,
            authority: ledger,
            operation_id: OperationId::parse(OPERATION)?,
            idempotency_key: IdempotencyKey::parse("idempotency:cli-wire")?,
            obligation_id: ObligationId::parse("obligation:cli-wire")?,
            channel: endpoint.channel().to_owned(),
            now: TimestampNs(100),
        })?
    };
    let owner = Owner {
        route: endpoint.digest(),
        journal: deployment.effects().path().to_path_buf(),
    };
    let evidence = {
        let (journal, ledger, publisher) = deployment.effect_dispatch_parts();
        WebhookAttempt::begin(
            &plan,
            &endpoint,
            ledger,
            journal,
            WebhookLimits {
                io_calls: 8,
                io_bytes: 4096,
                response_bytes: 16_384,
                connect_timeout_ns: 100_000_000,
            },
            101,
            1_000_000_000,
            &owner,
            |digest| {
                publisher
                    .spool()
                    .read(digest)
                    .map_err(LocalPublicationError::Spool)
            },
        )?
        .retire()
    };
    assert_eq!(evidence.io_calls(), 0);
    assert_eq!(evidence.sent_bytes(), 0);
    let retained = retain_webhook_evidence(&mut deployment, &evidence, &authority, &cx)?;
    if record {
        record_webhook_evidence(&evidence, &endpoint, deployment.effects_mut(), 102, &owner)?;
    }
    cx.drain_and_finalize();
    Ok(retained.digest())
}

#[test]
fn absent_wire_is_explicit_and_does_not_reclassify_a_committed_operation() -> TestResult {
    for committed in [false, true] {
        let dir = Directory::new("wire-absent")?;
        fixture(&dir.0, committed)?;
        let lock = dir.0.join("objects/LOCK");
        if lock.exists() {
            fs::remove_file(&lock)?;
        }
        let before = files(&dir.0)?;
        let args = ["--operation-id", OPERATION];
        let output = success(invoke(&dir.0, "evidence", &args)?)?;
        assert!(output.contains("\"action\":\"evidence\""));
        assert!(output.contains("\"wire_evidence\":null"));
        assert!(output.contains("\"network_access\":false"));
        assert!(output.contains("\"writes\":\"none\""));
        assert_eq!(before, files(&dir.0)?);
        assert!(
            !lock.exists(),
            "read-only inspection must not acquire a deployment writer"
        );
        assert_eq!(output, success(invoke(&dir.0, "evidence", &args)?)?);
        assert_eq!(before, files(&dir.0)?);
    }
    Ok(())
}

#[test]
fn cold_wire_metadata_does_not_disclose_bytes_or_complete_a_missing_journal_record() -> TestResult {
    for recorded in [false, true] {
        let dir = Directory::new("wire-retained")?;
        let digest = retained_fixture(&dir.0, recorded)?;
        let lock = dir.0.join("objects/LOCK");
        if lock.exists() {
            fs::remove_file(&lock)?;
        }
        let before = files(&dir.0)?;
        let args = ["--operation-id", OPERATION];
        let output = success(invoke(&dir.0, "evidence", &args)?)?;
        assert!(output.contains("\"action\":\"evidence\""));
        assert!(output.contains(&digest.to_text()));
        assert!(!output.contains("\"wire_evidence\":null"));
        assert!(output.contains(&format!("\"journal_observation_recorded\":{recorded}")));
        assert!(output.contains("\"network_access\":false"));
        assert!(output.contains("\"writes\":\"none\""));
        assert!(!output.contains(TARGET));
        assert!(!output.contains("POST "));
        assert!(!output.contains("\"request\":"));
        assert!(!output.contains("\"response_prefix\":"));
        assert!(!output.contains("\"state\":\"verified\""));
        assert_eq!(before, files(&dir.0)?);
        assert!(!lock.exists());
        assert_eq!(output, success(invoke(&dir.0, "evidence", &args)?)?);
        assert_eq!(before, files(&dir.0)?);
    }
    Ok(())
}

#[test]
fn cold_inspection_keeps_original_wire_when_terminal_proof_is_an_owner_attestation() -> TestResult {
    let dir = Directory::new("wire-terminal-proof")?;
    let wire = retained_fixture(&dir.0, true)?;
    let evidence = ContentDigest::sha256(b"recipient's independent confirmation").to_text();
    let mut request = vec![
        "--operation-id",
        OPERATION,
        "--outcome",
        "delivered",
        "--evidence",
        evidence.as_str(),
        "--statement",
        "Recipient independently confirmed receipt",
    ];
    let preview = success(invoke(&dir.0, "reconcile", &request)?)?;
    let approval = digest_field(&preview, "approval_digest")?;
    request.extend(["--approve", approval.as_str()]);
    let reconciled = success(invoke(&dir.0, "reconcile", &request)?)?;
    assert!(reconciled.contains("\"state\":\"verified\""));
    assert!(reconciled.contains("\"provenance\":\"operator_asserted\""));
    let before = files(&dir.0)?;
    let output = success(invoke(&dir.0, "evidence", &["--operation-id", OPERATION])?)?;
    assert!(output.contains(&wire.to_text()));
    assert!(output.contains("\"journal_observation_recorded\":true"));
    assert!(!output.contains(TARGET));
    assert!(output.contains("\"network_access\":false"));
    assert!(output.contains("\"writes\":\"none\""));
    assert_eq!(before, files(&dir.0)?);
    Ok(())
}

#[test]
fn missing_deployment_and_invalid_evidence_arguments_never_create_storage() -> TestResult {
    let dir = Directory::new("wire-missing")?;
    let missing = dir.0.join("absent");
    let output = invoke(&missing, "evidence", &["--operation-id", OPERATION])?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!missing.exists());
    fixture(&dir.0, true)?;
    let before = files(&dir.0)?;
    for args in [
        vec![],
        vec!["--operation-id", OPERATION, "--approve", "anything"],
        vec!["--operation-id", OPERATION, "--raw"],
    ] {
        let output = invoke(&dir.0, "evidence", &args)?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(before, files(&dir.0)?);
    }
    Ok(())
}

#[test]
fn damaged_retained_bytes_are_a_refusal_not_absent_or_verified_evidence() -> TestResult {
    let dir = Directory::new("wire-corrupt")?;
    let digest = retained_fixture(&dir.0, true)?;
    let path = dir
        .0
        .join("objects/spool/objects")
        .join(digest.to_text().trim_start_matches("sha256:"));
    let mut bytes = fs::read(&path)?;
    *bytes.last_mut().ok_or("empty retained object")? ^= 1;
    fs::write(path, bytes)?;
    let before = files(&dir.0)?;
    let output = invoke(&dir.0, "evidence", &["--operation-id", OPERATION])?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(before, files(&dir.0)?);
    Ok(())
}

#[test]
fn canonical_tombstone_or_indeterminate_marker_refuses_still_present_wire() -> TestResult {
    for indeterminate in [false, true] {
        let dir = Directory::new("wire-tombstone")?;
        let digest = retained_fixture(&dir.0, true)?;
        let hex = digest.to_text();
        let hex = hex.trim_start_matches("sha256:");
        assert!(dir.0.join("objects/spool/objects").join(hex).is_file());
        assert!(dir.0.join("objects/spool/holds").join(hex).is_file());
        let record = TombstoneRecord::new(
            ObjectId::parse("object:retained-wire-test")?,
            Generation(2),
            Generation(1),
            TombstoneReason::Deleted,
            None,
            digest,
        )?;
        // Publication names include the digest algorithm; the spool's hex-only names differ.
        let stem = digest.to_text().replacen(':', "-", 1);
        let suffix = if indeterminate {
            ROOT_INDETERMINATE_SUFFIX
        } else {
            ""
        };
        let path = dir
            .0
            .join("objects")
            .join(LOCAL_TOMBSTONES_DIR)
            .join(format!("{stem}{TOMBSTONE_RECORD_SUFFIX}{suffix}"));
        fs::write(path, tombstone_record_bytes(&record)?)?;
        let before = files(&dir.0)?;
        let output = invoke(&dir.0, "evidence", &["--operation-id", OPERATION])?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(before, files(&dir.0)?);
    }
    Ok(())
}

/// Count every actual read capability call, including metadata. The optional fault changes
/// only returned bytes during the final snapshot comparison, never the underlying files.
struct CountingIo {
    calls: AtomicU64,
    mutation_target: Option<PathBuf>,
    target_reads: AtomicU64,
}

impl CountingIo {
    fn new(mutation_target: Option<PathBuf>) -> Self {
        Self {
            calls: AtomicU64::new(0),
            mutation_target,
            target_reads: AtomicU64::new(0),
        }
    }
}

impl JournalReadIo for CountingIo {
    fn symlink_metadata(&self, path: &Path) -> io::Result<JournalFileMetadata> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        HostJournalReadIo.symlink_metadata(path)
    }

    fn read_bounded(&self, path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut bytes = HostJournalReadIo.read_bounded(path, maximum)?;
        if self.mutation_target.as_deref() == Some(path)
            && self.target_reads.fetch_add(1, Ordering::SeqCst) == 1
            && let Some(last) = bytes.last_mut()
        {
            *last ^= 1;
        }
        Ok(bytes)
    }
}

fn read_context(root: &Path, storage_operations: u64) -> TestResult<(ContextAuthority, ReplayCx)> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:wire-inspection-budget-test".into(),
        operation_id: OperationId::parse("operation:wire-inspection-budget-test")?,
        principal: "principal:local-operator".into(),
        capabilities: vec!["ADP-REPLAY-001".into(), INSPECT.into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(8 * 1024 * 1024)
            .storage_operations(storage_operations)
            .build()?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority_read_only(&authority, root.to_path_buf())?;
    Ok((authority, cx))
}

#[test]
fn cold_inspector_charges_every_metadata_and_payload_read_before_admission() -> TestResult {
    let dir = Directory::new("wire-read-budget")?;
    retained_fixture(&dir.0, true)?;
    let id = OperationId::parse(OPERATION)?;
    let (authority, cx) = read_context(&dir.0, 8192)?;
    let complete = CountingIo::new(None);
    assert!(
        read_retained_webhook_evidence_from_root_with_io(&complete, &dir.0, &id, &authority, &cx,)?
            .is_some()
    );
    let required = complete.calls.load(Ordering::SeqCst);
    assert!(
        required > 32,
        "directory and file metadata must count as storage calls"
    );
    let (limited, limited_cx) = read_context(&dir.0, required - 1)?;
    let bounded = CountingIo::new(None);
    let before = files(&dir.0)?;
    assert!(matches!(
        read_retained_webhook_evidence_from_root_with_io(
            &bounded,
            &dir.0,
            &id,
            &limited,
            &limited_cx,
        ),
        Err(WebhookRetentionError::Budget)
    ));
    assert_eq!(bounded.calls.load(Ordering::SeqCst), required - 1);
    assert_eq!(before, files(&dir.0)?);
    Ok(())
}

#[test]
fn changed_effect_history_during_final_reread_refuses_the_candidate() -> TestResult {
    let dir = Directory::new("wire-read-snapshot-change")?;
    retained_fixture(&dir.0, true)?;
    let id = OperationId::parse(OPERATION)?;
    let (authority, cx) = read_context(&dir.0, 8192)?;
    let fault = CountingIo::new(Some(dir.0.join("effects/journal.fssj")));
    let before = files(&dir.0)?;
    assert!(matches!(
        read_retained_webhook_evidence_from_root_with_io(&fault, &dir.0, &id, &authority, &cx,),
        Err(WebhookRetentionError::Custody)
    ));
    assert_eq!(fault.target_reads.load(Ordering::SeqCst), 2);
    assert_eq!(before, files(&dir.0)?);
    Ok(())
}
