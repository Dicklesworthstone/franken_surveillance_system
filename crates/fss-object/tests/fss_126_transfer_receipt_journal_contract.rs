#![forbid(unsafe_code)]
//! Contract and fault suite for `FSS-126` (`fss-x4a.13.10`):
//! ATP transfer receipt (`fss.transfer_receipt.v1`) and crash-resumable on-disk framed journal v1.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::json_input::{Value, parse};
use fss_core::{ContentDigest, TimestampNs};
use fss_object::atp_lifecycle::{
    ATP_LIFECYCLE_FORMAT_VERSION, ArchiveObjectState, AtpLifecycleCoordinator, AtpLifecycleError,
    AuthoritySnapshot, IndeterminateTransferObligation, LifecycleEvent, PathState,
    ProofOfRetrievability, TransferJournal, TransferSpec,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const RECEIPT_SCHEMA_JSON: &str = include_str!("../../../schemas/transfer_receipt.v1.json");
static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> io::Result<Self> {
        let base = fs::canonicalize(std::env::temp_dir())?;
        for _ in 0..32 {
            let n = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!("fss-126-journal-{}-{n}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "temp dir namespace exhausted",
        ))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn d(label: &str) -> ContentDigest {
    ContentDigest::sha256(label.as_bytes())
}

fn spec_for(archive_enabled: bool) -> TransferSpec {
    TransferSpec {
        format_version: ATP_LIFECYCLE_FORMAT_VERSION,
        protocol_generation: 1,
        sender: "node:cam-edge-126".to_owned(),
        receiver: "archive:vault-126".to_owned(),
        session_nonce: 126,
        manifest_root: d("fss126-manifest-root"),
        contract_basis_digest: d("fss126-contract-basis"),
        transfer_policy_digest: d("fss126-policy"),
        expected_authority_generation: 4,
        initial_fence: 20,
        archive_enabled,
        required_failure_domains: 2,
        expected_children: vec![(d("fss126-c1"), 4096), (d("fss126-c2"), 2048)],
        max_journal_records: 256,
        unknown_critical_extensions: Vec::new(),
    }
}

fn auth_for(spec: &TransferSpec) -> AuthoritySnapshot {
    AuthoritySnapshot {
        contract_basis_digest: spec.contract_basis_digest,
        authority_generation: spec.expected_authority_generation,
        privacy_epoch: 5,
        capability_active: true,
        privacy_active: true,
        destination_authorized: true,
        max_bytes_budget: 1_000_000,
        max_ops_budget: 1_000,
    }
}

fn assert_conforms_to_transfer_receipt_v1(raw: &str) -> Result<(), Box<dyn std::error::Error>> {
    let parsed = parse(raw)?;
    let obj = parsed.object().ok_or("receipt must be a JSON object")?;
    assert_eq!(
        obj.get("schema").and_then(Value::text),
        Some("fss.transfer_receipt.v1")
    );
    let required = [
        "schema",
        "transferId",
        "rootDigest",
        "state",
        "source",
        "destination",
        "bytes",
        "objects",
        "verification",
        "timestamps",
    ];
    for key in required {
        assert!(obj.contains_key(key), "missing required schema field {key}");
    }
    let allowed: BTreeSet<&str> = [
        "schema",
        "transferId",
        "rootDigest",
        "state",
        "semanticState",
        "archiveState",
        "pathStates",
        "publicationFence",
        "contractBasisDigest",
        "counters",
        "providerTuple",
        "proofOfRetrievability",
        "reconciliationObligation",
        "source",
        "destination",
        "bytes",
        "objects",
        "paths",
        "repair",
        "verification",
        "timestamps",
        "journalDigest",
        "errorId",
    ]
    .into_iter()
    .collect();
    for key in obj.keys() {
        assert!(
            allowed.contains(key.as_str()),
            "receipt emitted unexpected additionalProperty '{key}' forbidden by transfer_receipt.v1.json"
        );
    }
    let verification = obj
        .get("verification")
        .and_then(Value::object)
        .ok_or("verification object")?;
    for vkey in ["manifest", "objects", "closure", "root"] {
        assert!(
            verification.get(vkey).and_then(Value::boolean).is_some(),
            "verification.{vkey} must be boolean"
        );
    }
    let timestamps = obj
        .get("timestamps")
        .and_then(Value::object)
        .ok_or("timestamps object")?;
    for (tk, tv) in timestamps {
        assert!(tv.integer().is_some(), "timestamp '{tk}' must be integer");
    }
    // Verify schema file itself declares the exact same required set.
    for key in required {
        assert!(
            RECEIPT_SCHEMA_JSON.contains(&format!("\"{key}\"")),
            "schema file missing {key}"
        );
    }
    Ok(())
}

#[test]
fn multi_restart_resumable_journal_matches_uninterrupted_run_and_validates_schema_v1() -> TestResult
{
    let dir = TempDir::new()?;
    let journal_path = dir.0.join("transfer-126.journal");
    let spec = spec_for(true);
    let auth = auth_for(&spec);
    let c1 = spec.expected_children[0].0;
    let c2 = spec.expected_children[1].0;

    // Reference uninterrupted coordinator.
    let mut reference = AtpLifecycleCoordinator::new(spec.clone(), auth.clone())?;
    // Resumable coordinator persisted across 3 simulated cold restarts.
    let mut coord = AtpLifecycleCoordinator::new(spec.clone(), auth.clone())?;

    let stage1 = vec![
        (
            20,
            TimestampNs(100),
            LifecycleEvent::Reserve {
                reserved_bytes: 16_384,
                reserved_ops: 64,
            },
            0,
            1,
        ),
        (
            20,
            TimestampNs(110),
            LifecycleEvent::VerifyManifest {
                manifest_root: spec.manifest_root,
            },
            0,
            1,
        ),
        (
            20,
            TimestampNs(120),
            LifecycleEvent::OfferGraph {
                offered_bytes: 6144,
                offered_objects: 2,
            },
            0,
            1,
        ),
        (20, TimestampNs(130), LifecycleEvent::BeginReceiving, 0, 1),
        (
            20,
            TimestampNs(140),
            LifecycleEvent::PathDiscover {
                path_id: "wan-primary".to_owned(),
                failure_domain: "fd-a".to_owned(),
            },
            0,
            1,
        ),
        (
            20,
            TimestampNs(150),
            LifecycleEvent::PathTransition {
                path_id: "wan-primary".to_owned(),
                to: PathState::Candidate,
                reason: "init".to_owned(),
            },
            0,
            1,
        ),
        (
            20,
            TimestampNs(160),
            LifecycleEvent::PathTransition {
                path_id: "wan-primary".to_owned(),
                to: PathState::Probing,
                reason: "probe".to_owned(),
            },
            0,
            1,
        ),
        (
            20,
            TimestampNs(170),
            LifecycleEvent::PathTransition {
                path_id: "wan-primary".to_owned(),
                to: PathState::Active,
                reason: "ok".to_owned(),
            },
            0,
            1,
        ),
        (
            20,
            TimestampNs(180),
            LifecycleEvent::DeliverChild {
                path_id: "wan-primary".to_owned(),
                child_digest: c1,
                bytes: 4096,
                reused_existing: false,
            },
            4096,
            1,
        ),
    ];
    for (fence, ts, ev, wb, wo) in stage1 {
        reference.apply_event(fence, ts, ev.clone(), wb, wo)?;
        coord.apply_event(fence, ts, ev, wb, wo)?;
    }

    // Cold checkpoint 1 on disk -> reload into fresh coordinator.
    coord.journal().write_framed_file(&journal_path)?;
    coord = AtpLifecycleCoordinator::resume_from_journal_file(
        spec.clone(),
        auth.clone(),
        &journal_path,
    )?;
    assert_eq!(coord, reference);
    assert!(matches!(
        coord.to_transfer_receipt_v1_json(true, None),
        Err(AtpLifecycleError::ReceiptBeforeCommit { .. })
    ));

    let stage2 = vec![
        (
            20,
            TimestampNs(190),
            LifecycleEvent::RepairChild {
                child_digest: c2,
                reconstructed_digest: c2,
                repair_symbols_used: 2,
                bytes: 2048,
            },
            2048,
            1,
        ),
        (
            20,
            TimestampNs(200),
            LifecycleEvent::VerifyChild {
                child_digest: c1,
                verified_bytes: 4096,
            },
            0,
            1,
        ),
        (
            20,
            TimestampNs(210),
            LifecycleEvent::VerifyChild {
                child_digest: c2,
                verified_bytes: 2048,
            },
            0,
            1,
        ),
        (20, TimestampNs(220), LifecycleEvent::MarkStaged, 0, 1),
        (
            20,
            TimestampNs(230),
            LifecycleEvent::MarkChildrenVerified,
            0,
            1,
        ),
        (20, TimestampNs(240), LifecycleEvent::CloseGraph, 0, 1),
        (
            20,
            TimestampNs(250),
            LifecycleEvent::SatisfyDurability {
                failure_domains: vec!["fd-a".to_owned(), "fd-b".to_owned()],
            },
            0,
            1,
        ),
        (
            20,
            TimestampNs(260),
            LifecycleEvent::MarkExposureReady { policy_epoch: 5 },
            0,
            1,
        ),
    ];
    for (fence, ts, ev, wb, wo) in stage2 {
        reference.apply_event(fence, ts, ev.clone(), wb, wo)?;
        coord.apply_event(fence, ts, ev, wb, wo)?;
    }
    for (idx, child) in [c1, c2].into_iter().enumerate() {
        for (j, st) in [
            ArchiveObjectState::LocalDurable,
            ArchiveObjectState::RemoteStaged,
            ArchiveObjectState::RemoteChildrenVerified,
        ]
        .into_iter()
        .enumerate()
        {
            let ts = TimestampNs(270 + (idx * 3 + j) as i128 * 10);
            let ev = LifecycleEvent::AdvanceChildArchiveState {
                child_digest: child,
                to: st,
            };
            reference.apply_event(20, ts, ev.clone(), 0, 1)?;
            coord.apply_event(20, ts, ev, 0, 1)?;
        }
    }

    // Cold checkpoint 2 on disk -> reload into fresh coordinator.
    coord.journal().write_framed_file(&journal_path)?;
    coord = AtpLifecycleCoordinator::resume_from_journal_file(
        spec.clone(),
        auth.clone(),
        &journal_path,
    )?;
    assert_eq!(coord, reference);

    let por = ProofOfRetrievability {
        sample_id: "por-126-01".to_owned(),
        root_digest: spec.manifest_root,
        replica_generation: 1,
        failure_domain: "fd-b".to_owned(),
        observed_digest: spec.manifest_root,
        sampled_bytes: 6144,
        sampled_at: TimestampNs(400),
    };
    let stage3 = vec![
        (
            20,
            TimestampNs(350),
            LifecycleEvent::AdvanceFence { new_fence: 21 },
            0,
            1,
        ),
        (
            21,
            TimestampNs(360),
            LifecycleEvent::CommitRoot {
                root_digest: spec.manifest_root,
                commit_anchor: d("fss126-commit-anchor"),
            },
            0,
            1,
        ),
        (
            21,
            TimestampNs(370),
            LifecycleEvent::PublishArchiveRoot {
                root_digest: spec.manifest_root,
                provider_tuple: "s3://owner-archive/fss126/gen-1".to_owned(),
            },
            0,
            1,
        ),
        (
            21,
            TimestampNs(380),
            LifecycleEvent::QualifyReplicas {
                failure_domains: vec!["fd-a".to_owned(), "fd-b".to_owned()],
            },
            0,
            1,
        ),
        (
            21,
            TimestampNs(410),
            LifecycleEvent::VerifyRetrievability { proof: por },
            0,
            1,
        ),
        (21, TimestampNs(420), LifecycleEvent::CompleteArchive, 0, 1),
    ];
    for (fence, ts, ev, wb, wo) in stage3 {
        reference.apply_event(fence, ts, ev.clone(), wb, wo)?;
        coord.apply_event(fence, ts, ev, wb, wo)?;
    }
    let pre_digest = coord.build_receipt(true)?.receipt_digest;
    reference.apply_event(
        21,
        TimestampNs(430),
        LifecycleEvent::SealReceipt {
            receipt_digest: pre_digest,
        },
        0,
        1,
    )?;
    coord.apply_event(
        21,
        TimestampNs(430),
        LifecycleEvent::SealReceipt {
            receipt_digest: pre_digest,
        },
        0,
        1,
    )?;

    // Cold checkpoint 3 on disk -> reload and assert bit-identical receipt + schema compliance.
    coord.journal().write_framed_file(&journal_path)?;
    let reloaded = AtpLifecycleCoordinator::resume_from_journal_file(spec, auth, &journal_path)?;
    assert_eq!(reloaded, reference);
    assert_eq!(
        reloaded.build_receipt(true)?.receipt_digest,
        reference.build_receipt(true)?.receipt_digest
    );

    let receipt_json = reloaded.to_transfer_receipt_v1_json(true, None)?;
    assert_conforms_to_transfer_receipt_v1(&receipt_json)?;
    if let Ok(out_dir) = std::env::var("FSS_126_EMIT_RECEIPT_DIR") {
        fs::write(
            PathBuf::from(out_dir).join("archive_complete.json"),
            &receipt_json,
        )?;
    }
    assert!(receipt_json.contains("\"state\":\"complete\""));
    assert!(receipt_json.contains("\"semanticState\":\"atp.semantic.receipt_sealed\""));
    assert!(receipt_json.contains("\"archiveState\":\"atp.archive.complete\""));
    assert!(receipt_json.contains("\"verification\":{\"manifest\":true,\"objects\":true,\"closure\":true,\"root\":true,\"retrievability\":true}"));
    assert!(receipt_json.contains("\"timestamps\":{\"firstEventNs\":100,\"lastEventNs\":430}"));
    assert!(receipt_json.contains("\"providerTuple\":\"s3://owner-archive/fss126/gen-1\""));

    emit_caplog(
        "fss126_multi_restart_journal_and_receipt_v1",
        "bit_identical_after_3_restarts_and_schema_valid",
        "bit_identical_after_3_restarts_and_schema_valid",
        "pass",
    );
    Ok(())
}

#[test]
fn semantic_only_and_indeterminate_receipts_conform_and_disk_faults_fail_closed() -> TestResult {
    let dir = TempDir::new()?;

    // 1. Semantic-only (archive_enabled = false) sealed receipt conforms with archiveState omitted
    //    and verification.retrievability == null.
    let sem_spec = spec_for(false);
    let sem_auth = auth_for(&sem_spec);
    let mut sem = AtpLifecycleCoordinator::new(sem_spec.clone(), sem_auth)?;
    sem.apply_event(
        20,
        TimestampNs(10),
        LifecycleEvent::Reserve {
            reserved_bytes: 8192,
            reserved_ops: 32,
        },
        0,
        1,
    )?;
    sem.apply_event(
        20,
        TimestampNs(20),
        LifecycleEvent::OfferGraph {
            offered_bytes: 6144,
            offered_objects: 2,
        },
        0,
        1,
    )?;
    sem.apply_event(20, TimestampNs(30), LifecycleEvent::BeginReceiving, 0, 1)?;
    sem.apply_event(
        20,
        TimestampNs(40),
        LifecycleEvent::PathDiscover {
            path_id: "lan-1".to_owned(),
            failure_domain: "fd-1".to_owned(),
        },
        0,
        1,
    )?;
    for (i, to) in [PathState::Candidate, PathState::Probing, PathState::Active]
        .into_iter()
        .enumerate()
    {
        sem.apply_event(
            20,
            TimestampNs(50 + i as i128 * 10),
            LifecycleEvent::PathTransition {
                path_id: "lan-1".to_owned(),
                to,
                reason: "up".to_owned(),
            },
            0,
            1,
        )?;
    }
    let mut ts = 90_i128;
    for (digest, bytes) in sem_spec.expected_children.clone() {
        ts += 10;
        sem.apply_event(
            20,
            TimestampNs(ts),
            LifecycleEvent::DeliverChild {
                path_id: "lan-1".to_owned(),
                child_digest: digest,
                bytes,
                reused_existing: false,
            },
            bytes,
            1,
        )?;
        ts += 10;
        sem.apply_event(
            20,
            TimestampNs(ts),
            LifecycleEvent::VerifyChild {
                child_digest: digest,
                verified_bytes: bytes,
            },
            0,
            1,
        )?;
    }
    sem.apply_event(
        20,
        TimestampNs(ts + 10),
        LifecycleEvent::MarkChildrenVerified,
        0,
        1,
    )?;
    sem.apply_event(20, TimestampNs(ts + 20), LifecycleEvent::CloseGraph, 0, 1)?;
    sem.apply_event(
        20,
        TimestampNs(ts + 30),
        LifecycleEvent::SatisfyDurability {
            failure_domains: vec!["fd-1".to_owned(), "fd-2".to_owned()],
        },
        0,
        1,
    )?;
    sem.apply_event(
        20,
        TimestampNs(ts + 40),
        LifecycleEvent::CommitRoot {
            root_digest: sem_spec.manifest_root,
            commit_anchor: d("sem-commit"),
        },
        0,
        1,
    )?;
    let sem_digest = sem.build_receipt(true)?.receipt_digest;
    sem.apply_event(
        20,
        TimestampNs(ts + 50),
        LifecycleEvent::SealReceipt {
            receipt_digest: sem_digest,
        },
        0,
        1,
    )?;
    let sem_json = sem.to_transfer_receipt_v1_json(true, None)?;
    assert_conforms_to_transfer_receipt_v1(&sem_json)?;
    if let Ok(out_dir) = std::env::var("FSS_126_EMIT_RECEIPT_DIR") {
        fs::write(
            PathBuf::from(&out_dir).join("semantic_complete.json"),
            &sem_json,
        )?;
    }
    assert!(sem_json.contains("\"state\":\"complete\""));
    assert!(!sem_json.contains("\"archiveState\""));
    assert!(!sem_json.contains("\"providerTuple\""));
    assert!(sem_json.contains("\"retrievability\":null"));

    // 2. Indeterminate terminal receipt preserves durable obligation and schema compliance.
    let ind_spec = spec_for(false);
    let ind_auth = auth_for(&ind_spec);
    let mut ind = AtpLifecycleCoordinator::new(ind_spec.clone(), ind_auth)?;
    ind.apply_event(
        20,
        TimestampNs(10),
        LifecycleEvent::Reserve {
            reserved_bytes: 8192,
            reserved_ops: 32,
        },
        0,
        1,
    )?;
    ind.apply_event(
        20,
        TimestampNs(20),
        LifecycleEvent::OfferGraph {
            offered_bytes: 6144,
            offered_objects: 2,
        },
        0,
        1,
    )?;
    ind.apply_event(20, TimestampNs(30), LifecycleEvent::BeginReceiving, 0, 1)?;
    ind.apply_event(
        20,
        TimestampNs(40),
        LifecycleEvent::PathDiscover {
            path_id: "lan-1".to_owned(),
            failure_domain: "fd-1".to_owned(),
        },
        0,
        1,
    )?;
    for (i, to) in [PathState::Candidate, PathState::Probing, PathState::Active]
        .into_iter()
        .enumerate()
    {
        ind.apply_event(
            20,
            TimestampNs(50 + i as i128 * 10),
            LifecycleEvent::PathTransition {
                path_id: "lan-1".to_owned(),
                to,
                reason: "up".to_owned(),
            },
            0,
            1,
        )?;
    }
    let mut t2 = 90_i128;
    for (digest, bytes) in ind_spec.expected_children.clone() {
        t2 += 10;
        ind.apply_event(
            20,
            TimestampNs(t2),
            LifecycleEvent::DeliverChild {
                path_id: "lan-1".to_owned(),
                child_digest: digest,
                bytes,
                reused_existing: false,
            },
            bytes,
            1,
        )?;
        t2 += 10;
        ind.apply_event(
            20,
            TimestampNs(t2),
            LifecycleEvent::VerifyChild {
                child_digest: digest,
                verified_bytes: bytes,
            },
            0,
            1,
        )?;
    }
    ind.apply_event(
        20,
        TimestampNs(t2 + 10),
        LifecycleEvent::MarkChildrenVerified,
        0,
        1,
    )?;
    ind.apply_event(20, TimestampNs(t2 + 20), LifecycleEvent::CloseGraph, 0, 1)?;
    ind.apply_event(
        20,
        TimestampNs(t2 + 30),
        LifecycleEvent::SatisfyDurability {
            failure_domains: vec!["fd-1".to_owned(), "fd-2".to_owned()],
        },
        0,
        1,
    )?;
    ind.apply_event(
        20,
        TimestampNs(t2 + 40),
        LifecycleEvent::MarkIndeterminate {
            obligation: IndeterminateTransferObligation {
                obligation_id: "obl:fss126-reconcile".to_owned(),
                transfer_id: ind_spec.transfer_id(),
                fence: 20,
                reason: "commit_ack_timeout".to_owned(),
                follow_up_digest: d("reconcile-126"),
                created_at: TimestampNs(t2 + 40),
            },
            archive_state_affected: false,
        },
        0,
        1,
    )?;
    let ind_json = ind.to_transfer_receipt_v1_json(false, Some("ERR-ATP-INDETERMINATE-001"))?;
    assert_conforms_to_transfer_receipt_v1(&ind_json)?;
    if let Ok(out_dir) = std::env::var("FSS_126_EMIT_RECEIPT_DIR") {
        fs::write(PathBuf::from(out_dir).join("indeterminate.json"), &ind_json)?;
    }
    assert!(ind_json.contains("\"state\":\"indeterminate\""));
    assert!(ind_json.contains("\"obligationId\":\"obl:fss126-reconcile\""));
    assert!(ind_json.contains("\"errorId\":\"ERR-ATP-INDETERMINATE-001\""));

    // Oversize error_id (> 128 bytes) rejected before emitting non-conforming receipt JSON.
    let too_long_err = "E".repeat(129);
    assert!(matches!(
        ind.to_transfer_receipt_v1_json(false, Some(&too_long_err)),
        Err(AtpLifecycleError::InvalidInput(_))
    ));
    let mut path_check = AtpLifecycleCoordinator::new(spec_for(false), auth_for(&spec_for(false)))?;
    assert!(matches!(
        path_check.apply_event(
            20,
            TimestampNs(5),
            LifecycleEvent::PathDiscover {
                path_id: "p".repeat(129),
                failure_domain: "fd-1".to_owned(),
            },
            0,
            1,
        ),
        Err(AtpLifecycleError::InvalidInput(_))
    ));

    // 3. On-disk symlink, truncation, checksum bit-flip, and wrong transfer_id all fail closed.
    let valid_path = dir.0.join("valid.journal");
    sem.journal().write_framed_file(&valid_path)?;

    #[cfg(unix)]
    {
        let sym_path = dir.0.join("symlink.journal");
        std::os::unix::fs::symlink(&valid_path, &sym_path)?;
        assert!(matches!(
            sem.journal().write_framed_file(&sym_path),
            Err(AtpLifecycleError::InvalidInput(_))
        ));
        assert!(matches!(
            TransferJournal::read_framed_file(sem_spec.transfer_id(), &sym_path, 256),
            Err(AtpLifecycleError::JournalCorrupt { .. })
        ));
    }

    let raw = fs::read(&valid_path)?;
    let trunc_path = dir.0.join("truncated.journal");
    fs::write(&trunc_path, &raw[..raw.len() - 5])?;
    assert!(matches!(
        TransferJournal::read_framed_file(sem_spec.transfer_id(), &trunc_path, 256),
        Err(AtpLifecycleError::JournalCorrupt { .. })
    ));

    let mut corrupt = raw;
    let mid = corrupt.len() / 2;
    corrupt[mid] ^= 0xAA;
    let corrupt_path = dir.0.join("corrupt.journal");
    fs::write(&corrupt_path, &corrupt)?;
    assert!(matches!(
        TransferJournal::read_framed_file(sem_spec.transfer_id(), &corrupt_path, 256),
        Err(AtpLifecycleError::JournalCorrupt { .. }
            | AtpLifecycleError::IncompatibleVersion { .. })
    ));

    let mut other_spec = sem_spec;
    other_spec.session_nonce = 777;
    assert!(matches!(
        TransferJournal::read_framed_file(other_spec.transfer_id(), &valid_path, 256),
        Err(AtpLifecycleError::JournalCorrupt { .. })
    ));

    emit_caplog(
        "fss126_semantic_indeterminate_and_disk_faults",
        "all_receipts_conform_and_disk_faults_refused",
        "all_receipts_conform_and_disk_faults_refused",
        "pass",
    );
    Ok(())
}
