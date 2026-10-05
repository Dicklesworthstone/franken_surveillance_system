#![forbid(unsafe_code)]
#![allow(dead_code)]
//! Shared harness of the file-import fault campaign (fss-2h5zq.24) and the ingest gauntlet
//! (fss-2h5zq.31): deterministic contexts and deployments, the import state as the ledger and
//! the publisher show it, and the two admitted post-fault outcomes.
//!
//! Outcome vocabulary (fss-2h5zq.23 round 3, "Commits"; `file_adapter.rs` steps 14-16):
//! - `Untouched`: zero committed batches of the import identity and no visible import root.
//!   Staged objects may remain; they are unreferenced, never visible.
//! - `Incomplete`: capsule batches `c0..c<j>` committed as a gap-free prefix, the import object at
//!   generation 1, and no manifest batch. `RetainedFileImport::open` refuses it, doctor lists it
//!   under `imports.incomplete`, and a re-import completes it exactly once.
//! - `Complete`: the manifest batch exists and the import slot root is ledgered.
//!
//! No-Claim: every fault here is in-process injection, not process death or power loss.

use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, DigestAlgorithm, OperationId, RootAuthoritySpec,
    SensorId, StreamId, TimestampNs,
};
use fss_reference::ingest::recorded_decode::retained_source_capsule;
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits};
use fss_reference::{
    ADP_FILE_GENERATION, ADP_FILE_ROW_ID, ADP_REPLAY_ROW_ID, DeploymentLimits, DoctorValue,
    FileImportManifest, FileIngestLimits, FileIngestOutcome, FileIngestReceipt, FileIngestRequest,
    ReferenceDeployment, ReplayCx, ReplayIoAuthority, compute_import_identity, fetch_segment_bytes,
    inspect_deployment, sniff_format,
};

pub type Error = Box<dyn StdError>;
pub type TestResult = Result<(), Error>;

/// Site lineage of every campaign deployment.
pub const SITE: &str = "site:file-import-faults";
/// Receive time of every campaign import.
pub const RECEIVE_NS: i128 = 2_000_000_000;

/// Repository root.
pub fn repo_root() -> Result<PathBuf, Error> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(PathBuf::from)
        .ok_or_else(|| "cannot find repo root".into())
}

/// Path of a checked-in media fixture under `tests/fixtures/media`.
pub fn fixture(relative: &str) -> Result<PathBuf, Error> {
    Ok(repo_root()?.join("tests/fixtures/media").join(relative))
}

fn scratch_base() -> PathBuf {
    std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
}

/// A fresh replay context. A cancelled context is finalized, so every phase takes a new one.
pub fn cx(label: &str) -> Result<ReplayCx, Error> {
    let spec = RootAuthoritySpec {
        trace_id: format!("trace:file-import-faults-{label}"),
        operation_id: OperationId::parse(format!("operation:file-import-faults-{label}"))?,
        principal: format!("operator:file-import-faults-{label}"),
        capabilities: vec![ADP_FILE_ROW_ID.to_string(), ADP_REPLAY_ROW_ID.to_string()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".to_string(),
        retention_scope: "retention:ephemeral".to_string(),
        anchor_universe: ContentDigest::sha256(b"file-import-faults"),
        generation: 1,
    };
    let auth = ContextAuthority::new_root(spec)?;
    let scratch = scratch_base().join(format!("fif-cx-{}", std::process::id()));
    fs::create_dir_all(&scratch)?;
    let io = ReplayIoAuthority::from_context_authority(&auth, scratch)?;
    Ok(ReplayCx::new(io))
}

/// A fresh, empty directory unique to `label` and this process.
pub fn fresh_dir(label: &str) -> Result<PathBuf, Error> {
    let dir = scratch_base().join(format!("fif-{label}-{}", std::process::id()));
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Opens (or reopens) the deployment at `dir` with `limits`.
pub fn open(dir: &Path, limits: DeploymentLimits) -> Result<ReferenceDeployment, Error> {
    Ok(ReferenceDeployment::open_with_limits(
        dir,
        SITE,
        limits,
        &cx("open")?,
    )?)
}

/// Import request with the campaign's sensor, stream, receive time, chunk size and batch knob.
pub fn request(
    path: &Path,
    chunk_bytes: u64,
    max_batch_deltas: usize,
) -> Result<FileIngestRequest, Error> {
    let limits = FileIngestLimits {
        chunk_bytes,
        max_batch_deltas,
        ..FileIngestLimits::standard()
    };
    Ok(FileIngestRequest::new(
        path.to_path_buf(),
        SensorId::parse("sensor:fault-cam")?,
        StreamId::parse("stream:fault-main")?,
    )
    .with_limits(limits)
    .with_receive_time(TimestampNs(RECEIVE_NS)))
}

/// Import identity hex of `request`, computed from the file bytes exactly as the adapter does.
/// `None` when the bytes have no recognizable format (the import is then refused before any
/// identity exists).
pub fn identity_hex(request: &FileIngestRequest) -> Result<Option<String>, Error> {
    let bytes = fs::read(&request.path)?;
    let format = match fss_reference::ingest::sniff_format_with_hint(&bytes, request.format_hint) {
        Ok((format, _)) => format,
        Err(_) => match sniff_format(&bytes) {
            Ok((format, _)) => format,
            Err(_) => return Ok(None),
        },
    };
    let identity = compute_import_identity(
        ContentDigest::sha256(&bytes),
        format,
        request.limits.canonical_digest(),
        ADP_FILE_GENERATION,
        &request.sensor_id,
        &request.stream_id,
    );
    Ok(Some(hex(identity)))
}

/// Lowercase hex of a digest.
pub fn hex(digest: ContentDigest) -> String {
    digest.bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// The import as the canonical ledger and the local publisher show it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportView {
    /// Committed capsule batch suffixes (`c0`, `c1`, ...) in ledger order.
    pub capsule_batches: Vec<String>,
    /// Whether the final manifest batch is committed.
    pub manifest_batch: bool,
    /// Highest committed generation of `object:file-import:<id>`.
    pub import_generation: Option<u64>,
    /// Whether the import slot `fi-<id>` has a visible root.
    pub root_visible: bool,
    /// Whether the ledger names the import slot root (`batch:local-root:fi-<id>`).
    pub root_ledgered: bool,
}

/// Classification of an [`ImportView`] against the admitted outcomes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// (a) zero committed import batches and no visible import root.
    Untouched,
    /// (b) a recognizably incomplete import (`k` capsule batches, no manifest batch).
    Incomplete(usize),
    /// The import completed (only a fault after the manifest commit point produces it).
    Complete,
}

/// Observes the import `hex` in `deployment`.
pub fn view(deployment: &ReferenceDeployment, hex: &str) -> ImportView {
    let prefix = format!("batch:file-import:{hex}:");
    let object = format!("object:file-import:{hex}");
    let local_root = format!("batch:local-root:fi-{hex}");
    let mut capsule_batches = Vec::new();
    let mut manifest_batch = false;
    let mut import_generation = None;
    let mut root_ledgered = false;
    for batch in deployment.ledger().batches() {
        let id = batch.batch_id.as_str();
        if let Some(part) = id.strip_prefix(&prefix) {
            if part == "manifest" {
                manifest_batch = true;
            } else {
                capsule_batches.push(part.to_owned());
            }
        }
        if id == local_root {
            root_ledgered = true;
        }
        for delta in &batch.deltas {
            if delta.object_id.as_str() == object {
                import_generation = import_generation.max(Some(delta.new_generation));
            }
        }
    }
    let root_visible = fss_publication::SlotName::parse(&format!("fi-{hex}"))
        .ok()
        .is_some_and(|slot| deployment.publisher().root(&slot).is_some());
    ImportView {
        capsule_batches,
        manifest_batch,
        import_generation,
        root_visible,
        root_ledgered,
    }
}

/// Classifies `hex` as exactly one admitted outcome, or reports why it is neither.
///
/// `Untouched` requires no batch, no generation and no visible root. `Incomplete` requires a
/// gap-free capsule prefix `c0..c<k-1>`, generation 1, no manifest batch, and a refused
/// `RetainedFileImport::open`. `Complete` requires the manifest batch, generation 2, and a
/// visible ledgered root.
pub fn classify(
    deployment: &ReferenceDeployment,
    hex: &str,
    cx: &ReplayCx,
) -> Result<Outcome, Error> {
    let v = view(deployment, hex);
    if v.capsule_batches.is_empty()
        && !v.manifest_batch
        && v.import_generation.is_none()
        && !v.root_visible
    {
        if v.root_ledgered {
            return Err(format!("untouched import {hex} has a ledgered root: {v:?}").into());
        }
        return Ok(Outcome::Untouched);
    }
    let expected_prefix: Vec<String> = (0..v.capsule_batches.len())
        .map(|k| format!("c{k}"))
        .collect();
    if v.capsule_batches != expected_prefix {
        return Err(format!("capsule batches are not a gap-free unique prefix: {v:?}").into());
    }
    if v.manifest_batch {
        if v.import_generation != Some(2) || !v.root_visible || !v.root_ledgered {
            return Err(format!("manifest batch without a complete import: {v:?}").into());
        }
        return Ok(Outcome::Complete);
    }
    if v.import_generation != Some(1) {
        return Err(format!("incomplete import must be at generation 1: {v:?}").into());
    }
    // No reader may treat an incomplete import as retained evidence.
    if RetainedFileImport::open(
        deployment,
        digest_from_hex(hex)?,
        RetainedReadLimits::default(),
        cx,
    )
    .is_ok()
    {
        return Err(format!("incomplete import {hex} opened as retained").into());
    }
    Ok(Outcome::Incomplete(v.capsule_batches.len()))
}

/// Parses a 64-character lowercase hex digest.
pub fn digest_from_hex(hex: &str) -> Result<ContentDigest, Error> {
    let mut bytes = [0u8; 32];
    if hex.len() != 64 {
        return Err("identity hex must be 64 characters".into());
    }
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)?;
    }
    Ok(ContentDigest::new(DigestAlgorithm::Sha256, bytes))
}

/// Doctor's `imports.incomplete` list for the deployment at `dir` (the deployment must be
/// closed so the read-only inspection observes no writer).
pub fn doctor_incomplete(dir: &Path) -> Result<Vec<String>, Error> {
    let report = inspect_deployment(dir);
    let check = report
        .check("imports.incomplete")
        .ok_or("doctor report has no imports.incomplete check")?;
    match check.fields.get("incomplete_imports") {
        None => Ok(Vec::new()),
        Some(DoctorValue::StringList(list)) => Ok(list.clone()),
        Some(other) => Err(format!("unexpected incomplete_imports field {other:?}").into()),
    }
}

/// Asserts the exactly-once invariants of a completed import:
/// - the receipt names the planned batches `c0..c<k-1>` and `manifest`, each committed exactly
///   once in the ledger, and no other batch of this identity exists;
/// - no batch identifier and no delta identifier appears twice anywhere in the ledger;
/// - exactly one `sensor_capsule` delta per capsule, and one init plus one completion delta;
/// - every segment reassembles from custody to the exact source slice;
/// - `RetainedFileImport::open` admits the import and every retained capsule verifies against
///   its custody span (the `c<k>` lookup of `recorded_decode`).
pub fn assert_complete_once(
    deployment: &ReferenceDeployment,
    receipt: &FileIngestReceipt,
    source: &[u8],
    cx: &ReplayCx,
) -> TestResult {
    let hex = hex(receipt.import_identity);
    let prefix = format!("batch:file-import:{hex}:");
    let ledger_ids: Vec<&str> = deployment
        .ledger()
        .batches()
        .iter()
        .map(|b| b.batch_id.as_str())
        .collect();
    let unique: BTreeSet<&str> = ledger_ids.iter().copied().collect();
    if unique.len() != ledger_ids.len() {
        return Err("a batch identifier is committed twice".into());
    }
    let mut delta_ids = BTreeSet::new();
    for batch in deployment.ledger().batches() {
        for delta in &batch.deltas {
            if !delta_ids.insert(delta.delta_id.clone()) {
                return Err(format!("delta {} is committed twice", delta.delta_id).into());
            }
        }
    }
    let import_ids: Vec<&str> = ledger_ids
        .iter()
        .copied()
        .filter(|id| id.starts_with(&prefix))
        .collect();
    let receipt_ids: Vec<&str> = receipt.batch_ids.iter().map(|b| b.as_str()).collect();
    if import_ids != receipt_ids {
        return Err(
            format!("ledger batches {import_ids:?} != receipt batches {receipt_ids:?}").into(),
        );
    }
    let capsule_count = receipt.batch_ids.len() - 1;
    for (k, id) in receipt.batch_ids.iter().enumerate() {
        let expected = if k == capsule_count {
            format!("{prefix}manifest")
        } else {
            format!("{prefix}c{k}")
        };
        if id.as_str() != expected {
            return Err(format!("batch {k} is {id:?}, expected {expected}").into());
        }
    }
    let capsule_deltas = deployment
        .ledger()
        .batches()
        .iter()
        .filter(|b| b.batch_id.as_str().starts_with(&prefix))
        .flat_map(|b| &b.deltas)
        .filter(|d| d.family == "sensor_capsule")
        .count();
    if capsule_deltas != receipt.capsule_count {
        return Err(format!(
            "{capsule_deltas} capsule deltas for {} capsules",
            receipt.capsule_count
        )
        .into());
    }
    if view(deployment, &hex).import_generation != Some(2) {
        return Err("complete import must be at generation 2".into());
    }
    let retained = RetainedFileImport::open(
        deployment,
        receipt.import_identity,
        RetainedReadLimits::default(),
        cx,
    )?;
    if retained.import_root() != receipt.import_root {
        return Err("retained root differs from the receipt".into());
    }
    assert_spans_match(&receipt.manifest, deployment, source)?;
    if receipt.manifest.segment_spans.len() != receipt.capsule_count {
        return Err("one segment span per capsule".into());
    }
    for (index, span) in receipt.manifest.segment_spans.iter().enumerate() {
        let capsule = retained_source_capsule(deployment, &retained, index)?;
        if capsule.capsule_id != span.capsule_id {
            return Err(format!("retained capsule {index} has the wrong identity").into());
        }
    }
    Ok(())
}

/// Every segment reassembles from custody to exactly its source slice and digest.
pub fn assert_spans_match(
    manifest: &FileImportManifest,
    deployment: &ReferenceDeployment,
    source: &[u8],
) -> TestResult {
    for (index, span) in manifest.segment_spans.iter().enumerate() {
        let fetched = fetch_segment_bytes(manifest, deployment, index)?;
        let start = usize::try_from(span.offset)?;
        let end = start + usize::try_from(span.len)?;
        if source.get(start..end) != Some(fetched.as_slice())
            || ContentDigest::sha256(&fetched) != span.segment_sha256
        {
            return Err(format!("segment {index} does not match its source span").into());
        }
    }
    Ok(())
}

/// After a completed import is reopened: the slot is ledgered, reconcile is clean, nothing is
/// unreferenced, no temporary root record is left, and doctor lists no incomplete import.
pub fn assert_clean_after_reopen(dir: &Path, limits: DeploymentLimits) -> TestResult {
    {
        let mut deployment = open(dir, limits)?;
        let report = deployment.recovery_report().clone();
        if !report.unreferenced_objects.is_empty() {
            return Err(format!(
                "{} unreferenced objects after completion",
                report.unreferenced_objects.len()
            )
            .into());
        }
        if !report.orphaned_temps.is_empty() || !report.broken_roots.is_empty() {
            return Err(format!("unclean publication after completion: {report:?}").into());
        }
        if !deployment.reconcile()?.is_clean() {
            return Err("reconcile is not clean after completion".into());
        }
    }
    let incomplete = doctor_incomplete(dir)?;
    if !incomplete.is_empty() {
        return Err(format!("doctor still lists incomplete imports {incomplete:?}").into());
    }
    Ok(())
}

/// The outcome a successful re-import must report after a fault that left `outcome`.
pub fn expected_reimport(outcome: Outcome) -> FileIngestOutcome {
    match outcome {
        Outcome::Untouched => FileIngestOutcome::New,
        Outcome::Incomplete(_) => FileIngestOutcome::Resumed,
        Outcome::Complete => FileIngestOutcome::IdempotentExisting,
    }
}

/// Standard deployment limits.
pub fn standard() -> DeploymentLimits {
    DeploymentLimits::standard()
}
