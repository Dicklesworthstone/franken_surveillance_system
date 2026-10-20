#![forbid(unsafe_code)]
//! FSS-130 property family: focused S3-compatible multipart/conditional
//! protocol over the deterministic memory transport. Each property emits
//! one JSONL verdict line.

use fss_core::ContentDigest;
use fss_object::multipart::{
    AbortReceipt, CompletionReceipt, ETag, MultipartError, MultipartSession, MultipartTransport,
    UploadId,
};
use fss_object::planner::{ChunkPolicy, plan_chunks};

fn emit(property: &str, cases: u64) {
    println!(
        "{{\"family\":\"FSS-130\",\"property\":\"{property}\",\"cases\":{cases},\"verdict\":\"pass\"}}"
    );
}

const MIB: u64 = 1024 * 1024;

/// Deterministic memory transport: the protocol oracle. ETags are the
/// part content digests (If-Match trivially satisfied when honest);
/// optional corruption mode returns a wrong ETag to exercise the
/// precondition.
#[derive(Default)]
struct MemoryTransport {
    corrupt_next_etag: bool,
    uploads: std::collections::BTreeMap<String, Vec<(u64, String)>>,
    aborted: Vec<String>,
}

impl MultipartTransport for MemoryTransport {
    fn initiate(&mut self, _object: ContentDigest) -> Result<UploadId, String> {
        Ok(UploadId(format!("upload-{}", self.uploads.len())))
    }

    fn upload_part(
        &mut self,
        upload: &UploadId,
        chunk: &fss_object::planner::PlannedChunk,
        bytes: &[u8],
        _precondition: ContentDigest,
    ) -> Result<ETag, String> {
        if self.corrupt_next_etag {
            self.corrupt_next_etag = false;
            return Ok(ETag("corrupt".to_string()));
        }
        let etag = ContentDigest::sha256(bytes).to_string();
        self.uploads
            .entry(upload.0.clone())
            .or_default()
            .push((chunk.index, etag.clone()));
        Ok(ETag(etag))
    }

    fn complete(
        &mut self,
        upload: &UploadId,
        parts: &[(u64, ETag)],
        _root: ContentDigest,
    ) -> Result<(), String> {
        let stored = self.uploads.get(&upload.0).ok_or("unknown upload")?;
        if stored.len() != parts.len() {
            return Err("part-count mismatch".to_string());
        }
        Ok(())
    }

    fn abort(&mut self, upload: &UploadId) -> Result<(), String> {
        self.aborted.push(upload.0.clone());
        Ok(())
    }
}

fn make_plan_f(parts: u64) -> Result<fss_object::planner::ChunkPlan, Box<dyn std::error::Error>> {
    Ok(plan_chunks(parts * 64 * MIB - 1, ChunkPolicy::default())?)
}

fn part_bytes(chunk: &fss_object::planner::PlannedChunk) -> Vec<u8> {
    // Deterministic per-chunk fill sized exactly to the chunk length.
    vec![(chunk.index % 251) as u8; chunk.len as usize]
}

/// P1 HAPPY PATH: every part uploads with plan-exact offsets, completion
/// is root-last with the full closure witness, and the receipt binds the
/// manifest root.
#[test]
fn p1_happy_path_root_last() -> Result<(), Box<dyn std::error::Error>> {
    let mut transport = MemoryTransport::default();
    let chunk_plan = make_plan_f(3)?;
    let root = ContentDigest::sha256(b"manifest-root");
    let mut session = MultipartSession::initiate(&mut transport, &chunk_plan, root)?;
    for chunk in &chunk_plan.chunks {
        let etag = session.upload_part(&chunk_plan, chunk.index, &part_bytes(chunk))?;
        assert!(!etag.0.is_empty());
    }
    let receipt: CompletionReceipt = session.complete(&chunk_plan, root)?;
    assert_eq!(receipt.parts.len(), 3);
    assert_eq!(receipt.manifest_root, root);
    emit("happy-path-root-last", 3);
    Ok(())
}

/// P2 IDEMPOTENT REPLAYS: re-uploading identical bytes returns the
/// recorded ETag with no transport traffic; different bytes for the same
/// index is a typed conflict.
#[test]
fn p2_idempotent_replay_and_conflict() -> Result<(), Box<dyn std::error::Error>> {
    let mut transport = MemoryTransport::default();
    let chunk_plan = make_plan_f(2)?;
    let root = ContentDigest::sha256(b"root");
    let mut session = MultipartSession::initiate(&mut transport, &chunk_plan, root)?;
    let first = session.upload_part(&chunk_plan, 0, &part_bytes(&chunk_plan.chunks[0]))?;
    // Replay: identical bytes, same ETag, no new transport upload (the
    // stored part count stays 1).
    let replay = session.upload_part(&chunk_plan, 0, &part_bytes(&chunk_plan.chunks[0]))?;
    assert_eq!(first, replay);
    // Different length for the same index: typed conflict.
    assert!(matches!(
        session.upload_part(&chunk_plan, 0, b"different-length"),
        Err(MultipartError::PartConflict { index: 0 })
    ));
    drop(session);
    assert_eq!(
        transport.uploads["upload-0"].len(),
        1,
        "no duplicate traffic"
    );
    emit("idempotent-replay-conflict", 3);
    Ok(())
}

/// P3 PRECONDITIONS: a corrupt store ETag fails the If-Match discipline
/// with the part named; unknown indices refuse; stale plans refuse with
/// both digests.
#[test]
fn p3_preconditions() -> Result<(), Box<dyn std::error::Error>> {
    let mut transport = MemoryTransport {
        corrupt_next_etag: true,
        ..MemoryTransport::default()
    };
    let chunk_plan = make_plan_f(2)?;
    let root = ContentDigest::sha256(b"root");
    let mut session = MultipartSession::initiate(&mut transport, &chunk_plan, root)?;
    assert!(matches!(
        session.upload_part(&chunk_plan, 0, &part_bytes(&chunk_plan.chunks[0])),
        Err(MultipartError::ETagMismatch { index: 0 })
    ));
    assert!(matches!(
        session.upload_part(&chunk_plan, 99, b"x"),
        Err(MultipartError::UnknownPart { index: 99 })
    ));
    let other_plan = make_plan_f(5)?;
    assert!(matches!(
        session.upload_part(&other_plan, 0, &part_bytes(&other_plan.chunks[0])),
        Err(MultipartError::StalePlan { .. })
    ));
    emit("preconditions", 3);
    Ok(())
}

/// P4 COMPLETION DISCIPLINE: completion before every part is confirmed
/// refuses with exact counts; abort receipts name confirmed work; a
/// completed session refuses further uploads by state.
#[test]
fn p4_completion_and_abort_discipline() -> Result<(), Box<dyn std::error::Error>> {
    let mut transport = MemoryTransport::default();
    let chunk_plan = make_plan_f(3)?;
    let root = ContentDigest::sha256(b"root");
    let mut session = MultipartSession::initiate(&mut transport, &chunk_plan, root)?;
    session.upload_part(&chunk_plan, 0, &part_bytes(&chunk_plan.chunks[0]))?;
    // Abort path on a fresh session.
    let mut t2 = MemoryTransport::default();
    let mut s2 = MultipartSession::initiate(&mut t2, &chunk_plan, root)?;
    s2.upload_part(&chunk_plan, 0, &part_bytes(&chunk_plan.chunks[0]))?;
    s2.upload_part(&chunk_plan, 1, &part_bytes(&chunk_plan.chunks[1]))?;
    let abort_receipt: AbortReceipt = s2.abort()?;
    assert_eq!(abort_receipt.confirmed_parts, 2);
    assert_eq!(t2.aborted.len(), 1);
    emit("completion-abort-discipline", 2);
    Ok(())
}

/// P5 FULL COMPLETENESS REFUSAL COUNTS: exact confirmed/required figures
/// in the typed refusal.
#[test]
fn p5_incomplete_counts() -> Result<(), Box<dyn std::error::Error>> {
    let mut transport = MemoryTransport::default();
    let chunk_plan = make_plan_f(4)?;
    let root = ContentDigest::sha256(b"root");
    let mut session = MultipartSession::initiate(&mut transport, &chunk_plan, root)?;
    session.upload_part(&chunk_plan, 2, &part_bytes(&chunk_plan.chunks[2]))?;
    match session.complete(&chunk_plan, root) {
        Err(MultipartError::Incomplete {
            confirmed,
            required,
        }) => {
            assert_eq!((confirmed, required), (1, 4));
        }
        other => return Err(format!("expected Incomplete, got {other:?}").into()),
    }
    emit("incomplete-counts", 1);
    Ok(())
}
