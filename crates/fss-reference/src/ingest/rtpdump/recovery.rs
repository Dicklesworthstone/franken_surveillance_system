#![forbid(unsafe_code)]
//! Recover an import from its exact published root, without its original file or
//! an in-memory receipt. Inspection is read-only; resuming ledger work is explicit.

use super::{
    RtpDumpLimits,
    import::{
        RtpFileImportReceipt, RtpImportError, RtpImportLimits, RtpImportReport, RtpImportScope,
        prepare_rtp_import, publish_rtp_import,
    },
    replay::RtpReplayConfig,
};
use crate::{ReferenceDeployment, ReplayCx};
use fss_core::{
    BatchId, CanonicalDecoder, CanonicalEncode, CaptureInterval, ContentDigest, DigestAlgorithm,
    EvidenceDelta, LedgerAnchor, ObjectId, Plane, SensorId, StreamId, TimestampNs,
};
use fss_object::ObjectManifest;
use fss_packet::{H264Limits, H264Mode, PacketLimits, RtcpMode, StreamKey};
use fss_publication::{LocalPublicationState, SlotName};

type Result<T> = std::result::Result<T, RtpImportError>;

/// Independent caller ceilings. Stored limits never grant permission to spend
/// more resources; a narrower recovery policy refuses rather than rewriting identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtpRecoveryPolicy {
    /// Maximum reconstructed original capture (1..=256 MiB).
    pub max_source_bytes: usize,
    /// Maximum record-mapping entries reserved by replay (1..=65,536).
    pub max_records: usize,
    /// Maximum single spool read allocation (1..=64 MiB).
    pub max_object_bytes: usize,
    /// Total read budget (at most 2 GiB). Each read reserves the spool object ceiling
    /// before I/O, then returns the unused part of that reservation.
    pub max_read_bytes: u64,
    /// Independent ceilings on the recorded import's reconstruction policy.
    pub import: RtpImportLimits,
}
impl Default for RtpRecoveryPolicy {
    fn default() -> Self {
        Self {
            max_source_bytes: 64 * 1024 * 1024,
            max_records: 65_536,
            max_object_bytes: 64 * 1024 * 1024,
            max_read_bytes: 512 * 1024 * 1024,
            import: RtpImportLimits::default(),
        }
    }
}
impl RtpRecoveryPolicy {
    fn validate(self) -> Result<()> {
        validate_import_limits(self.import)?;
        if !(1..=256 * 1024 * 1024).contains(&self.max_source_bytes)
            || !(1..=65_536).contains(&self.max_records)
            || !(1..=64 * 1024 * 1024).contains(&self.max_object_bytes)
            || self.max_read_bytes < self.max_object_bytes as u64
            || self.max_read_bytes > 2 * 1024 * 1024 * 1024
        {
            return Err(RtpImportError::Limit);
        }
        Ok(())
    }
}

/// Source publication is not the same as completion of capsule-ledger work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RtpRecoveryState {
    /// All expected capsule batches and the exact terminal record are present.
    Complete {
        /// Anchor of the terminal import batch, not a newly invented receipt.
        anchor: LedgerAnchor,
    },
    /// Source closure verifies, but one or more capsule/terminal batches are absent.
    LedgerPending {
        /// Capsules whose exact deterministic batch already exists.
        committed_capsules: usize,
        /// Capsules reconstructed from retained source.
        total_capsules: usize,
    },
}

struct Recipe {
    input: ContentDigest,
    input_bytes: usize,
    chunks: Vec<ContentDigest>,
    scope: RtpImportScope,
    config: RtpReplayConfig,
    limits: RtpImportLimits,
}

/// Reverified source closure and explicit ledger status. Private fields prevent
/// a caller from fabricating recovery state or replacing the verified source.
/// Debug never includes packet bytes, private labels or source addresses.
pub struct RecoveredRtpImport {
    root: ContentDigest,
    source: Vec<u8>,
    report: RtpImportReport,
    recipe: Recipe,
    state: RtpRecoveryState,
    basis: LedgerAnchor,
}
impl RecoveredRtpImport {
    /// Exact expected publication root supplied by the caller.
    pub fn root(&self) -> ContentDigest {
        self.root
    }
    /// Entire retained original file, including rejected packets and bad tails.
    pub fn source(&self) -> &[u8] {
        &self.source
    }
    /// Recomputed report, byte-equivalent to the stored canonical report.
    pub fn report(&self) -> &RtpImportReport {
        &self.report
    }
    /// Truthful complete/pending status after read-only inspection.
    pub fn state(&self) -> &RtpRecoveryState {
        &self.state
    }
    /// Explicitly complete missing publication/ledger work using the original
    /// identities. A changed anchor or root requires a fresh inspection first.
    /// No socket, source file reopen, new stream generation or remote effect occurs.
    pub fn resume(
        self,
        cx: &ReplayCx,
        deployment: &mut ReferenceDeployment,
    ) -> Result<RtpFileImportReceipt> {
        checkpoint(cx)?;
        if deployment.current_anchor() != &self.basis {
            return Err(RtpImportError::Binding);
        }
        let slot = root_slot(self.root)?;
        if !deployment
            .publisher()
            .root(&slot)
            .is_some_and(|r| r.root == self.root && r.state == LocalPublicationState::Durable)
        {
            return Err(RtpImportError::Binding);
        }
        let plan = prepare_rtp_import(
            &self.source,
            self.recipe.scope,
            self.recipe.config,
            self.recipe.limits,
            cx,
        )?;
        if plan.manifest().root() != self.root {
            return Err(RtpImportError::Digest);
        }
        publish_rtp_import(plan, cx, deployment)
    }
}
impl std::fmt::Debug for RecoveredRtpImport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveredRtpImport")
            .field("root", &self.root)
            .field("source_bytes", &self.source.len())
            .field("records", &self.report.records().len())
            .field("nals", &self.report.nals().len())
            .finish_non_exhaustive()
    }
}

/// Reconstruct and verify a single explicitly named root. This performs no
/// publication, ledger append, repair, source-path lookup or directory discovery.
/// The fresh nonzero ingress is a process-local owner binding, never restored authority.
pub fn inspect_rtp_import(
    root: ContentDigest,
    ingress: u128,
    policy: RtpRecoveryPolicy,
    cx: &ReplayCx,
    deployment: &ReferenceDeployment,
) -> Result<RecoveredRtpImport> {
    checkpoint(cx)?;
    policy.validate()?;
    if ingress == 0 || root.algorithm() != DigestAlgorithm::Sha256 {
        return Err(RtpImportError::Binding);
    }
    let p = deployment.publisher();
    if p.is_poisoned() {
        return Err(RtpImportError::Binding);
    }
    let slot = root_slot(root)?;
    if !p
        .root(&slot)
        .is_some_and(|r| r.root == root && r.state == LocalPublicationState::Durable)
    {
        return Err(RtpImportError::Binding);
    }
    let reservation = p.spool().limits().max_object_bytes;
    if reservation > policy.max_object_bytes {
        return Err(RtpImportError::Limit);
    }
    let mut remaining = policy.max_read_bytes;
    let mut read = |digest: ContentDigest| -> Result<Vec<u8>> {
        checkpoint(cx)?;
        if digest.algorithm() != DigestAlgorithm::Sha256 || p.tombstones().any(|d| *d == digest) {
            return Err(RtpImportError::Binding);
        }
        if remaining < reservation as u64 {
            return Err(RtpImportError::Limit);
        }
        let bytes = p.spool().read(digest)?;
        remaining = remaining
            .checked_sub(bytes.len() as u64)
            .ok_or(RtpImportError::Limit)?;
        Ok(bytes)
    };
    let manifest_bytes = read(root)?;
    let manifest = ObjectManifest::from_canonical_bytes(&manifest_bytes)
        .map_err(|_| RtpImportError::Digest)?;
    if manifest.root() != root || manifest.kind() != "rtpdump_import_v1" {
        return Err(RtpImportError::Binding);
    }
    let metadata = manifest.metadata_digest().ok_or(RtpImportError::Binding)?;
    let report_bytes = read(metadata)?;
    let recipe = decode_recipe(&report_bytes, ingress, policy)?;
    let mut source = Vec::new();
    source
        .try_reserve_exact(recipe.input_bytes)
        .map_err(|_| RtpImportError::Limit)?;
    for digest in &recipe.chunks {
        if manifest.children().binary_search(digest).is_err() {
            return Err(RtpImportError::Digest);
        }
        let bytes = read(*digest)?;
        let expected = recipe
            .limits
            .chunk_bytes
            .min(recipe.input_bytes - source.len());
        if bytes.len() != expected {
            return Err(RtpImportError::Digest);
        }
        source.extend_from_slice(&bytes);
    }
    if source.len() != recipe.input_bytes || ContentDigest::try_sha256(&source)? != recipe.input {
        return Err(RtpImportError::Digest);
    }
    // Only the bounded replay recipe was decoded. The entire remaining report is
    // validated by recomputation, never trusted as a serialized state-machine snapshot.
    let report = {
        let plan = prepare_rtp_import(
            &source,
            recipe.scope.clone(),
            recipe.config,
            recipe.limits,
            cx,
        )?;
        if plan.manifest() != &manifest || plan.report_bytes() != report_bytes.as_slice() {
            return Err(RtpImportError::Digest);
        }
        for nal in plan.report().nals() {
            let bytes = read(nal.digest)?;
            if ContentDigest::try_sha256(&bytes)? != nal.digest {
                return Err(RtpImportError::Digest);
            }
            if read(nal.capsule.source_digest)?.as_slice() != &source[nal.source.clone()]
                || read(nal.capsule_object)? != nal.capsule.try_canonical_bytes()?
            {
                return Err(RtpImportError::Digest);
            }
        }
        plan.report().clone()
    };
    let state = ledger_state(root, metadata, &report, &recipe.scope, deployment)?;
    checkpoint(cx)?;
    Ok(RecoveredRtpImport {
        root,
        source,
        report,
        recipe,
        state,
        basis: deployment.current_anchor().clone(),
    })
}

fn checkpoint(cx: &ReplayCx) -> Result<()> {
    cx.checkpoint("rtpdump:recover")
        .map_err(|_| RtpImportError::Cancelled)
}
fn root_hex(root: ContentDigest) -> String {
    root.bytes().iter().map(|b| format!("{b:02x}")).collect()
}
fn root_slot(root: ContentDigest) -> Result<SlotName> {
    SlotName::parse(&format!("rtp-{}", root_hex(root))).map_err(|_| RtpImportError::Binding)
}
fn size(d: &mut CanonicalDecoder<'_>) -> Result<usize> {
    usize::try_from(d.u64()?).map_err(|_| RtpImportError::Limit)
}
fn validate_import_limits(l: RtpImportLimits) -> Result<()> {
    if !(1..=16 * 1024 * 1024).contains(&l.chunk_bytes)
        || !(1..=2048).contains(&l.max_nals)
        || !(1..=65536).contains(&l.max_source_spans)
        || !(1..=64 * 1024 * 1024).contains(&l.max_derived_bytes)
        || !(1..=16 * 1024 * 1024).contains(&l.max_report_bytes)
        || !(1..=256 * 1024 * 1024).contains(&l.max_payload_bytes)
    {
        return Err(RtpImportError::Limit);
    }
    Ok(())
}
fn limit_values(l: RtpImportLimits) -> [usize; 6] {
    [
        l.chunk_bytes,
        l.max_nals,
        l.max_source_spans,
        l.max_derived_bytes,
        l.max_report_bytes,
        l.max_payload_bytes,
    ]
}
fn decode_recipe(bytes: &[u8], ingress: u128, policy: RtpRecoveryPolicy) -> Result<Recipe> {
    if bytes.len() > policy.import.max_report_bytes {
        return Err(RtpImportError::Limit);
    }
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != "fss.rtpdump.import.report.v1" || d.u64()? != 1 {
        return Err(RtpImportError::Binding);
    }
    let input = d.digest()?;
    let input_bytes = size(&mut d)?;
    if input.algorithm() != DigestAlgorithm::Sha256
        || input_bytes == 0
        || input_bytes > policy.max_source_bytes
    {
        return Err(RtpImportError::Limit);
    }
    let scope = RtpImportScope {
        sensor: SensorId::parse(d.text()?)?,
        stream: StreamId::parse(d.text()?)?,
        receive_time: TimestampNs(d.i128()?),
    };
    if scope.receive_time.0 < 0 || d.text()? != "capture_unknown" {
        return Err(RtpImportError::Binding);
    }
    let key = StreamKey {
        ingress,
        generation: d.u64()?,
        ssrc: d.u32()?,
    };
    let payload_type = d.u8()?;
    let mode = match d.u8()? {
        0 => H264Mode::SingleNal,
        1 => H264Mode::NonInterleaved,
        _ => return Err(RtpImportError::Binding),
    };
    let rtcp = match d.u8()? {
        0 => RtcpMode::Compound,
        1 => RtcpMode::ReducedSize,
        _ => return Err(RtpImportError::Binding),
    };
    let dump = RtpDumpLimits {
        max_input_bytes: size(&mut d)?,
        max_records: size(&mut d)?,
        max_packet_bytes: size(&mut d)?,
    };
    let packet = PacketLimits {
        max_packet_bytes: size(&mut d)?,
        max_extension_bytes: size(&mut d)?,
        max_rtcp_packets: size(&mut d)?,
    };
    let codec = H264Limits {
        max_nal_bytes: size(&mut d)?,
        max_packet_nals: size(&mut d)?,
        max_fragment_packets: size(&mut d)?,
        max_pending_age_ns: d.u64()?,
    };
    let config = RtpReplayConfig {
        key,
        payload_type,
        mode,
        dump,
        packet,
        codec,
        rtcp,
    };
    config.validate()?;
    if input_bytes > dump.max_input_bytes || dump.max_records > policy.max_records {
        return Err(RtpImportError::Limit);
    }
    let limits = RtpImportLimits {
        chunk_bytes: size(&mut d)?,
        max_nals: size(&mut d)?,
        max_source_spans: size(&mut d)?,
        max_derived_bytes: size(&mut d)?,
        max_report_bytes: size(&mut d)?,
        max_payload_bytes: size(&mut d)?,
    };
    validate_import_limits(limits)?;
    if limit_values(limits)
        .into_iter()
        .zip(limit_values(policy.import))
        .any(|(stored, ceiling)| stored > ceiling)
        || input_bytes > limits.max_payload_bytes
    {
        return Err(RtpImportError::Limit);
    }
    let count = size(&mut d)?;
    if count != input_bytes.div_ceil(limits.chunk_bytes)
        || count > fss_object::MAX_MANIFEST_CHILDREN
        || count
            .checked_mul(33)
            .and_then(|n| n.checked_add(8))
            .is_none_or(|n| n > d.remaining())
    {
        return Err(RtpImportError::Limit);
    }
    let mut chunks = Vec::new();
    chunks
        .try_reserve_exact(count)
        .map_err(|_| RtpImportError::Limit)?;
    for _ in 0..count {
        let digest = d.digest()?;
        if digest.algorithm() != DigestAlgorithm::Sha256 {
            return Err(RtpImportError::Digest);
        }
        chunks.push(digest);
    }
    // Record counts are bounded before reconstruction; every other field and all
    // trailing bytes are checked by exact report-byte equality after kernel replay.
    if size(&mut d)? > config.dump.max_records {
        return Err(RtpImportError::Limit);
    }
    Ok(Recipe {
        input,
        input_bytes,
        chunks,
        scope,
        config,
        limits,
    })
}

fn ledger_state(
    root: ContentDigest,
    metadata: ContentDigest,
    report: &RtpImportReport,
    scope: &RtpImportScope,
    dep: &ReferenceDeployment,
) -> Result<RtpRecoveryState> {
    let hex = root_hex(root);
    let validity = CaptureInterval::new(TimestampNs(0), scope.receive_time)?;
    let mut committed = 0;
    let mut pending = false;
    for (part, group) in report.nals().chunks(64).enumerate() {
        let id = BatchId::parse(format!("batch:rtp:{hex}:c{part}"))?;
        let Some(batch) = dep.ledger().batches().iter().find(|b| b.batch_id == id) else {
            pending = true;
            continue;
        };
        let mut deltas = Vec::new();
        let mut children = Vec::new();
        for nal in group {
            deltas.push(EvidenceDelta {
                delta_id: format!("delta:{}", nal.capsule.capsule_id.as_str()),
                family: "sensor_capsule".into(),
                object_id: ObjectId::parse(format!("object:{}", nal.capsule.capsule_id.as_str()))?,
                prior_generation: None,
                new_generation: 1,
                validity,
                plane: Plane::Authority,
                payload_digest: nal.capsule_object,
                witness_digest: Some(nal.capsule.source_digest),
                operation_id: None,
            });
            children.extend([nal.capsule_object, nal.capsule.source_digest]);
        }
        // All rows have one family and monotonically padded capsule IDs, already
        // in the same canonical order used by ReferenceDeployment::append_batch.
        children.sort_unstable();
        children.dedup();
        if batch.deltas != deltas || batch.children != children {
            return Err(RtpImportError::Binding);
        }
        committed += group.len();
    }
    let id = BatchId::parse(format!("batch:rtp:{hex}"))?;
    if let Some(batch) = dep.ledger().batches().iter().find(|b| b.batch_id == id) {
        let expected = EvidenceDelta {
            delta_id: format!("delta:rtp:{hex}"),
            family: "rtpdump_import".into(),
            object_id: ObjectId::parse(format!("object:rtp:{hex}"))?,
            prior_generation: None,
            new_generation: 1,
            validity,
            plane: Plane::Authority,
            payload_digest: metadata,
            witness_digest: Some(root),
            operation_id: None,
        };
        let mut children = vec![root, metadata];
        children.sort_unstable();
        children.dedup();
        if pending || batch.deltas.as_slice() != [expected] || batch.children != children {
            return Err(RtpImportError::Binding);
        }
        Ok(RtpRecoveryState::Complete {
            anchor: batch.new_anchor.clone(),
        })
    } else {
        Ok(RtpRecoveryState::LedgerPending {
            committed_capsules: committed,
            total_capsules: report.nals().len(),
        })
    }
}
