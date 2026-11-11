#![forbid(unsafe_code)]
//! Read-only recorder acquisition metadata recovered from the ordinary retained import.

use fss_core::ContentDigest;

use crate::ingest::{FileIngestError, RetainedFileImport, RetainedReadLimits};
use crate::rtsp::recording_replay::ReplayReceipt;
use crate::{ReferenceDeployment, ReplayCx};

use super::{ADAPTER, GENERATION, checkpoint, corrupt, provenance};

/// Recover the exact recorder companion from a completed ordinary retained import.
///
/// Reopens current completion/root authority, verifies its native replay proof and the actual
/// retained companion manifest/metadata bytes, and checks current tombstones. The returned
/// request, PLAY acknowledgement, optional ONVIF pins and stop state remain acquisition
/// provenance; they do not establish capture time, interval completeness or scene coverage.
///
/// This bounded metadata inspection does not reconstruct original RTP or decode pictures.
/// Use [`RetainedFileImport::verify_source`] for complete original-byte verification. No
/// source archive, recorder connection or visible native replay slot is needed. Other
/// retained import profiles return `None` after their ordinary metadata authority checks.
pub fn retained_replay_receipt(
    deployment: &ReferenceDeployment,
    import_identity: ContentDigest,
    limits: RetainedReadLimits,
    cx: &ReplayCx,
) -> Result<Option<ReplayReceipt>, FileIngestError> {
    checkpoint(cx)?;
    if cx.root_dir() != deployment.root() {
        return Err(corrupt(
            "replay inspection requires destination root authority",
        ));
    }
    let retained = RetainedFileImport::open(deployment, import_identity, limits, cx)?;
    let manifest = retained.manifest();
    if manifest.adapter_id != ADAPTER {
        return Ok(None);
    }
    let suffix = manifest
        .adapter_generation
        .strip_prefix(GENERATION)
        .ok_or_else(|| corrupt("replay inspection generation"))?;
    let digest = ContentDigest::parse(&format!("sha256:{suffix}"))?;
    let proof = provenance::proof(deployment, digest, cx, &mut |_| Ok(()))?;
    proof.verify_companion(deployment, cx, &mut |_| Ok(()))?;
    let receipt = proof.receipt()?;
    if RetainedFileImport::open(deployment, import_identity, limits, cx)? != retained {
        return Err(corrupt("replay inspection authority changed"));
    }
    checkpoint(cx)?;
    Ok(Some(receipt))
}
