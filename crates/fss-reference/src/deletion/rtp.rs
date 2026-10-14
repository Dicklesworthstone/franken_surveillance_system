#![forbid(unsafe_code)]
//! Admit completed recorded-RTP roots into the existing import deletion universe.
//! Names discover candidates; only full original-source replay establishes membership.

use std::collections::BTreeSet;

use super::DeletionError;
use crate::ingest::rtpdump::import::{RtpImportError, RtpImportLimits};
use crate::ingest::rtpdump::recovery::{RtpRecoveryPolicy, RtpRecoveryState, inspect_rtp_import};
use crate::{ReferenceDeployment, ReplayCx};
use fss_core::{ContentDigest, SensorId};

#[derive(Debug)]
pub(super) struct RtpImport {
    pub(super) sensor: SensorId,
    pub(super) object_id: String,
    units: BTreeSet<String>,
}
impl RtpImport {
    pub(super) fn owns(&self, id: &str) -> bool {
        self.units.contains(id)
    }
}

/// Recognize the exact completion namespace, never a chunk batch or a root-only publication.
pub(super) fn has_terminal(deployment: &ReferenceDeployment, root: ContentDigest) -> bool {
    let id = format!("batch:rtp:{}", hex(root));
    deployment
        .ledger()
        .batches()
        .iter()
        .any(|batch| batch.batch_id.as_str() == id)
}

fn hex(root: ContentDigest) -> String {
    root.bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(super) fn inspect(
    deployment: &ReferenceDeployment,
    root: ContentDigest,
    cx: &ReplayCx,
) -> Result<RtpImport, DeletionError> {
    if !has_terminal(deployment, root) {
        return Err(DeletionError::UnknownImport(root));
    }
    // Admit every bounded v2 publication profile, without borrowing permission from stored
    // limits. The original recovery owner still validates each stored recipe and all bytes.
    let policy = RtpRecoveryPolicy {
        max_source_bytes: 256 * 1024 * 1024,
        max_records: 65_536,
        max_object_bytes: 64 * 1024 * 1024,
        max_read_bytes: 2 * 1024 * 1024 * 1024,
        import: RtpImportLimits {
            chunk_bytes: 16 * 1024 * 1024,
            max_nals: 2048,
            max_source_spans: 65_536,
            max_derived_bytes: 64 * 1024 * 1024,
            max_report_bytes: 16 * 1024 * 1024,
            max_payload_bytes: 256 * 1024 * 1024,
        },
    };
    let retained =
        inspect_rtp_import(root, 1, policy, cx, deployment).map_err(|error| match error {
            RtpImportError::Cancelled => DeletionError::Cancelled {
                stage: super::STAGE_DELETION_SCAN,
            },
            RtpImportError::Limit => DeletionError::Bound {
                limit: "rtp_import_verification",
            },
            RtpImportError::EvidenceDeleted { root, plan } => {
                DeletionError::EvidenceDeleted { import: root, plan }
            }
            _ => DeletionError::RecordMismatch,
        })?;
    if !matches!(retained.state(), RtpRecoveryState::Complete { .. }) {
        return Err(DeletionError::UnknownImport(root));
    }
    let hex = hex(root);
    let mut units = BTreeSet::from([format!("batch:rtp:{hex}"), format!("slot:rtp-{hex}")]);
    // These are the exact fixed partitions checked by the source recovery owner. Do not
    // absorb arbitrary batches merely because they begin with a selected root's spelling.
    for part in 0..retained.report().access_units().len().div_ceil(64) {
        units.insert(format!("batch:rtp:{hex}:c{part}"));
    }
    Ok(RtpImport {
        sensor: retained.scope().sensor.clone(),
        object_id: format!("object:rtp:{hex}"),
        units,
    })
}
