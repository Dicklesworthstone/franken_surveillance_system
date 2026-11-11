#![forbid(unsafe_code)]
//! Cold recorder provenance projection for retained-file metadata and source inspection.

use std::io::Write;

use fss_core::ContentDigest;
use fss_reference::ingest::RetainedReadLimits;
use fss_reference::ingest::rtsp_import::replay::retained_replay_receipt;
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::RunResult;

pub(super) fn report(
    deployment: &ReferenceDeployment,
    import_identity: ContentDigest,
    limits: RetainedReadLimits,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> RunResult<()> {
    let Some(receipt) = retained_replay_receipt(deployment, import_identity, limits, cx)? else {
        return Ok(());
    };
    writeln!(out, "replay_provenance=verified_metadata")?;
    writeln!(out, "replay_root={}", receipt.root())?;
    writeln!(out, "replay_request={}", receipt.request().digest())?;
    writeln!(out, "replay_approval={}", receipt.approval())?;
    writeln!(out, "replay_codec={}", receipt.request().codec().as_str())?;
    writeln!(out, "replay_windows={}", receipt.windows().len())?;
    writeln!(out, "replay_termination={}", receipt.termination().as_str())?;
    writeln!(
        out,
        "replay_publication_complete={}",
        receipt.publication_complete()
    )?;
    writeln!(
        out,
        "replay_requested_window={}",
        receipt.request().window()
    )?;
    writeln!(
        out,
        "replay_acknowledged_window={}",
        receipt.acceptance().acknowledged()
    )?;
    if let Some(source) = receipt.request().onvif_source() {
        writeln!(out, "replay_onvif_source={}", source.digest()?)?;
    }
    Ok(())
}
