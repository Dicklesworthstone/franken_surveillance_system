#![forbid(unsafe_code)]
//! Whole-source preview through one sealed read owner, with no publication or recovery handle.

use super::*;
use fss_reference::retained_source::{ImmutableRetainedSource, RetainedReadUsage, RetainedSource};

pub(super) fn run_with(
    options: &Options,
    output: &Path,
    authority: &ContextAuthority,
    cx: &ReplayCx,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> RunResult<(String, RetainedReadUsage)> {
    if options.approval.is_some() {
        return Err(OriginalMediaExportError::Unauthorized.into());
    }
    let source = ImmutableRetainedSource::open_cancellable(
        &options.root,
        options.read_limits,
        cx,
        cancelled,
    )?;
    if source.site_lineage() != options.site || !source.snapshot().effect_journal_present {
        return Err(OriginalMediaExportError::AuthorityChanged.into());
    }
    let preview = preview_original_media_export(&source, &options.request, authority, cx)?;
    // Preserve the existing report/approval identity; no partial JSON is released on refusal.
    let json = report(&preview, output, "awaiting_approval", false)?;
    cx.checkpoint("original_media_export:preview_delivery")
        .map_err(|_| OriginalMediaExportError::Cancelled)?;
    source.revalidate_snapshot_metadata()?;
    source.revalidate()?;
    Ok((json, source.usage()))
}

#[cfg(test)]
#[path = "immutable_tests.rs"]
mod tests;
