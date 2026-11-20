#![forbid(unsafe_code)]
//! Buffer exact review metadata and proposals under one immutable, nonrenewing read owner.

use super::*;
use fss_reference::retained_source::{ImmutableRetainedSource, RetainedReadUsage};

const MAX_REPORT_BYTES: usize = 4 * 1024 * 1024;

pub(super) fn run_with(
    options: &Options,
    authority: &ContextAuthority,
    cx: &ReplayCx,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> RunResult<(String, RetainedReadUsage)> {
    if options.approval.is_some() {
        return Err(
            ReviewError::InvalidRequest("immutable review cannot publish an approval").into(),
        );
    }
    authority.validate()?;
    if !authority.has_capability(CAP_REVIEW_PREPARE)
        || authority.cancellation_reason.is_some()
        || cx.root_dir() != options.root
        || authority.anchor_universe != ContentDigest::sha256(options.site.as_bytes())
    {
        return Err(ReviewError::Unauthorized.into());
    }
    let source = ImmutableRetainedSource::open_cancellable(
        &options.root,
        options.read_limits,
        cx,
        cancelled,
    )?;
    if source.site_lineage() != options.site {
        return Err(ReviewError::Unauthorized.into());
    }
    let json = render_read(options, &source, authority, cx)?;
    if json.len() > MAX_REPORT_BYTES {
        return Err(ReviewError::Limit.into());
    }
    cx.checkpoint("event_review_cli:delivery")?;
    source.revalidate_snapshot_metadata()?;
    source.revalidate()?;
    Ok((json, source.usage()))
}

#[cfg(test)]
#[path = "immutable_tests.rs"]
mod tests;
