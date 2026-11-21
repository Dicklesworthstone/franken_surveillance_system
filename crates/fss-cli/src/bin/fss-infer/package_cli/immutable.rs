#![forbid(unsafe_code)]
//! Fresh detector and sentinel previews from sealed source custody, without a publisher.

use fss_reference::retained_source::{ImmutableRetainedSource, RetainedReadUsage, RetainedSource};

use super::*;

pub(super) fn run(
    options: &Options,
    package: &RgbDetectorPackage,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
    cancelled: &(dyn Fn() -> bool + Sync),
    out: &mut impl Write,
) -> RunResult<RetainedReadUsage> {
    if options.retain {
        return Err(io::Error::other("immutable package analysis cannot retain reports").into());
    }
    let source = ImmutableRetainedSource::open_cancellable(
        &options.root,
        options.read_limits,
        cx,
        cancelled,
    )?;
    if source.site_lineage() != options.site {
        return Err(io::Error::other("retained package source site lineage mismatch").into());
    }
    let json = if let Some(stream) = &options.stream_sentinel {
        let report = fss_reference::ingest::long_sentinel::run_long_sentinel_detection(
            &source,
            package,
            &stream.request(&options.request),
            stream.config,
            &stream.limits,
            cx,
            scalar,
        )?;
        report.json().to_owned()
    } else if let Some(config) = options.sentinel {
        let report = run_sentinel_detection(
            &source,
            package,
            &options.request,
            config,
            &options.limits,
            cx,
            scalar,
        )?;
        report.json().to_owned()
    } else {
        run_package_detection(
            &source,
            package,
            &options.request,
            &options.limits,
            cx,
            scalar,
        )?
        .json
    };
    // The owner remembers every payload used by native decoding/inference, including original
    // source provenance, capsules and privacy bindings. Rehash them and check the original
    // publication/journal basis under the same budget before any stdout or export is released.
    source.revalidate()?;
    if let Some(path) = &options.report {
        export(path, json.as_bytes(), &options.root, cx)?;
    }
    out.write_all(json.as_bytes())?;
    Ok(source.usage())
}

#[cfg(test)]
#[path = "immutable_tests.rs"]
mod tests;
