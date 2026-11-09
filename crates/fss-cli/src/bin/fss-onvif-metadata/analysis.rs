#![forbid(unsafe_code)]
//! Finite source-verified lifecycle query under the existing native request owner.

#[path = "analysis/lifecycle_json.rs"]
mod lifecycle_json;
#[path = "analysis/report.rs"]
mod report;

use std::collections::BTreeMap;
use std::ffi::OsString;

use fss_core::{
    BudgetVector, CanonicalEncoder, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec,
};
use fss_reference::ReplayCx;
use fss_reference::onvif::metadata::lifecycle::{
    DEFAULT_LIFECYCLE_READ_WORK_UNITS, LifecycleReadLimits, RetainedLifecycle,
    contract::{MAX_LIFECYCLE_REPORT_BYTES, MAX_LIFECYCLE_WORK_UNITS},
};

use super::{ARGUMENT_ERROR, CommandOutput, LIMIT_ERROR, admission, runtime, tracks};

const HELP: &str = "fss-onvif-metadata lifecycle [options]
  --root ABSOLUTE_DIR --site SITE [--principal ID]
  --xml-source sha256:IMPORT_ID@sha256:EXPECTED_ROOT
  --rtp-source sha256:IMPORT_ID@sha256:EXPECTED_ROOT
  Repeat either source flag in the desired order, with 1..32 distinct source identities.
  [--include-values yes|no] [--timeout-ms 30000]
  [--max-analysis-work 4000000] [--max-analysis-bytes 4194304]
  All tracks source/grouping bounds are accepted; see tracks --help.
  The shared --max-work-units default is 33554432 for lifecycle.

Returns one complete fss.onvif_vendor_lifecycle_report.v1 JSON document, at most
32 MiB, with the complete original tracks report, every document disposition,
source-linked lifecycle relationships and shared cumulative request accounting.
Both source passes, tracklet replay and lifecycle interpretation consume the SAME
nonrenewing allowance. Opening may perform existing publisher recovery; indexed
source counters exclude opening work. No deployment is initialized, source data
acquired, derived root published or pending external effect reconciled.

ObjectTree Rename/Split/Merge/Delete and separate Behaviour Idle/Removed claims
use an independent generation. Original tracks-v1 runs and identities stay unchanged.
Endpoints link only to supported current or immediately preceding module-frame
occurrences. Unresolved/conflicted endpoints, integer reuse, unsupported references,
empty/rejected inputs and frozen-v1 skips remain explicit. UUIDs are never matched.

These are derived relationships over vendor_claimed observations, not physical
identity, departure, absence, coverage, authenticated origin, calibrated geometry,
an event or permission to act. Raw module names, integer ObjectIds and vendor times
are withheld unless --include-values yes. UUID strings remain withheld.
";

struct Options {
    common: tracks::Options,
    limits: LifecycleReadLimits,
}

fn number(
    values: &BTreeMap<String, OsString>,
    key: &str,
    default: u64,
    maximum: u64,
) -> Result<u64, &'static str> {
    let value = match values.get(key) {
        None => default,
        Some(value) => {
            let value = value.to_str().ok_or(ARGUMENT_ERROR)?;
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(ARGUMENT_ERROR);
            }
            value.parse().map_err(|_| ARGUMENT_ERROR)?
        }
    };
    if value == 0 || value > maximum {
        return Err(ARGUMENT_ERROR);
    }
    Ok(value)
}

fn parse(args: &[OsString]) -> Result<Options, &'static str> {
    if args.is_empty()
        || args.len() > 99
        || args.len() % 2 != 1
        || args[0] != "lifecycle"
        || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
    {
        return Err(ARGUMENT_ERROR);
    }
    let mut common_args = vec![OsString::from("tracks")];
    let mut values = BTreeMap::new();
    let mut explicit_work = false;
    for pair in args[1..].chunks_exact(2) {
        let key = pair[0].to_str().ok_or(ARGUMENT_ERROR)?;
        if matches!(key, "--max-analysis-work" | "--max-analysis-bytes") {
            if values.insert(key.to_owned(), pair[1].clone()).is_some() {
                return Err(ARGUMENT_ERROR);
            }
        } else {
            explicit_work |= key == "--max-work-units";
            common_args.extend_from_slice(pair);
        }
    }
    if !explicit_work {
        common_args.extend([
            "--max-work-units".into(),
            DEFAULT_LIFECYCLE_READ_WORK_UNITS.to_string().into(),
        ]);
    }
    let mut common = tracks::parse(&common_args)?;
    let mut limits = LifecycleReadLimits {
        source: common.limits,
        ..LifecycleReadLimits::default()
    };
    limits.projection.max_frames = common.limits.projection.max_frames;
    limits.projection.max_objects = common.limits.projection.max_objects;
    limits.projection.max_work_units = number(
        &values,
        "--max-analysis-work",
        limits.projection.max_work_units,
        MAX_LIFECYCLE_WORK_UNITS,
    )?;
    limits.projection.max_output_bytes = number(
        &values,
        "--max-analysis-bytes",
        limits.projection.max_output_bytes as u64,
        MAX_LIFECYCLE_REPORT_BYTES as u64,
    )? as usize;
    limits.validate().map_err(|_| ARGUMENT_ERROR)?;

    let mut request = CanonicalEncoder::new();
    request.text("fss.onvif_vendor_lifecycle_cli_request.v1");
    request.digest(common.approval);
    request.digest(limits.projection.digest().map_err(|_| ARGUMENT_ERROR)?);
    for value in [
        limits.parse.max_frames,
        limits.parse.max_objects,
        limits.parse.max_operations,
        limits.parse.max_references,
    ] {
        request.u64(value as u64);
    }
    request.u64(limits.parse.max_work_units);
    common.approval = ContentDigest::sha256(&request.finish_checked().map_err(|_| ARGUMENT_ERROR)?);
    Ok(Options { common, limits })
}

fn run(options: Options) -> Result<(CommandOutput, bool), &'static str> {
    let common = &options.common;
    let storage_operations = (common.limits.max_work_units as u64)
        .checked_mul(4)
        .and_then(|value| value.checked_add(4 * common.limits.max_indexed_reads + 4096))
        .ok_or(LIMIT_ERROR)?;
    let request = runtime::Request {
        approval: common.approval,
        principal: common.principal.clone(),
        timeout_ns: common.timeout_ns,
        bytes: common.limits.max_stored_bytes,
        network_bytes: 0,
        storage_operations,
        network: false,
        // Existing publisher opening may perform recovery under its exclusive lock.
        write: true,
        secrets: false,
    };
    let report = runtime::run(request, |scope| {
        scope.input()?;
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:onvif-vendor-lifecycle".into(),
            operation_id: OperationId::parse("operation:onvif-vendor-lifecycle")
                .map_err(|_| ARGUMENT_ERROR)?,
            principal: common.principal.clone(),
            capabilities: vec![fss_reference::ADP_REPLAY_ROW_ID.into()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(common.limits.max_stored_bytes)
                .storage_operations(storage_operations)
                .build()
                .map_err(|_| LIMIT_ERROR)?,
            privacy_scope: "privacy:owner-private-vendor-metadata".into(),
            retention_scope: "retention:existing-vendor-metadata-query".into(),
            anchor_universe: ContentDigest::sha256(common.site.as_bytes()),
            generation: 1,
        })
        .map_err(|_| ARGUMENT_ERROR)?;
        let cx = ReplayCx::from_context_authority_read_only(&authority, common.root.clone())
            .map_err(|_| ARGUMENT_ERROR)?
            .with_admission(|_| admission::check(scope));
        let result = RetainedLifecycle::open(
            &common.root,
            &common.site,
            &common.pins,
            options.limits,
            &cx,
        )
        .map_err(|error| error.code());
        let owner_error = cx.admission_refusal().map(admission::code);
        cx.drain_and_finalize();
        if let Some(error) = owner_error {
            return Err(error);
        }
        let retained = result?;
        // The existing native runner checks cancellation/deadline and drains before returning
        // any complete JSON to stdout. Serialization stays inside that original request.
        report::render(&retained, common.include_values)
    })?;
    Ok((
        CommandOutput {
            report,
            custody_receipt: None,
        },
        true,
    ))
}

pub(super) fn run_args(args: &[OsString]) -> Result<(CommandOutput, bool), &'static str> {
    if args.len() == 2 && matches!(args[1].to_str(), Some("--help" | "-h" | "help")) {
        return Ok((
            CommandOutput {
                report: HELP.to_owned(),
                custody_receipt: None,
            },
            true,
        ));
    }
    run(parse(args)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> Vec<OsString> {
        [
            "lifecycle".to_owned(),
            "--root".into(),
            "/tmp/fss-lifecycle-options".into(),
            "--site".into(),
            "site:lifecycle-options".into(),
            "--xml-source".into(),
            format!(
                "{}@{}",
                ContentDigest::sha256(b"source"),
                ContentDigest::sha256(b"root")
            ),
        ]
        .into_iter()
        .map(Into::into)
        .collect()
    }

    #[test]
    fn lifecycle_bounds_and_disclosure_are_bound_to_request() -> Result<(), &'static str> {
        let private = parse(&args())?;
        assert_eq!(private.common.limits.max_work_units, 32 * 1024 * 1024);
        assert!(!private.common.include_values);
        let mut changed = args();
        changed.extend(["--max-analysis-work".into(), "3000000".into()]);
        assert_ne!(private.common.approval, parse(&changed)?.common.approval);
        changed.extend(["--include-values".into(), "yes".into()]);
        assert!(parse(&changed)?.common.include_values);
        let tracks_args: Vec<_> = args()
            .into_iter()
            .enumerate()
            .map(|(i, value)| {
                if i == 0 {
                    OsString::from("tracks")
                } else {
                    value
                }
            })
            .collect();
        assert_ne!(
            private.common.approval,
            tracks::parse(&tracks_args)?.approval
        );
        Ok(())
    }

    #[test]
    fn refuses_impossible_duplicate_unknown_and_nondecimal_limits_before_io() {
        for extra in [
            vec!["--max-analysis-work", "+4000000"],
            vec!["--max-work-units", "10000000"],
            vec!["--max-analysis-work", "2000000"],
            vec!["--max-analysis-bytes", "0"],
            vec![
                "--max-analysis-work",
                "4000000",
                "--max-analysis-work",
                "4000000",
            ],
            vec!["--policy", "/tmp/unsupported.json"],
        ] {
            let mut candidate = args();
            candidate.extend(extra.into_iter().map(OsString::from));
            assert!(parse(&candidate).is_err());
        }
        let mut unpaired = args();
        unpaired.push("--max-analysis-work".into());
        assert!(parse(&unpaired).is_err());
    }
}
