#![forbid(unsafe_code)]
//! Finite raw vendor-coordinate zones over exact retained source pins.

#[path = "zones/report.rs"]
mod report;
#[path = "analysis/zones_json.rs"]
mod zones_json;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

use fss_core::{
    BudgetVector, CanonicalEncoder, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec,
};
use fss_reference::ReplayCx;
use fss_reference::onvif::metadata::zones::{
    DEFAULT_ZONE_READ_WORK_UNITS, RetainedZones, ZonePolicy, ZoneReadLimits,
    contract::{
        MAX_ZONE_POLICY_BYTES, MAX_ZONE_REPORT_BYTES, MAX_ZONE_WORK_UNITS, ZONE_GENERATION,
    },
};

use super::{
    ARGUMENT_ERROR, CommandOutput, LIMIT_ERROR, admission, clean_absolute, read_bounded_input,
    runtime, tracks,
};

// Include the one-byte trailing probe used to refuse a file that grows after its size check.
const POLICY_READ_BYTES: u64 = MAX_ZONE_POLICY_BYTES as u64 + 1;
const HELP: &str = "fss-onvif-metadata zones [options]
  --root ABSOLUTE_DIR --site SITE [--principal ID] --policy ABSOLUTE_JSON_FILE
  --xml-source sha256:IMPORT_ID@sha256:EXPECTED_ROOT
  --rtp-source sha256:IMPORT_ID@sha256:EXPECTED_ROOT
  Repeat either source flag in the desired order, with 1..32 distinct source identities.
  [--include-values yes|no] [--timeout-ms 30000]
  [--max-analysis-work 4000000] [--max-analysis-bytes 8388608]
  All tracks source/grouping bounds are accepted; see tracks --help.
  The shared --max-work-units default is 33554432 for zones.

The policy is a regular UTF-8 JSON file of at most 64 KiB, read under the native request.
It uses schema fss.onvif_vendor_zone_policy.v1 and coordinates raw_vendor_object_millionths.
Each of 1..16 rectangles supplies a local id, exact scope/module/frame-transform/object-
transform digests from tracks, min/max integer pairs and a nonnegative margin. Coordinates
and margin use one million subunits per raw vendor unit. No transformation is applied.

Returns complete fss.onvif_vendor_zones_report.v1 JSON, at most 32 MiB, containing the
original tracks report, full operator policy, every occurrence-by-zone cell and every
frame-by-zone sample, including empty and wrong-domain frames. Entire claimed boxes are
rounded outward and expanded by the declared margin: inside/outside are definite numeric
relations, boundary covers touching/intersection/rounding uncertainty, and unavailable
preserves missing, opaque or incompatible evidence. An unknown observation is never outside.

Side changes name original occurrences within one unchanged vendor tracklet. Boundary
samples do not establish a side; unavailable samples reset continuity. No interpolation,
physical identity, capture clock, dwell time, calibrated geometry, coverage, absence,
authority event or permission to act is inferred. Operator policy values are always reported;
raw vendor module/ObjectId/time values remain hidden unless --include-values yes.

Both complete source/analysis passes share one nonrenewing indexed-read/work allowance.
The policy read has a separate 65537-byte reservation including its trailing probe. Opening
can perform existing publisher recovery; its work is outside indexed-source counters.
No deployment is initialized, source data acquired, derived root published or effect reconciled.
The result commits both semantic policy and exact policy-file bytes; JSON whitespace can
change query_digest without changing the semantic analysis digest.
";

struct Options {
    common: tracks::Options,
    limits: ZoneReadLimits,
    policy: PathBuf,
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
        || args[0] != "zones"
        || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
    {
        return Err(ARGUMENT_ERROR);
    }
    let mut common_args = vec![OsString::from("tracks")];
    let mut values = BTreeMap::new();
    let mut explicit_work = false;
    for pair in args[1..].chunks_exact(2) {
        let key = pair[0].to_str().ok_or(ARGUMENT_ERROR)?;
        if matches!(
            key,
            "--policy" | "--max-analysis-work" | "--max-analysis-bytes"
        ) {
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
            DEFAULT_ZONE_READ_WORK_UNITS.to_string().into(),
        ]);
    }
    let mut common = tracks::parse(&common_args)?;
    let policy = PathBuf::from(values.get("--policy").ok_or(ARGUMENT_ERROR)?);
    if !clean_absolute(&policy) || policy.to_str().is_none() {
        return Err(ARGUMENT_ERROR);
    }
    let mut limits = ZoneReadLimits {
        source: common.limits,
        ..ZoneReadLimits::default()
    };
    limits.projection.max_work_units = number(
        &values,
        "--max-analysis-work",
        limits.projection.max_work_units,
        MAX_ZONE_WORK_UNITS,
    )?;
    limits.projection.max_output_bytes = number(
        &values,
        "--max-analysis-bytes",
        limits.projection.max_output_bytes as u64,
        MAX_ZONE_REPORT_BYTES as u64,
    )? as usize;
    limits.validate().map_err(|_| ARGUMENT_ERROR)?;
    let mut request = CanonicalEncoder::new();
    request.text("fss.onvif_vendor_zones_cli_request.v1");
    request.text(ZONE_GENERATION);
    request.digest(common.approval);
    request.text(policy.to_str().ok_or(ARGUMENT_ERROR)?);
    for value in [
        limits.projection.max_cells,
        limits.projection.max_frame_samples,
        limits.projection.max_transitions,
        limits.projection.max_output_bytes,
    ] {
        request.u64(value as u64);
    }
    request.u64(limits.projection.max_work_units);
    request.u64(POLICY_READ_BYTES);
    common.approval = ContentDigest::sha256(&request.finish_checked().map_err(|_| ARGUMENT_ERROR)?);
    Ok(Options {
        common,
        limits,
        policy,
    })
}

fn run(options: Options) -> Result<(CommandOutput, bool), &'static str> {
    let common = &options.common;
    let storage_operations = (common.limits.max_work_units as u64)
        .checked_mul(4)
        .and_then(|value| value.checked_add(4 * common.limits.max_indexed_reads + 4096))
        .ok_or(LIMIT_ERROR)?;
    let bytes = common
        .limits
        .max_stored_bytes
        .checked_add(POLICY_READ_BYTES)
        .ok_or(LIMIT_ERROR)?;
    let request = runtime::Request {
        approval: common.approval,
        principal: common.principal.clone(),
        timeout_ns: common.timeout_ns,
        bytes,
        network_bytes: 0,
        storage_operations,
        network: false,
        // The original existing-store owner can perform publisher recovery housekeeping.
        write: true,
        secrets: false,
    };
    let report = runtime::run(request, |scope| {
        let policy_bytes = read_bounded_input(&options.policy, MAX_ZONE_POLICY_BYTES, scope)?;
        let policy_digest = ContentDigest::sha256(&policy_bytes);
        let policy =
            ZonePolicy::parse_json(std::str::from_utf8(&policy_bytes).map_err(|_| ARGUMENT_ERROR)?)
                .map_err(|error| error.code())?;
        scope.now()?;
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:onvif-vendor-zones".into(),
            operation_id: OperationId::parse("operation:onvif-vendor-zones")
                .map_err(|_| ARGUMENT_ERROR)?,
            principal: common.principal.clone(),
            capabilities: vec![fss_reference::ADP_REPLAY_ROW_ID.into()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(bytes)
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
        let result = RetainedZones::open(
            &common.root,
            &common.site,
            &common.pins,
            &policy,
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
        report::render(
            &retained,
            common.include_values,
            policy_digest,
            policy_bytes.len(),
        )
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
            "zones".to_owned(),
            "--root".into(),
            "/tmp/fss-zones-options".into(),
            "--site".into(),
            "site:zones-options".into(),
            "--xml-source".into(),
            format!(
                "{}@{}",
                ContentDigest::sha256(b"source"),
                ContentDigest::sha256(b"root")
            ),
            "--policy".into(),
            "/tmp/zones-policy.json".into(),
        ]
        .into_iter()
        .map(Into::into)
        .collect()
    }
    #[test]
    fn policy_target_analysis_limits_and_disclosure_are_bound() -> Result<(), &'static str> {
        let original = parse(&args())?;
        assert_eq!(
            original.common.limits.max_work_units,
            DEFAULT_ZONE_READ_WORK_UNITS
        );
        assert!(!original.common.include_values);
        let mut explicit = args();
        explicit.extend([
            "--max-work-units".into(),
            DEFAULT_ZONE_READ_WORK_UNITS.to_string().into(),
        ]);
        assert_eq!(original.common.approval, parse(&explicit)?.common.approval);
        let mut changed = args();
        changed[8] = "/tmp/another-zone-policy.json".into();
        assert_ne!(original.common.approval, parse(&changed)?.common.approval);
        changed = args();
        changed.extend(["--max-analysis-work".into(), "3000000".into()]);
        assert_ne!(original.common.approval, parse(&changed)?.common.approval);
        changed.extend(["--include-values".into(), "yes".into()]);
        assert!(parse(&changed)?.common.include_values);
        Ok(())
    }
    #[test]
    fn missing_relative_duplicate_or_impossible_policy_arguments_refuse_before_io() {
        let mut missing = args();
        missing.truncate(7);
        assert!(parse(&missing).is_err());
        let mut relative = args();
        relative[8] = "relative.json".into();
        assert!(parse(&relative).is_err());
        for extra in [
            vec!["--policy", "/tmp/duplicate.json"],
            vec!["--max-analysis-work", "2000000"],
            vec!["--max-work-units", "12000000"],
            vec!["--max-analysis-work", "+4000000"],
            vec!["--max-analysis-bytes", "0"],
            vec![
                "--max-analysis-work",
                "4000000",
                "--max-analysis-work",
                "4000000",
            ],
        ] {
            let mut candidate = args();
            candidate.extend(extra.into_iter().map(OsString::from));
            assert!(parse(&candidate).is_err());
        }
    }
}
