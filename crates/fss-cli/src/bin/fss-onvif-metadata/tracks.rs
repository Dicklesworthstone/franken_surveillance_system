#![forbid(unsafe_code)]
//! Existing-source vendor tracklet query; no capture, publication or event/effect reconciliation.

#[path = "tracks/report.rs"]
pub(super) mod report;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

use fss_core::{
    BudgetVector, CanonicalEncoder, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec,
};
use fss_reference::ReplayCx;
use fss_reference::onvif::metadata::tracks::contract::{
    MAX_TRACK_FRAMES, MAX_TRACK_OBJECTS, MAX_TRACK_REPORT_BYTES,
};
use fss_reference::onvif::metadata::tracks::{
    MAX_TRACK_INDEXED_READS, MAX_TRACK_SOURCES, MAX_TRACK_STORED_BYTES, MAX_TRACK_WORK_UNITS,
    RetainedTracklets, TrackReadLimits, TrackSourcePin,
};

use super::{
    ARGUMENT_ERROR, CommandOutput, LIMIT_ERROR, admission, clean_absolute, digest, runtime, text,
};

const HELP: &str = "fss-onvif-metadata tracks [options]
  --root ABSOLUTE_DIR --site SITE [--principal ID]
  --xml-source sha256:IMPORT_ID@sha256:EXPECTED_ROOT
  --rtp-source sha256:IMPORT_ID@sha256:EXPECTED_ROOT
  Repeat either source flag in the desired order, with 1..32 distinct source identities.
  RTP pins also accept existing capture-rtp roots and verify their native original observations.
  [--include-values yes|no] [--timeout-ms 30000]
  [--max-read-bytes 67108864] [--max-read-attempts 8192]
  [--max-work-units 8388608] [--max-projection-work 2000000]
  [--max-frames 1024] [--max-objects 4096] [--max-tracklets 4096]
  [--max-vendor-gap-ms 5000] [--max-projection-bytes 4194304]

Returns one complete fss.onvif_vendor_tracklets_report.v1 JSON document, at most 16 MiB.
Both original-source reconstruction passes share one nonrenewing indexed read and work
allowance. Each projection reserves --max-projection-work from --max-work-units before
running; history/replay/frame accounting also consumes that same outer work allowance.
Opening uses the existing deployment capacity limits and may perform publisher recovery;
its recovery, directory scans and metadata/open syscalls are outside indexed read counters.
No deployment is initialized and pending external effects are not reconciled.

Groups consecutive claims from the same named vendor analytics module and integer ObjectId
within an exact generation scope, increasing vendor UTC and the selected maximum gap.
Each independently supplied source pin is a continuity barrier. Within RTP, only adjacent
complete documents with exact packet-boundary provenance can continue a run. Empty,
rejected, opaque, missing-object/module, clock and transform boundaries split grouping.
Source/transport incompleteness is retained in the report, never converted into absence.

The grouping is derived cognition over vendor_claimed observations. It is not physical
identity, camera coverage, authenticated origin, calibrated geometry, an event or permission.
Raw module names, ObjectIds and vendor timestamps are withheld by default.
--include-values yes explicitly releases those original values to local stdout.
Original classes, shapes and transformations remain available through the exact source,
document, frame and object handles and the existing inspect/inspect-rtp commands.
";

pub(super) struct Options {
    pub(super) root: PathBuf,
    pub(super) site: String,
    pub(super) principal: String,
    pub(super) pins: Vec<TrackSourcePin>,
    pub(super) limits: TrackReadLimits,
    pub(super) include_values: bool,
    pub(super) timeout_ns: u64,
    pub(super) approval: ContentDigest,
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

pub(super) fn parse(args: &[OsString]) -> Result<Options, &'static str> {
    if args.is_empty()
        || args.len() > 99
        || args.len() % 2 != 1
        || args[0] != "tracks"
        || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
    {
        return Err(ARGUMENT_ERROR);
    }
    let mut values = BTreeMap::new();
    let mut pins = Vec::new();
    for pair in args[1..].chunks_exact(2) {
        let key = pair[0].to_str().ok_or(ARGUMENT_ERROR)?;
        if matches!(key, "--xml-source" | "--rtp-source") {
            if pins.len() == MAX_TRACK_SOURCES {
                return Err(ARGUMENT_ERROR);
            }
            let (identity, root) = pair[1]
                .to_str()
                .ok_or(ARGUMENT_ERROR)?
                .split_once('@')
                .ok_or(ARGUMENT_ERROR)?;
            let identity = digest(identity)?;
            let root = digest(root)?;
            if identity.bytes() == [0; 32]
                || root.bytes() == [0; 32]
                || pins
                    .iter()
                    .any(|pin: &TrackSourcePin| pin.identity() == identity)
            {
                return Err(ARGUMENT_ERROR);
            }
            pins.push(if key == "--xml-source" {
                TrackSourcePin::Xml { identity, root }
            } else {
                TrackSourcePin::Rtp { identity, root }
            });
            continue;
        }
        if !matches!(
            key,
            "--root"
                | "--site"
                | "--principal"
                | "--include-values"
                | "--timeout-ms"
                | "--max-read-bytes"
                | "--max-read-attempts"
                | "--max-work-units"
                | "--max-projection-work"
                | "--max-frames"
                | "--max-objects"
                | "--max-tracklets"
                | "--max-vendor-gap-ms"
                | "--max-projection-bytes"
        ) || values.insert(key.to_owned(), pair[1].clone()).is_some()
        {
            return Err(ARGUMENT_ERROR);
        }
    }
    if pins.is_empty() {
        return Err(ARGUMENT_ERROR);
    }
    let root = PathBuf::from(values.get("--root").ok_or(ARGUMENT_ERROR)?);
    if !clean_absolute(&root) {
        return Err(ARGUMENT_ERROR);
    }
    let site = text(&values, "--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site)
        .map_err(|_| ARGUMENT_ERROR)?;
    if site.len() > 256 {
        return Err(ARGUMENT_ERROR);
    }
    let principal = values
        .get("--principal")
        .map(|value| value.to_str().ok_or(ARGUMENT_ERROR))
        .transpose()?
        .unwrap_or("operator:local-onvif-metadata")
        .to_owned();
    if principal.is_empty() || principal.len() > 256 || principal.chars().any(char::is_control) {
        return Err(ARGUMENT_ERROR);
    }
    let include_values = match values
        .get("--include-values")
        .map(|value| value.to_str().ok_or(ARGUMENT_ERROR))
        .transpose()?
    {
        None | Some("no") => false,
        Some("yes") => true,
        _ => return Err(ARGUMENT_ERROR),
    };
    let timeout_ns = number(&values, "--timeout-ms", 30_000, 60_000)? * 1_000_000;
    let mut limits = TrackReadLimits::default();
    limits.max_stored_bytes = number(
        &values,
        "--max-read-bytes",
        limits.max_stored_bytes,
        MAX_TRACK_STORED_BYTES,
    )?;
    limits.max_indexed_reads = number(
        &values,
        "--max-read-attempts",
        limits.max_indexed_reads,
        MAX_TRACK_INDEXED_READS,
    )?;
    limits.max_work_units = number(
        &values,
        "--max-work-units",
        limits.max_work_units as u64,
        MAX_TRACK_WORK_UNITS as u64,
    )? as usize;
    limits.projection.max_work_units = number(
        &values,
        "--max-projection-work",
        limits.projection.max_work_units,
        fss_reference::onvif::metadata::tracks::contract::MAX_TRACK_WORK_UNITS,
    )?;
    limits.projection.max_frames = number(
        &values,
        "--max-frames",
        limits.projection.max_frames as u64,
        MAX_TRACK_FRAMES as u64,
    )? as usize;
    limits.projection.max_objects = number(
        &values,
        "--max-objects",
        limits.projection.max_objects as u64,
        MAX_TRACK_OBJECTS as u64,
    )? as usize;
    limits.projection.max_tracklets = number(
        &values,
        "--max-tracklets",
        limits.projection.max_tracklets as u64,
        MAX_TRACK_OBJECTS as u64,
    )? as usize;
    limits.projection.max_output_bytes = number(
        &values,
        "--max-projection-bytes",
        limits.projection.max_output_bytes as u64,
        MAX_TRACK_REPORT_BYTES as u64,
    )? as usize;
    limits.projection.max_vendor_gap_ns = number(
        &values,
        "--max-vendor-gap-ms",
        limits.projection.max_vendor_gap_ns / 1_000_000,
        60_000,
    )? * 1_000_000;
    limits.validate().map_err(|_| ARGUMENT_ERROR)?;
    let mut approval = CanonicalEncoder::new();
    approval.text("fss.onvif_vendor_tracklet_cli_request.v1");
    approval.text(root.to_str().ok_or(ARGUMENT_ERROR)?);
    approval.text(&site);
    approval.text(&principal);
    approval.bool(include_values);
    approval.u64(timeout_ns);
    approval.u64(limits.max_stored_bytes);
    approval.u64(limits.max_indexed_reads);
    approval.u64(limits.max_work_units as u64);
    approval.digest(limits.projection.digest().map_err(|_| ARGUMENT_ERROR)?);
    approval.u64(pins.len() as u64);
    for pin in &pins {
        approval.text(pin.kind());
        approval.digest(pin.identity());
        approval.digest(pin.root());
    }
    Ok(Options {
        root,
        site,
        principal,
        pins,
        limits,
        include_values,
        timeout_ns,
        approval: ContentDigest::sha256(&approval.finish()),
    })
}

fn run(options: Options) -> Result<(CommandOutput, bool), &'static str> {
    // Native checkpoint costs cover both bounded source passes and pure cooperative work.
    let storage_operations = (options.limits.max_work_units as u64)
        .checked_mul(4)
        .and_then(|n| n.checked_add(4 * options.limits.max_indexed_reads + 4096))
        .ok_or(LIMIT_ERROR)?;
    let request = runtime::Request {
        approval: options.approval,
        principal: options.principal.clone(),
        timeout_ns: options.timeout_ns,
        bytes: options.limits.max_stored_bytes,
        network_bytes: 0,
        storage_operations,
        network: false,
        // Existing-store opening can perform publisher recovery housekeeping under its lock.
        write: true,
        secrets: false,
    };
    let report = runtime::run(request, |scope| {
        scope.input()?;
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:onvif-vendor-tracklets".into(),
            operation_id: OperationId::parse("operation:onvif-vendor-tracklets")
                .map_err(|_| ARGUMENT_ERROR)?,
            principal: options.principal.clone(),
            capabilities: vec![fss_reference::ADP_REPLAY_ROW_ID.into()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(options.limits.max_stored_bytes)
                .storage_operations(storage_operations)
                .build()
                .map_err(|_| LIMIT_ERROR)?,
            privacy_scope: "privacy:owner-private-vendor-metadata".into(),
            retention_scope: "retention:existing-vendor-metadata-query".into(),
            anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
            generation: 1,
        })
        .map_err(|_| ARGUMENT_ERROR)?;
        let cx = ReplayCx::from_context_authority_read_only(&authority, options.root.clone())
            .map_err(|_| ARGUMENT_ERROR)?
            .with_admission(|_| admission::check(scope));
        let result = RetainedTracklets::open(
            &options.root,
            &options.site,
            &options.pins,
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
        // Serialization remains inside the original native deadline/cancellation owner.
        // run() rechecks admission and drains before any complete report reaches stdout.
        report::render(&retained, options.include_values)
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
            "tracks".to_owned(),
            "--root".into(),
            "/tmp/fss-tracks-options".into(),
            "--site".into(),
            "site:tracks".into(),
            "--xml-source".into(),
            format!(
                "{}@{}",
                ContentDigest::sha256(b"first"),
                ContentDigest::sha256(b"first-root")
            ),
        ]
        .into_iter()
        .map(Into::into)
        .collect()
    }
    #[test]
    fn parse_preserves_mixed_order_and_defaults_to_private_values() -> Result<(), &'static str> {
        let mut args = args();
        args.extend([
            "--rtp-source".into(),
            format!(
                "{}@{}",
                ContentDigest::sha256(b"second"),
                ContentDigest::sha256(b"second-root")
            )
            .into(),
        ]);
        let parsed = parse(&args)?;
        assert!(!parsed.include_values);
        assert_eq!(
            parsed.pins.iter().map(|pin| pin.kind()).collect::<Vec<_>>(),
            ["xml", "rtp"]
        );
        Ok(())
    }
    #[test]
    fn refuses_unpinned_duplicates_unknown_and_nondecimal_bounds() {
        for extra in [
            vec!["--xml-source".into(), "sha256:missing-root".into()],
            vec!["--unknown".into(), "yes".into()],
            vec!["--max-frames".into(), "+1".into()],
            vec!["--site".into(), "site:duplicate".into()],
        ] {
            let mut candidate = args();
            candidate.extend(extra);
            assert!(parse(&candidate).is_err());
        }
        let mut duplicate = args();
        let pin = duplicate[6].clone();
        duplicate.extend(["--rtp-source".into(), pin]);
        assert!(parse(&duplicate).is_err());
    }
}
