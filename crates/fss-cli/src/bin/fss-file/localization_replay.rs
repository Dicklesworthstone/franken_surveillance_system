#![forbid(unsafe_code)]
//! Immutable-ID localization inspection and explicit, read-only native replay.

use super::{ParseResult, RunResult, Values, localize, malformed, number, text, write_new};
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_geometry::{GeometryBasis, WorkBudget};
use fss_reference::ingest::RetainedReadLimits;
use fss_reference::ingest::recorded_decode::DecodeBudget;
use fss_reference::ingest::recorded_decode::video_budget::RecordedVideoDecodeBudget;
use fss_reference::ingest::twin_localization::RecordedLocalizationError;
use fss_reference::ingest::twin_localization::retained::RetainedLocalization;
use fss_reference::{ReferenceDeployment, ReplayCx};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(super) struct Action {
    identity: ContentDigest,
    expected_root: ContentDigest,
    expected_receipt: ContentDigest,
    verify: bool,
    decode_work: u64,
    geometry_work: u64,
    receipt: Option<PathBuf>,
    report: Option<PathBuf>,
}

pub(super) fn is_command(command: &str) -> bool {
    matches!(command, "read-localization" | "verify-localization")
}

pub(super) fn accepts_option(command: &str, option: &str) -> bool {
    is_command(command)
        && (matches!(
            option,
            "--localization-id"
                | "--expected-root"
                | "--expected-receipt"
                | "--geometry-work-units"
                | "--receipt-out"
        ) || (command == "verify-localization"
            && matches!(
                option,
                "--execute-perception" | "--work-units" | "--report-out"
            )))
}

fn digest(values: &Values, key: &str) -> ParseResult<ContentDigest> {
    let value = ContentDigest::parse(text(values, key)?)
        .map_err(|_| malformed("invalid localization pin"))?;
    if value.algorithm() != DigestAlgorithm::Sha256 || value.bytes() == [0; 32] {
        return Err(malformed("nonzero SHA-256 localization pins required"));
    }
    Ok(value)
}

pub(super) fn parse(command: &str, values: &Values) -> ParseResult<Action> {
    let verify = command == "verify-localization";
    if verify && text(values, "--execute-perception")? != "yes" {
        return Err(malformed("native replay requires --execute-perception yes"));
    }
    let decode_work = number(values, "--work-units", Some(100_000_000))?;
    let geometry_work = number(values, "--geometry-work-units", Some(2_000_000_000))?;
    if decode_work == 0 || geometry_work == 0 {
        return Err(malformed("positive execution budgets required"));
    }
    Ok(Action {
        identity: digest(values, "--localization-id")?,
        expected_root: digest(values, "--expected-root")?,
        expected_receipt: digest(values, "--expected-receipt")?,
        verify,
        decode_work,
        geometry_work,
        receipt: values.get("--receipt-out").map(PathBuf::from),
        report: values.get("--report-out").map(PathBuf::from),
    })
}

pub(super) fn run(
    action: &Action,
    deployment: &mut ReferenceDeployment,
    read_limits: RetainedReadLimits,
    root: &Path,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> RunResult<()> {
    let mut geometry = WorkBudget::new(action.geometry_work);
    let package =
        RetainedLocalization::open(deployment, action.identity, read_limits, &mut geometry, cx)?;
    if package.publication_root() != action.expected_root
        || package.receipt_digest() != action.expected_receipt
    {
        return Err(RecordedLocalizationError::RetainedPackage.into());
    }
    let mut jpeg = DecodeBudget::new(action.decode_work);
    let mut video = RecordedVideoDecodeBudget::new(action.decode_work);
    let report = if action.verify {
        let result = package.verify_by_replay(
            deployment,
            GeometryBasis::new(1, 1)?,
            &mut jpeg,
            &mut video,
            &mut geometry,
            cx,
        )?;
        Some(localize::report(
            &result,
            package.twin_digest().bytes(),
            result.result().localization.matches.atlas,
            package.atlas_package().bytes(),
        ))
    } else {
        None
    };
    if let Some(path) = &action.receipt {
        write_new(path, package.receipt_bytes(), root, cx)?;
    }
    if let (Some(path), Some(report)) = (&action.report, &report) {
        write_new(path, report.as_bytes(), root, cx)?;
    }
    writeln!(
        out,
        "operation={}",
        if action.verify {
            "verify-localization"
        } else {
            "read-localization"
        }
    )?;
    writeln!(out, "localization_identity={}", package.identity())?;
    writeln!(out, "localization_root={}", package.publication_root())?;
    writeln!(out, "localization_receipt={}", package.receipt_digest())?;
    writeln!(out, "native_replay_verified={}", action.verify)?;
    writeln!(out, "calibration_activated=false")?;
    writeln!(out, "coverage_certifiable=false")?;
    writeln!(out, "jpeg_work_units={}", jpeg.used())?;
    writeln!(out, "video_work_units={}", video.used())?;
    writeln!(out, "total_geometry_work_units={}", geometry.used())?;
    if let Some(report) = report {
        writeln!(out, "localization_report={report}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    const PIN: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    fn args(command: &str) -> Vec<OsString> {
        [
            command,
            "--root",
            "/unused",
            "--site",
            "site:localize-cli",
            "--localization-id",
            PIN,
            "--expected-root",
            PIN,
            "--expected-receipt",
            PIN,
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }
    #[test]
    fn reading_is_explicitly_not_execution_and_accepts_no_ignored_source_override() {
        assert!(super::super::parse(&args("read-localization")).is_ok());
        for key in [
            "--import-id",
            "--manifest-out",
            "--camera",
            "--work-units",
            "--execute-perception",
            "--report-out",
        ] {
            let mut values = args("read-localization");
            values.extend([key.into(), "yes".into()]);
            assert!(super::super::parse(&values).is_err(), "{key}");
        }
    }
    #[test]
    fn native_replay_requires_explicit_execution_and_all_three_pins() {
        let mut values = args("verify-localization");
        assert!(super::super::parse(&values).is_err());
        values.extend(["--execute-perception".into(), "yes".into()]);
        assert!(super::super::parse(&values).is_ok());
        for key in ["--localization-id", "--expected-root", "--expected-receipt"] {
            let mut missing = values.clone();
            let index = missing
                .iter()
                .position(|arg| arg == key)
                .expect("fixture key");
            missing.drain(index..index + 2);
            assert!(super::super::parse(&missing).is_err(), "{key}");
        }
        let last = values.len() - 1;
        values[last] = "no".into();
        assert!(super::super::parse(&values).is_err());
    }
}
