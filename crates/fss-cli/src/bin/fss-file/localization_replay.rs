#![forbid(unsafe_code)]
//! Immutable localization custody inspection and explicit native replay.

use super::{ParseResult, RunResult, Values, localize, malformed, number, text, write_new};
use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, DigestAlgorithm, OperationId, RootAuthoritySpec,
};
use fss_geometry::{GeometryBasis, WorkBudget};
use fss_reference::agent_orient::OrientLimits;
use fss_reference::ingest::RetainedReadLimits;
use fss_reference::ingest::recorded_decode::DecodeBudget;
use fss_reference::ingest::recorded_decode::video_budget::RecordedVideoDecodeBudget;
use fss_reference::ingest::twin_localization::RecordedLocalizationError;
use fss_reference::ingest::twin_localization::retained::RetainedLocalization;
use fss_reference::retained_source::{
    ImmutableRetainedReadLimits, ImmutableRetainedSource, RetainedSource,
};
use fss_reference::{ReferenceDeployment, ReplayCx};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MAX_READ_BYTES: usize = 256 * 1024 * 1024;
const MAX_READ_OBJECTS: usize = 65_536;
const READ_DEADLINE: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub(super) struct Action {
    identity: ContentDigest,
    expected_root: ContentDigest,
    expected_receipt: ContentDigest,
    verify: bool,
    decode_work: u64,
    geometry_work: u64,
    read_limits: ImmutableRetainedReadLimits,
    receipt: Option<PathBuf>,
    report: Option<PathBuf>,
}

impl Action {
    pub(super) fn is_read_only(&self) -> bool {
        !self.verify
    }
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
        ) || (command == "read-localization"
            && matches!(option, "--max-read-bytes" | "--max-read-objects"))
            || (command == "verify-localization"
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
    let read_bound = |key: &str, maximum: usize| -> ParseResult<usize> {
        if !values.contains_key(key) {
            return Ok(maximum);
        }
        let text = text(values, key)?;
        text.parse::<usize>()
            .ok()
            .filter(|value| (1..=maximum).contains(value) && value.to_string() == text)
            .ok_or_else(|| {
                malformed("immutable read allowance must be a bounded canonical positive integer")
            })
    };
    Ok(Action {
        identity: digest(values, "--localization-id")?,
        expected_root: digest(values, "--expected-root")?,
        expected_receipt: digest(values, "--expected-receipt")?,
        verify,
        decode_work,
        geometry_work,
        read_limits: ImmutableRetainedReadLimits {
            snapshot: OrientLimits::default(),
            max_read_bytes: read_bound("--max-read-bytes", MAX_READ_BYTES)?,
            max_read_objects: read_bound("--max-read-objects", MAX_READ_OBJECTS)?,
        },
        receipt: values.get("--receipt-out").map(PathBuf::from),
        report: values.get("--report-out").map(PathBuf::from),
    })
}

fn check_pins(action: &Action, package: &RetainedLocalization) -> RunResult<()> {
    if package.publication_root() != action.expected_root
        || package.receipt_digest() != action.expected_receipt
    {
        return Err(RecordedLocalizationError::RetainedPackage.into());
    }
    Ok(())
}

/// Inspect an existing deployment without opening a publisher or recovering any journal.
/// The complete receipt is released only after the original allowance covers all rereads.
pub(super) fn read_only(
    action: &Action,
    read_limits: RetainedReadLimits,
    root: &Path,
    site: &str,
    principal: &str,
    out: &mut impl Write,
) -> RunResult<()> {
    if action.verify {
        return Err("native replay requires the explicit perception path".into());
    }
    // Only path metadata is inspected outside the shared native payload allowance.
    if !fs::symlink_metadata(root)?.file_type().is_dir()
        || !fs::symlink_metadata(root.join("LAYOUT"))?
            .file_type()
            .is_file()
    {
        return Err("existing non-symlink deployment required".into());
    }
    let root = fs::canonicalize(root)?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:localization-read-cli".into(),
        operation_id: OperationId::parse("operation:localization-read-cli")?,
        principal: principal.to_owned(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(action.read_limits.max_read_bytes as u64)
            .storage_operations(action.read_limits.max_read_objects as u64)
            .build()?,
        privacy_scope: "privacy:current-deployment-policy".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(site.as_bytes()),
        generation: 1,
    })?;
    authority.validate()?;
    let cx = ReplayCx::from_context_authority_read_only(&authority, root.clone())?;
    let started = Instant::now();
    let cancelled = || started.elapsed() >= READ_DEADLINE;
    let result = (|| -> RunResult<()> {
        let deployment =
            ImmutableRetainedSource::open_cancellable(&root, action.read_limits, &cx, &cancelled)?;
        if deployment.site_lineage() != site {
            return Err("deployment site does not match".into());
        }
        let mut geometry = WorkBudget::new(action.geometry_work);
        let package = RetainedLocalization::open(
            &deployment,
            action.identity,
            read_limits,
            &mut geometry,
            &cx,
        )?;
        check_pins(action, &package)?;
        let output = output(&package, false, 0, 0, geometry.used(), None)?;
        deployment.revalidate_snapshot_metadata()?;
        deployment.revalidate()?;
        if started.elapsed() >= READ_DEADLINE {
            return Err("localization inspection exceeded its cooperative deadline".into());
        }
        if let Some(path) = &action.receipt {
            write_new(path, package.receipt_bytes(), &root, &cx)?;
        }
        out.write_all(&output)?;
        Ok(())
    })();
    cx.drain_and_finalize();
    result
}

pub(super) fn run(
    action: &Action,
    deployment: &mut ReferenceDeployment,
    read_limits: RetainedReadLimits,
    root: &Path,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> RunResult<()> {
    if !action.verify {
        return Err("localization inspection requires the immutable read path".into());
    }
    let mut geometry = WorkBudget::new(action.geometry_work);
    let package =
        RetainedLocalization::open(deployment, action.identity, read_limits, &mut geometry, cx)?;
    check_pins(action, &package)?;
    let mut jpeg = DecodeBudget::new(action.decode_work);
    let mut video = RecordedVideoDecodeBudget::new(action.decode_work);
    let result = package.verify_by_replay(
        deployment,
        GeometryBasis::new(1, 1)?,
        &mut jpeg,
        &mut video,
        &mut geometry,
        cx,
    )?;
    let report = localize::report(
        &result,
        package.twin_digest().bytes(),
        result.result().localization.matches.atlas,
        package.atlas_package().bytes(),
    );
    let output = output(
        &package,
        true,
        jpeg.used(),
        video.used(),
        geometry.used(),
        Some(&report),
    )?;
    if let Some(path) = &action.receipt {
        write_new(path, package.receipt_bytes(), root, cx)?;
    }
    if let Some(path) = &action.report {
        write_new(path, report.as_bytes(), root, cx)?;
    }
    out.write_all(&output)?;
    Ok(())
}

fn output(
    package: &RetainedLocalization,
    verified: bool,
    jpeg_work: u64,
    video_work: u64,
    geometry_work: u64,
    report: Option<&str>,
) -> RunResult<Vec<u8>> {
    let mut out = Vec::new();
    writeln!(
        out,
        "operation={}",
        if verified {
            "verify-localization"
        } else {
            "read-localization"
        }
    )?;
    writeln!(out, "localization_identity={}", package.identity())?;
    writeln!(out, "localization_root={}", package.publication_root())?;
    writeln!(out, "localization_receipt={}", package.receipt_digest())?;
    writeln!(out, "native_replay_verified={verified}")?;
    writeln!(out, "calibration_activated=false")?;
    writeln!(out, "coverage_certifiable=false")?;
    writeln!(out, "jpeg_work_units={jpeg_work}")?;
    writeln!(out, "video_work_units={video_work}")?;
    writeln!(out, "total_geometry_work_units={geometry_work}")?;
    if let Some(report) = report {
        writeln!(out, "localization_report={report}")?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn shared_read_allowances_are_bounded_and_unavailable_on_the_perception_path() {
        let mut bounded = args("read-localization");
        bounded.extend([
            "--max-read-bytes".into(),
            "4096".into(),
            "--max-read-objects".into(),
            "32".into(),
        ]);
        let options = super::super::parse(&bounded)
            .expect("bounded read")
            .expect("read command");
        let super::super::Action::LocalizationReplay(action) = options.action else {
            panic!("localization read action");
        };
        assert!(action.is_read_only());
        assert_eq!(action.read_limits.max_read_bytes, 4096);
        assert_eq!(action.read_limits.max_read_objects, 32);
        for (flag, value) in [
            ("--max-read-bytes", "0"),
            ("--max-read-bytes", "268435457"),
            ("--max-read-bytes", "01"),
            ("--max-read-objects", "0"),
            ("--max-read-objects", "65537"),
            ("--max-read-objects", "+1"),
        ] {
            let mut values = args("read-localization");
            values.extend([flag.into(), value.into()]);
            assert!(super::super::parse(&values).is_err(), "{flag}={value}");
        }
        for flag in ["--max-read-bytes", "--max-read-objects"] {
            let mut values = args("verify-localization");
            values.extend([
                "--execute-perception".into(),
                "yes".into(),
                flag.into(),
                "1".into(),
            ]);
            assert!(super::super::parse(&values).is_err(), "{flag}");
        }
    }
}
