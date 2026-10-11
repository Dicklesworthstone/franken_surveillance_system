#![forbid(unsafe_code)]
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
//! Real-process recovery of committed evidence, with explicit custody and an independent pin.

#[path = "../src/custody_review/fixture.rs"]
mod fixture;

use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use fixture::{Fixture, TestResult, inventory};
use fss_cli::json_input::{self, Value};
use fss_core::{ContentDigest, ObjectId};
use fss_publication::SlotName;
use fss_reference::deployment_backup::{
    BACKUP_MANIFEST_FILENAME, BACKUP_PAYLOAD_DIRECTORY, BACKUP_PROFILE, BackupLimits,
    BackupManifest, FAMILY_RESTORE_FENCE, RESTORE_FENCE_OBJECT_ID, RESTORE_INCOMPLETE_FILENAME,
};
use fss_reference::{
    DeploymentLimits, ReferenceDeployment, ReferencePolicyAction, ReferencePolicyDecision,
};

fn arguments(
    action: &str,
    root: Option<&Path>,
    bundle: Option<&Path>,
    expected: Option<&str>,
) -> Vec<OsString> {
    let mut result = vec![action.into(), "--allow-originals".into()];
    for (option, path) in [("--root", root), ("--bundle", bundle)] {
        if let Some(path) = path {
            result.extend([option.into(), path.as_os_str().to_owned()]);
        }
    }
    if let Some(expected) = expected {
        result.extend(["--expect".into(), expected.into()]);
    }
    result
}

fn run(directory: &Path, arguments: &[OsString]) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-backup"))
        .current_dir(directory)
        .args(arguments)
        .output()?)
}

fn field<'a>(value: &'a Value, name: &str) -> TestResult<&'a Value> {
    value
        .object()
        .and_then(|fields| fields.get(name))
        .ok_or_else(|| format!("missing report field {name}").into())
}

fn report(output: &Output) -> TestResult<Value> {
    assert!(
        output.stderr.is_empty(),
        "backup must emit one complete JSON report"
    );
    assert!(
        output.stdout.len() <= 16 * 1024,
        "backup report exceeded its bound"
    );
    let text = std::str::from_utf8(&output.stdout)?;
    for original in [fixture::SOURCE, fixture::COUNTER] {
        assert!(
            !text.contains(std::str::from_utf8(original)?),
            "original evidence leaked"
        );
    }
    let value = json_input::parse(text)?;
    assert_eq!(
        field(&value, "format")?.text(),
        Some("fss.deployment_backup_report.v1")
    );
    Ok(value)
}

fn success(output: &Output, status: &str) -> TestResult<Value> {
    let value = report(output)?;
    assert!(output.status.success(), "backup refused: {value:?}");
    assert_eq!(field(&value, "status")?.text(), Some(status));
    assert_eq!(field(&value, "profile")?.text(), Some(BACKUP_PROFILE));
    Ok(value)
}

fn refused(output: &Output, error: &str, exit: i32) -> TestResult {
    let value = report(output)?;
    assert_eq!(
        output.status.code(),
        Some(exit),
        "unexpected exit: {value:?}"
    );
    assert_eq!(field(&value, "status")?.text(), Some("refused"));
    assert_eq!(field(&value, "error_id")?.text(), Some(error), "{value:?}");
    Ok(())
}

fn pin(report: &Value) -> TestResult<String> {
    let text = field(report, "manifest_digest")?
        .text()
        .ok_or("manifest digest")?;
    Ok(ContentDigest::parse(text)?.to_text())
}

fn same_snapshot(left: &Value, right: &Value) -> TestResult {
    for name in [
        "manifest_digest",
        "site",
        "source_anchor",
        "source_ledger_root",
        "source_effects_root",
        "file_count",
        "total_bytes",
        "deployment_limits",
    ] {
        assert_eq!(
            field(left, name)?,
            field(right, name)?,
            "snapshot changed: {name}"
        );
    }
    Ok(())
}

fn limit_values(limits: DeploymentLimits) -> [(&'static str, u64); 9] {
    [
        ("spool_object_max_bytes", limits.spool_object_max_bytes),
        ("spool_total_max_bytes", limits.spool_total_max_bytes),
        ("manifest_children_max", limits.manifest_children_max as u64),
        ("batch_entries_max", limits.batch_entries_max as u64),
        (
            "journal_record_max_bytes",
            u64::from(limits.journal_record_max_bytes),
        ),
        ("max_roots", limits.max_roots as u64),
        ("max_tombstones", limits.max_tombstones as u64),
        ("spool_max_objects", limits.spool_max_objects as u64),
        ("scan_max_objects", limits.scan_max_objects as u64),
    ]
}

fn with_limits(mut args: Vec<OsString>, limits: DeploymentLimits) -> Vec<OsString> {
    for (name, value) in limit_values(limits) {
        args.extend([
            format!("--{}", name.replace('_', "-")).into(),
            value.to_string().into(),
        ]);
    }
    args
}

#[test]
fn populated_roundtrip_preserves_custom_limits_evidence_and_the_committed_prefix() -> TestResult {
    let fixture = Fixture::new("backup-cli-roundtrip")?;
    let source = fixture.directory.join("bounded-deployment");
    let bundle = fixture.directory.join("approved-bundle");
    let destination = fixture.directory.join("restored-deployment");
    let limits = DeploymentLimits {
        spool_object_max_bytes: 128 * 1024,
        spool_total_max_bytes: 4 * 1024 * 1024,
        manifest_children_max: 64,
        batch_entries_max: 64,
        journal_record_max_bytes: 128 * 1024,
        max_roots: 32,
        max_tombstones: 24,
        spool_max_objects: 256,
        scan_max_objects: 512,
    };
    let cx = fixture::context(&fixture.directory)?;
    let mut deployment =
        ReferenceDeployment::open_with_limits(&source, fixture::SITE, limits, &cx)?;
    let slot = SlotName::parse("custody-source")?;
    let staged = deployment.stage_and_publish(&slot, &[fixture::SOURCE, fixture::COUNTER], &cx)?;
    deployment.publish_and_commit(&slot, &staged.manifest, fixture.event.interval, &cx)?;
    let mut event = fixture.event.clone();
    event.model_receipts = vec![staged.root];
    let published = deployment.publish_event(
        &ReferencePolicyDecision {
            event: event.clone(),
            action: ReferencePolicyAction::Hold,
        },
        &cx,
    )?;
    let source_anchor = deployment.current_anchor().clone();
    drop(deployment);
    cx.drain_and_finalize();
    let source_before = inventory(&source)?;

    let planned = success(
        &run(
            &fixture.directory,
            &with_limits(arguments("plan", Some(&source), None, None), limits),
        )?,
        "planned",
    )?;
    assert_eq!(field(&planned, "site")?.text(), Some(fixture::SITE));
    assert!(
        field(&planned, "file_count")?
            .integer()
            .ok_or("file count")?
            > 3
    );
    for (name, number) in limit_values(limits) {
        assert_eq!(
            field(field(&planned, "deployment_limits")?, name)?.integer(),
            Some(i128::from(number))
        );
    }
    // This approval exists before, and separately from, the bundle being authenticated.
    let approval = fixture.directory.join("approved-manifest.txt");
    fs::write(&approval, pin(&planned)?)?;
    let expected = fs::read_to_string(&approval)?;
    let admitted_files = field(&planned, "file_count")?
        .integer()
        .ok_or("file count")?;
    let admitted_bytes = field(&planned, "total_bytes")?
        .integer()
        .ok_or("total bytes")?;
    let exact_bounds = |mut args: Vec<OsString>| {
        args.extend([
            "--max-files".into(),
            admitted_files.to_string().into(),
            "--max-total-bytes".into(),
            admitted_bytes.to_string().into(),
        ]);
        args
    };
    let created = success(
        &run(
            &fixture.directory,
            &exact_bounds(with_limits(
                arguments("create", Some(&source), Some(&bundle), Some(&expected)),
                limits,
            )),
        )?,
        "created",
    )?;
    same_snapshot(&planned, &created)?;
    let bundle_before = inventory(&bundle)?;
    let inspected = success(
        &run(
            &fixture.directory,
            &exact_bounds(arguments("inspect", None, Some(&bundle), Some(&expected))),
        )?,
        "verified",
    )?;
    same_snapshot(&planned, &inspected)?;

    let manifest = BackupManifest::from_bytes(
        &fs::read(bundle.join(BACKUP_MANIFEST_FILENAME))?,
        ContentDigest::parse(&expected)?,
        BackupLimits::default(),
    )?;
    assert_eq!(manifest.deployment_limits(), &limits);
    assert_eq!(manifest.source_anchor(), &source_anchor);
    let restored = success(
        &run(
            &fixture.directory,
            &exact_bounds(arguments(
                "restore",
                Some(&destination),
                Some(&bundle),
                Some(&expected),
            )),
        )?,
        "restored",
    )?;
    same_snapshot(&planned, &restored)?;
    for report in [&created, &inspected, &restored] {
        let limits = field(report, "backup_limits")?;
        assert_eq!(field(limits, "max_files")?.integer(), Some(admitted_files));
        assert_eq!(
            field(limits, "max_total_bytes")?.integer(),
            Some(admitted_bytes)
        );
    }
    let restoration = field(&restored, "restoration")?;
    assert_eq!(
        field(restoration, "alert_effects_disabled")?.boolean(),
        Some(true)
    );
    assert_eq!(
        field(restoration, "effect_reconciliation_performed")?.boolean(),
        Some(false)
    );
    assert_ne!(
        field(restoration, "destination_anchor")?,
        field(&planned, "source_anchor")?
    );
    assert!(!destination.join(RESTORE_INCOMPLETE_FILENAME).exists());
    for file in manifest.files() {
        let original = fs::read(source.join(file.relative_path()))?;
        let retained = fs::read(
            bundle
                .join(BACKUP_PAYLOAD_DIRECTORY)
                .join(file.relative_path()),
        )?;
        assert!(
            original == retained,
            "bundle changed a retained file: {}",
            file.relative_path()
        );
        let recovered = fs::read(destination.join(file.relative_path()))?;
        if file.relative_path() == "ledger/journal.fssj" {
            assert!(
                recovered.starts_with(&original) && recovered.len() > original.len(),
                "restoration must retain the exact authority prefix and append its fence"
            );
        } else {
            assert!(
                original == recovered,
                "restore changed a retained file: {}",
                file.relative_path()
            );
        }
    }
    assert!(
        inventory(&source)? == source_before,
        "source changed during recovery"
    );
    assert!(
        inventory(&bundle)? == bundle_before,
        "inspection/restoration changed the bundle"
    );

    let cx = fixture::context(&fixture.directory)?;
    let recovered =
        ReferenceDeployment::open_with_limits(&destination, fixture::SITE, limits, &cx)?;
    assert_eq!(recovered.limits(), &limits);
    let (current_event, receipt) = recovered.current_event_authority(&event.event_id)?;
    assert_eq!(current_event, event);
    assert_eq!(receipt.event_root, published.event_root);
    assert!(recovered.publisher().spool().read(fixture.source)? == fixture::SOURCE);
    assert!(recovered.publisher().spool().read(fixture.counter)? == fixture::COUNTER);
    let fence = recovered
        .ledger()
        .current()
        .objects
        .get(&ObjectId::parse(RESTORE_FENCE_OBJECT_ID)?)
        .ok_or("missing retained restore fence")?;
    assert_eq!(fence.family, FAMILY_RESTORE_FENCE);
    assert_eq!(
        fence.payload_digest.to_text(),
        field(restoration, "fence_digest")?
            .text()
            .ok_or("fence digest")?
    );
    drop(recovered);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn malformed_authority_pins_and_restore_overrides_refuse_before_io() -> TestResult {
    let fixture = Fixture::new("backup-cli-preflight")?;
    let source = fixture.directory.join("must-not-open-source");
    let bundle = fixture.directory.join("must-not-open-bundle");
    let destination = fixture.directory.join("must-not-create-destination");
    let expected = ContentDigest::sha256(b"independently approved test snapshot").to_text();
    let plan = arguments("plan", Some(&source), None, None);
    let mut no_authority = plan.clone();
    no_authority.retain(|arg| arg != "--allow-originals");
    let mut cases = vec![
        Vec::new(),
        no_authority,
        arguments("create", Some(&source), Some(&bundle), None),
        arguments(
            "inspect",
            None,
            Some(&bundle),
            Some("not-a-manifest-digest"),
        ),
        arguments(
            "restore",
            Some(&destination),
            Some(&bundle),
            Some(&format!("sha256:{}", "0".repeat(64))),
        ),
        arguments("plan", Some(&source), None, Some(&expected)),
        arguments("inspect", Some(&source), Some(&bundle), Some(&expected)),
        vec!["plan".into(), "--root".into(), "--allow-originals".into()],
    ];
    for extra in [
        vec!["--allow-originals"],
        vec!["--unknown", "value"],
        vec!["--max-files", "0"],
        vec!["--max-files", "262145"],
        vec!["--max-files", "-1"],
        vec!["--max-files", "many"],
        vec!["--scan-max-objects", "1"],
        vec!["--max-files", "2", "--max-files", "3"],
    ] {
        let mut args = plan.clone();
        args.extend(extra.into_iter().map(OsString::from));
        cases.push(args);
    }
    for (action, root, extra) in [
        ("inspect", None, ["--max-roots", "32"]),
        (
            "restore",
            Some(destination.as_path()),
            ["--spool-max-objects", "256"],
        ),
    ] {
        let mut args = arguments(action, root, Some(&bundle), Some(&expected));
        args.extend(extra.into_iter().map(OsString::from));
        cases.push(args);
    }
    let before = inventory(&fixture.directory)?;
    for args in cases {
        refused(
            &run(&fixture.directory, &args)?,
            fss_cli::ERR_CLI_MALFORMED_VALUE,
            2,
        )?;
    }
    assert!(
        inventory(&fixture.directory)? == before,
        "invalid requests performed writes"
    );
    assert!(!source.exists() && !bundle.exists() && !destination.exists());
    Ok(())
}

#[test]
fn independent_pins_bounds_and_existing_destinations_never_merge_or_overwrite() -> TestResult {
    let fixture = Fixture::new("backup-cli-pins")?;
    let bundle = fixture.directory.join("bundle");
    let destination = fixture.directory.join("uncreated-restore");
    let source_before = inventory(&fixture.root)?;
    let planned = success(
        &run(
            &fixture.directory,
            &arguments("plan", Some(&fixture.root), None, None),
        )?,
        "planned",
    )?;
    let expected = pin(&planned)?;
    let wrong = ContentDigest::sha256(b"a different snapshot was approved").to_text();
    refused(
        &run(
            &fixture.directory,
            &arguments("create", Some(&fixture.root), Some(&bundle), Some(&wrong)),
        )?,
        "ERR-BACKUP-PIN-001",
        1,
    )?;
    assert!(!bundle.exists());
    let mut bounded = arguments(
        "create",
        Some(&fixture.root),
        Some(&bundle),
        Some(&expected),
    );
    bounded.extend(["--max-total-bytes".into(), "1".into()]);
    refused(
        &run(&fixture.directory, &bounded)?,
        "ERR-BACKUP-LIMIT-001",
        1,
    )?;
    assert!(!bundle.exists());
    success(
        &run(
            &fixture.directory,
            &arguments(
                "create",
                Some(&fixture.root),
                Some(&bundle),
                Some(&expected),
            ),
        )?,
        "created",
    )?;
    let bundle_before = inventory(&bundle)?;
    for (action, root) in [("inspect", None), ("restore", Some(destination.as_path()))] {
        refused(
            &run(
                &fixture.directory,
                &arguments(action, root, Some(&bundle), Some(&wrong)),
            )?,
            "ERR-BACKUP-PIN-001",
            1,
        )?;
    }
    assert!(!destination.exists());
    let occupied = fixture.directory.join("occupied-destination");
    fs::create_dir(&occupied)?;
    fs::write(
        occupied.join("operator-data"),
        b"existing destination must survive",
    )?;
    let occupied_before = inventory(&occupied)?;
    refused(
        &run(
            &fixture.directory,
            &arguments(
                "create",
                Some(&fixture.root),
                Some(&occupied),
                Some(&expected),
            ),
        )?,
        "ERR-BACKUP-DESTINATION-001",
        1,
    )?;
    refused(
        &run(
            &fixture.directory,
            &arguments("restore", Some(&occupied), Some(&bundle), Some(&expected)),
        )?,
        "ERR-BACKUP-DESTINATION-001",
        1,
    )?;
    assert!(
        inventory(&occupied)? == occupied_before,
        "existing destination was modified"
    );
    assert!(
        inventory(&fixture.root)? == source_before,
        "source was modified"
    );
    assert!(inventory(&bundle)? == bundle_before, "bundle was modified");
    Ok(())
}

#[test]
fn tampered_originals_refuse_inspection_and_restore_before_destination_reservation() -> TestResult {
    let fixture = Fixture::new("backup-cli-corruption")?;
    let bundle = fixture.directory.join("bundle");
    let destination = fixture.directory.join("must-not-activate");
    let source_before = inventory(&fixture.root)?;
    let planned = success(
        &run(
            &fixture.directory,
            &arguments("plan", Some(&fixture.root), None, None),
        )?,
        "planned",
    )?;
    let expected = pin(&planned)?;
    success(
        &run(
            &fixture.directory,
            &arguments(
                "create",
                Some(&fixture.root),
                Some(&bundle),
                Some(&expected),
            ),
        )?,
        "created",
    )?;
    let source_object = fixture.object_path(fixture.source);
    let copied_object = bundle
        .join(BACKUP_PAYLOAD_DIRECTORY)
        .join(source_object.strip_prefix(&fixture.root)?);
    let mut bytes = fs::read(&copied_object)?;
    *bytes.last_mut().ok_or("empty source envelope")? ^= 1;
    fs::write(&copied_object, bytes)?;
    let corrupt_before = inventory(&bundle)?;
    refused(
        &run(
            &fixture.directory,
            &arguments("inspect", None, Some(&bundle), Some(&expected)),
        )?,
        "ERR-BACKUP-VERIFY-001",
        1,
    )?;
    refused(
        &run(
            &fixture.directory,
            &arguments(
                "restore",
                Some(&destination),
                Some(&bundle),
                Some(&expected),
            ),
        )?,
        "ERR-BACKUP-VERIFY-001",
        1,
    )?;
    assert!(
        !destination.exists(),
        "unverified bundle reserved a destination"
    );
    assert!(
        inventory(&bundle)? == corrupt_before,
        "verification rewrote the corrupt bundle"
    );
    assert!(
        inventory(&fixture.root)? == source_before,
        "verification changed the source"
    );
    Ok(())
}

#[test]
fn populated_agent_process_roundtrip_inspects_history_without_restoring_authority() -> TestResult {
    use fss_core::{AgentView, PrincipalId};
    use fss_reference::deployment_backup::AGENT_BACKUP_PROFILE;
    use fss_reference::deployment_session::{OpenSessionRequest, open_session};

    let fixture = Fixture::new("backup-cli-agent")?;
    let mission = "Keep the unresolved case available after disk replacement";
    let opened = open_session(
        &fixture.root,
        &OpenSessionRequest {
            mission: mission.into(),
            objective: "Preserve exact uncertainty and custody".into(),
            principal: PrincipalId::parse("principal:agent-recovery-cli")?,
            view: AgentView::Brief,
            token_budget: 100_000,
        },
    )?;
    let source_before = inventory(&fixture.root)?;
    let planned_output = run(
        &fixture.directory,
        &arguments("plan", Some(&fixture.root), None, None),
    )?;
    let planned = report(&planned_output)?;
    assert!(planned_output.status.success(), "{planned:?}");
    assert_eq!(field(&planned, "profile")?.text(), Some(AGENT_BACKUP_PROFILE));
    assert_eq!(field(field(&planned, "agent_state")?, "session_count")?.integer(), Some(1));
    assert!(!std::str::from_utf8(&planned_output.stdout)?.contains(mission));
    let source_output = run(
        &fixture.directory,
        &arguments("agent-inspect", Some(&fixture.root), None, None),
    )?;
    let source_state = report(&source_output)?;
    assert!(source_output.status.success(), "{source_state:?}");
    assert_eq!(field(&source_state, "status")?.text(), Some("agent-inspected"));
    assert_eq!(field(&source_state, "historical_only")?.boolean(), Some(true));
    assert_eq!(field(&source_state, "restore_fence_present")?.boolean(), Some(false));
    assert_eq!(field(&source_state, "authority_granted")?.boolean(), Some(false));
    let sessions = field(&source_state, "sessions")?.array().ok_or("sessions array")?;
    assert_eq!(sessions.len(), 1);
    assert_eq!(
        field(field(&sessions[0], "session")?, "sessionId")?.text(),
        Some(opened.session.session_id.as_str()),
    );
    assert!(std::str::from_utf8(&source_output.stdout)?.contains(mission));
    let expected = pin(&planned)?;
    let bundle = fixture.directory.join("agent-bundle");
    let destination = fixture.directory.join("agent-restored");
    for (action, root, expected_status) in [
        ("create", Some(fixture.root.as_path()), "created"),
        ("inspect", None, "verified"),
        ("restore", Some(destination.as_path()), "restored"),
    ] {
        let output = run(
            &fixture.directory,
            &arguments(action, root, Some(&bundle), Some(&expected)),
        )?;
        let value = report(&output)?;
        assert!(output.status.success(), "{value:?}");
        assert_eq!(field(&value, "status")?.text(), Some(expected_status));
        assert_eq!(field(&value, "profile")?.text(), Some(AGENT_BACKUP_PROFILE));
        same_snapshot(&planned, &value)?;
        if action == "restore" {
            assert_eq!(
                field(field(&value, "restoration")?, "agent_mutations_disabled")?.boolean(),
                Some(true),
            );
        }
    }
    assert!(inventory(&fixture.root)? == source_before);
    let before = inventory(&destination)?;
    let output = run(
        &fixture.directory,
        &arguments("agent-inspect", Some(&destination), None, None),
    )?;
    let restored = report(&output)?;
    assert!(output.status.success(), "{restored:?}");
    assert_eq!(field(&restored, "restore_fence_present")?.boolean(), Some(true));
    assert_eq!(field(&restored, "authority_granted")?.boolean(), Some(false));
    for name in ["agent_state", "sessions", "workspace_revisions", "claims", "cases", "publications"] {
        assert_eq!(field(&restored, name)?, field(&source_state, name)?, "historical state changed: {name}");
    }
    assert!(inventory(&destination)? == before);
    let mut denied = arguments("agent-inspect", Some(&destination), None, None);
    denied.retain(|value| value != "--allow-originals");
    refused(&run(&fixture.directory, &denied)?, fss_cli::ERR_CLI_MALFORMED_VALUE, 2)?;
    assert!(inventory(&destination)? == before);
    Ok(())
}
