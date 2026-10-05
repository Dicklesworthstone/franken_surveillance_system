#![forbid(unsafe_code)]
//! The lab scenarios run on the real crates (fss-2h5zq.12): each report's ledger sequence,
//! anchor root and publication root are checked against the deployment the run left on disk,
//! reopened independently by this test.

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{AgentView, BudgetVector, ContentDigest, KnowledgeState, OperationId, PrincipalId};
use fss_reference::agent_orient::{
    CLAIM_COVERAGE, OrientLimits, OrientRequest, orient_deployment, read_deployment,
};
use fss_reference::{ReferenceDeployment, ReplayCx};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> TestResult<Self> {
        for n in 0..100 {
            let p = std::env::temp_dir()
                .join(format!("fss-lab-real-{label}-{}-{n}", std::process::id()));
            match std::fs::create_dir(&p) {
                Ok(()) => return Ok(Self(p)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("temporary directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn lab(args: &[&str], root: &Path) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-lab"))
        .args(args)
        .arg("--root")
        .arg(root)
        .output()?)
}

/// The JSON text value of `"key":"..."`, or the number of `"key":N`.
fn field<'a>(json: &'a str, key: &str) -> TestResult<&'a str> {
    let marker = format!("\"{key}\":");
    let start = json.find(&marker).ok_or(format!("missing {key}"))? + marker.len();
    let rest = &json[start..];
    if let Some(quoted) = rest.strip_prefix('"') {
        let end = quoted.find('"').ok_or(format!("unterminated {key}"))?;
        Ok(&quoted[..end])
    } else {
        let end = rest.find([',', '}']).ok_or(format!("unterminated {key}"))?;
        Ok(&rest[..end])
    }
}

fn reopen(root: &Path) -> TestResult<ReferenceDeployment> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:lab-real-crates".into(),
        operation_id: OperationId::parse("operation:lab-real-crates")?,
        principal: "operator:lab-test".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".into(),
        retention_scope: "retention:ephemeral".into(),
        anchor_universe: ContentDigest::sha256(b"fss.lab.anchor_universe.v1"),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, root.to_path_buf())?;
    Ok(ReferenceDeployment::reopen(root, "site:lab", &cx)?)
}

/// (scenario, envelope, event disposition, absence certified, transient indeterminate)
const EXPECTED: [(&str, &str, &str, &str, &str); 6] = [
    // Quiet's complete witness is retained in a committed source coverage record and certified
    // by both readers (fss-tch7u; see `durable_reader_agrees_with_every_report`).
    ("quiet", "certified_quiet", "quiet", "true", "false"),
    ("raccoon", "benign_activity", "benign", "false", "false"),
    (
        "intrusion",
        "corroborated_threat",
        "corroborated_threat",
        "false",
        "false",
    ),
    (
        "sneaky",
        "protected_residual",
        "protected_residual",
        "false",
        "false",
    ),
    (
        "lost-ack",
        "corroborated_threat",
        "corroborated_threat",
        "false",
        "true",
    ),
    (
        "corrupt-source",
        "protected_residual",
        "protected_residual",
        "false",
        "false",
    ),
];

#[test]
fn every_report_matches_the_deployment_it_left_on_disk() -> TestResult {
    let directory = Directory::new("disk")?;
    for (scenario, envelope, disposition, absence, transient) in EXPECTED {
        let root = directory.0.join(scenario);
        let output = lab(&["run", scenario], &root)?;
        assert!(
            output.status.success(),
            "{scenario}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report = String::from_utf8(output.stdout)?;
        assert_eq!(field(&report, "schema")?, "fss.lab.scenario.v2");
        assert_eq!(field(&report, "scenario")?, scenario);
        assert_eq!(field(&report, "envelope")?, envelope, "{scenario}");
        assert_eq!(
            field(&report, "event_disposition")?,
            disposition,
            "{scenario}"
        );
        assert_eq!(field(&report, "absence_certified")?, absence, "{scenario}");
        assert_eq!(
            field(&report, "transient_indeterminate")?,
            transient,
            "{scenario}"
        );

        // The report's identities are what the real stores hold.
        let deployment = reopen(&root)?;
        let anchor = deployment.current_anchor();
        assert_eq!(
            field(&report, "ledger_sequence")?,
            anchor.commit_sequence.to_string(),
            "{scenario}"
        );
        assert_eq!(
            field(&report, "ledger_anchor_root")?,
            anchor.state_root.to_string(),
            "{scenario}"
        );
        let publication = field(&report, "publication_root")?;
        assert!(
            deployment
                .publisher()
                .visible_roots()
                .any(|root| root.root.to_string() == publication),
            "{scenario}: publication root {publication} is not a visible root on disk"
        );
    }
    Ok(())
}

/// `absence_certified` of every report is what the durable reader `fss orient` uses says about
/// the root the run left on disk: the site coverage cell is known and no protected
/// `absence-uncertified` event world survives. Read here independently of the lab.
#[test]
fn durable_reader_agrees_with_every_report() -> TestResult {
    let directory = Directory::new("durable")?;
    for (scenario, ..) in EXPECTED {
        let root = directory.0.join(scenario);
        let output = lab(&["run", scenario], &root)?;
        assert!(output.status.success(), "{scenario}");
        let report = String::from_utf8(output.stdout)?;

        let limits = OrientLimits::default();
        let snapshot = read_deployment(&root, &limits)?;
        assert_eq!(snapshot.events.len(), 1, "{scenario}");
        let orientation = orient_deployment(
            &snapshot,
            &OrientRequest {
                view: AgentView::EpistemicMap,
                principal: PrincipalId::parse("principal:lab-real-crates")?,
                budget_tokens: None,
            },
            &limits,
        )?;
        let frame = &orientation.publication.situation.capsule.frame;
        let coverage = frame
            .knowledge_cells
            .iter()
            .find(|cell| cell.claim_id() == CLAIM_COVERAGE)
            .map(|cell| cell.knowledge_state());
        let uncertified = frame
            .world_envelope
            .adversarial_residuals
            .iter()
            .any(|world| world.protected && world.world_id == "world:events:absence-uncertified");
        let durable = coverage == Some(KnowledgeState::Known) && !uncertified;
        assert_eq!(
            field(&report, "absence_certified")?,
            durable.to_string(),
            "{scenario}"
        );
        if scenario == "quiet" {
            // The retained source coverage record covers both domains, and the rejected event's
            // residual is retracted for that stated, verified reason (fss-tch7u).
            assert_eq!(coverage, Some(KnowledgeState::Known));
            assert!(!uncertified);
            assert!(report.contains(r#""absence":"certified""#));
        } else {
            assert!(!durable, "{scenario}");
        }
    }
    Ok(())
}

#[test]
fn reports_are_byte_identical_across_fresh_roots() -> TestResult {
    let directory = Directory::new("determinism")?;
    for (scenario, ..) in EXPECTED {
        let first = lab(
            &["run", scenario],
            &directory.0.join(format!("{scenario}-a")),
        )?;
        let second = lab(
            &["run", scenario],
            &directory.0.join(format!("{scenario}-b")),
        )?;
        assert!(
            first.status.success() && second.status.success(),
            "{scenario}"
        );
        assert_eq!(first.stdout, second.stdout, "{scenario}");
    }
    Ok(())
}

#[test]
fn a_missing_root_and_an_unknown_scenario_are_refused() -> TestResult {
    let missing = Command::new(env!("CARGO_BIN_EXE_fss-lab"))
        .args(["run", "quiet"])
        .output()?;
    assert_eq!(missing.status.code(), Some(2));
    assert!(missing.stdout.is_empty());
    assert!(String::from_utf8(missing.stderr)?.contains("\"schema\":\"fss.cli_diagnostic.v1\""));

    let directory = Directory::new("unknown")?;
    let unknown = lab(&["run", "unknown-scenario"], &directory.0.join("root"))?;
    assert_eq!(unknown.status.code(), Some(2));
    assert!(unknown.stdout.is_empty());
    assert!(String::from_utf8(unknown.stderr)?.contains("ERR-CLI-MALFORMED-VALUE-001"));
    Ok(())
}
