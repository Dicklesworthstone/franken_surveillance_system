#![forbid(unsafe_code)]
//! Contract tests for durable work claims (FSS-226) through the real `fss` binary: two sessions of
//! one mission coordinate one case through exclusive, journaled claims.
//!
//! 1. a claim reserves exact case work; the same work claimed by the other session is a typed
//!    conflict, so it is never duplicated;
//! 2. only the holder changes a claim (CAS on the exact revision); a dependent claim cannot
//!    activate before its dependency completes;
//! 3. live claims are leases in the situation (one affordance per claim) and in the handoff's
//!    `leases`; completed and released claims are not;
//! 4. a transfer hands the work to the other session, which must activate it explicitly;
//! 5. every answer is the registered `fss.agent_cognitive_envelope.v1` (AOP-006) and conforms to
//!    its schema; the authority ledger, effect journal, spool, and `LAYOUT` never change.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use fss_cli::json_input::{Value, parse};
use fss_core::{ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SITE: &str = "site:work-claim-cli";
const CASE: &str = "case:east-door";
const MISSION: &str = "Keep the east door under watch.";
const OBJECTIVE: &str = "Know whether anyone entered through the east door.";

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-work-claim-cli-{name}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(std::io::Error::other("test directory capacity").into())
    }
}

impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn empty_deployment(directory: &OwnedDirectory) -> TestResult<PathBuf> {
    let root = directory.0.join("deployment");
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:work-claim-cli".to_owned(),
        operation_id: OperationId::parse("operation:work-claim-cli")?,
        principal: "operator:work-claim-cli".to_owned(),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_string()],
        deadline: None,
        priority: 10,
        budgets: fss_core::BudgetVector::default(),
        privacy_scope: "privacy:internal".to_string(),
        retention_scope: "retention:ephemeral".to_string(),
        anchor_universe: ContentDigest::sha256(b"work-claim-cli"),
        generation: 1,
    })?;
    let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
        &authority,
        directory.0.join("cx"),
    )?);
    drop(ReferenceDeployment::open(&root, SITE, &cx)?);
    Ok(root)
}

fn run_fss(args: &[OsString]) -> TestResult<(Option<i32>, String)> {
    let output = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(args)
        .output()?;
    Ok((output.status.code(), String::from_utf8(output.stdout)?))
}

fn field<'a>(value: &'a Value, path: &[&str]) -> TestResult<&'a Value> {
    let mut current = value;
    for key in path {
        current = current
            .object()
            .and_then(|fields| fields.get(*key))
            .ok_or_else(|| format!("missing field {key}"))?;
    }
    Ok(current)
}

fn text<'a>(value: &'a Value, path: &[&str]) -> TestResult<&'a str> {
    field(value, path)?
        .text()
        .ok_or_else(|| format!("{path:?} is not a string").into())
}

fn texts(value: &Value, path: &[&str]) -> TestResult<Vec<String>> {
    field(value, path)?
        .array()
        .ok_or("not an array")?
        .iter()
        .map(|item| {
            item.text()
                .map(ToOwned::to_owned)
                .ok_or_else(|| "not a string".into())
        })
        .collect()
}

/// Every file of the authority ledger, the effect journal, the spool, and `LAYOUT`.
fn authority_tree(root: &Path) -> TestResult<BTreeMap<PathBuf, ContentDigest>> {
    let mut out = BTreeMap::new();
    let mut pending: Vec<PathBuf> = ["ledger", "effects", "objects", "LAYOUT"]
        .iter()
        .map(|name| root.join(name))
        .filter(|path| path.exists())
        .collect();
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            for entry in fs::read_dir(&path)? {
                pending.push(entry?.path());
            }
        } else {
            out.insert(
                path.strip_prefix(root)?.to_path_buf(),
                ContentDigest::sha256(&fs::read(&path)?),
            );
        }
    }
    Ok(out)
}

fn raw_payload(stdout: &str) -> TestResult<&str> {
    let start = stdout.find(",\"payload\":").ok_or("payload missing")? + ",\"payload\":".len();
    let end = stdout
        .find(",\"payloadDigest\":")
        .ok_or("payload digest missing")?;
    Ok(&stdout[start..end])
}

fn assert_conforms(schema: &str, instance: &str, scratch: &Path) -> TestResult {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let file = scratch.join(format!(
        "instance-{}.json",
        ContentDigest::sha256(format!("{schema}\n{instance}").as_bytes())
            .to_text()
            .replace(':', "-")
    ));
    fs::write(&file, instance)?;
    let output = Command::new("python3")
        .arg("-B")
        .arg(root.join("scripts/json_instance_validate.py"))
        .arg(root.join("schemas").join(schema))
        .arg(&file)
        .output()?;
    fs::remove_file(&file)?;
    assert!(
        output.status.success(),
        "output does not conform to schemas/{schema}: {}{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    Ok(())
}

/// Validates the envelope and its payload against their registered schemas.
fn conforming(stdout: &str, scratch: &Path) -> TestResult<Value> {
    assert_conforms(
        "agent_response_envelope.v1.json",
        stdout.trim_end(),
        scratch,
    )?;
    let envelope = parse(stdout.trim_end())?;
    let payload = raw_payload(stdout)?;
    if payload != "null" {
        let schema = text(&envelope, &["payloadSchema"])?;
        assert_conforms(
            &format!("{}.json", schema.trim_start_matches("fss.")),
            payload,
            scratch,
        )?;
    }
    Ok(envelope)
}

struct Agent {
    root: PathBuf,
    scratch: PathBuf,
    session: String,
}

impl Agent {
    /// Opens a session of the shared mission; `budget` distinguishes the two sessions.
    fn open(directory: &OwnedDirectory, root: &Path, budget: &str) -> TestResult<Self> {
        let (code, stdout) = run_fss(&[
            "session".into(),
            "open".into(),
            "--json".into(),
            "--root".into(),
            root.as_os_str().to_owned(),
            "--mission".into(),
            MISSION.into(),
            "--objective".into(),
            OBJECTIVE.into(),
            "--budget-tokens".into(),
            budget.into(),
        ])?;
        assert_eq!(code, Some(0), "{stdout}");
        let scratch = directory.0.join(format!("scratch-{budget}"));
        fs::create_dir_all(&scratch)?;
        Ok(Self {
            root: root.to_path_buf(),
            scratch,
            session: text(&parse(stdout.trim_end())?, &["sessionId"])?.to_owned(),
        })
    }

    fn run(&self, transition: &str, extra: &[&str]) -> TestResult<(Option<i32>, Value)> {
        let mut args: Vec<OsString> = vec![
            "investigate".into(),
            "--json".into(),
            "--root".into(),
            self.root.as_os_str().to_owned(),
            "--session".into(),
            self.session.clone().into(),
            "--transition".into(),
            transition.into(),
        ];
        args.extend(extra.iter().map(OsString::from));
        let (code, stdout) = run_fss(&args)?;
        if code == Some(2) {
            return Ok((code, Value::Null));
        }
        let envelope = conforming(&stdout, &self.scratch)?;
        assert_eq!(text(&envelope, &["operationId"])?, "AOP-006");
        Ok((code, envelope))
    }

    /// An answered claim transition: exit 0, a cognitive-envelope payload.
    fn ok(&self, transition: &str, extra: &[&str]) -> TestResult<Value> {
        let (code, envelope) = self.run(transition, extra)?;
        assert_eq!(code, Some(0), "{transition}: {envelope:?}");
        assert_eq!(
            text(&envelope, &["payloadSchema"])?,
            "fss.agent_cognitive_envelope.v1"
        );
        Ok(envelope)
    }

    /// A typed refusal with `error_id`.
    fn refused(&self, transition: &str, extra: &[&str], error_id: &str) -> TestResult<Value> {
        let (code, envelope) = self.run(transition, extra)?;
        assert_eq!(code, Some(5), "{transition}: {envelope:?}");
        assert_eq!(text(&envelope, &["errorId"])?, error_id, "{envelope:?}");
        Ok(envelope)
    }

    /// Claims `work` of the case, returning (claim id, revision digest).
    fn claim(&self, work: &str, extra: &[&str]) -> TestResult<(String, String)> {
        let mut args = vec!["--case", CASE, "--work", work];
        args.extend_from_slice(extra);
        let claimed = self.ok("claim", &args)?;
        Ok((statement_of(&claimed)?.0, fingerprint(&claimed)?))
    }

    /// The handoff's `leases`.
    fn leases(&self) -> TestResult<Vec<String>> {
        let (code, stdout) = run_fss(&[
            "handoff".into(),
            "--json".into(),
            "--root".into(),
            self.root.as_os_str().to_owned(),
            "--session".into(),
            self.session.clone().into(),
        ])?;
        assert_eq!(code, Some(0), "{stdout}");
        texts(&conforming(&stdout, &self.scratch)?, &["payload", "leases"])
    }

    /// The affordance identities of the session's situation (from an answered list).
    fn affordances(&self) -> TestResult<Vec<String>> {
        let listed = self.ok("claim-list", &[])?;
        Ok(field(&listed, &["affordances"])?
            .array()
            .ok_or("affordances")?
            .iter()
            .filter_map(|item| {
                item.object()
                    .and_then(|fields| fields.get("affordanceId"))
                    .and_then(Value::text)
                    .map(ToOwned::to_owned)
            })
            .collect())
    }
}

fn fingerprint(envelope: &Value) -> TestResult<String> {
    Ok(text(envelope, &["decisionFingerprint"])?.to_owned())
}

/// The (claim id, statement) of a single-claim answer.
fn statement_of(envelope: &Value) -> TestResult<(String, String)> {
    let propositions = field(envelope, &["payload", "epistemic", "propositions"])?
        .array()
        .ok_or("propositions")?;
    assert_eq!(propositions.len(), 1);
    Ok((
        text(&propositions[0], &["id"])?.to_owned(),
        text(&propositions[0], &["statement"])?.to_owned(),
    ))
}

fn case_document() -> String {
    format!(
        r#"{{"caseId":"{CASE}","question":"Did a person enter through the east door?",
"decisionInformed":"Whether to prepare an owner alert",
"hypotheses":[{{"hypothesisId":"h:entry","description":"A person entered","predictions":["the track continues indoors"]}},
{{"hypothesisId":"h:passerby","description":"A person passed the door without entering","predictions":["the track leaves the frame eastward"]}}],
"knowns":[],"unknowns":[{{"statementId":"u:indoor","text":"Whether the hallway camera saw the person"}}],
"discriminators":[{{"discriminatorId":"d:hallway","description":"Hallway frames after the door event","separates":["h:entry","h:passerby"],"expectedOutcomes":["a person in the hallway","an empty hallway"]}}],
"probes":["probe:hallway-frames"],"stopRules":["one hypothesis supported by an independent observation"],"decisionWindowNs":3600000000000}}"#
    )
}

#[test]
fn two_sessions_coordinate_one_case_through_exclusive_claims() -> TestResult {
    let directory = OwnedDirectory::new("coordinate")?;
    let root = empty_deployment(&directory)?;
    let first = Agent::open(&directory, &root, "3000")?;
    let second = Agent::open(&directory, &root, "4000")?;
    assert_ne!(first.session, second.session);
    let case_file = first.scratch.join("case.json");
    fs::write(&case_file, case_document())?;
    let (code, _) = first.run("open", &["--case-file", &case_file.to_string_lossy()])?;
    assert_eq!(code, Some(0));
    let authority_before = authority_tree(&root)?;

    // The first session reserves the probe; the second can never duplicate it.
    let (probe, opened) = first.claim("probe:probe:hallway-frames", &[])?;
    let (id, statement) = statement_of(&first.ok("claim-inspect", &["--claim", &probe])?)?;
    assert_eq!(id, probe);
    assert!(statement.contains(" is claimed"), "{statement}");
    assert!(statement.contains(&first.session), "{statement}");
    assert!(
        statement.contains("confers no effect authority"),
        "{statement}"
    );
    second.refused(
        "claim",
        &["--case", CASE, "--work", "probe:probe:hallway-frames"],
        "ERR-AGENT-WORK-CLAIM-CONFLICT-001",
    )?;
    // Work that is not an element of the case is unavailable, never reserved.
    second.refused(
        "claim",
        &["--case", CASE, "--work", "probe:probe:roof"],
        "ERR-OP-PRECONDITION-FAILED-001",
    )?;

    // The second session takes the discriminator, which depends on the probe's result.
    let (discriminator, waiting) =
        second.claim("discriminator:d:hallway", &["--depends", &probe])?;
    second.refused(
        "claim-activate",
        &["--claim", &discriminator, "--expected", &waiting],
        "ERR-OP-PRECONDITION-FAILED-001",
    )?;
    // Only the holder changes a claim.
    second.refused(
        "claim-activate",
        &["--claim", &probe, "--expected", &opened],
        "ERR-PRECONDITION-STALE-001",
    )?;
    // Both reservations are leases of the mission: each holder's next moves name its own claim
    // (a claim held elsewhere is a blocked entry, never a next move), and each handoff lists both.
    let claim_moves = |agent: &Agent| -> TestResult<Vec<String>> {
        Ok(agent
            .affordances()?
            .into_iter()
            .filter(|affordance| affordance.starts_with("affordance:claim:"))
            .collect())
    };
    assert_eq!(
        claim_moves(&first)?,
        vec![format!("affordance:claim:{probe}")]
    );
    assert_eq!(
        claim_moves(&second)?,
        vec![format!("affordance:claim:{discriminator}")]
    );
    let mut expected = vec![probe.clone(), discriminator.clone()];
    expected.sort();
    assert_eq!(first.leases()?, expected);

    let artifact = ContentDigest::sha256(b"hallway frames 02:14-02:16").to_text();
    let active = fingerprint(&first.ok(
        "claim-activate",
        &["--claim", &probe, "--expected", &opened],
    )?)?;
    let progressed = fingerprint(&first.ok(
        "claim-progress",
        &[
            "--claim",
            &probe,
            "--expected",
            &active,
            "--artifact",
            &artifact,
        ],
    )?)?;
    // A stale revision is refused even for the holder.
    first.refused(
        "claim-release",
        &["--claim", &probe, "--expected", &active],
        "ERR-PRECONDITION-STALE-001",
    )?;
    let completed = first.ok(
        "claim-complete",
        &[
            "--claim",
            &probe,
            "--expected",
            &progressed,
            "--result",
            &artifact,
        ],
    )?;
    assert!(statement_of(&completed)?.1.contains(" is completed"));

    // With its dependency complete, the dependent claim activates.
    let running = fingerprint(&second.ok(
        "claim-activate",
        &["--claim", &discriminator, "--expected", &waiting],
    )?)?;
    assert_eq!(second.leases()?, vec![discriminator.clone()]);

    // The holder hands the work to the first session, which must activate it explicitly.
    let transferred = fingerprint(&second.ok(
        "claim-transfer",
        &[
            "--claim",
            &discriminator,
            "--expected",
            &running,
            "--recipient",
            &first.session,
        ],
    )?)?;
    second.refused(
        "claim-release",
        &["--claim", &discriminator, "--expected", &transferred],
        "ERR-PRECONDITION-STALE-001",
    )?;
    let (_, statement) = statement_of(&first.ok("claim-inspect", &["--claim", &discriminator])?)?;
    assert!(statement.contains(&first.session), "{statement}");
    let resumed = fingerprint(&first.ok(
        "claim-activate",
        &["--claim", &discriminator, "--expected", &transferred],
    )?)?;
    let released = first.ok(
        "claim-release",
        &["--claim", &discriminator, "--expected", &resumed],
    )?;
    assert!(statement_of(&released)?.1.contains(" is released"));
    assert!(first.leases()?.is_empty());
    assert!(
        !first
            .affordances()?
            .iter()
            .any(|affordance| affordance.starts_with("affordance:claim:"))
    );

    // The list keeps every claim (terminal ones included) as audit-visible facts.
    let listed = first.ok("claim-list", &[])?;
    let ids: Vec<String> = field(&listed, &["payload", "epistemic", "propositions"])?
        .array()
        .ok_or("propositions")?
        .iter()
        .map(|proposition| Ok(text(proposition, &["id"])?.to_owned()))
        .collect::<TestResult<_>>()?;
    assert_eq!(ids, expected);

    // Coordination never touched the authority ledger, the effect journal, or the spool.
    assert_eq!(authority_tree(&root)?, authority_before);
    Ok(())
}

#[test]
fn malformed_claim_transitions_are_argument_errors() -> TestResult {
    let directory = OwnedDirectory::new("malformed")?;
    let root = empty_deployment(&directory)?;
    let agent = Agent::open(&directory, &root, "3000")?;
    for (transition, extra) in [
        ("claim", vec!["--case", CASE, "--work", "everything"]),
        (
            "claim",
            vec!["--case", CASE, "--work", "case", "--lease-ms", "0"],
        ),
        (
            "claim",
            vec!["--case", CASE, "--work", "case", "--lease-ms", "300001"],
        ),
        ("claim-activate", vec!["--claim", "claim:x"]),
        (
            "claim-progress",
            vec!["--claim", "claim:x", "--expected", "sha256:00"],
        ),
        ("claim-inspect", vec!["--claim", "claim:x", "--case", CASE]),
        ("claim-everything", vec![]),
    ] {
        let (code, _) = agent.run(transition, &extra)?;
        assert_eq!(code, Some(2), "{transition} {extra:?}");
    }
    // Claims on a deployment where no case exists are unavailable, never reserved.
    agent.refused(
        "claim",
        &["--case", CASE, "--work", "case"],
        "ERR-OP-PRECONDITION-FAILED-001",
    )?;
    Ok(())
}
