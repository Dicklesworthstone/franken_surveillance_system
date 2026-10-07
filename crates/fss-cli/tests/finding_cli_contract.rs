#![forbid(unsafe_code)]
//! Contract tests for shared findings (FSS-227) through the real `fss` binary: two sessions of
//! one mission publish immutable findings on one case.
//!
//! 1. a finding is an immutable, root-last publication whose `fss.agent_finding.v1` rendering is
//!    hydrated from the agent publication store and conforms to its schema; an identical request
//!    is an exact retry;
//! 2. an explicit disagreement makes both findings `conflicted` (their recorded states are
//!    kept), lists one probe affordance per disputed finding, and reports the conflict until a
//!    supersession or withdrawal ends it; nothing is ranked away;
//! 3. a finding is superseded at most once and only while active; a superseded or withdrawn
//!    finding stays readable as `stale`;
//! 4. handoffs carry the active findings; the authority ledger, effect journal, and spool never
//!    change.

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

const SITE: &str = "site:finding-cli";
const CASE: &str = "case:east-door";
const MISSION: &str = "Keep the east door under watch.";
const OBJECTIVE: &str = "Know whether anyone entered through the east door.";

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-finding-cli-{name}-{}-{attempt}",
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
        trace_id: "trace:finding-cli".to_owned(),
        operation_id: OperationId::parse("operation:finding-cli")?,
        principal: "operator:finding-cli".to_owned(),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_string()],
        deadline: None,
        priority: 10,
        budgets: fss_core::BudgetVector::default(),
        privacy_scope: "privacy:internal".to_string(),
        retention_scope: "retention:ephemeral".to_string(),
        anchor_universe: ContentDigest::sha256(b"finding-cli"),
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

impl Agent {
    /// A finding transition answered with exit 0 and a cognitive-envelope payload.
    fn finding(&self, transition: &str, extra: &[&str]) -> TestResult<Value> {
        let envelope = self.ok(transition, extra)?;
        Ok(envelope)
    }

    /// The handoff's `findings`.
    fn handoff_findings(&self) -> TestResult<Vec<String>> {
        let (code, stdout) = run_fss(&[
            "handoff".into(),
            "--json".into(),
            "--root".into(),
            self.root.as_os_str().to_owned(),
            "--session".into(),
            self.session.clone().into(),
        ])?;
        assert_eq!(code, Some(0), "{stdout}");
        texts(
            &conforming(&stdout, &self.scratch)?,
            &["payload", "findings"],
        )
    }
}

/// (id, knowledge state shown) of every proposition of an answer.
fn standings(envelope: &Value) -> TestResult<Vec<(String, String)>> {
    field(envelope, &["payload", "epistemic", "propositions"])?
        .array()
        .ok_or("propositions")?
        .iter()
        .map(|item| {
            Ok((
                text(item, &["id"])?.to_owned(),
                text(item, &["state"])?.to_owned(),
            ))
        })
        .collect()
}

/// Hydrates and validates a finding's rendering through the answer's second proof pointer.
fn hydrated(agent: &Agent, envelope: &Value) -> TestResult<Value> {
    let pointer = texts(envelope, &["proofPointers"])?[1].clone();
    let bytes = fss_publication::read_verified(
        agent.root.join("agent/publications"),
        ContentDigest::parse(&pointer)?,
        1 << 20,
    )?;
    let rendering = String::from_utf8(bytes)?;
    assert_conforms("agent_finding.v1.json", &rendering, &agent.scratch)?;
    Ok(parse(&rendering)?)
}

fn conflict_moves(agent: &Agent) -> TestResult<Vec<String>> {
    Ok(agent
        .affordances()?
        .into_iter()
        .filter(|affordance| affordance.starts_with("affordance:finding:"))
        .collect())
}

#[test]
#[allow(clippy::too_many_lines)] // one board history is one ordered scenario
fn findings_disagree_visibly_and_are_superseded_or_withdrawn_never_edited() -> TestResult {
    let directory = OwnedDirectory::new("board")?;
    let root = empty_deployment(&directory)?;
    let first = Agent::open(&directory, &root, "3000")?;
    let second = Agent::open(&directory, &root, "4000")?;
    let case_file = first.scratch.join("case.json");
    fs::write(&case_file, case_document())?;
    let (code, _) = first.run("open", &["--case-file", &case_file.to_string_lossy()])?;
    assert_eq!(code, Some(0));
    let authority_before = authority_tree(&root)?;
    let hallway = ContentDigest::sha256(b"hallway frame 17: a person").to_text();
    let street = ContentDigest::sha256(b"street frame 4: the same person leaving").to_text();

    // The first session finds an entry; the rendering is hydrated and schema-valid.
    let entry_args = [
        "--case",
        CASE,
        "--hypothesis",
        "h:entry",
        "--claim",
        "A person entered through the east door.",
        "--state",
        "estimated",
        "--supporting",
        hallway.as_str(),
    ];
    let entry = first.finding("finding", &entry_args)?;
    let entry_id = standings(&entry)?[0].0.clone();
    assert_eq!(standings(&entry)?[0].1, "estimated");
    let rendering = hydrated(&first, &entry)?;
    assert_eq!(text(&rendering, &["findingId"])?, entry_id);
    assert_eq!(text(&rendering, &["epistemicState"])?, "estimated");
    // An identical finding is an exact retry.
    let retry = first.finding("finding", &entry_args)?;
    assert_eq!(standings(&retry)?[0].0, entry_id);
    assert_eq!(
        text(&retry, &["decisionFingerprint"])?,
        text(&entry, &["decisionFingerprint"])?
    );
    assert!(conflict_moves(&first)?.is_empty());

    // The second session disagrees: both findings are conflicted, their records unchanged.
    let passerby = second.finding(
        "finding",
        &[
            "--case",
            CASE,
            "--hypothesis",
            "h:passerby",
            "--claim",
            "The person passed the door and left eastward.",
            "--state",
            "estimated",
            "--supporting",
            &street,
            "--contradicting",
            &hallway,
            "--disagrees-with",
            &entry_id,
        ],
    )?;
    let passerby_id = standings(&passerby)?[0].0.clone();
    assert_eq!(standings(&passerby)?[0].1, "conflicted");
    let board = first.finding("finding-list", &[])?;
    let mut expected = vec![
        (entry_id.clone(), "conflicted".to_owned()),
        (passerby_id.clone(), "conflicted".to_owned()),
    ];
    expected.sort();
    assert_eq!(standings(&board)?, expected);
    assert!(
        texts(&board, &["degradation"])?
            .iter()
            .any(|line| line.starts_with("Unresolved conflict:"))
    );
    let mut moves = vec![
        format!("affordance:finding:{entry_id}"),
        format!("affordance:finding:{passerby_id}"),
    ];
    moves.sort();
    assert_eq!(conflict_moves(&second)?, moves);
    let mut active = vec![entry_id.clone(), passerby_id.clone()];
    active.sort();
    assert_eq!(first.handoff_findings()?, active);
    assert_eq!(
        text(&hydrated(&first, &entry)?, &["epistemicState"])?,
        "estimated"
    );

    // Disagreement is per case and only with visible findings.
    second.refused(
        "finding",
        &[
            "--case",
            CASE,
            "--claim",
            "Unrelated.",
            "--state",
            "unknown",
            "--supporting",
            &street,
            "--disagrees-with",
            "finding:nonexistent",
        ],
        "ERR-OP-PRECONDITION-FAILED-001",
    )?;

    // The first session supersedes its finding: the conflict ends; the old record stays stale.
    let corrected = first.finding(
        "finding",
        &[
            "--case",
            CASE,
            "--hypothesis",
            "h:passerby",
            "--claim",
            "On the street frames, the person passed the door without entering.",
            "--state",
            "estimated",
            "--supporting",
            &street,
            "--supersedes",
            &entry_id,
        ],
    )?;
    let corrected_id = standings(&corrected)?[0].0.clone();
    assert_eq!(standings(&corrected)?[0].1, "estimated");
    assert!(conflict_moves(&first)?.is_empty());
    let board = first.finding("finding-list", &["--case", CASE])?;
    let states: Vec<(String, String)> = standings(&board)?;
    assert!(states.contains(&(entry_id.clone(), "stale".to_owned())));
    assert!(states.contains(&(passerby_id.clone(), "estimated".to_owned())));
    // One successor each: superseding the superseded finding again is stale.
    first.refused(
        "finding",
        &[
            "--case",
            CASE,
            "--claim",
            "A second correction.",
            "--state",
            "unknown",
            "--supporting",
            &street,
            "--supersedes",
            &entry_id,
        ],
        "ERR-PRECONDITION-STALE-001",
    )?;

    // The second session withdraws its finding; the withdrawal is itself an immutable record.
    let withdrawal = second.finding(
        "finding-withdraw",
        &[
            "--finding",
            &passerby_id,
            "--claim",
            "Superseded by the first session's corrected finding.",
            "--supporting",
            &street,
        ],
    )?;
    let rendering = hydrated(&second, &withdrawal)?;
    assert_eq!(field(&rendering, &["withdrawn"])?, &Value::Bool(true));
    assert_eq!(second.handoff_findings()?, vec![corrected_id.clone()]);

    assert_eq!(authority_tree(&root)?, authority_before);
    Ok(())
}
