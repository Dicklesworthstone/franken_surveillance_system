#![forbid(unsafe_code)]
//! Contract tests for `fss investigate` (AOP-006) through the real `fss` binary:
//!
//! 1. open -> activate -> cite -> assess -> conclude over a durable session: every answer is a
//!    registered `AgentResponseEnvelope` whose payload validates against
//!    `fss.investigation_state.v1`, dispositions stay orthogonal to knowledge states, and an
//!    identical open is an exact retry;
//! 2. stale writers, wrong-side assessments, unacknowledged residual unknowns, unknown cases and
//!    sessions, and malformed case documents are typed refusals (exit 5 or 2) that write nothing
//!    outside `agent/`;
//! 3. the session-bound situation lists every open case as a typed `investigate` affordance and
//!    in `activeInvestigations`, and so does the handoff;
//! 4. after the deployment head moves and the session is resumed, an open case is refused as
//!    stale until it is rebased, and its inherited citations must be readmitted before they can
//!    support an assessment;
//! 5. the authority ledger, effect journal, spool, and `LAYOUT` are byte-identical throughout.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_cli::json_input::{Value, parse};
use fss_core::{ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SITE: &str = "site:investigate-cli";
const CASE: &str = "case:east-door";
const STOP_RULE: &str = "one hypothesis supported by an independent observation";

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-investigate-cli-{name}-{}-{attempt}",
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

    fn root(&self) -> PathBuf {
        self.0.join("deployment")
    }
}

impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn empty_deployment(directory: &OwnedDirectory) -> TestResult<PathBuf> {
    let root = directory.root();
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:investigate-cli".to_owned(),
        operation_id: OperationId::parse("operation:investigate-cli")?,
        principal: "operator:investigate-cli".to_owned(),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_string()],
        deadline: None,
        priority: 10,
        budgets: fss_core::BudgetVector::default(),
        privacy_scope: "privacy:internal".to_string(),
        retention_scope: "retention:ephemeral".to_string(),
        anchor_universe: ContentDigest::sha256(b"investigate-cli"),
        generation: 1,
    })?;
    let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
        &authority,
        directory.0.join("cx"),
    )?);
    drop(ReferenceDeployment::open(&root, SITE, &cx)?);
    Ok(root)
}

/// A bright square entering from the left (one watch candidate in zone `door`).
fn scene() -> TestResult<Vec<u8>> {
    let (width, height) = (96_u32, 48_u32);
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut stream = Vec::new();
    for index in 0..14_usize {
        let mut pixels = vec![40_u8; (width * height) as usize];
        if index >= 3 {
            let left = (index - 3) * 8;
            for y in 8..24 {
                for x in left..left + 16 {
                    pixels[y * width as usize + x] = 220;
                }
            }
        }
        stream.extend(encode_jpeg(width, height, &pixels, &config)?);
    }
    Ok(stream)
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn report_field(output: &Output, key: &str) -> TestResult<String> {
    let text = String::from_utf8(output.stdout.clone())?;
    let pattern = format!("\"{key}\":");
    let start = text
        .find(&pattern)
        .ok_or_else(|| format!("missing {key} in {text}"))?
        + pattern.len();
    let rest = &text[start..];
    Ok(match rest.strip_prefix('"') {
        Some(quoted) => quoted.split('"').next().unwrap_or_default().to_owned(),
        None => rest
            .split([',', '}', ']'])
            .next()
            .unwrap_or_default()
            .to_owned(),
    })
}

/// Imports one recording and publishes its single watch candidate: the head moves.
fn publish_event(directory: &OwnedDirectory) -> TestResult<String> {
    let root = directory.root();
    let input = directory.0.join("east.mjpeg");
    fs::write(&input, scene()?)?;
    let output = Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .arg("import")
        .arg("--root")
        .arg(&root)
        .args(["--site", SITE, "--input"])
        .arg(&input)
        .args(["--sensor", "sensor:east", "--stream", "stream:sensor:east"])
        .args(["--media-format", "mjpeg", "--receive-time-ns", "1000000000"])
        .output()?;
    success(&output);
    let import_id = String::from_utf8(output.stdout)?
        .lines()
        .find_map(|line| line.strip_prefix("import_identity=").map(str::to_owned))
        .ok_or("import identity missing")?;
    let watch = |extra: &[&str]| -> TestResult<Output> {
        Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
            .arg("watch")
            .arg("--root")
            .arg(&root)
            .args(["--site", SITE, "--import-id", &import_id])
            .args(["--interpretation", "gray", "--zone", "door:64,0,32,32"])
            .args(extra)
            .output()?)
    };
    let prepared = watch(&[])?;
    success(&prepared);
    let proposal = report_field(&prepared, "proposal_digest")?;
    let published = watch(&["--approve", &proposal])?;
    success(&published);
    report_field(&published, "event_id")
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

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn raw_payload(stdout: &str) -> TestResult<&str> {
    let start = stdout.find(",\"payload\":").ok_or("payload missing")? + ",\"payload\":".len();
    let end = stdout
        .find(",\"payloadDigest\":")
        .ok_or("payload digest missing")?;
    Ok(&stdout[start..end])
}

fn assert_conforms(schema: &str, instance: &str, scratch: &Path, label: &str) -> TestResult {
    let root = repository_root();
    let file = scratch.join(format!(
        "instance-{}.json",
        ContentDigest::sha256(format!("{schema}\n{label}\n{instance}").as_bytes())
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
        "{label}: output does not conform to schemas/{schema}: {}{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    Ok(())
}

fn assert_answer_conforms(stdout: &str, scratch: &Path, label: &str) -> TestResult {
    assert_conforms(
        "agent_response_envelope.v1.json",
        stdout.trim_end(),
        scratch,
        label,
    )?;
    let envelope = parse(stdout.trim_end())?;
    let payload = raw_payload(stdout)?;
    if payload != "null" {
        let schema = text(&envelope, &["payloadSchema"])?;
        let file = format!("{}.json", schema.trim_start_matches("fss."));
        assert_conforms(&file, payload, scratch, label)?;
    }
    Ok(())
}

struct Agent {
    root: PathBuf,
    scratch: PathBuf,
    session: String,
}

impl Agent {
    fn open(directory: &OwnedDirectory, root: &Path) -> TestResult<Self> {
        let (code, stdout) = run_fss(&[
            "session".into(),
            "open".into(),
            "--json".into(),
            "--root".into(),
            root.as_os_str().to_owned(),
            "--mission".into(),
            "Keep the east door under watch.".into(),
            "--objective".into(),
            "Know whether anyone entered through the east door.".into(),
        ])?;
        assert_eq!(code, Some(0), "{stdout}");
        let envelope = parse(stdout.trim_end())?;
        let scratch = directory.0.join("scratch");
        fs::create_dir_all(&scratch)?;
        Ok(Self {
            root: root.to_path_buf(),
            scratch,
            session: text(&envelope, &["sessionId"])?.to_owned(),
        })
    }

    fn args(&self, transition: &str, extra: &[&str]) -> Vec<OsString> {
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
        args
    }

    /// An answered command: exit 0, outcome ok, schema-conformant envelope and payload.
    fn ok(&self, transition: &str, extra: &[&str]) -> TestResult<(String, Value)> {
        let (code, stdout) = run_fss(&self.args(transition, extra))?;
        assert_eq!(code, Some(0), "{transition}: {stdout}");
        assert_answer_conforms(&stdout, &self.scratch, transition)?;
        let envelope = parse(stdout.trim_end())?;
        assert_eq!(text(&envelope, &["outcome"])?, "ok");
        assert_eq!(text(&envelope, &["operationId"])?, "AOP-006");
        Ok((stdout, envelope))
    }

    /// A typed refusal: exit 5, the named error identity, a null payload.
    fn refused(&self, transition: &str, extra: &[&str], error_id: &str) -> TestResult<Value> {
        let (code, stdout) = run_fss(&self.args(transition, extra))?;
        assert_eq!(code, Some(5), "{transition}: {stdout}");
        assert_answer_conforms(&stdout, &self.scratch, transition)?;
        let envelope = parse(stdout.trim_end())?;
        assert_eq!(text(&envelope, &["outcome"])?, "refused");
        assert_eq!(text(&envelope, &["errorId"])?, error_id, "{stdout}");
        assert_eq!(field(&envelope, &["payload"])?, &Value::Null);
        Ok(envelope)
    }

    fn case_file(&self, name: &str, body: &str) -> TestResult<String> {
        let path = self.scratch.join(name);
        fs::write(&path, body)?;
        Ok(path.to_string_lossy().into_owned())
    }
}

fn case_document() -> String {
    format!(
        r#"{{"caseId":"{CASE}","question":"Did a person enter through the east door?",
"decisionInformed":"Whether to prepare an owner alert",
"hypotheses":[{{"hypothesisId":"h:entry","description":"A person entered","predictions":["the track continues indoors"]}},
{{"hypothesisId":"h:passerby","description":"A person passed the door without entering","epistemicState":"estimated","predictions":["the track leaves the frame eastward"]}}],
"knowns":[{{"statementId":"k:door-camera","text":"The east camera covers the door","basis":["sensor:east"]}}],
"unknowns":[{{"statementId":"u:indoor","text":"Whether the hallway camera saw the person"}}],
"discriminators":[{{"discriminatorId":"d:hallway","description":"Hallway frames after the door event","separates":["h:entry","h:passerby"],"expectedOutcomes":["a person in the hallway","an empty hallway"]}}],
"probes":["probe:hallway-frames"],"stopRules":["{STOP_RULE}"],"decisionWindowNs":3600000000000}}"#
    )
}

fn evidence(label: &str) -> String {
    ContentDigest::sha256(label.as_bytes()).to_text()
}

fn fingerprint(envelope: &Value) -> TestResult<String> {
    Ok(text(envelope, &["decisionFingerprint"])?.to_owned())
}

fn dispositions(envelope: &Value) -> TestResult<Vec<(String, String, String)>> {
    field(envelope, &["payload", "hypotheses"])?
        .array()
        .ok_or("hypotheses")?
        .iter()
        .map(|hypothesis| {
            Ok((
                text(hypothesis, &["hypothesisId"])?.to_owned(),
                text(hypothesis, &["disposition"])?.to_owned(),
                text(hypothesis, &["epistemicState"])?.to_owned(),
            ))
        })
        .collect()
}

#[test]
fn a_case_lives_through_its_lifecycle_durably_typed_and_agent_plane_only() -> TestResult {
    let directory = OwnedDirectory::new("lifecycle")?;
    let root = empty_deployment(&directory)?;
    let authority_before = authority_tree(&root)?;
    let agent = Agent::open(&directory, &root)?;
    let file = agent.case_file("case.json", &case_document())?;

    let (opened_bytes, opened) = agent.ok("open", &["--case-file", &file])?;
    assert_eq!(text(&opened, &["payload", "state"])?, "draft");
    assert_eq!(text(&opened, &["payload", "investigationId"])?, CASE);
    assert_eq!(
        dispositions(&opened)?,
        vec![
            (
                "h:entry".to_owned(),
                "live".to_owned(),
                "unknown".to_owned()
            ),
            (
                "h:passerby".to_owned(),
                "live".to_owned(),
                "estimated".to_owned()
            ),
        ]
    );
    assert_eq!(
        text(&opened, &["payload", "revisionDigest"])?,
        fingerprint(&opened)?
    );
    assert_eq!(
        field(&opened, &["payload", "predecessorRevision"])?,
        &Value::Null
    );
    let affordances = texts(&opened, &["affordances"]).or_else(|_| -> TestResult<Vec<String>> {
        Ok(field(&opened, &["affordances"])?
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
    })?;
    assert!(
        affordances.contains(&format!("affordance:investigate:{CASE}")),
        "{affordances:?}"
    );

    // An identical open is an exact retry: the same head, nothing new committed.
    let (retry_bytes, retry) = agent.ok("open", &["--case-file", &file])?;
    assert_eq!(fingerprint(&retry)?, fingerprint(&opened)?);
    assert_eq!(raw_payload(&retry_bytes)?, raw_payload(&opened_bytes)?);

    let draft = fingerprint(&opened)?;
    let (_, active) = agent.ok("activate", &["--case", CASE, "--expected", &draft])?;
    assert_eq!(text(&active, &["payload", "state"])?, "active");
    assert_eq!(
        text(&active, &["payload", "predecessorRevision"])?,
        draft.as_str()
    );
    // A stale writer never overwrites the newer head.
    agent.refused(
        "activate",
        &["--case", CASE, "--expected", &draft],
        "ERR-PRECONDITION-STALE-001",
    )?;

    let seen = evidence("hallway frame 17: person");
    let away = evidence("street frame 4: nobody leaving east");
    let head = fingerprint(&active)?;
    let (_, cited) = agent.ok(
        "cite",
        &[
            "--case",
            CASE,
            "--expected",
            &head,
            "--hypothesis",
            "h:entry",
            "--evidence",
            &seen,
            "--side",
            "support",
        ],
    )?;
    let head = fingerprint(&cited)?;
    let (_, cited) = agent.ok(
        "cite",
        &[
            "--case",
            CASE,
            "--expected",
            &head,
            "--hypothesis",
            "h:passerby",
            "--evidence",
            &away,
            "--side",
            "contradiction",
        ],
    )?;
    let head = fingerprint(&cited)?;
    // Support evidence cannot refute: the citation side is enforced.
    agent.refused(
        "assess",
        &[
            "--case",
            CASE,
            "--expected",
            &head,
            "--hypothesis",
            "h:passerby",
            "--disposition",
            "refuted",
            "--evidence",
            &seen,
        ],
        "ERR-EVIDENCE-MISSING-001",
    )?;
    let (_, assessed) = agent.ok(
        "assess",
        &[
            "--case",
            CASE,
            "--expected",
            &head,
            "--hypothesis",
            "h:entry",
            "--disposition",
            "supported",
            "--evidence",
            &seen,
        ],
    )?;
    // Disposition and knowledge state stay orthogonal.
    assert_eq!(
        dispositions(&assessed)?[0],
        (
            "h:entry".to_owned(),
            "supported".to_owned(),
            "unknown".to_owned()
        )
    );

    // The session-bound situation and the handoff both carry the open case.
    let (_, listed) = agent.ok("list", &[])?;
    assert_eq!(
        texts(&listed, &["payload", "activeInvestigations"])?,
        vec![CASE.to_owned()]
    );
    let (code, stdout) = run_fss(&[
        "handoff".into(),
        "--json".into(),
        "--root".into(),
        root.as_os_str().to_owned(),
        "--session".into(),
        agent.session.clone().into(),
    ])?;
    assert_eq!(code, Some(0), "{stdout}");
    let handoff = parse(stdout.trim_end())?;
    assert_eq!(
        texts(&handoff, &["payload", "activeInvestigations"])?,
        vec![CASE.to_owned()]
    );

    let head = fingerprint(&assessed)?;
    // A conclusion must acknowledge every residual unknown and cannot leave a live alternative.
    agent.refused(
        "conclude",
        &[
            "--case",
            CASE,
            "--expected",
            &head,
            "--conclusion",
            "resolved",
            "--stop-rule",
            STOP_RULE,
            "--assessment",
            &seen,
            "--residual-unknowns",
            "none",
        ],
        "ERR-OP-PRECONDITION-FAILED-001",
    )?;
    agent.refused(
        "conclude",
        &[
            "--case",
            CASE,
            "--expected",
            &head,
            "--conclusion",
            "resolved",
            "--stop-rule",
            STOP_RULE,
            "--assessment",
            &seen,
            "--residual-unknowns",
            "u:indoor",
        ],
        "ERR-OP-PRECONDITION-FAILED-001",
    )?;
    let (_, refuted) = agent.ok(
        "assess",
        &[
            "--case",
            CASE,
            "--expected",
            &head,
            "--hypothesis",
            "h:passerby",
            "--disposition",
            "refuted",
            "--evidence",
            &away,
        ],
    )?;
    let head = fingerprint(&refuted)?;
    let (_, concluded) = agent.ok(
        "conclude",
        &[
            "--case",
            CASE,
            "--expected",
            &head,
            "--conclusion",
            "resolved",
            "--stop-rule",
            STOP_RULE,
            "--assessment",
            &seen,
            "--residual-unknowns",
            "u:indoor",
        ],
    )?;
    assert_eq!(text(&concluded, &["payload", "state"])?, "resolved");
    // Historical revisions stay readable by digest; the head is the resolved one.
    let (_, historical) = agent.ok("inspect", &["--case", CASE, "--revision", &draft])?;
    assert_eq!(text(&historical, &["payload", "state"])?, "draft");
    let (_, current) = agent.ok("inspect", &["--case", CASE])?;
    assert_eq!(fingerprint(&current)?, fingerprint(&concluded)?);
    let (_, listed) = agent.ok("list", &[])?;
    assert!(texts(&listed, &["payload", "activeInvestigations"])?.is_empty());

    assert_eq!(authority_tree(&root)?, authority_before);
    Ok(())
}

#[test]
fn refusals_are_typed_and_parse_errors_never_reach_the_store() -> TestResult {
    let directory = OwnedDirectory::new("refusals")?;
    let root = empty_deployment(&directory)?;
    let agent = Agent::open(&directory, &root)?;
    // No case was ever opened: an inspect or change is indistinguishable from an unknown case.
    agent.refused(
        "inspect",
        &["--case", CASE],
        "ERR-OP-PRECONDITION-FAILED-001",
    )?;
    // A single hypothesis is not an investigation.
    let lonely = format!(
        r#"{{"caseId":"{CASE}","question":"q","decisionInformed":"d",
"hypotheses":[{{"hypothesisId":"h:only","description":"the only idea"}}],
"stopRules":["{STOP_RULE}"],"decisionWindowNs":"1000"}}"#
    );
    let file = agent.case_file("lonely.json", &lonely)?;
    agent.refused(
        "open",
        &["--case-file", &file],
        "ERR-OP-PRECONDITION-FAILED-001",
    )?;
    // An unknown session.
    let stranger = Agent {
        root: root.clone(),
        scratch: agent.scratch.clone(),
        session: "session:unknown".to_owned(),
    };
    stranger.refused("list", &[], "ERR-AGENT-SESSION-NOT-FOUND-001")?;

    let journal = root.join("agent/sessions/journal.fssj");
    let before = fs::read(&journal)?;
    // Malformed documents, unknown fields, and options a transition does not take are argument
    // errors (exit 2): nothing is journaled.
    let malformed = agent.case_file("bad.json", r#"{"caseId": "case:x", "caseId": "case:y"}"#)?;
    let unknown = agent.case_file(
        "unknown.json",
        &case_document().replacen("\"caseId\"", "\"evidence\":[],\"caseId\"", 1),
    )?;
    for extra in [
        vec!["--case-file", malformed.as_str()],
        vec!["--case-file", unknown.as_str()],
        vec!["--case-file", unknown.as_str(), "--case", CASE],
    ] {
        let (code, stdout) = run_fss(&agent.args("open", &extra))?;
        assert_eq!(code, Some(2), "{stdout}");
    }
    let (code, _) = run_fss(&agent.args("teleport", &[]))?;
    assert_eq!(code, Some(2));
    assert_eq!(fs::read(&journal)?, before);
    Ok(())
}

#[test]
fn a_case_carried_across_a_resume_is_rebased_and_its_citations_readmitted() -> TestResult {
    let directory = OwnedDirectory::new("rebase")?;
    let root = empty_deployment(&directory)?;
    let agent = Agent::open(&directory, &root)?;
    let file = agent.case_file("case.json", &case_document())?;
    let (_, opened) = agent.ok("open", &["--case-file", &file])?;
    let (_, active) = agent.ok(
        "activate",
        &["--case", CASE, "--expected", &fingerprint(&opened)?],
    )?;
    let seen = evidence("hallway frame 17: person");
    let (_, cited) = agent.ok(
        "cite",
        &[
            "--case",
            CASE,
            "--expected",
            &fingerprint(&active)?,
            "--hypothesis",
            "h:entry",
            "--evidence",
            &seen,
            "--side",
            "support",
        ],
    )?;
    let (code, stdout) = run_fss(&[
        "handoff".into(),
        "--json".into(),
        "--root".into(),
        root.as_os_str().to_owned(),
        "--session".into(),
        agent.session.clone().into(),
    ])?;
    assert_eq!(code, Some(0), "{stdout}");
    let handoff_id = text(&parse(stdout.trim_end())?, &["payload", "handoffId"])?.to_owned();

    // The world moves on, and the session is resumed onto the new head.
    publish_event(&directory)?;
    let (code, stdout) = run_fss(&[
        "session".into(),
        "resume".into(),
        "--json".into(),
        "--root".into(),
        root.as_os_str().to_owned(),
        "--handoff".into(),
        handoff_id.into(),
    ])?;
    assert_eq!(code, Some(0), "{stdout}");
    let resumed = parse(stdout.trim_end())?;
    let invalidated = texts(&resumed, &["executionBoundary", "invalidated"])?;
    assert!(
        invalidated
            .iter()
            .any(|line| line.starts_with(&format!("investigation {CASE} invalidated"))),
        "{invalidated:?}"
    );

    // The old basis no longer admits changes: the case must be rebased first.
    let head = fingerprint(&cited)?;
    agent.refused(
        "assess",
        &[
            "--case",
            CASE,
            "--expected",
            &head,
            "--hypothesis",
            "h:entry",
            "--disposition",
            "supported",
            "--evidence",
            &seen,
        ],
        "ERR-AGENT-SESSION-STALE-001",
    )?;
    let (_, rebased) = agent.ok("rebase", &["--case", CASE, "--expected", &head])?;
    assert_eq!(text(&rebased, &["payload", "state"])?, "awaiting_evidence");
    // Known knowledge from the old basis is stale, never silently current.
    let knowns = field(&rebased, &["payload", "knowns"])?
        .array()
        .ok_or("knowns")?;
    assert_eq!(text(&knowns[0], &["epistemicState"])?, "stale");
    let (_, active) = agent.ok(
        "activate",
        &["--case", CASE, "--expected", &fingerprint(&rebased)?],
    )?;
    let head = fingerprint(&active)?;
    // The inherited citation must be readmitted before it supports anything.
    agent.refused(
        "assess",
        &[
            "--case",
            CASE,
            "--expected",
            &head,
            "--hypothesis",
            "h:entry",
            "--disposition",
            "supported",
            "--evidence",
            &seen,
        ],
        "ERR-EVIDENCE-MISSING-001",
    )?;
    let receipt = evidence("hallway frame 17 is still applicable at the new head");
    let (_, readmitted) = agent.ok(
        "readmit",
        &[
            "--case",
            CASE,
            "--expected",
            &head,
            "--hypothesis",
            "h:entry",
            "--evidence",
            &seen,
            "--side",
            "support",
            "--witness",
            &receipt,
        ],
    )?;
    let (_, assessed) = agent.ok(
        "assess",
        &[
            "--case",
            CASE,
            "--expected",
            &fingerprint(&readmitted)?,
            "--hypothesis",
            "h:entry",
            "--disposition",
            "supported",
            "--evidence",
            &seen,
        ],
    )?;
    assert_eq!(dispositions(&assessed)?[0].1, "supported");
    Ok(())
}
