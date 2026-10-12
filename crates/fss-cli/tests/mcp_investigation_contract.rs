#![forbid(unsafe_code)]
//! Real-process contracts for the MCP investigate/AOP-006 workflow.
//!
//! Each call starts and stops the actual stdio binary over one durable native deployment.
//! The tests cover every case transition, native byte/payload-digest parity, retained historical
//! revisions, exact CAS refusal, rebase debt and citation readmission after an approved head move.
//! Inline documents remain literal values, caller-supplied authority and files are refused, and
//! notifications never dispatch a mutation. Case cognition leaves non-agent authority untouched.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use fss_cli::json_input::{Value, parse};
use fss_cli::{ExitIdentity, escape_json_str, execute_fss_with_exit, parse_fss_args};
use fss_core::{ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SITE: &str = "site:mcp-investigate";
const CASE: &str = "case:east-door";
const PRINCIPAL: &str = "principal:mcp-investigator";
const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"investigation-contract","version":"1"}}}"#;
const READY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
const STOP_RULE: &str = "one hypothesis supported by an independent observation";

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-mcp-investigate-{name}-{}-{attempt}",
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
        trace_id: "trace:mcp-investigate".to_owned(),
        operation_id: OperationId::parse("operation:mcp-investigate")?,
        principal: "operator:mcp-investigate".to_owned(),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_string()],
        deadline: None,
        priority: 10,
        budgets: fss_core::BudgetVector::default(),
        privacy_scope: "privacy:internal".to_string(),
        retention_scope: "retention:ephemeral".to_string(),
        anchor_universe: ContentDigest::sha256(b"mcp-investigate"),
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

/// File bytes and directory membership, excluding read-induced access timestamps.
fn snapshot(root: &Path) -> TestResult<BTreeMap<PathBuf, (bool, Vec<u8>)>> {
    let mut pending = vec![root.to_path_buf()];
    let mut result = BTreeMap::new();
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        let relative = path.strip_prefix(root)?.to_path_buf();
        if metadata.is_dir() {
            result.insert(relative, (true, Vec::new()));
            for entry in fs::read_dir(&path)? {
                pending.push(entry?.path());
            }
        } else if metadata.is_file() {
            result.insert(relative, (false, fs::read(path)?));
        } else {
            return Err("unexpected special file in reference fixture".into());
        }
    }
    Ok(result)
}

fn quote(value: &str) -> String {
    format!("\"{}\"", escape_json_str(value))
}

fn object(fields: &[(&str, String)]) -> String {
    format!(
        "{{{}}}",
        fields
            .iter()
            .map(|(key, value)| format!("{}:{value}", quote(key)))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn call(id: u64, name: &str, arguments: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":{},"arguments":{arguments}}}}}"#,
        quote(name)
    )
}

/// Every exchange starts a fresh process, so no transition can rely on a live in-memory case.
fn exchange(root: &Path, principal: &str, requests: &str) -> TestResult<Vec<Value>> {
    let mut process = Command::new(env!("CARGO_BIN_EXE_fss-mcp"))
        .arg("--root")
        .arg(root)
        .args(["--principal", principal])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut input = process.stdin.take().ok_or("missing stdin")?;
    input.write_all(requests.as_bytes())?;
    drop(input);
    let output = process.wait_with_output()?;
    success(&output);
    assert!(output.stderr.is_empty(), "{output:?}");
    String::from_utf8(output.stdout)?
        .lines()
        .map(|line| parse(line).map_err(Into::into))
        .collect()
}

fn rpc(root: &Path, principal: &str, name: &str, arguments: &str) -> TestResult<Value> {
    let requests = format!("{INIT}\n{READY}\n{}\n", call(2, name, arguments));
    let mut answers = exchange(root, principal, &requests)?;
    assert_eq!(answers.len(), 2, "{answers:?}");
    let answer = answers.pop().ok_or("missing tools/call result")?;
    assert_eq!(field(&answer, &["id"])?, &Value::Number("2".to_owned()));
    Ok(answer)
}

struct Answer {
    semantic: String,
    envelope: Value,
    is_error: bool,
}

impl Answer {
    fn from_rpc(response: &Value) -> TestResult<Self> {
        let content = field(response, &["result", "content"])?
            .array()
            .ok_or("content is not an array")?;
        assert_eq!(content.len(), 1, "{response:?}");
        assert_eq!(text(&content[0], &["type"])?, "text");
        let semantic = text(&content[0], &["text"])?.to_owned();
        let is_error = match field(response, &["result", "isError"])? {
            Value::Bool(value) => *value,
            _ => return Err("isError is not a boolean".into()),
        };
        let envelope = parse(semantic.trim_end())?;
        Ok(Self {
            semantic,
            envelope,
            is_error,
        })
    }

    fn fingerprint(&self) -> TestResult<String> {
        fingerprint(&self.envelope)
    }

    fn text(&self, path: &[&str]) -> TestResult<&str> {
        text(&self.envelope, path)
    }
}

struct Agent {
    root: PathBuf,
    scratch: PathBuf,
    session: String,
}

impl Agent {
    fn open(directory: &OwnedDirectory, root: &Path) -> TestResult<Self> {
        let response = rpc(
            root,
            PRINCIPAL,
            "session_open",
            r#"{"mission":"Keep the east door under watch.","objective":"Know whether anyone entered through the east door.","budget_tokens":100000}"#,
        )?;
        let opened = Answer::from_rpc(&response)?;
        assert!(!opened.is_error, "{}", opened.semantic);
        assert_eq!(opened.text(&["outcome"])?, "ok");
        let scratch = directory.0.join("scratch");
        fs::create_dir(&scratch)?;
        assert_answer_conforms(&opened.semantic, &scratch, "session-open")?;
        Ok(Self {
            root: root.to_path_buf(),
            scratch,
            session: opened.text(&["sessionId"])?.to_owned(),
        })
    }

    fn arguments(&self, transition: &str, extra: &[(&str, String)]) -> String {
        let mut fields = vec![
            ("session", quote(&self.session)),
            ("transition", quote(transition)),
        ];
        fields.extend_from_slice(extra);
        object(&fields)
    }

    fn tool(&self, name: &str, arguments: &str) -> TestResult<Answer> {
        let answer = Answer::from_rpc(&rpc(&self.root, PRINCIPAL, name, arguments)?)?;
        assert_answer_conforms(&answer.semantic, &self.scratch, name)?;
        if field(&answer.envelope, &["payload"])? != &Value::Null {
            assert_eq!(
                answer.text(&["payloadDigest"])?,
                ContentDigest::sha256(raw_payload(&answer.semantic)?.as_bytes()).to_text(),
                "{}",
                answer.semantic
            );
        }
        Ok(answer)
    }

    fn ok(&self, transition: &str, extra: &[(&str, String)]) -> TestResult<Answer> {
        let answer = self.tool("investigate", &self.arguments(transition, extra))?;
        assert!(!answer.is_error, "{transition}: {}", answer.semantic);
        assert_eq!(answer.text(&["outcome"])?, "ok");
        assert_eq!(answer.text(&["operationId"])?, "AOP-006");
        assert_eq!(answer.text(&["sessionId"])?, self.session);
        Ok(answer)
    }

    fn change(
        &self,
        transition: &str,
        expected: &str,
        extra: &[(&str, String)],
    ) -> TestResult<Answer> {
        let mut fields = vec![("case", quote(CASE)), ("expected", quote(expected))];
        fields.extend_from_slice(extra);
        self.ok(transition, &fields)
    }

    fn refused(
        &self,
        transition: &str,
        expected: &str,
        extra: &[(&str, String)],
        error_id: &str,
    ) -> TestResult<Answer> {
        let mut fields = vec![("case", quote(CASE)), ("expected", quote(expected))];
        fields.extend_from_slice(extra);
        let answer = self.tool("investigate", &self.arguments(transition, &fields))?;
        assert!(answer.is_error, "{transition}: {}", answer.semantic);
        assert_eq!(answer.text(&["outcome"])?, "refused");
        assert_eq!(answer.text(&["operationId"])?, "AOP-006");
        assert_eq!(answer.text(&["errorId"])?, error_id, "{}", answer.semantic);
        assert_eq!(field(&answer.envelope, &["payload"])?, &Value::Null);
        Ok(answer)
    }

    fn inspect(&self) -> TestResult<Answer> {
        self.ok("inspect", &[("case", quote(CASE))])
    }

    /// Compare an actual MCP read to the unchanged native CLI dispatcher, byte for byte.
    fn assert_inspect_parity(&self, mcp: &Answer) -> TestResult {
        let args: Vec<OsString> = vec![
            "investigate".into(),
            "--json".into(),
            "--root".into(),
            self.root.as_os_str().to_owned(),
            "--session".into(),
            self.session.clone().into(),
            "--principal".into(),
            PRINCIPAL.into(),
            "--transition".into(),
            "inspect".into(),
            "--case".into(),
            CASE.into(),
        ];
        let (native, exit) = execute_fss_with_exit(parse_fss_args(args)?);
        assert_eq!(exit, ExitIdentity::SUCCESS, "{native}");
        assert_eq!(mcp.semantic, native);
        Ok(())
    }
}

fn citation(hypothesis: &str, evidence: &str, side: &str) -> Vec<(&'static str, String)> {
    vec![
        ("hypothesis", quote(hypothesis)),
        ("evidence", quote(evidence)),
        ("side", quote(side)),
    ]
}

fn assessment(hypothesis: &str, evidence: &str, disposition: &str) -> Vec<(&'static str, String)> {
    vec![
        ("hypothesis", quote(hypothesis)),
        ("evidence", quote(evidence)),
        ("disposition", quote(disposition)),
    ]
}

fn case_document() -> String {
    format!(
        r#"{{"caseId":"{CASE}","question":"Did a person enter through the east door?","decisionInformed":"Whether to prepare an owner alert","hypotheses":[{{"hypothesisId":"h:entry","description":"A person entered","predictions":["the track continues indoors"]}},{{"hypothesisId":"h:passerby","description":"A person passed the door without entering","epistemicState":"estimated","predictions":["the track leaves the frame eastward"]}}],"knowns":[{{"statementId":"k:door-camera","text":"The east camera covers the door","basis":["sensor:east"]}}],"unknowns":[{{"statementId":"u:indoor","text":"Whether the hallway camera saw the person"}}],"discriminators":[{{"discriminatorId":"d:hallway","description":"Hallway frames after the door event","separates":["h:entry","h:passerby"],"expectedOutcomes":["a person in the hallway","an empty hallway"]}}],"probes":["probe:hallway-frames"],"stopRules":["{STOP_RULE}"],"decisionWindowNs":3600000000000}}"#
    )
}

fn evidence(label: &str) -> String {
    ContentDigest::sha256(label.as_bytes()).to_text()
}

/// The (identity, statement) of every proposition of a `list` answer's cognitive envelope.
fn listed_cases(envelope: &Value) -> TestResult<Vec<(String, String)>> {
    field(envelope, &["payload", "epistemic", "propositions"])?
        .array()
        .ok_or("propositions")?
        .iter()
        .map(|proposition| {
            Ok((
                text(proposition, &["id"])?.to_owned(),
                text(proposition, &["statement"])?.to_owned(),
            ))
        })
        .collect()
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
fn mcp_case_lifecycle_survives_restarts_and_preserves_native_revisions() -> TestResult {
    let directory = OwnedDirectory::new("lifecycle")?;
    let root = empty_deployment(&directory)?;
    let authority_before = authority_tree(&root)?;
    let agent = Agent::open(&directory, &root)?;
    let opened = agent.ok("open", &[("draft", case_document())])?;
    let draft = opened.fingerprint()?;
    assert_eq!(opened.text(&["payload", "investigationId"])?, CASE);
    assert_eq!(opened.text(&["payload", "state"])?, "draft");
    assert_eq!(opened.text(&["payload", "revisionDigest"])?, draft);
    assert_eq!(
        field(&opened.envelope, &["payload", "predecessorRevision"])?,
        &Value::Null
    );
    assert_eq!(
        dispositions(&opened.envelope)?,
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

    let retried = agent.ok("open", &[("draft", case_document())])?;
    assert_eq!(retried.fingerprint()?, draft);
    assert_eq!(
        raw_payload(&retried.semantic)?,
        raw_payload(&opened.semantic)?
    );
    let active = agent.change("activate", &draft, &[])?;
    assert_eq!(active.text(&["payload", "state"])?, "active");
    assert_eq!(active.text(&["payload", "predecessorRevision"])?, draft);
    agent.refused("activate", &draft, &[], "ERR-PRECONDITION-STALE-001")?;
    assert_eq!(agent.inspect()?.fingerprint()?, active.fingerprint()?);

    let seen = evidence("hallway frame 17: person");
    let away = evidence("street frame 4: nobody leaving east");
    let cited = agent.change(
        "cite",
        &active.fingerprint()?,
        &citation("h:entry", &seen, "support"),
    )?;
    let cited = agent.change(
        "cite",
        &cited.fingerprint()?,
        &citation("h:passerby", &away, "contradiction"),
    )?;
    agent.refused(
        "assess",
        &cited.fingerprint()?,
        &assessment("h:passerby", &seen, "refuted"),
        "ERR-EVIDENCE-MISSING-001",
    )?;
    let assessed = agent.change(
        "assess",
        &cited.fingerprint()?,
        &assessment("h:entry", &seen, "supported"),
    )?;
    assert_eq!(
        dispositions(&assessed.envelope)?[0],
        (
            "h:entry".to_owned(),
            "supported".to_owned(),
            "unknown".to_owned()
        )
    );

    let listed = agent.ok("list", &[])?;
    let cases = listed_cases(&listed.envelope)?;
    assert_eq!(cases.len(), 1);
    assert_eq!(cases[0].0, CASE);
    assert!(!cases[0].1.contains(" is resolved"), "{cases:?}");
    let handoff = agent.tool("handoff", &object(&[("session", quote(&agent.session))]))?;
    assert!(!handoff.is_error, "{}", handoff.semantic);
    assert_eq!(
        texts(&handoff.envelope, &["payload", "activeInvestigations"])?,
        vec![CASE.to_owned()]
    );

    let conclusion = |residuals: &str| {
        vec![
            ("conclusion", quote("resolved")),
            ("stop_rule", quote(STOP_RULE)),
            ("assessment", quote(&seen)),
            ("residual_unknowns", residuals.to_owned()),
        ]
    };
    agent.refused(
        "conclude",
        &assessed.fingerprint()?,
        &conclusion("[]"),
        "ERR-OP-PRECONDITION-FAILED-001",
    )?;
    agent.refused(
        "conclude",
        &assessed.fingerprint()?,
        &conclusion(r#"["u:indoor"]"#),
        "ERR-OP-PRECONDITION-FAILED-001",
    )?;
    let refuted = agent.change(
        "assess",
        &assessed.fingerprint()?,
        &assessment("h:passerby", &away, "refuted"),
    )?;
    let concluded = agent.change(
        "conclude",
        &refuted.fingerprint()?,
        &conclusion(r#"["u:indoor"]"#),
    )?;
    assert_eq!(concluded.text(&["payload", "state"])?, "resolved");
    let historical = agent.ok(
        "inspect",
        &[("case", quote(CASE)), ("revision", quote(&draft))],
    )?;
    assert_eq!(historical.text(&["payload", "state"])?, "draft");
    assert_eq!(historical.fingerprint()?, draft);
    let current = agent.inspect()?;
    assert_eq!(current.fingerprint()?, concluded.fingerprint()?);
    agent.assert_inspect_parity(&current)?;
    let listed = agent.ok("list", &[])?;
    let cases = listed_cases(&listed.envelope)?;
    assert_eq!(cases.len(), 1);
    assert!(cases[0].1.contains(" is resolved"), "{cases:?}");
    assert_eq!(authority_tree(&root)?, authority_before);
    Ok(())
}

#[test]
fn mcp_case_drift_requires_rebase_then_exact_citation_readmission() -> TestResult {
    let directory = OwnedDirectory::new("rebase")?;
    let root = empty_deployment(&directory)?;
    let agent = Agent::open(&directory, &root)?;
    let opened = agent.ok("open", &[("draft", case_document())])?;
    let active = agent.change("activate", &opened.fingerprint()?, &[])?;
    let seen = evidence("hallway frame 17: person");
    let cited = agent.change(
        "cite",
        &active.fingerprint()?,
        &citation("h:entry", &seen, "support"),
    )?;
    let old_revision = cited.fingerprint()?;
    let handoff = agent.tool("handoff", &object(&[("session", quote(&agent.session))]))?;
    assert!(!handoff.is_error, "{}", handoff.semantic);
    let handoff_id = handoff.text(&["payload", "handoffId"])?;

    // Only the explicitly approved fixture publication moves the world/effect authority.
    publish_event(&directory)?;
    let authority_after_publication = authority_tree(&root)?;
    let resumed = agent.tool("session_resume", &object(&[("handoff", quote(handoff_id))]))?;
    assert!(!resumed.is_error, "{}", resumed.semantic);
    assert_eq!(resumed.text(&["sessionId"])?, agent.session);
    let invalidated = texts(&resumed.envelope, &["executionBoundary", "invalidated"])?;
    assert!(
        invalidated
            .iter()
            .any(|line| line.starts_with(&format!("investigation {CASE} invalidated"))),
        "{invalidated:?}"
    );

    agent.refused(
        "assess",
        &old_revision,
        &assessment("h:entry", &seen, "supported"),
        "ERR-AGENT-SESSION-STALE-001",
    )?;
    let rebased = agent.change("rebase", &old_revision, &[])?;
    assert_eq!(rebased.text(&["payload", "state"])?, "awaiting_evidence");
    let knowns = field(&rebased.envelope, &["payload", "knowns"])?
        .array()
        .ok_or("knowns")?;
    assert_eq!(text(&knowns[0], &["epistemicState"])?, "stale");
    let active = agent.change("activate", &rebased.fingerprint()?, &[])?;
    agent.refused(
        "assess",
        &active.fingerprint()?,
        &assessment("h:entry", &seen, "supported"),
        "ERR-EVIDENCE-MISSING-001",
    )?;

    let witness = evidence("hallway frame 17 is still applicable at the new head");
    let mut readmission = citation("h:entry", &seen, "support");
    readmission.push(("witness", quote(&witness)));
    let readmitted = agent.change("readmit", &active.fingerprint()?, &readmission)?;
    let assessed = agent.change(
        "assess",
        &readmitted.fingerprint()?,
        &assessment("h:entry", &seen, "supported"),
    )?;
    assert_eq!(dispositions(&assessed.envelope)?[0].1, "supported");
    let current = agent.inspect()?;
    assert_eq!(current.fingerprint()?, assessed.fingerprint()?);
    agent.assert_inspect_parity(&current)?;

    // The retained predecessor remains an old basis, not a silently rewritten citation.
    let historical = agent.ok(
        "inspect",
        &[("case", quote(CASE)), ("revision", quote(&old_revision))],
    )?;
    assert_eq!(historical.fingerprint()?, old_revision);
    assert_ne!(
        field(&historical.envelope, &["payload", "basisAnchor"])?,
        field(&current.envelope, &["payload", "basisAnchor"])?
    );
    assert_eq!(authority_tree(&root)?, authority_after_publication);
    Ok(())
}

#[test]
fn mcp_inline_expansion_is_durable_and_notifications_cannot_write_cases() -> TestResult {
    let directory = OwnedDirectory::new("boundaries")?;
    let root = empty_deployment(&directory)?;
    let authority_before = authority_tree(&root)?;
    let agent = Agent::open(&directory, &root)?;
    let outside = directory.0.join("operator-note");
    let outside_bytes = b"this file is not investigation input";
    fs::write(&outside, outside_bytes)?;
    let literal = format!("{}\n--root=/other", outside.display());
    let draft = case_document().replacen(
        &quote("Did a person enter through the east door?"),
        &quote(&literal),
        1,
    );
    let opened = agent.ok("open", &[("draft", draft.clone())])?;
    assert_eq!(opened.text(&["payload", "question"])?, literal);
    let revision = opened.fingerprint()?;

    let before_refusal = snapshot(&root)?;
    for arguments in [
        agent.arguments(
            "open",
            &[("draft", draft.clone()), ("root", quote("/other"))],
        ),
        agent.arguments(
            "open",
            &[
                ("draft", draft.clone()),
                ("principal", quote("principal:other")),
            ],
        ),
        agent.arguments("open", &[("case_file", quote(&outside.to_string_lossy()))]),
        agent.arguments("open", &[("draft", quote(&outside.to_string_lossy()))]),
        agent.arguments(
            "activate",
            &[
                ("case", quote(CASE)),
                ("expected", quote(&revision)),
                ("state", quote("resolved")),
            ],
        ),
        agent.arguments(
            "conclude",
            &[
                ("case", quote(CASE)),
                ("expected", quote(&revision)),
                ("conclusion", quote("resolved")),
                ("stop_rule", quote(STOP_RULE)),
                ("assessment", quote(&evidence("unused"))),
                ("residual_unknowns", r#"["u:indoor","u:indoor"]"#.to_owned()),
            ],
        ),
    ] {
        let response = rpc(&root, PRINCIPAL, "investigate", &arguments)?;
        assert_eq!(
            field(&response, &["error", "code"])?,
            &Value::Number("-32602".to_owned()),
            "{response:?}"
        );
    }
    let duplicate_key = format!(
        r#"{{"session":{},"transition":"open","draft":{},"draft":{}}}"#,
        quote(&agent.session),
        draft,
        draft
    );
    let duplicate_requests = format!(
        "{INIT}\n{READY}\n{}\n",
        call(2, "investigate", &duplicate_key)
    );
    let mut responses = exchange(&root, PRINCIPAL, &duplicate_requests)?;
    assert_eq!(responses.len(), 2, "{responses:?}");
    let response = responses.pop().ok_or("missing parse refusal")?;
    assert_eq!(field(&response, &["id"])?, &Value::Null);
    // Duplicate keys fail the bounded wire parser, before any command or journal is opened.
    assert_eq!(
        field(&response, &["error", "code"])?,
        &Value::Number("-32700".to_owned())
    );
    assert_eq!(snapshot(&root)?, before_refusal);

    let notification = format!(
        r#"{{"jsonrpc":"2.0","method":"tools/call","params":{{"name":"investigate","arguments":{}}}}}"#,
        agent.arguments(
            "activate",
            &[("case", quote(CASE)), ("expected", quote(&revision))]
        )
    );
    let answers = exchange(
        &root,
        PRINCIPAL,
        &format!("{INIT}\n{READY}\n{notification}\n"),
    )?;
    assert_eq!(answers.len(), 1, "{answers:?}");
    assert_eq!(snapshot(&root)?, before_refusal);
    assert_eq!(agent.inspect()?.text(&["payload", "state"])?, "draft");

    let stranger = Answer::from_rpc(&rpc(
        &root,
        "principal:other",
        "investigate",
        &agent.arguments("inspect", &[("case", quote(CASE))]),
    )?)?;
    assert!(stranger.is_error, "{}", stranger.semantic);
    assert_eq!(stranger.text(&["outcome"])?, "refused");
    assert_eq!(field(&stranger.envelope, &["payload"])?, &Value::Null);
    assert_eq!(agent.inspect()?.fingerprint()?, revision);

    let expansion = r#"{"hypothesis":{"hypothesisId":"h:reflection","description":"A reflection crossed the door","predictions":["No hallway track"]},"discriminator":{"discriminatorId":"d:reflection","description":"Compare hallway and exterior frames","separates":["h:entry","h:reflection"],"expectedOutcomes":["An interior track","An exterior-only reflection"]},"probe":"probe:reflection-frames"}"#;
    let expanded = agent.change("expand", &revision, &[("expansion", expansion.to_owned())])?;
    assert_eq!(dispositions(&expanded.envelope)?.len(), 3);
    assert_eq!(
        dispositions(&expanded.envelope)?[2],
        (
            "h:reflection".to_owned(),
            "live".to_owned(),
            "unknown".to_owned()
        )
    );
    let active = agent.change("activate", &expanded.fingerprint()?, &[])?;
    let blocked = agent.change(
        "set-state",
        &active.fingerprint()?,
        &[
            ("state", quote("blocked")),
            (
                "reason",
                quote(&evidence("hallway recording is unavailable")),
            ),
        ],
    )?;
    assert_eq!(blocked.text(&["payload", "state"])?, "blocked");
    let current = agent.inspect()?;
    assert_eq!(current.fingerprint()?, blocked.fingerprint()?);
    agent.assert_inspect_parity(&current)?;
    assert_eq!(fs::read(&outside)?, outside_bytes);
    assert_eq!(authority_tree(&root)?, authority_before);
    Ok(())
}
