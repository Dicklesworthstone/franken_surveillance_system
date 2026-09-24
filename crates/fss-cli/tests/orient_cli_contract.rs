#![forbid(unsafe_code)]
//! Contract tests for `fss orient` (AOP-003 `session.orient`) and `fss explain` (AOP-011) through
//! the real `fss` binary, over real deployments:
//!
//! 1. an empty deployment created by `ReferenceDeployment::open` orients to a valid
//!    `AgentResponseEnvelope` whose capsule carries `not_observable` coverage and no event facts;
//! 2. a deployment with a candidate published by the real `fss-file import` + `fss-event watch
//!    --approve` flow orients to that event as unclassified, indeterminate, single-sensor, and not
//!    corroborated, and `explain` answers why;
//! 3. every orientation view binds its registered view identity and token budget;
//! 4. neither command writes anything: the deployment tree digest is identical before and after;
//! 5. missing, foreign, and argument-invalid invocations are typed refusals with nonzero exits;
//! 6. the same root yields byte-identical output.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_core::{ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const WIDTH: u32 = 96;
const HEIGHT: u32 = 48;
const FRAMES: usize = 14;
const SITE: &str = "site:orient-cli";

// ---------------------------------------------------------------------------------------------
// Minimal JSON reader: every assertion below goes through a full parse, so the output is also
// proven to be one well-formed JSON document.
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Number(String),
    Text(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    fn parse(text: &str) -> TestResult<Self> {
        let bytes = text.as_bytes();
        let mut position = 0;
        let value = parse_value(bytes, &mut position)?;
        skip_whitespace(bytes, &mut position);
        if position != bytes.len() {
            return Err(format!("trailing bytes at {position}").into());
        }
        Ok(value)
    }

    fn get(&self, key: &str) -> TestResult<&Self> {
        match self {
            Self::Object(fields) => fields
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value)
                .ok_or_else(|| format!("missing key {key}").into()),
            _ => Err(format!("not an object when reading {key}").into()),
        }
    }

    fn path(&self, keys: &[&str]) -> TestResult<&Self> {
        let mut current = self;
        for key in keys {
            current = current.get(key)?;
        }
        Ok(current)
    }

    fn text(&self) -> TestResult<&str> {
        match self {
            Self::Text(value) => Ok(value),
            other => Err(format!("not a string: {other:?}").into()),
        }
    }

    fn items(&self) -> TestResult<&[Self]> {
        match self {
            Self::Array(items) => Ok(items),
            other => Err(format!("not an array: {other:?}").into()),
        }
    }

    fn texts(&self) -> TestResult<Vec<&str>> {
        self.items()?.iter().map(Self::text).collect()
    }

    fn number(&self) -> TestResult<u64> {
        match self {
            Self::Number(value) => Ok(value.parse()?),
            other => Err(format!("not a number: {other:?}").into()),
        }
    }

    /// The element of an array of objects whose `key` equals `value`.
    fn find(&self, key: &str, value: &str) -> TestResult<&Self> {
        for item in self.items()? {
            if item.get(key)?.text()? == value {
                return Ok(item);
            }
        }
        Err(format!("no element with {key} = {value}").into())
    }
}

fn skip_whitespace(bytes: &[u8], position: &mut usize) {
    while bytes
        .get(*position)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        *position += 1;
    }
}

fn expect(bytes: &[u8], position: &mut usize, literal: &str) -> TestResult {
    if bytes[*position..].starts_with(literal.as_bytes()) {
        *position += literal.len();
        Ok(())
    } else {
        Err(format!("expected {literal} at {position}").into())
    }
}

fn parse_string(bytes: &[u8], position: &mut usize) -> TestResult<String> {
    expect(bytes, position, "\"")?;
    let mut out = String::new();
    loop {
        let byte = *bytes.get(*position).ok_or("unterminated string")?;
        *position += 1;
        match byte {
            b'"' => return Ok(out),
            b'\\' => {
                let escaped = *bytes.get(*position).ok_or("dangling escape")?;
                *position += 1;
                match escaped {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'b' => out.push('\u{8}'),
                    b'f' => out.push('\u{c}'),
                    b'u' => {
                        let hex = std::str::from_utf8(
                            bytes.get(*position..*position + 4).ok_or("short escape")?,
                        )?;
                        *position += 4;
                        out.push(
                            char::from_u32(u32::from_str_radix(hex, 16)?).ok_or("bad escape")?,
                        );
                    }
                    _ => return Err("unknown escape".into()),
                }
            }
            byte if byte < 0x20 => return Err("raw control character in string".into()),
            _ => {
                let start = *position - 1;
                let mut end = *position;
                while end < bytes.len() && bytes[end] != b'"' && bytes[end] != b'\\' {
                    end += 1;
                }
                out.push_str(std::str::from_utf8(&bytes[start..end])?);
                *position = end;
            }
        }
    }
}

fn parse_value(bytes: &[u8], position: &mut usize) -> TestResult<Json> {
    skip_whitespace(bytes, position);
    match bytes.get(*position).copied().ok_or("unexpected end")? {
        b'n' => expect(bytes, position, "null").map(|()| Json::Null),
        b't' => expect(bytes, position, "true").map(|()| Json::Bool(true)),
        b'f' => expect(bytes, position, "false").map(|()| Json::Bool(false)),
        b'"' => parse_string(bytes, position).map(Json::Text),
        b'[' => {
            *position += 1;
            let mut items = Vec::new();
            skip_whitespace(bytes, position);
            if bytes.get(*position) == Some(&b']') {
                *position += 1;
                return Ok(Json::Array(items));
            }
            loop {
                items.push(parse_value(bytes, position)?);
                skip_whitespace(bytes, position);
                match bytes.get(*position) {
                    Some(b',') => *position += 1,
                    Some(b']') => {
                        *position += 1;
                        return Ok(Json::Array(items));
                    }
                    _ => return Err("bad array".into()),
                }
            }
        }
        b'{' => {
            *position += 1;
            let mut fields: Vec<(String, Json)> = Vec::new();
            skip_whitespace(bytes, position);
            if bytes.get(*position) == Some(&b'}') {
                *position += 1;
                return Ok(Json::Object(fields));
            }
            loop {
                skip_whitespace(bytes, position);
                let key = parse_string(bytes, position)?;
                if fields.iter().any(|(seen, _)| *seen == key) {
                    return Err(format!("duplicate key {key}").into());
                }
                skip_whitespace(bytes, position);
                expect(bytes, position, ":")?;
                fields.push((key, parse_value(bytes, position)?));
                skip_whitespace(bytes, position);
                match bytes.get(*position) {
                    Some(b',') => *position += 1,
                    Some(b'}') => {
                        *position += 1;
                        return Ok(Json::Object(fields));
                    }
                    _ => return Err("bad object".into()),
                }
            }
        }
        _ => {
            let start = *position;
            while bytes
                .get(*position)
                .is_some_and(|byte| byte.is_ascii_digit() || b"-+.eE".contains(byte))
            {
                *position += 1;
            }
            if start == *position {
                return Err(format!("unexpected byte at {start}").into());
            }
            Ok(Json::Number(
                std::str::from_utf8(&bytes[start..*position])?.to_owned(),
            ))
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------------------------

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-orient-cli-{name}-{}-{attempt}",
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

fn empty_deployment(name: &str) -> TestResult<(OwnedDirectory, PathBuf)> {
    let directory = OwnedDirectory::new(name)?;
    let root = directory.0.join("deployment");
    let spec = RootAuthoritySpec {
        trace_id: format!("trace:orient-cli-{name}"),
        operation_id: OperationId::parse(format!("operation:orient-cli-{name}"))?,
        principal: format!("operator:orient-cli-{name}"),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_string()],
        deadline: None,
        priority: 10,
        budgets: fss_core::BudgetVector::default(),
        privacy_scope: "privacy:internal".to_string(),
        retention_scope: "retention:ephemeral".to_string(),
        anchor_universe: ContentDigest::sha256(b"orient-cli"),
        generation: 1,
    };
    let authority = ContextAuthority::new_root(spec)?;
    let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
        &authority,
        directory.0.join("cx"),
    )?);
    drop(ReferenceDeployment::open(&root, SITE, &cx)?);
    Ok((directory, root))
}

/// Dark background; from frame 3 a bright 16x16 square enters at the left edge and moves right.
fn moving_scene() -> TestResult<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut stream = Vec::new();
    for index in 0..FRAMES {
        let mut pixels = vec![40_u8; (WIDTH * HEIGHT) as usize];
        if index >= 3 {
            let left = (index - 3) * 8;
            for y in 8..24 {
                for x in left..left + 16 {
                    pixels[y * WIDTH as usize + x] = 220;
                }
            }
        }
        stream.extend(encode_jpeg(WIDTH, HEIGHT, &pixels, &config)?);
    }
    Ok(stream)
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Value of the first `"key":` in a flat report line: a bare number or a quoted string body.
fn report_field(output: &Output, key: &str) -> TestResult<String> {
    let text = String::from_utf8(output.stdout.clone())?;
    let pattern = format!("\"{key}\":");
    let start = text
        .find(&pattern)
        .ok_or_else(|| format!("missing {key}"))?
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

/// Imports the moving scene with `fss-file import` and publishes its single candidate with
/// `fss-event watch --approve`. Returns the deployment root and the published event identity.
fn published_deployment(name: &str) -> TestResult<(OwnedDirectory, PathBuf, String)> {
    let directory = OwnedDirectory::new(name)?;
    let root = directory.0.join("deployment");
    let input = directory.0.join("recording.bin");
    fs::write(&input, moving_scene()?)?;
    let imported = Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .arg("import")
        .arg("--root")
        .arg(&root)
        .args(["--site", SITE, "--input"])
        .arg(&input)
        .args([
            "--sensor",
            "sensor:orient-cli",
            "--stream",
            "stream:orient-cli",
            "--receive-time-ns",
            "1000000000",
            "--media-format",
            "mjpeg",
        ])
        .output()?;
    success(&imported);
    let import_id = String::from_utf8(imported.stdout)?
        .lines()
        .find_map(|line| line.strip_prefix("import_identity=").map(str::to_owned))
        .ok_or("import identity missing")?;
    fs::remove_file(input)?;
    let watch = |extra: &[&str]| -> TestResult<Output> {
        Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
            .arg("watch")
            .arg("--root")
            .arg(&root)
            .args([
                "--site",
                SITE,
                "--import-id",
                &import_id,
                "--interpretation",
                "gray",
                "--zone",
                "door:64,0,32,32",
            ])
            .args(extra)
            .output()?)
    };
    let prepared = watch(&[])?;
    success(&prepared);
    assert_eq!(report_field(&prepared, "candidate_count")?, "1");
    let proposal = report_field(&prepared, "proposal_digest")?;
    let published = watch(&["--approve", &proposal])?;
    success(&published);
    assert_eq!(report_field(&published, "status")?, "published");
    let event_id = report_field(&published, "event_id")?;
    Ok((directory, root, event_id))
}

fn run_fss(args: &[OsString]) -> TestResult<(Option<i32>, String, String)> {
    let output = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(args)
        .output()?;
    Ok((
        output.status.code(),
        String::from_utf8(output.stdout)?,
        String::from_utf8(output.stderr)?,
    ))
}

fn orient_args(root: &Path, extra: &[&str]) -> Vec<OsString> {
    let mut args = vec![
        OsString::from("orient"),
        OsString::from("--json"),
        OsString::from("--root"),
        root.as_os_str().to_owned(),
    ];
    args.extend(extra.iter().map(OsString::from));
    args
}

fn explain_args(root: &Path, event_id: &str) -> Vec<OsString> {
    vec![
        OsString::from("explain"),
        OsString::from("--json"),
        OsString::from("--root"),
        root.as_os_str().to_owned(),
        OsString::from("--event-id"),
        OsString::from(event_id),
    ]
}

/// Every entry under `root`: mode, size, times, inode, and content digest (the doctor proof).
fn tree_digest(root: &Path) -> TestResult<BTreeMap<PathBuf, String>> {
    let mut out = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let meta = fs::symlink_metadata(&path)?;
        let relative = path.strip_prefix(root)?.to_path_buf();
        let common = format!(
            "mode={:o} size={} mtime={}.{} ctime={}.{} ino={} nlink={}",
            meta.mode(),
            meta.size(),
            meta.mtime(),
            meta.mtime_nsec(),
            meta.ctime(),
            meta.ctime_nsec(),
            meta.ino(),
            meta.nlink()
        );
        let detail = if meta.file_type().is_dir() {
            let mut names = Vec::new();
            for entry in fs::read_dir(&path)? {
                let entry = entry?;
                names.push(entry.file_name().to_string_lossy().into_owned());
                pending.push(entry.path());
            }
            names.sort();
            format!("dir [{}]", names.join(","))
        } else if meta.file_type().is_file() {
            format!("file {}", ContentDigest::sha256(&fs::read(&path)?))
        } else {
            "special".to_owned()
        };
        out.insert(relative, format!("{common} {detail}"));
    }
    Ok(out)
}

/// The verbatim payload bytes of a rendered envelope (between `"payload":` and `"payloadDigest"`).
fn raw_payload(stdout: &str) -> TestResult<&str> {
    let start = stdout.find(",\"payload\":").ok_or("payload missing")? + ",\"payload\":".len();
    let end = stdout
        .find(",\"payloadDigest\":")
        .ok_or("payload digest missing")?;
    Ok(&stdout[start..end])
}

/// Checks the registered envelope shape shared by every successful and refused answer.
fn assert_envelope(stdout: &str, operation_id: &str, view_id: &str) -> TestResult<Json> {
    assert!(stdout.ends_with("}\n"), "one JSON document per line");
    let envelope = Json::parse(stdout.trim_end())?;
    let Json::Object(fields) = &envelope else {
        return Err("envelope is not an object".into());
    };
    let keys: Vec<&str> = fields.iter().map(|(key, _)| key.as_str()).collect();
    assert_eq!(
        keys,
        vec![
            "schema",
            "contractBasis",
            "operationId",
            "requestId",
            "responseRevision",
            "principalId",
            "sessionId",
            "missionId",
            "traceId",
            "inputAnchor",
            "outputAnchor",
            "workspaceRevision",
            "effectiveViewId",
            "effectiveCapabilities",
            "effectivePrivacyProjection",
            "outcome",
            "taskId",
            "taskState",
            "errorId",
            "payloadSchema",
            "payload",
            "payloadDigest",
            "epistemicState",
            "completeness",
            "warnings",
            "contradictions",
            "degradation",
            "budgets",
            "proofPointers",
            "affordances",
            "decisionFingerprint",
            "compressionReceiptId",
            "validUntilNs",
            "continuation",
            "idempotencyKey",
            "recoveryClass",
            "safeRetry",
            "resnapshotRequired",
            "executionBoundary",
            "createdAtNs",
        ],
        "every registered response-envelope field, in schema order"
    );
    assert_eq!(
        envelope.get("schema")?.text()?,
        "fss.agent_response_envelope.v1"
    );
    assert_eq!(envelope.get("operationId")?.text()?, operation_id);
    assert_eq!(envelope.get("effectiveViewId")?.text()?, view_id);
    assert_eq!(
        envelope
            .path(&["contractBasis", "semanticProtocol"])?
            .text()?,
        "fss/1"
    );
    assert_eq!(
        envelope.get("outputAnchor")?,
        &Json::Null,
        "a read commits nothing"
    );
    assert_eq!(
        envelope.get("payloadDigest")?.text()?,
        ContentDigest::sha256(raw_payload(stdout)?.as_bytes()).to_text()
    );
    assert!(
        envelope
            .path(&["executionBoundary", "possiblyOccurred"])?
            .items()?
            .is_empty()
    );
    Ok(envelope)
}

fn cell<'a>(payload: &'a Json, claim: &str) -> TestResult<&'a Json> {
    payload
        .path(&["situationFrame", "knowledgeCells"])?
        .find("cellId", claim)
}

// ---------------------------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------------------------

#[test]
fn empty_deployment_orients_to_a_valid_capsule_without_invented_facts() -> TestResult {
    let (_directory, root) = empty_deployment("empty")?;
    let before = tree_digest(&root)?;
    let (code, stdout, stderr) = run_fss(&orient_args(&root, &[]))?;
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(stderr, "");
    let envelope = assert_envelope(&stdout, "AOP-003", "AVIEW-002")?;
    assert_eq!(tree_digest(&root)?, before, "orient must not write");

    assert_eq!(envelope.get("outcome")?.text()?, "ok");
    assert_eq!(envelope.get("errorId")?, &Json::Null);
    assert_eq!(
        envelope.get("payloadSchema")?.text()?,
        "fss.situation_capsule.v1"
    );
    assert_eq!(envelope.get("epistemicState")?.text()?, "not_observable");
    assert_eq!(envelope.get("completeness")?.text()?, "partial");
    assert_eq!(
        envelope
            .path(&["inputAnchor", "commitSequence"])?
            .number()?,
        0
    );
    assert_eq!(
        envelope.path(&["inputAnchor", "siteLineage"])?.text()?,
        SITE
    );
    assert_eq!(
        envelope.get("effectiveCapabilities")?.texts()?,
        vec!["CAP-AGENT-SITUATION-READ-001"]
    );

    let payload = envelope.get("payload")?;
    let cells = payload
        .path(&["situationFrame", "knowledgeCells"])?
        .items()?;
    assert!(!cells.is_empty());
    for candidate in cells {
        assert!(
            !candidate.get("cellId")?.text()?.starts_with("claim:event:"),
            "an empty deployment has no event facts"
        );
    }
    let coverage = cell(payload, "claim:coverage:site")?;
    assert_eq!(coverage.get("knowledgeState")?.text()?, "not_observable");
    assert!(coverage.get("supportingEvidence")?.items()?.is_empty());
    let ledger = cell(payload, "claim:deployment:ledger-head")?;
    assert_eq!(ledger.get("knowledgeState")?.text()?, "known");
    assert!(
        ledger
            .get("statement")?
            .text()?
            .contains("0 committed batches at commit 0")
    );
    assert!(payload.get("obligations")?.items()?.is_empty());
    assert!(payload.get("indeterminateEffects")?.items()?.is_empty());
    let residual = payload
        .path(&["situationFrame", "worldEnvelope", "adversarialResiduals"])?
        .find("worldId", "world:site:unobserved-activity")?;
    assert_eq!(residual.get("protected")?, &Json::Bool(true));

    // The frontier is listed, classified, and never executed.
    let affordances = payload.get("affordances")?;
    let plan = affordances.find("affordanceId", "affordance:orient:plan")?;
    assert_eq!(plan.get("robustnessClass")?.text()?, "unavailable");
    assert_eq!(plan.get("operationId")?.text()?, "AOP-007");
    let next = envelope.get("affordances")?.texts()?;
    assert!(next.contains(&"affordance:orient:reorient"));
    assert!(!next.contains(&"affordance:orient:plan"));
    assert!(
        payload
            .path(&["controlEnvelope", "blockedAffordanceIds"])?
            .texts()?
            .contains(&"affordance:orient:plan")
    );
    assert_eq!(
        envelope.get("compressionReceiptId")?.text()?,
        payload.path(&["compressionReceipt", "receiptId"])?.text()?
    );
    assert_eq!(
        payload.path(&["compressionReceipt", "viewId"])?.text()?,
        "AVIEW-002"
    );
    assert_eq!(
        payload.path(&["orientProjection", "capsuleId"])?.text()?,
        payload.get("capsuleId")?.text()?
    );
    assert_eq!(
        envelope.get("decisionFingerprint")?.text()?,
        payload.get("decisionFingerprint")?.text()?
    );

    let (_, again, _) = run_fss(&orient_args(&root, &[]))?;
    assert_eq!(again, stdout, "the same root yields byte-identical output");
    assert_eq!(tree_digest(&root)?, before);
    Ok(())
}

#[test]
fn published_watch_candidate_is_indeterminate_single_sensor_and_explainable() -> TestResult {
    let (_directory, root, event_id) = published_deployment("published")?;
    let before = tree_digest(&root)?;

    let (code, stdout, stderr) = run_fss(&orient_args(&root, &[]))?;
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let envelope = assert_envelope(&stdout, "AOP-003", "AVIEW-002")?;
    assert_eq!(envelope.get("outcome")?.text()?, "ok");
    assert_eq!(envelope.get("epistemicState")?.text()?, "indeterminate");
    assert!(
        envelope
            .path(&["inputAnchor", "commitSequence"])?
            .number()?
            > 0
    );
    let payload = envelope.get("payload")?;

    let lifecycle = cell(payload, &format!("claim:event:{event_id}:lifecycle"))?;
    assert_eq!(lifecycle.get("knowledgeState")?.text()?, "known");
    assert!(
        lifecycle
            .get("statement")?
            .text()?
            .contains("as kind unclassified in state indeterminate")
    );
    let presence = cell(payload, &format!("claim:event:{event_id}:unknown-presence"))?;
    assert_eq!(presence.get("knowledgeState")?.text()?, "indeterminate");
    assert_eq!(presence.get("hypothesisDisposition")?.text()?, "live");
    assert_eq!(
        presence.path(&["stateBasis", "basisKind"])?.text()?,
        "reconciliation"
    );
    let corroboration = cell(payload, &format!("claim:event:{event_id}:corroboration"))?;
    assert!(
        corroboration
            .get("statement")?
            .text()?
            .starts_with("Not corroborated: evidence names 1 failure domain")
    );
    assert!(
        envelope
            .get("warnings")?
            .texts()?
            .contains(&format!(
                "{event_id} is single-sensor and not corroborated; it grants no alert or effect authority."
            )
            .as_str())
    );
    let worlds = payload.path(&["situationFrame", "worldEnvelope"])?;
    let live = worlds
        .get("materialAlternativeWorlds")?
        .find("worldId", &format!("world:event:{event_id}:activity-live"))?;
    assert_eq!(live.get("protected")?, &Json::Bool(true));
    worlds
        .get("adversarialResiduals")?
        .find("worldId", &format!("world:event:{event_id}:artifact-live"))?;
    // The watch pipeline publishes no effect: nothing is owed, nothing is indeterminate.
    assert!(payload.get("obligations")?.items()?.is_empty());
    assert!(payload.get("indeterminateEffects")?.items()?.is_empty());
    let explain = payload
        .get("affordances")?
        .find("affordanceId", &format!("affordance:explain:{event_id}"))?;
    assert_eq!(explain.get("operationId")?.text()?, "AOP-011");
    assert_eq!(
        explain.get("robustnessClass")?.text()?,
        "information_gathering"
    );

    let (_, again, _) = run_fss(&orient_args(&root, &[]))?;
    assert_eq!(again, stdout, "byte-identical orientation");
    // One event's protected worlds and evidence exceed the brief target (800): admitted at the
    // registered maximum (1600) with a degradation; pulse (maximum 300) cannot hold them and is
    // refused rather than truncated.
    assert_eq!(
        payload
            .path(&["compressionReceipt", "targetTokens"])?
            .number()?,
        1600
    );
    assert!(
        envelope
            .get("degradation")?
            .texts()?
            .contains(&"The critical context exceeds the brief target of 800 tokens; it was admitted at the registered maximum of 1600 tokens.")
    );
    let (code, pulse, _) = run_fss(&orient_args(&root, &["--view", "pulse"]))?;
    assert_eq!(code, Some(5));
    let pulse = assert_envelope(&pulse, "AOP-003", "AVIEW-001")?;
    assert_eq!(pulse.get("outcome")?.text()?, "refused");
    assert_eq!(
        pulse.get("errorId")?.text()?,
        "ERR-AGENT-CONTEXT-INCOMPLETE-001"
    );
    let (code, map, _) = run_fss(&orient_args(&root, &["--view", "epistemic_map"]))?;
    assert_eq!(code, Some(0));
    let map = assert_envelope(&map, "AOP-003", "AVIEW-008")?;
    assert_eq!(
        map.path(&["payload", "compressionReceipt", "targetTokens"])?
            .number()?,
        1500
    );
    assert_ne!(
        map.path(&["payload", "capsuleId"])?.text()?,
        payload.get("capsuleId")?.text()?,
        "the view is bound into the capsule identity"
    );

    let (code, explained, stderr) = run_fss(&explain_args(&root, &event_id))?;
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let answer = assert_envelope(&explained, "AOP-011", "AVIEW-007")?;
    assert_eq!(answer.get("outcome")?.text()?, "ok");
    assert_eq!(
        answer.get("payloadSchema")?.text()?,
        "fss.agent_cognitive_envelope.v1"
    );
    assert_eq!(answer.get("epistemicState")?.text()?, "indeterminate");
    let cognitive = answer.get("payload")?;
    assert_eq!(
        cognitive.get("schema")?.text()?,
        "fss.agent_cognitive_envelope.v1"
    );
    assert_eq!(cognitive.get("answerClass")?.text()?, "indeterminate");
    let proposition = cognitive
        .path(&["epistemic", "propositions"])?
        .find("id", &format!("claim:event:{event_id}:unknown-presence"))?;
    assert_eq!(proposition.get("state")?.text()?, "indeterminate");
    assert_eq!(proposition.get("provenance")?.text()?, "derived");
    let invalidators = cognitive.path(&["epistemic", "invalidators"])?.texts()?;
    assert!(
        invalidators
            .iter()
            .any(|line| line.starts_with("Supporting evidence from a failure domain other than"))
    );
    assert!(!cognitive.get("evidenceHandles")?.items()?.is_empty());
    assert_eq!(
        cognitive.path(&["coverage", "authorizedDomain"])?.texts()?,
        vec!["door"]
    );
    assert_eq!(
        answer.get("decisionFingerprint")?.text()?,
        cognitive.get("decisionDigest")?.text()?
    );
    let (_, explained_again, _) = run_fss(&explain_args(&root, &event_id))?;
    assert_eq!(explained_again, explained, "byte-identical explanation");

    let (code, unknown, _) = run_fss(&explain_args(&root, "event:watch:never-published"))?;
    assert_eq!(code, Some(5));
    let refused = assert_envelope(&unknown, "AOP-011", "AVIEW-007")?;
    assert_eq!(refused.get("outcome")?.text()?, "refused");
    assert_eq!(
        refused.get("errorId")?.text()?,
        "ERR-AGENT-EVENT-NOT-FOUND-001"
    );
    assert_eq!(
        refused.path(&["payload", "answerClass"])?.text()?,
        "refusal"
    );

    assert_eq!(
        tree_digest(&root)?,
        before,
        "orient and explain must not write"
    );
    Ok(())
}

#[test]
fn every_orientation_view_binds_its_registered_view_and_budget() -> TestResult {
    let (_directory, root) = empty_deployment("views")?;
    let before = tree_digest(&root)?;
    // An empty deployment's critical context exceeds the pulse target (120) and is admitted at
    // the registered pulse maximum (300) with an explicit degradation; brief and epistemic_map
    // fit their registered targets.
    for (name, view_id, admitted_at, fell_back) in [
        ("pulse", "AVIEW-001", 300, true),
        ("brief", "AVIEW-002", 800, false),
        ("epistemic_map", "AVIEW-008", 1500, false),
    ] {
        let (code, stdout, stderr) = run_fss(&orient_args(&root, &["--view", name]))?;
        assert_eq!(code, Some(0), "{name}: {stderr}");
        let envelope = assert_envelope(&stdout, "AOP-003", view_id)?;
        let receipt = envelope.path(&["payload", "compressionReceipt"])?;
        assert_eq!(receipt.get("viewId")?.text()?, view_id);
        let admitted = receipt.get("targetTokens")?.number()?;
        assert_eq!(admitted, admitted_at, "{name}");
        assert_eq!(
            envelope
                .get("degradation")?
                .texts()?
                .iter()
                .any(|line| line.contains(&format!("registered maximum of {admitted_at} tokens"))),
            fell_back,
            "{name}"
        );
        assert_eq!(
            envelope
                .path(&["payload", "resourceState", "pressure"])?
                .text()?,
            if fell_back { "elevated" } else { "nominal" }
        );
        assert!(receipt.get("actualTokens")?.number()? <= admitted);
        assert_eq!(
            receipt
                .path(&["criticalPreservation", "omittedCriticalItems"])?
                .number()?,
            0
        );
        assert_eq!(
            envelope
                .path(&["payload", "contextPack", "viewId"])?
                .text()?,
            view_id
        );
    }
    let (_, pulse, _) = run_fss(&orient_args(&root, &["--view", "pulse"]))?;
    let pulse = Json::parse(pulse.trim_end())?;
    let affordances: Vec<&str> = pulse
        .path(&["payload", "affordances"])?
        .items()?
        .iter()
        .map(|item| item.get("affordanceId").and_then(Json::text))
        .collect::<TestResult<_>>()?;
    assert_eq!(affordances, vec!["affordance:orient:reorient"]);

    // Critical context is refused, never truncated, when it cannot fit an explicit budget.
    let (code, stdout, _) = run_fss(&orient_args(&root, &["--budget-tokens", "8"]))?;
    assert_eq!(code, Some(5));
    let refused = assert_envelope(&stdout, "AOP-003", "AVIEW-002")?;
    assert_eq!(refused.get("outcome")?.text()?, "refused");
    assert_eq!(
        refused.get("errorId")?.text()?,
        "ERR-AGENT-CONTEXT-INCOMPLETE-001"
    );
    assert_eq!(refused.get("payload")?, &Json::Null);
    assert_eq!(tree_digest(&root)?, before);
    Ok(())
}

#[test]
fn missing_foreign_and_malformed_requests_are_typed_refusals() -> TestResult {
    let directory = OwnedDirectory::new("refusals")?;
    let missing = directory.0.join("missing");
    for args in [
        orient_args(&missing, &[]),
        explain_args(&missing, "event:any"),
    ] {
        let (code, stdout, _) = run_fss(&args)?;
        assert_eq!(code, Some(4), "{args:?}");
        let diagnostic = Json::parse(stdout.trim_end())?;
        assert_eq!(diagnostic.get("schema")?.text()?, "fss.cli_diagnostic.v1");
        assert_eq!(diagnostic.get("phase")?.text()?, "execution");
        assert_eq!(
            diagnostic.get("error_id")?.text()?,
            "ERR-DOCTOR-NOT-A-DEPLOYMENT-001"
        );
        assert_eq!(
            diagnostic.get("exit_id")?.text()?,
            "EXIT-DOCTOR-NOT-A-DEPLOYMENT-004"
        );
        assert!(!missing.exists(), "a refused read creates nothing");
    }

    let foreign = directory.0.join("foreign");
    fs::create_dir(&foreign)?;
    fs::write(foreign.join("notes.txt"), b"not a deployment")?;
    let before = tree_digest(&foreign)?;
    let (code, stdout, _) = run_fss(&orient_args(&foreign, &[]))?;
    assert_eq!(code, Some(4));
    assert!(stdout.contains("\"error_id\":\"ERR-DOCTOR-NOT-A-DEPLOYMENT-001\""));
    assert_eq!(tree_digest(&foreign)?, before);

    let (_empty_dir, root) = empty_deployment("malformed")?;
    let root_text = root.to_str().ok_or("temporary path is not UTF-8")?;
    for (args, error_id) in [
        (vec!["orient", "--json"], "ERR-CLI-MISSING-VALUE-001"),
        (
            vec!["orient", "--root", root_text],
            "ERR-CLI-MISSING-VALUE-001",
        ),
        (
            vec!["orient", "--json", "--root", root_text, "--view", "case"],
            "ERR-CLI-MALFORMED-VALUE-001",
        ),
        (
            vec![
                "orient",
                "--json",
                "--root",
                root_text,
                "--budget-tokens",
                "0",
            ],
            "ERR-CLI-MALFORMED-VALUE-001",
        ),
        (
            vec![
                "orient",
                "--json",
                "--root",
                root_text,
                "--view",
                "pulse",
                "--budget-tokens",
                "301",
            ],
            "ERR-CLI-MALFORMED-VALUE-001",
        ),
        (
            vec!["orient", "--json", "--root", root_text, "--root", root_text],
            "ERR-CLI-DUPLICATE-OPTION-001",
        ),
        (
            vec!["orient", "--json", "--root", root_text, "--execute"],
            "ERR-CLI-UNKNOWN-OPTION-001",
        ),
        (
            vec!["orient", "--json", "--root", root_text, "extra"],
            "ERR-CLI-TRAILING-ARGUMENT-001",
        ),
        (
            vec!["explain", "--json", "--root", root_text],
            "ERR-CLI-MISSING-VALUE-001",
        ),
        (
            vec![
                "explain",
                "--json",
                "--root",
                root_text,
                "--event-id",
                "bad id",
            ],
            "ERR-CLI-MALFORMED-VALUE-001",
        ),
    ] {
        let os_args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let (code, stdout, stderr) = run_fss(&os_args)?;
        assert_eq!(code, Some(2), "{args:?}");
        assert_eq!(stdout, "", "no answer on an argument error: {args:?}");
        assert!(
            stderr.starts_with(&format!("fss: error[{error_id}]")),
            "{args:?}: {stderr}"
        );
    }

    // `--name=value` spelling is accepted like doctor's `--root=`.
    let mut equals = OsString::from("--root=");
    equals.push(root.as_os_str());
    let (code, via_equals, _) = run_fss(&[
        OsString::from("orient"),
        equals,
        OsString::from("--json"),
        OsString::from("--view=pulse"),
    ])?;
    assert_eq!(code, Some(0));
    let (_, via_space, _) = run_fss(&orient_args(&root, &["--view", "pulse"]))?;
    assert_eq!(via_equals, via_space);
    Ok(())
}
