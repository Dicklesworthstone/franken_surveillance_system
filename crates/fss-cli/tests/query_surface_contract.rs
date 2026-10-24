#![forbid(unsafe_code)]
//! Real executable parity and read-only query checks over retained reference deployments.
//! Generated recordings exercise wiring only; they establish no detector-quality claim.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use fss_cli::{ExitIdentity, escape_json_str, execute_fss_with_exit, parse_fss_args};
use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, DecisionPath, EventEvidence,
    EventHypothesis, EventId, EventKind, EventState, EvidenceClass, EvidenceEdgeRelation,
    OperationId, ProbabilityInterval, RootAuthoritySpec, TimestampNs,
};
use fss_reference::agent_follow::snapshot_anchor_token;
use fss_reference::agent_orient::{OrientLimits, read_deployment};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{
    ADP_REPLAY_ROW_ID, ReferenceDeployment, ReferencePolicyAction, ReferencePolicyDecision,
    ReplayCx, ReplayIoAuthority,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const SITE: &str = "site:query-surface";
const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"query-contract","version":"1"}}}"#;
const READY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

struct Fixture {
    directory: PathBuf,
    root: PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> TestResult<Self> {
        for attempt in 0..100 {
            let directory = std::env::temp_dir().join(format!(
                "fss-query-surface-{tag}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&directory) {
                Ok(()) => {
                    let fixture = Self {
                        root: directory.join("deployment"),
                        directory,
                    };
                    let authority = ContextAuthority::new_root(RootAuthoritySpec {
                        trace_id: "trace:query-surface".to_owned(),
                        operation_id: OperationId::parse("operation:query-surface")?,
                        principal: "operator:query-surface".to_owned(),
                        capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
                        deadline: None,
                        priority: 10,
                        budgets: BudgetVector::default(),
                        privacy_scope: "privacy:internal".to_owned(),
                        retention_scope: "retention:ephemeral".to_owned(),
                        anchor_universe: ContentDigest::sha256(b"query-surface"),
                        generation: 1,
                    })?;
                    let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
                        &authority,
                        fixture.directory.join("cx"),
                    )?);
                    drop(ReferenceDeployment::open(&fixture.root, SITE, &cx)?);
                    return Ok(fixture);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("query fixture directory capacity".into())
    }

    // Exercise native custody and every read surface with explicitly synthetic hypotheses.
    // No sensor observations, coverage, calibrated detections or effect authority are claimed.
    fn publish_hypotheses(&self, count: usize) -> TestResult<Vec<String>> {
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:query-catalogue".to_owned(),
            operation_id: OperationId::parse("operation:query-catalogue")?,
            principal: "operator:query-catalogue".to_owned(),
            capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::default(),
            privacy_scope: "privacy:internal".to_owned(),
            retention_scope: "retention:ephemeral".to_owned(),
            anchor_universe: ContentDigest::sha256(b"query-catalogue"),
            generation: 1,
        })?;
        let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
            &authority,
            self.directory.join("catalogue-cx"),
        )?);
        let start = read_deployment(&self.root, &OrientLimits::default())?
            .events
            .len();
        let mut deployment = ReferenceDeployment::open(&self.root, SITE, &cx)?;
        let mut ids = Vec::new();
        for index in start..start + count {
            let event = EventHypothesis {
                schema: EventHypothesis::SCHEMA.to_owned(),
                event_id: EventId::parse(format!("event:query-catalogue:{index:04}"))?,
                revision: 1,
                supersedes: None,
                state: EventState::Hypothesized,
                kind: EventKind::UnknownPresence,
                interval: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
                uncertainty_reason: None,
                zone_ids: vec!["door".to_owned()],
                track_ids: Vec::new(),
                probability: ProbabilityInterval::new(0.0, 1.0)?,
                evidence: Vec::new(),
                model_receipts: Vec::new(),
                decision_path: DecisionPath {
                    policy_generation: ContentDigest::sha256(b"query-catalogue-policy"),
                    fingerprint: ContentDigest::sha256(b"query-catalogue-hypothesis"),
                    abstained: true,
                    abstention_reason: Some("synthetic hypothesis only".to_owned()),
                },
            };
            event.verify()?;
            ids.push(event.event_id.as_str().to_owned());
            deployment.publish_event(
                &ReferencePolicyDecision {
                    event,
                    action: ReferencePolicyAction::Hold,
                },
                &cx,
            )?;
        }
        Ok(ids)
    }

    fn revise(&self, id: &str) -> TestResult {
        let snapshot = read_deployment(&self.root, &OrientLimits::default())?;
        let mut event = snapshot
            .event(&EventId::parse(id)?)
            .ok_or("missing event")?
            .event
            .clone();
        let predecessor = event.revision_digest();
        event.revision += 1;
        event.supersedes = Some(predecessor);
        event.state = EventState::Indeterminate;
        event.uncertainty_reason = Some("synthetic revision remains unadjudicated".to_owned());
        event.evidence.push(EventEvidence {
            digest: predecessor,
            class: EvidenceClass::Derived,
            failure_domain: "synthetic:query-catalogue".to_owned(),
            supports: true,
            relation: EvidenceEdgeRelation::Supports,
            capsule_digest: None,
            identity_digest: None,
        });
        event.decision_path.fingerprint = ContentDigest::sha256(b"revised query hypothesis");
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:query-revision".to_owned(),
            operation_id: OperationId::parse("operation:query-revision")?,
            principal: "operator:query-revision".to_owned(),
            capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::default(),
            privacy_scope: "privacy:internal".to_owned(),
            retention_scope: "retention:ephemeral".to_owned(),
            anchor_universe: ContentDigest::sha256(b"query-revision"),
            generation: 1,
        })?;
        let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
            &authority,
            self.directory.join("revision-cx"),
        )?);
        ReferenceDeployment::open(&self.root, SITE, &cx)?.publish_event(
            &ReferencePolicyDecision {
                event,
                action: ReferencePolicyAction::Hold,
            },
            &cx,
        )?;
        Ok(())
    }

    fn publish(&self, sensor: &str) -> TestResult<String> {
        self.publish_recording(sensor).map(|(event, _)| event)
    }

    fn publish_recording(&self, sensor: &str) -> TestResult<(String, String)> {
        let config = JpegConfig {
            quality: 90,
            subsampling: Subsampling::Grayscale,
            restart_interval: 0,
            custom_markers: Vec::new(),
        };
        let mut recording = Vec::new();
        for index in 0..14_usize {
            let mut pixels = vec![40_u8; 96 * 48];
            if index >= 3 {
                let left = (index - 3) * 8;
                for y in 8..24 {
                    for x in left..left + 16 {
                        pixels[y * 96 + x] = 220;
                    }
                }
            }
            recording.extend(encode_jpeg(96, 48, &pixels, &config)?);
        }
        let input = self
            .directory
            .join(format!("{}.mjpeg", sensor.replace(':', "-")));
        fs::write(&input, recording)?;
        let imported = Command::new(env!("CARGO_BIN_EXE_fss-file"))
            .args(["import", "--root"])
            .arg(&self.root)
            .args(["--site", SITE, "--input"])
            .arg(&input)
            .args(["--sensor", sensor, "--stream", &format!("stream:{sensor}")])
            .args([
                "--media-format",
                "mjpeg",
                "--receive-time-ns",
                "10000000000000",
            ])
            .args([
                "--capture-start-ns",
                "1000000000",
                "--capture-uncertainty-ns",
                "1000000",
            ])
            .args(["--assumed-fps", "10"])
            .output()?;
        success(&imported);
        let imported = String::from_utf8(imported.stdout)?;
        let identity = imported
            .lines()
            .find_map(|line| line.strip_prefix("import_identity="))
            .ok_or("missing import identity")?;
        let watch = |approval: Option<&str>| -> TestResult<Output> {
            let mut command = Command::new(env!("CARGO_BIN_EXE_fss-event"));
            command
                .args(["watch", "--root"])
                .arg(&self.root)
                .args([
                    "--site",
                    SITE,
                    "--import-id",
                    identity,
                    "--interpretation",
                    "gray",
                ])
                .args(["--zone", "door:64,0,32,32"]);
            if let Some(approval) = approval {
                command.args(["--approve", approval]);
            }
            Ok(command.output()?)
        };
        let prepared = watch(None)?;
        success(&prepared);
        let prepared = String::from_utf8(prepared.stdout)?;
        let proposal = quoted_field(&prepared, "proposal_digest")?;
        let published = watch(Some(&proposal))?;
        success(&published);
        Ok((
            quoted_field(&String::from_utf8(published.stdout)?, "event_id")?,
            identity.to_owned(),
        ))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn quote(value: &str) -> String {
    format!("\"{}\"", escape_json_str(value))
}

// Used only for digests, tokens and fixture event IDs, whose alphabets exclude JSON escapes.
fn quoted_field(text: &str, field: &str) -> TestResult<String> {
    let marker = format!("\"{field}\":\"");
    let start = text
        .find(&marker)
        .ok_or_else(|| format!("missing {field}"))?
        + marker.len();
    let value = text[start..]
        .split('"')
        .next()
        .ok_or("unterminated token")?;
    if value.contains('\\') {
        return Err("unexpected escaped token".into());
    }
    Ok(value.to_owned())
}

fn tree(root: &Path) -> TestResult<BTreeMap<PathBuf, (bool, Vec<u8>)>> {
    let mut pending = vec![root.to_path_buf()];
    let mut result = BTreeMap::new();
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        let relative = path.strip_prefix(root)?.to_path_buf();
        if metadata.is_dir() {
            result.insert(relative, (true, Vec::new()));
            for entry in fs::read_dir(path)? {
                pending.push(entry?.path());
            }
        } else if metadata.is_file() {
            result.insert(relative, (false, fs::read(path)?));
        } else {
            return Err("special file in reference fixture".into());
        }
    }
    Ok(result)
}

fn query(root: &Path, extra: &[&str]) -> TestResult<(String, ExitIdentity)> {
    native_command(root, "query", extra)
}

fn native_command(
    root: &Path,
    operation: &str,
    extra: &[&str],
) -> TestResult<(String, ExitIdentity)> {
    let mut args: Vec<OsString> = vec![
        operation.into(),
        "--json".into(),
        "--root".into(),
        root.as_os_str().to_owned(),
    ];
    args.extend(extra.iter().map(OsString::from));
    let expected = execute_fss_with_exit(parse_fss_args(args.clone())?);
    let output = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(args)
        .output()?;
    assert_eq!(output.status.code(), Some(i32::from(expected.1.code)));
    assert_eq!(
        String::from_utf8(output.stdout)?,
        format!("{}\n", expected.0)
    );
    assert!(output.stderr.is_empty());
    Ok(expected)
}

fn mcp(root: &Path, arguments: &str, expected: &(String, ExitIdentity)) -> TestResult {
    mcp_tool(root, "query", arguments, expected)
}

fn mcp_tool(
    root: &Path,
    name: &str,
    arguments: &str,
    expected: &(String, ExitIdentity),
) -> TestResult {
    let request = format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":{},"arguments":{arguments}}}}}"#,
        quote(name)
    );
    let mut process = Command::new(env!("CARGO_BIN_EXE_fss-mcp"))
        .arg("--root")
        .arg(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = process.stdin.take().ok_or("missing stdin")?;
    writeln!(stdin, "{INIT}\n{READY}\n{request}")?;
    drop(stdin);
    let output = process.wait_with_output()?;
    success(&output);
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout)?;
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[1].contains(&format!("\"text\":{}", quote(&expected.0))));
    assert!(lines[1].contains(&format!("\"isError\":{}", expected.1.code != 0)));
    Ok(())
}

fn conforms(fixture: &Fixture, answer: &str) -> TestResult {
    let repo = std::env::var_os("CARGO_MANIFEST_DIR")
        .map_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")), PathBuf::from)
        .join("../..");
    let start = answer.find(",\"payload\":").ok_or("missing payload")? + ",\"payload\":".len();
    let end = answer
        .find(",\"payloadDigest\":")
        .ok_or("missing payload digest")?;
    let payload = &answer[start..end];
    for (schema, instance) in [
        ("agent_response_envelope.v1.json", answer),
        ("agent_cognitive_envelope.v1.json", payload),
    ] {
        if instance == "null" {
            continue;
        }
        let path = fixture.directory.join(format!("{schema}.instance.json"));
        fs::write(&path, instance)?;
        let output = Command::new("python3")
            .arg("-B")
            .arg(repo.join("scripts/json_instance_validate.py"))
            .arg(repo.join("schemas").join(schema))
            .arg(path)
            .output()?;
        success(&output);
    }
    Ok(())
}

#[test]
fn real_empty_catalogue_and_native_refusal_match_every_surface() -> TestResult {
    let fixture = Fixture::new("empty")?;
    let before = tree(&fixture.root)?;
    let answer = query(&fixture.root, &[])?;
    assert_eq!(answer.1, ExitIdentity::SUCCESS);
    assert!(answer.0.contains("committed_index_exhausted"));
    assert!(answer.0.contains("claim:query:physical-absence"));
    assert!(answer.0.contains("not_observable"));
    conforms(&fixture, &answer.0)?;
    mcp(&fixture.root, "{}", &answer)?;
    let refused = query(
        &fixture.root,
        &["--continuation", "continuation:wrong-stream"],
    )?;
    assert_eq!(refused.1, ExitIdentity::AGENT_REFUSED);
    assert!(refused.0.contains("continuation_wrong_stream"));
    conforms(&fixture, &refused.0)?;
    mcp(
        &fixture.root,
        r#"{"continuation":"continuation:wrong-stream"}"#,
        &refused,
    )?;
    assert_eq!(tree(&fixture.root)?, before);
    Ok(())
}

#[test]
fn published_recordings_query_exactly_and_paginate_without_changing_custody() -> TestResult {
    let fixture = Fixture::new("recordings")?;
    let first_id = fixture.publish("sensor:query-east")?;
    let second_id = fixture.publish("sensor:query-west")?;
    assert_ne!(first_id, second_id);
    let snapshot = read_deployment(&fixture.root, &OrientLimits::default())?;
    assert_eq!(snapshot.events.len(), 2);
    let before = tree(&fixture.root)?;
    let page_one = query(&fixture.root, &["--max-entries", "1"])?;
    assert_eq!(page_one.1, ExitIdentity::SUCCESS);
    conforms(&fixture, &page_one.0)?;
    mcp(&fixture.root, r#"{"max_entries":1}"#, &page_one)?;
    let cursor = quoted_field(&page_one.0, "continuation")?;
    let page_two = query(
        &fixture.root,
        &["--max-entries", "1", "--continuation", &cursor],
    )?;
    assert_eq!(page_two.1, ExitIdentity::SUCCESS);
    conforms(&fixture, &page_two.0)?;
    mcp(
        &fixture.root,
        &format!(r#"{{"max_entries":1,"continuation":{}}}"#, quote(&cursor)),
        &page_two,
    )?;
    for id in [&first_id, &second_id] {
        let proposition = format!("\"id\":{}", quote(id));
        assert_eq!(
            page_one.0.matches(&proposition).count() + page_two.0.matches(&proposition).count(),
            1
        );
    }
    assert!(page_two.0.contains("\"continuation\":null"));
    let changed = query(
        &fixture.root,
        &["--max-entries", "2", "--continuation", &cursor],
    )?;
    assert_eq!(changed.1, ExitIdentity::AGENT_REFUSED);
    let row = snapshot
        .events
        .iter()
        .find(|row| row.event.event_id.as_str() == first_id)
        .ok_or("missing published record")?;
    let endpoint = row.event.interval.latest.0.to_string();
    let matching = query(
        &fixture.root,
        &[
            "--event-id",
            &first_id,
            "--from-ns",
            &endpoint,
            "--through-ns",
            &endpoint,
        ],
    )?;
    assert_eq!(matching.1, ExitIdentity::SUCCESS);
    assert!(matching.0.contains(&format!("\"id\":{}", quote(&first_id))));
    let outside = row
        .event
        .interval
        .latest
        .0
        .checked_add(1)
        .ok_or("fixture time overflow")?
        .to_string();
    let empty = query(
        &fixture.root,
        &["--event-id", &first_id, "--from-ns", &outside],
    )?;
    assert_eq!(empty.1, ExitIdentity::SUCCESS);
    assert!(!empty.0.contains(&format!("\"id\":{}", quote(&first_id))));
    assert!(empty.0.contains("claim:query:physical-absence"));
    assert_eq!(tree(&fixture.root)?, before);
    Ok(())
}

#[test]
fn large_native_catalogue_paginates_across_cli_library_and_mcp_without_mutation() -> TestResult {
    let fixture = Fixture::new("large-catalogue")?;
    let ids = fixture.publish_hypotheses(257)?;
    let snapshot = read_deployment(&fixture.root, &OrientLimits::default())?;
    assert_eq!(snapshot.events.len(), ids.len());
    assert!(
        snapshot
            .events
            .iter()
            .all(|row| row.event.evidence.is_empty())
    );
    let before = tree(&fixture.root)?;
    let mut continuation: Option<String> = None;
    let mut seen = BTreeMap::new();
    let mut pages = 0;
    loop {
        let mut extra = vec!["--max-entries", "32"];
        if let Some(token) = continuation.as_deref() {
            extra.extend(["--continuation", token]);
        }
        let answer = query(&fixture.root, &extra)?;
        assert_eq!(answer.1, ExitIdentity::SUCCESS, "{}", answer.0);
        conforms(&fixture, &answer.0)?;
        let arguments = match &continuation {
            Some(token) => format!(r#"{{"max_entries":32,"continuation":{}}}"#, quote(token)),
            None => r#"{"max_entries":32}"#.to_owned(),
        };
        mcp(&fixture.root, &arguments, &answer)?;
        assert!(answer.0.contains("claim:query:physical-absence"));
        let mut page_events = 0;
        for id in &ids {
            let marker = format!("\"id\":{}", quote(id));
            let count = answer.0.matches(&marker).count();
            assert!(count <= 1);
            if count == 1 {
                assert!(seen.insert(id.clone(), pages).is_none(), "duplicate {id}");
                page_events += 1;
            }
        }
        assert!((1..=32).contains(&page_events));
        pages += 1;
        if answer.0.contains("\"continuation\":null") {
            break;
        }
        continuation = Some(quoted_field(&answer.0, "continuation")?);
        assert!(pages < 9, "catalogue did not exhaust at its exact bound");
    }
    assert_eq!(pages, 9);
    assert_eq!(seen.len(), ids.len());
    for id in &ids {
        assert!(seen.contains_key(id), "missing {id}");
    }
    assert_eq!(tree(&fixture.root)?, before);
    Ok(())
}

#[test]
fn historical_catalogue_and_explanation_replay_exact_revisions_across_fresh_processes() -> TestResult
{
    let fixture = Fixture::new("history")?;
    let ids = fixture.publish_hypotheses(2)?;
    let old = read_deployment(&fixture.root, &OrientLimits::default())?;
    let at = snapshot_anchor_token(&old);
    let old_revision = old.events[0].revision_digest;
    let page_one = query(&fixture.root, &["--at", &at, "--max-entries", "1"])?;
    assert_eq!(page_one.1, ExitIdentity::SUCCESS, "{}", page_one.0);
    let cursor = quoted_field(&page_one.0, "continuation")?;
    fixture.revise(&ids[0])?;
    let later = fixture.publish_hypotheses(1)?.remove(0);
    let head = snapshot_anchor_token(&read_deployment(&fixture.root, &OrientLimits::default())?);
    let before = tree(&fixture.root)?;

    let historical = query(&fixture.root, &["--at", &at, "--state", "hypothesized"])?;
    assert_eq!(historical.1, ExitIdentity::SUCCESS, "{}", historical.0);
    assert!(historical.0.contains("claim:read:historical-scope"));
    assert!(historical.0.contains(&at));
    assert!(historical.0.contains(&head));
    assert!(historical.0.contains(&format!("\"id\":{}", quote(&ids[0]))));
    assert!(!historical.0.contains(&format!("\"id\":{}", quote(&later))));
    conforms(&fixture, &historical.0)?;
    mcp(
        &fixture.root,
        &format!(r#"{{"at":{},"state":"hypothesized"}}"#, quote(&at)),
        &historical,
    )?;

    let current = query(
        &fixture.root,
        &["--event-id", &ids[0], "--state", "hypothesized"],
    )?;
    assert_eq!(current.1, ExitIdentity::SUCCESS);
    assert!(!current.0.contains(&format!("\"id\":{}", quote(&ids[0]))));
    let stale_head = query(&fixture.root, &["--anchor", &at])?;
    assert_eq!(stale_head.1, ExitIdentity::AGENT_REFUSED);
    assert!(stale_head.0.contains("query anchor changed"));

    // The selected retained prefix is stable even as the deployment head advances. The native
    // continuation stays bound to that prefix; omitting --at must not silently replay it.
    let page_two = query(
        &fixture.root,
        &["--at", &at, "--max-entries", "1", "--continuation", &cursor],
    )?;
    assert_eq!(page_two.1, ExitIdentity::SUCCESS, "{}", page_two.0);
    assert!(page_two.0.contains("\"continuation\":null"));
    for id in &ids {
        let marker = format!("\"id\":{}", quote(id));
        assert_eq!(
            page_one.0.matches(&marker).count() + page_two.0.matches(&marker).count(),
            1
        );
    }
    assert!(!page_two.0.contains(&format!("\"id\":{}", quote(&later))));
    assert_eq!(
        query(
            &fixture.root,
            &["--max-entries", "1", "--continuation", &cursor,]
        )?
        .1,
        ExitIdentity::AGENT_REFUSED
    );
    mcp(
        &fixture.root,
        &format!(
            r#"{{"at":{},"max_entries":1,"continuation":{}}}"#,
            quote(&at),
            quote(&cursor)
        ),
        &page_two,
    )?;

    let explanation = native_command(
        &fixture.root,
        "explain",
        &[
            "--event-id",
            &ids[0],
            "--at",
            &at,
            "--view",
            "forensic",
            "--custody",
            "yes",
        ],
    )?;
    assert_eq!(explanation.1, ExitIdentity::SUCCESS, "{}", explanation.0);
    assert!(explanation.0.contains(&old_revision.to_text()));
    assert!(explanation.0.contains("revision 1 at commit"));
    assert!(explanation.0.contains("claim:read:historical-scope"));
    assert!(explanation.0.contains("publication-closure"));
    conforms(&fixture, &explanation.0)?;
    mcp_tool(
        &fixture.root,
        "explain",
        &format!(
            r#"{{"event_id":{},"at":{},"view":"forensic","custody":"yes"}}"#,
            quote(&ids[0]),
            quote(&at)
        ),
        &explanation,
    )?;
    let latest = native_command(
        &fixture.root,
        "explain",
        &["--event-id", &ids[0], "--view", "forensic"],
    )?;
    assert_eq!(latest.1, ExitIdentity::SUCCESS, "{}", latest.0);
    assert!(latest.0.contains("revision 2 at commit"));

    let missing = native_command(
        &fixture.root,
        "explain",
        &["--event-id", &later, "--at", &at, "--view", "forensic"],
    )?;
    assert_eq!(missing.1, ExitIdentity::AGENT_REFUSED);
    assert!(missing.0.contains("ERR-AGENT-EVENT-NOT-FOUND-001"));
    assert!(missing.0.contains("claim:read:historical-scope"));
    conforms(&fixture, &missing.0)?;
    assert_eq!(tree(&fixture.root)?, before);
    Ok(())
}

#[test]
fn unknown_foreign_and_forged_historical_tokens_refuse_without_mutation() -> TestResult {
    let fixture = Fixture::new("history-refusal")?;
    fixture.publish_hypotheses(1)?;
    let token = snapshot_anchor_token(&read_deployment(&fixture.root, &OrientLimits::default())?);
    let mut tokens = Vec::new();
    for (field, replacement) in [
        (1, "0".repeat(16)),
        (2, "999999".to_owned()),
        (4, "0".repeat(64)),
    ] {
        let mut parts: Vec<_> = token.split(':').map(str::to_owned).collect();
        parts[field] = replacement;
        tokens.push(parts.join(":"));
    }
    let before = tree(&fixture.root)?;
    for at in tokens {
        let answer = query(&fixture.root, &["--at", &at])?;
        assert_eq!(answer.1, ExitIdentity::AGENT_REFUSED);
        assert!(answer.0.contains("ERR-AGENT-RESNAPSHOT-001"));
        mcp(
            &fixture.root,
            &format!(r#"{{"at":{}}}"#, quote(&at)),
            &answer,
        )?;
        let explain = native_command(
            &fixture.root,
            "explain",
            &["--at", &at, "--event-id", "event:query-catalogue:0000"],
        )?;
        assert_eq!(explain.1, ExitIdentity::AGENT_REFUSED);
        assert!(explain.0.contains("ERR-AGENT-RESNAPSHOT-001"));
    }
    assert_eq!(tree(&fixture.root)?, before);
    Ok(())
}

#[test]
fn historical_reads_keep_current_deletion_denials_and_never_restore_evidence() -> TestResult {
    let fixture = Fixture::new("history-deletion")?;
    let (event, import) = fixture.publish_recording("sensor:historical-deletion")?;
    let at = snapshot_anchor_token(&read_deployment(&fixture.root, &OrientLimits::default())?);
    let planned = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["delete", "plan", "--root"])
        .arg(&fixture.root)
        .args(["--site", SITE, "--import-id", &import])
        .output()?;
    success(&planned);
    let planned = String::from_utf8(planned.stdout)?;
    let plan = quoted_field(&planned, "plan_digest")?;
    let approval = quoted_field(&planned, "approval_digest")?;
    let deleted = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["delete", "commit", "--root"])
        .arg(&fixture.root)
        .args(["--site", SITE, "--plan", &plan, "--approve", &approval])
        .output()?;
    success(&deleted);
    let before = tree(&fixture.root)?;

    let assert_current_deletion = |answer: &str| -> TestResult {
        let document = fss_cli::json_input::parse(answer)?;
        let warnings = document
            .object()
            .and_then(|fields| fields.get("warnings"))
            .and_then(fss_cli::json_input::Value::array)
            .ok_or("response warnings")?;
        assert!(
            warnings
                .iter()
                .filter_map(fss_cli::json_input::Value::text)
                .any(|warning| {
                    warning.contains(&import)
                        && warning.contains(&plan)
                        && warning.contains("`deleted`")
                }),
            "current committed deletion warning was lost: {answer}"
        );
        Ok(())
    };

    let catalogue = query(&fixture.root, &["--at", &at, "--event-id", &event])?;
    assert_eq!(catalogue.1, ExitIdentity::SUCCESS, "{}", catalogue.0);
    assert!(catalogue.0.contains("Historical metadata"));
    assert_current_deletion(&catalogue.0)?;
    conforms(&fixture, &catalogue.0)?;
    mcp(
        &fixture.root,
        &format!(r#"{{"at":{},"event_id":{}}}"#, quote(&at), quote(&event)),
        &catalogue,
    )?;

    let current = query(&fixture.root, &["--event-id", &event])?;
    assert_eq!(current.1, ExitIdentity::SUCCESS, "{}", current.0);
    assert_current_deletion(&current.0)?;
    mcp(
        &fixture.root,
        &format!(r#"{{"event_id":{}}}"#, quote(&event)),
        &current,
    )?;

    let absent_event = "event:query:absent-after-deletion";
    let empty = query(&fixture.root, &["--at", &at, "--event-id", absent_event])?;
    assert_eq!(empty.1, ExitIdentity::SUCCESS, "{}", empty.0);
    assert!(empty.0.contains("0 match; this page returns 0 record(s)"));
    assert_current_deletion(&empty.0)?;
    mcp(
        &fixture.root,
        &format!(r#"{{"at":{},"event_id":{}}}"#, quote(&at), quote(absent_event)),
        &empty,
    )?;

    let explanation = native_command(
        &fixture.root,
        "explain",
        &[
            "--at",
            &at,
            "--event-id",
            &event,
            "--view",
            "forensic",
            "--budget-tokens",
            "16000",
            "--custody",
            "yes",
        ],
    )?;
    assert_eq!(explanation.1, ExitIdentity::SUCCESS, "{}", explanation.0);
    assert!(explanation.0.contains("deleted"));
    assert!(explanation.0.contains(&plan));
    // The event's own metadata closure can remain intact after source deletion. Its
    // all_verified flag is scoped to that closure; direct denied sources are separate facts.
    let explained = fss_cli::json_input::parse(&explanation.0)?;
    let claims = explained.object()
        .and_then(|o| o.get("payload")).and_then(fss_cli::json_input::Value::object)
        .and_then(|o| o.get("epistemic")).and_then(fss_cli::json_input::Value::object)
        .and_then(|o| o.get("propositions")).and_then(fss_cli::json_input::Value::array)
        .ok_or("explanation propositions")?;
    let denials: Vec<_> = claims.iter().filter_map(fss_cli::json_input::Value::object)
        .filter(|claim| claim.get("id").and_then(fss_cli::json_input::Value::text)
            .is_some_and(|id| id.starts_with("claim:event-custody:") && id.contains(":denied-references:")))
        .collect();
    assert!(!denials.is_empty(), "current source denials were hidden: {}", explanation.0);
    let snapshot = read_deployment(&fixture.root, &OrientLimits::default())?;
    for denial in denials {
        assert_eq!(denial.get("state").and_then(fss_cli::json_input::Value::text), Some("known"));
        let evidence = denial.get("evidence").and_then(fss_cli::json_input::Value::array)
            .ok_or("denial evidence")?;
        assert!(evidence.len() > 1);
        assert_eq!(evidence[0].text(), Some(plan.as_str()));
        for reference in &evidence[1..] {
            let digest = ContentDigest::parse(reference.text().ok_or("denied digest")?)?;
            assert!(snapshot.deletions.entries().iter().any(|entry| {
                entry.plan_digest.to_text() == plan
                    && entry.plan.deletable.iter().any(|object| object.digest == digest)
            }));
        }
    }
    assert!(explanation.0.contains("claim:read:historical-scope"));
    conforms(&fixture, &explanation.0)?;
    mcp_tool(
        &fixture.root,
        "explain",
        &format!(
            r#"{{"at":{},"event_id":{},"view":"forensic","budget_tokens":16000,"custody":"yes"}}"#,
            quote(&at),
            quote(&event)
        ),
        &explanation,
    )?;
    assert_eq!(tree(&fixture.root)?, before);
    Ok(())
}

#[test]
fn current_deletion_blocks_support_outside_an_intact_historical_metadata_closure() -> TestResult {
    let fixture = Fixture::new("deleted-support-path")?;
    let (recorded, import) = fixture.publish_recording("sensor:deleted-support-path")?;
    let before = read_deployment(&fixture.root, &OrientLimits::default())?;
    let recorded = before.event(&EventId::parse(recorded)?).ok_or("recorded event")?;
    let source = recorded.event.evidence.iter().find_map(|edge| edge.capsule_digest)
        .ok_or("original source capsule")?;
    let id = EventId::parse("event:deleted-support-path")?;
    // A synthetic positive-support edge tests graph availability only. It grants neither
    // a physical-presence claim nor permission to hydrate an out-of-closure source.
    let policy = ContentDigest::sha256(b"synthetic deletion support fixture");
    let event = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_owned(),
        event_id: id.clone(),
        revision: 1,
        supersedes: None,
        state: EventState::Indeterminate,
        kind: EventKind::UnknownPresence,
        interval: recorded.event.interval,
        uncertainty_reason: Some("synthetic support graph; scene truth is not adjudicated".into()),
        zone_ids: Vec::new(),
        track_ids: Vec::new(),
        probability: ProbabilityInterval::new(0.0, 1.0)?,
        evidence: vec![EventEvidence {
            digest: source,
            class: EvidenceClass::Assertion,
            failure_domain: "synthetic:deletion-support".into(),
            supports: true,
            relation: EvidenceEdgeRelation::Supports,
            capsule_digest: Some(source),
            identity_digest: None,
        }],
        model_receipts: Vec::new(),
        decision_path: DecisionPath {
            policy_generation: policy,
            fingerprint: policy,
            abstained: true,
            abstention_reason: Some("test-only graph availability; no event or effect advice".into()),
        },
    };
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:deleted-support-path".into(),
        operation_id: OperationId::parse("operation:deleted-support-path")?,
        principal: "operator:query-surface".into(),
        capabilities: vec![ADP_REPLAY_ROW_ID.into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".into(),
        retention_scope: "retention:ephemeral".into(),
        anchor_universe: ContentDigest::sha256(b"deleted-support-path"),
        generation: 1,
    })?;
    let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
        &authority, fixture.directory.join("deleted-support-cx"),
    )?);
    ReferenceDeployment::open(&fixture.root, SITE, &cx)?.publish_event(
        &ReferencePolicyDecision { event: event.clone(), action: ReferencePolicyAction::Hold },
        &cx,
    )?;
    cx.drain_and_finalize();
    let at = snapshot_anchor_token(&read_deployment(&fixture.root, &OrientLimits::default())?);
    let explain = |at: Option<&str>| -> TestResult<(String, ExitIdentity)> {
        let mut options = vec![
            "--event-id", id.as_str(), "--view", "forensic",
            "--budget-tokens", "16000", "--custody", "yes",
        ];
        if let Some(at) = at { options.extend(["--at", at]); }
        native_command(&fixture.root, "explain", &options)
    };
    let unchecked = explain(None)?;
    assert_eq!(unchecked.1, ExitIdentity::SUCCESS, "{}", unchecked.0);
    assert!(unchecked.0.contains("Declared support availability: unchecked_reference_path."));
    assert!(unchecked.0.contains("all_verified=true"));

    let planned = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["delete", "plan", "--root"]).arg(&fixture.root)
        .args(["--site", SITE, "--import-id", &import]).output()?;
    success(&planned);
    let planned = String::from_utf8(planned.stdout)?;
    let plan = quoted_field(&planned, "plan_digest")?;
    let approval = quoted_field(&planned, "approval_digest")?;
    let deleted = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["delete", "commit", "--root"]).arg(&fixture.root)
        .args(["--site", SITE, "--plan", &plan, "--approve", &approval]).output()?;
    success(&deleted);
    let after_delete = tree(&fixture.root)?;
    for historical in [None, Some(at.as_str())] {
        let answer = explain(historical)?;
        assert_eq!(answer.1, ExitIdentity::SUCCESS, "{}", answer.0);
        assert!(answer.0.contains("Declared support availability: no_unblocked_reference_path."));
        assert!(answer.0.contains("Current event publication closure:"));
        assert!(answer.0.contains("all_verified=true"));
        assert!(answer.0.contains(&format!(":denied-references:{plan}")));
        assert!(answer.0.contains(&source.to_text()));
        assert!(answer.0.contains("intact event metadata does not restore source availability"));
        let arguments = match historical {
            None => format!(r#"{{"event_id":{},"view":"forensic","budget_tokens":16000,"custody":"yes"}}"#, quote(id.as_str())),
            Some(at) => format!(r#"{{"at":{},"event_id":{},"view":"forensic","budget_tokens":16000,"custody":"yes"}}"#, quote(at), quote(id.as_str())),
        };
        mcp_tool(&fixture.root, "explain", &arguments, &answer)?;
    }
    let current = read_deployment(&fixture.root, &OrientLimits::default())?;
    assert_eq!(&current.event(&id).ok_or("retained event")?.event, &event);
    assert_eq!(tree(&fixture.root)?, after_delete);
    Ok(())
}
