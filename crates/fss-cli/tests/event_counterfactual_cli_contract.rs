#![forbid(unsafe_code)]
//! Canonical source-loss explanations over real retained two-camera events.
//! Explicit assumptions, revision pins, complete transport parity and immutable reads.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use fss_cli::event_counterfactual::{EventCounterfactual, EventCounterfactualRequest};
use fss_cli::json_input::{Value, parse};
use fss_core::{AgentView, ContentDigest, EvidenceEdgeRelation, PrincipalId};
use fss_fusion::{Coverage, Observability, ScoreCalibration};
use fss_reference::agent_orient::{
    OrientLimits, OrientRequest, explain_event, orient_deployment, read_deployment,
};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:event-counterfactual-cli";
const PRINCIPAL: &str = "principal:event-counterfactual-cli";
const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"event-counterfactual-contract","version":"1"}}}"#;
const READY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> TestResult<Self> {
        for attempt in 0..64 {
            let path = std::env::temp_dir().join(format!(
                "fss-event-counterfactual-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("test directory allocation exhausted".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn get<'a>(value: &'a Value, key: &str) -> TestResult<&'a Value> {
    value
        .object()
        .and_then(|object| object.get(key))
        .ok_or_else(|| format!("missing object key {key}").into())
}
fn text(value: &Value) -> TestResult<&str> {
    value.text().ok_or_else(|| "expected text".into())
}
fn array(value: &Value) -> TestResult<&[Value]> {
    value.array().ok_or_else(|| "expected array".into())
}
fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn report_field(output: &Output, key: &str) -> TestResult<String> {
    let output = std::str::from_utf8(&output.stdout)?;
    let pattern = format!("\"{key}\":");
    let rest = output
        .split_once(pattern.as_str())
        .ok_or_else(|| format!("missing {key}"))?
        .1;
    Ok(match rest.strip_prefix('"') {
        Some(quoted) => quoted.split('"').next().unwrap_or_default().to_owned(),
        None => rest
            .split([',', '}', ']'])
            .next()
            .unwrap_or_default()
            .to_owned(),
    })
}

fn recording(
    start_frame: usize,
    initial_left: usize,
    step: isize,
    top: usize,
) -> TestResult<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut stream = Vec::new();
    for frame in 0..14_usize {
        let mut pixels = vec![40_u8; 96 * 48];
        if frame >= start_frame {
            let offset = (frame - start_frame) as isize * step;
            let left = (initial_left as isize + offset) as usize;
            if left + 16 <= 96 {
                for y in top..top + 16 {
                    for x in left..left + 16 {
                        pixels[y * 96 + x] = 220;
                    }
                }
            }
        }
        stream.extend(encode_jpeg(96, 48, &pixels, &config)?);
    }
    Ok(stream)
}

fn import(
    root: &Path,
    temp: &Path,
    name: &str,
    sensor: &str,
    receive_time_ns: i128,
    bytes: &[u8],
) -> TestResult<String> {
    let input = temp.join(format!("{name}.mjpeg"));
    fs::write(&input, bytes)?;
    let output = Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .args(["import", "--root"])
        .arg(root)
        .args(["--site", SITE, "--input"])
        .arg(&input)
        .args([
            "--sensor",
            sensor,
            "--stream",
            &format!("stream:{name}"),
            "--receive-time-ns",
            &receive_time_ns.to_string(),
            "--capture-start-ns",
            "1000000000",
            "--capture-uncertainty-ns",
            "1000000",
            "--assumed-fps",
            "10",
            "--media-format",
            "mjpeg",
        ])
        .output()?;
    success(&output);
    let stdout = String::from_utf8(output.stdout)?;
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("import_identity="))
        .map(str::to_owned)
        .ok_or_else(|| format!("missing import_identity in {stdout}").into())
}

fn published_corroborated(
    label: &str,
    shared_domain: bool,
) -> TestResult<(Directory, PathBuf, String)> {
    let directory = Directory::new(label)?;
    let root = directory.0.join("deployment");
    let first = import(
        &root,
        &directory.0,
        "north",
        "sensor:north",
        10_000_000_000_000,
        &recording(3, 0, 8, 8)?,
    )?;
    let second = import(
        &root,
        &directory.0,
        "east",
        "sensor:east",
        10_000_000_000_000,
        &recording(3, 80, -8, 8)?,
    )?;
    let run_corroborate = |extra: &[&str]| -> TestResult<Output> {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_fss-event"));
        cmd.args(["corroborate", "--root"])
            .arg(&root)
            .args([
                "--site",
                SITE,
                "--camera",
                &format!("north:{first}"),
                "--camera",
                &format!("east:{second}"),
                "--ground",
                "north:1,0,0,0,1,0,0,0,1",
                "--ground",
                "east:-1,0,96,0,1,0,0,0,1",
                "--interpretation",
                "gray",
                "--zone",
                "door:56,0,40,48",
                "--time-gate-ns",
                "250000000",
                "--distance-gate",
                "16",
            ]);
        if shared_domain {
            cmd.args(["--failure-domain", "clock:shared-ntp=north,east"]);
        }
        cmd.args(extra);
        Ok(cmd.output()?)
    };
    let preview = run_corroborate(&[])?;
    success(&preview);
    let proposal = report_field(&preview, "proposal_digest")?;
    let committed = run_corroborate(&["--approve", &proposal])?;
    success(&committed);
    assert_eq!(report_field(&committed, "status")?, "published");
    Ok((directory, root, report_field(&committed, "event_id")?))
}

fn tree(root: &Path) -> TestResult<BTreeMap<PathBuf, (bool, ContentDigest)>> {
    fn walk(
        root: &Path,
        path: &Path,
        output: &mut BTreeMap<PathBuf, (bool, ContentDigest)>,
    ) -> TestResult {
        output.insert(path.strip_prefix(root)?.to_path_buf(), (true, ContentDigest::sha256(b"directory")));
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                walk(root, &entry.path(), output)?;
            } else {
                assert!(entry.file_type()?.is_file());
                output.insert(
                    entry.path().strip_prefix(root)?.to_path_buf(),
                    (false, ContentDigest::sha256(&fs::read(entry.path())?)),
                );
            }
        }
        Ok(())
    }
    let mut result = BTreeMap::new();
    walk(root, root, &mut result)?;
    Ok(result)
}

fn quote(value: &str) -> String {
    format!("\"{}\"", fss_cli::escape_json_str(value))
}

fn retained_inputs(root: &Path, event_id: &str) -> TestResult<(String, Vec<(String, u32)>)> {
    let snapshot = read_deployment(root, &OrientLimits::default())?;
    let retained = snapshot
        .events
        .iter()
        .find(|retained| retained.event.event_id.as_str() == event_id)
        .ok_or("fixture event was not retained")?;
    let mut domains = BTreeMap::new();
    for edge in &retained.event.evidence {
        if matches!(
            edge.relation,
            EvidenceEdgeRelation::Supports | EvidenceEdgeRelation::Contradicts
        ) {
            assert!(!edge.failure_domain.is_empty());
            domains.insert(edge.failure_domain.clone(), 900_000);
        }
    }
    assert!(domains.len() >= 2, "fixture needs distinct declared domains");
    Ok((retained.revision_digest.to_text(), domains.into_iter().collect()))
}

fn request(revision: &str, without: &[String], scores: &[(String, u32)]) -> TestResult<String> {
    let calibration = ScoreCalibration::from_counts(
        "cal:event-counterfactual:v1",
        &[0, 300_000, 700_000],
        &[(5, 95), (50, 50), (95, 5)],
    )?;
    let bins = calibration
        .bins
        .iter()
        .map(|bin| {
            format!(
                "{{\"lo_ppm\":{},\"hi_ppm\":{},\"true_positives\":{},\"false_positives\":{}}}",
                bin.lo_ppm, bin.hi_ppm, bin.positives, bin.negatives
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let scores = scores
        .iter()
        .map(|(domain, score)| format!("{}:{score}", quote(domain)))
        .collect::<Vec<_>>()
        .join(",");
    let without = without.iter().map(|domain| quote(domain)).collect::<Vec<_>>().join(",");
    Ok(format!(
        "{{\"schema\":\"fss.event_counterfactual_request.v1\",\"event_revision_digest\":{},\"without_domains\":[{without}],\"score_calibration\":{{\"schema\":\"fss.score_calibration.v1\",\"generation\":{},\"digest\":{},\"bins\":[{bins}]}},\"domain_scores_ppm\":{{{scores}}}}}",
        quote(revision), quote(&calibration.generation), quote(&calibration.digest.to_text())
    ))
}

fn what_if(
    root: &Path,
    event_id: &str,
    request: &str,
    budget: u64,
    extra: &[&str],
) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(["explain", "--json", "--root"])
        .arg(root)
        .args([
            "--event-id",
            event_id,
            "--question",
            "what_if",
            "--counterfactual",
            request,
            "--view",
            "forensic",
            "--principal",
            PRINCIPAL,
            "--budget-tokens",
            &budget.to_string(),
        ])
        .args(extra)
        .output()?)
}

fn refusal(output: &Output, error_id: &str) -> TestResult {
    assert!(!output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    let response = parse(std::str::from_utf8(&output.stdout)?)?;
    assert_eq!(text(get(&response, "outcome")?)?, "refused");
    assert_eq!(text(get(&response, "errorId")?)?, error_id);
    assert_eq!(get(&response, "payload")?, &Value::Null);
    Ok(())
}

fn mcp_matches(
    root: &Path,
    event_id: &str,
    request: &str,
    budget: u64,
    expected: &Output,
) -> TestResult {
    let arguments = format!(
        "{{\"question\":\"what_if\",\"event_id\":{},\"counterfactual\":{request},\"view\":\"forensic\",\"budget_tokens\":{budget}}}",
        quote(event_id)
    );
    let messages = format!(
        "{INIT}\n{READY}\n{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\"name\":\"explain\",\"arguments\":{arguments}}}}}\n"
    );
    let mut process = Command::new(env!("CARGO_BIN_EXE_fss-mcp"))
        .arg("--root")
        .arg(root)
        .args(["--principal", PRINCIPAL])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut input = process.stdin.take().ok_or("missing MCP stdin")?;
    input.write_all(messages.as_bytes())?;
    drop(input);
    let output = process.wait_with_output()?;
    success(&output);
    assert!(output.stderr.is_empty(), "{output:?}");
    let wire = std::str::from_utf8(&output.stdout)?;
    let lines = wire.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 2, "initialize and one tools/call response only");
    assert!(lines[1].contains(&format!("\"isError\":{}", !expected.status.success())));
    let expected = std::str::from_utf8(&expected.stdout)?;
    assert!(
        lines[1].contains(&format!("\"text\":{}", quote(expected))),
        "MCP must preserve the complete CLI semantic envelope"
    );
    Ok(())
}

fn artifact_rows(document: &Value) -> TestResult<BTreeMap<String, Value>> {
    let propositions = array(get(get(get(document, "payload")?, "epistemic")?, "propositions")?)?;
    let mut result = BTreeMap::new();
    let mut indexes = BTreeSet::new();
    for proposition in propositions {
        let id = text(get(proposition, "id")?)?;
        let Some(index) = id.strip_prefix("claim:event-counterfactual:row:") else {
            continue;
        };
        assert!(indexes.insert(index.parse::<usize>()?), "duplicate artifact row identity");
        let statement = text(get(proposition, "statement")?)?;
        let body = statement
            .strip_prefix("Hypothetical source-loss artifact at ")
            .ok_or("invalid counterfactual artifact row")?;
        // A declared domain may itself contain ": "; locate the complete JSON suffix.
        let (pointer, value) = body
            .match_indices(": ")
            .find_map(|(index, _)| parse(&body[index + 2..]).ok().map(|value| (&body[..index], value)))
            .ok_or("artifact row has no complete JSON value")?;
        assert!(pointer.is_empty() || pointer.starts_with('/'), "invalid artifact JSON pointer");
        // A row may contain a complete subtree. Normalize it independently to exact scalar
        // and empty-container leaves so no dropped or overlapping field can pass parity.
        for (path, value) in flattened_at(&value, pointer) {
            assert!(result.insert(path, value).is_none(), "duplicate or overlapping artifact field");
        }
    }
    assert!(!result.is_empty(), "missing complete counterfactual artifact");
    assert_eq!(indexes, (0..indexes.len()).collect::<BTreeSet<_>>(), "artifact row identities must be contiguous");
    Ok(result)
}

fn row<'a>(rows: &'a BTreeMap<String, Value>, pointer: &str) -> TestResult<&'a Value> {
    rows.get(pointer).ok_or_else(|| format!("missing artifact pointer {pointer}").into())
}

fn assert_semantic_boundaries(rows: &BTreeMap<String, Value>, revision: &str) -> TestResult {
    assert_eq!(text(row(rows, "/schema")?)?, "fss.event_counterfactual.v1");
    assert_eq!(text(row(rows, "/question")?)?, "what_if");
    assert_eq!(
        text(row(rows, "/scope")?)?,
        "hypothetical_declared_failure_domain_loss"
    );
    assert_eq!(text(row(rows, "/source_event_revision_digest")?)?, revision);
    for key in [
        "source_custody_verified",
        "historical_decision_replayed",
        "physical_coverage_certified",
        "event_policy_changed",
        "published",
        "effect_authority",
    ] {
        assert_eq!(row(rows, &format!("/{key}"))?, &Value::Bool(false), "{key}");
    }
    assert!(rows.keys().any(|pointer| pointer.starts_with("/source_event/")));
    assert!(rows.keys().any(|pointer| pointer.starts_with("/ablation/")));
    assert!(rows.keys().any(|pointer| pointer.starts_with("/request/domain_scores_ppm/")));
    Ok(())
}

fn owner_artifact(root: &Path, event_id: &str, raw: &str) -> TestResult<EventCounterfactual> {
    let limits = OrientLimits::default();
    let snapshot = read_deployment(root, &limits)?;
    let event_id = snapshot
        .events
        .iter()
        .find(|retained| retained.event.event_id.as_str() == event_id)
        .ok_or("fixture event was not retained")?
        .event
        .event_id
        .clone();
    let orientation = orient_deployment(
        &snapshot,
        &OrientRequest {
            view: AgentView::Brief,
            principal: PrincipalId::parse(PRINCIPAL)?,
            budget_tokens: None,
        },
        &limits,
    )?;
    let explanation = explain_event(&snapshot, &orientation, &event_id)?
        .ok_or("fixture explanation was not available")?;
    Ok(EventCounterfactualRequest::parse(raw)?.compute(&explanation)?)
}

fn flattened_at(value: &Value, pointer: &str) -> BTreeMap<String, Value> {
    fn walk(value: &Value, path: &str, result: &mut BTreeMap<String, Value>) {
        if let Some(object) = value.object() {
            if !object.is_empty() {
                for (key, child) in object {
                    let key = key.replace('~', "~0").replace('/', "~1");
                    walk(child, &format!("{path}/{key}"), result);
                }
                return;
            }
        }
        if let Some(array) = value.array() {
            if !array.is_empty() {
                for (index, child) in array.iter().enumerate() {
                    walk(child, &format!("{path}/{index}"), result);
                }
                return;
            }
        }
        result.insert(path.to_owned(), value.clone());
    }
    let mut result = BTreeMap::new();
    walk(value, pointer, &mut result);
    result
}

#[test]
fn exact_native_artifact_and_mcp_parity_preserve_all_deployment_bytes() -> TestResult {
    let (_directory, root, event_id) = published_corroborated("complete-artifact", false)?;
    let (revision, scores) = retained_inputs(&root, &event_id)?;
    let without = vec![scores[0].0.clone()];
    let request = request(&revision, &without, &scores)?;
    let before = tree(&root)?;

    let artifact = owner_artifact(&root, &event_id, &request)?;
    let ablation = artifact.ablation();
    assert!(matches!(&ablation.original_query().coverage, Coverage::Gap { .. }));
    assert!(matches!(&ablation.counterfactual_query().coverage, Coverage::Gap { .. }));
    assert_eq!(ablation.baseline().supporting_clusters, 1, "shared calibration remains one common cause");
    assert!(!ablation.unavailable_evidence().is_empty());
    assert_eq!(
        ablation.original_query().evidence.len(),
        ablation.counterfactual_query().evidence.len(),
        "loss changes observability while retaining every original score and identity"
    );
    for original in &ablation.original_query().evidence {
        let changed = ablation
            .counterfactual_query()
            .evidence
            .iter()
            .find(|item| item.id == original.id)
            .ok_or("counterfactual discarded an evidence row")?;
        assert_eq!(original.calibration, changed.calibration);
        assert_eq!(original.failure_domains, changed.failure_domains);
        if ablation.unavailable_evidence().contains(&original.id) {
            assert!(matches!(&changed.observability, Observability::NotObservable { .. }));
        } else {
            assert_eq!(original.observability, changed.observability);
        }
    }
    let expected = flattened_at(&parse(&artifact.to_json()?)?, "");
    let output = what_if(&root, &event_id, &request, 16_000, &[])?;
    success(&output);
    let document = parse(std::str::from_utf8(&output.stdout)?)?;
    assert_eq!(text(get(&document, "operationId")?)?, "AOP-011");
    let rows = artifact_rows(&document)?;
    assert_eq!(rows, expected, "every field of the domain-owner artifact must survive the canonical envelope");
    assert_semantic_boundaries(&rows, &revision)?;
    mcp_matches(&root, &event_id, &request, 16_000, &output)?;
    assert_eq!(before, tree(&root)?, "explanation must not create directories or change retained bytes");
    Ok(())
}

#[test]
fn exact_revision_unknown_domains_and_incomplete_scores_fail_closed() -> TestResult {
    let (_directory, root, event_id) = published_corroborated("fail-closed", false)?;
    let (revision, scores) = retained_inputs(&root, &event_id)?;
    let without = vec![scores[0].0.clone()];
    let before = tree(&root)?;

    let stale = request(
        &ContentDigest::sha256(b"another event revision").to_text(),
        &without,
        &scores,
    )?;
    let stale_output = what_if(&root, &event_id, &stale, 16_000, &[])?;
    refusal(&stale_output, "ERR-AGENT-RESNAPSHOT-001")?;
    mcp_matches(&root, &event_id, &stale, 16_000, &stale_output)?;

    let mut unknown_scores = scores.clone();
    unknown_scores.push(("undeclared:domain".to_owned(), 900_000));
    let unknown = request(
        &revision,
        &[without[0].clone(), "undeclared:domain".to_owned()],
        &unknown_scores,
    )?;
    refusal(
        &what_if(&root, &event_id, &unknown, 16_000, &[])?,
        "ERR-FUSION-INPUT-INVALID-001",
    )?;
    let missing = request(&revision, &without, &scores[..scores.len() - 1])?;
    refusal(
        &what_if(&root, &event_id, &missing, 16_000, &[])?,
        "ERR-FUSION-INPUT-INVALID-001",
    )?;
    let mut extra_scores = scores.clone();
    extra_scores.push(("undeclared:score".to_owned(), 900_000));
    let extra = request(&revision, &without, &extra_scores)?;
    refusal(
        &what_if(&root, &event_id, &extra, 16_000, &[])?,
        "ERR-FUSION-INPUT-INVALID-001",
    )?;
    assert_eq!(before, tree(&root)?);
    Ok(())
}

#[test]
fn complete_result_refuses_when_the_caller_context_allowance_is_too_small() -> TestResult {
    let (_directory, root, event_id) = published_corroborated("context-refusal", false)?;
    let (revision, scores) = retained_inputs(&root, &event_id)?;
    let request = request(&revision, &[scores[0].0.clone()], &scores)?;
    let before = tree(&root)?;
    let full = what_if(&root, &event_id, &request, 16_000, &[])?;
    success(&full);
    let full_document = parse(std::str::from_utf8(&full.stdout)?)?;
    let charged = get(get(get(&full_document, "budgets")?, "consumed")?, "tokens")?
        .integer()
        .ok_or("missing context charge")?;
    assert!(charged > 1);
    let tight = what_if(&root, &event_id, &request, 1, &[])?;
    refusal(&tight, "ERR-AGENT-CONTEXT-INCOMPLETE-001")?;
    assert!(
        !std::str::from_utf8(&tight.stdout)?.contains("claim:event-counterfactual:row:"),
        "a refusal must not leak a truncated successful artifact"
    );
    mcp_matches(&root, &event_id, &request, 1, &tight)?;
    assert_eq!(before, tree(&root)?);
    Ok(())
}

#[test]
fn normalized_order_preserves_identity_but_same_bin_assumptions_change_it() -> TestResult {
    let (_directory, root, event_id) = published_corroborated("semantic-identity", false)?;
    let (revision, scores) = retained_inputs(&root, &event_id)?;
    let mut without = vec![scores[0].0.clone(), scores[1].0.clone()];
    let first_request = request(&revision, &without, &scores)?;
    let before = tree(&root)?;
    let first = what_if(&root, &event_id, &first_request, 16_000, &[])?;
    success(&first);

    let mut reversed = scores.clone();
    reversed.reverse();
    without.reverse();
    let reordered_request = request(&revision, &without, &reversed)?;
    assert_ne!(first_request, reordered_request, "fixture must change raw JSON order");
    let reordered = what_if(&root, &event_id, &reordered_request, 16_000, &[])?;
    success(&reordered);
    assert_eq!(first.stdout, reordered.stdout, "map and simultaneous selector order cannot change semantic identity");
    mcp_matches(&root, &event_id, &reordered_request, 16_000, &reordered)?;

    let mut changed = scores;
    changed[0].1 = 850_000;
    let changed_request = request(&revision, &without, &changed)?;
    let original_artifact = owner_artifact(&root, &event_id, &first_request)?;
    let changed_artifact = owner_artifact(&root, &event_id, &changed_request)?;
    assert_eq!(
        original_artifact.ablation().digest(),
        changed_artifact.ablation().digest(),
        "same-bin scores leave the calibrated numerical query unchanged"
    );
    assert_ne!(original_artifact.request_digest(), changed_artifact.request_digest());
    assert_ne!(original_artifact.digest(), changed_artifact.digest());
    let changed_output = what_if(&root, &event_id, &changed_request, 16_000, &[])?;
    success(&changed_output);
    let first_document = parse(std::str::from_utf8(&first.stdout)?)?;
    let changed_document = parse(std::str::from_utf8(&changed_output.stdout)?)?;
    assert_ne!(
        text(get(&first_document, "decisionFingerprint")?)?,
        text(get(&changed_document, "decisionFingerprint")?)?,
        "canonical receipt must bind exact caller assumptions, including same-bin values"
    );
    assert_eq!(before, tree(&root)?);
    Ok(())
}
