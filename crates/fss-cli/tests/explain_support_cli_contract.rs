#![forbid(unsafe_code)]
//! Real retained scene -> approved candidate -> standard AOP-011 explanation.
//! Uses the existing native JPEG fixture and real CLI processes, not an injected snapshot.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_cli::json_input::{Value, parse};
use fss_core::{AgentView, ContentDigest, KnowledgeState, PrincipalId};
use fss_reference::agent_orient::{OrientLimits, OrientRequest, explain_event, orient_deployment, read_deployment};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:explain-support-cli";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> TestResult<Self> {
        for attempt in 0..64 {
            let path = std::env::temp_dir().join(format!("fss-explain-support-{label}-{}-{attempt}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {},
                Err(error) => return Err(error.into()),
            }
        }
        Err("test directory allocation exhausted".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

fn get<'a>(value: &'a Value, key: &str) -> TestResult<&'a Value> {
    value.object().and_then(|object| object.get(key)).ok_or_else(|| format!("missing object key {key}").into())
}
fn text(value: &Value) -> TestResult<&str> { value.text().ok_or_else(|| "expected text".into()) }
fn array(value: &Value) -> TestResult<&[Value]> { value.array().ok_or_else(|| "expected array".into()) }
fn success(output: &Output) {
    assert!(output.status.success(), "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
}

fn report_field(output: &Output, key: &str) -> TestResult<String> {
    let output = std::str::from_utf8(&output.stdout)?;
    let pattern = format!("\"{key}\":");
    let rest = output.split_once(pattern.as_str()).ok_or_else(|| format!("missing {key}"))?.1;
    Ok(match rest.strip_prefix('"') {
        Some(quoted) => quoted.split('"').next().unwrap_or_default().to_owned(),
        None => rest.split([',', '}', ']']).next().unwrap_or_default().to_owned(),
    })
}

fn published(label: &str) -> TestResult<(Directory, PathBuf, String)> {
    let directory = Directory::new(label)?;
    let root = directory.0.join("deployment");
    let source = directory.0.join("recording.mjpeg");
    let config = JpegConfig { quality: 90, subsampling: Subsampling::Grayscale,
        restart_interval: 0, custom_markers: Vec::new() };
    let mut media = Vec::new();
    for frame in 0..14_usize {
        let mut pixels = vec![40_u8; 96 * 48];
        if frame >= 3 {
            let left = (frame - 3) * 8;
            for y in 8..24 { for x in left..left + 16 { pixels[y * 96 + x] = 220; } }
        }
        media.extend(encode_jpeg(96, 48, &pixels, &config)?);
    }
    fs::write(&source, media)?;
    let imported = Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .args(["import", "--root"]).arg(&root).args(["--site", SITE, "--input"]).arg(&source)
        .args(["--sensor", "sensor:explain-test", "--stream", "stream:explain-test",
            "--receive-time-ns", "1000000000", "--media-format", "mjpeg"]).output()?;
    success(&imported);
    let import_id = std::str::from_utf8(&imported.stdout)?.lines()
        .find_map(|line| line.strip_prefix("import_identity=")).ok_or("missing import identity")?.to_owned();
    fs::remove_file(&source)?;
    let watch = |extra: &[&str]| -> TestResult<Output> {
        Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
            .args(["watch", "--root"]).arg(&root)
            .args(["--site", SITE, "--import-id", &import_id, "--interpretation", "gray",
                "--zone", "door:64,0,32,32"]).args(extra).output()?)
    };
    let preview = watch(&[])?;
    success(&preview);
    assert_eq!(report_field(&preview, "candidate_count")?, "1");
    let proposal = report_field(&preview, "proposal_digest")?;
    let committed = watch(&["--approve", &proposal])?;
    success(&committed);
    assert_eq!(report_field(&committed, "status")?, "published");
    Ok((directory, root, report_field(&committed, "event_id")?))
}

fn explain(root: &Path, event: &str) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(["explain", "--json", "--root"]).arg(root).args(["--event-id", event]).output()?)
}

fn tree(root: &Path) -> TestResult<BTreeMap<PathBuf, ContentDigest>> {
    fn walk(root: &Path, path: &Path, output: &mut BTreeMap<PathBuf, ContentDigest>) -> TestResult {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() { walk(root, &entry.path(), output)?; }
            else {
                assert!(entry.file_type()?.is_file());
                output.insert(entry.path().strip_prefix(root)?.to_path_buf(), ContentDigest::sha256(&fs::read(entry.path())?));
            }
        }
        Ok(())
    }
    let mut result = BTreeMap::new();
    walk(root, root, &mut result)?;
    Ok(result)
}

#[test]
fn real_standard_explain_preserves_original_cells_worlds_and_read_only_custody() -> TestResult {
    let (_directory, root, id) = published("standard")?;
    let limits = OrientLimits::default();
    let snapshot = read_deployment(&root, &limits)?;
    let orientation = orient_deployment(&snapshot, &OrientRequest {
        view: AgentView::Brief, principal: PrincipalId::parse("principal:local-operator")?, budget_tokens: None,
    }, &limits)?;
    let event_id = fss_core::EventId::parse(id.as_str())?;
    let original = explain_event(&snapshot, &orientation, &event_id)?.ok_or("event missing")?;
    let before = tree(&root)?;
    let output = explain(&root, &id)?;
    success(&output);
    let document = parse(std::str::from_utf8(&output.stdout)?)?;
    assert_eq!(text(get(&document, "schema")?)?, "fss.agent_response_envelope.v1");
    assert_eq!(text(get(&document, "operationId")?)?, "AOP-011");
    assert_eq!(text(get(&document, "effectiveViewId")?)?, "AVIEW-007");
    let payload = get(&document, "payload")?;
    assert_eq!(text(get(payload, "schema")?)?, "fss.agent_cognitive_envelope.v1");
    let rows = array(get(get(payload, "epistemic")?, "propositions")?)?;
    let find = |id: &str| rows.iter().find(|row| {
        row.object().and_then(|object| object.get("id")).and_then(Value::text) == Some(id)
    });
    for cell in &original.cells {
        let row = find(cell.claim_id()).ok_or("original cell omitted")?;
        assert_eq!(text(get(row, "statement")?)?, cell.disclosable_statement());
        assert_eq!(text(get(row, "state")?)?, cell.knowledge_state().as_str());
    }
    for world in &original.worlds { assert!(find(&world.world_id).is_some(), "protected alternative omitted"); }
    assert!(rows.iter().any(|row| row.object().and_then(|object| object.get("id"))
        .and_then(Value::text).is_some_and(|id| id.starts_with("claim:event-support:") && id.ends_with(":structure"))));
    let custody = rows.iter().find(|row| row.object().and_then(|object| object.get("id"))
        .and_then(Value::text).is_some_and(|id| id.ends_with(":custody-and-independence"))).ok_or("custody unknown omitted")?;
    assert_eq!(text(get(custody, "state")?)?, "unknown");
    let physical = original.cells.iter().find(|cell| cell.claim_id().ends_with(":unknown-presence"))
        .map_or(KnowledgeState::Unknown, |cell| cell.knowledge_state());
    assert_eq!(text(get(&document, "epistemicState")?)?, physical.as_str());
    let budget = get(payload, "budget")?;
    let requested = get(get(budget, "requested")?, "tokens")?.integer().ok_or("token limit")?;
    let consumed = get(get(budget, "consumed")?, "tokens")?.integer().ok_or("token charge")?;
    assert_eq!(requested, i128::from(AgentView::DecisionDiff.maximum_tokens()));
    assert!(consumed > i128::from(orientation.consumed.tokens) && consumed <= requested);
    assert_eq!(get(get(&document, "budgets")?, "consumed")?, get(budget, "consumed")?);
    assert_eq!(text(get(&document, "decisionFingerprint")?)?, text(get(payload, "decisionDigest")?)?);
    assert_ne!(text(get(&document, "decisionFingerprint")?)?, original.receipt.receipt_digest().to_text());
    assert_eq!(array(get(payload, "evidenceHandles")?)?.len(), 2, "ephemeral witnesses are not source handles");
    assert!(array(get(get(&document, "executionBoundary")?, "possiblyOccurred")?)?.is_empty());
    assert_eq!(tree(&root)?, before);
    assert_eq!(explain(&root, &id)?.stdout, output.stdout, "deterministic exact retry");
    assert_eq!(tree(&root)?, before);
    Ok(())
}

#[test]
fn unknown_event_keeps_the_existing_registered_refusal_and_no_support_guess() -> TestResult {
    let (_directory, root, _) = published("unknown")?;
    let before = tree(&root)?;
    let output = explain(&root, "event:does-not-exist")?;
    assert!(!output.status.success());
    let document = parse(std::str::from_utf8(&output.stdout)?)?;
    assert_eq!(text(get(&document, "operationId")?)?, "AOP-011");
    assert_eq!(text(get(&document, "errorId")?)?, "ERR-AGENT-EVENT-NOT-FOUND-001");
    assert!(!std::str::from_utf8(&output.stdout)?.contains("claim:event-support:"));
    assert_eq!(tree(&root)?, before);
    Ok(())
}
