#![forbid(unsafe_code)]
//! Actual executable contracts over synthetic, disjoint, source-labelled passages.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use fss_cli::agent_json::{object, string};
use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const FIXTURE: &[u8] = include_bytes!("../../../fixtures/clock-alignment/validated_sessions.json");

struct Input(PathBuf);
impl Input {
    fn new(name: &str, bytes: &[u8]) -> Test<Self> {
        for attempt in 0..100 {
            let root = std::env::temp_dir().join(format!(
                "fss-clock-validation-{name}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => {
                    let result = Self(root);
                    fs::write(result.0.join("query.json"), bytes)?;
                    return Ok(result);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("test directory capacity".into())
    }
    fn run(&self, work: u64) -> Test<Output> {
        let path = self.0.join("query.json");
        Ok(Command::new(env!("CARGO_BIN_EXE_fss-clock-align"))
            .arg("--input")
            .arg(&path)
            .arg("--input-digest")
            .arg(ContentDigest::sha256(&fs::read(&path)?).to_text())
            .arg("--work-units")
            .arg(work.to_string())
            .output()?)
    }
}
impl Drop for Input {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn fields_mut(value: &mut Value) -> Test<&mut BTreeMap<String, Value>> {
    match value {
        Value::Object(fields) => Ok(fields),
        _ => Err("object".into()),
    }
}
fn rows_mut<'a>(value: &'a mut Value, key: &str) -> Test<&'a mut Vec<Value>> {
    match fields_mut(value)?.get_mut(key) {
        Some(Value::Array(rows)) => Ok(rows),
        _ => Err("array".into()),
    }
}
fn encode(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(v) => v.to_string(),
        Value::Number(v) => v.clone(),
        Value::Text(v) => string(v),
        Value::Array(rows) => format!(
            "[{}]",
            rows.iter().map(encode).collect::<Vec<_>>().join(",")
        ),
        Value::Object(fields) => object(
            &fields
                .iter()
                .map(|(k, v)| (k.as_str(), encode(v)))
                .collect::<Vec<_>>(),
        ),
    }
}
fn report(output: &Output) -> Test<BTreeMap<String, Value>> {
    Ok(parse(std::str::from_utf8(&output.stdout)?)?
        .object()
        .and_then(|v| v.get("report"))
        .and_then(Value::object)
        .ok_or("report")?
        .clone())
}

#[test]
fn command_runs_all_sessions_retains_all_hypotheses_and_leaves_input_unchanged() -> Test {
    let input = Input::new("complete", FIXTURE)?;
    let first = input.run(100_000_000)?;
    assert_eq!(
        first.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(first.stderr.is_empty());
    let body = report(&first)?;
    assert_eq!(
        body.get("schema").and_then(Value::text),
        Some("fss.clock_validation_report.v1")
    );
    assert_eq!(
        body.get("hypothesis_count").and_then(Value::integer),
        Some(3)
    );
    assert_eq!(
        body.get("additional_session_count")
            .and_then(Value::integer),
        Some(2)
    );
    assert_eq!(
        body.get("supported_in_every_session_count")
            .and_then(Value::integer),
        Some(1)
    );
    assert_eq!(
        body.get("clock_activated").and_then(Value::boolean),
        Some(false)
    );
    assert_eq!(
        body.get("independent_clock_validation")
            .and_then(Value::boolean),
        Some(false)
    );
    for projection in body
        .get("projections")
        .and_then(Value::array)
        .ok_or("projections")?
    {
        assert_eq!(
            projection
                .object()
                .and_then(|v| v.get("mappings"))
                .and_then(Value::array)
                .map(|v| v.len()),
            Some(3)
        );
    }
    let second = input.run(100_000_000)?;
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(fs::read(input.0.join("query.json"))?, FIXTURE);
    assert_eq!(
        fs::read_dir(&input.0)?.count(),
        1,
        "read-only command must not publish any files"
    );
    Ok(())
}

#[test]
fn a_complete_inventory_without_shared_support_has_exit_three_and_full_diagnostics() -> Test {
    let mut value = parse(std::str::from_utf8(FIXTURE)?)?;
    rows_mut(&mut value, "hypotheses")?.retain(|row| {
        row.object()
            .and_then(|v| v.get("skew_ppb"))
            .and_then(Value::integer)
            != Some(500_000)
    });
    let bytes = encode(&value);
    let output = Input::new("unsupported", bytes.as_bytes())?.run(100_000_000)?;
    assert_eq!(
        output.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body = report(&output)?;
    assert_eq!(
        body.get("supported_in_every_session_count")
            .and_then(Value::integer),
        Some(0)
    );
    assert_eq!(
        body.get("hypothesis_count").and_then(Value::integer),
        Some(2)
    );
    assert_eq!(
        body.get("sessions").and_then(Value::array).map(|v| v.len()),
        Some(2)
    );
    Ok(())
}

#[test]
fn insufficient_work_or_relabelled_evidence_returns_no_successful_json_prefix() -> Test {
    let exhausted = Input::new("budget", FIXTURE)?.run(1)?;
    assert_eq!(exhausted.status.code(), Some(2));
    assert!(exhausted.stdout.is_empty());
    parse(std::str::from_utf8(&exhausted.stderr)?)?;
    let mut value = parse(std::str::from_utf8(FIXTURE)?)?;
    let pin = rows_mut(&mut value, "training")?[0]
        .object()
        .and_then(|v| v.get("evidence_digest"))
        .cloned()
        .ok_or("source pin")?;
    let session = &mut rows_mut(&mut value, "sessions")?[0];
    fields_mut(&mut rows_mut(session, "training")?[0])?.insert("evidence_digest".into(), pin);
    let bytes = encode(&value);
    let refused = Input::new("aliased", bytes.as_bytes())?.run(100_000_000)?;
    assert_eq!(refused.status.code(), Some(2));
    assert!(refused.stdout.is_empty());
    let error = parse(std::str::from_utf8(&refused.stderr)?)?;
    assert_eq!(
        error
            .object()
            .and_then(|v| v.get("code"))
            .and_then(Value::text),
        Some("ERR-CLOCK-ALIGNMENT-INPUT-001")
    );
    Ok(())
}

#[test]
fn help_names_the_validation_profile_and_its_unpruned_interval_policy() -> Test {
    let output = Command::new(env!("CARGO_BIN_EXE_fss-clock-align"))
        .arg("--help")
        .output()?;
    assert_eq!(output.status.code(), Some(0));
    let text = std::str::from_utf8(&output.stdout)?;
    assert!(text.contains("fss.clock_validation_query.v1"));
    assert!(text.contains("ALL supplied hypotheses"));
    Ok(())
}
