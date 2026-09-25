#![forbid(unsafe_code)]
//! Argument and real empty-deployment regressions for the query projection.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::path::Path;

use fss_core::{ContextAuthority, OperationId, RootAuthoritySpec};
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};

use super::*;
use crate::token::tokenize_os_args;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn parse(extra: &[&str]) -> Result<QueryArgs, CliError> {
    let args = ["query", "--json", "--root", "/owner/deployment"]
        .into_iter().chain(extra.iter().copied()).map(OsString::from);
    parse_query_args(&tokenize_os_args(args)?)
}

#[test]
fn exact_predicates_are_native_and_conjunctive() -> TestResult {
    let parsed = parse(&[
        "--event-id", "event:query:1", "--kind", "unknown_presence", "--state", "indeterminate",
        "--zone", "door", "--from-ns", "-10", "--through-ns", "20", "--max-entries", "1",
        "--principal", "principal:query-test",
    ])?;
    assert_eq!(parsed.request.filter.event_id.as_ref().map(EventId::as_str), Some("event:query:1"));
    assert_eq!(parsed.request.filter.kind, Some(EventKind::UnknownPresence));
    assert_eq!(parsed.request.filter.state, Some(EventState::Indeterminate));
    assert_eq!(parsed.request.filter.zone.as_deref(), Some("door"));
    assert_eq!(parsed.request.filter.from_ns, Some(-10));
    assert_eq!(parsed.request.filter.through_ns, Some(20));
    assert_eq!(parsed.request.max_entries, 1);
    assert_eq!(parsed.request.principal.as_str(), "principal:query-test");
    Ok(())
}

#[test]
fn time_bounds_can_be_one_sided_and_preserve_all_i128_bits() -> TestResult {
    assert_eq!(parse(&["--from-ns", "-1"])?.request.filter.through_ns, None);
    assert_eq!(parse(&["--through-ns", "1"])?.request.filter.from_ns, None);
    let lower = i128::MIN.to_string();
    let upper = i128::MAX.to_string();
    let args = parse(&["--from-ns", &lower, "--through-ns", &upper])?;
    assert_eq!(args.request.filter.from_ns, Some(i128::MIN));
    assert_eq!(args.request.filter.through_ns, Some(i128::MAX));
    Ok(())
}

#[test]
fn malformed_ambiguous_and_mutating_inputs_are_refused() {
    for extra in [
        vec!["--from-ns", "2", "--through-ns", "1"],
        vec!["--from-ns", "-0"], vec!["--from-ns", "+1"], vec!["--from-ns", "1e2"],
        vec!["--max-entries", "0"], vec!["--max-entries", "33"], vec!["--max-entries", "01"],
        vec!["--zone", "door", "--zone", "window"], vec!["--zone", "bad\nzone"],
        vec!["--kind", "person"], vec!["--state", "safe"], vec!["--anchor", "latest"],
        vec!["--continuation", "--root=/other"], vec!["--approve", "yes"],
        vec!["--certify-absence"], vec!["anything suspicious?"],
    ] {
        assert!(parse(&extra).is_err(), "accepted {extra:?}");
    }
}

struct Directory(PathBuf);
impl Directory {
    fn deployment(tag: &str) -> TestResult<(Self, PathBuf)> {
        let mut owned = None;
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!("fss-query-projection-{tag}-{}-{attempt}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => { owned = Some(Self(path)); break; }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        let directory = owned.ok_or("query test directory capacity")?;
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:query-projection".to_owned(),
            operation_id: OperationId::parse("operation:query-projection")?,
            principal: "operator:query-projection".to_owned(),
            capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()], deadline: None, priority: 10,
            budgets: BudgetVector::default(), privacy_scope: "privacy:internal".to_owned(),
            retention_scope: "retention:ephemeral".to_owned(),
            anchor_universe: ContentDigest::sha256(b"query-projection"), generation: 1,
        })?;
        let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(&authority, directory.0.join("cx"))?);
        let root = directory.0.join("deployment");
        drop(ReferenceDeployment::open(&root, "site:query-projection", &cx)?);
        Ok((directory, root))
    }
}
impl Drop for Directory {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

fn snapshot(root: &Path) -> TestResult<BTreeMap<PathBuf, Vec<u8>>> {
    let mut pending = vec![root.to_path_buf()];
    let mut rows = BTreeMap::new();
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            rows.insert(path.strip_prefix(root)?.to_path_buf(), Vec::new());
            for entry in fs::read_dir(path)? { pending.push(entry?.path()); }
        } else if metadata.is_file() {
            rows.insert(path.strip_prefix(root)?.to_path_buf(), fs::read(path)?);
        } else { return Err("unexpected special file in fixture".into()); }
    }
    Ok(rows)
}

#[test]
fn empty_read_preserves_uncertainty_is_deterministic_and_writes_nothing() -> TestResult {
    let (_directory, root) = Directory::deployment("empty")?;
    let before = snapshot(&root)?;
    let mut args = parse(&[])?;
    args.root = root.clone();
    let (text, exit) = execute_query(&args);
    assert_eq!(exit, ExitIdentity::SUCCESS, "{text}");
    assert!(text.contains("fss.agent_response_envelope.v1"));
    assert!(text.contains("fss.agent_cognitive_envelope.v1"));
    assert!(text.contains("committed_index_exhausted"));
    assert!(text.contains("claim:query:physical-absence"));
    assert!(text.contains("not_observable"));
    assert!(text.contains("bounded_summary"));
    assert!(!text.contains("silence_certificate"));
    assert_eq!(execute_query(&args).0, text);
    assert_eq!(snapshot(&root)?, before);
    Ok(())
}

#[test]
fn exact_anchor_and_wrong_cursor_refusals_are_not_empty_successes() -> TestResult {
    let (_directory, root) = Directory::deployment("refusal")?;
    let before = snapshot(&root)?;
    let current = read_deployment(&root, &OrientLimits::default())?;
    let token = snapshot_anchor_token(&current);
    let mut args = parse(&["--anchor", &token])?;
    args.root = root.clone();
    assert_eq!(execute_query(&args).1, ExitIdentity::SUCCESS);
    args.request.continuation = Some("continuation:wrong-stream".to_owned());
    let (text, exit) = execute_query(&args);
    assert_eq!(exit, ExitIdentity::AGENT_REFUSED);
    assert!(text.contains("continuation_wrong_stream"));
    assert!(text.contains("rebase_required"));
    assert!(text.contains("\"payload\":null"));
    args.request.continuation = None;
    let stale = format!("anchor:{}:999:none:{}", "a".repeat(16), "b".repeat(64));
    args.request.expected_anchor = Some(AnchorToken::parse(&stale).ok_or("bad fixture anchor")?);
    let (text, exit) = execute_query(&args);
    assert_eq!(exit, ExitIdentity::AGENT_REFUSED);
    assert!(text.contains("query anchor changed"));
    assert_eq!(snapshot(&root)?, before);
    Ok(())
}
