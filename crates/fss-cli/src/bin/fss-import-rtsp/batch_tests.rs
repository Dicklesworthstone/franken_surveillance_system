#![forbid(unsafe_code)]
//! Pure planning and deterministic effect-boundary tests for native batch import.

use super::*;

fn child(generation: u64, codec: &str) -> Vec<String> {
    let digest = ContentDigest::sha256(b"batch-import-operator-fixture").to_text();
    [
        "--archive", "/absent-batch-fixture/source",
        "--root", "/absent-batch-fixture/destination",
        "--site", "site:test",
        "--window-slot", "recording-test",
        "--window-root", &digest,
        "--codec", codec,
        "--sensor-id", "sensor:test",
        "--stream-id", "stream:test",
        "--generation", &generation.to_string(),
        "--anchor", &digest,
        "--receive-clock", &digest,
        "--receive-time-ns", "2000000000",
        "--owner-authorized", "yes",
        "--read-originals", "yes",
        "--retain-originals", "yes",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn set(input: &mut Vec<String>, key: &str, value: &str) {
    if let Some(index) = input.iter().position(|arg| arg == key) {
        input[index + 1] = value.into();
    } else {
        input.extend([key.into(), value.into()]);
    }
}

fn input(children: &[Vec<String>]) -> Vec<OsString> {
    let requests = children
        .iter()
        .map(|child| array(&child.iter().map(|arg| string(arg)).collect::<Vec<_>>()))
        .collect::<Vec<_>>();
    vec!["--requests".into(), array(&requests).into()]
}

fn approved(count: u64) -> Result<BatchPlan> {
    let children = (1..=count).map(|i| child(i, "avc")).collect::<Vec<_>>();
    let mut plan = BatchPlan::parse(&input(&children))?;
    plan.approve = Some(plan.approval()?);
    Ok(plan)
}

#[derive(Default)]
struct Script {
    rows: Vec<Value>,
    calls: Vec<ContentDigest>,
    fault_at: Option<usize>,
    bad_receipt_at: Option<usize>,
    fail_output_at: Option<usize>,
    reused: bool,
}

impl Effects for Script {
    fn emit(&mut self, row: &str) -> Result<()> {
        if self.fail_output_at == Some(self.rows.len()) {
            return Err(OUTPUT);
        }
        self.rows.push(parse(row).map_err(|_| "test row JSON")?);
        Ok(())
    }

    fn import(&mut self, child: &Options) -> Result<String> {
        let pin = child.approval()?;
        assert_eq!(child.approve, Some(pin));
        let index = self.calls.len();
        self.calls.push(pin);
        if self.fault_at == Some(index) {
            return Err("ERR-RTSP-IMPORT-SOURCE-001");
        }
        if self.bad_receipt_at == Some(index) {
            return Ok("{\"kind\":\"imported\"}".into());
        }
        Ok(object(&[
            ("kind", string("imported")),
            ("approval_digest", string(&pin.to_text())),
            ("reused", self.reused.to_string()),
        ]))
    }
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    value
        .object()
        .and_then(|v| v.get(key))
        .ok_or("test field missing")
}

fn terminal(script: &Script) -> Result<&Value> {
    let row = script.rows.last().ok_or("test terminal missing")?;
    assert_eq!(field(row, "kind")?.text(), Some("batch_terminal"));
    field(row, "detail")
}

#[test]
fn pure_plan_preserves_each_native_epoch_and_sums_not_widens_limits() -> Result<()> {
    let plan = BatchPlan::parse(&input(&[child(1, "avc"), child(2, "hevc")]))?;
    assert!(plan.children.iter().all(|c| c.approve.is_none()));
    assert_ne!(plan.pins[0], plan.pins[1]);
    let preview = parse(&plan.preview()?).map_err(|_| "preview JSON")?;
    assert_eq!(field(&preview, "maximum_frames")?.integer(), Some(512));
    assert_eq!(
        field(&preview, "maximum_work")?.integer(),
        Some(2_000_000_000_000)
    );
    assert_eq!(field(&preview, "atomic")?.boolean(), Some(false));
    assert_eq!(field(&preview, "network")?.text(), Some("none"));
    let children = field(&preview, "children")?.array().ok_or("child previews")?;
    for (index, child) in children.iter().enumerate() {
        assert_eq!(field(child, "generation")?.integer(), Some(index as i128 + 1));
        assert_eq!(field(child, "capture_time_label")?.text(), Some("unknown"));
        assert_eq!(field(child, "maximum_frames")?.integer(), Some(256));
    }
    Ok(())
}

#[test]
fn all_children_validate_before_any_effect_and_child_approval_is_forbidden() -> Result<()> {
    let first = child(1, "avc");
    for (key, value) in [
        ("--codec", "auto"),
        ("--owner-authorized", "no"),
        ("--read-originals", "no"),
        ("--retain-originals", "no"),
        ("--max-work", "0"),
        ("--root", "/different/destination"),
        ("--site", "site:other"),
        ("--principal", "principal:other"),
    ] {
        let mut second = child(2, "avc");
        set(&mut second, key, value);
        assert!(
            BatchPlan::parse(&input(&[first.clone(), second])).is_err(),
            "{key}"
        );
    }
    let mut second = child(2, "avc");
    set(
        &mut second,
        "--approve",
        &ContentDigest::sha256(b"child approval").to_text(),
    );
    assert!(BatchPlan::parse(&input(&[first, second])).is_err());
    Ok(())
}

#[test]
fn duplicate_and_malformed_or_oversized_batches_refuse() {
    for json in ["[]", "{}", "[1]", "[[1]]", "[[\"--root\"]]", "null", "[] trailing"] {
        assert!(BatchPlan::parse(&["--requests".into(), json.into()]).is_err());
    }
    assert!(BatchPlan::parse(&input(&[child(1, "avc"), child(1, "avc")])).is_err());
    let seventeen = (1..=17).map(|i| child(i, "avc")).collect::<Vec<_>>();
    assert!(BatchPlan::parse(&input(&seventeen)).is_err());
    let oversized = " ".repeat(MAX_REQUEST_BYTES + 1);
    assert!(BatchPlan::parse(&["--requests".into(), oversized.into()]).is_err());
    let mut duplicate = input(&[child(1, "avc")]);
    duplicate.extend(duplicate.clone());
    assert!(BatchPlan::parse(&duplicate).is_err());
}

#[test]
fn canonical_child_ordering_is_ignored_but_batch_order_and_bounds_are_bound() -> Result<()> {
    let first = child(1, "avc");
    let second = child(2, "hevc");
    let original = BatchPlan::parse(&input(&[first.clone(), second.clone()]))?.approval()?;
    let reordered = first.chunks_exact(2).rev().flatten().cloned().collect();
    assert_eq!(
        BatchPlan::parse(&input(&[reordered, second.clone()]))?.approval()?,
        original
    );
    assert_ne!(
        BatchPlan::parse(&input(&[second.clone(), first.clone()]))?.approval()?,
        original
    );
    let mut changed = second;
    set(&mut changed, "--max-work", "1000");
    assert_ne!(BatchPlan::parse(&input(&[first, changed]))?.approval()?, original);
    Ok(())
}

#[test]
fn absent_stale_child_or_mutated_plan_approval_cannot_emit_or_import() -> Result<()> {
    let mut plan = approved(2)?;
    for approval in [None, Some(plan.pins[0]), Some(ContentDigest::sha256(b"stale"))] {
        plan.approve = approval;
        let mut script = Script::default();
        assert_eq!(execute(&mut plan, &mut script), Err(APPROVAL));
        assert!(script.calls.is_empty());
        assert!(script.rows.is_empty());
    }
    plan.approve = Some(plan.approval()?);
    plan.children[1].work = 1;
    let mut script = Script::default();
    assert_eq!(execute(&mut plan, &mut script), Err(APPROVAL));
    assert!(script.calls.is_empty());
    assert!(script.rows.is_empty());
    Ok(())
}

#[test]
fn successful_batch_returns_every_original_receipt_without_cross_epoch_claims() -> Result<()> {
    let mut plan = approved(3)?;
    let mut script = Script::default();
    execute(&mut plan, &mut script)?;
    assert_eq!(script.calls, plan.pins);
    assert_eq!(script.rows.len(), 8);
    for (sequence, row) in script.rows.iter().enumerate() {
        assert_eq!(field(row, "sequence")?.integer(), Some(sequence as i128));
    }
    let end = terminal(&script)?;
    assert_eq!(field(end, "complete")?.boolean(), Some(true));
    assert_eq!(field(end, "completed_imports")?.integer(), Some(3));
    assert_eq!(field(end, "continuity_between_imports")?.boolean(), Some(false));
    assert_eq!(field(end, "absence_certifiable")?.boolean(), Some(false));
    Ok(())
}

#[test]
fn unconfirmed_child_stops_and_preserves_completed_prefix_without_rollback_claim() -> Result<()> {
    let mut plan = approved(3)?;
    let mut script = Script {
        fault_at: Some(1),
        ..Script::default()
    };
    assert_eq!(execute(&mut plan, &mut script), Err("ERR-RTSP-IMPORT-SOURCE-001"));
    assert_eq!(script.calls.len(), 2);
    let end = terminal(&script)?;
    assert_eq!(field(end, "complete")?.boolean(), Some(false));
    assert_eq!(field(end, "completed_imports")?.integer(), Some(1));
    assert_eq!(field(end, "failed_import")?.integer(), Some(2));
    assert_eq!(field(end, "unattempted_imports")?.integer(), Some(1));
    assert_eq!(
        field(end, "failed_import_state")?.text(),
        Some("unconfirmed_may_be_durable")
    );
    Ok(())
}

#[test]
fn output_failure_at_every_row_prevents_later_imports_or_fabricated_terminals() -> Result<()> {
    for failed_row in 0..8 {
        let mut plan = approved(3)?;
        let mut script = Script {
            fail_output_at: Some(failed_row),
            ..Script::default()
        };
        assert_eq!(execute(&mut plan, &mut script), Err(OUTPUT));
        assert_eq!(script.rows.len(), failed_row);
        assert_eq!(script.calls.len(), (failed_row / 2).min(3));
        assert!(script.rows.iter().all(|row| {
            field(row, "kind").ok().and_then(Value::text) != Some("batch_terminal")
        }));
    }
    Ok(())
}

#[test]
fn malformed_or_wrong_native_receipt_is_unconfirmed_and_never_advances() -> Result<()> {
    let mut plan = approved(3)?;
    let mut script = Script {
        bad_receipt_at: Some(1),
        ..Script::default()
    };
    assert_eq!(execute(&mut plan, &mut script), Err(RECEIPT));
    assert_eq!(script.calls.len(), 2);
    assert_eq!(field(terminal(&script)?, "completed_imports")?.integer(), Some(1));
    let wrong = object(&[
        ("kind", string("imported")),
        ("approval_digest", string(&plan.pins[0].to_text())),
    ]);
    assert_eq!(verify_receipt(&wrong, plan.pins[1]), Err(RECEIPT));
    assert_eq!(
        verify_receipt(&" ".repeat(MAX_ROW_BYTES + 1), plan.pins[0]),
        Err(OUTPUT)
    );
    Ok(())
}

#[test]
fn exact_replay_delegates_same_pins_and_keeps_native_reused_receipts() -> Result<()> {
    let mut plan = approved(2)?;
    let mut first = Script {
        fault_at: Some(1),
        ..Script::default()
    };
    assert!(execute(&mut plan, &mut first).is_err());
    let mut retry = Script {
        reused: true,
        ..Script::default()
    };
    execute(&mut plan, &mut retry)?;
    assert_eq!(first.calls, retry.calls);
    let receipt = field(field(&retry.rows[2], "detail")?, "receipt")?;
    assert_eq!(field(receipt, "reused")?.boolean(), Some(true));
    assert_eq!(field(terminal(&retry)?, "complete")?.boolean(), Some(true));
    Ok(())
}

#[test]
fn one_and_sixteen_imports_stay_within_priced_row_and_native_work_bounds() -> Result<()> {
    for count in [1, 16] {
        let mut plan = approved(count)?;
        let mut script = Script::default();
        execute(&mut plan, &mut script)?;
        assert_eq!(script.calls.len(), count as usize);
        assert_eq!(script.rows.len(), 2 * count as usize + 2);
        assert_eq!(plan.sum(|c| c.work)?, count * 1_000_000_000_000);
    }
    Ok(())
}
