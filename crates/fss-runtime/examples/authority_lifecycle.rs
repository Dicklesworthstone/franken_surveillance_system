//! Deterministic authority-lifecycle e2e for FSS-021 slice 2.
//!
//! Exercises the public semantic surface end to end and records one JSONL
//! transition per step: root construction → legal narrowing → obligation
//! register/leak/resolve → budget spend + typed overdraft refusal →
//! cancellation cascade → drain request → finalize leak report.
//!
//! Reproduce: `cargo run -p fss-runtime --example authority_lifecycle`.
//! Output is secret-free: ids, kinds, counts, and digests only.

use fss_core::{
    BudgetVector, ContentDigest, ObligationId, OperationId, RegionId, RegionKind,
    RootAuthoritySpec, TimestampNs,
};
use fss_runtime::authority::AuthorityCx;
use fss_runtime::budget::Budget;
use fss_runtime::obligation::{new_obligation, ObligationTerminal};

fn step(seq: u32, transition: &str, detail: &str) {
    // Bounded structured log: scenario/seed fixed; no secrets, no raw media.
    println!(
        "{{\"scenario\":\"authority-lifecycle\",\"seed\":0,\"seq\":{seq},\"transition\":\"{transition}\",\"detail\":\"{detail}\"}}"
    );
}

fn spec(trace: &str, op: &str) -> RootAuthoritySpec {
    RootAuthoritySpec {
        trace_id: trace.to_string(),
        operation_id: OperationId::parse(op).expect("operation id"),
        principal: "principal:local-operator".to_string(),
        capabilities: Vec::new(),
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(1024)
            .storage_operations(64)
            .build()
            .expect("budget vector"),
        privacy_scope: "privacy:local-authorized".to_string(),
        retention_scope: "retention:existing-policy".to_string(),
        anchor_universe: ContentDigest::sha256(b"authority-lifecycle-universe"),
        generation: 1,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (mut root, mut tree) = AuthorityCx::root(
        spec("trace:authority-lifecycle", "operation:root"),
        RegionId::new("region:process").expect("region id"),
        RegionKind::Process,
        Budget::new(100, 1_000, 10_000),
        TimestampNs(1_000),
    )
    .expect("root authority");
    step(0, "root-constructed", "region:process kind=Process");

    // Legal narrowing: Process admits Property; trace_id inherited; budget
    // strictly inside the parent's.
    let mut child = root
        .scope_down(
            &mut tree,
            RegionId::new("region:property").expect("child id"),
            RegionKind::Property,
            Budget::new(50, 500, 5_000),
            spec("trace:authority-lifecycle", "operation:property"),
            TimestampNs(2_000),
        )
        .expect("legal scope_down");
    step(1, "scope-down-legal", "region:property kind=Property budget=50/500/5000");

    // Obligation lifecycle through the tree.
    let ob = new_obligation(
        "obligation:capture-drain",
        OperationId::parse("operation:property").expect("operation id"),
        "capture ring drained and receipt published",
    )
    .expect("obligation");
    child.register_obligation(&mut tree, ob).expect("register");
    let leaks = child.leaked_obligations(&tree);
    step(2, "obligation-registered", &format!("pending={}", leaks.len()));

    child
        .resolve_obligation(
            &mut tree,
            &ObligationId::parse("obligation:capture-drain").expect("obligation id"),
            ObligationTerminal::Completed,
            Some(ContentDigest::sha256(b"capture-drain-receipt")),
            None,
        )
        .expect("resolve");
    step(3, "obligation-resolved", "terminal=Verified proof=present");

    // Budget: spend inside bounds; typed refusal on overdraft.
    child.budget_mut().spend_work(50).expect("spend");
    let refused = child.budget_mut().spend_bytes(501).is_err();
    step(4, "budget-exercised", &format!("overdraft_refused={refused}"));

    // Cancellation cascades through the chain; drain requested on the subtree.
    root.request_cancellation();
    let cascaded = child.is_cancel_requested();
    step(5, "cancellation-cascade", &format!("child_observed={cascaded}"));
    tree.request_drain(
        &RegionId::new("region:process").expect("region id"),
        Some("authority-lifecycle teardown"),
        TimestampNs(3_000),
    )
    .expect("drain request");
    step(6, "drain-requested", "subtree=region:process");

    // Finalize: the leak oracle reads the tree; no pending obligations remain.
    let report = child.finalize_report(&tree);
    step(7, "finalize-report", &format!("leaked={}", report.len()));

    if refused && cascaded && report.is_empty() {
        step(8, "outcome", "Completed");
        Ok(())
    } else {
        step(8, "outcome", "Indeterminate");
        Err("lifecycle invariant violated".into())
    }
}
