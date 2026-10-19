#![forbid(unsafe_code)]
//! Native capture results remain distinct from task completion and custody closure.
//!
//! Reuse the bounded camera and child-process fixtures from the parent module. A
//! successful `captured` return also proves the camera observed the client's close;
//! it is not just an assertion about a report produced while a socket remains live.

use super::*;

fn execution<'a>(
    terminal: &'a Value,
    outcome: &str,
    custody: &str,
    quiescent: bool,
) -> Test<&'a Value> {
    let runtime = value(terminal, "runtime")?;
    assert_eq!(text(runtime, "execution")?, "synchronous_owned");
    assert!(boolean(runtime, "closure_returned")?);
    assert!(boolean(runtime, "native_resources_closed")?);
    assert_eq!(boolean(runtime, "quiescent")?, quiescent);
    assert_eq!(integer(runtime, "active_tasks")?, 0);
    assert_eq!(text(runtime, "custody_state")?, custody);
    assert_eq!(value(runtime, "receipt_error")?, &Value::Null);
    assert_eq!(
        value(runtime, "closure_error")?,
        value(terminal, "error_id")?
    );

    let receipt = value(runtime, "task_receipt")?;
    fss_core::TaskId::new(text(receipt, "task_id")?)?;
    fss_core::RegionId::new(text(receipt, "region_id")?)?;
    assert_eq!(text(receipt, "outcome")?, outcome);
    let registered = integer(receipt, "registered_ns")?;
    assert!(registered >= 0);
    assert!(integer(receipt, "completed_ns")? >= registered);
    if outcome == "success" {
        assert_eq!(value(receipt, "reason")?, &Value::Null);
    } else {
        let reason = text(receipt, "reason")?;
        assert!(!reason.trim().is_empty());
        assert!(reason.len() <= 256);
        assert!(!reason.chars().any(char::is_control));
    }

    // These real socket/archive paths cannot be reported as uncharged work.
    let reservation = value(runtime, "reservation")?;
    assert!(integer(reservation, "bytes")? > 0);
    assert!(integer(reservation, "network_bytes")? > 0);
    assert!(integer(runtime, "storage_admissions")? > 0);
    let budget = value(runtime, "budget")?;
    let allowance = value(budget, "allowance")?;
    let charged = value(budget, "charged")?;
    let remaining = value(budget, "remaining")?;
    for dimension in [
        "latencyMs",
        "tokens",
        "bytes",
        "modelCalls",
        "cpuMillis",
        "acceleratorMillis",
        "energyMilliJoules",
        "networkBytes",
        "storageOperations",
    ] {
        let spent = integer(charged, dimension)?;
        let available = integer(remaining, dimension)?;
        assert!(spent >= 0 && available >= 0, "{dimension}");
        assert_eq!(
            spent + available,
            integer(allowance, dimension)?,
            "{dimension}"
        );
    }
    assert_eq!(integer(charged, "bytes")?, integer(reservation, "bytes")?);
    assert_eq!(
        integer(charged, "networkBytes")?,
        integer(reservation, "network_bytes")?
    );
    assert_eq!(
        integer(charged, "storageOperations")?,
        integer(runtime, "storage_admissions")?
    );
    if quiescent {
        let proof = value(runtime, "quiescence_proof")?;
        ContentDigest::parse(text(proof, "proof_digest")?)?;
        assert_eq!(integer(proof, "total_tasks")?, 1);
        assert_eq!(integer(proof, "total_obligations")?, 1);
        assert!(
            value(runtime, "pending_obligations")?
                .array()
                .ok_or("pending obligations are not an array")?
                .is_empty()
        );
    } else {
        assert_eq!(value(runtime, "quiescence_proof")?, &Value::Null);
    }
    Ok(runtime)
}

#[test]
fn target_stop_closes_native_resources_before_proving_runtime_quiescence() -> Test {
    let directory = Directory::new("runtime-target")?;
    let listener = listener()?;
    let approved = approve(&args(&directory, listener.local_addr()?, 2))?;
    let (output, camera) = captured(listener, &approved, Behavior::Target)?;
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(&camera.methods[..3], ["DESCRIBE", "SETUP", "PLAY"]);
    assert!(!camera.source_eof);

    let rows = rows(&output)?;
    let terminal = detail(&rows, "terminal")?;
    assert!(boolean(terminal, "complete")?);
    assert_eq!(text(terminal, "stop_cause")?, "owner_stopped");
    assert_eq!(integer(terminal, "durable_pictures")?, 2);
    assert_eq!(integer(terminal, "indexed_windows")?, 1);
    assert_eq!(value(terminal, "error_id")?, &Value::Null);
    assert!(!boolean(terminal, "input_end_observed")?);
    execution(terminal, "success", "verified", true)?;
    // Runtime closure does not promote capture into unestablished coverage truth.
    assert!(!boolean(terminal, "coverage_certified")?);
    Ok(())
}

#[test]
fn retained_eof_prefix_settles_custody_without_erasing_the_native_shortfall() -> Test {
    let directory = Directory::new("runtime-shortfall")?;
    let listener = listener()?;
    let approved = approve(&args(&directory, listener.local_addr()?, 2))?;
    let (output, camera) = captured(listener, &approved, Behavior::EofAfterOne)?;
    assert!(!output.status.success());
    assert!(camera.source_eof);

    let rows = rows(&output)?;
    let terminal = detail(&rows, "terminal")?;
    assert!(!boolean(terminal, "complete")?);
    assert_eq!(text(terminal, "stop_cause")?, "input_ended_before_target");
    assert_eq!(
        text(terminal, "error_id")?,
        "ERR-CAPTURE-RTSP-SHORTFALL-001"
    );
    assert!(boolean(terminal, "input_end_observed")?);
    assert_eq!(integer(terminal, "collected_pictures")?, 1);
    assert_eq!(integer(terminal, "durable_pictures")?, 1);
    assert_eq!(integer(terminal, "indexed_windows")?, 1);
    ContentDigest::parse(text(terminal, "snapshot_digest")?)?;
    execution(terminal, "failed", "verified", true)?;
    Ok(())
}

#[test]
fn malformed_source_closes_the_socket_but_keeps_canonical_custody_pending() -> Test {
    let directory = Directory::new("runtime-pending-custody")?;
    let listener = listener()?;
    let approved = approve(&args(&directory, listener.local_addr()?, 2))?;
    let (output, camera) = captured(listener, &approved, Behavior::MalformedAfterOne)?;
    assert!(!output.status.success());
    assert!(!camera.source_eof);

    let rows = rows(&output)?;
    let terminal = detail(&rows, "terminal")?;
    assert!(!boolean(terminal, "complete")?);
    assert_eq!(text(terminal, "stop_cause")?, "protocol_failure");
    assert_eq!(text(terminal, "error_id")?, "ERR-CAPTURE-RTSP-SOURCE-001");
    assert_eq!(integer(terminal, "collected_pictures")?, 1);
    assert_eq!(integer(terminal, "durable_windows")?, 0);
    assert!(integer(terminal, "unsealed_rtp_bytes")? > 0);
    assert!(integer(terminal, "unsealed_pictures")? >= 1);
    let runtime = execution(terminal, "indeterminate", "pending", false)?;
    let pending = value(runtime, "pending_obligations")?
        .array()
        .ok_or("pending custody is not an array")?;
    assert!(
        !pending.is_empty(),
        "native loss erased the custody obligation"
    );
    for obligation in pending {
        assert!(!text(obligation, "id")?.trim().is_empty());
        assert!(!text(obligation, "terminal_predicate")?.trim().is_empty());
    }
    assert!(
        rows.iter()
            .all(|row| text(row, "kind").ok() != Some("window_durable")),
        "task completion fabricated a durable media window"
    );
    Ok(())
}

#[test]
fn authentication_refusal_finishes_the_task_without_inventing_pending_media() -> Test {
    let directory = Directory::new("runtime-auth-refusal")?;
    let listener = listener()?;
    let approved = approve(&args(&directory, listener.local_addr()?, 2))?;
    let (output, camera) = captured(listener, &approved, Behavior::AuthenticationRequired)?;
    assert!(!output.status.success());
    assert_eq!(camera.methods, ["DESCRIBE"]);

    let rows = rows(&output)?;
    let terminal = detail(&rows, "terminal")?;
    assert!(!boolean(terminal, "complete")?);
    assert_eq!(text(terminal, "stop_cause")?, "authentication_required");
    assert_eq!(
        text(terminal, "error_id")?,
        "ERR-CAPTURE-RTSP-AUTH-UNSUPPORTED-001"
    );
    assert_eq!(integer(terminal, "collected_pictures")?, 0);
    assert_eq!(integer(terminal, "durable_windows")?, 0);
    execution(terminal, "failed", "failed", true)?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for secret in [SECRET_REALM, SECRET_NONCE, "WWW-Authenticate"] {
        assert!(
            !combined.contains(secret),
            "runtime report leaked a challenge"
        );
    }
    Ok(())
}
