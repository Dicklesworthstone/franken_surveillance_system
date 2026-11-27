#![forbid(unsafe_code)]
//! Camera-supervision plans and commits must describe the scope the daemon will execute.

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn context<'a>(
    anchor: &'a LedgerAnchor,
    principal: &'a PrincipalId,
    approval: Option<ContentDigest>,
) -> IntentCtx<'a> {
    IntentCtx {
        root: Path::new("camera-supervision-target-contract"),
        site_lineage: "site-target-shape",
        anchor,
        principal,
        approval,
    }
}

#[test]
fn invalid_control_targets_are_refused_for_both_preview_and_commit() -> TestResult {
    let anchor = LedgerAnchor::genesis("site-target-shape");
    let principal = PrincipalId::parse("principal:owner")?;
    for (op, camera_id) in [
        (BoundedControlOp::StartCamera, None),
        (BoundedControlOp::StopCamera, None),
        (BoundedControlOp::SnapshotCamera, None),
        (BoundedControlOp::ReloadManifest, Some("sensor:front")),
        (BoundedControlOp::ReloadManifest, Some(DAEMON_STOP_TARGET)),
        (BoundedControlOp::TriggerScrub, Some("sensor:front")),
        (BoundedControlOp::TriggerScrub, Some(DAEMON_STOP_TARGET)),
    ] {
        for approval in [
            None,
            Some(control_op_approval_digest(
                "site-target-shape",
                op,
                camera_id,
            )),
        ] {
            let ctx = context(&anchor, &principal, approval);
            assert!(
                matches!(
                    run_camera_supervision(&ctx, op, camera_id, Some(ctx.site_lineage), None),
                    Err(OpsError::InvalidRequest(_))
                ),
                "invalid target for {op:?} must be refused before producing a preview or connecting"
            );
        }
    }
    Ok(())
}

#[test]
fn valid_control_target_shapes_keep_their_exact_preview_approvals() -> TestResult {
    let anchor = LedgerAnchor::genesis("site-target-shape");
    let principal = PrincipalId::parse("principal:owner")?;
    let ctx = context(&anchor, &principal, None);
    for (op, camera_id) in [
        (BoundedControlOp::StartCamera, Some("sensor:front")),
        (BoundedControlOp::StopCamera, Some("sensor:front")),
        (BoundedControlOp::StopCamera, Some(DAEMON_STOP_TARGET)),
        (BoundedControlOp::SnapshotCamera, Some("sensor:front")),
        (BoundedControlOp::ProbeDetect, Some("sensor:front")),
        (BoundedControlOp::ProbeDetect, None),
        (BoundedControlOp::TriggerScrub, None),
    ] {
        let expected =
            if op == BoundedControlOp::StopCamera && camera_id == Some(DAEMON_STOP_TARGET) {
                daemon_stop_approval_digest(ctx.site_lineage, deployment_root_digest(ctx.root))
            } else {
                control_op_approval_digest(ctx.site_lineage, op, camera_id)
            };
        let preview = run_camera_supervision(&ctx, op, camera_id, Some(ctx.site_lineage), None)?;
        assert_eq!(preview.anchor, anchor);
        assert!(
            preview.proof_pointers.contains(&expected.to_text()),
            "preview for {op:?} must retain its exact approval digest"
        );
    }
    Ok(())
}

#[test]
fn proposed_control_keys_are_scoped_but_explicit_retries_survive_anchor_drift() -> TestResult {
    let anchor = LedgerAnchor::genesis("site-target-shape");
    let principal = PrincipalId::parse("principal:owner")?;
    let approval = control_op_approval_digest(
        "site-target-shape",
        BoundedControlOp::SnapshotCamera,
        Some("sensor:front"),
    );
    let ctx = context(&anchor, &principal, None);
    let key = camera_control_request_key(&ctx, approval, None)?;
    assert_eq!(key, camera_control_request_key(&ctx, approval, None)?);

    let mut changed_anchor = anchor.clone();
    changed_anchor.commit_sequence += 1;
    let changed = context(&changed_anchor, &principal, None);
    assert_ne!(key, camera_control_request_key(&changed, approval, None)?);
    let other = PrincipalId::parse("principal:other")?;
    assert_ne!(
        key,
        camera_control_request_key(&context(&anchor, &other, None), approval, None)?
    );
    let mut other_root = context(&anchor, &principal, None);
    other_root.root = Path::new("another-deployment-root");
    assert_ne!(
        key,
        camera_control_request_key(&other_root, approval, None)?
    );

    let retry = context(&changed_anchor, &principal, Some(approval));
    assert!(matches!(
        camera_control_request_key(&retry, approval, None),
        Err(OpsError::InvalidRequest(_))
    ));
    assert_eq!(
        key,
        camera_control_request_key(&retry, approval, Some(key))?
    );
    let next = ContentDigest::sha256(b"explicit-distinct-control-request");
    assert_eq!(
        next,
        camera_control_request_key(&ctx, approval, Some(next))?
    );
    for raw in [
        format!("sha256:{}", "0".repeat(64)),
        format!("blake3:{}", "1".repeat(64)),
    ] {
        let invalid = ContentDigest::parse(&raw)?;
        assert!(matches!(
            camera_control_request_key(&ctx, approval, Some(invalid)),
            Err(OpsError::InvalidRequest(_))
        ));
    }
    Ok(())
}

#[test]
fn replay_projection_preserves_uncertain_execution_and_inert_recovery() -> TestResult {
    let anchor = LedgerAnchor::genesis("site-target-shape");
    let principal = PrincipalId::parse("principal:owner")?;
    let approval = ContentDigest::sha256(b"approval");
    let key = ContentDigest::sha256(b"retry");
    let operation_id = OperationId::parse("op:ctrl:original")?;
    let ctx = context(&anchor, &principal, Some(approval));
    for progress in [
        RetainedControlProgress::NeverStarted,
        RetainedControlProgress::DispatchStarted,
        RetainedControlProgress::SubsystemReturned,
        RetainedControlProgress::CancelledBeforeExecution,
    ] {
        for recovered in [false, true] {
            let result = camera_control_response(
                &ctx,
                BoundedControlOp::SnapshotCamera,
                Some("sensor:front"),
                ctx.site_lineage,
                ContentDigest::sha256(b"descriptor"),
                approval,
                key,
                2,
                IpcResponse::ControlReplayed {
                    request_id: 2,
                    operation_id: operation_id.clone(),
                    progress,
                    recovered,
                },
            )?;
            assert!(result.payload_json.contains("\"status\":\"replayed\""));
            assert!(result.payload_json.contains("\"authorityChanged\":false"));
            assert!(
                result
                    .payload_json
                    .contains("\"semanticCompletionProved\":false")
            );
            assert!(result.payload_json.contains(progress.as_str()));
            assert!(result.payload_json.contains(operation_id.as_str()));
            assert_eq!(result.idempotency_key, key.to_text());
            assert_eq!(
                !result.possibly_occurred.is_empty(),
                matches!(
                    progress,
                    RetainedControlProgress::DispatchStarted
                        | RetainedControlProgress::SubsystemReturned
                )
            );
            assert!(result.not_started[0].contains("did not enqueue or dispatch"));
            if recovered {
                assert!(result.warnings[0].contains("remains inert"));
            }
        }
    }
    Ok(())
}

fn assert_registered_recovery_class(json: &str) -> TestResult {
    use fss_core::json_input::{Value, parse_mcp_reply};

    let schema = parse_mcp_reply(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../schemas/agent_response_envelope.v1.json"
    )))?;
    let allowed = schema
        .object()
        .and_then(|object| object.get("properties"))
        .and_then(Value::object)
        .and_then(|object| object.get("recoveryClass"))
        .and_then(Value::object)
        .and_then(|object| object.get("enum"))
        .and_then(Value::array)
        .ok_or("response schema lacks its closed recoveryClass enum")?;
    let response = parse_mcp_reply(json)?;
    let class = response
        .object()
        .and_then(|object| object.get("recoveryClass"))
        .and_then(Value::text)
        .ok_or("response lacks recoveryClass")?;
    assert!(allowed.iter().any(|value| value.text() == Some(class)));
    Ok(())
}

#[test]
fn lost_control_acknowledgement_preserves_retry_key_and_unknown_effects() -> TestResult {
    use fss_core::json_input::{Value, parse_mcp_reply};

    let anchor = LedgerAnchor::genesis("site-target-shape");
    let principal = PrincipalId::parse("principal:owner")?;
    let approval = ContentDigest::sha256(b"approved intended action");
    let key = ContentDigest::sha256(b"original request key");
    let ctx = context(&anchor, &principal, Some(approval));
    // Even an oversized transport diagnostic must not force a fallback that loses the key.
    let error = control_outcome_uncertain(
        &ctx,
        approval,
        key,
        format!("reply lost after submission: {}", "é".repeat(10_000)),
    );
    let (json, exit) = render_refusal_envelope(
        ctx.root,
        "commit",
        &principal,
        None,
        OPS_COMMIT_PAYLOAD_SCHEMA,
        &error,
    );
    assert_eq!(exit, ExitIdentity::AGENT_REFUSED);
    assert_registered_recovery_class(&json)?;
    let envelope = parse_mcp_reply(&json)?;
    let fields = envelope.object().ok_or("missing response envelope")?;
    assert_eq!(
        fields.get("outcome").and_then(Value::text),
        Some("indeterminate")
    );
    assert_eq!(
        fields.get("taskState").and_then(Value::text),
        Some("indeterminate")
    );
    assert_eq!(
        fields.get("errorId").and_then(Value::text),
        Some("ERR-EFFECT-INDETERMINATE-001")
    );
    assert_eq!(
        fields.get("idempotencyKey").and_then(Value::text),
        Some(key.to_text().as_str())
    );
    assert_eq!(
        fields.get("safeRetry").and_then(Value::text),
        Some("yes_same_request")
    );
    assert_eq!(
        fields.get("recoveryClass").and_then(Value::text),
        Some("reconciliation_required")
    );
    let payload = fields
        .get("payload")
        .and_then(Value::object)
        .ok_or("missing retry payload")?;
    assert_eq!(
        payload.get("approvalDigest").and_then(Value::text),
        Some(approval.to_text().as_str())
    );
    assert_eq!(
        payload
            .get("semanticCompletionProved")
            .and_then(Value::boolean),
        Some(false)
    );
    assert!(json.contains(&anchor.state_root.to_text()));
    assert!(json.contains("may have durably admitted or dispatched"));
    assert!(!json.contains("No unauthorized read, policy mutation, or effect occurred."));
    Ok(())
}

#[test]
fn uncertain_daemon_refusal_and_post_submission_cancellation_keep_the_original_key() -> TestResult {
    let anchor = LedgerAnchor::genesis("site-target-shape");
    let principal = PrincipalId::parse("principal:owner")?;
    let approval = ContentDigest::sha256(b"approved shutdown");
    let key = ContentDigest::sha256(b"shutdown retry key");
    let ctx = context(&anchor, &principal, Some(approval));
    for response in [
        IpcResponse::Refused {
            request_id: 3,
            error_id: fss_core::ErrorId::parse(fss_core::ERR_OP_RECONCILIATION_REQUIRED_001)?,
            reason: "shutdown requested, but its durable return boundary is uncertain".to_owned(),
            retryable: false,
        },
        IpcResponse::Refused {
            request_id: 3,
            error_id: fss_core::ErrorId::parse("ERR-DAEMON-SHUTDOWN-001")?,
            reason: "control journal lock poisoned after shutdown request".to_owned(),
            retryable: false,
        },
        IpcResponse::Cancelled { request_id: 3 },
    ] {
        let result = camera_control_response(
            &ctx,
            BoundedControlOp::StopCamera,
            Some(DAEMON_STOP_TARGET),
            ctx.site_lineage,
            ContentDigest::sha256(b"descriptor"),
            approval,
            key,
            3,
            response,
        );
        let Err(OpsError::ControlOutcomeUncertain {
            idempotency_key,
            approval_digest,
            input_anchor,
            ..
        }) = result
        else {
            return Err(
                "an ambiguous control boundary was flattened into a definite refusal".into(),
            );
        };
        assert_eq!(idempotency_key, key);
        assert_eq!(approval_digest, approval);
        assert_eq!(*input_anchor, anchor);
    }
    let offline = OpsError::DaemonUnavailable("connection refused before submission".to_owned());
    let (json, _) = render_refusal_envelope(
        ctx.root,
        "commit",
        &principal,
        None,
        OPS_COMMIT_PAYLOAD_SCHEMA,
        &offline,
    );
    assert_registered_recovery_class(&json)?;
    assert!(json.contains("\"outcome\":\"refused\""));
    assert!(!json.contains("\"outcome\":\"indeterminate\""));
    Ok(())
}

#[test]
fn mismatched_success_response_never_attributes_another_operation_to_this_key() -> TestResult {
    let anchor = LedgerAnchor::genesis("site-target-shape");
    let principal = PrincipalId::parse("principal:owner")?;
    let approval = ContentDigest::sha256(b"approval");
    let key = ContentDigest::sha256(b"original key");
    let ctx = context(&anchor, &principal, Some(approval));
    let other_operation = OperationId::parse("op:ctrl:another-request")?;
    for response in [
        IpcResponse::ControlAccepted {
            request_id: 99,
            operation_id: other_operation.clone(),
            state: ControlOperationState::Queued,
        },
        IpcResponse::ControlReplayed {
            request_id: 99,
            operation_id: other_operation.clone(),
            progress: RetainedControlProgress::SubsystemReturned,
            recovered: true,
        },
    ] {
        let result = camera_control_response(
            &ctx,
            BoundedControlOp::SnapshotCamera,
            Some("sensor:front"),
            ctx.site_lineage,
            ContentDigest::sha256(b"descriptor"),
            approval,
            key,
            7,
            response,
        );
        let Err(OpsError::ControlOutcomeUncertain {
            idempotency_key, ..
        }) = result
        else {
            return Err(
                "mismatched response was incorrectly attributed to the original key".into(),
            );
        };
        assert_eq!(idempotency_key, key);
    }
    Ok(())
}

#[test]
fn manifest_reload_preview_requires_live_owner_and_retries_keep_the_original_approval() -> TestResult
{
    let anchor = LedgerAnchor::genesis("site-target-shape");
    let principal = PrincipalId::parse("principal:owner")?;
    let preview = context(&anchor, &principal, None);
    assert!(matches!(
        run_camera_supervision(
            &preview,
            BoundedControlOp::ReloadManifest,
            None,
            Some(preview.site_lineage),
            None,
        ),
        Err(OpsError::DaemonUnavailable(_))
    ));
    let sealed = manifest_reload_approval_digest(
        preview.site_lineage,
        deployment_root_digest(preview.root),
        ContentDigest::sha256(b"previous active manifest"),
        ContentDigest::sha256(b"previously approved candidate"),
    );
    let key = ContentDigest::sha256(b"original reload request");
    let retry = context(&anchor, &principal, Some(sealed));
    // A retry carries its original approval to the daemon. It is not compared against the
    // old operation-only digest or replaced by a new preview after candidate-file drift.
    assert!(matches!(
        run_camera_supervision(
            &retry,
            BoundedControlOp::ReloadManifest,
            None,
            Some(retry.site_lineage),
            Some(key),
        ),
        Err(OpsError::DaemonUnavailable(_))
    ));
    assert!(matches!(
        run_camera_supervision(
            &retry,
            BoundedControlOp::ReloadManifest,
            None,
            Some(retry.site_lineage),
            None,
        ),
        Err(OpsError::InvalidRequest(_))
    ));
    Ok(())
}

#[test]
fn manifest_reload_preview_verifies_exact_generations_scope_and_correlation() -> TestResult {
    let anchor = LedgerAnchor::genesis("site-target-shape");
    let principal = PrincipalId::parse("principal:owner")?;
    let ctx = context(&anchor, &principal, None);
    let active = ContentDigest::sha256(b"active configuration");
    let candidate = ContentDigest::sha256(b"approved candidate");
    let approval = manifest_reload_approval_digest(
        ctx.site_lineage,
        deployment_root_digest(ctx.root),
        active,
        candidate,
    );
    let valid = || IpcResponse::ManifestReloadPreview {
        request_id: 17,
        active_manifest_digest: active,
        candidate_manifest_digest: candidate,
        approval_digest: approval,
    };
    let checked = validate_manifest_reload_preview(&ctx, ctx.site_lineage, 17, valid())?;
    assert_eq!(checked.active_manifest_digest, active);
    assert_eq!(checked.candidate_manifest_digest, candidate);
    assert_eq!(checked.approval_digest, approval);
    assert!(validate_manifest_reload_preview(&ctx, ctx.site_lineage, 18, valid()).is_err());
    assert!(validate_manifest_reload_preview(&ctx, "another-deployment", 17, valid()).is_err());
    let mut other_root = context(&anchor, &principal, None);
    other_root.root = Path::new("another-reload-deployment");
    assert!(validate_manifest_reload_preview(&other_root, ctx.site_lineage, 17, valid()).is_err());
    for (wrong_active, wrong_candidate, wrong_approval) in [
        (ContentDigest::sha256(b"other active"), candidate, approval),
        (
            active,
            ContentDigest::sha256(b"changed candidate"),
            approval,
        ),
        (
            active,
            candidate,
            control_op_approval_digest(ctx.site_lineage, BoundedControlOp::ReloadManifest, None),
        ),
        (
            active,
            candidate,
            ContentDigest::parse(&format!("sha256:{}", "0".repeat(64)))?,
        ),
    ] {
        let response = IpcResponse::ManifestReloadPreview {
            request_id: 17,
            active_manifest_digest: wrong_active,
            candidate_manifest_digest: wrong_candidate,
            approval_digest: wrong_approval,
        };
        assert!(validate_manifest_reload_preview(&ctx, ctx.site_lineage, 17, response).is_err());
    }
    let next_approval = manifest_reload_approval_digest(
        ctx.site_lineage,
        deployment_root_digest(ctx.root),
        active,
        ContentDigest::sha256(b"next candidate"),
    );
    assert_ne!(
        camera_control_request_key(&ctx, approval, None)?,
        camera_control_request_key(&ctx, next_approval, None)?
    );
    Ok(())
}
