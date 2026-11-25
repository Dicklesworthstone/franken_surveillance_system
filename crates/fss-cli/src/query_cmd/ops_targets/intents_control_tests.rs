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
                    run_camera_supervision(&ctx, op, camera_id, Some(ctx.site_lineage)),
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
        (BoundedControlOp::ReloadManifest, None),
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
        let preview = run_camera_supervision(&ctx, op, camera_id, Some(ctx.site_lineage))?;
        assert_eq!(preview.anchor, anchor);
        assert!(
            preview.proof_pointers.contains(&expected.to_text()),
            "preview for {op:?} must retain its exact approval digest"
        );
    }
    Ok(())
}
