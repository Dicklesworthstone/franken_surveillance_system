#![forbid(unsafe_code)]
//! Pure publication-result contracts. Supplied outcomes are renderer inputs, not
//! substitute runtime success or evidence that a fixture camera was contacted.

use super::*;
use fss_core::json_input::{self, Value};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn receipt() -> Test<SiteProbeReceipt> {
    let mut receipt = fss_reference::site::parse_probe_receipts(include_bytes!(
        "../../../../fixtures/site/probes.v1.json"
    ))?
    .remove(0);
    receipt.presentation = "/PRIVATE_HANDOFF_ROUTE_CANARY/?variant=PRIVATE_QUERY_CANARY".into();
    receipt.control_root = "/PRIVATE_HANDOFF_ROUTE_CANARY/".into();
    receipt.server_identity = "PRIVATE_SERVER_CANARY".into();
    receipt.validate()?;
    Ok(receipt)
}

fn unifi() -> PublicationSelection {
    PublicationSelection::Unifi {
        camera_ref: ContentDigest::sha256(b"PRIVATE_CAMERA_ID_CANARY"),
        view: "main",
        quality: "high",
    }
}

fn onvif() -> PublicationSelection {
    PublicationSelection::Onvif {
        onboarding_plan: ContentDigest::sha256(b"historical-onboarding"),
        profile_digest: ContentDigest::sha256(b"PRIVATE_PROFILE_TOKEN_CANARY"),
    }
}

fn context<'a>(
    receipt: &'a SiteProbeReceipt,
    selection: PublicationSelection,
) -> Test<PublicationContext<'a>> {
    Ok(PublicationContext {
        approval: ContentDigest::sha256(b"exact-independent-probe-approval"),
        site_id: &receipt.site_id,
        source_id: &receipt.source_id,
        selection,
        receipt_file: Path::new("/private/site/probe-receipt.json"),
        receipt,
        receipt_digest: receipt.digest()?,
        file_digest: ContentDigest::sha256(array(&[receipt_json(receipt)]).as_bytes()),
    })
}

fn facts(credentials: bool) -> Facts {
    Facts {
        connection_attempted: true,
        credential_access_attempted: credentials,
        credentials_loaded: credentials,
        teardown_acknowledged: true,
        ..Facts::default()
    }
}

fn saved() -> PublicationOutcome {
    PublicationOutcome {
        receipt_saved: true,
        receipt_file_may_exist: true,
        error: None,
        post_commit_error: None,
        finalization_error: None,
    }
}

fn outcomes() -> [PublicationOutcome; 6] {
    [
        saved(),
        PublicationOutcome {
            post_commit_error: Some("ERR-ONVIF-CANCELLED-001"),
            ..saved()
        },
        PublicationOutcome {
            finalization_error: Some("ERR-ONVIF-AUTHORITY-001"),
            ..saved()
        },
        PublicationOutcome {
            post_commit_error: Some("ERR-ONVIF-DEADLINE-001"),
            finalization_error: Some("ERR-ONVIF-AUTHORITY-001"),
            ..saved()
        },
        PublicationOutcome {
            receipt_saved: false,
            receipt_file_may_exist: true,
            error: Some("ERR-ONVIF-PRIVATE-FILE-001"),
            ..saved()
        },
        PublicationOutcome {
            receipt_saved: false,
            receipt_file_may_exist: false,
            error: Some("ERR-ONVIF-PRIVATE-FILE-001"),
            ..saved()
        },
    ]
}

fn field<'a>(value: &'a Value, key: &str) -> Test<&'a Value> {
    value
        .object()
        .and_then(|fields| fields.get(key))
        .ok_or_else(|| format!("missing publication field {key}").into())
}

#[test]
fn committed_receipt_stays_saved_and_addressable_after_late_owner_errors() -> Test {
    let receipt = receipt()?;
    for selection in [unifi(), onvif()] {
        for outcome in outcomes().into_iter().skip(1).take(3) {
            let context = context(&receipt, selection)?;
            let expected_receipt = context.receipt_digest.to_text();
            let expected_file = context.file_digest.to_text();
            let (output, exit) = render_publication(context, facts(true), outcome);
            let value = json_input::parse(&output)?;
            assert_eq!(exit, ExitIdentity::RUNTIME_FAILURE);
            assert_eq!(field(&value, "status")?.text(), Some("refused"));
            assert_eq!(field(&value, "receipt_saved")?.boolean(), Some(true));
            assert_eq!(
                field(&value, "receipt_file_may_exist")?.boolean(),
                Some(true)
            );
            assert_eq!(
                field(&value, "receipt_digest")?.text(),
                Some(expected_receipt.as_str())
            );
            assert_eq!(
                field(&value, "receipt_file_digest")?.text(),
                Some(expected_file.as_str())
            );
            assert_eq!(field(&value, "error_id")?, &Value::Null);
            assert_eq!(
                field(&value, "post_commit_error")?.text(),
                outcome.post_commit_error
            );
            assert_eq!(
                field(&value, "finalization_error")?.text(),
                outcome.finalization_error
            );
            assert_eq!(field(&value, "retry_automatically")?.boolean(), Some(false));
            assert_eq!(
                field(&value, "teardown_acknowledged")?.boolean(),
                Some(true)
            );
        }
    }
    Ok(())
}

#[test]
fn uncertain_partial_file_does_not_become_a_saved_receipt_or_disappear_from_result() -> Test {
    let receipt = receipt()?;
    for selection in [unifi(), onvif()] {
        for outcome in outcomes().into_iter().skip(4) {
            let context = context(&receipt, selection)?;
            let intended_receipt = context.receipt_digest.to_text();
            let intended_file = context.file_digest.to_text();
            let (output, exit) = render_publication(context, facts(false), outcome);
            let value = json_input::parse(&output)?;
            assert_eq!(exit, ExitIdentity::RUNTIME_FAILURE);
            assert_eq!(field(&value, "receipt_saved")?.boolean(), Some(false));
            assert_eq!(
                field(&value, "receipt_file_may_exist")?.boolean(),
                Some(outcome.receipt_file_may_exist)
            );
            assert_eq!(field(&value, "receipt_digest")?, &Value::Null);
            assert_eq!(field(&value, "receipt_file_digest")?, &Value::Null);
            assert!(!output.contains(&intended_receipt));
            assert!(!output.contains(&intended_file));
            assert_eq!(field(&value, "error_id")?.text(), outcome.error);
            assert_eq!(field(&value, "post_commit_error")?, &Value::Null);
            assert_eq!(field(&value, "finalization_error")?, &Value::Null);
            assert_eq!(
                field(&value, "receipt_file")?.text(),
                Some("/private/site/probe-receipt.json")
            );
            assert_eq!(
                field(&value, "remote_session_may_exist")?.boolean(),
                Some(false)
            );
            assert_eq!(field(&value, "retry_automatically")?.boolean(), Some(false));
        }
    }
    Ok(())
}

#[test]
fn publication_results_never_render_private_routes_profile_tokens_or_source_bytes() -> Test {
    let receipt = receipt()?;
    for selection in [unifi(), onvif()] {
        for outcome in outcomes() {
            let (output, exit) =
                render_publication(context(&receipt, selection)?, facts(true), outcome);
            let value = json_input::parse(&output)?;
            for private in [
                "PRIVATE_HANDOFF_ROUTE_CANARY",
                "PRIVATE_QUERY_CANARY",
                "PRIVATE_SERVER_CANARY",
                "PRIVATE_CAMERA_ID_CANARY",
                "PRIVATE_HANDOFF_FILE_CANARY",
                "PRIVATE_PROFILE_TOKEN_CANARY",
            ] {
                assert!(!output.contains(private));
            }
            assert_eq!(field(&value, "schema")?.text(), Some(selection.schema()));
            assert_eq!(field(&value, "source_retained")?.boolean(), Some(false));
            assert_eq!(field(&value, "exit_id")?.text(), Some(exit.identifier));
            assert_eq!(
                field(&value, "exit_code")?.integer(),
                Some(i128::from(exit.code))
            );
            if outcome.receipt_saved
                && outcome.post_commit_error.is_none()
                && outcome.finalization_error.is_none()
            {
                assert_eq!(exit, ExitIdentity::SUCCESS);
                assert_eq!(field(&value, "status")?.text(), Some("ok"));
            }
            match selection {
                PublicationSelection::Unifi { .. } => {
                    assert_eq!(field(&value, "console_contacted")?.boolean(), Some(false));
                    assert!(field(&value, "onvif_http_contacted").is_err());
                }
                PublicationSelection::Onvif { .. } => {
                    assert_eq!(
                        field(&value, "onvif_http_contacted")?.boolean(),
                        Some(false)
                    );
                    assert_eq!(
                        field(&value, "onvif_http_origin_verified")?.boolean(),
                        Some(false)
                    );
                    assert_eq!(
                        field(&value, "binding_basis")?.text(),
                        Some("operator-bound-historical-consistency")
                    );
                    for absent in [
                        "onvif_contacted",
                        "http_origin_verified",
                        "bindings_digest",
                        "source_digest",
                        "file_identity",
                        "codec",
                    ] {
                        assert!(field(&value, absent).is_err());
                    }
                    assert!(field(&value, "console_contacted").is_err());
                }
            }
        }
    }
    Ok(())
}

/// Frozen public renderer from the pre-ONVIF UniFi owner (738838c). The field order,
/// nullability, status and exits are copied independently of the new projection helpers.
/// Only input access is adapted to the pure context; this performs no simulated write.
fn legacy_unifi_render(
    context: &PublicationContext<'_>,
    facts: Facts,
    outcome: PublicationOutcome,
) -> Test<(String, ExitIdentity)> {
    let PublicationSelection::Unifi {
        camera_ref,
        view,
        quality,
    } = context.selection
    else {
        return Err("legacy renderer requires UniFi selection".into());
    };
    let receipt_saved = outcome.receipt_saved;
    let error = outcome.error;
    let post_commit = outcome.post_commit_error;
    let finalization = outcome.finalization_error;
    let exit = if receipt_saved && post_commit.is_none() && finalization.is_none() {
        ExitIdentity::SUCCESS
    } else {
        ExitIdentity::RUNTIME_FAILURE
    };
    let optional = |value: Option<&str>| value.map_or_else(|| "null".to_owned(), string);
    let output = object(&[
        ("schema", string("fss.site_unifi_probe_result.v1")),
        (
            "status",
            string(if exit == ExitIdentity::SUCCESS {
                "ok"
            } else {
                "refused"
            }),
        ),
        ("approval", string(&context.approval.to_text())),
        (
            "manifest_digest",
            string(&context.receipt.manifest_digest.to_text()),
        ),
        ("site_id", string(context.site_id)),
        ("source_id", string(context.source_id)),
        ("camera_ref", string(&camera_ref.to_text())),
        ("view", string(view)),
        ("quality", string(quality)),
        (
            "receipt_file",
            string(context.receipt_file.to_str().unwrap_or("")),
        ),
        (
            "receipt_digest",
            if receipt_saved {
                string(&context.receipt_digest.to_text())
            } else {
                "null".to_owned()
            },
        ),
        (
            "receipt_file_digest",
            if receipt_saved {
                string(&context.file_digest.to_text())
            } else {
                "null".to_owned()
            },
        ),
        ("receipt_saved", receipt_saved.to_string()),
        (
            "receipt_file_may_exist",
            outcome.receipt_file_may_exist.to_string(),
        ),
        (
            "connection_attempted",
            facts.connection_attempted.to_string(),
        ),
        (
            "credential_access_attempted",
            facts.credential_access_attempted.to_string(),
        ),
        (
            "teardown_acknowledged",
            facts.teardown_acknowledged.to_string(),
        ),
        (
            "remote_session_may_exist",
            facts.remote_session_may_exist.to_string(),
        ),
        ("source_retained", "false".to_owned()),
        ("console_contacted", "false".to_owned()),
        ("retry_automatically", "false".to_owned()),
        ("error_id", optional(error)),
        ("post_commit_error", optional(post_commit)),
        ("finalization_error", optional(finalization)),
        ("exit_id", string(exit.identifier)),
        ("exit_code", exit.code.to_string()),
    ]);
    Ok((output, exit))
}

#[test]
fn unifi_publication_json_is_byte_identical_to_the_prior_renderer_for_every_outcome() -> Test {
    let receipt = receipt()?;
    for outcome in outcomes() {
        for credentials in [false, true] {
            let context = context(&receipt, unifi())?;
            let expected = legacy_unifi_render(&context, facts(credentials), outcome)?;
            let actual = render_publication(context, facts(credentials), outcome);
            assert_eq!(actual, expected);
        }
    }
    Ok(())
}

/// Frozen ONVIF projection published in 1b38ca9. In particular, the historical binding
/// basis and HTTP-origin/contact fields retain their original spelling and position.
fn published_onvif_render(
    context: &PublicationContext<'_>,
    facts: Facts,
    outcome: PublicationOutcome,
) -> Test<(String, ExitIdentity)> {
    let PublicationSelection::Onvif {
        onboarding_plan,
        profile_digest,
    } = context.selection
    else {
        return Err("published renderer requires ONVIF selection".into());
    };
    let receipt_saved = outcome.receipt_saved;
    let error = outcome.error;
    let post_commit = outcome.post_commit_error;
    let finalization = outcome.finalization_error;
    let exit = if receipt_saved && post_commit.is_none() && finalization.is_none() {
        ExitIdentity::SUCCESS
    } else {
        ExitIdentity::RUNTIME_FAILURE
    };
    let optional = |value: Option<&str>| value.map_or_else(|| "null".to_owned(), string);
    let output = object(&[
        ("schema", string("fss.site_onvif_probe_result.v1")),
        (
            "status",
            string(if exit == ExitIdentity::SUCCESS {
                "ok"
            } else {
                "refused"
            }),
        ),
        ("approval", string(&context.approval.to_text())),
        (
            "manifest_digest",
            string(&context.receipt.manifest_digest.to_text()),
        ),
        ("site_id", string(context.site_id)),
        ("source_id", string(context.source_id)),
        ("onboarding_plan", string(&onboarding_plan.to_text())),
        ("profile_digest", string(&profile_digest.to_text())),
        (
            "binding_basis",
            string("operator-bound-historical-consistency"),
        ),
        ("onvif_http_origin_verified", "false".to_owned()),
        (
            "receipt_file",
            string(context.receipt_file.to_str().unwrap_or("")),
        ),
        (
            "receipt_digest",
            if receipt_saved {
                string(&context.receipt_digest.to_text())
            } else {
                "null".to_owned()
            },
        ),
        (
            "receipt_file_digest",
            if receipt_saved {
                string(&context.file_digest.to_text())
            } else {
                "null".to_owned()
            },
        ),
        ("receipt_saved", receipt_saved.to_string()),
        (
            "receipt_file_may_exist",
            outcome.receipt_file_may_exist.to_string(),
        ),
        (
            "connection_attempted",
            facts.connection_attempted.to_string(),
        ),
        (
            "credential_access_attempted",
            facts.credential_access_attempted.to_string(),
        ),
        (
            "teardown_acknowledged",
            facts.teardown_acknowledged.to_string(),
        ),
        (
            "remote_session_may_exist",
            facts.remote_session_may_exist.to_string(),
        ),
        ("source_retained", "false".to_owned()),
        ("onvif_http_contacted", "false".to_owned()),
        ("retry_automatically", "false".to_owned()),
        ("error_id", optional(error)),
        ("post_commit_error", optional(post_commit)),
        ("finalization_error", optional(finalization)),
        ("exit_id", string(exit.identifier)),
        ("exit_code", exit.code.to_string()),
    ]);
    Ok((output, exit))
}

#[test]
fn onvif_publication_json_is_byte_identical_to_the_published_renderer_for_every_outcome() -> Test {
    let receipt = receipt()?;
    for outcome in outcomes() {
        for credentials in [false, true] {
            let context = context(&receipt, onvif())?;
            let expected = published_onvif_render(&context, facts(credentials), outcome)?;
            let actual = render_publication(context, facts(credentials), outcome);
            assert_eq!(actual, expected);
        }
    }
    Ok(())
}
