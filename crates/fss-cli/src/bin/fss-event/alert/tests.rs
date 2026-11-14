#![forbid(unsafe_code)]
use super::*;

type Test = Result<(), Box<dyn std::error::Error>>;
const APPROVAL: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
fn arguments(extra: &[&str]) -> Vec<OsString> {
    [
        "--root",
        "/unused",
        "--site",
        "site:test",
        "--event-id",
        "event:one",
        "--relay",
        "127.0.0.1:8080",
        "--path",
        "/alerts",
        "--plaintext-approval",
        APPROVAL,
        "--deadline-ms",
        "5000",
    ]
    .into_iter()
    .chain(extra.iter().copied())
    .map(OsString::from)
    .collect()
}

#[test]
fn disclosure_selection_requires_both_rich_profile_and_separate_valid_approval() -> Test {
    let default = parse(&arguments(&[]))?;
    assert_eq!(
        default.disclosure_profile,
        WebhookDisclosureProfile::ReferencesV1
    );
    assert!(default.metadata_approval.is_none());
    let explicit = parse(&arguments(&["--disclosure-profile", "references-v1"]))?;
    assert_eq!(explicit.disclosure_profile, default.disclosure_profile);
    let rich = parse(&arguments(&[
        "--disclosure-profile",
        "event-metadata-v1",
        "--metadata-approval",
        APPROVAL,
    ]))?;
    assert_eq!(
        rich.disclosure_profile,
        WebhookDisclosureProfile::EventMetadataV1
    );
    assert_eq!(
        rich.metadata_approval
            .map(|digest| digest.to_text())
            .as_deref(),
        Some(APPROVAL)
    );
    for extra in [
        vec!["--disclosure-profile", "event-metadata-v1"],
        vec!["--metadata-approval", APPROVAL],
        vec![
            "--disclosure-profile",
            "references-v1",
            "--metadata-approval",
            APPROVAL,
        ],
        vec![
            "--disclosure-profile",
            "event-metadata-v2",
            "--metadata-approval",
            APPROVAL,
        ],
        vec![
            "--disclosure-profile",
            "event-metadata-v1",
            "--metadata-approval",
            APPROVAL,
            "--metadata-approval",
            APPROVAL,
        ],
    ] {
        assert!(parse(&arguments(&extra)).is_err());
    }
    for invalid in [
        format!("sha256:{}", "0".repeat(64)),
        format!("blake3:{}", "1".repeat(64)),
    ] {
        assert!(
            parse(&arguments(&[
                "--disclosure-profile",
                "event-metadata-v1",
                "--metadata-approval",
                &invalid
            ]))
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn metadata_preview_and_next_command_keep_the_explicit_disclosure_selection() -> Test {
    let action = parse(&arguments(&[
        "--disclosure-profile",
        "event-metadata-v1",
        "--metadata-approval",
        APPROVAL,
    ]))?;
    let endpoint = WebhookEndpoint::new_with_profile(
        action.relay,
        &action.path,
        action.plaintext_approval,
        action.disclosure_profile,
        action.metadata_approval,
    )?;
    let ids = alert_identities(ContentDigest::sha256(b"revision"), endpoint.digest())?;
    let preview = WebhookRequestPreview {
        profile: action.disclosure_profile,
        request_digest: ContentDigest::sha256(b"complete bounded HTTP request"),
        request_bytes: 2048,
    };
    let approval = ContentDigest::sha256(b"plan approval");
    let report = Report {
        stage: "plan_preview",
        action: &action,
        endpoint: &endpoint,
        ids: &ids,
        event_state: "corroborated",
        preview: Some(preview),
        policy_action: ReferencePolicyAction::PrepareAlert,
        plan: Some(approval),
        dispatch: None,
        operation: None,
        obligation: None,
        evidence: None,
        retained_evidence: None,
        runtime: None,
        next: None,
    };
    let command = report.command(approval, None);
    assert!(command.contains(" --disclosure-profile event-metadata-v1 --metadata-approval "));
    assert!(command.contains(APPROVAL));
    assert!(!command.contains(" --dispatch "));
    let json = fss_core::json_input::parse(&report.json())?;
    let fields = json.object().ok_or("report object")?;
    assert_eq!(
        fields
            .get("disclosure_profile")
            .and_then(|value| value.text()),
        Some("event-metadata-v1")
    );
    assert_eq!(
        fields
            .get("metadata_approval")
            .and_then(|value| value.text()),
        Some(APPROVAL)
    );
    assert_eq!(
        fields
            .get("request_preview_sha256")
            .and_then(|value| value.text()),
        Some(preview.request_digest.to_text().as_str())
    );
    assert_eq!(
        fields
            .get("request_preview_bytes")
            .and_then(|value| value.integer()),
        Some(2048)
    );
    assert_eq!(
        fields.get("delivery_claim").and_then(|value| value.text()),
        Some("not_dispatched")
    );
    Ok(())
}
