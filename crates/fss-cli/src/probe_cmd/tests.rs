#![forbid(unsafe_code)]

use super::*;

const ROOT: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn parse(transition: &str, extra: &[&str]) -> Result<ProbeArgs, CliError> {
    let mut values = vec![
        "investigate",
        "--json",
        "--root",
        "/existing/deployment",
        "--session",
        "session:probe",
        "--principal",
        "principal:owner",
        "--subscription",
        "probe:retained",
        "--authority-root",
        ROOT,
        "--transition",
        transition,
    ];
    values.extend_from_slice(extra);
    let tokens: Vec<_> = values
        .iter()
        .enumerate()
        .map(|(index, value)| ArgToken::new(index, (*value).to_owned()))
        .collect();
    let command = crate::parse_fss_tokens(&tokens)?;
    let crate::FssCommand::Probe(args) = command else {
        panic!("probe routed to another grammar");
    };
    Ok(*args)
}

#[test]
fn exact_probe_action_and_receipt_change_request_identity() -> Result<(), Box<dyn std::error::Error>>
{
    let poll = parse("probe", &[])?;
    assert_eq!(poll.request.action, SupervisionAction::Poll);
    assert_eq!(poll.request.view, AgentView::Case);
    let forensic = parse("probe", &["--view", "forensic"])?;
    assert_eq!(forensic.request.view, AgentView::Forensic);
    assert_ne!(forensic.request.digest(), poll.request.digest());
    let inspect = parse("probe-inspect", &[])?;
    let ack = parse("probe-ack", &["--receipt", ROOT])?;
    let discard = parse("probe-discard", &["--receipt", ROOT])?;
    let advance = parse(
        "probe-advance",
        &["--window-index", "1", "--after-receipt", ROOT],
    )?;
    assert_eq!(
        advance.request.action,
        SupervisionAction::Advance {
            target_count: 2,
            after_receipt: ContentDigest::parse(ROOT)?
        }
    );
    let identities = [poll, inspect, ack, discard, advance].map(|a| a.request.digest());
    assert_eq!(
        identities
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        5
    );
    Ok(())
}

#[test]
fn probe_cannot_register_replace_refill_or_mix_native_actions() {
    for (transition, extra) in [
        ("probe", vec!["--receipt", ROOT]),
        ("probe", vec!["--max-poll-attempts", "64"]),
        ("probe", vec!["--discover-plan", "/private/recipe"]),
        ("probe", vec!["--site", "another-site"]),
        ("probe", vec!["--budget-tokens", "1000000"]),
        ("probe", vec!["--view", "epistemic_map"]),
        ("probe", vec!["--view", "brief"]),
        ("probe-ack", vec![]),
        ("probe-configure", vec![]),
        (
            "probe-advance",
            vec!["--window-index", "0", "--after-receipt", ROOT],
        ),
        (
            "probe-advance",
            vec!["--window-index", "01", "--after-receipt", ROOT],
        ),
        (
            "probe-advance",
            vec!["--window-index", "32", "--after-receipt", ROOT],
        ),
        (
            "probe-advance",
            vec![
                "--window-index",
                "1",
                "--after-receipt",
                ROOT,
                "--receipt",
                ROOT,
            ],
        ),
    ] {
        assert!(
            parse(transition, &extra).is_err(),
            "accepted {transition}: {extra:?}"
        );
    }
}
