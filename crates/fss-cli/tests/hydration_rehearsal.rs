use std::process::{Command, Output};

fn run(scenario: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fss-hydration-rehearsal"))
        .arg(scenario)
        .output()
        .expect("hydration rehearsal process must start")
}

#[test]
fn success_transcript_is_byte_deterministic() {
    let first = run("success");
    let second = run("success");

    assert!(first.status.success());
    assert!(second.status.success());
    assert_eq!(first.stdout, second.stdout);
    assert!(first.stderr.is_empty());
    let transcript = String::from_utf8(first.stdout).expect("transcript must be UTF-8");
    assert_eq!(transcript.lines().count(), 1);
    assert!(transcript.contains("\"schema\":\"fss.hydration_rehearsal.v1\""));
    assert!(transcript.contains("\"scenario\":\"success\""));
    assert!(transcript.contains("\"outcome\":\"ok\""));
    assert!(transcript.contains("\"availability\":\"available\""));
    assert!(transcript.contains("\"requestedLevel\":\"H1\""));
    assert!(transcript.contains("\"deliveredLevel\":\"H1\""));
    assert!(!transcript.contains("\"artifactDigest\":null"));
    assert!(!transcript.contains("\"continuationDigest\":null"));
}

#[test]
fn expiry_transcript_is_byte_deterministic_and_typed() {
    let first = run("expired");
    let second = run("expired");

    assert!(first.status.success());
    assert!(second.status.success());
    assert_eq!(first.stdout, second.stdout);
    assert!(first.stderr.is_empty());
    let transcript = String::from_utf8(first.stdout).expect("transcript must be UTF-8");
    assert_eq!(transcript.lines().count(), 1);
    assert!(transcript.contains("\"scenario\":\"expired\""));
    assert!(transcript.contains("\"outcome\":\"typed_unavailable\""));
    assert!(transcript.contains("\"availability\":\"expired\""));
    assert!(transcript.contains("\"deliveredLevel\":null"));
    assert!(transcript.contains("\"artifactDigest\":null"));
    assert!(transcript.contains("\"continuationDigest\":null"));
}

#[test]
fn all_preserves_canonical_scenario_order() {
    let output = run("all");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let transcript = String::from_utf8(output.stdout).expect("transcript must be UTF-8");
    let lines: Vec<_> = transcript.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("\"scenario\":\"success\""));
    assert!(lines[1].contains("\"scenario\":\"expired\""));
}

#[test]
fn unknown_scenario_fails_closed() {
    let output = run("not-a-scenario");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).expect("error must be UTF-8");
    assert!(error.contains("unknown scenario"));
    assert!(error.contains("success, expired, or all"));
}
