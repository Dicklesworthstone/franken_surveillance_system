#![forbid(unsafe_code)]

use super::*;
use fss_cli::json_input::{Value, parse};

fn args() -> Vec<OsString> {
    [
        ("--root", "/owner/archive"),
        ("--pins", "/owner/pins"),
        ("--peer", "127.0.0.1:8554"),
        ("--authority", "camera.test:8554"),
        ("--presentation", "/camera/main"),
        ("--control-root", "/camera"),
        ("--sensor-id", "sensor:camera"),
        ("--stream-id", "stream:main"),
        ("--generation", "1"),
        ("--ingress", "1"),
        ("--ssrc", "7"),
        ("--frame-duration-ticks", "3600"),
        ("--stop-after-pictures", "2"),
        ("--owner-authorized", "yes"),
        ("--plaintext", "yes"),
        ("--retain-originals", "yes"),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value.to_owned()))
    .chain(
        ["--anchor", "--receive-clock", "--timing-evidence", "--journal-id"]
            .into_iter()
            .map(|key| (key.to_owned(), ContentDigest::sha256(key.as_bytes()).to_text())),
    )
    .flat_map(|(key, value)| [key.into(), value.into()])
    .collect()
}

fn set(args: &mut Vec<OsString>, key: &str, value: &str) {
    match args.iter().position(|arg| arg == key) {
        Some(at) => args[at + 1] = value.into(),
        None => args.extend([key.into(), value.into()]),
    }
}

fn supervised() -> Vec<OsString> {
    let mut input = args();
    set(&mut input, "--progress-timeout-ms", "5000");
    input
}

#[test]
fn omitted_supervision_preserves_exact_legacy_preview_approval_and_delegation() {
    for codec in ["avc", "hevc"] {
        let mut input = args();
        set(&mut input, "--codec", codec);
        let legacy = Options::parse(&input).expect("native plan");
        let mut current = SinglePlan::parse(&input).expect("single plan");
        assert_eq!(
            current.digest().expect("digest"),
            legacy.digest().expect("digest")
        );
        assert_eq!(
            current.preview().expect("preview"),
            legacy.preview().expect("preview")
        );
        assert!(!current.approved());
        current.approval = Some(legacy.digest().expect("digest"));
        assert_eq!(current.admit(), Ok(None));
        assert_eq!(current.capture.approve, current.approval);
    }
}

#[test]
fn child_approval_cannot_authorize_supervision_or_be_mutated_by_refusal() {
    let mut plan = SinglePlan::parse(&supervised()).expect("plan");
    let native = plan.capture.digest().expect("native digest");
    assert_ne!(plan.digest().expect("outer digest"), native);
    plan.approval = Some(native);
    assert!(plan.admit().is_err());
    assert_eq!(plan.capture.approve, None);
    plan.approval = Some(plan.digest().expect("digest"));
    assert!(plan.admit().expect("admit").is_some());
    assert_eq!(plan.capture.approve, Some(native));
    let mut legacy = args();
    set(&mut legacy, "--approve", &plan.approval.expect("outer").to_text());
    assert!(SinglePlan::parse(&legacy).expect("parse").admit().is_err());
}

#[test]
fn every_changed_native_scope_or_timeout_invalidates_the_outer_approval() {
    let original = SinglePlan::parse(&supervised()).expect("plan");
    let approval = original.digest().expect("approval");
    for (key, value) in [
        ("--progress-timeout-ms", "4999"),
        ("--root", "/owner/other-archive"),
        ("--pins", "/owner/other-pins"),
        ("--peer", "127.0.0.2:8554"),
        ("--generation", "2"),
        ("--ingress", "2"),
        ("--ssrc", "8"),
        ("--codec", "hevc"),
        ("--payload-type", "97"),
        ("--principal", "principal:other"),
        ("--stop-after-pictures", "3"),
        ("--max-steps", "1000"),
    ] {
        let mut input = supervised();
        set(&mut input, key, value);
        set(&mut input, "--approve", &approval.to_text());
        let mut changed = SinglePlan::parse(&input).expect("changed plan");
        assert_ne!(changed.digest().expect("digest"), approval, "{key}");
        assert!(changed.admit().is_err(), "{key}");
    }
}

#[test]
fn supervision_is_one_exact_native_capture_without_destination_rewriting() {
    let plan = SinglePlan::parse(&supervised()).expect("plan");
    let preview = parse(&plan.preview().expect("preview")).expect("JSON");
    let fields = preview.object().expect("object");
    assert_eq!(fields["maximum_attempts"].integer(), Some(1));
    assert_eq!(fields["automatic_reconnect"].boolean(), Some(false));
    assert_eq!(fields["destination_rewriting"].boolean(), Some(false));
    assert_eq!(fields["progress_timeout_ns"].integer(), Some(5_000_000_000));
    let child = fields["capture"].object().expect("child");
    assert_eq!(child["root"].text(), Some("/owner/archive"));
    assert_eq!(child["pins"].text(), Some("/owner/pins"));
    assert_eq!(
        child["bounds"].object().expect("bounds")["generation"].integer(),
        Some(1)
    );
    assert!(matches!(fields["capture"], Value::Object(_)));
}

#[test]
fn invalid_timeout_duplicates_and_unknown_options_are_refused() {
    for value in [
        "", "0", "600001", "-1", "1.0", "+1", "1e3", "18446744073709551616",
    ] {
        let mut input = supervised();
        set(&mut input, "--progress-timeout-ms", value);
        assert!(SinglePlan::parse(&input).is_err(), "{value}");
    }
    let mut duplicate = supervised();
    duplicate.extend(["--progress-timeout-ms".into(), "5000".into()]);
    assert!(SinglePlan::parse(&duplicate).is_err());
    let mut unknown = supervised();
    unknown.extend(["--unknown".into(), "yes".into()]);
    assert!(SinglePlan::parse(&unknown).is_err());
    assert!(SinglePlan::parse(&supervised()[1..]).is_err());
}

#[test]
fn timeout_bounds_and_argument_order_use_one_shared_policy() {
    for (milliseconds, nanoseconds) in [("1", 1_000_000), ("600000", 600_000_000_000)] {
        let mut input = supervised();
        set(&mut input, "--progress-timeout-ms", milliseconds);
        let original = SinglePlan::parse(&input).expect("bounded plan");
        assert_eq!(original.timeout_ns, Some(nanoseconds));
        let approval = original.digest().expect("digest");
        set(&mut input, "--approve", &approval.to_text());
        let reverse: Vec<_> = input
            .chunks_exact(2)
            .rev()
            .flat_map(|pair| pair.iter().cloned())
            .collect();
        let mut changed = SinglePlan::parse(&reverse).expect("reordered");
        assert_eq!(changed.digest().expect("digest"), approval);
        assert_eq!(
            changed.admit(),
            Ok(Some(Supervision::new(nanoseconds, approval).expect("policy")))
        );
    }
}
