#![forbid(unsafe_code)]

use super::*;

fn args() -> Vec<OsString> {
    [
        "--root",
        "/owner/private/archive",
        "--pins",
        "/owner/private/pins",
        "--peer",
        "127.0.0.1:8554",
        "--authority",
        "camera.test:8554",
        "--presentation",
        "/camera/main",
        "--control-root",
        "/camera",
        "--sensor-id",
        "sensor:camera",
        "--stream-id",
        "stream:main",
        "--generation",
        "1",
        "--ingress",
        "1",
        "--ssrc",
        "7",
        "--anchor",
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "--receive-clock",
        "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "--timing-evidence",
        "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        "--journal-id",
        "sha256:4444444444444444444444444444444444444444444444444444444444444444",
        "--frame-duration-ticks",
        "3600",
        "--stop-after-pictures",
        "2",
        "--owner-authorized",
        "yes",
        "--plaintext",
        "yes",
        "--retain-originals",
        "yes",
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

fn set(args: &mut Vec<OsString>, key: &str, value: &str) {
    if let Some(index) = args.iter().position(|arg| arg == key) {
        args[index + 1] = OsString::from(value);
    } else {
        args.push(OsString::from(key));
        args.push(OsString::from(value));
    }
}

#[test]
fn exact_approval_excludes_only_approval_itself_and_argument_order() {
    let mut input = args();
    let options = Options::parse(&input).expect("valid plan");
    let approval = options.digest().expect("approval");
    set(&mut input, "--approve", &approval.to_text());
    let approved = Options::parse(&input).expect("approved plan");
    assert_eq!(approved.approve, Some(approval));
    assert_eq!(approved.digest().expect("same plan"), approval);
    let reversed: Vec<_> = input
        .chunks_exact(2)
        .rev()
        .flat_map(|pair| pair.iter().cloned())
        .collect();
    assert_eq!(
        Options::parse(&reversed)
            .expect("reordered")
            .digest()
            .expect("digest"),
        approval
    );
    assert!(
        options
            .preview()
            .expect("preview")
            .contains("\"effects\":\"none-until-exact-approval\"")
    );
}

#[test]
fn all_operator_effect_inputs_change_approval() {
    let baseline = Options::parse(&args())
        .expect("plan")
        .digest()
        .expect("digest");
    for (key, value) in [
        ("--root", "/owner/private/another-archive"),
        ("--pins", "/owner/private/another-journal"),
        ("--peer", "127.0.0.2:8554"),
        ("--authority", "other.test:8554"),
        ("--presentation", "/camera/sub"),
        ("--control-root", "/"),
        ("--sensor-id", "sensor:other"),
        ("--stream-id", "stream:other"),
        ("--generation", "2"),
        ("--ingress", "2"),
        ("--ssrc", "8"),
        (
            "--anchor",
            "sha256:5555555555555555555555555555555555555555555555555555555555555555",
        ),
        (
            "--receive-clock",
            "sha256:5555555555555555555555555555555555555555555555555555555555555555",
        ),
        (
            "--timing-evidence",
            "sha256:5555555555555555555555555555555555555555555555555555555555555555",
        ),
        (
            "--journal-id",
            "sha256:5555555555555555555555555555555555555555555555555555555555555555",
        ),
        ("--frame-duration-ticks", "3000"),
        ("--stop-after-pictures", "3"),
        ("--principal", "principal:other"),
        ("--payload-type", "97"),
        ("--media-index", "1"),
        ("--rtp-channel", "2"),
        ("--timeout-ms", "20000"),
        ("--drain-timeout-ms", "5000"),
        ("--connect-timeout-ms", "1000"),
        ("--response-timeout-ms", "1000"),
        ("--max-steps", "10000"),
        ("--max-report-bytes", "131072"),
        ("--max-source-bytes", "8388608"),
        ("--max-io-calls", "10000"),
        ("--read-bytes", "1024"),
        ("--max-window-pictures", "64"),
        ("--max-windows", "16"),
        ("--max-storage-bytes", "268435456"),
        ("--max-storage-pause-ms", "1000"),
    ] {
        let mut input = args();
        set(&mut input, key, value);
        let changed = Options::parse(&input).unwrap_or_else(|reason| panic!("{key}: {reason}"));
        assert_ne!(changed.digest().expect("digest"), baseline, "{key}");
    }
}

#[test]
fn native_default_changes_cannot_reuse_an_approval() {
    let original = Options::parse(&args())
        .expect("plan")
        .digest()
        .expect("digest");
    let mut changed = Options::parse(&args()).expect("plan");
    changed.media.syntax.max_reference_frames -= 1;
    assert_ne!(changed.digest().expect("digest"), original);
    let mut changed = Options::parse(&args()).expect("plan");
    changed.recording.limits.max_age_ns -= 1;
    assert_ne!(changed.digest().expect("digest"), original);
    let mut changed = Options::parse(&args()).expect("plan");
    changed.pin_limits.max_records -= 1;
    assert_ne!(changed.digest().expect("digest"), original);
    let mut changed = Options::parse(&args()).expect("plan");
    changed.work.max_graph_objects -= 1;
    assert_ne!(changed.digest().expect("digest"), original);
    let mut changed = Options::parse(&args()).expect("plan");
    changed.publication.spool.max_objects -= 1;
    assert_ne!(changed.digest().expect("digest"), original);
}

#[test]
fn malformed_or_credential_bearing_routes_fail_before_effects() {
    for (key, value) in [
        ("--peer", "camera.test:8554"),
        ("--peer", "0.0.0.0:8554"),
        ("--peer", "239.1.2.3:8554"),
        ("--peer", "127.0.0.1:0"),
        ("--authority", "user:password@camera.test"),
        ("--authority", "camera.test:0"),
        ("--authority", "camera.test:70000"),
        ("--authority", "camera.test:8554:8555"),
        ("--authority", "-bad.test"),
        ("--authority", "camera..test"),
        ("--authority", "[not-ipv6]:8554"),
        ("--presentation", "/outside"),
        ("--presentation", "/camera?token=secret"),
        ("--presentation", "/camera/../elsewhere"),
        ("--presentation", "/camera/%2e%2e/elsewhere"),
        ("--presentation", "/camera//main"),
        ("--presentation", "/camera/main\r\nAuthorization: secret"),
        ("--control-root", "/camera?token=secret"),
    ] {
        let mut input = args();
        set(&mut input, key, value);
        assert!(Options::parse(&input).is_err(), "{key}");
    }
}

#[test]
fn archive_and_journal_paths_cannot_alias_or_nest_lexically() {
    for (key, value) in [
        ("--root", "."),
        ("--root", "/"),
        ("--root", "relative"),
        ("--root", "/owner/./archive"),
        ("--root", "/owner/private/../archive"),
        ("--root", "/owner/private/pins"),
        ("--root", "/owner/private/pins/archive"),
        ("--pins", "/owner/private/archive/journal"),
        ("--pins", "/owner/private/archive"),
        ("--pins", "/owner/private/archive/"),
        ("--pins", "/owner/private/\nsecret"),
    ] {
        let mut input = args();
        set(&mut input, key, value);
        assert!(Options::parse(&input).is_err(), "{key}");
    }
}

#[test]
fn acknowledgements_unknown_options_and_duplicates_fail_closed() {
    for (key, value) in [
        ("--owner-authorized", "no"),
        ("--plaintext", "no"),
        ("--retain-originals", "no"),
        ("--credentials", "secret"),
        ("--generation", "0"),
        ("--ingress", "0"),
        ("--ssrc", "4294967296"),
        (
            "--journal-id",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            "--timing-evidence",
            "blake3:1111111111111111111111111111111111111111111111111111111111111111",
        ),
        ("--stop-after-pictures", "-1"),
        ("--frame-duration-ticks", "+3600"),
    ] {
        let mut input = args();
        set(&mut input, key, value);
        assert!(Options::parse(&input).is_err(), "{key}");
    }
    let mut input = args();
    input.extend([OsString::from("--generation"), OsString::from("1")]);
    assert!(Options::parse(&input).is_err());
    input.pop();
    assert!(Options::parse(&input).is_err());
    assert!(Options::parse(&vec![OsString::from("x"); MAX_ARGUMENTS + 2]).is_err());
}

#[test]
fn runtime_and_storage_reservations_have_finite_hard_bounds() {
    for (key, value) in [
        ("--frame-duration-ticks", "0"),
        ("--frame-duration-ticks", "90001"),
        ("--stop-after-pictures", "0"),
        ("--stop-after-pictures", "4097"),
        ("--max-window-pictures", "257"),
        ("--max-windows", "129"),
        ("--read-bytes", "4097"),
        ("--max-source-bytes", "268435457"),
        ("--max-steps", "1000001"),
        ("--timeout-ms", "600001"),
        ("--drain-timeout-ms", "60001"),
        ("--max-storage-pause-ms", "60001"),
        ("--max-storage-bytes", "1073741825"),
        ("--max-report-bytes", "131071"),
        ("--rtp-channel", "255"),
    ] {
        let mut input = args();
        set(&mut input, key, value);
        assert!(Options::parse(&input).is_err(), "{key}");
    }
}

#[test]
fn timing_identity_binds_source_epoch_and_declared_cadence() {
    let first = Options::parse(&args()).expect("plan");
    for (key, value) in [
        ("--generation", "2"),
        ("--ingress", "2"),
        ("--ssrc", "8"),
        ("--frame-duration-ticks", "3000"),
        (
            "--receive-clock",
            "sha256:5555555555555555555555555555555555555555555555555555555555555555",
        ),
        (
            "--timing-evidence",
            "sha256:5555555555555555555555555555555555555555555555555555555555555555",
        ),
    ] {
        let mut input = args();
        set(&mut input, key, value);
        let next = Options::parse(&input).expect("other timing");
        assert_ne!(
            first.archive.namespace.digest(),
            next.archive.namespace.digest(),
            "{key}"
        );
        assert_ne!(
            first.archive.namespace.scope().decode_clock,
            next.archive.namespace.scope().decode_clock,
            "{key}",
        );
    }
}

#[test]
fn explicit_ipv6_authority_and_peer_are_supported_without_dns() {
    let mut input = args();
    set(&mut input, "--peer", "[::1]:8554");
    set(&mut input, "--authority", "[::1]:8554");
    let plan = Options::parse(&input).expect("IPv6 loopback");
    assert_eq!(
        plan.binding.peer(),
        "[::1]:8554".parse::<SocketAddr>().expect("address")
    );
    assert_eq!(plan.binding.authority(), "[::1]:8554");
}

#[test]
fn full_width_ingress_is_preserved_in_binding_and_json_string() {
    for ingress in [u128::from(u64::MAX) + 1, (1_u128 << 127) | 7, u128::MAX] {
        let decimal = ingress.to_string();
        let mut input = args();
        set(&mut input, "--ingress", &decimal);
        let plan = Options::parse(&input).expect("full native ingress width");
        assert_eq!(plan.binding.key().ingress, ingress);
        let preview = plan.preview().expect("exact preview");
        assert!(preview.contains(&format!("\"ingress\":\"{decimal}\"")));
        assert_eq!(preview.matches("\"ingress\":").count(), 1);
    }
}

#[test]
fn ingress_high_half_changes_approval_and_decode_clock() {
    let baseline = Options::parse(&args()).expect("baseline");
    let approval = baseline.digest().expect("baseline approval");
    let clock = baseline.archive.namespace.scope().decode_clock;
    let mut previous_approval = approval;
    let mut previous_clock = clock;
    for ingress in [(1_u128 << 64) | 1, (1_u128 << 127) | 1] {
        let mut input = args();
        set(&mut input, "--ingress", &ingress.to_string());
        set(&mut input, "--approve", &approval.to_text());
        let plan = Options::parse(&input).expect("distinct high half");
        let changed_approval = plan.digest().expect("full width approval");
        let changed_clock = plan.archive.namespace.scope().decode_clock;
        assert_ne!(Some(changed_approval), plan.approve);
        assert_ne!(changed_approval, previous_approval);
        assert_ne!(changed_clock, clock);
        assert_ne!(changed_clock, previous_clock);
        assert_ne!(
            plan.archive.namespace.digest(),
            baseline.archive.namespace.digest()
        );
        previous_approval = changed_approval;
        previous_clock = changed_clock;
    }
}

#[test]
fn ingress_refuses_overflow_zero_signs_and_nondecimal_input() {
    for value in [
        "340282366920938463463374607431768211456",
        "0",
        "-1",
        "+1",
        " 1",
        "1 ",
        "1_0",
        "0x01",
        "١",
    ] {
        let mut input = args();
        set(&mut input, "--ingress", value);
        assert!(Options::parse(&input).is_err(), "{value}");
    }
}
