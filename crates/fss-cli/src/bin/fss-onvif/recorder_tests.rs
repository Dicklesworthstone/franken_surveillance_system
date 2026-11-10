#![forbid(unsafe_code)]

use super::*;
use std::ffi::OsString;

fn args(command: &str) -> Vec<OsString> {
    let mut result: Vec<OsString> = [
        command, "--peer", "127.0.0.1:8080", "--authority", "127.0.0.1:8080",
        "--device-path", "/onvif/device_service", "--service-root", "/onvif",
        "--output", "/tmp/never-opened-onvif-recording.json", "--owner-authorized", "yes",
        "--plaintext", "yes",
    ].into_iter().map(Into::into).collect();
    if command == "replay" {
        result.extend([
            "--recording-token", "PRIVATE_RECORDING_TOKEN_CANARY", "--codec", "avc",
            "--replay-start", "20261101T120000Z", "--replay-end", "20261101T120100Z",
            "--rtsp-peer", "127.0.0.1:554", "--rtsp-authority", "127.0.0.1:554",
        ].into_iter().map(OsString::from));
    }
    result
}

fn replace(args: &mut [OsString], key: &str, value: &str) {
    let index = args.iter().position(|arg| arg == key).expect("fixture option");
    args[index + 1] = value.into();
}

#[test]
fn recording_plans_are_distinct_redacted_and_keep_all_effects_unapproved() {
    let inventory = Plan::parse(&args("recordings")).unwrap();
    let replay = Plan::parse(&args("replay")).unwrap();
    let mut live = args("recordings");
    live.remove(0);
    let live = Plan::parse(&live).unwrap();
    assert_ne!(inventory.digest().unwrap(), live.digest().unwrap());
    assert_ne!(inventory.digest().unwrap(), replay.digest().unwrap());
    for plan in [inventory, replay] {
        let text = plan.preview().unwrap();
        assert!(!text.contains("PRIVATE_RECORDING_TOKEN_CANARY"));
        assert!(text.contains("\"schema\":\"fss.onvif_recording_operator_plan.v1\""));
        assert!(text.contains("\"device_contacted\":false"));
        assert!(text.contains("\"credentials_read\":false"));
        assert!(text.contains("\"capture_authorized\":false"));
        assert!(plan.approval.is_none());
    }
}

#[test]
fn exact_recording_window_codec_route_and_authentication_are_approval_bound() {
    let baseline = args("replay");
    let expected = Plan::parse(&baseline).unwrap().digest().unwrap();
    for (key, value) in [
        ("--recording-token", "different-recording"), ("--codec", "hevc"),
        ("--replay-start", "20261101T120001Z"), ("--replay-end", "20261101T120101Z"),
        ("--output", "/tmp/another-private-handoff.json"),
        ("--device-path", "/onvif/another_device_service"),
    ] {
        let mut changed = baseline.clone();
        replace(&mut changed, key, value);
        assert_ne!(Plan::parse(&changed).unwrap().digest().unwrap(), expected, "{key}");
    }
    let mut equivalent = baseline.clone();
    replace(&mut equivalent, "--replay-start", "20261101T120000.000Z");
    assert_eq!(Plan::parse(&equivalent).unwrap().digest().unwrap(), expected);
    for extra in [
        vec!["--principal", "principal:another"],
        vec!["--max-response-bytes", "65536"],
        vec!["--credential-file", "/private/missing", "--auth-realm", "owner-realm"],
        vec!["--auth-mode", "username-token", "--credential-file", "/private/missing"],
    ] {
        let mut changed = baseline.clone();
        changed.extend(extra.into_iter().map(OsString::from));
        assert_ne!(Plan::parse(&changed).unwrap().digest().unwrap(), expected);
    }
}

#[test]
fn recording_commands_reject_implicit_selection_and_legacy_modes_before_io() {
    for (key, value) in [
        ("--profile", "live-profile"), ("--media-version", "media2"),
        ("--recording-token", "duplicate"), ("--codec", "hevc"),
    ] {
        let mut invalid = args("replay");
        invalid.extend([key.into(), value.into()]);
        assert!(Plan::parse(&invalid).is_err());
    }
    for (key, value) in [
        ("--recording-token", "recording"), ("--codec", "avc"),
        ("--replay-start", "20261101T120000Z"), ("--rtsp-peer", "127.0.0.1:554"),
    ] {
        let mut invalid = args("recordings");
        invalid.extend([key.into(), value.into()]);
        assert!(Plan::parse(&invalid).is_err());
        let mut legacy = args("recordings");
        legacy.remove(0);
        legacy.extend([key.into(), value.into()]);
        assert!(Plan::parse(&legacy).is_err());
    }
    for key in ["--recording-token", "--codec", "--replay-start", "--replay-end", "--rtsp-peer", "--rtsp-authority"] {
        let mut invalid = args("replay");
        let index = invalid.iter().position(|arg| arg == key).unwrap();
        invalid.drain(index..index + 2);
        assert!(Plan::parse(&invalid).is_err(), "missing {key}");
    }
    for (key, value) in [
        ("--codec", "auto"), ("--replay-end", "20261101T110000Z"),
        ("--replay-end", "20261110T120000Z"), ("--recording-token", "bad\ntoken"),
    ] {
        let mut invalid = args("replay");
        replace(&mut invalid, key, value);
        assert!(Plan::parse(&invalid).is_err(), "{key}");
    }
}

#[test]
fn recorder_username_token_owner_signs_only_the_selected_read_operations() {
    for command in ["recordings", "replay"] {
        let mut arguments = args(command);
        arguments.extend([
            "--auth-mode".into(), "username-token".into(),
            "--credential-file".into(), "/private/unopened-credentials".into(),
        ]);
        let plan = Plan::parse(&arguments).unwrap();
        assert_eq!(plan.max_http_exchanges(), if command == "replay" { 4 } else { 3 });
        let approval = plan.digest().unwrap();
        let config = plan.config(approval).unwrap();
        let route = HttpRoute::new(plan.peer, &plan.authority, "/onvif/recording_service", plan.generation, approval).unwrap();
        let request = plan.recording.as_ref().unwrap();
        assert!(request.username_request_matches(&plan.device_path, &config.device, &wire::get_services_request()));
        assert!(!request.username_request_matches(&plan.device_path, &route, &wire::get_services_request()));
        for body in [
            wire::get_capabilities_request(), wire::get_profiles_request(),
            wire::get_stream_uri_request("live-profile").unwrap(),
            wire::recording::get_recording_information_request("wrong-recording").unwrap(),
            wire::recording::get_replay_uri_request("wrong-recording").unwrap(),
        ] {
            assert!(!request.username_request_matches(&plan.device_path, &route, &body));
        }
        match request {
            RecorderRequest::Inventory => {
                assert!(request.username_request_matches(&plan.device_path, &route, &wire::recording::get_recordings_request()));
            }
            RecorderRequest::Replay { token, .. } => {
                assert!(!request.username_request_matches(&plan.device_path, &route, &wire::recording::get_recordings_request()));
                for body in [
                    wire::recording::get_recording_information_request(token).unwrap(),
                    wire::recording::get_replay_uri_request(token).unwrap(),
                ] {
                    assert!(request.username_request_matches(&plan.device_path, &route, &body));
                }
            }
        }
    }
}
