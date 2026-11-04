#![forbid(unsafe_code)]

use super::*;

type Test = Result<(), Box<dyn std::error::Error>>;

const EXPORT: &[u8] = br#"{"camera":{"id":"PRIVATE_CAMERA_ID_CANARY","name":"PRIVATE_CAMERA_NAME_CANARY","hasPackageCamera":true},"streams":{"high":"rtsps://192.0.2.7:7441/HIGH_CAPABILITY_CANARY?enableSrtp","medium":null,"package":"rtsps://192.0.2.7:7441/PACKAGE_CAPABILITY_CANARY?enableSrtp"},"rtsp":{"high":"rtsp://192.0.2.7:7447/HIGH_CAPABILITY_CANARY/%4aexact?opaque=%4A","package":"rtsp://192.0.2.7:7447/PACKAGE_CAPABILITY_CANARY/","low":null}}"#;
// A fixed observation for deterministic pure-planning vectors only. The Linux
// contract below also uses the exact production InputLease and a real replacement.
const FIXTURE_FINGERPRINT: [u8; 88] = [0x42; 88];

fn spec(bytes: &[u8]) -> Result<UnifiSourceSpec, std::net::AddrParseError> {
    Ok(UnifiSourceSpec {
        source: PathBuf::from("/private/unifi-export.json"),
        expected: ContentDigest::sha256(bytes),
        quality: ProtectQuality::High,
        transport: TransportChoice::OperatorRtsp,
        peer: "192.0.2.7:7447".parse()?,
    })
}

fn input(bytes: &[u8]) -> ProtectedUnifiInput<'_> {
    ProtectedUnifiInput {
        bytes,
        fingerprint: &FIXTURE_FINGERPRINT,
    }
}

fn args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

fn native_args() -> Vec<OsString> {
    args(&["--peer", "192.0.2.7:7447", "--codec", "hevc"])
}

#[test]
fn exact_private_endpoint_and_original_argument_order_survive_selection() -> Test {
    let spec = spec(EXPORT)?;
    let selection = spec.prepare(input(EXPORT), &native_args())?;
    assert!(selection.matches_route(
        spec.peer,
        "192.0.2.7:7447",
        "/HIGH_CAPABILITY_CANARY/%4aexact?opaque=%4A",
        "/HIGH_CAPABILITY_CANARY/%4aexact",
    ));
    selection.with_capture_arguments(|actual| {
        assert_eq!(
            actual,
            args(&[
                "--peer",
                "192.0.2.7:7447",
                "--codec",
                "hevc",
                "--authority",
                "192.0.2.7:7447",
                "--presentation",
                "/HIGH_CAPABILITY_CANARY/%4aexact?opaque=%4A",
                "--control-root",
                "/HIGH_CAPABILITY_CANARY/%4aexact",
            ])
        );
    });
    assert!(!selection.matches_route(
        spec.peer,
        "192.0.2.7:7447",
        "/HIGH_CAPABILITY_CANARY/%4Aexact?opaque=%4A",
        "/HIGH_CAPABILITY_CANARY/%4aexact",
    ));

    let mut explicit = native_args();
    explicit.extend(args(&["--control-root", "/owner-approved-subtree/"]));
    let selection = spec.prepare(input(EXPORT), &explicit)?;
    selection.with_capture_arguments(|actual| {
        assert_eq!(&actual[..explicit.len()], explicit.as_slice());
        assert_eq!(actual.len(), explicit.len() + 4);
    });
    assert!(selection.matches_route(
        spec.peer,
        "192.0.2.7:7447",
        "/HIGH_CAPABILITY_CANARY/%4aexact?opaque=%4A",
        "/owner-approved-subtree/",
    ));
    Ok(())
}

#[test]
fn package_view_stays_distinct_and_codec_is_always_operator_selected() -> Test {
    let main = spec(EXPORT)?;
    let mut package = main.clone();
    package.quality = ProtectQuality::Package;
    let main_selection = main.prepare(input(EXPORT), &native_args())?;
    let package_selection = package.prepare(input(EXPORT), &native_args())?;
    assert_eq!(main_selection.view(), "main");
    assert_eq!(package_selection.view(), "package");
    assert_eq!(main_selection.camera_ref(), package_selection.camera_ref());
    assert!(package_selection.matches_route(
        package.peer,
        "192.0.2.7:7447",
        "/PACKAGE_CAPABILITY_CANARY/",
        "/PACKAGE_CAPABILITY_CANARY/",
    ));
    let native = ContentDigest::sha256(b"same native approval");
    assert_ne!(
        main.approval(main_selection.file_identity(), "single", "capture", native)?,
        package.approval(
            package_selection.file_identity(),
            "single",
            "capture",
            native
        )?,
    );
    assert_eq!(
        package
            .prepare(input(EXPORT), &args(&["--peer", "192.0.2.7:7447"]))
            .err(),
        Some(ERR_UNIFI_SOURCE),
    );
    Ok(())
}

#[test]
fn missing_disabled_secure_and_unsupported_views_never_fall_back() -> Test {
    for (transport, quality, expected) in [
        (
            TransportChoice::Published,
            ProtectQuality::High,
            ERR_UNIFI_TRANSPORT,
        ),
        (
            TransportChoice::Published,
            ProtectQuality::Medium,
            "ERR-CAPTURE-UNIFI-STREAM-DISABLED-001",
        ),
        (
            TransportChoice::Published,
            ProtectQuality::Low,
            "ERR-CAPTURE-UNIFI-STREAM-MISSING-001",
        ),
        (
            TransportChoice::OperatorRtsp,
            ProtectQuality::Low,
            "ERR-CAPTURE-UNIFI-STREAM-DISABLED-001",
        ),
        (
            TransportChoice::OperatorRtsp,
            ProtectQuality::Medium,
            "ERR-CAPTURE-UNIFI-STREAM-MISSING-001",
        ),
    ] {
        let mut spec = spec(EXPORT)?;
        spec.quality = quality;
        spec.transport = transport;
        assert_eq!(
            spec.prepare(input(EXPORT), &native_args()).err(),
            Some(expected)
        );
    }
    let unsupported = String::from_utf8(EXPORT.to_vec())?
        .replace("\"hasPackageCamera\":true", "\"hasPackageCamera\":false");
    let mut spec = spec(unsupported.as_bytes())?;
    spec.quality = ProtectQuality::Package;
    assert_eq!(
        spec.prepare(input(unsupported.as_bytes()), &native_args())
            .err(),
        Some("ERR-CAPTURE-UNIFI-PACKAGE-001"),
    );
    Ok(())
}

#[test]
fn typed_callers_cannot_inject_approval_routes_or_ambiguous_native_arguments() -> Test {
    let spec = spec(EXPORT)?;
    for key in [
        "--approve",
        "--authority",
        "--presentation",
        "--unifi-source",
        "--unifi-digest",
        "--quality",
        "--stream-transport",
        "--capture-mode",
    ] {
        let mut options = native_args();
        options.extend(args(&[key, "PRIVATE_ARGUMENT_CANARY"]));
        assert_eq!(
            spec.prepare(input(EXPORT), &options).err(),
            Some(ERR_UNIFI_SOURCE)
        );
    }
    for options in [
        args(&["--peer", "192.0.2.7:7447", "--codec"]),
        args(&["--peer", "192.0.2.7:7447", "--codec", ""]),
        args(&["--peer", "192.0.2.7:7447", "--codec", "jpeg"]),
        args(&[
            "--peer",
            "192.0.2.7:7447",
            "--codec",
            "avc",
            "--codec",
            "hevc",
        ]),
        args(&["--codec", "avc"]),
        args(&[
            "--peer",
            "192.0.2.7:7447",
            "--codec",
            "avc",
            "--principal",
            "invalid principal",
        ]),
        args(&[
            "--peer",
            "192.0.2.7:7447",
            "--codec",
            "avc",
            "--output",
            &"x".repeat(4097),
        ]),
        vec![OsString::from("x"); MAX_ARGUMENTS + 2],
    ] {
        assert_eq!(
            spec.prepare(input(EXPORT), &options).err(),
            Some(ERR_UNIFI_SOURCE)
        );
    }
    assert_eq!(
        spec.prepare(
            input(EXPORT),
            &args(&["--peer", "192.0.2.8:7447", "--codec", "hevc"])
        )
        .err(),
        Some(ERR_UNIFI_ROUTE),
    );
    Ok(())
}

#[test]
fn exact_literal_peer_port_and_export_digest_are_required() -> Test {
    for (peer, bytes, expected) in [
        ("192.0.2.8:7447", EXPORT, ERR_UNIFI_ROUTE),
        ("192.0.2.7:554", EXPORT, ERR_UNIFI_ROUTE),
        ("192.0.2.7:7447", b"{}".as_slice(), ERR_UNIFI_SOURCE),
        ("192.0.2.7:7447", b"".as_slice(), ERR_UNIFI_SOURCE),
    ] {
        let mut spec = spec(EXPORT)?;
        spec.peer = peer.parse()?;
        assert_eq!(
            spec.prepare(input(bytes), &args(&["--peer", peer, "--codec", "hevc"]))
                .err(),
            Some(expected),
        );
    }
    let bytes = vec![b' '; MAX_EXPORT_BYTES + 1];
    assert_eq!(
        spec(&bytes)?.prepare(input(&bytes), &native_args()).err(),
        Some(ERR_UNIFI_SOURCE)
    );
    let mut malformed = EXPORT.to_vec();
    malformed.pop();
    malformed.extend_from_slice(b",\"apiKey\":\"PRIVATE_KEY_CANARY\"}");
    assert_eq!(
        spec(&malformed)?
            .prepare(input(&malformed), &native_args())
            .err(),
        Some(ERR_UNIFI_SOURCE),
    );
    // Exact preservation never bypasses the native URI scope gate: an encoded
    // path separator remains inadmissible instead of being decoded or rewritten.
    let encoded_separator = String::from_utf8(EXPORT.to_vec())?.replace("%4a", "%2f");
    assert_eq!(
        spec(encoded_separator.as_bytes())?
            .prepare(input(encoded_separator.as_bytes()), &native_args())
            .err(),
        Some(ERR_UNIFI_SOURCE),
    );
    Ok(())
}

#[test]
fn typed_source_coordinates_do_not_bypass_original_path_and_digest_checks() -> Test {
    for path in [
        "relative.json",
        "/",
        "/private/../export.json",
        "/private/./export.json",
        "/private/export\n.json",
    ] {
        let mut spec = spec(EXPORT)?;
        spec.source = PathBuf::from(path);
        assert_eq!(
            spec.prepare(input(EXPORT), &native_args()).err(),
            Some(ERR_UNIFI_SOURCE)
        );
    }
    for digest in [
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "blake3:1111111111111111111111111111111111111111111111111111111111111111",
    ] {
        let mut spec = spec(EXPORT)?;
        spec.expected = ContentDigest::parse(digest)?;
        assert_eq!(
            spec.prepare(input(EXPORT), &native_args()).err(),
            Some(ERR_UNIFI_SOURCE)
        );
    }
    Ok(())
}

#[test]
fn existing_v1_approval_vectors_preserve_single_and_all_reconnect_operations() -> Test {
    let spec = spec(EXPORT)?;
    let selection = spec.prepare(input(EXPORT), &native_args())?;
    let native = ContentDigest::sha256(b"fixed-native-approval-from-existing-owner");
    // These vectors were independently encoded from the pre-extraction binary's
    // exact field order/policy using SHA-256 and big-endian length prefixes.
    for (mode, operation, expected) in [
        (
            "single",
            "capture",
            "f00780fe51c17e90ab9ba808f13a372f8c41834a5fd7b4dccc1fd733a35cef4a",
        ),
        (
            "reconnect",
            "capture",
            "32ab4997d9a808c65da03e9fabc9bd4fa6d731cd34ae6c6c77e11a232ccbdfdd",
        ),
        (
            "reconnect",
            "recover",
            "46908775d32c3c0c825b02a047febbbc80ae2847c4a209357b89f32805eb33a4",
        ),
        (
            "reconnect",
            "index",
            "da72732a52c175268ba1e1bd94c8b1874e1ba812925949e857dc611cd86ac8d8",
        ),
    ] {
        assert_eq!(
            spec.approval(selection.file_identity(), mode, operation, native)?
                .to_text(),
            format!("sha256:{expected}"),
        );
    }
    for (mode, operation) in [
        ("single", "recover"),
        ("single", "index"),
        ("unknown", "capture"),
        ("reconnect", "resume"),
    ] {
        assert_eq!(
            spec.approval(selection.file_identity(), mode, operation, native),
            Err(ERR_UNIFI_SOURCE)
        );
    }
    Ok(())
}

#[test]
fn existing_v1_report_bytes_and_safe_debug_preserve_capability_redaction() -> Test {
    let spec = spec(EXPORT)?;
    let input = input(EXPORT);
    let selection = spec.prepare(input, &native_args())?;
    let native = ContentDigest::sha256(b"fixed-native-approval-from-existing-owner");
    let report = spec.preview(
        &selection,
        "single",
        "capture",
        native,
        "{\"presentation_uri\":\"[redacted]\",\"control_root_uri\":\"[redacted]\"}",
    )?;
    assert_eq!(
        report,
        concat!(
            "{\"schema\":\"fss.rtsp_from_unifi_plan.v1\",\"phase\":\"planned\",",
            "\"approval\":\"sha256:f00780fe51c17e90ab9ba808f13a372f8c41834a5fd7b4dccc1fd733a35cef4a\",",
            "\"policy\":\"private-unifi-protect-capability-selected-view:exact-owner-peer:explicit-codec-and-cadence:no-url-rewrite:no-quality-fallback:no-tls-downgrade:revalidate-private-source-before-capture:v1\",",
            "\"quality\":\"high\",\"view\":\"main\",",
            "\"camera_ref\":\"sha256:3e7793c1dc8e6cbaa5398611d7ac57e403780a1e13aeecd4f4fc3921e2c0757a\",",
            "\"stream_transport\":\"operator-rtsp\",\"capture_mode\":\"single\",\"operation\":\"capture\",",
            "\"unifi_digest\":\"sha256:34f5e40b79bb15e0aac1933789169d7e25dca8cb990ff74bfb2c667ee47133b7\",",
            "\"unifi_file_identity\":\"sha256:d0f43ddb188f467b633172990a759b9dabf6ba5a244bc374bd2c8c1bae95edba\",",
            "\"native_capture\":{\"presentation_uri\":\"[redacted]\",\"control_root_uri\":\"[redacted]\"},",
            "\"model_specific_assumptions\":false,\"hardware_qualified\":false,\"effects_started\":false}"
        )
    );
    let diagnostics = format!("{spec:?}\n{input:?}\n{selection:?}\n{report}");
    for private in [
        "PRIVATE_CAMERA_ID_CANARY",
        "PRIVATE_CAMERA_NAME_CANARY",
        "HIGH_CAPABILITY_CANARY",
        "PACKAGE_CAPABILITY_CANARY",
        "/private/unifi-export.json",
        "192.0.2.7",
        "opaque=",
    ] {
        assert!(
            !diagnostics.contains(private),
            "private capability escaped metadata report"
        );
    }
    let mut different = spec.clone();
    different.source = PathBuf::from("/private/different.json");
    assert_eq!(
        different.preview(&selection, "single", "capture", native, "{}"),
        Err(ERR_UNIFI_SOURCE)
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../bin/fss-onvif/private_file.rs"]
mod private_file;

#[cfg(target_os = "linux")]
#[test]
fn real_private_lease_identity_replacement_changes_the_exact_outer_approval() -> Test {
    use std::fs::{self, DirBuilder, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let fixture = Fixture(PathBuf::from(format!(
        "/tmp/fss-unifi-pure-identity-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )));
    DirBuilder::new().mode(0o700).create(&fixture.0)?;
    let path = fixture.0.join("export.json");
    let write_private = || -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(EXPORT)
    };
    write_private()?;
    let checkpoint = || Ok(());
    let before = private_file::InputLease::open(&path, &checkpoint)?;
    let before_fingerprint = before.fingerprint();
    let mut spec = spec(EXPORT)?;
    spec.source = path.clone();
    let selection = spec.prepare(
        ProtectedUnifiInput {
            bytes: before.bytes(),
            fingerprint: &before_fingerprint,
        },
        &native_args(),
    )?;
    let native = ContentDigest::sha256(b"native-plan");
    let original = spec.approval(selection.file_identity(), "single", "capture", native)?;
    before.revalidate(&checkpoint)?;

    fs::rename(&path, fixture.0.join("previous-inode.json"))?;
    write_private()?;
    assert!(before.revalidate(&checkpoint).is_err());
    let after = private_file::InputLease::open(&path, &checkpoint)?;
    let after_fingerprint = after.fingerprint();
    assert_eq!(before.bytes(), after.bytes());
    assert_ne!(before_fingerprint, after_fingerprint);
    let replacement = spec.prepare(
        ProtectedUnifiInput {
            bytes: after.bytes(),
            fingerprint: &after_fingerprint,
        },
        &native_args(),
    )?;
    assert_ne!(selection.file_identity(), replacement.file_identity());
    assert_ne!(
        original,
        spec.approval(replacement.file_identity(), "single", "capture", native)?
    );
    after.revalidate(&checkpoint)?;
    Ok(())
}
