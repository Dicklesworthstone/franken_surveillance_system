#![forbid(unsafe_code)]
//! Admission tests for the exact local review and disclosure command surface.

use std::ffi::OsString;

use fss_core::ContentDigest;

use super::options::{Action, parse};

fn publication() -> Vec<OsString> {
    [
        "review",
        "--root",
        "/existing",
        "--site",
        "site:review-cli",
        "--import-identity",
        &ContentDigest::sha256(b"import").to_text(),
        "--expected-import-root",
        &ContentDigest::sha256(b"source-root").to_text(),
        "--sensor",
        "sensor:camera",
        "--movie-start-tick",
        "0",
        "--movie-end-tick",
        "400",
        "--privacy-digest",
        &ContentDigest::sha256(b"privacy").to_text(),
        "--recipient",
        "principal:reviewer",
        "--purpose",
        "incident review",
        "--issued-at-ns",
        "100",
        "--expires-at-ns",
        "200",
        "--max-media-bytes",
        "1048576",
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

fn delivery() -> Vec<OsString> {
    [
        "review-read",
        "--root",
        "/existing",
        "--site",
        "site:review-cli",
        "--review-root",
        &ContentDigest::sha256(b"review").to_text(),
        "--principal",
        "principal:reviewer",
        "--attested-now-ns",
        "110:120",
        "--out",
        "/private/movie.mkv",
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

fn replace(args: &mut [OsString], key: &str, value: &str) -> Result<(), String> {
    let position = args
        .iter()
        .position(|arg| arg == key)
        .ok_or("missing test flag")?;
    args[position + 1] = OsString::from(value);
    Ok(())
}

#[test]
fn publication_requires_all_source_privacy_recipient_time_and_output_pins() -> Result<(), String> {
    for key in [
        "--import-identity",
        "--expected-import-root",
        "--sensor",
        "--movie-start-tick",
        "--movie-end-tick",
        "--privacy-digest",
        "--recipient",
        "--purpose",
        "--issued-at-ns",
        "--expires-at-ns",
        "--max-media-bytes",
    ] {
        let mut args = publication();
        let position = args
            .iter()
            .position(|arg| arg == key)
            .ok_or("missing test flag")?;
        args.drain(position..=position + 1);
        assert!(parse(&args).is_err(), "accepted omitted {key}");
    }
    let options = parse(&publication())?;
    let Action::Publish { request, approval } = options.action else {
        return Err("wrong action".into());
    };
    assert!(approval.is_none());
    assert_eq!(
        request.access.import_identity,
        request.movie.import_identity
    );
    assert_eq!(
        request.access.movie_start_tick,
        request.movie.movie_start_tick
    );
    assert_eq!(request.access.movie_end_tick, request.movie.movie_end_tick);
    assert_eq!(
        request.access.maximum_media_bytes,
        request.movie.limits.max_output_bytes
    );
    Ok(())
}

#[test]
fn disclosure_never_infers_recipient_or_current_time_and_never_accepts_raw_override()
-> Result<(), String> {
    for key in ["--principal", "--attested-now-ns", "--out", "--review-root"] {
        let mut args = delivery();
        let position = args
            .iter()
            .position(|arg| arg == key)
            .ok_or("missing test flag")?;
        args.drain(position..=position + 1);
        assert!(parse(&args).is_err(), "accepted omitted {key}");
    }
    for flag in [
        "--raw",
        "--force",
        "--include-all",
        "--skip-privacy",
        "--skip-expiry",
        "--recipient",
    ] {
        let mut args = delivery();
        args.extend([flag.into(), "yes".into()]);
        assert!(parse(&args).is_err(), "accepted {flag}");
    }
    let options = parse(&delivery())?;
    let Action::Read {
        attested_now,
        approval,
        ..
    } = options.action
    else {
        return Err("wrong action".into());
    };
    assert_eq!((attested_now.earliest.0, attested_now.latest.0), (110, 120));
    assert!(approval.is_none());
    Ok(())
}

#[test]
fn invalid_intervals_and_noncanonical_numbers_are_refused_before_any_io() -> Result<(), String> {
    for (key, value) in [
        ("--movie-start-tick", "400"),
        ("--movie-end-tick", "0"),
        ("--movie-start-tick", "+0"),
        ("--movie-start-tick", "00"),
        ("--movie-end-tick", "18446744073709551616"),
        ("--issued-at-ns", "200"),
        ("--expires-at-ns", "99"),
        ("--expires-at-ns", "+200"),
        ("--max-media-bytes", "0"),
        ("--max-media-bytes", "67108865"),
        ("--purpose", "unsafe\nlabel"),
    ] {
        let mut args = publication();
        replace(&mut args, key, value)?;
        assert!(parse(&args).is_err(), "accepted invalid {key}");
    }
    for value in ["120:110", "110", "110:120:130", "+110:120", "0110:120"] {
        let mut args = delivery();
        replace(&mut args, "--attested-now-ns", value)?;
        assert!(parse(&args).is_err(), "accepted invalid attested interval");
    }
    Ok(())
}

#[test]
fn approval_is_exact_and_actions_do_not_accept_other_operations_flags() -> Result<(), String> {
    let approved = ContentDigest::sha256(b"exact approval");
    let mut args = publication();
    args.extend(["--approve".into(), approved.to_text().into()]);
    let Action::Publish { approval, .. } = parse(&args)?.action else {
        return Err("wrong action".into());
    };
    assert_eq!(approval, Some(approved));
    let mut duplicate = publication();
    duplicate.extend(["--recipient".into(), "principal:other".into()]);
    assert!(parse(&duplicate).is_err());
    let mut missing_value = delivery();
    missing_value.push("--approve".into());
    assert!(parse(&missing_value).is_err());
    for command in ["review-show", "review-revoke"] {
        let mut args: Vec<OsString> = [
            command,
            "--root",
            "/existing",
            "--site",
            "site:review-cli",
            "--review-root",
            &ContentDigest::sha256(b"review").to_text(),
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        assert!(parse(&args).is_ok());
        args.extend(["--out".into(), "/private/movie.mkv".into()]);
        assert!(parse(&args).is_err());
    }
    Ok(())
}
