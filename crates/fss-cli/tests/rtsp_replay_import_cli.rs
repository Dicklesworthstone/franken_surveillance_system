#![forbid(unsafe_code)]
//! Whole recorder replay custody through real binaries, including source-free cold decoding.
//! Synthetic AVC/HEVC fixtures establish custody behavior, not camera interoperability.

#[path = "../../fss-reference/tests/hevc_recording_support/mod.rs"]
mod hevc_recording_support;
#[path = "../../fss-reference/tests/recording_support/mod.rs"]
mod recording_support;
#[path = "rtsp_replay_import_cli/retained_time.rs"]
mod retained_time;
#[path = "rtsp_replay_import_cli/support.rs"]
mod support;

use std::ffi::OsString;
use std::fs;
use std::process::Command;

use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;
use fss_reference::ingest::rtsp_import::RtspImportCodec;

use support::{Fixture, SITE, Test, approve, field, good, run, serial, set};

#[test]
fn approved_avc_and_hevc_replays_reconcile_and_decode_with_the_source_offline() -> Test {
    let _serial = serial();
    for codec in [RtspImportCodec::Avc, RtspImportCodec::Hevc] {
        let fixture = Fixture::new(codec, 2, 0)?;
        let mut args = fixture.args()?;
        let preview = good(run(&args)?)?;
        assert!(!fixture.target().exists());
        assert!(preview.contains("\"writes\":\"none\""));
        assert!(preview.contains("\"selection\":\"complete_replay_receipt\""));
        assert!(preview.contains("\"historical_utc_calibrated\":false"));
        let approved = field(&parse(&preview)?, "approval_digest")?.to_owned();

        let mut wrong = args.clone();
        set(
            &mut wrong,
            "--approve",
            &ContentDigest::sha256(b"wrong plan").to_text(),
        );
        let refused = run(&wrong)?;
        assert!(!refused.status.success());
        assert!(refused.stdout.is_empty());
        assert!(String::from_utf8_lossy(&refused.stderr).contains("ERR-RTSP-IMPORT-APPROVAL-001"));
        assert!(!fixture.target().exists());

        set(&mut args, "--approve", &approved);
        let imported = good(run(&args)?)?;
        for expected in [
            "\"kind\":\"imported\"",
            "\"windows\":2",
            "\"capture_time_label\":\"unknown\"",
            "\"replay_termination\":\"budget\"",
            "\"replay_publication_complete\":false",
            "\"destination_contains_complete_replay\":true",
            "\"continuity_certified\":false",
            "\"absence_certifiable\":false",
            "\"historical_utc_calibrated\":false",
            "\"upstream_interval_completeness\":\"unknown\"",
            "\"reused\":false",
        ] {
            assert!(imported.contains(expected), "{expected}: {imported}");
        }
        assert!(imported.contains(&format!("\"frames\":{}", fixture.frames)));
        let imported = parse(&imported)?;
        assert_eq!(
            field(&imported, "replay_root")?,
            fixture.receipt.root().to_text()
        );
        assert_eq!(
            field(&imported, "replay_request")?,
            fixture.receipt.request().digest().to_text()
        );
        assert_eq!(
            field(&imported, "replay_approval")?,
            fixture.receipt.approval().to_text()
        );
        assert_eq!(
            field(&imported, "requested_window")?,
            fixture.receipt.request().window().to_string()
        );
        assert_eq!(
            field(&imported, "acknowledged_window")?,
            fixture.receipt.acceptance().acknowledged().to_string()
        );
        let onvif = fixture.receipt.request().onvif_source();
        assert_eq!(onvif.is_some(), codec == RtspImportCodec::Hevc);
        if let Some(source) = onvif {
            assert_eq!(
                field(&imported, "onvif_source")?,
                source.digest()?.to_text()
            );
        } else {
            assert_eq!(
                imported
                    .object()
                    .and_then(|report| report.get("onvif_source")),
                Some(&Value::Null)
            );
        }
        let identity = field(&imported, "import_identity")?.to_owned();
        let proof = field(&imported, "origin_proof")?.to_owned();
        ContentDigest::parse(&proof)?;
        let committed = fixture.journals()?;
        let retried = good(run(&args)?)?;
        assert!(retried.contains("\"reused\":true"));
        let retried = parse(&retried)?;
        assert_eq!(field(&retried, "import_identity")?, identity);
        assert_eq!(field(&retried, "origin_proof")?, proof);
        assert_eq!(
            fixture.journals()?,
            committed,
            "exact retry appended custody/effects"
        );

        fs::rename(
            fixture.archive(),
            fixture.directory.0.join("archive offline"),
        )?;
        let common: Vec<OsString> = vec![
            "--root".into(),
            fixture.target().into_os_string(),
            "--site".into(),
            SITE.into(),
            "--import-id".into(),
            identity.into(),
        ];
        for command in ["inspect", "verify"] {
            let report = good(
                Command::new(env!("CARGO_BIN_EXE_fss-file"))
                    .arg(command)
                    .args(&common)
                    .output()?,
            )?;
            assert!(report.contains(if codec == RtspImportCodec::Avc {
                "media_format=mp4avc"
            } else {
                "media_format=mp4hevc"
            }));
            assert!(report.contains(&format!("segment_count={}", fixture.frames)));
            assert!(report.contains("capture_time_class=unknown"));
            assert!(report.contains("absence_certifiable=false"));
            assert_replay_origin(&report, &fixture)?;
        }
        let decoded = good(
            Command::new(env!("CARGO_BIN_EXE_fss-file"))
                .arg("decode")
                .args(&common)
                .args([
                    "--segment",
                    "0",
                    "--segment-count",
                    &fixture.frames.to_string(),
                    "--interpretation",
                    "ycbcr",
                    "--work-units",
                    "1000000000",
                ])
                .output()?,
        )?;
        assert!(!decoded.is_empty());
        assert_eq!(
            fixture.journals()?.1,
            committed.1,
            "offline analysis dispatched an effect"
        );
        let before_retry = fixture.journals()?;
        let missing = run(&args)?;
        assert!(!missing.status.success());
        assert!(missing.stdout.is_empty());
        assert!(String::from_utf8_lossy(&missing.stderr).contains("ERR-RTSP-IMPORT-SOURCE-001"));
        assert!(!fixture.archive().exists());
        assert_eq!(fixture.journals()?, before_retry);
    }
    Ok(())
}

fn assert_replay_origin(report: &str, fixture: &Fixture) -> Test {
    let receipt = &fixture.receipt;
    for expected in [
        "replay_provenance=verified_metadata".to_owned(),
        format!("replay_root={}", receipt.root()),
        format!("replay_request={}", receipt.request().digest()),
        format!("replay_approval={}", receipt.approval()),
        format!("replay_codec={}", receipt.request().codec().as_str()),
        format!("replay_windows={}", receipt.windows().len()),
        format!("replay_termination={}", receipt.termination().as_str()),
        format!(
            "replay_publication_complete={}",
            receipt.publication_complete()
        ),
        format!("replay_requested_window={}", receipt.request().window()),
        format!(
            "replay_acknowledged_window={}",
            receipt.acceptance().acknowledged()
        ),
    ] {
        assert!(
            report.lines().any(|line| line == expected),
            "{expected}: {report}"
        );
    }
    if let Some(source) = receipt.request().onvif_source() {
        let expected = format!("replay_onvif_source={}", source.digest()?);
        assert!(
            report.lines().any(|line| line == expected),
            "{expected}: {report}"
        );
    } else {
        assert!(
            !report
                .lines()
                .any(|line| line.starts_with("replay_onvif_source="))
        );
    }
    Ok(())
}

#[test]
fn decode_gaps_need_a_new_explicit_plan_and_remain_visible_in_the_result() -> Test {
    let _serial = serial();
    let fixture = Fixture::new(RtspImportCodec::Avc, 2, 3600)?;
    let mut args = fixture.args()?;
    approve(&mut args)?;
    let refused = run(&args)?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());

    // Changing gap semantics invalidates the old approval before attempting custody.
    set(&mut args, "--decode-gaps", "preserve");
    let refused = run(&args)?;
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("ERR-RTSP-IMPORT-APPROVAL-001"));
    approve(&mut args)?;
    let imported = good(run(&args)?)?;
    assert!(imported.contains("\"decode_gaps\":\"preserve\""));
    assert!(imported.contains("\"decode_gap_intervals\":[{\"start\":\"3600\",\"end\":\"7200\"}]"));
    assert!(imported.contains("\"frames\":2"));
    assert!(imported.contains("\"continuity_certified\":false"));
    assert!(imported.contains("\"historical_utc_calibrated\":false"));
    Ok(())
}

#[test]
fn independent_replay_pins_and_whole_receipt_bounds_cannot_silently_select_less() -> Test {
    let _serial = serial();
    let fixture = Fixture::new(RtspImportCodec::Hevc, 2, 0)?;
    let other = ContentDigest::sha256(b"not this recording replay").to_text();
    for (key, value) in [
        ("--expected-replay-root", other.as_str()),
        ("--expected-replay-request", other.as_str()),
        ("--codec", "avc"),
        ("--max-windows", "1"),
        ("--max-frames", "4"),
        ("--max-original-bytes", "1"),
        ("--max-media-bytes", "1"),
    ] {
        let mut args = fixture.args()?;
        set(&mut args, key, value);
        approve(&mut args)?;
        let refused = run(&args)?;
        assert!(
            !refused.status.success(),
            "{key} admitted incomplete or substituted receipt"
        );
        assert!(refused.stdout.is_empty());
    }
    let mut args = fixture.args()?;
    approve(&mut args)?;
    let imported = good(run(&args)?)?;
    assert!(imported.contains("\"frames\":8"));
    assert!(imported.contains("\"windows\":2"));
    assert!(imported.contains("\"reused\":false"));
    Ok(())
}

#[test]
fn approved_missing_archive_refusal_never_recreates_custody_and_help_explains_partial_time() -> Test
{
    let _serial = serial();
    let fixture = Fixture::new(RtspImportCodec::Avc, 1, 0)?;
    fs::rename(
        fixture.archive(),
        fixture.directory.0.join("archive offline"),
    )?;
    let mut args = fixture.args()?;
    approve(&mut args)?;
    let missing = run(&args)?;
    assert!(!missing.status.success());
    assert!(missing.stdout.is_empty());
    assert!(!fixture.archive().exists());
    assert!(!fixture.target().exists());
    let help = good(run(&["replay".into(), "--help".into()])?)?;
    for text in [
        "every native original window",
        "remains partial",
        "operator assumption",
        "No recorder is contacted",
    ] {
        assert!(help.contains(text), "{text}");
    }
    Ok(())
}
