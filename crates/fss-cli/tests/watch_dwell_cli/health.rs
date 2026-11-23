#![forbid(unsafe_code)]
//! Real-process health admission, exact approvals and cold retry for sampled dwell.

use super::*;

fn optical(fixture: &Fixture, variance: u64, glare_min: u8, glare_ppm: u32) -> Command {
    let mut command = fixture.dwell();
    command.args([
        "--sensor-health",
        "conservative-optical-v1",
        "--min-laplacian-variance-x1000",
        &variance.to_string(),
        "--glare-luma-min",
        &glare_min.to_string(),
        "--max-glare-ppm",
        &glare_ppm.to_string(),
    ]);
    command
}

#[test]
fn screened_dwell_approvals_bind_policy_and_survive_cold_retry() -> Test {
    let fixture = Fixture::new("screened-approval", true)?;
    let before = fixture.journals()?;
    let plain = succeeded(fixture.dwell().output()?)?;
    let conservative = succeeded(
        fixture
            .dwell()
            .args(["--sensor-health", "conservative-v1"])
            .output()?,
    )?;
    let screened = succeeded(optical(&fixture, 0, 255, 1_000_000).output()?)?;
    let changed = succeeded(optical(&fixture, 0, 254, 1_000_000).output()?)?;
    assert!(!plain.contains("\"sensor_health\":"));
    for report in [&conservative, &screened, &changed] {
        assert!(report.contains("\"candidate_count\":1,"), "{report}");
        assert!(report.contains("\"sensor_health\":"));
        assert!(report.contains("\"health_certified\":false"));
        assert!(report.contains("\"continuous_occupancy_certified\":false"));
        assert!(report.contains("\"absence_certifiable\":false"));
        assert!(report.contains("\"alert_authorized\":false"));
        assert_ne!(
            digest_field(report, "analysis_digest")?,
            digest_field(&plain, "analysis_digest")?,
        );
    }
    for flag in [
        "--sensor-health conservative-optical-v1",
        "--min-laplacian-variance-x1000 0",
        "--glare-luma-min 255",
        "--max-glare-ppm 1000000",
    ] {
        assert!(screened.contains(flag), "rerun omitted {flag}");
    }
    let approval = digest_field(&screened, "proposal_digest")?;
    for other in [&plain, &conservative, &changed] {
        let wrong = digest_field(other, "proposal_digest")?;
        assert_ne!(approval, wrong);
        let error = refused(
            optical(&fixture, 0, 255, 1_000_000)
                .args(["--approve", &wrong.to_text()])
                .output()?,
        )?;
        assert!(error.contains("ERR-WATCH-APPROVAL-STALE-001"), "{error}");
    }
    let dropped = refused(
        fixture
            .dwell()
            .args(["--approve", &approval.to_text()])
            .output()?,
    )?;
    assert!(dropped.contains("ERR-WATCH-APPROVAL-STALE-001"));
    assert_eq!(fixture.journals()?, before);

    let published = succeeded(
        optical(&fixture, 0, 255, 1_000_000)
            .args(["--approve", &approval.to_text()])
            .output()?,
    )?;
    assert!(published.contains("\"status\":\"published\""));
    let after = fixture.journals()?;
    assert_ne!(after.0, before.0);
    assert_eq!(after.1, before.1, "dwell publication dispatched an effect");
    let retry = succeeded(
        optical(&fixture, 0, 255, 1_000_000)
            .args(["--approve", &approval.to_text()])
            .output()?,
    )?;
    assert!(retry.contains("\"status\":\"already_published\""));
    assert_eq!(digest_field(&retry, "proposal_digest")?, approval);
    assert_eq!(fixture.journals()?, after);
    Ok(())
}

#[test]
fn optical_findings_withdraw_dwell_and_export_complete_diagnostics() -> Test {
    let fixture = Fixture::new("optical-refusal", true)?;
    let before = fixture.journals()?;
    for (variance, glare_min, glare_ppm, finding) in [
        (u64::MAX, 255, 1_000_000, "severe_blur"),
        (0, 0, 0, "localized_highlight_glare"),
    ] {
        let target = fixture.dir.0.join(format!("dwell-{finding}.json"));
        let report = succeeded(
            optical(&fixture, variance, glare_min, glare_ppm)
                .arg("--report-out")
                .arg(&target)
                .output()?,
        )?;
        assert!(report.contains("\"candidate_count\":0,"), "{report}");
        assert!(report.contains(finding), "missing {finding}: {report}");
        assert!(report.contains("\"health_certified\":false"));
        assert!(report.contains("\"absence_certifiable\":false"));
        assert!(report.contains("\"continuous_occupancy_certified\":false"));
        assert!(!report.contains("--approve"));
        assert_eq!(fs::read_to_string(target)?, report);
        assert_eq!(fixture.journals()?, before);
    }
    Ok(())
}

#[test]
fn visual_health_cannot_supply_missing_capture_time() -> Test {
    let fixture = Fixture::new("screened-time", false)?;
    let before = fixture.journals()?;
    for mut command in [
        {
            let mut command = fixture.dwell();
            command.args(["--sensor-health", "conservative-v1"]);
            command
        },
        optical(&fixture, 0, 255, 1_000_000),
    ] {
        let error = refused(command.output()?)?;
        assert!(error.contains("capture-time hints"), "{error}");
        assert_eq!(fixture.journals()?, before);
    }
    Ok(())
}
