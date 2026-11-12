#![forbid(unsafe_code)]
//! Existing-store QSR ownership through real retained model, health and source-custody owners.

mod qsr_observations_support;

use std::fs;

use fss_core::ContentDigest;
use fss_reference::ingest::package_zones::PackageZoneError;
use fss_reference::ingest::qsr_observations::{
    QsrConfig, QsrError, QsrObservationReport, STAGE_QSR_REVALIDATE,
};
use fss_reference::{DeploymentLimits, ReferenceDeployment, ReferenceError};
use qsr_observations_support::{Directory, Fixture, SITE, Test, config, context};

#[test]
fn repeated_native_reads_preserve_pending_committed_and_indeterminate_effects() -> Test {
    let fixture = Fixture::new("qsr-existing-effects")?;
    let before = fixture.source.journals()?;
    let temporary = fixture.source.root.join("LAYOUT.tmp.qsr-local-recovery");
    fs::write(&temporary, b"stale local layout temporary")?;
    for _ in 0..2 {
        let cx = context(&fixture.source.root)?;
        let result = QsrObservationReport::open_existing(
            &fixture.source.root,
            SITE,
            fixture.report,
            config(),
            &cx,
        )?;
        assert_eq!(result.encoded(), fixture.expected_bytes);
        assert_eq!(result.to_json()?, fixture.expected_json);
        cx.drain_and_finalize();
        assert_eq!(fixture.source.journals()?, before);
    }
    assert!(!temporary.exists(), "locked local recovery remains active");
    Ok(())
}

#[test]
fn refused_and_cancelled_reads_leave_both_journals_unchanged() -> Test {
    let fixture = Fixture::new("qsr-existing-refusals")?;
    let before = fixture.source.journals()?;
    let mut unknown_zone = config();
    unknown_zone.zone_roles[0].zone = "foreign-zone".into();
    for (digest, config) in [
        (ContentDigest::sha256(b"unretained QSR source"), config()),
        (fixture.report, unknown_zone),
    ] {
        let cx = context(&fixture.source.root)?;
        assert!(
            QsrObservationReport::open_existing(&fixture.source.root, SITE, digest, config, &cx,)
                .is_err()
        );
        cx.drain_and_finalize();
        assert_eq!(fixture.source.journals()?, before);
    }
    let cx = context(&fixture.source.root)?;
    let refused = QsrObservationReport::open_existing(
        &fixture.source.root,
        "site:foreign-deployment",
        fixture.report,
        config(),
        &cx,
    );
    let Err(QsrError::Source(PackageZoneError::Source(error))) = refused else {
        return Err("expected exact site mismatch refusal".into());
    };
    assert!(matches!(
        error.downcast_ref::<ReferenceError>(),
        Some(ReferenceError::SiteLineageMismatch { .. })
    ));
    cx.drain_and_finalize();
    assert_eq!(fixture.source.journals()?, before);
    for stage in ["qsr:open_existing", STAGE_QSR_REVALIDATE] {
        let cx = context(&fixture.source.root)?;
        cx.set_cancel_at_checkpoint(stage);
        assert!(matches!(
            QsrObservationReport::open_existing(
                &fixture.source.root,
                SITE,
                fixture.report,
                config(),
                &cx,
            ),
            Err(QsrError::Cancelled)
        ));
        cx.drain_and_finalize();
        assert_eq!(fixture.source.journals()?, before);
    }
    let original = fs::read(&fixture.source.chunk)?;
    let mut corrupt = original;
    *corrupt.last_mut().ok_or("source object")? ^= 1;
    fs::write(&fixture.source.chunk, &corrupt)?;
    let cx = context(&fixture.source.root)?;
    assert!(
        QsrObservationReport::open_existing(
            &fixture.source.root,
            SITE,
            fixture.report,
            config(),
            &cx,
        )
        .is_err()
    );
    cx.drain_and_finalize();
    assert_eq!(fs::read(&fixture.source.chunk)?, corrupt);
    assert_eq!(fixture.source.journals()?, before);
    Ok(())
}

#[test]
fn absent_empty_foreign_and_incomplete_deployments_are_never_initialized() -> Test {
    let directory = Directory::new("qsr-existing-missing")?;
    let root = directory.0.join("absent");
    let cx = context(&root)?;
    let read = || {
        QsrObservationReport::open_existing(
            &root,
            SITE,
            ContentDigest::sha256(b"absent report"),
            QsrConfig::default(),
            &cx,
        )
    };
    assert!(read().is_err());
    assert!(!root.exists());
    fs::create_dir(&root)?;
    assert!(read().is_err());
    assert!(fs::read_dir(&root)?.next().is_none());
    let foreign = root.join("foreign-data");
    fs::write(&foreign, b"unrelated source bytes")?;
    assert!(read().is_err());
    assert_eq!(fs::read(&foreign)?, b"unrelated source bytes");
    assert_eq!(fs::read_dir(&root)?.count(), 1);
    cx.drain_and_finalize();

    for (label, relative) in [
        ("qsr-missing-layout", "LAYOUT"),
        ("qsr-missing-ledger", "ledger/journal.fssj"),
        ("qsr-missing-effects", "effects/journal.fssj"),
    ] {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let cx = context(&root)?;
        drop(ReferenceDeployment::open(&root, SITE, &cx)?);
        fs::remove_file(root.join(relative))?;
        let temporary = root.join("LAYOUT.tmp.preserve-incomplete-store");
        fs::write(&temporary, b"incomplete store evidence")?;
        assert!(
            QsrObservationReport::open_existing(
                &root,
                SITE,
                ContentDigest::sha256(b"absent report"),
                QsrConfig::default(),
                &cx,
            )
            .is_err()
        );
        assert!(!root.join(relative).exists());
        assert_eq!(fs::read(&temporary)?, b"incomplete store evidence");
        cx.drain_and_finalize();
    }
    Ok(())
}

#[test]
fn context_root_and_request_shape_are_checked_before_local_recovery() -> Test {
    let fixture = Fixture::new("qsr-existing-scope")?;
    let before = fixture.source.journals()?;
    let temporary = fixture.source.root.join("LAYOUT.tmp.preserve-wrong-scope");
    fs::write(&temporary, b"recovery must not start")?;
    let other_root = fixture.source.directory.0.join("other-root");
    let other_cx = context(&other_root)?;
    assert!(matches!(
        QsrObservationReport::open_existing(
            &fixture.source.root,
            SITE,
            fixture.report,
            config(),
            &other_cx,
        ),
        Err(QsrError::Invalid(_))
    ));
    assert!(!other_root.exists());
    other_cx.drain_and_finalize();
    let cx = context(&fixture.source.root)?;
    let mut invalid = config();
    invalid.lane_stages.push("only-one-stage".into());
    assert!(matches!(
        QsrObservationReport::open_existing(
            &fixture.source.root,
            SITE,
            fixture.report,
            invalid,
            &cx,
        ),
        Err(QsrError::Invalid(_))
    ));
    cx.drain_and_finalize();
    assert_eq!(fs::read(&temporary)?, b"recovery must not start");
    assert_eq!(fixture.source.journals()?, before);
    Ok(())
}

#[test]
fn explicit_original_limits_work_and_standard_limits_cannot_override_their_digest() -> Test {
    let limits = DeploymentLimits {
        spool_total_max_bytes: DeploymentLimits::STANDARD_SPOOL_TOTAL_MAX_BYTES - 1,
        ..DeploymentLimits::standard()
    };
    let fixture = Fixture::new_with_limits("qsr-existing-capacities", limits)?;
    let before = fixture.source.journals()?;
    let cx = context(&fixture.source.root)?;
    let refused = QsrObservationReport::open_existing(
        &fixture.source.root,
        SITE,
        fixture.report,
        config(),
        &cx,
    );
    let Err(QsrError::Source(PackageZoneError::Source(error))) = refused else {
        return Err("expected exact persisted capacity refusal".into());
    };
    assert!(matches!(
        error.downcast_ref::<ReferenceError>(),
        Some(ReferenceError::LimitsDigestMismatch { .. })
    ));
    assert_eq!(fixture.source.journals()?, before);
    let result = QsrObservationReport::open_existing_with_limits(
        &fixture.source.root,
        SITE,
        limits,
        fixture.report,
        config(),
        &cx,
    )?;
    assert_eq!(result.to_json()?, fixture.expected_json);
    assert_eq!(result.encoded(), fixture.expected_bytes);
    cx.drain_and_finalize();
    assert_eq!(fixture.source.journals()?, before);
    Ok(())
}
