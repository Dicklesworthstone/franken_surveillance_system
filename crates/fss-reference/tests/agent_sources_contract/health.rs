#![forbid(unsafe_code)]
//! Protected diagnostics remain unfiltered and are reread even when no source row matches.

use super::*;

#[test]
fn filters_preserve_complete_historical_health_and_obligations_without_source_bytes()
    -> TestResult
{
    let fixture = qsr_observations_support::Fixture::new("sources-protected-health")?;
    let root = &fixture.source.root;
    let mut request = request()?;
    request.principal = PrincipalId::parse(qsr_observations_support::PRINCIPAL)?;
    let limits = SourcesQueryLimits::default();
    let cx = context_for_site(root, &request, limits, qsr_observations_support::SITE)?;
    let full = query_sources(root, &request, limits, &cx, &|| false)?;
    assert!(!full.snapshot.historical_health.is_empty());
    assert!(!full.snapshot.obligations.is_empty());
    assert!(!full.rows.is_empty());
    assert!(full.snapshot.historical_health.iter().all(|receipt| {
        matches!(
            &receipt.metadata,
            fss_reference::agent_orient::historical_health::HistoricalHealthMetadata::Retained { .. }
        )
    }));
    fs::remove_file(&fixture.source.chunk)?;
    let without_media = files(root)?;
    request.filter.sensor_id = Some(SensorId::parse("sensor:no-match")?);
    let filtered = query_sources(root, &request, limits, &cx, &|| false)?;
    assert!(filtered.rows.is_empty());
    assert_eq!(filtered.summary, full.summary);
    assert_eq!(filtered.snapshot.historical_health, full.snapshot.historical_health);
    assert_eq!(filtered.snapshot.obligations, full.snapshot.obligations);
    assert_eq!(filtered.snapshot.operations, full.snapshot.operations);
    assert_eq!(files(root)?, without_media);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn protected_receipt_changed_after_initial_snapshot_refuses_even_an_unmatched_page()
    -> TestResult
{
    let fixture = qsr_observations_support::Fixture::new("sources-health-final-reread")?;
    let root = &fixture.source.root;
    let mut request = request()?;
    request.principal = PrincipalId::parse(qsr_observations_support::PRINCIPAL)?;
    request.filter.sensor_id = Some(SensorId::parse("sensor:no-match")?);
    let limits = SourcesQueryLimits::default();
    let cx = context_for_site(root, &request, limits, qsr_observations_support::SITE)?;
    let opening_calls = AtomicUsize::new(0);
    let admission = || {
        opening_calls.fetch_add(1, Ordering::SeqCst);
        false
    };
    let owner = ImmutableRetainedSource::open_cancellable(root, limits.read, &cx, &admission)?;
    let receipt = owner.snapshot().historical_health.first().ok_or("historical receipt")?
        .receipt_digest;
    let count = opening_calls.load(Ordering::SeqCst);
    drop(owner);
    let path = object_path(root, receipt);
    let original = fs::read(&path)?;
    let calls = AtomicUsize::new(0);
    let changed = AtomicBool::new(false);
    // A query has one admission check before the same immutable open. The next probe is the
    // first inventory checkpoint, after every original protected receipt has been decoded.
    // Corrupting it here exercises the query's final complete-snapshot reread, not opening.
    let result = query_sources(root, &request, limits, &cx, &|| {
        if calls.fetch_add(1, Ordering::SeqCst) + 1 == count + 2 {
            assert!(fs::write(&path, b"protected diagnostic changed after the opening snapshot").is_ok());
            changed.store(true, Ordering::SeqCst);
        }
        false
    });
    fs::write(&path, original)?;
    assert!(changed.load(Ordering::SeqCst));
    assert!(result.is_err(), "unmatched rows cannot hide changed historical diagnostics");
    let restored = query_sources(root, &request, limits, &cx, &|| false)?;
    assert!(restored.rows.is_empty());
    assert!(!restored.snapshot.historical_health.is_empty());
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn layout_mutation_after_opening_never_releases_the_old_authority_page() -> TestResult {
    let fixture = populated("sources-final-authority")?;
    let root = fixture.deployment.root();
    let request = request()?;
    let limits = SourcesQueryLimits::default();
    let cx = context(root, &request, limits)?;
    let opening_calls = AtomicUsize::new(0);
    let admission = || {
        opening_calls.fetch_add(1, Ordering::SeqCst);
        false
    };
    let owner = ImmutableRetainedSource::open_cancellable(root, limits.read, &cx, &admission)?;
    let count = opening_calls.load(Ordering::SeqCst);
    drop(owner);
    let path = root.join("LAYOUT");
    let original = fs::read(&path)?;
    let calls = AtomicUsize::new(0);
    let changed = AtomicBool::new(false);
    let result = query_sources(root, &request, limits, &cx, &|| {
        if calls.fetch_add(1, Ordering::SeqCst) + 1 == count + 2 {
            assert!(fs::write(&path, b"changed layout after opening").is_ok());
            changed.store(true, Ordering::SeqCst);
        }
        false
    });
    fs::write(&path, original)?;
    assert!(changed.load(Ordering::SeqCst));
    assert!(result.is_err());
    cx.drain_and_finalize();
    Ok(())
}
