#![forbid(unsafe_code)]
//! Movie tables remain exact when all source reads share an immutable custody owner.

use super::*;
use fss_core::{BudgetVector, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_reference::agent_orient::OrientLimits;
use fss_reference::retained_source::{ImmutableRetainedReadLimits, ImmutableRetainedSource};
use std::sync::atomic::{AtomicBool, Ordering};

pub(super) fn limits() -> ImmutableRetainedReadLimits {
    ImmutableRetainedReadLimits {
        snapshot: OrientLimits::default(),
        max_read_bytes: 64 * 1024 * 1024,
        max_read_objects: 20_000,
    }
}

pub(super) fn read_context(root: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:immutable-movie-selection".into(),
        operation_id: OperationId::parse("operation:immutable-movie-selection")?,
        principal: "principal:movie-reader".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(20_000)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority_read_only(
        &authority,
        root.to_path_buf(),
    )?)
}

fn select(
    f: &Fixture,
    source: &ImmutableRetainedSource<'_>,
    cx: &ReplayCx,
) -> TestResult<RetainedMovieSelection> {
    Ok(f.retained.select_movie_interval(
        source,
        400..800,
        RetainedReadLimits::default(),
        MovieSelectionLimits::default(),
        cx,
    )?)
}

#[test]
fn live_writer_preserves_avc_hevc_and_movie_edit_selection_byte_for_byte() -> TestResult {
    for name in [
        "indexed_avc.mp4",
        "hevc_fragmented_av.mp4",
        "qt_av.mov",
        "inband/hev1_partial_change.mp4",
    ] {
        let f = Fixture::new("immutable-movie-parity", name)?;
        let expected = f.select(400..800)?;
        let before = snapshot(&f.root)?;
        let cx = read_context(&f.root)?;
        let source = ImmutableRetainedSource::open(&f.root, limits(), &cx)?;
        assert_eq!(select(&f, &source, &cx)?, expected, "{name}");
        source.revalidate()?;
        assert_eq!(snapshot(&f.root)?, before, "{name}");
        cx.drain_and_finalize();
    }
    Ok(())
}

#[test]
fn source_metadata_and_final_validation_share_exact_bytes_and_attempts() -> TestResult {
    let f = Fixture::new("immutable-movie-budgets", "indexed_avc.mp4")?;
    let before = snapshot(&f.root)?;
    let cx = read_context(&f.root)?;
    let measured = ImmutableRetainedSource::open(&f.root, limits(), &cx)?;
    select(&f, &measured, &cx)?;
    measured.revalidate()?;
    let used = measured.usage();
    let exact = ImmutableRetainedReadLimits {
        max_read_bytes: usize::try_from(used.read_bytes)?,
        max_read_objects: usize::try_from(used.read_objects)?,
        ..limits()
    };
    let admitted = ImmutableRetainedSource::open(&f.root, exact, &cx)?;
    select(&f, &admitted, &cx)?;
    admitted.revalidate()?;
    assert_eq!(admitted.usage(), used);
    for short in [
        ImmutableRetainedReadLimits {
            max_read_bytes: exact.max_read_bytes - 1,
            ..exact
        },
        ImmutableRetainedReadLimits {
            max_read_objects: exact.max_read_objects - 1,
            ..exact
        },
    ] {
        let source = ImmutableRetainedSource::open(&f.root, short, &cx)?;
        select(&f, &source, &cx)?;
        assert!(source.revalidate().is_err());
        assert!(
            source.revalidate().is_err(),
            "final failure replenished the allowance"
        );
    }
    assert_eq!(snapshot(&f.root)?, before);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn changed_source_and_final_cancellation_invalidate_the_complete_selection() -> TestResult {
    let f = Fixture::new("immutable-movie-final", "indexed_avc.mp4")?;
    let cx = read_context(&f.root)?;
    let cancelled = AtomicBool::new(false);
    let stop = || cancelled.load(Ordering::SeqCst);
    let source = ImmutableRetainedSource::open_cancellable(&f.root, limits(), &cx, &stop)?;
    select(&f, &source, &cx)?;
    cancelled.store(true, Ordering::SeqCst);
    assert!(source.revalidate().is_err());
    cancelled.store(false, Ordering::SeqCst);
    assert!(source.revalidate().is_err());

    let source = ImmutableRetainedSource::open(&f.root, limits(), &cx)?;
    select(&f, &source, &cx)?;
    let digest = *f
        .retained
        .manifest()
        .ordered_chunks
        .last()
        .ok_or("source chunk")?;
    let path = f.deployment.publisher().spool().object_path(digest);
    let mut bytes = fs::read(&path)?;
    bytes[0] ^= 1;
    fs::write(path, bytes)?;
    let before = snapshot(&f.root)?;
    assert!(source.revalidate().is_err());
    let fresh = ImmutableRetainedSource::open(&f.root, limits(), &cx)?;
    assert!(select(&f, &fresh, &cx).is_err());
    assert_eq!(snapshot(&f.root)?, before);
    cx.drain_and_finalize();
    Ok(())
}
