#![forbid(unsafe_code)]
//! HEVC discovery shares the bounded engine without sharing codec identities.
mod hevc_recording_support;
mod hevc_catalog_support;
mod recording_support;

use hevc_catalog_support::*;
use fss_core::{CanonicalEncode, ContentDigest};
use fss_object::ObjectManifest;
use fss_reference::rtsp::recording_catalog::{CatalogBuilder, CatalogError as E,
    CatalogQueryLimits, CatalogScope, CATALOG_KIND, MAX_CATALOG_BYTES, MAX_CATALOG_WINDOWS,
    verify_catalog};
use fss_reference::rtsp::recording_catalog::hevc::{HevcCatalogBuilder, HevcCatalogWindow,
    HevcRecordingCatalog, HEVC_CATALOG_KIND, prepare_hevc_catalog, verify_hevc_catalog};

type TestResult = Result<(), Error>;
fn pair() -> Result<HevcRecordingCatalog, Error> {
    let first = window(1_000)?; let second = window(100_000)?;
    let a = slot(0)?; let b = slot(1)?;
    Ok(prepare_hevc_catalog(scope()?, &[HevcCatalogWindow { slot: &a, recording: &first },
        HevcCatalogWindow { slot: &b, recording: &second }])?)
}

#[test]
fn independent_canonical_bytes_and_flat_source_closure_are_exact() -> TestResult {
    let first = window(1_000)?; let second = window(100_000)?;
    let a = slot(0)?; let b = slot(1)?; let basis = scope()?;
    let catalog = prepare_hevc_catalog(basis.clone(), &[
        HevcCatalogWindow { slot: &a, recording: &first }, HevcCatalogWindow { slot: &b, recording: &second }])?;
    let expected = index("fss.hevc_recording_catalog.v1", &basis,
        &[(&a, first.publication_plan()), (&b, second.publication_plan())], None)?;
    assert_eq!(catalog.index_bytes(), expected);
    assert_eq!(catalog.manifest(), &manifest(HEVC_CATALOG_KIND, &expected,
        &[first.publication_plan(), second.publication_plan()], None)?);
    assert_eq!(catalog.manifest().kind(), HEVC_CATALOG_KIND);
    for recording in [&first, &second] {
        assert!(catalog.manifest().children().contains(&recording.manifest().root()));
        for (_, root, _) in recording.publication_plan().children() {
            assert!(catalog.manifest().children().contains(&root));
        }
    }
    let verified = verify_hevc_catalog(catalog.manifest(), catalog.index_bytes(), &basis)?;
    assert_eq!(verified.entries(), catalog.entries());
    assert_eq!(verified.byte_len(), catalog.index_bytes().len() + catalog.manifest().canonical_bytes().len());
    assert!(verified.byte_len() <= MAX_CATALOG_BYTES);
    Ok(())
}

#[test]
fn query_reports_whole_windows_requested_overlaps_and_unindexed_intervals() -> TestResult {
    let c = pair()?;
    let selected = c.select(0..200_000, CatalogQueryLimits::default())?;
    assert_eq!(selected.catalog_root(), c.manifest().root());
    assert_eq!(selected.query(), 0..200_000);
    assert_eq!(selected.windows().len(), 2);
    assert_eq!(selected.windows()[0].ordinal(), 0);
    assert_eq!(selected.windows()[0].requested_interval(), 1_000..73_000);
    assert_eq!(selected.windows()[1].requested_interval(), 100_000..172_000);
    assert_eq!(selected.unindexed(), &[0..1_000, 73_000..100_000, 172_000..200_000]);
    assert_eq!(selected.output_bytes(), c.entries().iter().map(|e| e.byte_len() as u64).sum::<u64>());
    let one_tick = c.select(1_001..1_002, CatalogQueryLimits::default())?;
    assert_eq!(one_tick.windows()[0].requested_interval(), 1_001..1_002);
    assert_eq!(one_tick.output_bytes(), c.entries()[0].byte_len() as u64);
    assert!(one_tick.unindexed().is_empty());
    assert_eq!(c.entries()[0].samples(), 4);
    Ok(())
}

#[test]
fn half_open_edges_and_empty_matches_never_become_coverage_claims() -> TestResult {
    let c = pair()?;
    for query in [0..1_000, 73_000..100_000, 172_000..u64::MAX] {
        let s = c.select(query.clone(), CatalogQueryLimits::default())?;
        assert!(s.windows().is_empty()); assert_eq!(s.output_bytes(), 0);
        assert_eq!(s.unindexed(), &[query]);
    }
    assert_eq!(c.select(73_000..100_001, CatalogQueryLimits::default())?.windows()[0].ordinal(), 1);
    for query in [0..0, 2..1, u64::MAX..u64::MAX] {
        assert_eq!(c.select(query, CatalogQueryLimits::default()).err(), Some(E::Interval));
    }
    Ok(())
}

#[test]
fn byte_and_window_limits_refuse_the_whole_selection_without_truncation() -> TestResult {
    let c = pair()?;
    let bytes = c.entries().iter().map(|e| e.byte_len() as u64).sum::<u64>();
    for limits in [
        CatalogQueryLimits { max_windows: 1, max_output_bytes: bytes },
        CatalogQueryLimits { max_windows: 2, max_output_bytes: bytes - 1 },
        CatalogQueryLimits { max_windows: 0, max_output_bytes: bytes },
        CatalogQueryLimits { max_windows: MAX_CATALOG_WINDOWS + 1, max_output_bytes: bytes },
        CatalogQueryLimits { max_windows: 2, max_output_bytes: 0 },
    ] { assert_eq!(c.select(0..200_000, limits).err(), Some(E::Limit)); }
    assert_eq!(c.select(0..200_000, CatalogQueryLimits { max_windows: 2, max_output_bytes: bytes })?.output_bytes(), bytes);
    Ok(())
}

#[test]
fn duplicate_roots_slots_overlaps_and_scope_failures_leave_builder_retryable() -> TestResult {
    let first = window(0)?; let next = window(100_000)?; let overlap = window(71_999)?;
    let a = slot(0)?; let b = slot(1)?;
    let mut builder = HevcCatalogBuilder::new(scope()?)?;
    assert!(builder.is_empty()); builder.push(&a, &first)?;
    assert_eq!(builder.push(&a, &first), Err(E::Order));
    assert_eq!(builder.push(&b, &first), Err(E::Order));
    assert_eq!(builder.push(&a, &next), Err(E::Order));
    assert_eq!(builder.push(&b, &overlap), Err(E::Order));
    assert_eq!(builder.len(), 1);
    builder.push(&b, &next)?;
    let c = builder.prepare()?; assert_eq!(c.entries().len(), 2);
    assert_eq!(c.entries()[1].root(), next.manifest().root());
    let mut wrong = scope()?; wrong.recording.generation = 2;
    let mut builder = HevcCatalogBuilder::new(wrong)?;
    assert_eq!(builder.push(&a, &first), Err(E::Scope)); assert!(builder.is_empty());
    Ok(())
}

#[test]
fn expected_scope_and_decode_clock_are_not_learned_from_the_index() -> TestResult {
    let c = pair()?;
    for field in 0..7 {
        let mut wrong = scope()?;
        match field {
            0 => wrong.recording.generation += 1,
            1 => wrong.recording.anchor = ContentDigest::sha256(b"other anchor"),
            2 => wrong.recording.receive_clock = ContentDigest::sha256(b"other receive clock"),
            3 => wrong.decode_clock = ContentDigest::sha256(b"other decode clock"),
            4 => wrong.time_scale = 1_000,
            5 => wrong.recording.sensor = fss_core::SensorId::parse("other-sensor")?,
            _ => wrong.recording.stream = fss_core::StreamId::parse("other-stream")?,
        }
        assert_eq!(verify_hevc_catalog(c.manifest(), c.index_bytes(), &wrong).err(), Some(E::Scope));
    }
    let mut wrong = scope()?; wrong.time_scale = 0;
    assert_eq!(HevcCatalogBuilder::new(wrong).err(), Some(E::Scope));
    Ok(())
}

#[test]
fn avc_bytes_stay_identical_and_public_entrypoints_do_not_switch_codecs() -> TestResult {
    let avc = recording_support::fixture(1, false)?.prepare()?;
    let basis = CatalogScope { recording: avc.summary().scope.clone(),
        decode_clock: ContentDigest::sha256(b"avc-test-clock"), time_scale: 90_000 };
    let a = slot(0)?;
    let mut builder = CatalogBuilder::new(basis.clone())?;
    builder.push(&a, &avc)?; let catalog = builder.prepare()?;
    let expected = index("fss.recording_catalog.v1", &basis, &[(&a, &avc)], None)?;
    assert_eq!(catalog.index_bytes(), expected);
    assert_eq!(catalog.manifest(), &manifest(CATALOG_KIND, &expected, &[&avc], None)?);
    verify_catalog(catalog.manifest(), catalog.index_bytes(), &basis)?;
    assert!(verify_hevc_catalog(catalog.manifest(), catalog.index_bytes(), &basis).is_err());
    let hevc = pair()?;
    assert!(verify_catalog(hevc.manifest(), hevc.index_bytes(), hevc.scope()).is_err());
    // HEVC exposes a generic publication plan, but that is not an AVC window grant.
    let h = window(0)?;
    let mut avc_builder = CatalogBuilder::new(scope()?)?;
    assert_eq!(avc_builder.push(&a, h.publication_plan()), Err(E::Digest));
    assert!(avc_builder.is_empty());
    Ok(())
}

#[test]
fn rehashed_codec_relabeling_cannot_change_the_window_family() -> TestResult {
    let h = window(0)?; let a = slot(0)?; let basis = scope()?;
    let hevc_as_avc = index("fss.recording_catalog.v1", &basis, &[(&a, h.publication_plan())], None)?;
    let root = manifest(CATALOG_KIND, &hevc_as_avc, &[h.publication_plan()], None)?;
    assert_eq!(verify_catalog(&root, &hevc_as_avc, &basis).err(), Some(E::Digest));
    let avc = recording_support::fixture(1, false)?.prepare()?;
    let basis = CatalogScope { recording: avc.summary().scope.clone(), ..scope()? };
    let avc_as_hevc = index("fss.hevc_recording_catalog.v1", &basis, &[(&a, &avc)], None)?;
    let root = manifest(HEVC_CATALOG_KIND, &avc_as_hevc, &[&avc], None)?;
    assert_eq!(verify_hevc_catalog(&root, &avc_as_hevc, &basis).err(), Some(E::Digest));
    Ok(())
}

#[test]
fn canonical_checksum_closure_and_declared_window_roots_fail_closed() -> TestResult {
    let h = window(0)?; let a = slot(0)?; let basis = scope()?;
    let c = prepare_hevc_catalog(basis.clone(), &[HevcCatalogWindow { slot: &a, recording: &h }])?;
    for end in [0, 1, 32, c.index_bytes().len() - 1] {
        assert!(verify_hevc_catalog(c.manifest(), &c.index_bytes()[..end], &basis).is_err());
    }
    let mut changed = c.index_bytes().to_vec();
    let last = changed.last_mut().ok_or("empty index")?; *last ^= 1;
    assert_eq!(verify_hevc_catalog(c.manifest(), &changed, &basis).err(), Some(E::Digest));
    let mut extra = c.index_bytes().to_vec(); extra.push(0);
    assert!(verify_hevc_catalog(c.manifest(), &extra, &basis).is_err());
    let no_leaves = ObjectManifest::new(HEVC_CATALOG_KIND, [h.manifest().root()],
        Some(ContentDigest::sha256(c.index_bytes())))?;
    assert_eq!(verify_hevc_catalog(&no_leaves, c.index_bytes(), &basis).err(), Some(E::Digest));
    let roots = [ContentDigest::sha256(b"unrelated source with plausible time")];
    let changed = index("fss.hevc_recording_catalog.v1", &basis, &[(&a, h.publication_plan())], Some(&roots))?;
    let root = manifest(HEVC_CATALOG_KIND, &changed, &[h.publication_plan()], Some(&roots))?;
    assert_eq!(verify_hevc_catalog(&root, &changed, &basis).err(), Some(E::Digest));
    assert_eq!(verify_hevc_catalog(c.manifest(), &vec![0; MAX_CATALOG_BYTES + 1], &basis).err(), Some(E::Limit));
    Ok(())
}

#[test]
fn catalog_capacity_empty_pages_and_deterministic_replay_have_fixed_bounds() -> TestResult {
    assert_eq!(HevcCatalogBuilder::new(scope()?)?.prepare().err(), Some(E::Limit));
    let mut builder = HevcCatalogBuilder::new(scope()?)?;
    for i in 0..MAX_CATALOG_WINDOWS {
        builder.push(&slot(i)?, &window(i as u64 * 72_000)?)?;
    }
    assert_eq!(builder.push(&slot(MAX_CATALOG_WINDOWS)?, &window(MAX_CATALOG_WINDOWS as u64 * 72_000)?), Err(E::Limit));
    assert_eq!(builder.len(), MAX_CATALOG_WINDOWS);
    let full = builder.prepare()?;
    assert!(full.byte_len() <= MAX_CATALOG_BYTES);
    let a = pair()?; let b = pair()?;
    assert_eq!(a.manifest(), b.manifest()); assert_eq!(a.index_bytes(), b.index_bytes());
    assert_eq!(a.select(1_000..172_000, CatalogQueryLimits::default())?,
        b.select(1_000..172_000, CatalogQueryLimits::default())?);
    Ok(())
}
