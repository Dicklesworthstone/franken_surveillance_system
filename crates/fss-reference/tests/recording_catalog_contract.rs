#![forbid(unsafe_code)]
//! Canonical recording catalogs: exact time basis, half-open range selection and budget refusals.

mod collector_support;
use collector_support::*;
use fss_core::{CanonicalEncode, ContentDigest};
use fss_object::ObjectManifest;
use fss_publication::SlotName;
use fss_reference::rtsp::recording::PreparedRecording;
use fss_reference::rtsp::recording_collector::CollectorLimits;
use fss_reference::rtsp::recording_catalog::*;

fn window(seq: u64, dts: u64) -> Result<PreparedRecording, Error> {
    let mut c = collector(CollectorLimits::default())?;
    let a = sample(seq, 90_000 + seq as u32 * 3600, true, seq.is_multiple_of(2))?;
    a.source(&mut c, 1)?; accepted(c.push_picture(a.timed(dts), 1))?;
    c.seal(2)?; c.take_ready().ok_or_else(|| "missing window".into())
}
fn catalog_scope() -> Result<CatalogScope, Error> {
    Ok(CatalogScope { recording: scope()?, decode_clock: ContentDigest::try_sha256(b"explicit-dts-epoch")?, time_scale: 90_000 })
}
fn pair() -> Result<RecordingCatalog, Error> {
    let a = window(1, 3600)?; let b = window(3, 10800)?;
    Ok(prepare_catalog(catalog_scope()?, &[
        CatalogWindow { slot: &SlotName::parse("first")?, recording: &a },
        CatalogWindow { slot: &SlotName::parse("second")?, recording: &b },
    ])?)
}
#[test]
fn canonical_roundtrip_pins_every_leaf_and_exact_time_basis() -> TestResult {
    let c = pair()?;
    let decoded = verify_catalog(c.manifest(), c.index_bytes(), &catalog_scope()?)?;
    assert_eq!(decoded.index_bytes(), c.index_bytes()); assert_eq!(decoded.entries(), c.entries());
    assert_eq!(decoded.manifest(), c.manifest());
    assert!(c.byte_len() < MAX_CATALOG_BYTES);
    let a = window(1, 3600)?;
    assert!(c.manifest().children().contains(&a.manifest().root()));
    for (_, d, _) in a.children() { assert!(c.manifest().children().contains(&d)); }
    Ok(())
}
#[test]
fn range_selects_full_windows_and_reports_internal_and_external_unknowns() -> TestResult {
    let c = pair()?; let s = c.select(0..18000, CatalogQueryLimits::default())?;
    assert_eq!(s.windows().len(), 2);
    assert_eq!(s.windows()[0].requested_interval(), 3600..7200);
    assert_eq!(s.unindexed(), &[0..3600, 7200..10800, 14400..18000]);
    assert_eq!(s.output_bytes(), c.entries().iter().map(|e| e.byte_len() as u64).sum::<u64>());
    Ok(())
}
#[test]
fn half_open_boundaries_do_not_double_select_neighbors() -> TestResult {
    let c = pair()?;
    assert!(c.select(7200..10800, CatalogQueryLimits::default())?.windows().is_empty());
    let s = c.select(5000..11000, CatalogQueryLimits::default())?;
    assert_eq!(s.windows()[0].requested_interval(), 5000..7200);
    assert_eq!(s.windows()[1].requested_interval(), 10800..11000);
    assert_eq!(s.unindexed(), std::slice::from_ref(&(7200..10800)));
    Ok(())
}
#[test]
fn budget_failure_never_becomes_a_truncated_success() -> TestResult {
    let c = pair()?;
    assert_eq!(c.select(0..18000, CatalogQueryLimits { max_windows: 1, ..CatalogQueryLimits::default() }), Err(CatalogError::Limit));
    let total = c.select(0..18000, CatalogQueryLimits::default())?.output_bytes();
    assert_eq!(c.select(0..18000, CatalogQueryLimits { max_output_bytes: total - 1, ..CatalogQueryLimits::default() }), Err(CatalogError::Limit));
    assert!(c.select(0..18000, CatalogQueryLimits { max_output_bytes: total, ..CatalogQueryLimits::default() }).is_ok());
    Ok(())
}
#[test]
fn empty_index_answer_is_unknown_not_absence() -> TestResult {
    let c = pair()?; let s = c.select(20_000..u64::MAX, CatalogQueryLimits::default())?;
    assert!(s.windows().is_empty()); assert_eq!(s.output_bytes(), 0);
    assert_eq!(s.unindexed(), std::slice::from_ref(&(20_000..u64::MAX)));
    assert_eq!(c.select(5..5, CatalogQueryLimits::default()), Err(CatalogError::Interval));
    assert_eq!(c.select(std::ops::Range { start: 6, end: 5 }, CatalogQueryLimits::default()), Err(CatalogError::Interval));
    Ok(())
}
#[test]
fn overlapping_unordered_and_duplicate_slots_are_refused() -> TestResult {
    let a = window(1, 3600)?; let b = window(3, 5000)?;
    let x = SlotName::parse("x")?; let y = SlotName::parse("y")?;
    assert!(matches!(prepare_catalog(catalog_scope()?, &[
        CatalogWindow { slot: &x, recording: &a }, CatalogWindow { slot: &y, recording: &b }]), Err(CatalogError::Order)));
    let b = window(3, 10800)?;
    assert!(matches!(prepare_catalog(catalog_scope()?, &[
        CatalogWindow { slot: &x, recording: &b }, CatalogWindow { slot: &y, recording: &a }]), Err(CatalogError::Order)));
    assert!(matches!(prepare_catalog(catalog_scope()?, &[
        CatalogWindow { slot: &x, recording: &a }, CatalogWindow { slot: &x, recording: &b }]), Err(CatalogError::Order)));
    Ok(())
}
#[test]
fn exact_scope_timebase_and_generation_are_not_inferred_from_the_page() -> TestResult {
    let c = pair()?;
    for field in 0..5 {
        let mut s = catalog_scope()?;
        match field {
            0 => s.recording.generation += 1,
            1 => s.time_scale += 1,
            2 => s.decode_clock = ContentDigest::try_sha256(b"other-decode-clock")?,
            3 => s.recording.receive_clock = ContentDigest::try_sha256(b"other-receive-clock")?,
            _ => s.recording.anchor = ContentDigest::try_sha256(b"other-authority")?,
        }
        assert!(matches!(verify_catalog(c.manifest(), c.index_bytes(), &s), Err(CatalogError::Scope)));
    }
    Ok(())
}
#[test]
fn every_truncation_and_single_byte_change_is_refused() -> TestResult {
    let c = pair()?;
    for cut in 0..c.index_bytes().len() {
        assert!(verify_catalog(c.manifest(), &c.index_bytes()[..cut], &catalog_scope()?).is_err());
    }
    for i in 0..c.index_bytes().len() {
        let mut bytes = c.index_bytes().to_vec(); bytes[i] ^= 1;
        assert!(verify_catalog(c.manifest(), &bytes, &catalog_scope()?).is_err());
    }
    Ok(())
}
#[test]
fn rehashed_root_cannot_hide_an_omitted_original_object() -> TestResult {
    let c = pair()?; let meta = c.manifest().metadata_digest().ok_or("metadata")?;
    let mut children: Vec<_> = c.manifest().children().iter().copied().filter(|d| *d != meta).collect();
    children.remove(0);
    let altered = ObjectManifest::new(CATALOG_KIND, children, Some(meta))?;
    assert!(matches!(verify_catalog(&altered, c.index_bytes(), &catalog_scope()?), Err(CatalogError::Digest)));
    assert_ne!(altered.canonical_bytes(), c.manifest().canonical_bytes());
    Ok(())
}
#[test]
fn page_count_limit_is_refused_before_copying_unbounded_inputs() -> TestResult {
    let a = window(1, 3600)?; let slot = SlotName::parse("a")?;
    assert!(matches!(prepare_catalog(catalog_scope()?, &[]), Err(CatalogError::Limit)));
    let inputs: Vec<_> = (0..MAX_CATALOG_WINDOWS + 1).map(|_| CatalogWindow { slot: &slot, recording: &a }).collect();
    assert!(matches!(prepare_catalog(catalog_scope()?, &inputs), Err(CatalogError::Limit)));
    Ok(())
}
#[test]
fn query_partition_covers_each_tick_exactly_once() -> TestResult {
    let c = pair()?;
    for start in (0..16000).step_by(700) {
        for width in [1, 3599, 3600, 7201] {
            let end = start + width;
            let s = c.select(start..end, CatalogQueryLimits::default())?;
            let mut parts = s.unindexed().to_vec();
            parts.extend(s.windows().iter().map(SelectedWindow::requested_interval));
            parts.sort_by_key(|r| r.start);
            assert_eq!(parts.first().ok_or("partition")?.start, start);
            assert_eq!(parts.last().ok_or("partition")?.end, end);
            for adjacent in parts.windows(2) { assert_eq!(adjacent[0].end, adjacent[1].start); }
        }
    }
    Ok(())
}

#[test]
fn incremental_builder_retains_only_metadata_and_refusal_does_not_advance() -> TestResult {
    let mut b = CatalogBuilder::new(catalog_scope()?)?;
    assert!(b.is_empty());
    {
        let first = window(1, 3600)?;
        b.push(&SlotName::parse("first")?, &first)?;
        assert_eq!(b.push(&SlotName::parse("first")?, &first), Err(CatalogError::Order));
        assert_eq!(b.len(), 1);
    }
    let second = window(3, 10800)?;
    b.push(&SlotName::parse("second")?, &second)?;
    drop(second);
    let catalog = b.prepare()?;
    assert_eq!(catalog.index_bytes(), pair()?.index_bytes());
    Ok(())
}
