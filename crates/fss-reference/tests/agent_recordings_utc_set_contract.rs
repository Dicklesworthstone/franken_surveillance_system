#![forbid(unsafe_code)]
//! Native UTC lookup across catalog pages retains one clock universe and shared read budget.

#[path = "recording_clock_contract/support.rs"]
mod clock_support;
mod collector_support;
#[path = "agent_recordings_utc_contract/support.rs"]
mod fixture;
mod hevc_catalog_support;
mod hevc_recording_support;
mod recording_support;

use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use fixture::{Fixture, NativeWindow, TestResult};
use fss_core::ContentDigest;
use fss_object::{HostSpoolIo, ObjectManifest, RecordingSpoolIo, SpoolIoCall};
use fss_publication::custody_audit::CustodyAuditError;
use fss_publication::custody_audit::pinned_metadata::PinnedMetadataError;
use fss_publication::{SlotName, read_verified_with_io, root_record_bytes};
use fss_reference::agent_recordings::RecordingQueryCodec;
use fss_reference::agent_recordings::set::RecordingCatalogPin;
use fss_reference::agent_recordings::utc::RecordingUtcQueryError as E;
use fss_reference::agent_recordings::utc_set::{
    RecordingUtcSetQuery, RecordingUtcSetQueryLimits, RecordingUtcSetQueryRequest,
    query_recordings_utc_set,
};
use fss_reference::rtsp::recording_catalog::hevc::{HevcCatalogWindow, prepare_hevc_catalog};
use fss_reference::rtsp::recording_catalog::{CatalogError, CatalogWindow, prepare_catalog};

fn publish_catalog(f: &Fixture, name: &str, members: &[usize]) -> TestResult<RecordingCatalogPin> {
    let (manifest, bytes) = match f.request.codec {
        RecordingQueryCodec::Avc => {
            let entries = members
                .iter()
                .map(|index| CatalogWindow {
                    slot: &f.windows[*index].0,
                    recording: f.windows[*index].1.plan(),
                })
                .collect::<Vec<_>>();
            let catalog = prepare_catalog(f.scope().clone(), &entries)?;
            (catalog.manifest().clone(), catalog.index_bytes().to_vec())
        }
        RecordingQueryCodec::Hevc => {
            let mut entries = Vec::new();
            for index in members {
                let (slot, NativeWindow::Hevc(recording)) = &f.windows[*index] else {
                    return Err("expected HEVC fixture".into());
                };
                entries.push(HevcCatalogWindow { slot, recording });
            }
            let catalog = prepare_hevc_catalog(f.scope().clone(), &entries)?;
            (catalog.manifest().clone(), catalog.index_bytes().to_vec())
        }
    };
    let slot = SlotName::parse(name)?;
    f.put(&bytes)?;
    f.publish(&slot, &manifest)?;
    Ok(RecordingCatalogPin {
        slot,
        root: manifest.root(),
    })
}

fn request(f: &Fixture, catalogs: Vec<RecordingCatalogPin>) -> RecordingUtcSetQueryRequest {
    RecordingUtcSetQueryRequest {
        codec: f.request.codec,
        scope: f.request.scope.clone(),
        catalogs,
        clock_slot: f.request.clock_slot.clone(),
        clock_root: f.request.clock_root,
        interval: f.request.interval.clone(),
        max_windows: f.request.max_windows,
        max_hydration_bytes: f.request.max_hydration_bytes,
    }
}

fn query(f: &Fixture, request: &RecordingUtcSetQueryRequest) -> Result<RecordingUtcSetQuery, E> {
    query_recordings_utc_set(
        &HostSpoolIo,
        &f.root,
        request,
        RecordingUtcSetQueryLimits::default(),
        &|| false,
    )
}

#[test]
fn clock_index_spanning_eight_window_capture_pages_is_queryable_for_both_codecs() -> TestResult {
    for codec in [RecordingQueryCodec::Avc, RecordingQueryCodec::Hevc] {
        // Exercise both the first page boundary and the entire admitted capture universe.
        for count in [9, 64] {
            let admissions = (0..count)
                .map(|i| 40_000_000 + 500_000 * i as u64)
                .collect::<Vec<_>>();
            let all = (0..count).collect::<Vec<_>>();
            let mut f = Fixture::with_admissions("paged-capture", codec, &admissions, &all)?;
            let mut pages = Vec::new();
            for (page, members) in all.chunks(8).enumerate() {
                pages.push(publish_catalog(
                    &f,
                    &format!("capture-page-{:06}", page * 8),
                    members,
                )?);
            }
            f.request.catalog_slot = pages[0].slot.clone();
            f.request.catalog_root = pages[0].root;
            // Legacy singleton semantics remain strict rather than dropping later clock rows.
            assert!(matches!(f.query(), Err(E::ClockCatalogMismatch)));
            let last = f.clock.windows()[count - 1].utc_interval();
            let mut r = request(&f, pages);
            r.interval = last.earliest_ns..last.latest_ns + 1;
            let selected = query(&f, &r)?;
            assert_eq!(selected.scanned_windows, count);
            assert_eq!(selected.unique_windows, count);
            assert_eq!(selected.clock_windows, count);
            assert_eq!(
                selected.read_usage.pinned_roots,
                count + r.catalogs.len() + 1
            );
            assert_eq!(
                selected.read_usage.metadata_objects,
                count + 2 * r.catalogs.len() + 2
            );
            let final_row = selected
                .rows
                .iter()
                .find(|row| row.entry.slot() == &f.windows[count - 1].0)
                .ok_or("last capture-page window was lost")?;
            assert_eq!(final_row.clock_ordinal, Some(count - 1));
            assert_eq!(final_row.utc_interval, Some(last));
            assert_eq!(final_row.locations.len(), 1);
            assert_eq!(final_row.locations[0].catalog_index, (count - 1) / 8);
            assert_eq!(final_row.locations[0].ordinal, (count - 1) % 8);
            assert!(selected.indexed_gaps.is_empty());
            for leaf in &f.leaves {
                assert!(!f.object(*leaf).exists());
                assert!(selected.reference_digests.contains(leaf));
            }
            r.catalogs.reverse();
            assert_eq!(query(&f, &r)?, selected);
        }
    }
    Ok(())
}

#[test]
fn overlapping_pages_deduplicate_quotes_preserve_all_memberships_and_read_no_source() -> TestResult
{
    for codec in [RecordingQueryCodec::Avc, RecordingQueryCodec::Hevc] {
        let f = Fixture::new("overlapping-pages", codec, &[0, 2])?;
        let r = request(
            &f,
            vec![
                publish_catalog(&f, "a-page", &[0, 1])?,
                publish_catalog(&f, "b-page", &[1, 2])?,
            ],
        );
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        let selected = query_recordings_utc_set(
            &io,
            &f.root,
            &r,
            RecordingUtcSetQueryLimits::default(),
            &|| false,
        )?;
        assert_eq!(selected.scanned_windows, 4);
        assert_eq!(selected.unique_windows, 3);
        assert_eq!(selected.rows.len(), 2);
        assert_eq!(selected.rows[0].entry.slot(), &f.windows[0].0);
        let shared = &selected.rows[1];
        assert_eq!(shared.entry.slot(), &f.windows[1].0);
        assert_eq!(shared.clock_ordinal, None);
        assert_eq!(shared.utc_interval, None);
        assert_eq!(shared.locations.len(), 2);
        assert_eq!(shared.locations[0].catalog_index, 0);
        assert_eq!(shared.locations[0].ordinal, 1);
        assert_eq!(shared.locations[1].catalog_index, 1);
        assert_eq!(shared.locations[1].ordinal, 0);
        assert_eq!(
            selected.quoted_hydration_bytes,
            selected
                .rows
                .iter()
                .map(|row| row.entry.byte_len() as u64)
                .sum::<u64>()
        );
        assert_eq!(selected.read_usage.io_calls, io.calls().len() as u64);
        assert_eq!(io.call_count(SpoolIoCall::ReadDir), 0);
        assert_eq!(io.call_count(SpoolIoCall::NextDirEntry), 0);
        assert!(io.is_read_only());
        assert!(!f.root.join("LOCK").exists());
        // A successful metadata observation still makes no claim about original bytes.
        for leaf in &f.leaves {
            assert!(!f.object(*leaf).exists());
            fs::write(f.object(*leaf), b"unread corrupt source payload")?;
        }
        assert_eq!(query(&f, &r)?, selected);
        let mut changed = shared.clone();
        changed.locations.remove(0);
        assert_ne!(changed.row_digest(), shared.row_digest());
        changed = shared.clone();
        changed.clock_ordinal = Some(0);
        assert_ne!(changed.row_digest(), shared.row_digest());
    }
    Ok(())
}

#[test]
fn unknown_clocks_survive_an_unrelated_utc_interval_and_consume_both_output_quotas() -> TestResult {
    let f = Fixture::new("unknown-clock", RecordingQueryCodec::Avc, &[0, 2])?;
    let mut r = request(
        &f,
        vec![
            publish_catalog(&f, "a-page", &[0])?,
            publish_catalog(&f, "b-page", &[1, 2])?,
        ],
    );
    r.interval = 0..100;
    r.max_windows = 1;
    let result = query(&f, &r)?;
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].entry.slot(), &f.windows[1].0);
    assert_eq!(result.rows[0].utc_interval, None);
    assert_eq!(result.indexed_gaps, vec![0..100]);
    r.max_hydration_bytes = result.quoted_hydration_bytes - 1;
    assert!(matches!(
        query(&f, &r),
        Err(E::Catalog(CatalogError::Limit))
    ));
    r.max_hydration_bytes = f.request.max_hydration_bytes;
    r.interval = f.request.interval.clone();
    assert!(matches!(
        query(&f, &r),
        Err(E::Catalog(CatalogError::Limit))
    ));
    Ok(())
}

#[test]
fn singleton_selection_matches_legacy_results_without_changing_legacy_identities() -> TestResult {
    for codec in [RecordingQueryCodec::Avc, RecordingQueryCodec::Hevc] {
        let f = Fixture::new("singleton-parity", codec, &[0, 2])?;
        let legacy = f.query()?;
        let r = request(
            &f,
            vec![RecordingCatalogPin {
                slot: f.request.catalog_slot.clone(),
                root: f.request.catalog_root,
            }],
        );
        let result = query(&f, &r)?;
        assert_eq!(result.clock_root, legacy.clock_root);
        assert_eq!(result.clock_metadata_digest, legacy.clock_metadata_digest);
        assert_eq!(result.clock_approval_digest, legacy.clock_approval_digest);
        assert_eq!(result.clock_policy, legacy.clock_policy);
        assert_eq!(result.clock_offset, legacy.clock_offset);
        assert_eq!(result.clock_brackets, legacy.clock_brackets);
        assert_eq!(result.clock_windows, legacy.clock_windows);
        assert_eq!(result.indexed_gaps, legacy.indexed_gaps);
        assert_eq!(result.quoted_hydration_bytes, legacy.quoted_hydration_bytes);
        assert_eq!(result.rows.len(), legacy.rows.len());
        for (row, original) in result.rows.iter().zip(&legacy.rows) {
            assert_eq!(row.entry, original.entry);
            assert_eq!(row.clock_ordinal, original.clock_ordinal);
            assert_eq!(row.utc_interval, original.utc_interval);
            assert_eq!(row.locations[0].ordinal, original.ordinal);
        }
        assert_eq!(f.query()?, legacy);
    }
    Ok(())
}

#[test]
fn utc_edges_and_union_gaps_use_closed_envelopes_with_half_open_query_bounds() -> TestResult {
    let f = Fixture::new("utc-edges", RecordingQueryCodec::Avc, &[0, 1, 2])?;
    let mut r = request(
        &f,
        vec![
            publish_catalog(&f, "a-page", &[0, 1])?,
            publish_catalog(&f, "b-page", &[2])?,
        ],
    );
    let bounds = f.clock.windows()[0].utc_interval();
    for at in [bounds.earliest_ns, bounds.latest_ns] {
        r.interval = at..at + 1;
        assert_eq!(query(&f, &r)?.rows[0].entry.slot(), &f.windows[0].0);
    }
    r.interval = bounds.latest_ns + 1..bounds.latest_ns + 2;
    assert!(
        query(&f, &r)?
            .rows
            .iter()
            .all(|row| row.entry.slot() != &f.windows[0].0)
    );
    r.interval = 0..1;
    let empty = query(&f, &r)?;
    assert!(empty.rows.is_empty());
    assert_eq!(empty.indexed_gaps, vec![0..1]);
    r.interval = bounds.earliest_ns..f.clock.windows()[2].utc_interval().latest_ns + 1;
    let all = query(&f, &r)?;
    assert_eq!(all.rows.len(), 3);
    let expected = f
        .clock
        .windows()
        .windows(2)
        .filter_map(|w| {
            let start = w[0].utc_interval().latest_ns + 1;
            let end = w[1].utc_interval().earliest_ns;
            (start < end).then_some(start..end)
        })
        .collect::<Vec<_>>();
    assert_eq!(all.indexed_gaps, expected);
    Ok(())
}

#[test]
fn invalid_catalog_sets_clock_slots_and_bounds_are_refused_before_io() -> TestResult {
    let f = Fixture::new("invalid-request", RecordingQueryCodec::Avc, &[0, 2])?;
    let good = request(
        &f,
        vec![RecordingCatalogPin {
            slot: f.request.catalog_slot.clone(),
            root: f.request.catalog_root,
        }],
    );
    for mutation in 0..9 {
        let mut r = good.clone();
        match mutation {
            0 => r.catalogs.clear(),
            1 => r.catalogs.push(r.catalogs[0].clone()),
            2 => r.catalogs = vec![r.catalogs[0].clone(); 9],
            3 => r.clock_slot = SlotName::parse("other-clock")?,
            4 => r.scope.recording.generation = 0,
            5 => r.interval = 2..2,
            6 => r.max_windows = 0,
            7 => r.max_hydration_bytes = 0,
            _ => r.scope.time_scale = 0,
        }
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        assert!(matches!(
            query_recordings_utc_set(
                &io,
                &f.root,
                &r,
                RecordingUtcSetQueryLimits::default(),
                &|| false,
            ),
            Err(E::InvalidRequest)
        ));
        assert!(io.calls().is_empty(), "mutation {mutation}");
    }
    let mut limits = RecordingUtcSetQueryLimits::default();
    limits.max_scanned_windows += 1;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    assert!(matches!(
        query_recordings_utc_set(&io, &f.root, &good, limits, &|| false),
        Err(E::InvalidRequest)
    ));
    assert!(io.calls().is_empty());
    Ok(())
}

#[test]
fn a_clock_member_outside_the_complete_selected_union_refuses_even_an_empty_time_result()
-> TestResult {
    let f = Fixture::new("foreign-clock-member", RecordingQueryCodec::Avc, &[0, 2])?;
    let mut r = request(
        &f,
        vec![
            publish_catalog(&f, "a-page", &[0])?,
            publish_catalog(&f, "b-page", &[1])?,
        ],
    );
    r.interval = 0..1;
    assert!(matches!(query(&f, &r), Err(E::ClockCatalogMismatch)));
    Ok(())
}

#[test]
fn conflicting_catalog_descriptors_for_the_same_root_are_never_deduplicated() -> TestResult {
    let f = Fixture::new("conflicting-member", RecordingQueryCodec::Avc, &[0, 2])?;
    let alias = SlotName::parse("aliased-original-window")?;
    f.publish(&alias, f.windows[0].1.plan().manifest())?;
    let conflict = prepare_catalog(
        f.scope().clone(),
        &[CatalogWindow {
            slot: &alias,
            recording: f.windows[0].1.plan(),
        }],
    )?;
    f.put(conflict.index_bytes())?;
    let slot = SlotName::parse("z-conflicting-page")?;
    f.publish(&slot, conflict.manifest())?;
    let r = request(
        &f,
        vec![
            RecordingCatalogPin {
                slot: f.request.catalog_slot.clone(),
                root: f.request.catalog_root,
            },
            RecordingCatalogPin {
                slot,
                root: conflict.root(),
            },
        ],
    );
    assert!(matches!(
        query(&f, &r),
        Err(E::Catalog(CatalogError::WindowMismatch))
    ));
    Ok(())
}

#[test]
fn all_pages_clock_and_final_revalidation_consume_one_nonrefillable_allowance() -> TestResult {
    let f = Fixture::new("shared-budget", RecordingQueryCodec::Avc, &[0, 2])?;
    let r = request(
        &f,
        vec![
            publish_catalog(&f, "a-page", &[0, 1])?,
            publish_catalog(&f, "b-page", &[1, 2])?,
        ],
    );
    let baseline = query(&f, &r)?;
    for mutation in 0..4 {
        let mut limits = RecordingUtcSetQueryLimits::default();
        match mutation {
            0 => limits.max_scanned_windows = baseline.scanned_windows - 1,
            1 => limits.metadata.max_io_calls = baseline.read_usage.io_calls - 1,
            2 => limits.metadata.max_read_bytes = baseline.read_usage.read_bytes - 1,
            _ => limits.metadata.max_catalogue_entries = baseline.read_usage.pinned_roots - 1,
        }
        let result = query_recordings_utc_set(&HostSpoolIo, &f.root, &r, limits, &|| false);
        assert!(result.is_err(), "shared budget mutation {mutation}");
    }
    let mut exact = RecordingUtcSetQueryLimits::default();
    exact.max_scanned_windows = baseline.scanned_windows;
    exact.metadata.max_io_calls = baseline.read_usage.io_calls;
    exact.metadata.max_read_bytes = baseline.read_usage.peak_reserved_read_bytes;
    assert!(query_recordings_utc_set(&HostSpoolIo, &f.root, &r, exact, &|| false).is_ok());
    Ok(())
}

#[test]
fn unselected_members_and_late_pages_remain_part_of_tombstone_and_metadata_checks() -> TestResult {
    for corrupt_metadata in [false, true] {
        let f = Fixture::new("unselected-check", RecordingQueryCodec::Avc, &[0, 1, 2])?;
        let mut r = request(
            &f,
            vec![
                publish_catalog(&f, "a-page", &[0, 1])?,
                publish_catalog(&f, "b-page", &[2])?,
            ],
        );
        r.interval = 0..1;
        assert!(query(&f, &r)?.rows.is_empty());
        if corrupt_metadata {
            fs::write(f.object(r.catalogs[1].root), b"corrupt unselected page")?;
        } else {
            let (_, leaf, _) = f.windows[2].1.plan().children()[0];
            fs::write(f.tombstone(leaf), b"deleted unselected source")?;
        }
        assert!(query(&f, &r).is_err());
    }
    Ok(())
}

#[test]
fn final_global_pass_rejects_earlier_page_and_clock_rebinding_and_late_tombstones() -> TestResult {
    for mutation_kind in 0..4 {
        let f = Fixture::new("final-pass", RecordingQueryCodec::Avc, &[0, 1, 2])?;
        let mut r = request(
            &f,
            vec![
                publish_catalog(&f, "a-page", &[0])?,
                publish_catalog(&f, "b-page", &[1, 2])?,
            ],
        );
        r.interval = 0..1;
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        let injected = AtomicBool::new(false);
        let first = &r.catalogs[0];
        let manifest_bytes =
            read_verified_with_io(&f.root, first.root, 16 * 1024 * 1024, &HostSpoolIo)?;
        let manifest = ObjectManifest::from_canonical_bytes(&manifest_bytes)?;
        let replacement = root_record_bytes(
            &first.slot,
            ContentDigest::sha256(b"changed-earlier-page"),
            manifest.children().len(),
        )?;
        let clock_replacement = root_record_bytes(
            &r.clock_slot,
            ContentDigest::sha256(b"changed-clock-index"),
            f.clock.manifest().children().len(),
        )?;
        let clock_metadata = f
            .clock
            .manifest()
            .metadata_digest()
            .ok_or("clock metadata")?;
        let (_, leaf, _) = f.windows[0].1.plan().children()[0];
        let mutation = || {
            // Fifteen first-pass opens admitted both pages, every member and the clock.
            // Inject during final rehashing; no already-observed prefix can escape review.
            if io.call_count(SpoolIoCall::OpenRead) >= 16 && !injected.swap(true, Ordering::SeqCst)
            {
                return match mutation_kind {
                    0 => fs::write(
                        f.root
                            .join("roots")
                            .join(format!("{}.root", first.slot.as_str())),
                        &replacement,
                    )
                    .is_err(),
                    1 => fs::write(
                        f.root
                            .join("roots")
                            .join(format!("{}.root", r.clock_slot.as_str())),
                        &clock_replacement,
                    )
                    .is_err(),
                    2 => fs::write(f.tombstone(leaf), b"late source deletion").is_err(),
                    _ => fs::write(f.tombstone(clock_metadata), b"late clock deletion").is_err(),
                };
            }
            false
        };
        let result = query_recordings_utc_set(
            &io,
            &f.root,
            &r,
            RecordingUtcSetQueryLimits::default(),
            &mutation,
        );
        assert!(injected.load(Ordering::SeqCst));
        assert!(matches!(
            result,
            Err(E::Storage(
                PinnedMetadataError::Changed | PinnedMetadataError::Tombstoned
            ))
        ));
    }
    Ok(())
}

#[test]
fn cancellation_before_io_or_during_later_metadata_never_returns_a_partial_page() -> TestResult {
    let f = Fixture::new("cancelled", RecordingQueryCodec::Avc, &[0, 2])?;
    let r = request(
        &f,
        vec![
            publish_catalog(&f, "a-page", &[0])?,
            publish_catalog(&f, "b-page", &[1, 2])?,
        ],
    );
    for late in [false, true] {
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        let result = query_recordings_utc_set(
            &io,
            &f.root,
            &r,
            RecordingUtcSetQueryLimits::default(),
            &|| !late || io.call_count(SpoolIoCall::OpenRead) >= 10,
        );
        assert!(matches!(
            result,
            Err(E::Storage(PinnedMetadataError::Audit(
                CustodyAuditError::Cancelled
            )))
        ));
        if !late {
            assert!(io.calls().is_empty());
        }
    }
    Ok(())
}
