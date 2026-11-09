#![forbid(unsafe_code)]
//! Whole-namespace UTC lookup keeps clock uncertainty, complete custody and one read budget.

#[path = "recording_clock_contract/support.rs"]
mod clock_support;
mod collector_support;
mod hevc_catalog_support;
mod hevc_recording_support;
mod recording_support;
#[path = "agent_recordings_utc_discovery_contract/support.rs"]
mod support;
#[path = "agent_recordings_utc_contract/support.rs"]
mod utc_support;

use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use fss_core::ContentDigest;
use fss_object::{HostSpoolIo, RecordingSpoolIo, SpoolIoCall};
use fss_publication::custody_audit::CustodyAuditError;
use fss_publication::custody_audit::pinned_metadata::PinnedMetadataError;
use fss_publication::{SlotName, root_record_bytes};
use fss_reference::agent_recordings::RecordingQueryCodec;
use fss_reference::agent_recordings::discover::{
    RecordingDiscoveryError as D, RecordingDiscoveryLimits, RecordingDiscoveryRequest,
    discover_recordings,
};
use fss_reference::agent_recordings::set::RecordingCatalogPin;
use fss_reference::agent_recordings::utc::RecordingUtcQueryError as U;
use fss_reference::agent_recordings::utc_discover::{
    RecordingUtcDiscoveryError as E, RecordingUtcDiscoveryLimits, discover_recordings_utc,
};
use fss_reference::agent_recordings::utc_set::{
    RecordingUtcSetQueryLimits, RecordingUtcSetQueryRequest, query_recordings_utc_set,
};
use fss_reference::rtsp::recording_catalog::CatalogError;
use support::{Fixture, TestResult, namespace_slot};

#[test]
fn discovers_native_capture_pages_and_binds_the_entire_clock_without_manual_pins() -> TestResult {
    for codec in [RecordingQueryCodec::Avc, RecordingQueryCodec::Hevc] {
        for count in [9, 64, 65] {
            let clocked = (0..count.min(64)).collect::<Vec<_>>();
            let fixture = Fixture::new("capture-pages", codec, count, 8, &clocked)?;
            let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
            let result =
                fixture.query_with(&io, RecordingUtcDiscoveryLimits::default(), &|| false)?;
            assert_eq!(result.catalogs.len(), count.div_ceil(8));
            assert_eq!(result.scanned_windows, count);
            assert_eq!(result.unique_windows, count);
            assert_eq!(result.clock_windows, clocked.len());
            assert_eq!(result.rows.len(), count - clocked.len() + 1);
            assert_eq!(
                result.rows[0].entry.slot(),
                &fixture.windows[clocked.len() - 1].0
            );
            assert_eq!(result.rows[0].clock_ordinal, Some(clocked.len() - 1));
            if count == 65 {
                let unknown = &result.rows[1];
                assert_eq!(unknown.entry.slot(), &fixture.windows[64].0);
                assert_eq!(unknown.clock_ordinal, None);
                assert_eq!(unknown.utc_interval, None);
                assert_eq!(unknown.locations[0].catalog_index, 8);
                assert_eq!(unknown.locations[0].ordinal, 0);
            }
            assert!(result.indexed_gaps.is_empty());
            assert_eq!(
                result.scanned_root_entries,
                count + result.catalogs.len() + 1
            );
            assert_eq!(
                result.read_usage.pinned_roots,
                count + result.catalogs.len() + 1
            );
            assert_eq!(
                result.read_usage.metadata_objects,
                count + 2 * result.catalogs.len() + 2
            );
            assert_eq!(result.read_usage.io_calls, io.calls().len() as u64);
            assert_eq!(io.call_count(SpoolIoCall::ReadDir), 2);
            assert!(io.is_read_only());
            assert!(!fixture.root.join("LOCK").exists());
            for leaf in &fixture.leaves {
                assert!(result.reference_digests.contains(leaf));
                assert!(!fixture.object(*leaf).exists());
                fs::write(
                    fixture.object(*leaf),
                    b"corrupt source payload must remain unread",
                )?;
            }
            assert_eq!(fixture.query()?, result);
        }
    }
    Ok(())
}

#[test]
fn shared_selection_matches_explicit_utc_and_discovery_inventory_keeps_its_identity() -> TestResult
{
    for codec in [RecordingQueryCodec::Avc, RecordingQueryCodec::Hevc] {
        let fixture = Fixture::new("selection-parity", codec, 9, 8, &[0, 8])?;
        let discovered = fixture.query()?;
        let request = &fixture.request;
        let explicit = query_recordings_utc_set(
            &HostSpoolIo,
            &fixture.root,
            &RecordingUtcSetQueryRequest {
                codec,
                scope: request.scope.clone(),
                catalogs: fixture
                    .catalogs
                    .iter()
                    .rev()
                    .map(|catalog| RecordingCatalogPin {
                        slot: catalog.slot.clone(),
                        root: catalog.manifest.root(),
                    })
                    .collect(),
                clock_slot: request.clock_slot.clone(),
                clock_root: request.clock_root,
                interval: request.interval.clone(),
                max_windows: request.max_windows,
                max_hydration_bytes: request.max_hydration_bytes,
            },
            RecordingUtcSetQueryLimits::default(),
            &|| false,
        )?;
        assert_eq!(discovered.catalogs, explicit.catalogs);
        assert_eq!(discovered.rows, explicit.rows);
        assert_eq!(discovered.indexed_gaps, explicit.indexed_gaps);
        assert_eq!(discovered.reference_digests, explicit.reference_digests);
        assert_eq!(
            discovered.clock_metadata_digest,
            explicit.clock_metadata_digest
        );
        assert_eq!(discovered.clock_policy, explicit.clock_policy);
        assert_eq!(discovered.clock_offset, explicit.clock_offset);
        assert_eq!(
            discovered.quoted_hydration_bytes,
            explicit.quoted_hydration_bytes
        );
        assert_ne!(discovered.request_digest, explicit.request_digest);
        assert_ne!(discovered.decision_digest, explicit.decision_digest);
        let ticks = discover_recordings(
            &HostSpoolIo,
            &fixture.root,
            &RecordingDiscoveryRequest {
                codec,
                scope: request.scope.clone(),
                interval: 0..u64::MAX,
                max_windows: 64,
                max_hydration_bytes: request.max_hydration_bytes,
            },
            RecordingDiscoveryLimits::default(),
            &|| false,
        )?;
        assert_eq!(ticks.namespace_digest, discovered.namespace_digest);
        assert_eq!(ticks.inventory_digest, discovered.inventory_digest);
        assert_eq!(ticks.catalogs, discovered.catalogs);
        assert_eq!(ticks.scanned_windows, discovered.scanned_windows);
        assert_eq!(ticks.rows.len(), 9);
    }
    Ok(())
}

#[test]
fn a_large_unknown_clock_remainder_is_visible_and_charged_without_partial_success() -> TestResult {
    let clocked = (0..64).collect::<Vec<_>>();
    for count in [128, 129] {
        let mut fixture = Fixture::new(
            "unknown-remainder",
            RecordingQueryCodec::Avc,
            count,
            8,
            &clocked,
        )?;
        fixture.request.interval = 0..1;
        if count == 129 {
            assert!(matches!(
                fixture.query(),
                Err(E::Utc(U::Catalog(CatalogError::Limit)))
            ));
            continue;
        }
        let result = fixture.query()?;
        assert_eq!(result.catalogs.len(), 16);
        assert_eq!(result.scanned_windows, 128);
        assert_eq!(result.clock_windows, 64);
        assert_eq!(result.rows.len(), 64);
        assert_eq!(result.indexed_gaps, vec![0..1]);
        assert!(
            result
                .rows
                .iter()
                .all(|row| row.clock_ordinal.is_none() && row.utc_interval.is_none())
        );
        assert_eq!(result.rows[0].entry.slot(), &fixture.windows[64].0);
        assert_eq!(result.rows[63].entry.slot(), &fixture.windows[127].0);
        fixture.request.max_windows = 63;
        assert!(matches!(
            fixture.query(),
            Err(E::Utc(U::Catalog(CatalogError::Limit)))
        ));
        fixture.request.max_windows = 64;
        fixture.request.max_hydration_bytes = result.quoted_hydration_bytes - 1;
        assert!(matches!(
            fixture.query(),
            Err(E::Utc(U::Catalog(CatalogError::Limit)))
        ));
    }
    Ok(())
}

#[test]
fn an_empty_or_truncated_namespace_cannot_discard_any_nonempty_pinned_clock_member() -> TestResult {
    for empty in [false, true] {
        let all = (0..9).collect::<Vec<_>>();
        let mut fixture = Fixture::new("clock-universe", RecordingQueryCodec::Avc, 9, 8, &all)?;
        fixture.request.interval = 0..1;
        assert!(fixture.query()?.rows.is_empty());
        if empty {
            for catalog in &fixture.catalogs {
                fs::remove_file(fixture.record(&catalog.slot))?;
            }
            for (slot, _) in &fixture.windows {
                fs::remove_file(fixture.record(slot))?;
            }
        } else {
            fs::remove_file(fixture.record(&fixture.catalogs[1].slot))?;
            fs::remove_file(fixture.record(&fixture.windows[8].0))?;
        }
        assert!(matches!(
            fixture.query(),
            Err(E::Utc(U::ClockCatalogMismatch))
        ));
    }
    Ok(())
}

#[test]
fn all_namespace_members_and_pages_are_checked_even_outside_the_requested_utc_interval()
-> TestResult {
    for defect in 0..6 {
        let all = (0..9).collect::<Vec<_>>();
        let mut fixture = Fixture::new("unselected-refusal", RecordingQueryCodec::Avc, 9, 8, &all)?;
        fixture.request.interval = 0..1;
        assert!(fixture.query()?.rows.is_empty());
        match defect {
            0 => fs::remove_file(fixture.record(&fixture.catalogs[1].slot))?,
            1 => fs::remove_file(fixture.record(&fixture.windows[1].0))?,
            2 => fs::write(
                fixture
                    .record(&fixture.catalogs[1].slot)
                    .with_extension("root.tmp"),
                b"pending",
            )?,
            3 => fs::write(
                fixture.object(
                    fixture.catalogs[1]
                        .manifest
                        .metadata_digest()
                        .ok_or("index")?,
                ),
                b"corrupt page",
            )?,
            4 => fs::write(
                fixture.object(fixture.clock.manifest().metadata_digest().ok_or("clock")?),
                b"corrupt clock",
            )?,
            _ => {
                let (_, leaf, _) = fixture.windows[8].1.plan().children()[0];
                fs::write(fixture.tombstone(leaf), b"deleted unselected source")?;
            }
        }
        let result = fixture.query();
        if defect == 0 {
            assert!(matches!(result, Err(E::Discovery(D::UnindexedWindows))));
        } else if defect == 1 {
            assert!(matches!(result, Err(E::Discovery(D::Sequence))));
        } else {
            assert!(result.is_err(), "defect {defect}");
        }
    }
    Ok(())
}

#[test]
fn discovery_clock_and_both_revalidation_passes_share_one_nonrefillable_allowance() -> TestResult {
    let fixture = Fixture::new("shared-budget", RecordingQueryCodec::Avc, 3, 2, &[0, 2])?;
    let baseline = fixture.query()?;
    let maximum = RecordingUtcDiscoveryLimits::default();
    assert_eq!(maximum.max_scan_roots, 16_384);
    assert_eq!(maximum.max_windows, 4096);
    assert_eq!(maximum.max_pages, 1024);
    assert_eq!(maximum.metadata.max_catalogue_entries, 5121);
    assert_eq!(maximum.metadata.max_objects, 6146);
    assert_eq!(maximum.metadata.max_edges, 65_857);
    let edges = fixture
        .catalogs
        .iter()
        .map(|catalog| catalog.manifest.children().len())
        .sum::<usize>()
        + fixture
            .windows
            .iter()
            .map(|(_, window)| window.plan().manifest().children().len())
            .sum::<usize>()
        + fixture.clock.manifest().children().len();
    for dimension in 0..8 {
        let mut limits = maximum;
        match dimension {
            0 => limits.max_scan_roots = baseline.scanned_root_entries - 1,
            1 => limits.max_windows = baseline.scanned_windows - 1,
            2 => limits.max_pages = baseline.catalogs.len() - 1,
            3 => limits.metadata.max_catalogue_entries = baseline.read_usage.pinned_roots - 1,
            4 => limits.metadata.max_objects = baseline.read_usage.metadata_objects - 1,
            5 => limits.metadata.max_edges = edges - 1,
            6 => limits.metadata.max_io_calls = baseline.read_usage.io_calls - 1,
            _ => limits.metadata.max_read_bytes = baseline.read_usage.read_bytes - 1,
        }
        assert!(
            fixture.query_with(&HostSpoolIo, limits, &|| false).is_err(),
            "dimension {dimension}"
        );
    }
    let exact = RecordingUtcDiscoveryLimits {
        max_scan_roots: baseline.scanned_root_entries,
        max_windows: baseline.scanned_windows,
        max_pages: baseline.catalogs.len(),
        metadata: fss_publication::custody_audit::CustodyAuditLimits {
            max_catalogue_entries: baseline.read_usage.pinned_roots,
            max_objects: baseline.read_usage.metadata_objects,
            max_edges: edges,
            max_io_calls: baseline.read_usage.io_calls,
            max_read_bytes: baseline.read_usage.peak_reserved_read_bytes,
            ..maximum.metadata
        },
    };
    let constrained = fixture.query_with(&HostSpoolIo, exact, &|| false)?;
    assert_eq!(constrained.rows, baseline.rows);
    assert_eq!(constrained.read_usage, baseline.read_usage);
    assert_ne!(constrained.request_digest, baseline.request_digest);
    Ok(())
}

#[test]
fn final_pass_rejects_namespace_additions_removals_rebinding_and_clock_or_source_tombstones()
-> TestResult {
    for mutation in 0..6 {
        let mut fixture =
            Fixture::new("late-mutation", RecordingQueryCodec::Avc, 3, 2, &[0, 1, 2])?;
        fixture.request.interval = 0..1;
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        let injected = AtomicBool::new(false);
        let next = namespace_slot(fixture.request.codec, &fixture.request.scope, false, 3)?;
        let new_record = root_record_bytes(&next, ContentDigest::sha256(b"new tail"), 1)?;
        let clock_record = root_record_bytes(
            &fixture.request.clock_slot,
            ContentDigest::sha256(b"changed clock"),
            fixture.clock.manifest().children().len(),
        )?;
        let first = &fixture.catalogs[0];
        let changed_page = root_record_bytes(
            &first.slot,
            ContentDigest::sha256(b"changed page"),
            first.manifest.children().len(),
        )?;
        let (_, leaf, _) = fixture.windows[0].1.plan().children()[0];
        let clock_metadata = fixture
            .clock
            .manifest()
            .metadata_digest()
            .ok_or("clock metadata")?;
        let mutate = || {
            if io.call_count(SpoolIoCall::OpenRead) > fixture.first_pass_opens()
                && !injected.swap(true, Ordering::SeqCst)
            {
                return match mutation {
                    0 => fs::write(fixture.record(&next), &new_record).is_err(),
                    1 => fs::remove_file(fixture.record(&fixture.windows[0].0)).is_err(),
                    2 => fs::write(fixture.record(&fixture.request.clock_slot), &clock_record)
                        .is_err(),
                    3 => fs::write(fixture.record(&first.slot), &changed_page).is_err(),
                    4 => fs::write(fixture.tombstone(leaf), b"late source deletion").is_err(),
                    _ => fs::write(fixture.tombstone(clock_metadata), b"late clock deletion")
                        .is_err(),
                };
            }
            false
        };
        assert!(
            fixture
                .query_with(&io, RecordingUtcDiscoveryLimits::default(), &mutate)
                .is_err()
        );
        assert!(injected.load(Ordering::SeqCst), "mutation {mutation}");
    }
    Ok(())
}

#[test]
fn unrelated_directory_entries_are_charged_without_changing_selected_inventory_or_identity()
-> TestResult {
    let fixture = Fixture::new("unrelated", RecordingQueryCodec::Avc, 3, 2, &[0, 2])?;
    let baseline = fixture.query()?;
    for name in ["other.root.tmp", "foreign.root", "not-a-selected-slot"] {
        fs::write(fixture.root.join("roots").join(name), b"not interpreted")?;
    }
    let result = fixture.query()?;
    assert_eq!(result.request_digest, baseline.request_digest);
    assert_eq!(result.namespace_digest, baseline.namespace_digest);
    assert_eq!(result.inventory_digest, baseline.inventory_digest);
    assert_eq!(result.decision_digest, baseline.decision_digest);
    assert_eq!(result.rows, baseline.rows);
    assert_eq!(result.reference_digests, baseline.reference_digests);
    assert_eq!(
        result.scanned_root_entries,
        baseline.scanned_root_entries + 3
    );
    assert!(result.read_usage.io_calls > baseline.read_usage.io_calls);
    assert_eq!(result.read_usage.read_bytes, baseline.read_usage.read_bytes);
    Ok(())
}

#[test]
fn invalid_scope_clock_output_and_scan_ceiling_requests_are_rejected_before_io() -> TestResult {
    let fixture = Fixture::new("invalid", RecordingQueryCodec::Avc, 3, 2, &[0, 2])?;
    for mutation in 0..7 {
        let mut request = fixture.request.clone();
        match mutation {
            0 => request.scope.recording.generation = 0,
            1 => request.scope.time_scale = 0,
            2 => request.clock_slot = SlotName::parse("foreign-clock")?,
            3 => request.interval = 1..1,
            4 => request.max_windows = 0,
            5 => request.max_windows = 65,
            _ => request.max_hydration_bytes = 0,
        }
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        assert!(matches!(
            discover_recordings_utc(
                &io,
                &fixture.root,
                &request,
                RecordingUtcDiscoveryLimits::default(),
                &|| false
            ),
            Err(E::InvalidRequest)
        ));
        assert!(io.calls().is_empty());
    }
    for dimension in 0..9 {
        let mut limits = RecordingUtcDiscoveryLimits::default();
        match dimension {
            0 => limits.max_scan_roots += 1,
            1 => limits.max_windows += 1,
            2 => limits.max_pages += 1,
            3 => limits.metadata.max_catalogue_entries += 1,
            4 => limits.metadata.max_objects += 1,
            5 => limits.metadata.max_edges += 1,
            6 => limits.metadata.max_object_bytes += 1,
            7 => limits.metadata.max_read_bytes += 1,
            _ => limits.metadata.max_io_calls += 1,
        }
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        assert!(matches!(
            fixture.query_with(&io, limits, &|| false),
            Err(E::InvalidRequest)
        ));
        assert!(io.calls().is_empty());
    }
    Ok(())
}

#[test]
fn cancellation_before_discovery_during_enumeration_or_after_clock_reads_never_returns_rows()
-> TestResult {
    let fixture = Fixture::new("cancelled", RecordingQueryCodec::Avc, 3, 2, &[0, 2])?;
    for phase in 0..3 {
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        let cancelled = || match phase {
            0 => true,
            1 => io.call_count(SpoolIoCall::NextDirEntry) >= 2,
            _ => io.call_count(SpoolIoCall::OpenRead) >= fixture.first_pass_opens(),
        };
        assert!(matches!(
            fixture.query_with(&io, RecordingUtcDiscoveryLimits::default(), &cancelled),
            Err(E::Discovery(D::Storage(PinnedMetadataError::Audit(
                CustodyAuditError::Cancelled
            )))) | Err(E::Utc(U::Storage(PinnedMetadataError::Audit(
                CustodyAuditError::Cancelled
            ))))
        ));
        if phase == 0 {
            assert!(io.calls().is_empty());
        }
    }
    Ok(())
}
