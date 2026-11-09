#![forbid(unsafe_code)]
//! Capture sessions share budgets and custody while preserving independent clock provenance.

#[path = "recording_clock_contract/support.rs"]
mod clock_support;
mod collector_support;
#[path = "agent_recordings_utc_sessions_contract/support.rs"]
mod fixture;
mod hevc_recording_support;

use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use fixture::{Fixture, TestResult};
use fss_core::{ContentDigest, SensorId, StreamId};
use fss_object::{HostSpoolIo, RecordingSpoolIo, SpoolIoCall};
use fss_publication::custody_audit::CustodyAuditError;
use fss_publication::custody_audit::pinned_metadata::PinnedMetadataError;
use fss_publication::{SlotName, root_record_bytes};
use fss_reference::agent_recordings::RecordingQueryCodec::{Avc, Hevc};
use fss_reference::agent_recordings::set::RecordingCatalogPin;
use fss_reference::agent_recordings::utc::RecordingUtcQueryError as U;
use fss_reference::agent_recordings::utc_sessions::{
    RecordingUtcSessionPin, RecordingUtcSessionsError as E, RecordingUtcSessionsLimits,
    query_recordings_utc_sessions,
};
use fss_reference::agent_recordings::utc_set::{
    RecordingUtcSetQueryLimits, RecordingUtcSetQueryRequest, query_recordings_utc_set,
};
use fss_reference::rtsp::recording_catalog::{CatalogError, CatalogWindow, prepare_catalog};
use fss_reference::rtsp::recording_clock::{
    ClockWindow, RecordingClockIndex, clock_slot, verify_clock_metadata,
};

fn mixed(name: &str) -> TestResult<Fixture> {
    Fixture::new(name, &[Avc, Hevc], 2, 1, &[0])
}

#[test]
fn native_avc_and_hevc_sessions_preserve_scope_and_canonicalize_both_input_orders() -> TestResult {
    let mut f = mixed("mixed-union")?;
    let envelopes = f
        .sessions
        .iter()
        .map(|session| session.clock.windows()[0].utc_interval())
        .collect::<Vec<_>>();
    f.request.interval = envelopes
        .iter()
        .map(|interval| interval.earliest_ns)
        .min()
        .ok_or("earliest")?
        ..envelopes
            .iter()
            .map(|interval| interval.latest_ns)
            .max()
            .ok_or("latest")?
            + 1;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let result = f.query_with(&io, RecordingUtcSessionsLimits::default(), &|| false)?;
    assert_eq!(result.rows.len(), 4);
    assert_eq!(result.sessions.len(), 2);
    assert_eq!(result.scanned_windows, 4);
    assert_eq!(result.unique_windows, 4);
    assert_eq!(
        result
            .rows
            .iter()
            .filter(|row| row.row.utc_interval.is_none())
            .count(),
        2
    );
    assert!(
        result
            .sessions
            .windows(2)
            .all(|pair| pair[0].session_digest < pair[1].session_digest)
    );
    for session in &result.sessions {
        let original = f
            .sessions
            .iter()
            .find(|source| source.scope == session.scope)
            .ok_or("original scope")?;
        assert_eq!(session.codec, original.codec);
        assert_eq!(session.clock_root, original.clock.root());
        let verified_clock = verify_clock_metadata(
            original.clock.manifest(),
            original.clock.index_bytes(),
            &original.scope,
            fixture::clock_codec(original.codec),
        )?;
        assert_eq!(session.clock_policy, verified_clock.policy());
        assert_eq!(session.clock_offset, verified_clock.offset_interval());
        assert_eq!(
            session.clock_approval_digest,
            original.clock.approval_digest()
        );
        assert_eq!(session.catalogs.len(), 2);
        assert_eq!(session.clock_windows, 1);
        assert_eq!(session.unique_windows, 2);
    }
    for row in &result.rows {
        let session = &result.sessions[row.session_index];
        assert_eq!(row.session_digest, session.session_digest);
        for location in &row.row.locations {
            assert_eq!(
                location.catalog_root,
                session.catalogs[location.catalog_index].pin.root
            );
        }
    }
    assert_eq!(
        result.quoted_hydration_bytes,
        result
            .rows
            .iter()
            .map(|row| row.row.entry.byte_len() as u64)
            .sum::<u64>()
    );
    assert_eq!(result.read_usage.io_calls, io.calls().len() as u64);
    assert!(io.is_read_only());
    assert_eq!(io.call_count(SpoolIoCall::ReadDir), 0);
    assert_eq!(io.call_count(SpoolIoCall::NextDirEntry), 0);
    assert!(!f.root.join("LOCK").exists());
    for leaf in &f.leaves {
        assert!(!f.object(*leaf).exists());
        assert!(result.reference_digests.contains(leaf));
        fs::write(
            f.object(*leaf),
            b"corrupt source never read by metadata selection",
        )?;
    }
    f.request.sessions.reverse();
    for session in &mut f.request.sessions {
        session.catalogs.reverse();
    }
    assert_eq!(f.query()?, result);
    Ok(())
}

#[test]
fn full_eight_session_eight_page_universe_fits_default_metadata_accounting() -> TestResult {
    let clocked = (0..64).collect::<Vec<_>>();
    let f = Fixture::new(
        "full-default-universe",
        &[Avc, Hevc, Avc, Hevc, Avc, Hevc, Avc, Hevc],
        64,
        8,
        &clocked,
    )?;
    let result = f.query()?;
    assert!(result.rows.is_empty());
    assert_eq!(result.sessions.len(), 8);
    assert_eq!(result.scanned_windows, 512);
    assert_eq!(result.unique_windows, 512);
    assert_eq!(result.read_usage.pinned_roots, 584);
    assert_eq!(result.read_usage.metadata_objects, 656);
    for session in &result.sessions {
        assert_eq!(session.catalogs.len(), 8);
        assert_eq!(session.scanned_windows, 64);
        assert_eq!(session.clock_windows, 64);
        assert_eq!(session.indexed_gaps, vec![0..1]);
    }
    let mut limits = RecordingUtcSessionsLimits::default();
    limits.max_scanned_windows = 511;
    assert!(matches!(
        f.query_with(&HostSpoolIo, limits, &|| false),
        Err(E::Utc(U::Catalog(CatalogError::Limit)))
    ));
    Ok(())
}

#[test]
fn every_unknown_time_window_survives_and_consumes_the_shared_output_and_quote_bounds() -> TestResult
{
    let mut f = mixed("unknown-bounds")?;
    let result = f.query()?;
    assert_eq!(result.rows.len(), 2);
    assert!(
        result
            .rows
            .iter()
            .all(|row| row.row.utc_interval.is_none() && row.row.clock_ordinal.is_none())
    );
    assert_eq!(result.indexed_gaps, vec![0..1]);
    assert!(
        result
            .sessions
            .iter()
            .all(|session| session.indexed_gaps == vec![0..1])
    );
    f.request.max_windows = 1;
    assert!(matches!(
        f.query(),
        Err(E::Utc(U::Catalog(CatalogError::Limit)))
    ));
    f.request.max_windows = 2;
    f.request.max_hydration_bytes = result.quoted_hydration_bytes - 1;
    assert!(matches!(
        f.query(),
        Err(E::Utc(U::Catalog(CatalogError::Limit)))
    ));
    f.request.max_hydration_bytes += 1;
    assert_eq!(f.query()?.rows, result.rows);
    Ok(())
}

#[test]
fn each_clock_must_join_its_own_complete_catalogs_even_for_an_empty_utc_result() -> TestResult {
    let mut f = Fixture::new("incomplete-inactive-source", &[Avc, Hevc], 2, 1, &[0, 1])?;
    assert!(f.query()?.rows.is_empty());
    f.request.sessions[1].catalogs.pop();
    assert!(matches!(f.query(), Err(E::Utc(U::ClockCatalogMismatch))));
    Ok(())
}

#[test]
fn duplicate_memberships_within_one_session_keep_locations_and_quote_once() -> TestResult {
    let mut f = Fixture::new("same-session-membership", &[Avc, Hevc], 3, 3, &[0, 2])?;
    f.request.sessions[0].catalogs = vec![
        f.publish_catalog(0, "overlap-page-a", &[0, 1])?,
        f.publish_catalog(0, "overlap-page-b", &[1, 2])?,
    ];
    let result = f.query()?;
    assert_eq!(result.scanned_windows, 7);
    assert_eq!(result.unique_windows, 6);
    assert_eq!(result.rows.len(), 2);
    let row = result
        .rows
        .iter()
        .find(|row| {
            result.sessions[row.session_index]
                .scope
                .recording
                .generation
                == 1
        })
        .ok_or("duplicated member")?;
    assert_eq!(row.row.locations.len(), 2);
    assert_eq!(row.row.locations[0].catalog_index, 0);
    assert_eq!(row.row.locations[1].catalog_index, 1);
    assert_eq!(
        result.quoted_hydration_bytes,
        result
            .rows
            .iter()
            .map(|row| row.row.entry.byte_len() as u64)
            .sum::<u64>()
    );
    Ok(())
}

#[test]
fn shared_allowance_includes_every_session_and_the_final_revalidation() -> TestResult {
    let f = mixed("aggregate-read-budget")?;
    let baseline = f.query()?;
    for mutation in 0..6 {
        let mut limits = RecordingUtcSessionsLimits::default();
        match mutation {
            0 => limits.max_scanned_windows = baseline.scanned_windows - 1,
            1 => limits.metadata.max_catalogue_entries = baseline.read_usage.pinned_roots - 1,
            2 => limits.metadata.max_objects = baseline.read_usage.metadata_objects - 1,
            3 => limits.metadata.max_io_calls = baseline.read_usage.io_calls - 1,
            4 => limits.metadata.max_read_bytes = baseline.read_usage.read_bytes - 1,
            _ => limits.metadata.max_edges = 0,
        }
        assert!(
            f.query_with(&HostSpoolIo, limits, &|| false).is_err(),
            "shared budget mutation {mutation}"
        );
    }
    let mut exact = RecordingUtcSessionsLimits::default();
    exact.max_scanned_windows = baseline.scanned_windows;
    exact.metadata.max_catalogue_entries = baseline.read_usage.pinned_roots;
    exact.metadata.max_objects = baseline.read_usage.metadata_objects;
    exact.metadata.max_io_calls = baseline.read_usage.io_calls;
    exact.metadata.max_read_bytes = baseline.read_usage.peak_reserved_read_bytes;
    assert!(f.query_with(&HostSpoolIo, exact, &|| false).is_ok());
    Ok(())
}

#[test]
fn mixed_sources_duplicate_scopes_and_conflicting_pins_refuse_before_filesystem_access()
-> TestResult {
    let f = mixed("invalid-union")?;
    for mutation in 0..13 {
        let mut request = f.request.clone();
        match mutation {
            0 => request.sessions.clear(),
            1 => request.sessions = vec![request.sessions[0].clone(); 9],
            2 => {
                request.sessions[1].scope.recording.sensor = SensorId::parse("different-sensor")?;
                request.sessions[1].clock_slot = clock_slot(
                    fixture::clock_codec(request.sessions[1].codec),
                    &request.sessions[1].scope,
                )?;
            }
            3 => {
                request.sessions[1].scope.recording.stream = StreamId::parse("different-stream")?;
                request.sessions[1].clock_slot = clock_slot(
                    fixture::clock_codec(request.sessions[1].codec),
                    &request.sessions[1].scope,
                )?;
            }
            4 => request.sessions[1] = request.sessions[0].clone(),
            5 => {
                request.sessions[1].catalogs[0].slot = request.sessions[0].catalogs[0].slot.clone()
            }
            6 => request.sessions[1].catalogs[0].root = request.sessions[0].catalogs[0].root,
            7 => request.sessions[1].clock_root = request.sessions[0].clock_root,
            8 => request.sessions[0].catalogs.clear(),
            9 => request.sessions[1].clock_slot = SlotName::parse("not-derived-clock-slot")?,
            10 => request.interval = 2..2,
            11 => request.max_windows = 65,
            _ => request.max_hydration_bytes = 0,
        }
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        assert!(
            matches!(
                query_recordings_utc_sessions(
                    &io,
                    &f.root,
                    &request,
                    RecordingUtcSessionsLimits::default(),
                    &|| false
                ),
                Err(E::InvalidRequest)
            ),
            "mutation {mutation}"
        );
        assert!(io.calls().is_empty());
    }
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let mut limits = RecordingUtcSessionsLimits::default();
    limits.max_scanned_windows += 1;
    assert!(matches!(
        f.query_with(&io, limits, &|| false),
        Err(E::InvalidRequest)
    ));
    assert!(io.calls().is_empty());
    Ok(())
}

#[test]
fn unselected_source_leaves_catalog_metadata_and_clock_references_remain_in_the_full_closure()
-> TestResult {
    for mutation in 0..3 {
        let f = Fixture::new("unselected-custody", &[Avc, Hevc], 2, 1, &[0, 1])?;
        let before = f.query()?;
        assert!(before.rows.is_empty());
        match mutation {
            0 => {
                let (_, leaf, _) = f.sessions[1].windows[1].1.plan().children()[0];
                assert!(before.reference_digests.contains(&leaf));
                fs::write(f.tombstone(leaf), b"deleted unselected source")?;
            }
            1 => {
                let metadata = f.sessions[1].catalogs[1]
                    .manifest
                    .metadata_digest()
                    .ok_or("page metadata")?;
                fs::write(f.object(metadata), b"corrupt unselected page")?;
            }
            _ => {
                let metadata = f.sessions[1]
                    .clock
                    .manifest()
                    .metadata_digest()
                    .ok_or("clock metadata")?;
                fs::write(f.tombstone(metadata), b"deleted unselected clock")?;
            }
        }
        assert!(f.query().is_err());
    }
    Ok(())
}

#[test]
fn final_global_pass_rejects_earlier_session_mutation_after_the_last_session_was_admitted()
-> TestResult {
    for mutation in 0..4 {
        let f = Fixture::new("global-final-pass", &[Avc, Hevc], 2, 1, &[0, 1])?;
        let baseline = f.query()?;
        let early = &baseline.sessions[0];
        let original = f
            .sessions
            .iter()
            .find(|source| source.scope == early.scope)
            .ok_or("original early session")?;
        let page = &early.catalogs[0];
        let changed_page = root_record_bytes(
            &page.pin.slot,
            ContentDigest::sha256(b"rebound early page"),
            original.catalogs[0].manifest.children().len(),
        )?;
        let changed_clock = root_record_bytes(
            &early.clock_slot,
            ContentDigest::sha256(b"rebound early clock"),
            original.clock.manifest().children().len(),
        )?;
        let (_, leaf, _) = original.windows[0].1.plan().children()[0];
        let clock_metadata = original
            .clock
            .manifest()
            .metadata_digest()
            .ok_or("clock metadata")?;
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        let injected = AtomicBool::new(false);
        let mutate = || {
            if io.call_count(SpoolIoCall::OpenRead) >= f.first_pass_opens()
                && !injected.swap(true, Ordering::SeqCst)
            {
                return match mutation {
                    0 => fs::write(f.record(&page.pin.slot), &changed_page).is_err(),
                    1 => fs::write(f.record(&early.clock_slot), &changed_clock).is_err(),
                    2 => fs::write(f.tombstone(leaf), b"late unselected source deletion").is_err(),
                    _ => fs::write(f.tombstone(clock_metadata), b"late early clock deletion")
                        .is_err(),
                };
            }
            false
        };
        assert!(matches!(
            f.query_with(&io, RecordingUtcSessionsLimits::default(), &mutate),
            Err(E::Utc(U::Storage(
                PinnedMetadataError::Changed | PinnedMetadataError::Tombstoned
            )))
        ));
        assert!(injected.load(Ordering::SeqCst));
    }
    Ok(())
}

#[test]
fn cancellation_before_or_during_a_later_session_never_returns_a_partial_union() -> TestResult {
    let f = mixed("cancelled-union")?;
    for late in [false, true] {
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        let result = f.query_with(&io, RecordingUtcSessionsLimits::default(), &|| {
            !late || io.call_count(SpoolIoCall::OpenRead) >= 14
        });
        assert!(matches!(
            result,
            Err(E::Utc(U::Storage(PinnedMetadataError::Audit(
                CustodyAuditError::Cancelled
            ))))
        ));
        if !late {
            assert!(io.calls().is_empty());
        }
    }
    Ok(())
}

#[test]
fn per_session_gaps_survive_other_sessions_and_union_edges_remain_conditional() -> TestResult {
    let mut f = Fixture::new("per-session-gaps", &[Avc, Hevc], 1, 1, &[0])?;
    let first = f.sessions[0].clock.windows()[0].utc_interval();
    let second = f.sessions[1].clock.windows()[0].utc_interval();
    assert!(first.earliest_ns < second.earliest_ns);
    f.request.interval = first.earliest_ns..second.latest_ns + 1;
    let result = f.query()?;
    let later = result
        .sessions
        .iter()
        .find(|session| session.scope.recording.generation == 2)
        .ok_or("later scope")?;
    assert_eq!(
        later.indexed_gaps,
        vec![first.earliest_ns..second.earliest_ns]
    );
    assert!(
        result
            .indexed_gaps
            .iter()
            .all(|gap| gap.start >= first.latest_ns + 1)
    );
    let first_digest = f.request.sessions[0].session_digest()?;
    f.request.interval = first.latest_ns..first.latest_ns + 1;
    assert!(
        f.query()?
            .rows
            .iter()
            .any(|row| row.session_digest == first_digest)
    );
    f.request.interval = first.latest_ns + 1..first.latest_ns + 2;
    assert!(
        f.query()?
            .rows
            .iter()
            .all(|row| row.session_digest != first_digest)
    );
    Ok(())
}

#[test]
fn one_session_uses_the_same_catalog_clock_and_final_read_semantics_as_the_existing_set()
-> TestResult {
    let f = Fixture::new("single-source-equivalence", &[Avc], 3, 2, &[0, 2])?;
    let pin = &f.request.sessions[0];
    let legacy = query_recordings_utc_set(
        &HostSpoolIo,
        &f.root,
        &RecordingUtcSetQueryRequest {
            codec: pin.codec,
            scope: pin.scope.clone(),
            catalogs: pin.catalogs.clone(),
            clock_slot: pin.clock_slot.clone(),
            clock_root: pin.clock_root,
            interval: f.request.interval.clone(),
            max_windows: f.request.max_windows,
            max_hydration_bytes: f.request.max_hydration_bytes,
        },
        RecordingUtcSetQueryLimits::default(),
        &|| false,
    )?;
    let result = f.query()?;
    assert_eq!(result.sessions[0].catalogs, legacy.catalogs);
    assert_eq!(
        result.sessions[0].clock_metadata_digest,
        legacy.clock_metadata_digest
    );
    assert_eq!(result.reference_digests, legacy.reference_digests);
    assert_eq!(result.indexed_gaps, legacy.indexed_gaps);
    assert_eq!(result.quoted_hydration_bytes, legacy.quoted_hydration_bytes);
    assert_eq!(result.read_usage, legacy.read_usage);
    assert_eq!(
        result
            .rows
            .iter()
            .map(|row| row.row.clone())
            .collect::<Vec<_>>(),
        legacy.rows
    );
    let original = &result.rows[0];
    let mut changed = original.clone();
    changed.session_index += 1;
    assert_ne!(changed.row_digest(), original.row_digest());
    changed = original.clone();
    changed.session_digest = ContentDigest::sha256(b"different source provenance");
    assert_ne!(changed.row_digest(), original.row_digest());
    Ok(())
}

#[test]
fn distinct_decode_scopes_cannot_reinterpret_the_same_recording_root_as_two_sessions() -> TestResult
{
    let mut f = Fixture::new("cross-scope-root-alias", &[Avc], 1, 1, &[0])?;
    let original = &f.sessions[0];
    let mut scope = original.scope.clone();
    scope.decode_clock = ContentDigest::sha256(b"different declared decode origin");
    let (slot, native) = &original.windows[0];
    let catalog = prepare_catalog(
        scope.clone(),
        &[CatalogWindow {
            slot,
            recording: native.plan(),
        }],
    )?;
    let catalog_slot = SlotName::parse("different-decode-scope-page")?;
    f.put(catalog.index_bytes())?;
    f.publish(&catalog_slot, catalog.manifest())?;
    let clock = RecordingClockIndex::prepare(
        scope.clone(),
        fixture::clock_codec(Avc),
        ContentDigest::sha256(b"second scope historical approval"),
        clock_support::exchange()?,
        clock_support::host(100_000_000),
        &[clock_support::bracket(30_000_000)],
        &[ClockWindow::from_avc(slot.clone(), native.plan())?],
    )?;
    let clock_slot = clock_slot(fixture::clock_codec(Avc), &scope)?;
    f.put(clock.index_bytes())?;
    f.publish(&clock_slot, clock.manifest())?;
    f.request.sessions.push(RecordingUtcSessionPin {
        codec: Avc,
        scope,
        catalogs: vec![RecordingCatalogPin {
            slot: catalog_slot,
            root: catalog.root(),
        }],
        clock_slot,
        clock_root: clock.root(),
    });
    assert!(matches!(
        f.query(),
        Err(E::Utc(U::Catalog(CatalogError::WindowMismatch)))
    ));
    Ok(())
}

#[test]
fn exhausted_output_and_quote_allow_a_verified_empty_later_session_but_never_an_unknown_row()
-> TestResult {
    let mut f = mixed("empty-later-contribution")?;
    for pin in &mut f.request.sessions {
        pin.catalogs.truncate(1);
    }
    let first =
        if f.request.sessions[0].session_digest()? < f.request.sessions[1].session_digest()? {
            0
        } else {
            1
        };
    let later = 1 - first;
    let envelope = f.sessions[first].clock.windows()[0].utc_interval();
    let other = f.sessions[later].clock.windows()[0].utc_interval();
    let point = if envelope.earliest_ns < other.earliest_ns {
        envelope.earliest_ns
    } else {
        envelope.latest_ns
    };
    f.request.interval = point..point + 1;
    f.request.max_windows = 1;
    f.request.max_hydration_bytes = f.sessions[first].windows[0].1.plan().byte_len() as u64;
    let result = f.query()?;
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].session_index, 0);
    assert_eq!(result.quoted_hydration_bytes, f.request.max_hydration_bytes);
    assert_eq!(result.sessions[1].clock_windows, 1);
    assert_eq!(result.sessions[1].quoted_hydration_bytes, 0);
    assert_eq!(
        result.sessions[1].indexed_gaps,
        vec![f.request.interval.clone()]
    );
    let unknown_page = &f.sessions[later].catalogs[1];
    f.request.sessions[later]
        .catalogs
        .push(RecordingCatalogPin {
            slot: unknown_page.slot.clone(),
            root: unknown_page.manifest.root(),
        });
    assert!(matches!(
        f.query(),
        Err(E::Utc(U::Catalog(CatalogError::Limit)))
    ));
    Ok(())
}
