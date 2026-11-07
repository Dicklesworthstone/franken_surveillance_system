#![forbid(unsafe_code)]
//! Agent UTC discovery stays metadata-only, conditional, exact-pinned and fail-closed.

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

use fixture::{ADMISSIONS, Fixture, TestResult, clock_codec, rechecksum};
use fss_core::{CanonicalDecoder, ContentDigest};
use fss_object::{HostSpoolIo, ObjectManifest, RecordingSpoolIo, SpoolIoCall};
use fss_publication::custody_audit::CustodyAuditError;
use fss_publication::custody_audit::pinned_metadata::PinnedMetadataError;
use fss_publication::{SlotName, root_record_bytes};
use fss_reference::agent_recordings::RecordingQueryCodec;
use fss_reference::agent_recordings::utc::{
    RecordingUtcQueryError as E, RecordingUtcQueryLimits, query_recordings_utc,
};
use fss_reference::rtsp::recording_catalog::CatalogError;
use fss_reference::rtsp::recording_clock::{
    RecordingClockError, RecordingClockIndex, clock_slot, verify_clock_metadata,
};
use fss_reference::site::clock::ClockCorrelationError;

#[test]
fn avc_and_hevc_return_conditional_candidates_and_every_unavailable_clock_without_source_reads()
-> TestResult {
    for codec in [RecordingQueryCodec::Avc, RecordingQueryCodec::Hevc] {
        let fixture = Fixture::new(codec.as_str(), codec, &[0, 2])?;
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        let query = query_recordings_utc(
            &io,
            &fixture.root,
            &fixture.request,
            RecordingUtcQueryLimits::default(),
            &|| false,
        )?;
        assert_eq!(
            query.rows.iter().map(|row| row.ordinal).collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert_eq!(query.rows[0].clock_ordinal, Some(0));
        assert_eq!(
            query.rows[0].utc_interval,
            Some(fixture.clock.windows()[0].utc_interval())
        );
        assert_eq!(query.rows[1].clock_ordinal, None);
        assert_eq!(query.rows[1].utc_interval, None);
        assert!(query.indexed_gaps.is_empty());
        assert_eq!(query.scanned_windows, 3);
        assert_eq!(query.clock_windows, 2);
        assert_eq!(query.clock_brackets, 2);
        assert_eq!(query.clock_root, fixture.clock.root());
        assert_eq!(
            query.clock_metadata_digest,
            ContentDigest::sha256(fixture.clock.index_bytes())
        );
        assert_eq!(query.clock_approval_digest, clock_support::approval());
        assert_eq!(query.clock_policy, clock_support::exchange()?.policy);
        assert_eq!(
            query.clock_offset,
            clock_support::exchange()?.correlation()?.offset_interval()
        );
        assert_eq!(
            query.quoted_hydration_bytes,
            query
                .rows
                .iter()
                .map(|row| row.entry.byte_len() as u64)
                .sum::<u64>()
        );
        assert_eq!(query.read_usage.pinned_roots, 5);
        assert_eq!(query.read_usage.metadata_objects, 7);
        assert_eq!(query.read_usage.io_calls, io.calls().len() as u64);
        assert_eq!(io.call_count(SpoolIoCall::ReadDir), 0);
        assert_eq!(io.call_count(SpoolIoCall::NextDirEntry), 0);
        assert!(io.is_read_only());
        assert!(!fixture.root.join("LOCK").exists());
        assert!(query.reference_digests.contains(&fixture.clock.root()));
        assert!(query.reference_digests.contains(&fixture.catalog.root()));
        for (slot, window) in &fixture.windows {
            assert!(
                query
                    .reference_digests
                    .contains(&window.plan().manifest().root())
            );
            assert_eq!(
                &query
                    .rows
                    .iter()
                    .find(|row| row.entry.slot() == slot)
                    .map(|row| row.entry.root()),
                &if slot == &fixture.windows[2].0 {
                    None
                } else {
                    Some(window.plan().manifest().root())
                }
            );
        }
        for leaf in &fixture.leaves {
            assert!(query.reference_digests.contains(leaf));
            assert!(!fixture.object(*leaf).exists());
            fs::write(
                fixture.object(*leaf),
                b"deliberately corrupt original source/media/index",
            )?;
        }
        assert_eq!(fixture.query()?, query);
    }
    Ok(())
}

#[test]
fn closed_clock_envelopes_obey_half_open_utc_query_edges_without_cropping_the_quote() -> TestResult
{
    let mut fixture = Fixture::new("closed-edges", RecordingQueryCodec::Avc, &[0, 2])?;
    let bounds = fixture.clock.windows()[0].utc_interval();
    let quote = fixture.query()?.quoted_hydration_bytes;
    for interval in [
        bounds.earliest_ns..bounds.earliest_ns + 1,
        bounds.latest_ns..bounds.latest_ns + 1,
    ] {
        fixture.request.interval = interval;
        let query = fixture.query()?;
        assert_eq!(
            query.rows.iter().map(|row| row.ordinal).collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert_eq!(query.quoted_hydration_bytes, quote);
        assert!(query.indexed_gaps.is_empty());
    }
    for interval in [
        bounds.earliest_ns - 1..bounds.earliest_ns,
        bounds.latest_ns + 1..bounds.latest_ns + 2,
    ] {
        fixture.request.interval = interval.clone();
        let query = fixture.query()?;
        assert_eq!(
            query.rows.iter().map(|row| row.ordinal).collect::<Vec<_>>(),
            vec![1]
        );
        assert_eq!(query.indexed_gaps, vec![interval]);
        assert_eq!(query.rows[0].utc_interval, None);
        assert_eq!(
            query.quoted_hydration_bytes,
            fixture.windows[1].1.plan().byte_len() as u64
        );
    }
    Ok(())
}

#[test]
fn all_clock_unavailable_rows_consume_atomic_window_and_hydration_limits() -> TestResult {
    let mut fixture = Fixture::new("quotas", RecordingQueryCodec::Avc, &[0])?;
    fixture.request.interval = 1..2;
    let baseline = fixture.query()?;
    assert_eq!(
        baseline
            .rows
            .iter()
            .map(|row| row.ordinal)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert!(baseline.rows.iter().all(|row| row.utc_interval.is_none()));
    assert_eq!(baseline.indexed_gaps, vec![1..2]);
    fixture.request.max_windows = 1;
    assert!(matches!(
        fixture.query(),
        Err(E::Catalog(CatalogError::Limit))
    ));
    fixture.request.max_windows = 2;
    fixture.request.max_hydration_bytes = baseline.quoted_hydration_bytes - 1;
    assert!(matches!(
        fixture.query(),
        Err(E::Catalog(CatalogError::Limit))
    ));
    fixture.request.max_hydration_bytes += 1;
    assert_eq!(fixture.query()?.rows, baseline.rows);
    Ok(())
}

#[test]
fn exact_scope_codec_clock_slot_and_both_roots_are_required() -> TestResult {
    let fixture = Fixture::new("pins", RecordingQueryCodec::Avc, &[0, 2])?;
    let mut wrong = fixture.request.clone();
    wrong.catalog_root = fixture.clock.root();
    assert!(
        query_recordings_utc(
            &HostSpoolIo,
            &fixture.root,
            &wrong,
            RecordingUtcQueryLimits::default(),
            &|| false
        )
        .is_err()
    );
    wrong = fixture.request.clone();
    wrong.clock_root = fixture.catalog.root();
    assert!(
        query_recordings_utc(
            &HostSpoolIo,
            &fixture.root,
            &wrong,
            RecordingUtcQueryLimits::default(),
            &|| false
        )
        .is_err()
    );
    for change in 0..7 {
        wrong = fixture.request.clone();
        match change {
            0 => wrong.codec = RecordingQueryCodec::Hevc,
            1 => wrong.scope.recording.generation += 1,
            2 => wrong.scope.recording.anchor = ContentDigest::sha256(b"other source anchor"),
            3 => {
                wrong.scope.recording.receive_clock = ContentDigest::sha256(b"other receive clock")
            }
            4 => wrong.scope.decode_clock = ContentDigest::sha256(b"other decode clock"),
            5 => wrong.scope.time_scale += 1,
            _ => wrong.clock_slot = SlotName::parse("arbitrary-clock-alias")?,
        }
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        assert!(matches!(
            query_recordings_utc(
                &io,
                &fixture.root,
                &wrong,
                RecordingUtcQueryLimits::default(),
                &|| false
            ),
            Err(E::InvalidRequest)
        ));
        assert!(io.calls().is_empty());
    }
    let mut scope = fixture.scope().clone();
    scope.recording.generation += 1;
    assert!(matches!(
        verify_clock_metadata(
            fixture.clock.manifest(),
            fixture.clock.index_bytes(),
            &scope,
            clock_codec(fixture.request.codec)
        ),
        Err(RecordingClockError::Scope)
    ));
    Ok(())
}

#[test]
fn invalid_bounds_limits_and_initial_cancellation_do_no_filesystem_work() -> TestResult {
    let fixture = Fixture::new("invalid", RecordingQueryCodec::Avc, &[0])?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let mut request = fixture.request.clone();
    request.interval = 1..1;
    assert!(matches!(
        query_recordings_utc(
            &io,
            &fixture.root,
            &request,
            RecordingUtcQueryLimits::default(),
            &|| false
        ),
        Err(E::InvalidRequest)
    ));
    let mut limits = RecordingUtcQueryLimits::default();
    limits.metadata.max_read_bytes += 1;
    assert!(matches!(
        query_recordings_utc(&io, &fixture.root, &fixture.request, limits, &|| false),
        Err(E::InvalidRequest)
    ));
    assert!(matches!(
        query_recordings_utc(
            &io,
            &fixture.root,
            &fixture.request,
            RecordingUtcQueryLimits::default(),
            &|| true
        ),
        Err(E::Storage(PinnedMetadataError::Audit(
            CustodyAuditError::Cancelled
        )))
    ));
    assert!(io.calls().is_empty());
    Ok(())
}

#[test]
fn metadata_allowance_is_shared_across_both_indexes_and_complete_revalidation() -> TestResult {
    let fixture = Fixture::new("shared-budget", RecordingQueryCodec::Avc, &[0, 2])?;
    let baseline = fixture.query()?;
    let mut limits = RecordingUtcQueryLimits::default();
    limits.metadata.max_io_calls = baseline.read_usage.io_calls;
    limits.metadata.max_read_bytes = baseline.read_usage.peak_reserved_read_bytes;
    let exact = query_recordings_utc(
        &HostSpoolIo,
        &fixture.root,
        &fixture.request,
        limits,
        &|| false,
    )?;
    assert_eq!(exact.rows, baseline.rows);
    assert_ne!(exact.request_digest, baseline.request_digest);
    assert_ne!(exact.decision_digest, baseline.decision_digest);
    limits.metadata.max_io_calls -= 1;
    assert!(matches!(
        query_recordings_utc(
            &HostSpoolIo,
            &fixture.root,
            &fixture.request,
            limits,
            &|| false
        ),
        Err(E::Storage(PinnedMetadataError::Audit(
            CustodyAuditError::Limit("io_calls")
        )))
    ));
    limits.metadata.max_io_calls += 1;
    limits.metadata.max_read_bytes -= 1;
    assert!(matches!(
        query_recordings_utc(
            &HostSpoolIo,
            &fixture.root,
            &fixture.request,
            limits,
            &|| false
        ),
        Err(E::Storage(PinnedMetadataError::Audit(
            CustodyAuditError::Limit("read_bytes")
        )))
    ));
    Ok(())
}

#[test]
fn clock_rows_outside_the_catalog_refuse_even_when_the_utc_request_excludes_them() -> TestResult {
    let mut fixture = Fixture::new("foreign-clock-row", RecordingQueryCodec::Avc, &[0])?;
    let unrelated = fixture.windows[2]
        .1
        .descriptor(SlotName::parse("foreign-slot")?)?;
    let index = RecordingClockIndex::prepare(
        fixture.scope().clone(),
        clock_codec(fixture.request.codec),
        clock_support::approval(),
        clock_support::exchange()?,
        clock_support::host(100_000_000),
        &[clock_support::bracket(ADMISSIONS[2])],
        &[unrelated],
    )?;
    fixture.put(index.index_bytes())?;
    fixture.publish(&fixture.request.clock_slot, index.manifest())?;
    fixture.request.clock_root = index.root();
    fixture.request.interval = 1..2;
    assert!(matches!(fixture.query(), Err(E::ClockCatalogMismatch)));
    Ok(())
}

#[test]
fn independently_rehashed_catalog_cost_disagreement_cannot_change_clock_member_quotes() -> TestResult
{
    for codec in [RecordingQueryCodec::Avc, RecordingQueryCodec::Hevc] {
        let mut fixture = Fixture::new("cost-disagreement", codec, &[0, 2])?;
        let windows: Vec<_> = fixture
            .windows
            .iter()
            .map(|(slot, window)| (slot, window.plan()))
            .collect();
        let domain = match codec {
            RecordingQueryCodec::Avc => "fss.recording_catalog.v1",
            RecordingQueryCodec::Hevc => "fss.hevc_recording_catalog.v1",
        };
        let metadata = hevc_catalog_support::index_with_bytes(
            domain,
            fixture.scope(),
            &windows,
            None,
            Some(fixture.windows[0].1.plan().byte_len() + 1),
        )?;
        let originals: Vec<_> = windows.iter().map(|(_, window)| *window).collect();
        let manifest =
            hevc_catalog_support::manifest(fixture.catalog.kind(), &metadata, &originals, None)?;
        fixture.put(&metadata)?;
        fixture.publish(&fixture.request.catalog_slot, &manifest)?;
        fixture.request.catalog_root = manifest.root();
        fixture.request.interval = 1..2;
        assert!(matches!(fixture.query(), Err(E::ClockCatalogMismatch)));
    }
    Ok(())
}

#[test]
fn rehashed_redundant_utc_claims_are_reconstructed_instead_of_trusted() -> TestResult {
    let mut fixture = Fixture::new("forged-utc", RecordingQueryCodec::Avc, &[0, 2])?;
    let mut metadata = fixture.clock.index_bytes().to_vec();
    let at = metadata
        .len()
        .checked_sub(33 + 16)
        .ok_or("last UTC interval")?;
    let claimed = u64::from_be_bytes(metadata[at..at + 8].try_into()?);
    metadata[at..at + 8].copy_from_slice(&(claimed + 1).to_be_bytes());
    rechecksum(&mut metadata)?;
    fixture.replace_clock_metadata(&metadata)?;
    assert!(matches!(
        fixture.query(),
        Err(E::Clock(RecordingClockError::Malformed))
    ));
    Ok(())
}

#[test]
fn rehashed_sampled_clock_discontinuity_refuses_before_any_candidate_escapes() -> TestResult {
    let mut fixture = Fixture::new("clock-step", RecordingQueryCodec::Avc, &[0, 2])?;
    let mut metadata = fixture.clock.index_bytes().to_vec();
    let body_len = metadata.len().checked_sub(33).ok_or("clock trailer")?;
    let mut decoder = CanonicalDecoder::new(&metadata[..body_len]);
    decoder.text()?;
    decoder.u64()?;
    decoder.u8()?;
    decoder.text()?;
    decoder.text()?;
    decoder.u64()?;
    decoder.digest()?;
    decoder.digest()?;
    decoder.digest()?;
    decoder.u32()?;
    decoder.digest()?;
    decoder.text()?;
    decoder.bytes()?;
    decoder.bytes()?;
    for _ in 0..15 {
        decoder.u64()?;
    }
    let terminal_wall = body_len - decoder.remaining() + 8;
    let claimed = u64::from_be_bytes(metadata[terminal_wall..terminal_wall + 8].try_into()?);
    metadata[terminal_wall..terminal_wall + 8]
        .copy_from_slice(&(claimed + 1_000_000_000).to_be_bytes());
    rechecksum(&mut metadata)?;
    fixture.replace_clock_metadata(&metadata)?;
    assert!(matches!(
        fixture.query(),
        Err(E::Clock(RecordingClockError::Correlation(
            ClockCorrelationError::WallClockDiscontinuity
        )))
    ));
    Ok(())
}

#[test]
fn missing_corrupt_and_wrong_kind_clock_metadata_fail_without_media_reads() -> TestResult {
    for defect in 0..3 {
        let mut fixture = Fixture::new("bad-clock", RecordingQueryCodec::Avc, &[0, 2])?;
        let metadata = fixture
            .clock
            .manifest()
            .metadata_digest()
            .ok_or("clock metadata")?;
        match defect {
            0 => fs::remove_file(fixture.object(metadata))?,
            1 => fs::write(fixture.object(metadata), b"invalid spool envelope")?,
            _ => {
                let source = *fixture.leaves.first().ok_or("leaf")?;
                let manifest = ObjectManifest::new("wrong_clock_family", [], Some(source))?;
                fixture.publish(&fixture.request.clock_slot, &manifest)?;
                fixture.request.clock_root = manifest.root();
            }
        }
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        let result = query_recordings_utc(
            &io,
            &fixture.root,
            &fixture.request,
            RecordingUtcQueryLimits::default(),
            &|| false,
        );
        assert!(result.is_err());
        if defect == 2 {
            assert!(matches!(
                result,
                Err(E::Clock(RecordingClockError::Malformed))
            ));
            // Catalog root/manifest/metadata and clock root/manifest only: the
            // wrong-kind manifest's source-typed metadata is never opened.
            assert_eq!(io.call_count(SpoolIoCall::OpenRead), 5);
        }
        assert!(io.is_read_only());
    }
    Ok(())
}

#[test]
fn every_catalog_member_and_full_closure_remain_current_even_when_excluded_by_utc() -> TestResult {
    for defect in 0..3 {
        let fixture = Fixture::new("custody", RecordingQueryCodec::Avc, &[0, 2])?;
        let (slot, excluded) = &fixture.windows[2];
        match defect {
            0 => fs::remove_file(
                fixture
                    .root
                    .join("roots")
                    .join(format!("{}.root", slot.as_str())),
            )?,
            1 => {
                let leaf = excluded.plan().children().next().ok_or("source")?.1;
                fs::write(fixture.tombstone(leaf), b"tombstone denies unread original")?;
            }
            _ => fs::write(
                fixture
                    .root
                    .join("roots")
                    .join(format!("{}.root.tmp", fixture.request.clock_slot.as_str())),
                b"pending clock publication",
            )?,
        }
        assert!(fixture.query().is_err());
    }
    Ok(())
}

#[test]
fn final_pass_rejects_late_clock_tombstones_and_changed_unselected_root_bindings() -> TestResult {
    for change_root in [false, true] {
        let fixture = Fixture::new("late-change", RecordingQueryCodec::Avc, &[0, 2])?;
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        let injected = AtomicBool::new(false);
        let (slot, window) = &fixture.windows[2];
        let replacement = root_record_bytes(
            slot,
            fixture.windows[0].1.plan().manifest().root(),
            window.plan().manifest().children().len(),
        )?;
        let clock_metadata = fixture
            .clock
            .manifest()
            .metadata_digest()
            .ok_or("clock metadata")?;
        let mutation = || {
            // All twelve first-pass root/object opens have completed. Inject
            // during the rehash pass, before final tombstone and slot checks.
            if io.call_count(SpoolIoCall::OpenRead) >= 13 && !injected.swap(true, Ordering::SeqCst)
            {
                return if change_root {
                    fs::write(
                        fixture
                            .root
                            .join("roots")
                            .join(format!("{}.root", slot.as_str())),
                        &replacement,
                    )
                    .is_err()
                } else {
                    fs::write(fixture.tombstone(clock_metadata), b"late clock deletion").is_err()
                };
            }
            false
        };
        let result = query_recordings_utc(
            &io,
            &fixture.root,
            &fixture.request,
            RecordingUtcQueryLimits::default(),
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
fn active_writer_lock_and_unrelated_unsettled_roots_do_not_expand_query_authority() -> TestResult {
    let fixture = Fixture::new("locked", RecordingQueryCodec::Hevc, &[0, 2])?;
    let lock = fs::File::create(fixture.root.join("LOCK"))?;
    lock.try_lock()?;
    fs::write(
        fixture.root.join("roots/unrelated.root.indeterminate"),
        b"foreign pending publication",
    )?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let query = query_recordings_utc(
        &io,
        &fixture.root,
        &fixture.request,
        RecordingUtcQueryLimits::default(),
        &|| false,
    )?;
    assert_eq!(query.rows.len(), 2);
    assert_eq!(io.call_count(SpoolIoCall::ReadDir), 0);
    assert!(io.is_read_only());
    lock.unlock()?;
    Ok(())
}

#[test]
fn conditional_utc_request_identity_binds_clock_root_interval_and_allowances() -> TestResult {
    let fixture = Fixture::new("identities", RecordingQueryCodec::Avc, &[0, 2])?;
    let baseline = fixture
        .request
        .request_digest(RecordingUtcQueryLimits::default())?;
    let mut request = fixture.request.clone();
    request.interval.end += 1;
    assert_ne!(
        request.request_digest(RecordingUtcQueryLimits::default())?,
        baseline
    );
    request = fixture.request.clone();
    request.clock_root = ContentDigest::sha256(b"different clock index");
    assert_ne!(
        request.request_digest(RecordingUtcQueryLimits::default())?,
        baseline
    );
    let mut limits = RecordingUtcQueryLimits::default();
    limits.metadata.max_io_calls -= 1;
    assert_ne!(fixture.request.request_digest(limits)?, baseline);
    assert_eq!(
        fixture.request.clock_slot,
        clock_slot(clock_codec(fixture.request.codec), fixture.scope())?
    );
    assert_eq!(fixture.query()?, fixture.query()?);
    Ok(())
}
