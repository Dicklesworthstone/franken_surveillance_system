#![forbid(unsafe_code)]
//! Exact native recorder-time queries under a held writer lock and hostile local changes.

mod hevc_recording_support;
mod recording_support;
#[path = "rtsp_replay_time_pinned_contract/io.rs"]
mod read_io;

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use fss_core::ContentDigest;
use fss_object::SpoolLimits;
use fss_publication::{
    LocalPublicationLimits, LocalRootPublisher, NeverCancel, SlotName,
};
use fss_reference::rtsp::client::replay::{ReplayAcceptance, ReplayWindow};
use fss_reference::rtsp::recording::PreparedRecording;
use fss_reference::rtsp::recording::local::{RecordingProgress, RecordingPublication};
use fss_reference::rtsp::recording_catalog::CatalogScope;
use fss_reference::rtsp::recording_replay::ReplayRequest;
use recording_support::{Error, fixture, scope};

type TestResult = Result<(), Error>;
static NEXT_PATH: AtomicUsize = AtomicUsize::new(0);

fn path(name: &str) -> PathBuf {
    std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("rtsp_replay_time_pinned_contract")
        .join(format!(
            "{}-{}-{name}",
            std::process::id(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed)
        ))
}

fn limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        16,
        512,
        16,
        128,
        SpoolLimits::new(128, 32 * 1024 * 1024, 8 * 1024 * 1024, 256),
    )
}

fn request() -> Result<ReplayRequest, Error> {
    Ok(ReplayRequest::new(
        scope()?,
        ContentDigest::sha256(b"approved credential-free route"),
        ReplayWindow::from_timestamps("20261105T010000Z", "20261105T010500Z")?,
        ContentDigest::sha256(b"original decode clock"),
    )?)
}

fn catalog_scope(request: &ReplayRequest) -> CatalogScope {
    CatalogScope {
        recording: request.scope().clone(),
        decode_clock: request.decode_clock(),
        time_scale: 90_000,
    }
}

fn accepted(request: &ReplayRequest) -> Result<ReplayAcceptance, Error> {
    Ok(ReplayAcceptance::new(
        7,
        request.window(),
        ReplayWindow::from_timestamps("20261105T010100Z", "20261105T010400Z")?,
    )?)
}

fn publish_window(
    publisher: &mut LocalRootPublisher,
    slot: &SlotName,
    recording: &PreparedRecording,
) -> TestResult {
    let mut job = RecordingPublication::new(
        recording,
        publisher,
        slot.clone(),
        recording.byte_len(),
        100,
    )?;
    for now in 0..4 {
        assert!(matches!(
            job.step(now, &NeverCancel)?,
            RecordingProgress::ChildStaged { .. }
        ));
    }
    assert!(matches!(
        job.step(4, &NeverCancel)?,
        RecordingProgress::Published(_)
    ));
    Ok(())
}

// Reuse real source construction, including reconstruction of AVC provenance after adding
// recorded-time extensions. The enclosing module preserves this fixture's existing imports.
#[path = "recording_replay_contract/utc"]
mod native {
    #[allow(dead_code)]
    #[path = "fixtures.rs"]
    mod fixtures;

    use super::*;
    use fixtures::*;
    use read_io::{ReadOnlyIo, Rewrite};
    use fss_publication::{
        LOCAL_ROOTS_DIR, LOCAL_TOMBSTONES_DIR, ROOT_RECORD_SUFFIX, ROOT_TEMP_SUFFIX,
        TOMBSTONE_RECORD_SUFFIX,
    };
    use fss_reference::rtsp::recording::MAX_RECORDING_BYTES;
    use fss_reference::rtsp::recording_replay::time::{
        ReplayTimeQuery, ReplayTimeReport, query_replay_time,
    };
    use fss_reference::rtsp::recording_replay::time::pinned::{
        ReplayTimeReadLimits, ReplayTimeReadReport, query_replay_time_read_only,
    };

    fn stamped_avc() -> Result<recording_support::Fixture, Error> {
        rebuild_avc(fixture(941, true)?, |index, wire| {
            if index == 0 {
                stamp(wire, NTP_SECONDS, 0x8000_0000, 0x80, 7)?;
            }
            Ok(())
        })
    }

    fn observe(
        sealed: &Sealed,
        io: &ReadOnlyIo,
        query: &ReplayTimeQuery,
        limits: ReplayTimeReadLimits,
    ) -> Result<ReplayTimeReadReport, Error> {
        Ok(query_replay_time_read_only(io, &sealed.root, query, limits, &|| false)?)
    }

    fn assert_same(expected: &ReplayTimeReport, actual: &ReplayTimeReport) {
        assert_eq!(actual.digest, expected.digest);
        assert_eq!(actual.index_digest, expected.index_digest);
        assert_eq!(actual.receipt.metadata_bytes(), expected.receipt.metadata_bytes());
        assert_eq!(actual.matches, expected.matches);
        assert_eq!(actual.unknown, expected.unknown);
        assert_eq!(actual.source_only, expected.source_only);
        // Cover the complete report, including every count, scope and source-proof field.
        assert_eq!(format!("{actual:?}").as_bytes(), format!("{expected:?}").as_bytes());
    }

    fn assert_metered(io: &ReadOnlyIo, result: &ReplayTimeReadReport) {
        assert_eq!(
            io.read_bytes.load(Ordering::SeqCst),
            result.metadata_usage.read_bytes + result.original_usage.read_bytes
        );
        assert_eq!(
            io.calls.load(Ordering::SeqCst),
            result.metadata_usage.io_calls + result.original_usage.io_calls
        );
        assert_eq!(io.forbidden.load(Ordering::SeqCst), 0);
    }

    fn changed_envelope(path: &std::path::Path) -> Result<Vec<u8>, Error> {
        let mut bytes = std::fs::read(path)?;
        let last = bytes.last_mut().ok_or("nonempty native envelope")?;
        *last ^= 1;
        Ok(bytes)
    }

    #[test]
    fn avc_report_is_identical_under_writer_lock_without_recovery_or_scanning() -> TestResult {
        let sealed = seal_avc("readonly-avc", &stamped_avc()?, 2, 7)?;
        let publisher = sealed.open()?;
        let expected = query_replay_time(&publisher, &sealed.query(), &NeverCancel)?;
        let unrelated = sealed.root.join(LOCAL_ROOTS_DIR).join(format!(
            "unrelated{ROOT_RECORD_SUFFIX}{ROOT_TEMP_SUFFIX}"
        ));
        std::fs::write(&unrelated, b"unrelated pending publication must remain untouched")?;
        let io = ReadOnlyIo::default();
        let result = observe(&sealed, &io, &sealed.query(), ReplayTimeReadLimits::default())?;
        assert_same(&expected, &result.report);
        assert_eq!(result.report.matches.len(), 2);
        assert_eq!(result.metadata_usage.pinned_roots, 3);
        assert_eq!(result.original_usage.completed_roots, 2);
        assert_eq!(result.original_usage.objects, 10);
        assert_metered(&io, &result);
        assert_eq!(
            std::fs::read(&unrelated)?,
            b"unrelated pending publication must remain untouched"
        );
        assert_eq!(io.opened_count(&unrelated), 0);
        // The existing writer remains live throughout the observation.
        assert!(publisher.root(&sealed.receipt.slot()?).is_some());
        Ok(())
    }

    #[test]
    fn hevc_unknown_source_only_tail_preserves_exact_native_projection() -> TestResult {
        let mut packets = stamped_hevc()?;
        packets[5].bytes[24] |= 1;
        let sealed = seal_hevc(
            "readonly-hevc-tail",
            &packets[..8],
            &hevc_recording_support::timings(2),
            7,
        )?;
        let publisher = sealed.open()?;
        let expected = query_replay_time(&publisher, &sealed.query(), &NeverCancel)?;
        let io = ReadOnlyIo::default();
        let actual = observe(&sealed, &io, &sealed.query(), ReplayTimeReadLimits::default())?;
        assert_same(&expected, &actual.report);
        assert_eq!(actual.report.matches.len(), 2);
        assert_eq!(actual.report.source_only.len(), 1);
        assert!(actual.report.source_only[0].evidence.unknown.is_some());
        assert!(actual.report.source_only[0].evidence.utc.is_none());
        assert_metered(&io, &actual);
        Ok(())
    }

    #[test]
    fn semantically_equal_extension_padding_retains_distinct_source_digests_under_lock()
    -> TestResult {
        let mut reports = Vec::new();
        for changed in [false, true] {
            let source = rebuild_avc(fixture(942, true)?, |index, wire| {
                let mut extension = content(NTP_SECONDS, 0, 0x80, 7);
                if changed {
                    extension[10..12].copy_from_slice(&[0xCA, index as u8]);
                }
                raw_extension(wire, 0xABAC, &extension)
            })?;
            let sealed = seal_avc("readonly-exact-packets", &source, 1, 7)?;
            let publisher = sealed.open()?;
            let expected = query_replay_time(&publisher, &sealed.query(), &NeverCancel)?;
            let result = observe(
                &sealed, &ReadOnlyIo::default(), &sealed.query(), ReplayTimeReadLimits::default(),
            )?;
            assert_same(&expected, &result.report);
            reports.push(result.report);
        }
        let a = &reports[0];
        let b = &reports[1];
        assert_eq!(a.matches[0].evidence.header, b.matches[0].evidence.header);
        assert_eq!(a.matches[0].evidence.utc, b.matches[0].evidence.utc);
        assert_ne!(a.matches[0].evidence.packet_set_digest, b.matches[0].evidence.packet_set_digest);
        assert_ne!(a.matches[0].evidence.proof_digest, b.matches[0].evidence.proof_digest);
        assert_ne!(a.index_digest, b.index_digest);
        assert_ne!(a.digest, b.digest);
        Ok(())
    }

    #[test]
    fn receipt_pins_and_declared_counts_are_checked_before_any_original_read() -> TestResult {
        let sealed = seal_avc("readonly-receipt-admission", &stamped_avc()?, 2, 7)?;
        let publisher = sealed.open()?;
        let original_paths: Vec<_> = sealed.receipt.windows().iter().flat_map(|window| {
            std::iter::once(window.root()).chain(window.original_leaf_digests())
        }).map(|digest| publisher.spool().object_path(digest)).collect();
        for case in 0..7 {
            let mut query = sealed.query();
            match case {
                0 => query.request = ContentDigest::sha256(b"unapproved request"),
                1 => query.receipt_root = ContentDigest::sha256(b"wrong receipt"),
                2 => query.scope.recording.generation += 1,
                3 => query.limits.max_windows = 1,
                4 => query.limits.max_samples = 1,
                5 => query.limits.max_packets = 1,
                _ => query.limits.max_source_bytes = MAX_RECORDING_BYTES as u64,
            }
            let io = ReadOnlyIo::default();
            assert!(query_replay_time_read_only(
                &io, &sealed.root, &query, ReplayTimeReadLimits::default(), &|| false,
            ).is_err(), "case {case}");
            assert!(original_paths.iter().all(|path| io.opened_count(path) == 0), "case {case}");
            assert_eq!(io.forbidden.load(Ordering::SeqCst), 0);
        }
        let metadata = sealed.receipt.manifest().metadata_digest().ok_or("receipt metadata")?;
        let metadata_path = publisher.spool().object_path(metadata);
        std::fs::write(&metadata_path, changed_envelope(&metadata_path)?)?;
        let io = ReadOnlyIo::default();
        assert!(observe(&sealed, &io, &sealed.query(), ReplayTimeReadLimits::default()).is_err());
        assert!(original_paths.iter().all(|path| io.opened_count(path) == 0));
        Ok(())
    }

    #[test]
    fn every_original_payload_role_is_rehashed_before_a_report_is_released() -> TestResult {
        for role in 0..4 {
            let sealed = seal_avc("readonly-original-tamper", &stamped_avc()?, 1, 7)?;
            let publisher = sealed.open()?;
            let digest = sealed.receipt.windows()[0].original_leaf_digests()[role];
            let target = publisher.spool().object_path(digest);
            std::fs::write(&target, changed_envelope(&target)?)?;
            let io = ReadOnlyIo::default();
            let error = query_replay_time_read_only(
                &io, &sealed.root, &sealed.query(), ReplayTimeReadLimits::default(), &|| false,
            ).err().ok_or("corrupt original cannot yield a report")?;
            assert_eq!(error.code(), "ERR-REPLAY-TIME-CUSTODY-001", "role {role}");
            assert_eq!(io.forbidden.load(Ordering::SeqCst), 0);
        }
        Ok(())
    }

    #[test]
    fn final_revalidation_covers_earlier_windows_after_later_native_reads() -> TestResult {
        for case in 0..4 {
            let sealed = seal_avc("readonly-final-scope", &stamped_avc()?, 2, 7)?;
            let publisher = sealed.open()?;
            let first = &sealed.receipt.windows()[0];
            let second = &sealed.receipt.windows()[1];
            let (target, bytes) = match case {
                0 => {
                    let target = publisher.spool().object_path(first.original_leaf_digests()[3]);
                    let bytes = changed_envelope(&target)?;
                    (target, bytes)
                }
                1 => (
                    sealed.root.join(LOCAL_ROOTS_DIR).join(format!(
                        "{}{ROOT_RECORD_SUFFIX}", first.slot().as_str()
                    )),
                    b"changed exact root binding".to_vec(),
                ),
                2 => {
                    let digest = first.original_leaf_digests()[2];
                    assert_ne!(digest, second.original_leaf_digests()[2]);
                    (
                        sealed.root.join(LOCAL_TOMBSTONES_DIR).join(format!(
                            "{}{TOMBSTONE_RECORD_SUFFIX}{ROOT_TEMP_SUFFIX}",
                            digest.to_text().replacen(':', "-", 1)
                        )),
                        b"pending deletion denies earlier original".to_vec(),
                    )
                }
                _ => {
                    let digest = sealed.receipt.manifest().metadata_digest().ok_or("receipt metadata")?;
                    let target = publisher.spool().object_path(digest);
                    let bytes = changed_envelope(&target)?;
                    (target, bytes)
                }
            };
            let io = ReadOnlyIo {
                rewrite: Some(Rewrite {
                    when: publisher.spool().object_path(second.root()),
                    // First admission is metadata-only; second begins native verification
                    // after the first native closure already completed its own readback.
                    occurrence: 2,
                    target,
                    bytes,
                }),
                ..ReadOnlyIo::default()
            };
            let error = query_replay_time_read_only(
                &io, &sealed.root, &sealed.query(), ReplayTimeReadLimits::default(), &|| false,
            ).err().ok_or("changed whole-query custody cannot yield a report")?;
            assert!(io.rewritten.load(Ordering::SeqCst), "case {case}");
            assert_eq!(error.code(), "ERR-REPLAY-TIME-CUSTODY-001", "case {case}");
            assert_eq!(io.forbidden.load(Ordering::SeqCst), 0);
        }
        Ok(())
    }

    #[test]
    fn metadata_and_original_budgets_are_independent_and_never_refill_per_window() -> TestResult {
        let source = stamped_avc()?;
        let one = seal_avc("readonly-budget-one", &source, 1, 7)?;
        let two = seal_avc("readonly-budget-two", &source, 2, 7)?;
        let one_result = observe(
            &one, &ReadOnlyIo::default(), &one.query(), ReplayTimeReadLimits::default(),
        )?;
        for case in 0..9 {
            let mut limits = ReplayTimeReadLimits::default();
            match case {
                0 => limits.metadata.max_read_bytes = 0,
                1 => limits.metadata.max_io_calls = 0,
                2 => limits.originals.max_read_bytes = 0,
                3 => limits.originals.max_io_calls = 0,
                4 => limits.originals.max_catalogue_entries = 1,
                5 => limits.originals.max_objects = 5,
                6 => limits.originals.max_edges = 4,
                7 => limits.originals.max_read_bytes = one_result.original_usage.peak_reserved_read_bytes,
                _ => limits.originals.max_io_calls = one_result.original_usage.io_calls,
            }
            let io = ReadOnlyIo::default();
            let error = query_replay_time_read_only(
                &io, &two.root, &two.query(), limits, &|| false,
            ).err().ok_or("one-window allowance cannot fund a complete two-window query")?;
            assert_eq!(error.code(), "ERR-REPLAY-TIME-LIMIT-001", "case {case}: {error:?}");
            assert_eq!(io.forbidden.load(Ordering::SeqCst), 0);
        }
        let io = ReadOnlyIo::default();
        let mut invalid = ReplayTimeReadLimits::default();
        invalid.metadata.max_object_bytes = 2 * 1024 * 1024 + 1;
        assert!(query_replay_time_read_only(
            &io, &two.root, &two.query(), invalid, &|| false,
        ).is_err());
        assert_eq!(io.calls.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[test]
    fn cancellation_precedes_io_and_stops_in_progress_native_retrieval() -> TestResult {
        let sealed = seal_avc("readonly-cancel", &stamped_avc()?, 1, 7)?;
        let publisher = sealed.open()?;
        let io = ReadOnlyIo::default();
        let error = query_replay_time_read_only(
            &io, &sealed.root, &sealed.query(), ReplayTimeReadLimits::default(), &|| true,
        ).err().ok_or("cancelled observation")?;
        assert_eq!(error.code(), "ERR-REPLAY-TIME-CANCELLED-001");
        assert_eq!(io.calls.load(Ordering::SeqCst), 0);
        let source = publisher.spool().object_path(
            sealed.receipt.windows()[0].original_leaf_digests()[0],
        );
        let io = ReadOnlyIo::default();
        let error = query_replay_time_read_only(
            &io, &sealed.root, &sealed.query(), ReplayTimeReadLimits::default(),
            &|| io.opened_count(&source) != 0,
        ).err().ok_or("revoked during original retrieval")?;
        assert_eq!(error.code(), "ERR-REPLAY-TIME-CANCELLED-001");
        assert_eq!(io.opened_count(&source), 1);
        assert_eq!(io.forbidden.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[test]
    fn a_missing_archive_is_never_created_or_recovered() -> TestResult {
        let sealed = seal_avc("readonly-query-pins", &stamped_avc()?, 1, 7)?;
        let missing = path("readonly-missing");
        assert!(!missing.exists());
        let io = ReadOnlyIo::default();
        assert!(query_replay_time_read_only(
            &io, &missing, &sealed.query(), ReplayTimeReadLimits::default(), &|| false,
        ).is_err());
        assert!(!missing.exists());
        assert_eq!(io.forbidden.load(Ordering::SeqCst), 0);
        Ok(())
    }
}
