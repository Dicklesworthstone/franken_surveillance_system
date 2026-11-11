#![forbid(unsafe_code)]
//! Identical packet-derived recorder UTC from archive custody and imported retained custody.
//! Source-only data, missing assertions and partial retrieval never become media/coverage.

mod hevc_recording_support;
#[path = "rtsp_replay_import_contract/support.rs"]
mod import_support;
mod recording_support;
#[path = "rtsp_retained_replay_time_contract/support.rs"]
mod support;

use std::cell::Cell;
use std::fs;

use fss_core::{ContentDigest, SensorId, StreamId};
use fss_packet::onvif_replay::ReplayExtensionError;
use fss_publication::{NeverCancel, PublishCancellation, PublishCutPoint};
use fss_reference::ingest::RetainedReadLimits;
use fss_reference::ingest::rtsp_import::RtspImportCodec;
use fss_reference::ingest::rtsp_import::replay::query_retained_replay_time;
use fss_reference::rtsp::recording_replay::time::{
    REPLAY_TIME_END_EXCLUSIVE_NS, ReplayTimeQuery, ReplayTimeReport, ReplayTimeUnknown,
    query_replay_time,
};
use fss_reference::rtsp::recording_replay::{ReplayCodec, ReplayTermination};
use import_support::{Fixture, Test, context};
use support::{ERA_NS, query, timestamp_fixture};

fn retained(
    fixture: &Fixture,
    identity: ContentDigest,
    query: &ReplayTimeQuery,
    cancel: &dyn PublishCancellation,
) -> Test<ReplayTimeReport> {
    Ok(query_retained_replay_time(
        fixture.target()?,
        identity,
        query,
        RetainedReadLimits::default(),
        &fixture.cx,
        cancel,
    )?)
}

fn identical(left: &ReplayTimeReport, right: &ReplayTimeReport) {
    assert_eq!(left.query, right.query);
    assert_eq!(left.receipt.root(), right.receipt.root());
    assert_eq!(
        left.receipt.metadata_bytes(),
        right.receipt.metadata_bytes()
    );
    assert_eq!(left.digest, right.digest);
    assert_eq!(left.index_digest, right.index_digest);
    assert_eq!(left.scanned_windows, right.scanned_windows);
    assert_eq!(left.scanned_samples, right.scanned_samples);
    assert_eq!(left.scanned_packets, right.scanned_packets);
    assert_eq!(left.source_bytes_reserved, right.source_bytes_reserved);
    assert_eq!(left.source_bytes, right.source_bytes);
    assert_eq!(left.outside_samples, right.outside_samples);
    assert_eq!(left.matches, right.matches);
    assert_eq!(left.unknown, right.unknown);
    assert_eq!(left.source_only, right.source_only);
}

#[test]
fn cold_retained_avc_and_hevc_preserve_exact_archive_rows_digests_and_unknowns() -> Test {
    for codec in [RtspImportCodec::Avc, RtspImportCodec::Hevc] {
        let mut f = timestamp_fixture("retained-time-parity", codec)?;
        let initial = query(&f);
        let mut outside = initial.clone();
        outside.start_ns += 100_000_000_000;
        outside.end_ns += 100_000_000_000;
        let mut era = initial.clone();
        era.ntp_era = 1;
        era.start_ns += ERA_NS;
        era.end_ns += ERA_NS;
        let mut expected = Vec::new();
        for query in [&initial, &outside, &era] {
            expected.push(query_replay_time(
                f.source.as_ref().ok_or("source")?,
                query,
                &NeverCancel,
            )?);
        }
        let known = if codec == RtspImportCodec::Avc { 1 } else { 2 };
        assert_eq!(expected[0].matches.len(), known);
        assert_eq!(expected[0].unknown.len(), known * 2);
        assert!(
            expected[0]
                .unknown
                .iter()
                .any(|row| row.evidence.unknown == Some(ReplayTimeUnknown::MissingFirstExtension))
        );
        assert!(expected[0].unknown.iter().any(|row| row.evidence.unknown
            == Some(ReplayTimeUnknown::MalformedExtension(
                ReplayExtensionError::ReservedBits
            ))));
        assert_eq!(
            expected[0].source_only.len(),
            if codec == RtspImportCodec::Hevc { 3 } else { 0 }
        );
        assert!(expected[1].matches.is_empty());
        assert_eq!(expected[1].outside_samples, known);
        assert_eq!(expected[0].index_digest, expected[1].index_digest);
        assert_ne!(expected[0].digest, expected[1].digest);
        assert_ne!(expected[0].index_digest, expected[2].index_digest);
        let imported = f.run()?.import;
        assert_eq!(imported.capture_time_label, "unknown");
        f.assert_original_closure()?;
        f.offline_archive_and_reopen()?;
        let before = f.snapshot()?;
        let anchor = f.target()?.current_anchor().clone();
        for archive in &expected {
            let result = retained(&f, imported.import_identity, &archive.query, &NeverCancel)?;
            identical(archive, &result);
            assert_eq!(
                result.receipt.termination(),
                ReplayTermination::ProtocolFailure
            );
            assert!(!result.receipt.publication_complete());
            assert!(result.receipt.request().onvif_source().is_some());
        }
        assert_eq!(f.snapshot()?, before);
        assert_eq!(f.target()?.current_anchor(), &anchor);
        assert_eq!(
            f.retained(imported.import_identity)?
                .manifest()
                .capture_time_label,
            "unknown"
        );
    }
    Ok(())
}

#[test]
fn independent_pins_time_bounds_and_cumulative_limits_refuse_without_writes() -> Test {
    let mut f = timestamp_fixture("retained-time-bounds", RtspImportCodec::Hevc)?;
    let imported = f.run()?.import;
    let valid = query(&f);
    f.offline_archive_and_reopen()?;
    let before = f.snapshot()?;
    for case in 0..19 {
        let mut query = valid.clone();
        match case {
            0 => query.receipt_root = ContentDigest::sha256(b"unrelated replay root"),
            1 => query.request = ContentDigest::sha256(b"unrelated replay request"),
            2 => query.codec = ReplayCodec::Avc,
            3 => query.scope.recording.sensor = SensorId::parse("sensor:unrelated")?,
            4 => query.scope.recording.stream = StreamId::parse("stream:unrelated")?,
            5 => query.scope.recording.generation += 1,
            6 => query.scope.recording.anchor = ContentDigest::sha256(b"unrelated source owner"),
            7 => {
                query.scope.recording.receive_clock =
                    ContentDigest::sha256(b"unrelated receive clock")
            }
            8 => query.scope.decode_clock = f.receipt.request().base_decode_clock(),
            9 => query.scope.time_scale += 1,
            10 => query.start_ns = query.end_ns,
            11 => query.start_ns = -1,
            12 => query.end_ns = REPLAY_TIME_END_EXCLUSIVE_NS + 1,
            13 => query.limits.max_windows = 2,
            14 => query.limits.max_samples = f.frames - 1,
            15 => {
                query.limits.max_packets = f
                    .receipt
                    .windows()
                    .iter()
                    .map(|w| w.packets())
                    .sum::<usize>()
                    - 1
            }
            16 => query.limits.max_source_bytes = 3 * 32 * 1024 * 1024 - 1,
            17 => query.limits.max_results = 1,
            _ => query.limits.max_windows = 0,
        }
        assert!(
            retained(&f, imported.import_identity, &query, &NeverCancel).is_err(),
            "case {case}"
        );
        assert_eq!(f.snapshot()?, before, "case {case}");
    }
    assert!(
        retained(
            &f,
            ContentDigest::sha256(b"other import"),
            &valid,
            &NeverCancel
        )
        .is_err()
    );
    for case in 0..3 {
        let mut limits = RetainedReadLimits::default();
        match case {
            0 => limits.max_source_bytes = 1,
            1 => limits.max_chunk_bytes = 1,
            _ => limits.max_segment_bytes = 0,
        }
        assert!(
            query_retained_replay_time(
                f.target()?,
                imported.import_identity,
                &valid,
                limits,
                &f.cx,
                &NeverCancel,
            )
            .is_err()
        );
    }
    let wrong_context = context(&f.directory.0.join("unrelated-destination"))?;
    assert!(
        query_retained_replay_time(
            f.target()?,
            imported.import_identity,
            &valid,
            RetainedReadLimits::default(),
            &wrong_context,
            &NeverCancel,
        )
        .is_err()
    );
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn count_and_source_admission_precede_original_payload_read() -> Test {
    let mut f = timestamp_fixture("retained-time-admission", RtspImportCodec::Avc)?;
    let imported = f.run()?.import;
    let valid = query(&f);
    let packet = *f.packet_packs.last().ok_or("last original")?;
    fs::write(
        f.target()?.publisher().spool().object_path(packet),
        b"corrupt source",
    )?;
    let before = f.snapshot()?;
    for source_bound in [false, true] {
        let mut limited = valid.clone();
        if source_bound {
            limited.limits.max_source_bytes = 3 * 32 * 1024 * 1024 - 1;
        } else {
            limited.limits.max_windows = 2;
        }
        let refusal = query_retained_replay_time(
            f.target()?,
            imported.import_identity,
            &limited,
            RetainedReadLimits::default(),
            &f.cx,
            &NeverCancel,
        )
        .expect_err("whole-query limit was bypassed");
        assert_eq!(refusal.code(), "ERR-REPLAY-TIME-LIMIT-001");
    }
    assert!(retained(&f, imported.import_identity, &valid, &NeverCancel).is_err());
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn proof_companion_and_late_original_damage_refuse_even_after_a_successful_query() -> Test {
    let mut f = timestamp_fixture("retained-time-corrupt", RtspImportCodec::Hevc)?;
    let imported = f.run()?.import;
    let query = query(&f);
    f.offline_archive_and_reopen()?;
    let clean = retained(&f, imported.import_identity, &query, &NeverCancel)?;
    let before = f.snapshot()?;
    for digest in [
        imported.proof,
        f.receipt.root(),
        f.receipt.manifest().metadata_digest().ok_or("metadata")?,
        *f.packet_packs.last().ok_or("late original")?,
    ] {
        let path = f.target()?.publisher().spool().object_path(digest);
        let bytes = fs::read(&path)?;
        fs::write(&path, b"damaged retained recorder custody")?;
        assert!(retained(&f, imported.import_identity, &query, &NeverCancel).is_err());
        assert_eq!(f.snapshot()?, before);
        fs::write(path, bytes)?;
        identical(
            &clean,
            &retained(&f, imported.import_identity, &query, &NeverCancel)?,
        );
    }
    Ok(())
}

struct CancelAt {
    calls: Cell<usize>,
    stop: Option<usize>,
}
impl CancelAt {
    fn new(stop: Option<usize>) -> Self {
        Self {
            calls: Cell::new(0),
            stop,
        }
    }
}
impl PublishCancellation for CancelAt {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        let calls = self.calls.get() + 1;
        self.calls.set(calls);
        self.stop.is_some_and(|stop| calls >= stop)
    }
}

#[test]
fn interruption_at_admission_projection_and_final_revalidation_returns_no_report() -> Test {
    let mut f = timestamp_fixture("retained-time-cancel", RtspImportCodec::Hevc)?;
    let imported = f.run()?.import;
    let query = query(&f);
    let observed = CancelAt::new(None);
    let complete = retained(&f, imported.import_identity, &query, &observed)?;
    let calls = observed.calls.get();
    assert!(calls > 8);
    let before = f.snapshot()?;
    for at in [1, calls / 2, calls - 1] {
        assert!(
            retained(
                &f,
                imported.import_identity,
                &query,
                &CancelAt::new(Some(at))
            )
            .is_err()
        );
        assert_eq!(f.snapshot()?, before);
    }
    f.cx.request_cancellation();
    assert!(retained(&f, imported.import_identity, &query, &NeverCancel).is_err());
    f.cx = context(&f.directory.0.join("destination"))?;
    identical(
        &complete,
        &retained(&f, imported.import_identity, &query, &NeverCancel)?,
    );
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn committed_deletion_blocks_retained_utc_queries_but_preserves_separate_archive() -> Test {
    use fss_reference::deletion::{commit_deletion, plan_deletion};

    for codec in [RtspImportCodec::Avc, RtspImportCodec::Hevc] {
        let mut f = timestamp_fixture("retained-time-deleted", codec)?;
        let imported = f.run()?.import;
        let query = query(&f);
        let archive = query_replay_time(f.source.as_ref().ok_or("source")?, &query, &NeverCancel)?;
        identical(
            &archive,
            &retained(&f, imported.import_identity, &query, &NeverCancel)?,
        );
        let plan = plan_deletion(f.target()?, imported.import_identity, &f.cx)?;
        assert!(plan.blockers.is_empty());
        let approval = plan.approval_digest("principal:replay-import")?;
        commit_deletion(
            f.target.as_mut().ok_or("target")?,
            plan.digest()?,
            approval,
            "principal:replay-import",
            &f.cx,
        )?;
        let before = f.snapshot()?;
        assert!(retained(&f, imported.import_identity, &query, &NeverCancel).is_err());
        identical(
            &archive,
            &query_replay_time(f.source.as_ref().ok_or("source")?, &query, &NeverCancel)?,
        );
        assert_eq!(f.snapshot()?, before);
    }
    Ok(())
}
