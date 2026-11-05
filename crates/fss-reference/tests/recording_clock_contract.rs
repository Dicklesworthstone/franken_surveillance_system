#![forbid(unsafe_code)]
//! Retained clock admission, all-packet bounds, root custody and cold native replay.

mod collector_support;
#[path = "recording_clock_contract/support.rs"]
mod fixture;
#[path = "recording_clock_contract/storage.rs"]
mod storage;

use fixture::*;
use fss_core::ContentDigest;
use fss_reference::rtsp::recording_catalog::CatalogQueryLimits;
use fss_reference::rtsp::recording_clock::{
    MAX_CLOCK_BRACKETS, MAX_CLOCK_WINDOWS, RecordingClockCodec as Codec, RecordingClockError as E,
    RecordingClockIndex, UtcInterval, clock_slot,
};
use fss_reference::site::clock::ClockCorrelationError as C;

#[test]
fn every_source_coordinate_and_read_completion_bound_survives_arrival_reordering() -> TestResult {
    let recording = window(1, 0, &[60_000_000, 30_000_000])?;
    assert_eq!(
        recording
            .packets()?
            .iter()
            .map(|p| p.received_ns)
            .collect::<Vec<_>>(),
        vec![60_000_000, 30_000_000]
    );
    let original = descriptor("first", &recording)?;
    assert_eq!(original.packet_admissions(), &[30_000_000, 60_000_000]);
    let index = prepare(&[original], &[bracket(30_000_000), bracket(60_000_000)])?;
    // Independently calculated from the two fixed-point server timestamps,
    // asymmetric 20.001ms exchange, 1ns precision, nominal 15ppm allowance,
    // explicit 500ppm exchange/age drift, and the full native read completion.
    assert_eq!(
        index.windows()[0].utc_interval(),
        UtcInterval {
            earliest_ns: EPOCH + 1_019_983_696,
            latest_ns: EPOCH + 1_069_032_304,
        }
    );
    assert_eq!(index.windows()[0].decode_interval(), 0..3600);
    assert_eq!(index.windows()[0].root(), recording.manifest().root());
    assert_eq!(index.windows()[0].byte_len(), recording.byte_len());
    Ok(())
}

#[test]
fn packets_sharing_a_native_read_coordinate_keep_one_exact_bracket() -> TestResult {
    let recording = window(1, 0, &[30_000_000, 30_000_000])?;
    let original = descriptor("first", &recording)?;
    let index = prepare(&[original], &[bracket(30_000_000)])?;
    assert_eq!(recording.summary().packets, 2);
    assert_eq!(index.windows()[0].packet_admissions(), &[30_000_000]);
    assert_eq!(index.brackets(), &[bracket(30_000_000)]);
    Ok(())
}

#[test]
fn compatible_unused_reads_are_checked_then_clipped_without_changing_identity() -> TestResult {
    let recording = window(1, 0, &[30_000_000, 60_000_000])?;
    let windows = [descriptor("first", &recording)?];
    let compact = prepare(&windows, &[bracket(30_000_000), bracket(60_000_000)])?;
    let mut brackets = [
        bracket(30_000_000),
        bracket(40_000_000),
        bracket(60_000_000),
    ];
    let extra = prepare(&windows, &brackets)?;
    assert_eq!(extra.root(), compact.root());
    assert_eq!(extra.index_bytes(), compact.index_bytes());
    assert_eq!(extra.brackets().len(), 2);
    brackets[1].completed.wall_clock_unix_ns += 1_000_000_000;
    assert!(matches!(
        RecordingClockIndex::prepare(
            catalog_scope()?,
            Codec::Avc,
            approval(),
            exchange()?,
            host(100_000_000),
            &brackets,
            &windows,
        ),
        Err(E::Correlation(C::WallClockDiscontinuity))
    ));
    Ok(())
}

#[test]
fn clipped_wide_samples_cannot_hide_a_contradiction_in_the_retained_table() -> TestResult {
    let recording = window(1, 0, &[30_000_000, 60_000_000])?;
    let mut early = bracket(30_000_000);
    early.completed.wall_clock_unix_ns += 4_000;
    let mut omitted = bracket(40_000_000);
    omitted.completed.monotonic_after_ns = 41_001_000;
    omitted.completed.wall_clock_unix_ns = EPOCH + 40_501_000;
    let mut late = bracket(60_000_000);
    late.completed.wall_clock_unix_ns -= 15_000;
    let brackets = [early, omitted, late];
    let source = exchange()?;
    // Each origin comparison and each supplied adjacent pair admits these
    // bracketed samples. The wide unused middle sample bridges two incompatible
    // retained neighbours; publishing only those neighbours would not reopen.
    let mut all = source.correlation()?;
    for sample in &brackets {
        all.observe_later_sample(sample.completed)?;
    }
    all.observe_later_sample(host(100_000_000))?;
    assert!(matches!(
        RecordingClockIndex::prepare(
            catalog_scope()?,
            Codec::Avc,
            approval(),
            source,
            host(100_000_000),
            &brackets,
            &[descriptor("first", &recording)?],
        ),
        Err(E::Correlation(C::WallClockDiscontinuity))
    ));
    Ok(())
}

#[test]
fn missing_duplicate_reordered_or_overlapping_read_brackets_are_refused() -> TestResult {
    let recording = window(1, 0, &[30_000_000, 60_000_000])?;
    let windows = [descriptor("first", &recording)?];
    let scope = catalog_scope()?;
    let source = exchange()?;
    let admit = |brackets: &[_]| {
        RecordingClockIndex::prepare(
            scope.clone(),
            Codec::Avc,
            approval(),
            source,
            host(100_000_000),
            brackets,
            &windows,
        )
    };
    assert!(matches!(
        admit(&[bracket(30_000_000)]),
        Err(E::MissingBracket)
    ));
    assert!(matches!(
        admit(&[bracket(30_000_000), bracket(30_000_000)]),
        Err(E::Order)
    ));
    assert!(matches!(
        admit(&[bracket(60_000_000), bracket(30_000_000)]),
        Err(E::Order)
    ));
    let mut overlap = bracket(30_000_000);
    overlap.completed = host(60_000_001);
    assert!(matches!(
        admit(&[overlap, bracket(60_000_000)]),
        Err(E::Order)
    ));
    let mut reversed = bracket(30_000_000);
    reversed.completed.monotonic_after_ns = reversed.completed.monotonic_before_ns - 1;
    assert!(matches!(
        admit(&[reversed, bracket(60_000_000)]),
        Err(E::Order)
    ));
    Ok(())
}

#[test]
fn terminal_discontinuity_expiry_or_reads_before_synchronization_refuse_all_windows() -> TestResult
{
    let recording = window(1, 0, &[30_000_000])?;
    let windows = [descriptor("first", &recording)?];
    for delta in [-1_000_000_000_i64, 1_000_000_000] {
        let mut terminal = host(100_000_000);
        terminal.wall_clock_unix_ns = terminal
            .wall_clock_unix_ns
            .checked_add_signed(delta)
            .ok_or("fixture time")?;
        assert!(matches!(
            RecordingClockIndex::prepare(
                catalog_scope()?,
                Codec::Avc,
                approval(),
                exchange()?,
                terminal,
                &[bracket(30_000_000)],
                &windows,
            ),
            Err(E::Correlation(C::WallClockDiscontinuity))
        ));
    }
    assert!(matches!(
        RecordingClockIndex::prepare(
            catalog_scope()?,
            Codec::Avc,
            approval(),
            exchange()?,
            host(61_000_000_000),
            &[bracket(30_000_000)],
            &windows,
        ),
        Err(E::Correlation(C::Expired))
    ));
    assert!(matches!(
        RecordingClockIndex::prepare(
            catalog_scope()?,
            Codec::Avc,
            approval(),
            exchange()?,
            host(29_000_000),
            &[bracket(30_000_000)],
            &windows,
        ),
        Err(E::Order)
    ));
    let early = window(1, 0, &[20_000_999])?;
    assert!(matches!(
        RecordingClockIndex::prepare(
            catalog_scope()?,
            Codec::Avc,
            approval(),
            exchange()?,
            host(100_000_000),
            &[bracket(20_000_999)],
            &[descriptor("early", &early)?],
        ),
        Err(E::Order)
    ));
    Ok(())
}

#[test]
fn exact_scope_codec_and_approval_are_required_before_preparation() -> TestResult {
    let recording = window(1, 0, &[30_000_000])?;
    let windows = [descriptor("first", &recording)?];
    let scope = catalog_scope()?;
    for field in 0..5 {
        let mut wrong = scope.clone();
        match field {
            0 => wrong.recording.generation += 1,
            1 => wrong.recording.receive_clock = ContentDigest::sha256(b"other capture session"),
            2 => wrong.recording.anchor = ContentDigest::sha256(b"other source owner"),
            3 => wrong.time_scale = 48_000,
            _ => {
                wrong.decode_clock = ContentDigest::new(fss_core::DigestAlgorithm::Sha256, [0; 32])
            }
        }
        assert!(matches!(
            RecordingClockIndex::prepare(
                wrong,
                Codec::Avc,
                approval(),
                exchange()?,
                host(100_000_000),
                &[bracket(30_000_000)],
                &windows,
            ),
            Err(E::Scope)
        ));
    }
    assert!(matches!(
        RecordingClockIndex::prepare(
            scope.clone(),
            Codec::Hevc,
            approval(),
            exchange()?,
            host(100_000_000),
            &[bracket(30_000_000)],
            &windows,
        ),
        Err(E::Scope)
    ));
    assert!(matches!(
        RecordingClockIndex::prepare(
            scope,
            Codec::Avc,
            ContentDigest::new(fss_core::DigestAlgorithm::Sha256, [0; 32]),
            exchange()?,
            host(100_000_000),
            &[bracket(30_000_000)],
            &windows,
        ),
        Err(E::Scope)
    ));
    Ok(())
}

#[test]
fn duplicate_roots_slots_and_noncanonical_decode_order_are_refused() -> TestResult {
    let first = window(1, 0, &[30_000_000])?;
    let second = window(3, 7200, &[60_000_000])?;
    let a = descriptor("first", &first)?;
    let b = descriptor("second", &second)?;
    for windows in [
        vec![a.clone(), a.clone()],
        vec![a.clone(), descriptor("first", &second)?],
        vec![b.clone(), a.clone()],
    ] {
        assert!(matches!(
            RecordingClockIndex::prepare(
                catalog_scope()?,
                Codec::Avc,
                approval(),
                exchange()?,
                host(100_000_000),
                &[bracket(30_000_000), bracket(60_000_000)],
                &windows,
            ),
            Err(E::Order)
        ));
    }
    let index = prepare(&[a, b], &[bracket(30_000_000), bracket(60_000_000)])?;
    assert_eq!(index.windows()[1].decode_interval(), 7200..10800);
    Ok(())
}

#[test]
fn half_open_queries_observe_closed_endpoints_and_keep_the_whole_window_cost() -> TestResult {
    let recording = window(1, 0, &[30_000_000])?;
    let index = prepare(&[descriptor("first", &recording)?], &[bracket(30_000_000)])?;
    let interval = index.windows()[0].utc_interval();
    for (query, ordinals) in [
        (interval.latest_ns..interval.latest_ns + 1, vec![0]),
        (interval.earliest_ns - 1..interval.earliest_ns, vec![]),
        (interval.latest_ns + 1..interval.latest_ns + 2, vec![]),
    ] {
        let selected = index.select(query.clone(), CatalogQueryLimits::default())?;
        assert_eq!(selected.query(), query);
        assert_eq!(selected.ordinals(), ordinals);
        assert_eq!(
            selected.output_bytes(),
            if ordinals.is_empty() {
                0
            } else {
                recording.byte_len() as u64
            }
        );
    }
    assert!(matches!(
        index.select(4..4, CatalogQueryLimits::default()),
        Err(E::Interval)
    ));
    Ok(())
}

#[test]
fn selection_refuses_count_and_byte_overflow_atomically_without_truncation() -> TestResult {
    let a = window(1, 0, &[30_000_000])?;
    let b = window(3, 7200, &[60_000_000])?;
    let index = prepare(
        &[descriptor("first", &a)?, descriptor("second", &b)?],
        &[bracket(30_000_000), bracket(60_000_000)],
    )?;
    let interval = index.windows()[0].utc_interval().earliest_ns
        ..index.windows()[1].utc_interval().latest_ns + 1;
    let total = (a.byte_len() + b.byte_len()) as u64;
    assert!(matches!(
        index.select(
            interval.clone(),
            CatalogQueryLimits {
                max_windows: 1,
                max_output_bytes: total
            }
        ),
        Err(E::Limit)
    ));
    assert!(matches!(
        index.select(
            interval.clone(),
            CatalogQueryLimits {
                max_windows: 2,
                max_output_bytes: total - 1
            }
        ),
        Err(E::Limit)
    ));
    let result = index.select(
        interval,
        CatalogQueryLimits {
            max_windows: 2,
            max_output_bytes: total,
        },
    )?;
    assert_eq!(result.ordinals(), &[0, 1]);
    assert_eq!(result.output_bytes(), total);
    Ok(())
}

#[test]
fn immutable_root_binds_exact_exchange_peer_approval_and_final_sample() -> TestResult {
    let recording = window(1, 0, &[30_000_000])?;
    let windows = [descriptor("first", &recording)?];
    let brackets = [bracket(30_000_000)];
    let base = prepare(&windows, &brackets)?;
    for changed in 0..4 {
        let mut source = exchange()?;
        let mut permit = approval();
        let mut terminal = host(100_000_000);
        match changed {
            0 => source.reply[12..16].copy_from_slice(b"NEXT"),
            1 => source.peer = "127.0.0.1:4123".parse()?,
            2 => permit = ContentDigest::sha256(b"distinct explicit capture approval"),
            _ => terminal = host(200_000_000),
        }
        let index = RecordingClockIndex::prepare(
            catalog_scope()?,
            Codec::Avc,
            permit,
            source,
            terminal,
            &brackets,
            &windows,
        )?;
        assert_eq!(index.windows(), base.windows());
        assert_ne!(index.root(), base.root());
        assert_eq!(
            clock_slot(index.codec(), index.scope())?,
            clock_slot(base.codec(), base.scope())?
        );
    }
    let mut other = catalog_scope()?;
    other.recording.receive_clock = ContentDigest::sha256(b"separate capture clock");
    assert_ne!(
        clock_slot(Codec::Avc, &other)?,
        clock_slot(Codec::Avc, base.scope())?
    );
    assert_ne!(
        clock_slot(Codec::Hevc, base.scope())?,
        clock_slot(Codec::Avc, base.scope())?
    );
    Ok(())
}

#[test]
fn count_ceiling_is_refused_before_oversized_input_is_walked() -> TestResult {
    let recording = window(1, 0, &[30_000_000])?;
    let original = descriptor("first", &recording)?;
    let windows = vec![original.clone(); MAX_CLOCK_WINDOWS + 1];
    assert!(matches!(
        RecordingClockIndex::prepare(
            catalog_scope()?,
            Codec::Avc,
            approval(),
            exchange()?,
            host(100_000_000),
            &[bracket(30_000_000)],
            &windows
        ),
        Err(E::Limit)
    ));
    let brackets = vec![bracket(30_000_000); MAX_CLOCK_BRACKETS + 1];
    assert!(matches!(
        RecordingClockIndex::prepare(
            catalog_scope()?,
            Codec::Avc,
            approval(),
            exchange()?,
            host(100_000_000),
            &brackets,
            &[original]
        ),
        Err(E::Limit)
    ));
    Ok(())
}
