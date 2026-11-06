#![forbid(unsafe_code)]
//! Movie-time semantics over independently authored sample tables and retained real media.

use super::*;

fn box_size(bytes: &[u8], at: usize) -> usize {
    u32::from_be_bytes(bytes[at..at + 4].try_into().expect("fixture size")) as usize
}

fn replace_table(bytes: &mut Vec<u8>, kind: &[u8; 4], replacement: &[u8]) {
    let at = field(bytes, kind, 0) - 8;
    let old = box_size(bytes, at);
    for parent in [b"stbl", b"minf", b"mdia", b"trak", b"moov"] {
        let parent_at = field(bytes, parent, 0) - 8;
        let size = box_size(bytes, parent_at) - old + replacement.len();
        patch32(bytes, parent_at, size as u32);
    }
    bytes.splice(at..at + old, replacement.iter().copied());
}

fn append_table(bytes: &mut Vec<u8>, extra: &[u8]) {
    let table_at = field(bytes, b"stbl", 0) - 8;
    let insert = table_at + box_size(bytes, table_at);
    for parent in [b"stbl", b"minf", b"mdia", b"trak", b"moov"] {
        let at = field(bytes, parent, 0) - 8;
        let size = box_size(bytes, at) + extra.len();
        patch32(bytes, at, size as u32);
    }
    bytes.splice(insert..insert, extra.iter().copied());
}

/// A real indexed MP4: table offsets, edit versions, and NAL headers go through the public
/// parser before the selector sees them. Every sample lasts ten media ticks and has eight
/// payload bytes; `offsets` supplies signed `ctts` values in decode order.
fn timed_fixture(
    offsets: &[i32],
    random_access: &[usize],
    movie_scale: u32,
    media_scale: u32,
    edits: &[(u64, i64)],
) -> Fixture {
    let mut f = fixture(
        Options {
            signed_ctts: true,
            ..Options::default()
        },
        &vec![8; offsets.len()],
    );
    for (i, offset) in offsets.iter().enumerate() {
        let at = field(&f.bytes, b"ctts", 12 + i * 8);
        patch32(&mut f.bytes, at, *offset as u32);
        let header = if random_access.contains(&i) {
            0x65
        } else {
            0x41
        };
        f.bytes[f.sources[i].start + 4] = header;
        f.payloads[i][0] = header;
    }
    for (kind, scale) in [(b"mvhd", movie_scale), (b"mdhd", media_scale)] {
        let at = field(&f.bytes, kind, 12);
        patch32(&mut f.bytes, at, scale);
    }
    let sync = table(
        b"stss",
        &random_access
            .iter()
            .map(|n| *n as u32 + 1)
            .collect::<Vec<_>>(),
        1,
    );
    replace_table(&mut f.bytes, b"stss", &sync);
    if !edits.is_empty() {
        let mut rows = words(&[edits.len() as u32]);
        for (duration, media_time) in edits {
            rows.extend_from_slice(&duration.to_be_bytes());
            rows.extend_from_slice(&media_time.to_be_bytes());
            rows.extend_from_slice(&0x0001_0000_u32.to_be_bytes());
        }
        let edts = atom(b"edts", &full_atom(b"elst", 1, 0, &rows));
        let track_at = field(&f.bytes, b"trak", 0) - 8;
        let insert = track_at + box_size(&f.bytes, track_at);
        for parent in [b"trak", b"moov"] {
            let at = field(&f.bytes, parent, 0) - 8;
            let size = box_size(&f.bytes, at) + edts.len();
            patch32(&mut f.bytes, at, size as u32);
        }
        f.bytes.splice(insert..insert, edts);
    }
    f
}

fn exact(start: u128, end: u128, denominator: u32) -> MovieInterval {
    MovieInterval {
        start_numerator: start,
        end_numerator: end,
        denominator,
    }
}

fn indices(selection: &MovieSelection) -> Vec<usize> {
    selection.samples.iter().map(|s| s.sample_index).collect()
}

fn verify_quotes(parsed: &AvcMp4<'_>, selection: &MovieSelection) -> Test {
    let mut bytes = 0;
    let mut end = 0;
    for span in &selection.decode_spans {
        assert!(span.first_sample >= end);
        end = span.first_sample + span.sample_count;
        let stream = parsed.annex_b(span.first_sample, span.sample_count)?;
        assert_eq!(span.annex_b_bytes, stream.bytes().len() as u64);
        assert_eq!(
            span.source_bytes,
            parsed.samples()[span.first_sample..end]
                .iter()
                .map(|s| s.source.len() as u64)
                .sum::<u64>()
        );
        for copy in stream.mappings() {
            assert_eq!(
                &stream.bytes()[copy.output_start..copy.output_start + copy.source.len()],
                &parsed.source()[copy.source.clone()]
            );
        }
        bytes += stream.bytes().len() as u64;
    }
    assert_eq!(bytes, selection.annex_b_bytes);
    Ok(())
}

#[test]
fn signed_offsets_and_fractional_movie_ticks_select_whole_original_samples() -> Test {
    let f = timed_fixture(&[-5; 4], &[0], 1000, 300, &[]);
    let p = AvcMp4::parse(&f.bytes, None, DemuxLimits::default())?;
    let selected = p.select_movie_interval(16..34, MovieSelectionLimits::default())?;
    assert_eq!(indices(&selected), [0, 1]);
    assert_eq!(selected.samples[0].interval, exact(4800, 5000, 300));
    assert_eq!(selected.samples[1].interval, exact(5000, 10_200, 300));
    assert_eq!(selected.samples[0].source, f.sources[0]);
    assert_eq!(selected.samples[1].source, f.sources[1]);
    assert!(selected.gaps.is_empty());
    assert_eq!(selected.sample_bytes, 24);
    assert_eq!(selected.decode_bytes, 24);
    verify_quotes(&p, &selected)?;
    let boundary = p.select_movie_interval(50..51, MovieSelectionLimits::default())?;
    assert_eq!(indices(&boundary), [2]);
    assert_eq!(boundary.samples[0].interval, exact(15_000, 15_300, 300));
    let gap = p.select_movie_interval(117..133, MovieSelectionLimits::default())?;
    assert!(gap.samples.is_empty());
    assert!(gap.decode_spans.is_empty());
    assert_eq!(gap.gaps[0].interval, exact(35_100, 39_900, 300));
    Ok(())
}

#[test]
fn b_frames_keep_presentation_order_distinct_from_decode_prerequisites() -> Test {
    // Presentation bins in coding order: 0, 3, 1, 2, 4.
    let f = timed_fixture(&[0, 20, -10, -10, 0], &[0], 1000, 100, &[]);
    let p = AvcMp4::parse(&f.bytes, None, DemuxLimits::default())?;
    let s = p.select_movie_interval(100..300, MovieSelectionLimits::default())?;
    assert_eq!(indices(&s), [2, 3]);
    assert!(s.gaps.is_empty());
    assert_eq!(s.sample_bytes, 24);
    assert_eq!(s.decode_bytes, 48);
    assert_eq!(s.decode_spans.len(), 1);
    assert_eq!(s.decode_spans[0].first_sample, 0);
    assert_eq!(s.decode_spans[0].sample_count, 4);
    assert_eq!(s.decode_spans[0].requested_samples, [2, 3]);
    // Coding sample 1 presents after the query, but must remain in the extraction span.
    assert_eq!(p.samples()[1].presentation_time(), 30);
    verify_quotes(&p, &s)
}

#[test]
fn empty_trimmed_and_repeated_edits_preserve_appearance_and_source_identity() -> Test {
    let f = timed_fixture(
        &[0, 0, 0],
        &[0],
        1000,
        100,
        &[(100, -1), (200, 10), (100, 0), (100, 10), (50, -1)],
    );
    let p = AvcMp4::parse(&f.bytes, None, DemuxLimits::default())?;
    let s = p.select_movie_interval(50..600, MovieSelectionLimits::default())?;
    assert_eq!(indices(&s), [1, 2, 0, 1]);
    assert_eq!(
        s.samples.iter().map(|r| r.edit_index).collect::<Vec<_>>(),
        [Some(1), Some(1), Some(2), Some(3)]
    );
    assert_eq!(s.samples[0].source, s.samples[3].source);
    assert_eq!(s.sample_bytes, 36);
    assert_eq!(s.decode_bytes, 36);
    assert_eq!(s.decode_spans[0].requested_samples, [0, 1, 2]);
    assert_eq!(
        s.gaps,
        [
            MovieGap {
                interval: exact(5000, 10_000, 100),
                kind: MovieGapKind::EmptyEdit
            },
            MovieGap {
                interval: exact(50_000, 55_000, 100),
                kind: MovieGapKind::EmptyEdit
            },
            MovieGap {
                interval: exact(55_000, 60_000, 100),
                kind: MovieGapKind::Unrepresented
            },
        ]
    );
    assert_eq!(s.edits.len(), 5);
    assert_eq!(s.edits[0].media_time, None);
    assert_eq!(s.edits[1].media_time, Some(10));
    verify_quotes(&p, &s)
}

#[test]
fn edit_endpoints_between_media_ticks_do_not_round_away_a_visible_sample() -> Test {
    let f = timed_fixture(&[0, 0], &[0], 1000, 300, &[(33, 1), (1, -1)]);
    let p = AvcMp4::parse(&f.bytes, None, DemuxLimits::default())?;
    let s = p.select_movie_interval(0..34, MovieSelectionLimits::default())?;
    assert_eq!(indices(&s), [0, 1]);
    assert_eq!(s.samples[0].interval, exact(0, 9000, 300));
    assert_eq!(s.samples[1].interval, exact(9000, 9900, 300));
    assert_eq!(
        s.gaps,
        [MovieGap {
            interval: exact(9900, 10_200, 300),
            kind: MovieGapKind::EmptyEdit
        }]
    );
    assert_eq!(s.samples[1].source, f.sources[1]);
    Ok(())
}

#[test]
fn separate_random_access_runs_do_not_import_unrelated_earlier_gops() -> Test {
    let f = timed_fixture(&[0; 10], &[0, 3, 6], 1000, 100, &[]);
    let p = AvcMp4::parse(&f.bytes, None, DemuxLimits::default())?;
    let s = p.select_movie_interval(400..800, MovieSelectionLimits::default())?;
    assert_eq!(indices(&s), [4, 5, 6, 7]);
    assert_eq!(
        s.decode_spans
            .iter()
            .map(|r| (r.first_sample, r.sample_count))
            .collect::<Vec<_>>(),
        [(3, 3), (6, 2)]
    );
    assert_eq!(s.decode_spans[0].requested_samples, [4, 5]);
    assert_eq!(s.decode_spans[1].requested_samples, [6, 7]);
    assert_eq!(s.decode_bytes, 60);
    verify_quotes(&p, &s)
}

#[test]
fn absent_or_mismatched_random_access_refuses_without_guessing() -> Test {
    for has_sync in [false, true] {
        let mut f = timed_fixture(&[0, 0], if has_sync { &[0] } else { &[] }, 1000, 100, &[]);
        // Separately exercise IDR-without-sync and sync-without-IDR.
        f.bytes[f.sources[0].start + 4] = if has_sync { 0x41 } else { 0x65 };
        let p = AvcMp4::parse(&f.bytes, None, DemuxLimits::default())?;
        assert_eq!(
            p.select_movie_interval(100..200, MovieSelectionLimits::default()),
            Err(DemuxError::RandomAccessRequired)
        );
        let outside = p.select_movie_interval(200..300, MovieSelectionLimits::default())?;
        assert!(outside.samples.is_empty());
        assert_eq!(
            outside.gaps,
            [MovieGap {
                interval: exact(20_000, 30_000, 100),
                kind: MovieGapKind::Unrepresented
            }]
        );
    }
    Ok(())
}

#[test]
fn adversarial_presentation_order_is_sorted_and_duplicate_timestamps_refuse() -> Test {
    for count in [2, 7, 64] {
        for rotation in [0, 1, count / 2] {
            let offsets: Vec<_> = (0..count)
                .map(|i| (((count - i - 1 + rotation) % count) as i32 - i as i32) * 10)
                .collect();
            let f = timed_fixture(&offsets, &[0], 1000, 100, &[]);
            let p = AvcMp4::parse(&f.bytes, None, DemuxLimits::default())?;
            let s =
                p.select_movie_interval(0..count as u64 * 100, MovieSelectionLimits::default())?;
            let expected: Vec<_> = (0..count)
                .map(|bin| (count - 1 + rotation - bin) % count)
                .collect();
            assert_eq!(indices(&s), expected);
            assert!(s.gaps.is_empty());
        }
    }
    let f = timed_fixture(&[0, -10, -20, -30], &[0], 1000, 100, &[]);
    let p = AvcMp4::parse(&f.bytes, None, DemuxLimits::default())?;
    assert_eq!(
        p.select_movie_interval(0..200, MovieSelectionLimits::default()),
        Err(DemuxError::Timeline)
    );
    Ok(())
}

#[test]
fn reordered_variable_durations_admit_when_the_presentation_grid_is_exact() -> Test {
    // Coding DTS/duration: (0,10), (10,20), (30,30); presentation order is 0,2,1.
    let mut f = timed_fixture(&[0, 30, -20], &[0], 1000, 100, &[]);
    replace_table(
        &mut f.bytes,
        b"stts",
        &table(b"stts", &[1, 10, 1, 20, 1, 30], 2),
    );
    let duration = field(&f.bytes, b"mdhd", 16);
    patch32(&mut f.bytes, duration, 60);
    let p = AvcMp4::parse(&f.bytes, None, DemuxLimits::default())?;
    let s = p.select_movie_interval(100..500, MovieSelectionLimits::default())?;
    assert_eq!(indices(&s), [2, 1]);
    assert_eq!(s.samples[0].interval, exact(10_000, 40_000, 100));
    assert_eq!(s.samples[1].interval, exact(40_000, 50_000, 100));
    assert!(s.gaps.is_empty());
    verify_quotes(&p, &s)
}

#[test]
fn inconsistent_composition_duration_and_cslg_refuse_only_the_new_selector() -> Test {
    let irregular = timed_fixture(&[-5, 0, 0], &[0], 1000, 100, &[]);
    let p = AvcMp4::parse(&irregular.bytes, None, DemuxLimits::default())?;
    assert!(p.annex_b(0, 3).is_ok());
    assert_eq!(
        p.select_movie_interval(0..100, MovieSelectionLimits::default()),
        Err(DemuxError::Unsupported)
    );
    let mut f = timed_fixture(&[0; 3], &[0], 1000, 100, &[]);
    let original = AvcMp4::parse(&f.bytes, None, DemuxLimits::default())?
        .annex_b(0, 3)?
        .bytes()
        .to_vec();
    // Even an apparently zero shift must not silently pick between ISO and QuickTime cslg.
    append_table(
        &mut f.bytes,
        &full_atom(b"cslg", 0, 0, &words(&[0, 0, 0, 0, 30])),
    );
    let p = AvcMp4::parse(&f.bytes, None, DemuxLimits::default())?;
    assert_eq!(p.annex_b(0, 3)?.bytes(), original);
    assert_eq!(
        p.select_movie_interval(0..100, MovieSelectionLimits::default()),
        Err(DemuxError::Unsupported)
    );
    Ok(())
}

#[test]
fn all_output_and_work_limits_are_exact_and_include_preroll() -> Test {
    let f = timed_fixture(&[0, 20, -10, -10, 0], &[0], 1000, 100, &[]);
    let p = AvcMp4::parse(&f.bytes, None, DemuxLimits::default())?;
    let s = p.select_movie_interval(100..300, MovieSelectionLimits::default())?;
    let rows = s.samples.len()
        + s.edits.len()
        + s.gaps.len()
        + s.decode_spans.len()
        + s.decode_spans
            .iter()
            .map(|r| r.requested_samples.len())
            .sum::<usize>();
    let exact_limits = MovieSelectionLimits {
        max_work: s.work,
        max_rows: rows,
        max_decode_samples: 4,
        max_source_bytes: s.decode_bytes,
        max_annex_b_bytes: s.annex_b_bytes,
    };
    assert_eq!(p.select_movie_interval(100..300, exact_limits)?, s);
    for limits in [
        MovieSelectionLimits {
            max_work: s.work - 1,
            ..exact_limits
        },
        MovieSelectionLimits {
            max_rows: rows - 1,
            ..exact_limits
        },
        MovieSelectionLimits {
            max_decode_samples: 3,
            ..exact_limits
        },
        MovieSelectionLimits {
            max_source_bytes: s.sample_bytes,
            ..exact_limits
        },
        MovieSelectionLimits {
            max_annex_b_bytes: s.annex_b_bytes - 1,
            ..exact_limits
        },
    ] {
        assert_eq!(
            p.select_movie_interval(100..300, limits),
            Err(DemuxError::Limit)
        );
    }
    // A successful parse does not widen the existing extraction output ceiling.
    let small = AvcMp4::parse(
        &f.bytes,
        None,
        DemuxLimits {
            maximum_output_bytes: 1,
            ..DemuxLimits::default()
        },
    )?;
    assert_eq!(
        small.select_movie_interval(100..300, MovieSelectionLimits::default()),
        Err(DemuxError::Limit)
    );
    Ok(())
}

#[test]
fn cancellation_refuses_at_every_phase_without_partial_rows() -> Test {
    let f = timed_fixture(
        &[0, 20, -10, -10, 0],
        &[0],
        1000,
        100,
        &[(50, -1), (500, 0)],
    );
    let p = AvcMp4::parse(&f.bytes, None, DemuxLimits::default())?;
    let mut calls = 0;
    let full = p.select_movie_interval_with_checkpoint(
        0..600,
        MovieSelectionLimits::default(),
        &mut || {
            calls += 1;
            Ok(())
        },
    )?;
    assert!(!full.samples.is_empty());
    for cancel_at in 0..calls {
        let mut seen = 0;
        let result = p.select_movie_interval_with_checkpoint(
            0..600,
            MovieSelectionLimits::default(),
            &mut || {
                if seen == cancel_at {
                    return Err(DemuxError::Cancelled);
                }
                seen += 1;
                Ok(())
            },
        );
        assert_eq!(result, Err(DemuxError::Cancelled), "checkpoint {cancel_at}");
    }
    Ok(())
}

#[test]
fn invalid_ranges_limits_and_cumulative_edit_overflow_refuse() -> Test {
    let f = timed_fixture(&[0], &[0], u32::MAX, u32::MAX, &[]);
    let p = AvcMp4::parse(&f.bytes, None, DemuxLimits::default())?;
    for query in [0..0, 100..99] {
        assert_eq!(
            p.select_movie_interval(query, MovieSelectionLimits::default()),
            Err(DemuxError::Timeline)
        );
    }
    for bad in [
        MovieSelectionLimits {
            max_work: 0,
            ..MovieSelectionLimits::default()
        },
        MovieSelectionLimits {
            max_work: usize::MAX,
            ..MovieSelectionLimits::default()
        },
        MovieSelectionLimits {
            max_rows: usize::MAX,
            ..MovieSelectionLimits::default()
        },
        MovieSelectionLimits {
            max_decode_samples: usize::MAX,
            ..MovieSelectionLimits::default()
        },
        MovieSelectionLimits {
            max_source_bytes: u64::MAX,
            ..MovieSelectionLimits::default()
        },
        MovieSelectionLimits {
            max_annex_b_bytes: u64::MAX,
            ..MovieSelectionLimits::default()
        },
    ] {
        assert_eq!(bad.validate(), Err(DemuxError::Limit));
    }
    let far = p.select_movie_interval(u64::MAX - 1..u64::MAX, MovieSelectionLimits::default())?;
    assert_eq!(
        far.gaps[0].interval,
        exact(
            u128::from(u64::MAX - 1) * u128::from(u32::MAX),
            u128::from(u64::MAX) * u128::from(u32::MAX),
            u32::MAX
        )
    );
    let overflow = timed_fixture(&[0], &[0], 1000, 100, &[(u64::MAX, -1), (1, -1)]);
    let p = AvcMp4::parse(&overflow.bytes, None, DemuxLimits::default())?;
    assert_eq!(
        p.select_movie_interval(0..1, MovieSelectionLimits::default()),
        Err(DemuxError::Timeline)
    );
    Ok(())
}

#[test]
fn retained_b_frame_fixture_has_known_movie_selection_and_exact_bootstrap_quote() -> Test {
    let p = AvcMp4::parse(
        include_bytes!("../../../tests/fixtures/indexed_avc.mp4"),
        None,
        DemuxLimits::default(),
    )?;
    let complete = p.select_movie_interval(0..2000, MovieSelectionLimits::default())?;
    assert_eq!(complete.movie_timescale, 1000);
    assert_eq!(complete.samples.len(), 10);
    assert!(complete.gaps.is_empty());
    let first = p.select_movie_interval(0..1, MovieSelectionLimits::default())?;
    assert_eq!(indices(&first), [0]);
    assert!(first.decode_bytes < 4338);
    let s = p.select_movie_interval(400..800, MovieSelectionLimits::default())?;
    assert_eq!(indices(&s), [3, 1]);
    assert_eq!(s.decode_spans[0].first_sample, 0);
    assert_eq!(s.decode_spans[0].sample_count, 4);
    assert_eq!(s.decode_spans[0].requested_samples, [1, 3]);
    assert!(s.gaps.is_empty());
    assert_eq!(
        s.samples[0].interval,
        exact(400 * 10_240, 600 * 10_240, 10_240)
    );
    assert_eq!(
        s.samples[1].interval,
        exact(600 * 10_240, 800 * 10_240, 10_240)
    );
    verify_quotes(&p, &s)
}

#[test]
fn fragmented_hevc_and_inband_selections_use_the_same_bootstrap_as_extraction() -> Test {
    for bytes in [
        include_bytes!("../../../tests/fixtures/interleaved_av.mp4").as_slice(),
        include_bytes!("../../../tests/fixtures/fragmented_av.mp4").as_slice(),
        include_bytes!("../../../tests/fixtures/hevc_av.mp4").as_slice(),
        include_bytes!("../../../tests/fixtures/hevc_fragmented_av.mp4").as_slice(),
        include_bytes!("../../../tests/fixtures/qt_av.mov").as_slice(),
        include_bytes!("../../../tests/fixtures/qt_hevc.mov").as_slice(),
        include_bytes!("../../../tests/fixtures/inband/avc3_partial_change.mp4").as_slice(),
        include_bytes!("../../../tests/fixtures/inband/hev1_partial_change.mp4").as_slice(),
        include_bytes!("../../../tests/fixtures/inband/avc3_empty_change.mp4").as_slice(),
        include_bytes!("../../../tests/fixtures/inband/hev1_empty_change.mp4").as_slice(),
        include_bytes!("../../../tests/fixtures/inband/avc3_later_pps_entry.mp4").as_slice(),
        include_bytes!("../../../tests/fixtures/inband/hev1_later_pps_entry.mp4").as_slice(),
    ] {
        let p = AvcMp4::parse_inband(bytes, None, DemuxLimits::default())?;
        let s = p.select_movie_interval(0..10_000_000, MovieSelectionLimits::default())?;
        assert!(!s.samples.is_empty());
        assert_eq!(
            s.gaps.last().map(|g| g.kind),
            Some(MovieGapKind::Unrepresented)
        );
        verify_quotes(&p, &s)?;
    }
    Ok(())
}

#[test]
fn recovered_fragment_tail_stays_unrepresented() -> Test {
    let bytes = include_bytes!("../../../tests/fixtures/fragmented_av.mp4");
    let second = nth_box(bytes, b"moof", 1) - 4;
    let p = AvcMp4::parse_recovering_tail(
        &bytes[..second + 16],
        None,
        DemuxLimits::default(),
        &mut || Ok(()),
    )?;
    assert_eq!(p.samples().len(), 5);
    assert_eq!(p.truncated_tail(), Some(second));
    let s = p.select_movie_interval(0..4000, MovieSelectionLimits::default())?;
    assert!(s.samples.iter().all(|sample| sample.sample_index < 5));
    let tail = s.gaps.last().expect("unrepresented tail");
    assert_eq!(tail.kind, MovieGapKind::Unrepresented);
    assert_eq!(
        tail.interval.end_numerator,
        4000 * u128::from(p.timescale())
    );
    verify_quotes(&p, &s)
}

#[test]
fn decode_discontinuity_is_a_gap_and_cannot_borrow_an_earlier_bootstrap() -> Test {
    let mut bytes = include_bytes!("../../../tests/fixtures/fragmented_av.mp4").to_vec();
    let tfdt = nth_box(&bytes, b"tfdt", 2);
    assert_eq!(bytes[tfdt + 4], 1);
    let at = tfdt + 8;
    let decode = u64::from_be_bytes(bytes[at..at + 8].try_into()?);
    bytes[at..at + 8].copy_from_slice(&(decode + 10_240).to_be_bytes());
    let p = AvcMp4::parse(&bytes, None, DemuxLimits::default())?;
    assert_eq!(p.samples()[5].decode_time, decode + 10_240);
    let s = p.select_movie_interval(0..4000, MovieSelectionLimits::default())?;
    assert!(s.gaps.iter().any(|gap| {
        gap.kind == MovieGapKind::Unrepresented
            && gap.interval.end_numerator - gap.interval.start_numerator
                == 10_240 * u128::from(p.movie_timescale())
    }));
    assert_eq!(s.decode_spans.len(), 2);
    verify_quotes(&p, &s)?;
    let source = p.samples()[5].source.clone();
    let headers = length_prefixed_nals(&bytes[source.clone()], p.nal_length_bytes())?
        .into_iter()
        .filter(|nal| bytes[source.start + nal.start] & 31 == 5)
        .map(|nal| source.start + nal.start)
        .collect::<Vec<_>>();
    assert!(!headers.is_empty());
    for at in headers {
        bytes[at] = 0x41;
    }
    let missing = AvcMp4::parse(&bytes, None, DemuxLimits::default())?;
    assert!(missing.annex_b(0, 10).is_ok());
    assert_eq!(
        missing.select_movie_interval(0..4000, MovieSelectionLimits::default()),
        Err(DemuxError::RandomAccessRequired)
    );
    Ok(())
}
