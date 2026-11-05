#![forbid(unsafe_code)]
//! Real HEVC originals, native publication, raw SNTP evidence and cold archive reads.

use super::*;
use fss_packet::ntp::SntpRequest;
use fss_reference::rtsp::recording_clock::{
    ClockWindow, ReceiveClockBracket, RecordingClockCodec, RecordingClockIndex, publish_clock_index,
};
use fss_reference::site::clock::HostClockSample;
use fss_reference::site::clock_proof::{LOCAL_NTP_CLOCK_POLICY, LocalNtpExchange};

const EPOCH: u64 = 1_800_000_000_000_000_000;

fn host(monotonic_ns: u64) -> HostClockSample {
    HostClockSample {
        monotonic_before_ns: monotonic_ns,
        wall_clock_unix_ns: EPOCH + monotonic_ns,
        monotonic_after_ns: monotonic_ns,
    }
}

fn timestamp(reply: &mut [u8; 48], start: usize, unix_ns: u64) {
    let seconds = (unix_ns / 1_000_000_000 + 2_208_988_800) as u32;
    let fraction = ((u128::from(unix_ns % 1_000_000_000) << 32) / 1_000_000_000) as u32;
    reply[start..start + 4].copy_from_slice(&seconds.to_be_bytes());
    reply[start + 4..start + 8].copy_from_slice(&fraction.to_be_bytes());
}

fn exchange() -> std::result::Result<LocalNtpExchange, source::Error> {
    let request = SntpRequest::new(EPOCH)?;
    let mut reply = [0_u8; 48];
    reply[0] = 0x24;
    reply[1] = 2;
    reply[2] = 6;
    reply[3] = (-30_i8) as u8;
    reply[12..16].copy_from_slice(b"TEST");
    timestamp(&mut reply, 16, EPOCH - 1_000_000_000);
    reply[24..32].copy_from_slice(&request.wire_bytes()[40..48]);
    // A 20-microsecond local exchange with one microsecond of server work.
    // These coordinates precede the fixture's actual packet admissions 65633..65643.
    timestamp(&mut reply, 32, EPOCH + 5_000);
    timestamp(&mut reply, 40, EPOCH + 6_000);
    Ok(LocalNtpExchange {
        peer: "127.0.0.1:123".parse()?,
        request: *request.wire_bytes(),
        reply,
        sent_before: host(0),
        sent_after: host(1_000),
        received_before: host(20_000),
        received_after: host(20_001),
        policy: LOCAL_NTP_CLOCK_POLICY,
    })
}

fn prepare_index(
    o: &ArchiveOptions,
    windows: &[ClockWindow],
) -> std::result::Result<RecordingClockIndex, source::Error> {
    let brackets: Vec<_> = source::packets()?
        .iter()
        .map(|packet| ReceiveClockBracket {
            admission_ns: packet.received_ns,
            completed: host(packet.received_ns + 1),
        })
        .collect();
    Ok(RecordingClockIndex::prepare(
        o.scope.clone(),
        RecordingClockCodec::Hevc,
        ContentDigest::sha256(b"explicit archive UTC fixture approval"),
        exchange()?,
        host(100_000),
        &brackets,
        windows,
    )?)
}

fn attach_clock(
    o: &mut ArchiveOptions,
    publisher: &mut LocalRootPublisher,
    ordinals: &[usize],
) -> std::result::Result<RecordingClockIndex, source::Error> {
    let namespace = HevcArchiveNamespace::new(o.scope.clone())?;
    let mut windows = Vec::new();
    for &ordinal in ordinals {
        windows.push(ClockWindow::from_hevc(
            namespace.window_slot(ordinal)?,
            &window(ordinal as u64 * 100_000)?,
        )?);
    }
    let index = prepare_index(o, &windows)?;
    publish_clock_index(&index, publisher, &NeverCancel)?;
    let bounds = index
        .windows()
        .first()
        .ok_or("clock window")?
        .utc_interval();
    o.action = Action::QueryUtc;
    o.query = None;
    o.utc_query = Some(utc::UtcQuery {
        expected_index: index.root(),
        interval: bounds.earliest_ns..bounds.latest_ns + 1,
    });
    Ok(index)
}

#[test]
fn utc_arguments_require_both_pins_and_refuse_decode_or_export_options() -> TestResult {
    let digest = ContentDigest::sha256(b"UTC parser fixture").to_text();
    let valid = [
        "--expected-snapshot",
        digest.as_str(),
        "--expected-clock-index",
        digest.as_str(),
        "--start-utc-ns",
        "1800000000000000000",
        "--end-utc-ns",
        "1800000000000000001",
    ];
    let options = parse_archive_args(&argv("query-utc", &valid))?.ok_or("UTC options")?;
    assert_eq!(options.action, Action::QueryUtc);
    assert!(options.query.is_none());
    assert_eq!(
        options.utc_query.ok_or("UTC query")?.interval,
        EPOCH..EPOCH + 1
    );
    for missing in [
        "--expected-snapshot",
        "--expected-clock-index",
        "--start-utc-ns",
        "--end-utc-ns",
    ] {
        let args: Vec<_> = valid
            .chunks_exact(2)
            .filter(|pair| pair[0] != missing)
            .flat_map(|pair| pair.iter().copied())
            .collect();
        assert!(parse_archive_args(&argv("query-utc", &args)).is_err());
    }
    for (option, value) in [
        ("--start", "0"),
        ("--end", "1"),
        ("--output-dir", "private-output"),
        ("--allow-whole-windows", "yes"),
        ("--expected-clock-index", digest.as_str()),
    ] {
        let mut args = valid.to_vec();
        args.extend([option, value]);
        assert!(parse_archive_args(&argv("query-utc", &args)).is_err());
    }
    for value in ["-1", "+1", "18446744073709551616", "1.5"] {
        let mut args = valid;
        args[5] = value;
        assert!(parse_archive_args(&argv("query-utc", &args)).is_err());
    }
    let mut empty = valid;
    empty[7] = empty[5];
    assert!(parse_archive_args(&argv("query-utc", &empty)).is_err());
    for action in ["inspect", "query", "verify", "export"] {
        assert!(parse_archive_args(&argv(action, &["--expected-clock-index", &digest])).is_err());
        assert!(parse_archive_args(&argv(action, &["--start-utc-ns", "1"])).is_err());
    }
    Ok(())
}

#[test]
fn retained_utc_candidates_keep_unknown_originals_and_legacy_inventory_identity() -> TestResult {
    let (mut o, mut p) = setup("utc-candidates")?;
    let legacy = execute_for::<HevcArchiveCodec>(&o, &p, &clock())?;
    let index = attach_clock(&mut o, &mut p, &[0, 1])?;
    let report = execute_for::<HevcArchiveCodec>(&o, &p, &clock())?;
    for required in [
        "\"command\":\"query-utc\"",
        "\"candidate_windows\":2,\"clock_unavailable_windows\":1",
        "\"time_basis\":\"node_read_admission_bracket\"",
        "\"camera_capture_time\":\"unknown\"",
        "\"server_authenticated\":false,\"coverage_claim\":false,\"absence_claim\":false",
        "\"node_admission_utc_interval_ns\":\"unknown\"",
        "\"all_snapshot_windows_have_clock_evidence\":false",
        "\"payload_bytes_emitted\":0,\"complete\":true",
    ] {
        assert!(report.contains(required), "missing report field {required}");
    }
    assert!(report.contains(&format!(
        "\"clock_index\":{}",
        quoted(&index.root().to_text())
    )));
    assert!(report.contains(&format!(
        "\"source_receive_clock\":{}",
        quoted(&o.scope.recording.receive_clock.to_text())
    )));
    assert_eq!(report.matches("\"source_generation\":1").count(), 3);
    assert!(!report.contains("\"unindexed\""));
    assert!(!report.contains("objects_source_init_media_index"));
    let total: usize = [0, 100_000, 200_000]
        .into_iter()
        .map(window)
        .collect::<std::result::Result<Vec<_>, _>>()?
        .iter()
        .map(PreparedHevcRecording::byte_len)
        .sum();
    assert!(report.contains(&format!("\"whole_window_output_bytes\":{total}")));
    o.action = Action::Inspect;
    assert_eq!(legacy, execute_for::<HevcArchiveCodec>(&o, &p, &clock())?);
    Ok(())
}

#[test]
fn closed_admission_bounds_overlap_half_open_queries_without_inventing_utc_gaps() -> TestResult {
    let (mut o, mut p) = setup("utc-boundaries")?;
    let index = attach_clock(&mut o, &mut p, &[0])?;
    let bounds = index.windows()[0].utc_interval();
    for (query, candidates) in [
        (bounds.latest_ns..bounds.latest_ns + 1, 1),
        (bounds.earliest_ns - 1..bounds.earliest_ns, 0),
        (bounds.latest_ns + 1..bounds.latest_ns + 2, 0),
    ] {
        o.utc_query.as_mut().ok_or("UTC query")?.interval = query;
        let report = execute_for::<HevcArchiveCodec>(&o, &p, &clock())?;
        assert!(report.contains(&format!(
            "\"candidate_windows\":{candidates},\"clock_unavailable_windows\":2"
        )));
        assert!(report.contains("\"absence_claim\":false"));
        assert!(!report.contains("\"unindexed\""));
    }
    Ok(())
}

#[test]
fn candidate_and_unknown_window_costs_refuse_atomically() -> TestResult {
    let (mut o, mut p) = setup("utc-budgets")?;
    attach_clock(&mut o, &mut p, &[0])?;
    let total: u64 = [0, 100_000, 200_000]
        .into_iter()
        .map(window)
        .collect::<std::result::Result<Vec<_>, _>>()?
        .iter()
        .map(|w| w.byte_len() as u64)
        .sum();
    o.query_limits.max_windows = 2;
    assert!(matches!(
        execute_for::<HevcArchiveCodec>(&o, &p, &clock()),
        Err(ArchiveCommandError::Archive(ArchiveError::Limit))
    ));
    o.query_limits.max_windows = 3;
    o.query_limits.max_output_bytes = total - 1;
    assert!(matches!(
        execute_for::<HevcArchiveCodec>(&o, &p, &clock()),
        Err(ArchiveCommandError::Archive(ArchiveError::Limit))
    ));
    o.query_limits.max_output_bytes = total;
    assert!(execute_for::<HevcArchiveCodec>(&o, &p, &clock())?.contains("\"candidate_windows\":1"));
    Ok(())
}

#[test]
fn exact_snapshot_and_clock_index_pins_are_both_required_on_reopen() -> TestResult {
    let (mut o, mut p) = setup("utc-reopen")?;
    let index = attach_clock(&mut o, &mut p, &[0, 1, 2])?;
    let report = execute_for::<HevcArchiveCodec>(&o, &p, &clock())?;
    assert!(report.contains("\"all_snapshot_windows_have_clock_evidence\":true"));
    drop(p);
    assert_eq!(report, execute_archive(&o)?);
    let expected = o.expected;
    o.expected = Some(ContentDigest::sha256(b"another snapshot"));
    assert!(matches!(
        execute_archive(&o),
        Err(ArchiveCommandError::SnapshotMismatch)
    ));
    o.expected = expected;
    o.utc_query.as_mut().ok_or("UTC query")?.expected_index =
        ContentDigest::sha256(b"another clock index");
    assert!(matches!(
        execute_archive(&o),
        Err(ArchiveCommandError::ClockIndex(_))
    ));
    o.utc_query.as_mut().ok_or("UTC query")?.expected_index = index.root();
    assert_eq!(report, execute_archive(&o)?);
    Ok(())
}

#[test]
fn clock_rows_outside_snapshot_refuse_even_when_utc_query_would_skip_them() -> TestResult {
    let (mut o, mut p) = setup("utc-foreign")?;
    let slot = SlotName::parse("foreign-clock-original")?;
    let w = window(0)?;
    publish(&mut p, &slot, &w)?;
    let index = prepare_index(&o, &[ClockWindow::from_hevc(slot, &w)?])?;
    publish_clock_index(&index, &mut p, &NeverCancel)?;
    o.action = Action::QueryUtc;
    o.utc_query = Some(utc::UtcQuery {
        expected_index: index.root(),
        interval: 0..1,
    });
    assert!(matches!(
        execute_for::<HevcArchiveCodec>(&o, &p, &clock()),
        Err(ArchiveCommandError::ClockIndexSnapshotMismatch)
    ));
    Ok(())
}

#[test]
fn damaged_retained_clock_bytes_cannot_be_hidden_by_an_empty_selection() -> TestResult {
    let (mut o, mut p) = setup("utc-corrupt-clock")?;
    let index = attach_clock(&mut o, &mut p, &[0])?;
    let digest = ContentDigest::sha256(index.index_bytes()).to_text();
    let name = digest.strip_prefix("sha256:").ok_or("sha256")?;
    fs::write(
        o.root.join("spool/objects").join(name),
        b"corrupt clock evidence",
    )?;
    o.utc_query.as_mut().ok_or("UTC query")?.interval = 0..1;
    assert!(execute_for::<HevcArchiveCodec>(&o, &p, &clock()).is_err());
    Ok(())
}

#[test]
fn utc_query_keeps_existing_operation_deadline_and_recovery_quotas() -> TestResult {
    let (mut o, mut p) = setup("utc-deadline")?;
    attach_clock(&mut o, &mut p, &[0])?;
    assert!(matches!(
        execute_for::<HevcArchiveCodec>(&o, &p, &FixedClock { now: 100, end: 100 }),
        Err(ArchiveCommandError::Deadline)
    ));
    o.archive_limits.max_windows = 2;
    assert!(execute_for::<HevcArchiveCodec>(&o, &p, &clock()).is_err());
    Ok(())
}
