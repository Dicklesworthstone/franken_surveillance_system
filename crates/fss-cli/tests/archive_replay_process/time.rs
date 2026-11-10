#![forbid(unsafe_code)]
//! Real archive executable queries over native AVC/HEVC originals.

use super::*;

const UTC_NS: i128 = 1_793_840_520_000_000_000;
const NTP_SECONDS: u32 = 4_002_829_320;

fn query_args(root: &Path, receipt: &ReplayReceipt) -> Test<Vec<OsString>> {
    let mut values = args(root, receipt);
    values[0] = "query-replay-utc".into();
    change(&mut values, "--ntp-era", Some("0"))?;
    change(&mut values, "--utc-start-ns", Some(&UTC_NS.to_string()))?;
    change(
        &mut values,
        "--utc-end-ns",
        Some(&(UTC_NS + 1_000_000_000).to_string()),
    )?;
    Ok(values)
}

fn timed_hevc(name: &str) -> Test<(PathBuf, ReplayReceipt)> {
    let root = path(name);
    let template = request()?;
    let request = ReplayRequest::new_hevc(
        hevc_recording_support::scope()?,
        template.route(),
        template.window(),
        template.base_decode_clock(),
    )?;
    let namespace = HevcArchiveNamespace::new(catalog_scope(&request))?;
    let mut packets = hevc_recording_support::packets()?;
    for packet in &mut packets {
        assert_eq!(packet.bytes[0] & 0x10, 0);
        let at = 12 + 4 * usize::from(packet.bytes[0] & 0x0F);
        let timestamp = u32::from_be_bytes(
            packet.bytes[4..8]
                .try_into()
                .map_err(|_| "fixture RTP timestamp")?,
        );
        // Exact binary fractions make the operator's decimal boundaries checkable.
        // The last group is genuine retained boundary lookahead, not a sample.
        let fraction = match timestamp {
            0 => 0_u32,
            18_000 => 0x8000_0000,
            _ => 0xC000_0000,
        };
        let mut extension = vec![0xAB, 0xAC, 0, 3];
        extension.extend_from_slice(&NTP_SECONDS.to_be_bytes());
        extension.extend_from_slice(&fraction.to_be_bytes());
        extension.extend_from_slice(&[0x80, 7, 0xCA, 0xFE]);
        packet.bytes[0] |= 0x10;
        packet.bytes.splice(at..at, extension);
    }
    let original =
        hevc_recording_support::prepare(&packets[..8], &hevc_recording_support::timings(2))?;
    assert_eq!(original.source_only_nals(), 3);
    let slot = namespace.window_slot(0)?;
    let mut publisher = LocalRootPublisher::open(&root, limits())?;
    publish_original(&mut publisher, &slot, original.publication_plan())?;
    let receipt = prepare(
        request,
        vec![ReplayWindowProof::from_hevc(slot, &original)?],
        ReplayTermination::RequestedStop,
        true,
    )?;
    publish_replay_receipt(&receipt, &mut publisher, &NeverCancel)?;
    drop(publisher);
    Ok((root, receipt))
}

#[test]
fn query_help_exposes_explicit_era_pins_and_bounded_historical_time() -> Test {
    let _serial = serial();
    for args in [vec!["help"], vec!["query-replay-utc", "--help"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_fss-archive"))
            .args(args)
            .output()?;
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let help = String::from_utf8(output.stdout)?;
        for expected in [
            "query-replay-utc",
            "--ntp-era",
            "--utc-start-ns",
            "--utc-end-ns",
            "--expected-replay-root",
            "--expected-replay-request",
            "--max-query-results",
            "8 MiB",
            "not calibrated capture time",
            "low byte",
        ] {
            assert!(help.contains(expected), "missing help: {expected}");
        }
    }
    Ok(())
}

#[test]
fn invalid_time_inputs_refuse_before_open_and_never_echo_private_values() -> Test {
    let _serial = serial();
    let missing = path("PRIVATE_TIME_ARCHIVE_SENTINEL");
    let receipt = prepare(
        request()?,
        Vec::new(),
        ReplayTermination::ProtocolFailure,
        false,
    )?;
    for (key, value) in [
        ("--ntp-era", None),
        ("--ntp-era", Some("4294967296")),
        ("--utc-start-ns", Some("PRIVATE_TIME_SENTINEL")),
        ("--utc-start-ns", Some("+1")),
        ("--utc-start-ns", Some("-1")),
        ("--utc-end-ns", Some("253402300800000000001")),
        ("--utc-end-ns", Some("0")),
        ("--max-query-samples", Some("0")),
        ("--max-query-source-bytes", Some("2147483649")),
        ("--max-query-results", Some("32769")),
    ] {
        let mut values = query_args(&missing, &receipt)?;
        change(&mut values, key, value)?;
        let output = run(&values)?;
        assert_eq!(
            output.status.code(),
            Some(i32::from(ExitIdentity::MALFORMED_VALUE.code))
        );
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr)?;
        assert!(!error.contains("PRIVATE_TIME_SENTINEL"));
        assert!(!error.contains("PRIVATE_TIME_ARCHIVE_SENTINEL"));
        assert!(!missing.exists());
    }
    let mut duplicate = query_args(&missing, &receipt)?;
    duplicate.extend([OsString::from("--ntp-era"), OsString::from("0")]);
    let output = run(&duplicate)?;
    assert_eq!(
        output.status.code(),
        Some(i32::from(ExitIdentity::MALFORMED_VALUE.code))
    );
    assert!(String::from_utf8(output.stderr)?.contains(ERR_CLI_DUPLICATE_OPTION));
    assert!(output.stdout.is_empty());
    assert!(!missing.exists());
    Ok(())
}

#[test]
fn time_options_do_not_expand_the_existing_receipt_inspection_command() -> Test {
    let _serial = serial();
    let missing = path("inspect-query-option-refused");
    let receipt = prepare(
        request()?,
        Vec::new(),
        ReplayTermination::ProtocolFailure,
        false,
    )?;
    let mut values = args(&missing, &receipt);
    change(&mut values, "--ntp-era", Some("0"))?;
    let output = run(&values)?;
    assert_eq!(
        output.status.code(),
        Some(i32::from(ExitIdentity::MALFORMED_VALUE.code))
    );
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr)?.contains(ERR_CLI_UNKNOWN_OPTION));
    assert!(!missing.exists());
    Ok(())
}

#[test]
fn missing_extensions_remain_unknown_even_when_the_request_contains_the_query() -> Test {
    let _serial = serial();
    let (root, receipt) = setup(
        "time-unknown-avc",
        1,
        ReplayTermination::RequestedStop,
        true,
    )?;
    let report = report(run(&query_args(&root, &receipt)?)?)?;
    assert_eq!(
        text(&report, "schema")?,
        "fss.local_replay_time_operator_report.v1"
    );
    assert_eq!(text(&report, "command")?, "query-replay-utc");
    assert_eq!(field(&report, "scanned_samples")?.integer(), Some(1));
    assert_eq!(field(&report, "matched_samples")?.integer(), Some(0));
    assert_eq!(field(&report, "unknown_samples")?.integer(), Some(1));
    assert_eq!(
        field(&report, "known_samples_outside_query")?.integer(),
        Some(0)
    );
    let unknown = field(&report, "unknown")?
        .array()
        .ok_or("unknown samples")?;
    assert_eq!(unknown.len(), 1);
    let evidence = field(&unknown[0], "evidence")?;
    assert_eq!(field(evidence, "header")?, &Value::Null);
    assert_eq!(field(evidence, "recorder_utc_ns")?, &Value::Null);
    assert!(!text(evidence, "unknown_reason")?.is_empty());
    assert_eq!(text(&report, "calibrated_capture_time")?, "unknown");
    assert_eq!(text(&report, "coverage_claim")?, "not_claimed");
    assert_eq!(text(&report, "absence_claim")?, "not_claimed");
    assert_eq!(field(&report, "operation_complete")?.boolean(), Some(true));
    Ok(())
}

#[test]
fn hevc_query_returns_verified_samples_and_keeps_boundary_lookahead_separate() -> Test {
    let _serial = serial();
    let (root, receipt) = timed_hevc("time-hevc-source-only")?;
    let values = query_args(&root, &receipt)?;
    let first = run(&values)?;
    let repeat = run(&values)?;
    assert_eq!(first.stdout, repeat.stdout);
    let report = report(first)?;
    assert_eq!(text(&report, "codec")?, "hevc");
    assert_eq!(
        text(&report, "replay_receipt_root")?,
        receipt.root().to_text()
    );
    assert_eq!(
        text(&report, "replay_request")?,
        receipt.request().digest().to_text()
    );
    assert_eq!(field(&report, "scanned_samples")?.integer(), Some(2));
    assert_eq!(field(&report, "matched_samples")?.integer(), Some(2));
    assert_eq!(field(&report, "unknown_samples")?.integer(), Some(0));
    assert_eq!(
        field(&report, "source_bytes_reserved")?.integer(),
        Some(32 * 1024 * 1024)
    );
    assert_eq!(text(&report, "play_cseq_correlation")?, "low_byte_only");
    assert_eq!(text(&report, "device_clock_error")?, "unknown");
    assert_eq!(
        field(&report, "source_bytes_emitted")?.boolean(),
        Some(false)
    );
    let matches = field(&report, "matches")?.array().ok_or("sample matches")?;
    assert_eq!(matches.len(), 2);
    for (ordinal, row) in matches.iter().enumerate() {
        assert_eq!(field(row, "sample")?.integer(), Some(ordinal as i128));
        assert_eq!(text(row, "root")?, receipt.windows()[0].root().to_text());
        assert_eq!(text(row, "slot")?, receipt.windows()[0].slot().as_str());
        let evidence = field(row, "evidence")?;
        let utc = field(evidence, "recorder_utc_ns")?;
        let expected = UTC_NS + ordinal as i128 * 500_000_000;
        assert_eq!(field(utc, "earliest")?.integer(), Some(expected));
        assert_eq!(field(utc, "latest")?.integer(), Some(expected));
        let header = field(evidence, "header")?;
        assert_eq!(
            field(header, "ntp_seconds")?.integer(),
            Some(i128::from(NTP_SECONDS))
        );
        assert_eq!(field(header, "cseq_low")?.integer(), Some(7));
        assert_eq!(field(header, "clean_point")?.boolean(), Some(true));
        assert_eq!(field(evidence, "unknown_reason")?, &Value::Null);
        ContentDigest::parse(text(evidence, "packet_set_digest")?)?;
        ContentDigest::parse(text(evidence, "proof_digest")?)?;
    }
    let source_only = field(&report, "source_only")?
        .array()
        .ok_or("source-only groups")?;
    assert!(!source_only.is_empty());
    for row in source_only {
        assert_eq!(field(row, "sample")?, &Value::Null);
        assert_eq!(text(row, "root")?, receipt.windows()[0].root().to_text());
    }
    ContentDigest::parse(text(&report, "index_digest")?)?;
    ContentDigest::parse(text(&report, "report_digest")?)?;
    Ok(())
}

#[test]
fn half_open_query_selection_changes_without_rewriting_original_evidence() -> Test {
    let _serial = serial();
    let (root, receipt) = timed_hevc("time-hevc-selection")?;
    let mut values = query_args(&root, &receipt)?;
    change(
        &mut values,
        "--utc-start-ns",
        Some(&(UTC_NS + 500_000_000).to_string()),
    )?;
    change(
        &mut values,
        "--utc-end-ns",
        Some(&(UTC_NS + 600_000_000).to_string()),
    )?;
    let selected = report(run(&values)?)?;
    assert_eq!(field(&selected, "matched_samples")?.integer(), Some(1));
    assert_eq!(
        field(&selected, "known_samples_outside_query")?.integer(),
        Some(1)
    );
    let rows = field(&selected, "matches")?
        .array()
        .ok_or("selected samples")?;
    assert_eq!(field(&rows[0], "sample")?.integer(), Some(1));
    let all = report(run(&query_args(&root, &receipt)?)?)?;
    assert_eq!(
        text(&selected, "index_digest")?,
        text(&all, "index_digest")?
    );
    assert_ne!(
        text(&selected, "report_digest")?,
        text(&all, "report_digest")?
    );
    let publisher = LocalRootPublisher::open(&root, limits())?;
    assert_eq!(
        publisher.spool().read(receipt.root())?,
        receipt.manifest().canonical_bytes()
    );
    let window = &receipt.windows()[0];
    let original = fss_reference::rtsp::recording::hevc::local::load_hevc_recording(
        &publisher,
        window.slot(),
        window.root(),
        receipt.request().scope(),
        &NeverCancel,
    )?;
    assert_eq!(
        original
            .publication_plan()
            .children()
            .map(|(_, digest, _)| digest),
        window.original_leaf_digests()
    );
    Ok(())
}

#[test]
fn changed_pins_and_exhausted_query_allowances_emit_no_partial_success() -> Test {
    let _serial = serial();
    let (root, receipt) = timed_hevc("time-hevc-query-refusal")?;
    let wrong = ContentDigest::sha256(b"independent foreign time-query pin").to_text();
    for (key, value) in [
        ("--expected-replay-root", wrong.as_str()),
        ("--expected-replay-request", wrong.as_str()),
        ("--decode-clock", wrong.as_str()),
        ("--codec", "avc"),
        ("--max-query-samples", "1"),
        ("--max-query-source-bytes", "33554431"),
        ("--max-query-results", "1"),
    ] {
        let mut values = query_args(&root, &receipt)?;
        change(&mut values, key, Some(value))?;
        let output = run(&values)?;
        assert_eq!(
            output.status.code(),
            Some(i32::from(ExitIdentity::RUNTIME_FAILURE.code)),
            "{key}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty(), "{key}");
    }
    let verified = report(run(&query_args(&root, &receipt)?)?)?;
    assert_eq!(field(&verified, "matched_samples")?.integer(), Some(2));
    assert_eq!(
        text(&verified, "replay_receipt_root")?,
        receipt.root().to_text()
    );
    Ok(())
}

#[test]
fn empty_failed_attempt_reports_no_samples_without_an_absence_claim() -> Test {
    let _serial = serial();
    let (root, receipt) = setup(
        "time-empty-failed",
        0,
        ReplayTermination::ProtocolFailure,
        false,
    )?;
    let report = report(run(&query_args(&root, &receipt)?)?)?;
    assert_eq!(field(&report, "scanned_windows")?.integer(), Some(0));
    assert_eq!(field(&report, "scanned_samples")?.integer(), Some(0));
    assert_eq!(field(&report, "matched_samples")?.integer(), Some(0));
    assert_eq!(field(&report, "unknown_samples")?.integer(), Some(0));
    assert_eq!(
        field(&report, "publication_complete")?.boolean(),
        Some(false)
    );
    assert_eq!(text(&report, "termination")?, "protocol_failure");
    assert_eq!(text(&report, "absence_claim")?, "not_claimed");
    assert_eq!(text(&report, "coverage_claim")?, "not_claimed");
    Ok(())
}
