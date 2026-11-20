#![forbid(unsafe_code)]
//! Recorded-input boundary cases for the RTP ingest and custody contract.
mod caplog_support;
mod rtpdump_support;

use caplog_support::Record;
use fss_core::{ContentDigest, SensorId, StreamId, TimestampNs};
use fss_packet::H264Error;
use fss_reference::ingest::rtpdump::import::*;
use fss_reference::ingest::rtpdump::{RtpDumpFault, RtpDumpKind};
use rtpdump_support::*;

fn scope() -> Result<RtpImportScope, Error> {
    Ok(RtpImportScope {
        sensor: SensorId::parse("sensor:recorded-rtp-corpus")?,
        stream: StreamId::parse("stream:recorded-rtp-corpus")?,
        receive_time: TimestampNs(1_000_000_000),
    })
}

#[test]
fn framing_mutations_preserve_source_and_do_not_admit_partial_rtp() -> TestResult {
    let authority = cx()?;
    let pristine = dump(&[(17, false, &[9, 0xf0], 0), (18, true, &[0x65, 0x80], 1)]);
    let last = header().len() + 8 + rtp(17, false, &[9, 0xf0]).len();
    for (step, plen) in [
        ("truncated_record", None),
        ("larger_plen", Some(15_u16)),
        ("zero_plen", Some(0)),
    ] {
        let mut bytes = pristine.clone();
        match plen {
            None => bytes.truncate(bytes.len() - 1),
            Some(value) => bytes[last + 2..last + 4].copy_from_slice(&value.to_be_bytes()),
        }
        let plan = prepare_rtp_import(
            &bytes,
            scope()?,
            config(),
            RtpImportLimits::default(),
            &authority,
        )?;
        let report = plan.report();
        assert_eq!(report.input_digest(), ContentDigest::sha256(&bytes));
        assert_eq!(report.input_bytes(), bytes.len());
        assert!(report.nals().is_empty() && report.access_units().is_empty());
        if step == "truncated_record" {
            let ImportEnd::FramingRefused(err) = report.end() else {
                return Err("truncation appeared to be complete input".into());
            };
            assert_eq!(err.fault, RtpDumpFault::TruncatedRecord);
            assert_eq!(err.span, last..bytes.len());
        } else {
            assert_eq!(report.end(), &ImportEnd::Ended);
            let row = report.records().last().ok_or("missing original record")?;
            assert_eq!(row.source, last..bytes.len());
            assert!(row.sequence.is_none() && row.nals.is_empty());
            if step == "larger_plen" {
                assert_eq!(row.kind, RtpDumpKind::CapturedPrefix);
                assert_eq!(row.disposition, RecordDisposition::CapturedPrefix);
            } else {
                // rtptools reserves zero plen for RTCP. An RTP-shaped payload there cannot supply media.
                assert_eq!(row.kind, RtpDumpKind::Rtcp);
                assert!(matches!(
                    row.disposition,
                    RecordDisposition::PacketRefused(_)
                ));
            }
        }
        Record::new(step)
            .check(
                "framed_records",
                if step == "truncated_record" { 1 } else { 2 },
                report.records().len(),
            )
            .check("retained_source_bytes", bytes.len(), report.input_bytes())
            .check("complete_nals", 0, report.nals().len())
            .emit_checked(0, true);
    }
    Ok(())
}

#[test]
fn a_lost_fu_reports_the_retired_sequence_span_without_publishing_a_partial_nal() -> TestResult {
    // The two fragments at seq 0 and 1 belong to one IDR. Omit seq 2 before the next AUD.
    let bytes = dump(&[
        (65_534, false, &[9, 0xf0], 0),
        (65_535, true, &[9, 0xf0], 1),
        (0, false, &[0x7c, 0x85, 0x11], 2),
        (1, false, &[0x7c, 0x05, 0x22], 3),
        (3, true, &[9, 0xf0], 4),
    ]);
    let plan = prepare_rtp_import(
        &bytes,
        scope()?,
        config(),
        RtpImportLimits::default(),
        &cx()?,
    )?;
    let report = plan.report();
    let last = report.records().last().ok_or("missing gap record")?;
    let discarded = last.discarded.as_ref().ok_or("missing fragment discard")?;
    assert_eq!(discarded.reason, H264Error::Gap);
    assert_eq!(
        (discarded.first_sequence, discarded.last_sequence),
        (65_536, 65_537)
    );
    assert!(last.gap_before);
    assert_eq!(report.stats().missing, 1);
    assert_eq!(report.nals().len(), 2);
    assert!(
        report
            .nals()
            .iter()
            .all(|n| n.digest == ContentDigest::sha256(&[9, 0xf0]))
    );
    Record::new("fragment_gap")
        .check("first_sequence", 65_536_u64, discarded.first_sequence)
        .check("last_sequence", 65_537_u64, discarded.last_sequence)
        .check("retired_fragments", 2, discarded.fragments)
        .check("retired_nal_bytes", 3, discarded.byte_len)
        .check(
            "ledger_eligible_access_units",
            2,
            report.access_units().len(),
        )
        .emit_checked(0, true);
    Ok(())
}

#[test]
fn recording_header_endpoint_is_absent_from_projected_reports() -> TestResult {
    let base = dump(&[(5, false, &[9, 0xf0], 0), (6, true, &[0x65, 0x80], 1)]);
    let newline = base.iter().position(|b| *b == b'\n').ok_or("header")?;
    let mut bytes = b"#!rtpplay1.0 192.0.2.89/43210\n".to_vec();
    bytes.extend_from_slice(&base[newline + 1..]);
    let plan = prepare_rtp_import(
        &bytes,
        scope()?,
        config(),
        RtpImportLimits::default(),
        &cx()?,
    )?;
    let report = plan.report();
    assert_eq!(report.input_digest(), ContentDigest::sha256(&bytes));
    assert_eq!(report.nals().len(), 1);
    let marker = b"192.0.2.89";
    assert!(
        !plan
            .report_bytes()
            .windows(marker.len())
            .any(|s| s == marker)
    );
    assert!(!format!("{report:?}").contains("192.0.2.89"));
    Record::new("header_privacy")
        .check("retained_source_bytes", bytes.len(), report.input_bytes())
        .check("admitted_nals", 1, report.nals().len())
        .emit_checked(0, true);
    Ok(())
}
