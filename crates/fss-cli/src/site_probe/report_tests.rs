#![forbid(unsafe_code)]

use super::super::plan::{ProbeOutput, SiteProbeOptions};
use super::*;
use fss_core::json_input::{self, Value};
use fss_reference::site::SiteManifest;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn fixture() -> TestResult<(SiteManifest, SiteProbeReceipt, SiteProbeOptions, Facts)> {
    let manifest = SiteManifest::parse(include_str!("../../../../fixtures/site/manifest.v1.json"))?;
    let receipt = fss_reference::site::parse_probe_receipts(include_bytes!(
        "../../../../fixtures/site/probes.v1.json"
    ))?
    .into_iter()
    .next()
    .ok_or("receipt fixture absent")?;
    let options = SiteProbeOptions {
        source: receipt.source_id.clone(),
        codec: receipt.codec,
        media_index: receipt.media_index,
        payload_type: Some(receipt.payload_type),
        rtp_channel: receipt.rtp_channel,
        observe_frames: 3,
        timeout_ms: 10_000,
        principal: "principal:probe-evidence-test".into(),
        approve: None,
        output: ProbeOutput::Session,
    };
    // These are declared evidence-encoding fixtures, not a claim that this test
    // acquired media. Actual connection/counter ownership is covered by the
    // native loopback and command-process contracts.
    let facts = Facts {
        connection_attempted: true,
        teardown_acknowledged: true,
        totals: Some(TcpTotals {
            received_bytes: 2048,
            sent_bytes: 512,
            read_calls: 8,
            write_calls: 5,
            last_sent_cseq: Some(5),
            peer_eof: false,
        }),
        accounting: Some(ProbeAccounting {
            rtp_packets: 6,
            rtp_bytes: 768,
            unverified_nal_bytes_excluded: 23,
            unfinished_fragment_bytes_excluded: 7,
            rtcp_frames_excluded: 1,
            rtcp_bytes_excluded: 28,
            closing_frames_excluded: 1,
            closing_bytes_excluded: 64,
            control_responses: 5,
            discarded_wire_bytes: 2048,
        }),
        last_observed_ns: 250_000_000,
        ..Facts::default()
    };
    Ok((manifest, receipt, options, facts))
}

fn field<'a>(value: &'a Value, key: &str) -> TestResult<&'a Value> {
    value
        .object()
        .and_then(|fields| fields.get(key))
        .ok_or_else(|| format!("missing report field {key}").into())
}

fn witness(plan: &ProbePlan<'_>, receipt: &SiteProbeReceipt, facts: Facts) -> TestResult<String> {
    let report = json_input::parse(&success(plan, receipt, facts)?)?;
    Ok(field(&report, "completion_digest")?
        .text()
        .ok_or("completion digest text")?
        .to_owned())
}

#[test]
fn measured_session_preserves_planner_receipts_and_separates_tail_bytes() -> TestResult {
    let (manifest, receipt, options, facts) = fixture()?;
    let plan = ProbePlan::new(&manifest, &options)?;
    let text = success(&plan, &receipt, facts)?;
    let report = json_input::parse(&text)?;
    assert_eq!(field(&report, "schema")?.text(), Some(SCHEMA));
    assert_eq!(field(&report, "status")?.text(), Some("measured"));
    assert_eq!(field(&report, "receipt_issued")?.boolean(), Some(true));
    assert_eq!(field(&report, "error_id")?, &Value::Null);
    let receipts = field(&report, "receipts")?.array().ok_or("receipt array")?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0], json_input::parse(&receipt_json(&receipt))?);
    let roundtrip =
        fss_reference::site::parse_probe_receipts(array(&[receipt_json(&receipt)]).as_bytes())?;
    assert_eq!(roundtrip, vec![receipt.clone()]);
    assert_eq!(
        field(&report, "receipt_digest")?.text(),
        Some(receipt.digest()?.to_text().as_str()),
    );
    let counts = field(&report, "accounting")?;
    assert_eq!(
        field(counts, "unverified_nal_bytes_excluded")?.integer(),
        Some(23)
    );
    assert_eq!(
        field(counts, "unfinished_fragment_bytes_excluded")?.integer(),
        Some(7)
    );
    // Reconstructed tails overlap original wire accounting; they must not be
    // summed into another original-byte count or treated as omitted pictures.
    assert_eq!(field(counts, "discarded_wire_bytes")?.integer(), Some(2048));
    assert_eq!(field(&receipts[0], "observed_frames")?.integer(), Some(4));
    for name in [
        "source_retained",
        "raw_media_returned",
        "pixels_decoded",
        "source_freshness_verified",
        "source_origin_authenticated",
        "rights_verdict_verified",
        "capture_authorized",
        "retry_automatically",
    ] {
        assert_eq!(field(&report, name)?.boolean(), Some(false));
    }
    assert!(text.len() < crate::site_cmd::MAX_SITE_OUTPUT_BYTES);
    Ok(())
}

#[test]
fn jpeg_session_reports_reconstruction_without_claiming_decoded_pixels() -> TestResult {
    let (manifest, mut receipt, mut options, mut facts) = fixture()?;
    receipt.codec = ProbeCodec::Jpeg;
    receipt.payload_type = 26;
    receipt.parameter_set_digests.clear();
    options.codec = ProbeCodec::Jpeg;
    options.payload_type = Some(26);
    facts
        .accounting
        .as_mut()
        .ok_or("accounting absent")?
        .unverified_nal_bytes_excluded = 0;
    let plan = ProbePlan::new(&manifest, &options)?;
    let report = json_input::parse(&success(&plan, &receipt, facts)?)?;
    assert_eq!(
        field(&report, "measurement_basis")?.text(),
        Some(JPEG_MEASUREMENT_BASIS)
    );
    assert_eq!(field(&report, "codec")?.text(), Some("jpeg"));
    assert_eq!(field(&report, "pixels_decoded")?.boolean(), Some(false));
    assert_eq!(field(&report, "source_retained")?.boolean(), Some(false));
    let receipts = field(&report, "receipts")?
        .array()
        .ok_or("receipts absent")?;
    assert_eq!(receipts[0], json_input::parse(&receipt_json(&receipt))?);
    assert!(
        field(&receipts[0], "parameter_set_digests")?
            .array()
            .ok_or("parameters absent")?
            .is_empty()
    );
    Ok(())
}

#[test]
fn completion_witness_binds_each_native_counter_and_receipt_claim() -> TestResult {
    let (manifest, receipt, options, facts) = fixture()?;
    let plan = ProbePlan::new(&manifest, &options)?;
    let original = witness(&plan, &receipt, facts)?;
    for index in 0..10 {
        let mut changed = facts;
        let measured = changed.accounting.as_mut().ok_or("accounting absent")?;
        match index {
            0 => measured.rtp_packets += 1,
            1 => measured.rtp_bytes += 1,
            2 => measured.unverified_nal_bytes_excluded += 1,
            3 => measured.unfinished_fragment_bytes_excluded += 1,
            4 => measured.rtcp_frames_excluded += 1,
            5 => measured.rtcp_bytes_excluded += 1,
            6 => measured.closing_frames_excluded += 1,
            7 => measured.closing_bytes_excluded += 1,
            8 => measured.control_responses += 1,
            _ => {
                measured.discarded_wire_bytes += 1;
                changed
                    .totals
                    .as_mut()
                    .ok_or("totals absent")?
                    .received_bytes += 1;
            }
        }
        assert_ne!(witness(&plan, &receipt, changed)?, original);
    }
    for index in 0..5 {
        let mut changed = facts;
        let totals = changed.totals.as_mut().ok_or("totals absent")?;
        match index {
            0 => totals.sent_bytes += 1,
            1 => totals.read_calls += 1,
            2 => totals.write_calls += 1,
            3 => totals.last_sent_cseq = Some(6),
            _ => totals.peer_eof = true,
        }
        assert_ne!(witness(&plan, &receipt, changed)?, original);
    }
    let mut changed = facts;
    changed.last_observed_ns += 1;
    assert_ne!(witness(&plan, &receipt, changed)?, original);
    let mut changed = receipt.clone();
    changed.server_identity = "changed-declared-server".into();
    assert_ne!(witness(&plan, &changed, facts)?, original);
    assert_eq!(witness(&plan, &receipt, facts)?, original);
    Ok(())
}

#[test]
fn valid_receipt_cannot_replace_missing_or_unsettled_session_evidence() -> TestResult {
    let (manifest, receipt, mut options, facts) = fixture()?;
    let plan = ProbePlan::new(&manifest, &options)?;
    for index in 0..11 {
        let mut changed = facts;
        match index {
            0 => changed.teardown_acknowledged = false,
            1 => changed.remote_session_may_exist = true,
            2 => changed.pending_cseq = Some(5),
            3 => changed.totals = None,
            4 => changed.accounting = None,
            5 => changed.unsent_request_bytes = 1,
            6 => changed.last_observed_ns = options.timeout_ms * 1_000_000,
            7 => {
                changed
                    .accounting
                    .as_mut()
                    .ok_or("accounting absent")?
                    .discarded_wire_bytes += 1
            }
            8 => {
                changed
                    .totals
                    .as_mut()
                    .ok_or("totals absent")?
                    .last_sent_cseq = None
            }
            9 => {
                changed
                    .accounting
                    .as_mut()
                    .ok_or("accounting absent")?
                    .rtp_bytes = 2049
            }
            _ => {
                changed.totals.as_mut().ok_or("totals absent")?.write_calls =
                    plan.transport.max_io_calls + 1
            }
        }
        assert_eq!(success(&plan, &receipt, changed), Err(ENCODING));
    }
    options.observe_frames = receipt.observed_frames + 1;
    assert_eq!(
        success(&ProbePlan::new(&manifest, &options)?, &receipt, facts),
        Err(ENCODING),
    );
    Ok(())
}

#[test]
fn refusal_preserves_uncertainty_and_late_close_without_issuing_evidence() -> TestResult {
    let (manifest, _, options, mut facts) = fixture()?;
    let plan = ProbePlan::new(&manifest, &options)?;
    facts.remote_session_may_exist = true;
    facts.teardown_acknowledged = false;
    facts.pending_cseq = Some(5);
    facts.request_sent_bytes = 11;
    facts.unsent_request_bytes = 17;
    for remote_uncertain in [true, false] {
        facts.remote_session_may_exist = remote_uncertain;
        facts.teardown_acknowledged = !remote_uncertain;
        let report = json_input::parse(&refusal(
            &plan,
            "ERR-SITE-PROBE-DEADLINE-001",
            facts,
            ExitIdentity::RUNTIME_FAILURE,
        ))?;
        assert_eq!(
            field(&report, "status")?.text(),
            Some(if remote_uncertain {
                "indeterminate"
            } else {
                "refused"
            }),
        );
        assert_eq!(field(&report, "receipt_issued")?.boolean(), Some(false));
        assert_eq!(
            field(&report, "receipts")?
                .array()
                .map(|values| values.len()),
            Some(0)
        );
        assert_eq!(field(&report, "receipt_digest")?, &Value::Null);
        assert_eq!(field(&report, "completion_digest")?, &Value::Null);
        assert_eq!(
            field(&report, "connection_attempted")?.boolean(),
            Some(true)
        );
        assert_eq!(field(&report, "request_sent_bytes")?.integer(), Some(11));
        assert_eq!(
            field(&report, "teardown_acknowledged")?.boolean(),
            Some(!remote_uncertain),
        );
    }
    let unknown = json_input::parse(&refusal(
        &plan,
        "ERR-SITE-PROBE-AUTHORITY-001",
        Facts::default(),
        ExitIdentity::RUNTIME_FAILURE,
    ))?;
    assert_eq!(field(&unknown, "transport")?, &Value::Null);
    assert_eq!(field(&unknown, "accounting")?, &Value::Null);
    assert_eq!(
        field(&unknown, "connection_attempted")?.boolean(),
        Some(false)
    );
    Ok(())
}
