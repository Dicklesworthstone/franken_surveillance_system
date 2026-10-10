#![forbid(unsafe_code)]
//! Recorded RTP continuity drives the core acquisition session truthfully (fss-2h5zq.29/.30).
//!
//! Every recording here is the oracle-encoded, first-party Baseline fixture
//! (`fss-packet/tests/fixtures/avc/baseline.264`) packetized per RFC 6184 with advancing RTP
//! timestamps, published through the real rtpdump import, re-read, and only then driven through
//! the continuity module. The first picture's I420 digest is compared with the sealed FFmpeg
//! oracle digest retained by `fss-codec-h264`, so `Verified` decode is not assumed.
//!
//! Planted negatives (the mutant each test would catch) are named in every test's doc comment.
mod rtpdump_support;

use std::collections::BTreeSet;

use fss_core::{
    AcquisitionSession, AcquisitionState, AcquisitionStateKind, AdapterAck, CanonicalDecode,
    CanonicalDecoder, CanonicalEncode, CaptureInterval, ContractError, CoverageContinuity,
    CoverageStopReason, EventId, EventReadResult, EventRevisionStore, LedgerAnchor,
    NotObservableReason, SensorId, SourceId, StreamId, TimestampNs, WindowedDegradationEvidence,
};
use fss_core::{DeviceId, SensorCapsule};
use fss_packet::ContinuityError;
use fss_reference::ReferenceDeployment;
use fss_reference::ingest::rtp_continuity::*;
use fss_reference::ingest::rtpdump::import::*;
use fss_reference::ingest::rtpdump::replay::{RestartCause, RtpReplayConfig};
use rtpdump_support::*;

const ORIGIN_NS: i128 = 1_000_000_000_000;
const SSRC_A: u32 = 7;
const SSRC_B: u32 = 0x0b0b_0b0b;
const MAX_PAYLOAD: usize = 300;

/// Oracle digest of the first decoded picture of baseline.264 (sealed FFmpeg laboratory oracle,
/// retained by fss-codec-h264; never regenerated here).
fn oracle_first_picture() -> Result<[u8; 32], Error> {
    let text =
        include_str!("../../fss-codec-h264/tests/fixtures/decode/fss_packet_baseline.sha256");
    let line = text
        .lines()
        .find(|l| l.starts_with("0 "))
        .ok_or("oracle line 0 missing")?;
    let hex = line
        .split_whitespace()
        .nth(2)
        .ok_or("oracle digest missing")?;
    let mut out = [0_u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2).ok_or("short digest")?, 16)?;
    }
    Ok(out)
}

fn new_directory(label: &str) -> Result<std::path::PathBuf, Error> {
    let root = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(root)?;
    // Never delete or overwrite another test's retained publication evidence.
    for i in 0..1000 {
        let p = root.join(format!("rtp-continuity-{label}-{}-{i}", std::process::id()));
        match std::fs::create_dir(&p) {
            Ok(()) => return Ok(p),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    Err("test directory allocation exhausted".into())
}

fn source() -> Result<SourceId, Error> {
    Ok(SourceId::parse("src:rtp-continuity-camera")?)
}

struct Run {
    report: RtpContinuityReport,
    import: RtpImportReport,
}

fn policy(window: u64) -> RtpContinuityPolicy {
    RtpContinuityPolicy {
        window_packets: window,
        ..RtpContinuityPolicy::default()
    }
}

/// Import → publish → verified re-read → continuity, all through the real pipeline.
fn run(
    label: &str,
    bytes: &[u8],
    cfg: RtpReplayConfig,
    policy: RtpContinuityPolicy,
) -> Result<Run, Error> {
    let root = new_directory(label)?;
    let cx = cx()?;
    let mut dep = ReferenceDeployment::open(&root, "site:rtp-continuity", &cx)?;
    let scope = RtpImportScope {
        sensor: SensorId::parse("sensor:rtp-continuity")?,
        stream: StreamId::parse("stream:rtp-continuity")?,
        receive_time: TimestampNs(2_000_000_000_000),
    };
    let plan = prepare_rtp_import(bytes, scope, cfg, RtpImportLimits::default(), &cx)?;
    let receipt = publish_rtp_import(plan, &cx, &mut dep)?;
    let verified = load_rtp_import(&receipt, &cx, &dep)?;
    let continuity_scope = RtpContinuityScope {
        source_id: source()?,
        device_id: DeviceId::parse("device:rtp-continuity-camera")?,
        failure_domain: "domain:rtp-continuity-camera".into(),
        recording_origin: TimestampNs(ORIGIN_NS),
        basis: dep.current_anchor().clone(),
        negative_predicate: "no_unknown_person_present".into(),
    };
    let report = drive_rtp_continuity(&receipt, &verified, &continuity_scope, policy, &cx)?;
    Ok(Run {
        report,
        import: verified.report().clone(),
    })
}

/// Extended sequence of planned packet `index` for a stream starting at 65534 (index 0 is the
/// probation packet; the baseline is 65535 and the counter then unwraps past 65535).
fn ext(index: usize) -> u64 {
    65_534 + index as u64
}

fn first_vcl(planned: &[Planned]) -> Result<usize, Error> {
    Ok(planned
        .iter()
        .position(|p| p.vcl)
        .ok_or("no VCL packet planned")?)
}

fn at(offset_ms: u32) -> TimestampNs {
    TimestampNs(ORIGIN_NS + i128::from(offset_ms) * 1_000_000)
}

fn interval(a: TimestampNs, b: TimestampNs) -> Result<CaptureInterval, Error> {
    Ok(CaptureInterval::new(a, b)?)
}

mod caplog_support;

/// Prints one CAPLOG record after the test's assertions passed. Step and observed text are
/// JSON-escaped; every step name is unique within the e2e script.
fn caplog(step: &str, observed: &str) {
    println!(
        "CAPLOG {{\"bead\":\"fss-2h5zq.30\",\"step\":{},\"verdict\":\"pass\",\"observed\":{}}}",
        caplog_support::json_string(step),
        caplog_support::json_string(observed)
    );
}

fn kinds_text(report: &RtpContinuityReport) -> String {
    report
        .kinds()
        .iter()
        .map(|k| k.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

fn witness(window: &RtpContinuityWindow) -> Result<&fss_core::ContinuityWitness, Error> {
    match &window.outcome {
        RtpWindowOutcome::Verified { witness } => Ok(witness),
        other => Err(format!("expected verified window, got {other:?}").into()),
    }
}

fn evidence(window: &RtpContinuityWindow) -> Result<&fss_core::DegradationEvidence, Error> {
    match &window.outcome {
        RtpWindowOutcome::Degraded { evidence } => Ok(evidence),
        other => Err(format!("expected degraded window, got {other:?}").into()),
    }
}

fn windowed_evidence(window: &RtpContinuityWindow) -> Result<&WindowedDegradationEvidence, Error> {
    let scoped = window
        .windowed_degradation
        .as_deref()
        .ok_or("degraded window is missing its sequence-bound evidence")?;
    assert_eq!(&scoped.degradation, evidence(window)?);
    assert_eq!(
        (scoped.window_start_seq, scoped.window_end_seq),
        (window.start_seq, window.end_seq)
    );
    Ok(scoped)
}

/// Reconstruct one generation from its retained witnesses, decoding every degraded window from
/// its canonical bytes. The resulting audit identities and final session must equal the driver.
fn replay_recorded_windows(report: &RtpContinuityReport) -> TestResult {
    assert_eq!(report.generations().len(), 1);
    let generation = &report.generations()[0];
    let request = report.session().request().clone();
    let transition_time = |digest| {
        report
            .session()
            .history()
            .iter()
            .find(|record| record.witness_digest == digest)
            .map(|record| record.timestamp_ns)
            .ok_or("retained witness has no audit transition")
    };
    let mut replay = AcquisitionSession::new(request.clone())?;
    replay.authenticate(
        generation.auth.clone(),
        transition_time(generation.auth.receipt_digest())?,
    )?;
    let ack = AdapterAck {
        adapter_id: request.adapter_identity.adapter_id.clone(),
        request_digest: request.request_digest(),
        ack_timestamp_ns: generation.auth.authorized_at_ns,
        session_handle: format!("rtp-g{}", generation.generation),
        allocated_buffer_frames: 0,
    };
    let accepted_at = transition_time(ack.ack_digest())?;
    replay.accept(ack, accepted_at)?;
    let first = &generation
        .first_picture
        .as_ref()
        .ok_or("replay needs a retained first picture")?
        .witness;
    replay.observe_first_frame(first.clone(), transition_time(first.witness_digest())?)?;
    let mut gap_seen = false;
    for window in report.windows() {
        match &window.outcome {
            RtpWindowOutcome::Degraded { .. } => {
                let retained = windowed_evidence(window)?;
                let bytes = retained.canonical_bytes();
                let mut decoder = CanonicalDecoder::new(&bytes);
                let decoded = WindowedDegradationEvidence::decode_canonical(&mut decoder)?;
                decoder.ensure_finished()?;
                assert_eq!(&decoded, retained);
                assert_eq!(decoded.canonical_bytes(), bytes);
                assert_eq!(decoded.request_digest, request.request_digest());
                assert_eq!(
                    decoded.predecessor_digest,
                    replay.continuity_predecessor_digest()?
                );
                let degraded_at = transition_time(decoded.evidence_digest())?;
                replay.degrade_window(decoded, degraded_at)?;
                gap_seen = true;
            }
            RtpWindowOutcome::Verified { witness } => {
                assert!(window.windowed_degradation.is_none());
                replay.verify_continuity(
                    witness.as_ref().clone(),
                    transition_time(witness.witness_digest())?,
                )?;
                if gap_seen {
                    assert!(matches!(
                        replay.check_absence_claim_allowed(),
                        Err(fss_core::AcquisitionError::AbsenceClaimForbidden { .. })
                    ));
                }
            }
            RtpWindowOutcome::TooShort => assert!(window.windowed_degradation.is_none()),
            RtpWindowOutcome::CleanNotVerified { refusal } => {
                return Err(
                    format!("unexpected clean-window refusal during replay: {refusal}").into(),
                );
            }
        }
    }
    let AcquisitionState::Cancelled { quiescence, .. } = report.session().state() else {
        return Err("recorded session did not close with verified quiescence".into());
    };
    replay.cancel(
        quiescence.clone(),
        transition_time(quiescence.receipt_digest())?,
    )?;
    assert_eq!(&replay, report.session());
    Ok(())
}

/// The access-unit capsule holding the first complete NAL whose first source record is `record`.
fn capsule_from_record(import: &RtpImportReport, record: usize) -> Option<&SensorCapsule> {
    import
        .nals()
        .iter()
        .find(|n| n.spans.first().is_some_and(|s| s.record == record))
        .and_then(|n| import.access_units().get(n.access_unit))
        .map(|u| &u.capsule)
}

/// Clean recording: exactly one window, verified, covering exactly the recorded interval from the
/// first picture's first packet to the last packet of the one stream; the first picture is a real
/// decode equal to the oracle.
///
/// Planted negatives: (a) starting the window at the baseline instead of the first picture
/// (`window_start_seq` assertion); (b) skipping the decode and declaring `Verified` (oracle
/// digest assertion); (c) a coverage witness naming a site-wide domain (domain assertion);
/// (d) omitting the session `verify_continuity` call (state-kind assertion); (e) a verified
/// window minting a self-certifying coverage witness (`certifies_absence` assertion); (f) an
/// authentication receipt that expires at the instant it is issued (receipt assertions).
#[test]
fn clean_recording_reaches_continuity_verified_with_one_exact_witness() -> TestResult {
    let planned = packetize(2, MAX_PAYLOAD, 65_534, SSRC_A, 90_000, 0);
    let bytes = dump_planned(&planned);
    let run = run("clean", &bytes, config_for(SSRC_A), policy(1_000))?;
    let report = &run.report;
    assert_eq!(
        report.kinds(),
        vec![
            AcquisitionStateKind::Requested,
            AcquisitionStateKind::Authenticated,
            AcquisitionStateKind::AdapterAccepted,
            AcquisitionStateKind::FirstFrameObserved,
            AcquisitionStateKind::ContinuityVerified,
            AcquisitionStateKind::Cancelled,
        ]
    );
    assert_eq!(report.generations().len(), 1);
    let generation = &report.generations()[0];
    assert_eq!(
        (generation.generation, generation.ssrc, generation.cause),
        (1, SSRC_A, None)
    );
    let picture = generation
        .first_picture
        .as_ref()
        .ok_or("no first picture")?;
    assert_eq!(picture.i420_sha256, oracle_first_picture()?);
    assert_eq!(picture.dimensions, (160, 128));
    let vcl = first_vcl(&planned)?;
    assert_eq!(picture.sequence, ext(vcl));
    assert_eq!(picture.witness.sequence_number, ext(vcl));

    assert_eq!(report.windows().len(), 1);
    let window = &report.windows()[0];
    assert!(window.windowed_degradation.is_none());
    let w = witness(window)?;
    let last = planned.len() - 1;
    assert_eq!(
        (w.window_start_seq, w.window_end_seq),
        (ext(vcl), ext(last))
    );
    assert_eq!(w.frames_observed, ext(last) - ext(vcl) + 1);
    assert_eq!((w.discontinuities, w.packet_loss), (0, 0));
    assert_eq!(w.observed_jitter_ns, 0);
    assert!(w.observed_jitter_ns <= w.max_jitter_threshold_ns);
    let pts_last =
        i128::from(planned[last].timestamp - planned[vcl].timestamp) * 1_000_000_000 / 90_000;
    assert_eq!(w.window_start_pts_ns, TimestampNs(0));
    assert_eq!(w.window_end_pts_ns, TimestampNs(pts_last));
    let request = report.session().request();
    w.verify(
        &request.source_identity.source_id,
        &request.device_identity.device_id,
        &request.adapter_identity.adapter_id,
    )?;
    let only = BTreeSet::from([source()?.as_str().to_owned()]);
    assert_eq!(w.coverage_witness.authorized_domain, only);
    assert_eq!(w.coverage_witness.observed_domain, only);
    // Changed from `certifies_absence()` (fss-2h5zq.29 review D1): the core witness carries no
    // interval, so a certifying witness would certify absence over all time, outside the
    // recorded window. The verified witness is continuous and complete (the core requires both)
    // but stops `Unsupported`, so it never certifies on its own.
    assert_eq!(
        (
            w.coverage_witness.continuity,
            w.coverage_witness.stop_reason
        ),
        (
            CoverageContinuity::Continuous,
            CoverageStopReason::Unsupported
        )
    );
    assert!(!w.coverage_witness.certifies_absence());
    assert_eq!(window.coverage, w.coverage_witness);
    // The authentication receipt (D5): issued at the generation's first arrival, valid through
    // the end of the last recorded millisecond, and the one the core recorded.
    let auth = &generation.auth;
    assert_eq!(auth.authorized_at_ns, at(planned[0].offset_ms));
    assert_eq!(
        auth.expires_at_ns,
        TimestampNs(at(planned[last].offset_ms).0 + 1_000_000)
    );
    assert!(auth.expires_at_ns > auth.authorized_at_ns);
    assert!(
        report
            .session()
            .history()
            .iter()
            .any(|r| r.to == AcquisitionStateKind::Authenticated
                && r.witness_digest == auth.receipt_digest())
    );
    // The first frame's media time is the first picture's own (zero by construction here).
    assert_eq!(picture.witness.pts_ns, TimestampNs(0));
    assert_eq!(
        window.interval,
        interval(at(planned[vcl].offset_ms), at(planned[last].offset_ms))?
    );
    // The verified history carries this witness's digest.
    assert!(
        report
            .session()
            .history()
            .iter()
            .any(|r| r.to == AcquisitionStateKind::ContinuityVerified
                && r.witness_digest == w.witness_digest())
    );
    caplog(
        "clean_continuity_verified",
        &format!("{}|{}", kinds_text(report), w.witness_digest()),
    );
    Ok(())
}

/// Builds the four-repetition loss recording: packet `drop` never arrives.
fn loss_run(label: &str, drop: usize) -> Result<(Vec<Planned>, Run), Error> {
    let planned = packetize(4, MAX_PAYLOAD, 65_534, SSRC_A, 90_000, 0);
    let mut kept = planned.clone();
    kept.remove(drop);
    let run = run(label, &dump_planned(&kept), config_for(SSRC_A), policy(16))?;
    Ok((planned, run))
}

/// Loss: the window holding the lost packet degrades with the gap interval recorded and absence
/// over it invalidated; absence over the gap (or any query touching it, whatever comes first) is
/// refused; absence over the verified windows before it reaches the shared stored-witness rule,
/// which refuses the recorded capsules' estimated clock; later clean windows recover verified
/// transport continuity after the exact degraded span; the first capsule after the gap has
/// `gap_before`. Recovery does not establish decoding of later reference-dependent pictures.
///
/// Planted negatives: (a) counting a lost position as observed (`observed_packet_loss`);
/// (b) evaluating only the first overlapping window (spanning query); (c) certifying from the
/// session alone without the stored rule (clean query answer); (d) treating recovered continuity
/// as coverage of the gap (spanning recovered query); (e) the importer clearing `gap_before`
/// after a loss; (f) retaining an unbound gap while refusing all later clean windows.
#[test]
fn loss_degrades_records_the_gap_and_refuses_absence_over_it() -> TestResult {
    let drop = 46;
    let (planned, run) = loss_run("loss", drop)?;
    let report = &run.report;
    let lost = ext(drop);
    let windows = report.windows();
    let gap_index = windows
        .iter()
        .position(|w| (w.start_seq..=w.end_seq).contains(&lost))
        .ok_or("no window holds the lost position")?;
    assert!(gap_index >= 2, "the loss must follow two verified windows");
    for window in &windows[..gap_index] {
        witness(window)?;
    }
    let gap = &windows[gap_index];
    let ev = evidence(gap)?;
    assert_eq!(gap.missing_positions, 1);
    assert_eq!(ev.observed_packet_loss, 1);
    assert!(ev.lost_dimensions.contains(&LOST_PACKET_LOSS.to_owned()));
    assert!(
        ev.lost_dimensions
            .contains(&LOST_MEDIA_RECONSTRUCTION.to_owned())
    );
    assert_eq!(
        ev.invalidated_negative_claims,
        vec![
            INVALIDATED_ABSENCE.to_owned(),
            format!(
                "absence_interval_ns:{}..{}",
                gap.interval.earliest.0, gap.interval.latest.0
            )
        ]
    );
    assert_eq!(gap.coverage.continuity, CoverageContinuity::Gapped);
    assert!(!gap.coverage.certifies_absence());
    let scoped = windowed_evidence(gap)?;
    assert_eq!(
        scoped.request_digest,
        report.session().request().request_digest()
    );
    assert_eq!(
        scoped.predecessor_digest,
        witness(&windows[gap_index - 1])?.witness_digest()
    );
    assert!(report.session().history().iter().any(|transition| {
        transition.to == AcquisitionStateKind::Degraded
            && transition.witness_digest == scoped.evidence_digest()
    }));
    // Later clean windows recover their own spans, without extending coverage across this gap.
    let later = &windows[gap_index + 1..];
    assert!(!later.is_empty());
    assert!(
        later
            .iter()
            .all(|w| !matches!(w.outcome, RtpWindowOutcome::CleanNotVerified { .. }))
    );
    let recovered = &later[0];
    let recovered_witness = witness(recovered)?;
    assert_eq!(recovered_witness.window_start_seq, gap.end_seq + 1);
    assert!(recovered.windowed_degradation.is_none());
    assert!(!recovered.coverage.certifies_absence());
    assert!(report.kinds().contains(&AcquisitionStateKind::Degraded));

    // Absence over the gap interval.
    match report.absence_over(gap.interval) {
        RtpAbsenceAnswer::NotCertified(RtpAbsenceRefusal::GapOverlaps { gaps }) => {
            assert_eq!(gaps, vec![(1, gap.start_seq, gap.end_seq, gap.interval)]);
        }
        other => return Err(format!("gap absence must be refused, got {other:?}").into()),
    }
    // A query starting in a verified window and reaching into the gap.
    let before = &windows[gap_index - 1];
    let spanning = interval(before.interval.earliest, gap.interval.latest)?;
    assert!(matches!(
        report.absence_over(spanning),
        RtpAbsenceAnswer::NotCertified(RtpAbsenceRefusal::GapOverlaps { .. })
    ));
    // A query inside the verified run before the gap: the shared stored-witness rule decides.
    let clean = interval(
        windows[0].interval.earliest,
        TimestampNs(before.interval.latest.0 - 1),
    )?;
    assert!(clean.latest < gap.interval.earliest);
    assert_eq!(
        report.absence_over(clean),
        RtpAbsenceAnswer::NotCertified(RtpAbsenceRefusal::StoredWitnessRule(
            ContractError::CoverageUncertified
        ))
    );
    // Recovery cannot erase the recorded gap even when the query ends in a clean window.
    let through_recovery = interval(before.interval.earliest, recovered.interval.latest)?;
    assert!(matches!(
        report.absence_over(through_recovery),
        RtpAbsenceAnswer::NotCertified(RtpAbsenceRefusal::GapOverlaps { .. })
    ));
    let recovered_interior = interval(
        TimestampNs(recovered.interval.earliest.0 + 1),
        recovered.interval.latest,
    )?;
    assert!(recovered_interior.earliest > gap.interval.latest);
    assert_eq!(
        report.absence_over(recovered_interior),
        RtpAbsenceAnswer::NotCertified(RtpAbsenceRefusal::StoredWitnessRule(
            ContractError::CoverageUncertified
        ))
    );

    // Capsules: none inside the verified windows follows a gap; the first after the loss does.
    for window in &windows[..gap_index] {
        assert!(report.window_capsules(window).all(|c| !c.gap_before));
    }
    let after = capsule_from_record(&run.import, drop).ok_or("no capsule after the loss")?;
    assert!(after.gap_before);
    assert_eq!(planned.len() - 1, run.import.records().len());
    caplog(
        "loss_degraded_gap_refused",
        &format!(
            "{}|{}|{}|{}",
            kinds_text(report),
            scoped.evidence_digest(),
            recovered_witness.witness_digest(),
            gap.lost_dimensions.join("+")
        ),
    );
    Ok(())
}

/// The module's own verified-window witness never certifies absence in the core event store, and
/// (fss-3qlsa regression) the gap window's gapped witness revokes a certifying witness in both
/// registration orders.
///
/// The verified window's witness, registered alone, is refused as uncertified: it carries no
/// interval, so certifying would claim absence over all time (review D1). To keep the any-gap-wins
/// regression meaningful, a control witness that does certify alone (the same witness with a
/// `Complete` stop reason, the pre-fix shape) is registered with the gap witness in both orders,
/// and the gap is named among the refusal reasons.
///
/// Planted negatives: (a) the gap window carrying a continuous coverage witness; (b) the store
/// evaluating only the first registered witness (certifying-first order); (c) a verified window
/// minting a self-certifying witness (alone assertion).
#[test]
fn gap_witness_revokes_absence_in_either_registration_order() -> TestResult {
    let (_, run) = loss_run("store-order", 46)?;
    let windows = run.report.windows();
    let verified = windows
        .iter()
        .find(|w| matches!(w.outcome, RtpWindowOutcome::Verified { .. }))
        .ok_or("no verified window")?;
    let gap = windows
        .iter()
        .find(|w| matches!(w.outcome, RtpWindowOutcome::Degraded { .. }))
        .ok_or("no degraded window")?;
    let domain = source()?;
    let absent = EventId::parse("evt_rtp_absent")?;
    // Inverted from the pre-fix test, which asserted `AbsentWithCoverage` here: that answer
    // certified absence over all time from one recorded window, which is the D1 defect.
    let mut alone = EventRevisionStore::new(LedgerAnchor::genesis("site:rtp-store"));
    alone.register_coverage_witness(
        alone.current_anchor().clone(),
        verified.coverage.clone(),
        TimestampNs(1),
    )?;
    match alone.read_event_in_domain(&absent, domain.as_str(), None)? {
        EventReadResult::NotObservable {
            reason,
            all_reasons,
            ..
        } => {
            assert_eq!(reason, NotObservableReason::CoverageWitnessUncertified);
            assert_eq!(
                all_reasons,
                vec![NotObservableReason::CoverageWitnessUncertified]
            );
        }
        other => {
            return Err(format!("the module's witness certified absence alone: {other:?}").into());
        }
    }
    // Control: a certifying witness over the same source certifies alone ...
    let mut certifying = verified.coverage.clone();
    certifying.stop_reason = CoverageStopReason::Complete;
    assert!(certifying.certifies_absence());
    let mut control = EventRevisionStore::new(LedgerAnchor::genesis("site:rtp-store"));
    control.register_coverage_witness(
        control.current_anchor().clone(),
        certifying.clone(),
        TimestampNs(1),
    )?;
    assert!(matches!(
        control.read_event_in_domain(&absent, domain.as_str(), None)?,
        EventReadResult::AbsentWithCoverage(_)
    ));
    // ... and the gap window's witness revokes it in either registration order.
    for order in [
        [certifying.clone(), gap.coverage.clone()],
        [gap.coverage.clone(), certifying.clone()],
    ] {
        let mut store = EventRevisionStore::new(LedgerAnchor::genesis("site:rtp-store"));
        for (i, witness) in order.into_iter().enumerate() {
            store.register_coverage_witness(
                store.current_anchor().clone(),
                witness,
                TimestampNs(1 + i as i128),
            )?;
        }
        match store.read_event_in_domain(&absent, domain.as_str(), None)? {
            EventReadResult::NotObservable { all_reasons, .. } => {
                assert!(all_reasons.contains(&NotObservableReason::CoverageWitnessGapped));
            }
            other => {
                return Err(format!("absence over a gap was certified: {other:?}").into());
            }
        }
    }
    caplog("store_order_gap_refused", "not_observable_both_orders");
    Ok(())
}

/// Reorder within tolerance: no transport loss, but the depacketizer dropped the late packet's
/// media, so the window degrades with exactly `media_reconstruction_gap` and zero loss.
///
/// Planted negatives: (a) treating a within-tolerance reorder as lost (`missing_positions`);
/// (b) presenting transport continuity as media continuity (window verified).
#[test]
fn reorder_within_tolerance_is_delivered_but_media_gap_degrades() -> TestResult {
    let mut planned = packetize(4, MAX_PAYLOAD, 65_534, SSRC_A, 90_000, 0);
    let late = 46;
    // Packet 46 arrives right after 47, at 47's recorder time.
    planned[late].offset_ms = planned[late + 1].offset_ms;
    planned.swap(late, late + 1);
    let run = run(
        "reorder-in",
        &dump_planned(&planned),
        config_for(SSRC_A),
        policy(16),
    )?;
    let window = run
        .report
        .windows()
        .iter()
        .find(|w| (w.start_seq..=w.end_seq).contains(&ext(late)))
        .ok_or("no window")?;
    let ev = evidence(window)?;
    assert_eq!(window.missing_positions, 0);
    assert_eq!(ev.observed_packet_loss, 0);
    assert_eq!(
        ev.lost_dimensions,
        vec![LOST_MEDIA_RECONSTRUCTION.to_owned()]
    );
    caplog("reorder_within_tolerance", &ev.lost_dimensions.join("+"));
    Ok(())
}

/// Reorder beyond tolerance: the position counts as lost, and late.
///
/// Planted negative: ignoring the tolerance (accepting any reordered packet as timely).
#[test]
fn reorder_beyond_tolerance_counts_as_loss() -> TestResult {
    let mut planned = packetize(4, MAX_PAYLOAD, 65_534, SSRC_A, 90_000, 0);
    let late = 46;
    let mut packet = planned.remove(late);
    let landing = late + 20;
    packet.offset_ms = planned[landing - 1].offset_ms;
    planned.insert(landing, packet);
    let mut p = policy(16);
    p.reorder_tolerance_packets = 8;
    p.max_jitter_threshold_ns = 1_000_000_000;
    let run = run(
        "reorder-out",
        &dump_planned(&planned),
        config_for(SSRC_A),
        p,
    )?;
    let window = run
        .report
        .windows()
        .iter()
        .find(|w| (w.start_seq..=w.end_seq).contains(&ext(late)))
        .ok_or("no window")?;
    let ev = evidence(window)?;
    assert_eq!(window.missing_positions, 1);
    assert_eq!(ev.observed_packet_loss, 1);
    assert!(ev.lost_dimensions.contains(&LOST_PACKET_LOSS.to_owned()));
    assert!(ev.lost_dimensions.contains(&LOST_LATE_PACKET.to_owned()));
    caplog("reorder_beyond_tolerance", &ev.lost_dimensions.join("+"));
    Ok(())
}

/// SSRC change: a new stream generation (reconnect with a strictly newer core stream generation),
/// whose first capsule carries `gap_before`, whose own first picture is decoded and verified, and
/// whose continuity never joins the old generation's.
///
/// The new SSRC passes the replay's two-packet validation (its first two packets are consecutive),
/// so its first packet is the restart record; that record is the new epoch's probation packet.
///
/// Planted negatives: (a) the replay refusing the new SSRC (no second generation); (b) reusing the
/// generation (`stream_generation` ordering); (c) an absence run spanning the generation boundary.
/// Not a planted negative here: the importer's explicit restart fence
/// (`gap || record.restart.is_some()`). The restart record is always the new epoch's probation
/// packet, which is a fence on its own, so removing the explicit fence changes no observable
/// value; it is kept as defense in depth and the `gap_before` assertions below hold either way.
#[test]
fn ssrc_change_opens_a_new_stream_generation() -> TestResult {
    let a = packetize(2, MAX_PAYLOAD, 65_534, SSRC_A, 90_000, 0);
    let a_end = a.last().ok_or("empty")?.offset_ms;
    let b = packetize(2, MAX_PAYLOAD, 1_000, SSRC_B, 900_000, a_end + 40);
    let mut planned = a.clone();
    planned.extend(b.iter().cloned());
    let run = run(
        "ssrc",
        &dump_planned(&planned),
        config_for(SSRC_A),
        policy(1_000),
    )?;
    let report = &run.report;
    let generations = report.generations();
    assert_eq!(generations.len(), 2);
    assert_eq!(
        (
            generations[1].generation,
            generations[1].ssrc,
            generations[1].cause
        ),
        (2, SSRC_B, Some(RestartCause::SsrcChange))
    );
    assert!(generations[1].stream_generation > generations[0].stream_generation);
    for g in generations {
        let picture = g
            .first_picture
            .as_ref()
            .ok_or("generation without picture")?;
        assert_eq!(picture.i420_sha256, oracle_first_picture()?);
    }
    use AcquisitionStateKind as K;
    assert_eq!(
        report.kinds(),
        vec![
            K::Requested,
            K::Authenticated,
            K::AdapterAccepted,
            K::FirstFrameObserved,
            K::ContinuityVerified,
            K::Requested,
            K::Authenticated,
            K::AdapterAccepted,
            K::FirstFrameObserved,
            K::ContinuityVerified,
            K::Cancelled,
        ]
    );
    assert_eq!(
        report.session().request().source_identity.stream_generation,
        generations[1].stream_generation
    );
    // The restart record and the capsule fence.
    let restart = &run.import.records()[a.len()];
    assert_eq!(restart.restart, Some(RestartCause::SsrcChange));
    assert_eq!((restart.generation, restart.ssrc), (2, SSRC_B));
    let first_b = run
        .import
        .access_units()
        .iter()
        .find(|u| u.generation == 2)
        .ok_or("no capsule in generation 2")?;
    assert!(first_b.capsule.gap_before);
    let windows = report.windows();
    assert_eq!(windows.len(), 2);
    assert_eq!((windows[0].generation, windows[1].generation), (1, 2));
    let across = interval(windows[0].interval.earliest, windows[1].interval.latest)?;
    assert!(matches!(
        report.absence_over(across),
        RtpAbsenceAnswer::NotCertified(RtpAbsenceRefusal::OutsideVerifiedCoverage)
    ));
    caplog(
        "ssrc_change_new_generation",
        &format!(
            "{}|{}",
            kinds_text(report),
            generations[1].stream_generation
        ),
    );
    Ok(())
}

/// A sequence jump on the same SSRC: the kernel suspects a discontinuity, then requires a restart;
/// the old generation's last window degrades, a new generation opens with cause
/// `sequence_restart` and verifies on its own.
///
/// Planted negatives: (a) dropping the suspected discontinuity (old window stays verified);
/// (b) the replay staying in `RestartRequired` forever (no second generation).
#[test]
fn sequence_restart_opens_a_new_stream_generation() -> TestResult {
    let a = packetize(2, MAX_PAYLOAD, 65_534, SSRC_A, 90_000, 0);
    let a_end = a.last().ok_or("empty")?.offset_ms;
    let jump = 65_534_u16.wrapping_add(a.len() as u16).wrapping_add(10_000);
    let b = packetize(2, MAX_PAYLOAD, jump, SSRC_A, 900_000, a_end + 40);
    let mut planned = a.clone();
    planned.extend(b.iter().cloned());
    let run = run(
        "restart",
        &dump_planned(&planned),
        config_for(SSRC_A),
        policy(1_000),
    )?;
    let generations = run.report.generations();
    assert_eq!(generations.len(), 2);
    assert_eq!(generations[1].cause, Some(RestartCause::SequenceRestart));
    assert!(generations[1].first_picture.is_some());
    let old = run
        .report
        .windows()
        .iter()
        .rfind(|w| w.generation == 1)
        .ok_or("no window in generation 1")?;
    let ev = evidence(old)?;
    assert!(
        ev.lost_dimensions
            .contains(&LOST_SEQUENCE_DISCONTINUITY.to_owned())
    );
    assert!(
        run.report
            .windows()
            .iter()
            .any(|w| w.generation == 2 && matches!(w.outcome, RtpWindowOutcome::Verified { .. }))
    );
    caplog("sequence_restart_new_generation", &kinds_text(&run.report));
    Ok(())
}

/// A one-time 100 ms arrival step: the window holding it degrades with exactly `timing_jitter`;
/// the next clean window recovers continuity immediately after that accounted sequence span.
/// The degraded interval remains excluded from negative evidence after recovery.
///
/// Planted negatives: (a) not comparing jitter against the threshold (window verified);
/// (b) permanently stranding a clean generation after a jitter spike (next window unverified);
/// (c) treating recovery as proof of absence over the degraded interval.
#[test]
fn jitter_step_degrades_then_recovers_without_erasing_the_gap() -> TestResult {
    let mut planned = packetize(4, MAX_PAYLOAD, 65_534, SSRC_A, 90_000, 0);
    let vcl = first_vcl(&planned)?;
    let step = vcl + 32; // first position of the third 16-packet window
    for p in planned.iter_mut().skip(step) {
        p.offset_ms += 100;
    }
    let mut p = policy(16);
    p.max_jitter_threshold_ns = 5_000_000;
    let run = run("jitter", &dump_planned(&planned), config_for(SSRC_A), p)?;
    let windows = run.report.windows();
    witness(&windows[0])?;
    witness(&windows[1])?;
    assert_eq!(windows[2].start_seq, ext(step));
    let ev = evidence(&windows[2])?;
    assert_eq!(ev.lost_dimensions, vec![LOST_TIMING_JITTER.to_owned()]);
    assert_eq!(ev.observed_packet_loss, 0);
    assert!(ev.observed_jitter_ns > 5_000_000);
    let recovered = witness(&windows[3])?;
    assert_eq!(recovered.window_start_seq, windows[2].end_seq + 1);
    let scoped = windowed_evidence(&windows[2])?;
    assert_eq!(
        scoped.predecessor_digest,
        witness(&windows[1])?.witness_digest()
    );
    assert!(windows[3].lost_dimensions.is_empty());
    assert!(!recovered.coverage_witness.certifies_absence());
    assert!(matches!(
        run.report.absence_over(interval(
            windows[1].interval.earliest,
            windows[3].interval.latest
        )?),
        RtpAbsenceAnswer::NotCertified(RtpAbsenceRefusal::GapOverlaps { .. })
    ));
    assert_eq!(
        run.report.absence_over(interval(
            TimestampNs(windows[3].interval.earliest.0 + 1),
            windows[3].interval.latest
        )?),
        RtpAbsenceAnswer::NotCertified(RtpAbsenceRefusal::StoredWitnessRule(
            ContractError::CoverageUncertified
        ))
    );
    assert!(matches!(
        run.report.absence_over(windows[2].interval),
        RtpAbsenceAnswer::NotCertified(RtpAbsenceRefusal::GapOverlaps { .. })
    ));
    caplog(
        "jitter_degraded_recovered",
        &format!(
            "{}|{}|{}",
            scoped.evidence_digest(),
            recovered.witness_digest(),
            ev.lost_dimensions.join("+")
        ),
    );
    Ok(())
}

/// Two adjacent jitter windows chain through both retained degradation identities and recover
/// at the following clean window. This works even when no clean window preceded the first gap.
/// Replaying the exact canonical wrappers preserves the full session and all invalidated claims.
///
/// Planted negatives: (a) using the last clean witness as every degradation's predecessor;
/// (b) requiring an already verified window before admitting the first degraded span;
/// (c) changing the request, sequence span, or legacy evidence while retaining only its digest;
/// (d) clearing earlier gaps when continuity resumes.
#[test]
fn consecutive_degraded_windows_replay_and_recover_in_the_same_generation() -> TestResult {
    for (label, first_gap_index, caplog_step) in [
        ("initial-gaps", 0_usize, "first_window_gap_recovered"),
        ("later-gaps", 2_usize, "consecutive_gaps_replayed"),
    ] {
        let mut planned = packetize(4, MAX_PAYLOAD, 65_534, SSRC_A, 90_000, 0);
        let vcl = first_vcl(&planned)?;
        // A first-window step follows the first VCL packet so it belongs to the sequence
        // window, while the recorded first picture still decodes and establishes its witness.
        let first_step = vcl + first_gap_index * 16 + usize::from(first_gap_index == 0);
        let second_step = vcl + (first_gap_index + 1) * 16;
        for packet in planned.iter_mut().skip(first_step) {
            packet.offset_ms += 100;
        }
        for packet in planned.iter_mut().skip(second_step) {
            packet.offset_ms += 100;
        }
        let mut p = policy(16);
        p.max_jitter_threshold_ns = 5_000_000;
        let run = run(label, &dump_planned(&planned), config_for(SSRC_A), p)?;
        let report = &run.report;
        assert_eq!(report.generations().len(), 1);
        let windows = report.windows();
        for window in &windows[..first_gap_index] {
            witness(window)?;
        }
        let first_gap = &windows[first_gap_index];
        let second_gap = &windows[first_gap_index + 1];
        let first_scoped = windowed_evidence(first_gap)?;
        let second_scoped = windowed_evidence(second_gap)?;
        let predecessor = if first_gap_index == 0 {
            let first = &report.generations()[0]
                .first_picture
                .as_ref()
                .ok_or("no first picture")?
                .witness;
            assert_eq!(first_gap.start_seq, first.sequence_number);
            first.witness_digest()
        } else {
            witness(&windows[first_gap_index - 1])?.witness_digest()
        };
        assert_eq!(first_scoped.predecessor_digest, predecessor);
        assert_eq!(
            second_scoped.predecessor_digest,
            first_scoped.evidence_digest()
        );
        assert_eq!(second_gap.start_seq, first_gap.end_seq + 1);
        for gap in [first_gap, second_gap] {
            assert_eq!(gap.lost_dimensions, vec![LOST_TIMING_JITTER.to_owned()]);
            assert_eq!(gap.coverage.continuity, CoverageContinuity::Gapped);
            assert!(!gap.coverage.certifies_absence());
        }
        let recovered = &windows[first_gap_index + 2];
        let recovered_witness = witness(recovered)?;
        assert_eq!(recovered_witness.window_start_seq, second_gap.end_seq + 1);
        assert!(recovered.windowed_degradation.is_none());
        match report.absence_over(interval(
            first_gap.interval.earliest,
            recovered.interval.latest,
        )?) {
            RtpAbsenceAnswer::NotCertified(RtpAbsenceRefusal::GapOverlaps { gaps }) => {
                assert_eq!(
                    gaps,
                    vec![
                        (
                            1,
                            first_gap.start_seq,
                            first_gap.end_seq,
                            first_gap.interval
                        ),
                        (
                            1,
                            second_gap.start_seq,
                            second_gap.end_seq,
                            second_gap.interval
                        ),
                    ]
                );
            }
            other => {
                return Err(format!("both retained gaps must win after recovery: {other:?}").into());
            }
        }
        replay_recorded_windows(report)?;
        caplog(
            caplog_step,
            &format!(
                "{}|{}|{}|{}",
                kinds_text(report),
                first_scoped.evidence_digest(),
                second_scoped.evidence_digest(),
                recovered_witness.witness_digest()
            ),
        );
    }
    Ok(())
}

/// The canonical synthetic fixture family is packet-perfect but not decodable: no first frame,
/// so the generation degrades with `first_frame_not_verified` and never reaches continuity; its
/// `ssrc_reset` variant opens a second generation whose first capsule is fenced.
///
/// Planted negatives: (a) declaring a first frame without a decoded picture; (b) the old
/// refusal of the second SSRC.
#[test]
fn non_decodable_canonical_fixtures_never_reach_continuity() -> TestResult {
    let ssrc = 287_454_020;
    let clean = include_bytes!("../../../tests/fixtures/media/rtp/clean.rtp");
    let run1 = run("canonical-clean", clean, config_for(ssrc), policy(16))?;
    assert_eq!(
        kinds_text(&run1.report),
        "requested,authenticated,adapter_accepted,degraded,cancelled"
    );
    assert!(run1.report.windows().is_empty());
    let g = &run1.report.generations()[0];
    assert!(
        g.pre_first_frame_lost
            .contains(&LOST_FIRST_FRAME_NOT_VERIFIED.to_owned())
    );
    assert!(matches!(
        run1.report.absence_over(g.interval),
        RtpAbsenceAnswer::NotCertified(RtpAbsenceRefusal::GenerationUnverified { .. })
    ));
    let reset = include_bytes!("../../../tests/fixtures/media/rtp/ssrc_reset.rtp");
    let run2 = run("canonical-reset", reset, config_for(ssrc), policy(16))?;
    let generations = run2.report.generations();
    assert_eq!(generations.len(), 2);
    assert_eq!(generations[1].cause, Some(RestartCause::SsrcChange));
    assert_eq!(generations[1].ssrc, 0x5566_7788);
    let fenced = run2
        .import
        .access_units()
        .iter()
        .find(|u| u.generation == 2)
        .ok_or("no generation-2 capsule")?;
    assert!(fenced.capsule.gap_before);
    caplog("canonical_fixtures_unverified", &kinds_text(&run2.report));
    Ok(())
}

/// Cancellation before the run admits nothing.
///
/// Planted negative: a run that ignores the context's cancellation.
#[test]
fn cancellation_refuses_the_run() -> TestResult {
    let planned = packetize(1, MAX_PAYLOAD, 65_534, SSRC_A, 90_000, 0);
    let bytes = dump_planned(&planned);
    let root = new_directory("cancel")?;
    let cx = cx()?;
    let mut dep = ReferenceDeployment::open(&root, "site:rtp-continuity-cancel", &cx)?;
    let scope = RtpImportScope {
        sensor: SensorId::parse("sensor:rtp-continuity")?,
        stream: StreamId::parse("stream:rtp-continuity")?,
        receive_time: TimestampNs(2_000_000_000_000),
    };
    let plan = prepare_rtp_import(
        &bytes,
        scope,
        config_for(SSRC_A),
        RtpImportLimits::default(),
        &cx,
    )?;
    let receipt = publish_rtp_import(plan, &cx, &mut dep)?;
    let verified = load_rtp_import(&receipt, &cx, &dep)?;
    let continuity_scope = RtpContinuityScope {
        source_id: source()?,
        device_id: DeviceId::parse("device:rtp-continuity-camera")?,
        failure_domain: "domain:rtp-continuity-camera".into(),
        recording_origin: TimestampNs(ORIGIN_NS),
        basis: dep.current_anchor().clone(),
        negative_predicate: "no_unknown_person_present".into(),
    };
    cx.request_cancellation();
    assert!(matches!(
        drive_rtp_continuity(&receipt, &verified, &continuity_scope, policy(16), &cx),
        Err(RtpContinuityError::Cancelled { .. })
    ));
    caplog("cancellation_refused", "cancelled");
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// fss-2h5zq.29 independent-review fixes (D2-D5, mutants E, F, G, H, O). The reviewer's probes
// P1, P2, P4 and P5 (local commit e2e3fb0) are reused below with exact-variant assertions.
// ---------------------------------------------------------------------------------------------

/// Serializes `planned` with one extra raw record (`packet`, original length `plen`, recorder
/// offset `offset_ms`) inserted before planned packet `before`.
fn dump_with_record(
    planned: &[Planned],
    before: usize,
    packet: &[u8],
    plen: u16,
    offset_ms: u32,
) -> Vec<u8> {
    let mut b = header();
    for (i, p) in planned.iter().enumerate() {
        if i == before {
            record(&mut b, packet, plen, offset_ms);
        }
        let wire = rtp_full(p.seq, p.marker, p.timestamp, p.ssrc, &p.payload);
        record(&mut b, &wire, wire.len() as u16, p.offset_ms);
    }
    b
}

/// Probe P1 (review D2): one stray foreign-SSRC packet mid-stream, inside a pending FU-A
/// fragment, then the bound SSRC resumes. The stray fails the replay's two-packet SSRC
/// validation: it is refused alone, opens no generation and retires no fragment, and the bound
/// stream keeps ingesting to its end. The windows whose recorder interval contains the stray's
/// arrival degrade with exactly `packet_refused` (fail-closed: a foreign packet in the recording
/// is not certified away).
///
/// Planted negatives: (a) switching generation on the first foreign packet (the pre-fix replay:
/// a second generation that never gets a baseline and 31 refused records); (b) the stray retiring
/// the bound stream's pending fragment (`discarded` and the completed NAL); (c) charging the stray
/// to no window.
#[test]
fn stray_foreign_ssrc_packet_is_refused_and_the_stream_keeps_ingesting() -> TestResult {
    let mut planned = packetize(2, MAX_PAYLOAD, 65_534, SSRC_A, 90_000, 0);
    let at_index = 30;
    // Precondition: the stray lands inside a fragmented NAL (an FU-A continuation follows it).
    assert_eq!(planned[at_index].payload[0] & 31, 28);
    assert_eq!(planned[at_index].payload[1] & 0x80, 0);
    let mut stray = planned[at_index].clone();
    stray.ssrc = SSRC_B;
    stray.seq = 12_345;
    planned.insert(at_index, stray);
    let run = run(
        "stray",
        &dump_planned(&planned),
        config_for(SSRC_A),
        policy(16),
    )?;
    let records = run.import.records();
    assert_eq!(records.len(), planned.len());
    let refused: Vec<usize> = records
        .iter()
        .enumerate()
        .filter(|(_, r)| matches!(r.disposition, RecordDisposition::StreamRefused(_)))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(refused, vec![at_index]);
    let stray_record = &records[at_index];
    assert_eq!(
        stray_record.disposition,
        RecordDisposition::StreamRefused(ContinuityError::StreamMismatch)
    );
    assert!(stray_record.discarded.is_none());
    assert!(
        records
            .iter()
            .all(|r| r.generation == 1 && r.ssrc == SSRC_A && r.restart.is_none())
    );
    // Every bound-SSRC packet after the probation packet reaches the depacketizer ...
    for (i, r) in records.iter().enumerate().skip(1) {
        if i != at_index {
            assert!(
                matches!(r.disposition, RecordDisposition::H264(_)),
                "record {i}: {:?}",
                r.disposition
            );
        }
    }
    // ... and the fragment pending across the stray completes on the next record.
    assert!(!records[at_index + 1].nals.is_empty());
    assert!(records[at_index + 1].discarded.is_none());

    let report = &run.report;
    assert_eq!(report.generations().len(), 1);
    let g = &report.generations()[0];
    assert_eq!((g.generation, g.ssrc, g.cause), (1, SSRC_A, None));
    assert!(g.first_picture.is_some());
    // `planned` holds one extra (stray) packet: the last bound packet is planned index len - 1,
    // at extended sequence 65534 + (len - 2).
    assert_eq!(
        report.windows().last().map(|w| w.end_seq),
        Some(ext(planned.len() - 2))
    );
    let stray_at = at(planned[at_index].offset_ms);
    let hit: Vec<&RtpContinuityWindow> = report
        .windows()
        .iter()
        .filter(|w| w.interval.earliest <= stray_at && stray_at <= w.interval.latest)
        .collect();
    assert!(!hit.is_empty());
    for w in &hit {
        assert_eq!(w.lost_dimensions, vec![LOST_PACKET_REFUSED.to_owned()]);
        evidence(w)?;
    }
    caplog(
        "stray_foreign_ssrc_refused",
        &format!("{}|{}", kinds_text(report), hit.len()),
    );
    Ok(())
}

/// fss-iui8a N1: a foreign SSRC sends two consecutive packets on another payload type (PCMU,
/// payload type 0: an audio stream interleaved in the recording) inside a pending FU-A fragment of
/// the bound H.264 stream. Two consecutive packets of one SSRC pass the sequence half of the
/// replay's two-packet validation, so only its payload-type checks keep them from opening a
/// generation: both are refused alone as strays, retire no fragment, and the bound stream keeps
/// ingesting to its end in generation 1.
///
/// Planted negative: mutant M10 (both payload-type checks removed from `new_source_validated`)
/// opens a generation for the audio SSRC, so records leave generation 1 and the bound stream
/// stops reaching the depacketizer.
#[test]
fn foreign_ssrc_on_another_payload_type_opens_no_generation() -> TestResult {
    foreign_payload_types_open_no_generation("foreign-pt", [PCMU, PCMU])
}

/// fss-iui8a review: the foreign SSRC's first packet is on the bound payload type and its second
/// on PCMU. The first passes the replay's first payload-type check, so only the lookahead's
/// check on the second packet keeps the pair from opening a generation.
///
/// Planted negative: removing only the lookahead payload-type check of `new_source_validated`
/// (replay.rs, the per-packet check in the probation loop) opens a generation for SSRC_B.
#[test]
fn foreign_ssrc_bound_then_other_payload_type_opens_no_generation() -> TestResult {
    let bound = config_for(SSRC_A).payload_type;
    foreign_payload_types_open_no_generation("foreign-pt-bound-pcmu", [bound, PCMU])
}

/// fss-iui8a review: the foreign SSRC's first packet is on PCMU and its second on the bound
/// payload type. The lookahead from the second packet sees a bound-stream record, so only the
/// first packet's own payload-type check keeps it from opening a generation with the second.
///
/// Planted negative: removing only the first payload-type check of `new_source_validated`
/// (replay.rs, the check of the candidate packet itself) opens a generation for SSRC_B.
#[test]
fn foreign_ssrc_other_then_bound_payload_type_opens_no_generation() -> TestResult {
    let bound = config_for(SSRC_A).payload_type;
    foreign_payload_types_open_no_generation("foreign-pt-pcmu-bound", [PCMU, bound])
}

/// PCMU, payload type 0: an audio stream interleaved in the recording.
const PCMU: u8 = 0;

/// Two consecutive foreign-SSRC packets with `payload_types` inside a pending FU-A fragment of
/// the bound stream: both are refused alone as strays, retire no fragment, and the bound stream
/// keeps ingesting to its end in generation 1.
fn foreign_payload_types_open_no_generation(label: &str, payload_types: [u8; 2]) -> TestResult {
    let bound = config_for(SSRC_A).payload_type;
    assert_eq!(bound, 96, "rtp_full writes payload type 96");
    let planned = packetize(2, MAX_PAYLOAD, 65_534, SSRC_A, 90_000, 0);
    let at_index = 30;
    // Precondition: the foreign packets land inside a fragmented NAL.
    assert_eq!(planned[at_index].payload[0] & 31, 28);
    assert_eq!(planned[at_index].payload[1] & 0x80, 0);
    let offset_ms = planned[at_index].offset_ms;
    let mut foreign = Vec::new();
    for ((seq, timestamp), payload_type) in [(500_u16, 8_000_u32), (501, 8_160)]
        .into_iter()
        .zip(payload_types)
    {
        let mut wire = rtp_full(seq, false, timestamp, SSRC_B, &[0xff; 160]);
        wire[1] = payload_type;
        foreign.push(wire);
    }
    let mut bytes = header();
    for (i, p) in planned.iter().enumerate() {
        if i == at_index {
            for wire in &foreign {
                record(&mut bytes, wire, wire.len() as u16, offset_ms);
            }
        }
        let wire = rtp_full(p.seq, p.marker, p.timestamp, p.ssrc, &p.payload);
        record(&mut bytes, &wire, wire.len() as u16, p.offset_ms);
    }
    let run = run(label, &bytes, config_for(SSRC_A), policy(16))?;
    let records = run.import.records();
    assert_eq!(records.len(), planned.len() + 2);
    let refused: Vec<usize> = records
        .iter()
        .enumerate()
        .filter(|(_, r)| matches!(r.disposition, RecordDisposition::StreamRefused(_)))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(refused, vec![at_index, at_index + 1], "{label}");
    for r in &records[at_index..at_index + 2] {
        assert_eq!(
            r.disposition,
            RecordDisposition::StreamRefused(ContinuityError::StreamMismatch)
        );
        assert!(r.discarded.is_none());
    }
    assert!(
        records
            .iter()
            .all(|r| r.generation == 1 && r.ssrc == SSRC_A && r.restart.is_none())
    );
    for (i, r) in records.iter().enumerate().skip(1) {
        if !refused.contains(&i) {
            assert!(
                matches!(r.disposition, RecordDisposition::H264(_)),
                "record {i}: {:?}",
                r.disposition
            );
        }
    }
    // The fragment pending across both foreign packets completes on the next bound record.
    assert!(!records[at_index + 2].nals.is_empty());
    assert!(records[at_index + 2].discarded.is_none());

    let report = &run.report;
    assert_eq!(report.generations().len(), 1);
    let g = &report.generations()[0];
    assert_eq!((g.generation, g.ssrc, g.cause), (1, SSRC_A, None));
    assert!(g.first_picture.is_some());
    assert_eq!(
        report.windows().last().map(|w| w.end_seq),
        Some(ext(planned.len() - 1))
    );
    let foreign_at = at(offset_ms);
    let hit: Vec<&RtpContinuityWindow> = report
        .windows()
        .iter()
        .filter(|w| w.interval.earliest <= foreign_at && foreign_at <= w.interval.latest)
        .collect();
    assert!(!hit.is_empty());
    for w in &hit {
        assert_eq!(w.lost_dimensions, vec![LOST_PACKET_REFUSED.to_owned()]);
        evidence(w)?;
    }
    // One record per variant: the label keeps the three variants' step names distinct.
    caplog(
        &format!("foreign_payload_type_refused_{}", label.replace('-', "_")),
        &format!(
            "{label}|{payload_types:?}|{}|{}",
            kinds_text(report),
            hit.len()
        ),
    );
    Ok(())
}

/// Probe P2 (review mutant G): the packet right before the first picture's first packet (the last
/// SEI fragment, which the picture does not need) is lost. The picture still decodes, but a lost
/// position between the baseline and the first frame keeps the generation from a first frame: it
/// degrades with exactly `first_frame_not_verified` and `packet_loss`, and no window exists.
///
/// Planted negative: ignoring lost positions between the baseline and the first frame (the
/// generation would observe a first frame and only window 0 would degrade).
#[test]
fn loss_between_baseline_and_first_frame_blocks_the_first_frame() -> TestResult {
    let planned = packetize(2, MAX_PAYLOAD, 65_534, SSRC_A, 90_000, 0);
    let v = first_vcl(&planned)?;
    assert!(v >= 3, "need a non-VCL packet after the baseline, v={v}");
    // The dropped packet is not needed for the picture: it ends a non-VCL (SEI) NAL.
    assert_eq!(planned[v - 1].payload[1] & 31, 6);
    let mut kept = planned.clone();
    kept.remove(v - 1);
    let run = run(
        "pre-first-loss",
        &dump_planned(&kept),
        config_for(SSRC_A),
        policy(1_000),
    )?;
    let g = &run.report.generations()[0];
    assert!(g.first_picture.is_none());
    assert_eq!(
        g.pre_first_frame_lost,
        vec![
            LOST_FIRST_FRAME_NOT_VERIFIED.to_owned(),
            LOST_PACKET_LOSS.to_owned()
        ]
    );
    assert!(run.report.windows().is_empty());
    assert_eq!(
        kinds_text(&run.report),
        "requested,authenticated,adapter_accepted,degraded,cancelled"
    );
    caplog(
        "pre_first_frame_loss_blocks",
        &g.pre_first_frame_lost.join("+"),
    );
    Ok(())
}

/// Review mutant F: faults before the first frame keep the generation from a first frame, both a
/// fault on a sequenced packet before it (a reversed recorder offset on the PPS) and an unsequenced
/// fault arriving no later than it (a stray foreign-SSRC packet between the baseline and the first
/// picture). The picture itself is intact in both.
///
/// Planted negatives: (a) not charging pre-first-frame faults (a first frame is observed);
/// (b) dropping the reversed-offset fault (review mutant O, pre-first-frame variant).
#[test]
fn faults_before_the_first_frame_block_it() -> TestResult {
    // Sequenced: the PPS's recorder offset runs backwards.
    let mut planned = packetize(2, MAX_PAYLOAD, 65_534, SSRC_A, 90_000, 100);
    let v = first_vcl(&planned)?;
    let pps = 2;
    assert_eq!(planned[pps].payload[0] & 31, 8);
    assert!(pps < v);
    planned[pps].offset_ms = 50;
    let run1 = run(
        "pre-first-reversed",
        &dump_planned(&planned),
        config_for(SSRC_A),
        policy(1_000),
    )?;
    assert!(run1.import.records()[pps].offset_reversed);
    let g = &run1.report.generations()[0];
    assert!(g.first_picture.is_none());
    assert_eq!(
        g.pre_first_frame_lost,
        vec![
            LOST_FIRST_FRAME_NOT_VERIFIED.to_owned(),
            LOST_TIMING_UNUSABLE.to_owned()
        ]
    );

    // Unsequenced: a stray foreign-SSRC packet right before the first picture, same offset.
    let mut planned = packetize(2, MAX_PAYLOAD, 65_534, SSRC_A, 90_000, 0);
    let mut stray = planned[pps].clone();
    stray.ssrc = SSRC_B;
    stray.seq = 12_345;
    planned.insert(v, stray);
    let run2 = run(
        "pre-first-stray",
        &dump_planned(&planned),
        config_for(SSRC_A),
        policy(1_000),
    )?;
    assert_eq!(
        run2.import.records()[v].disposition,
        RecordDisposition::StreamRefused(ContinuityError::StreamMismatch)
    );
    let g = &run2.report.generations()[0];
    assert!(g.first_picture.is_none());
    assert_eq!(
        g.pre_first_frame_lost,
        vec![
            LOST_FIRST_FRAME_NOT_VERIFIED.to_owned(),
            LOST_PACKET_REFUSED.to_owned()
        ]
    );
    caplog("pre_first_frame_faults_block", &kinds_text(&run2.report));
    Ok(())
}

/// Review mutant O: a reversed recorder offset inside a window degrades exactly that window with
/// `timing_clock_unusable`, charged to the record's own sequence; the window before it verifies.
///
/// Planted negative: ignoring `offset_reversed` (the window would verify).
#[test]
fn reversed_recorder_offset_degrades_its_window() -> TestResult {
    let mut planned = packetize(4, MAX_PAYLOAD, 65_534, SSRC_A, 90_000, 0);
    let v = first_vcl(&planned)?;
    let k = v + 20; // inside the second 16-packet window
    assert!(planned[k - 1].offset_ms > 0);
    planned[k].offset_ms = planned[k - 1].offset_ms - 1;
    let mut p = policy(16);
    p.max_jitter_threshold_ns = 1_000_000_000;
    let run = run("reversed", &dump_planned(&planned), config_for(SSRC_A), p)?;
    let records = run.import.records();
    assert!(records[k].offset_reversed);
    assert_eq!(records.iter().filter(|r| r.offset_reversed).count(), 1);
    let windows = run.report.windows();
    witness(&windows[0])?;
    assert_eq!(
        (windows[1].start_seq, windows[1].end_seq),
        (ext(v + 16), ext(v + 31))
    );
    let ev = evidence(&windows[1])?;
    assert_eq!(ev.lost_dimensions, vec![LOST_TIMING_UNUSABLE.to_owned()]);
    assert_eq!(windows[1].missing_positions, 0);
    caplog("reversed_offset_degrades", &ev.lost_dimensions.join("+"));
    Ok(())
}

/// Review D4: an unsequenced fault (a snaplen-truncated record) is charged by its recorder
/// arrival. It follows the last packet of window 0 (the end of the first picture) but carries the
/// next picture's offset, so it arrives inside window 1 only: window 0 verifies and window 1
/// degrades with exactly `packet_refused`.
///
/// Planted negative: charging unsequenced faults to the window of the highest sequence seen so
/// far (the pre-fix rule: window 0 would degrade instead).
#[test]
fn unsequenced_fault_is_charged_by_arrival() -> TestResult {
    let planned = packetize(4, MAX_PAYLOAD, 65_534, SSRC_A, 90_000, 0);
    let v = first_vcl(&planned)?;
    let end0 = (v..planned.len())
        .find(|&i| planned[i].marker)
        .ok_or("no marker packet")?;
    assert!(planned[end0 + 1].offset_ms > planned[end0].offset_ms);
    let offset = planned[end0 + 1].offset_ms;
    let truncated = rtp_full(0, false, 0, SSRC_A, &[0x09, 0xf0]);
    // Original length one byte longer than captured: a snaplen-truncated record.
    let bytes = dump_with_record(
        &planned,
        end0 + 1,
        &truncated,
        truncated.len() as u16 + 1,
        offset,
    );
    let mut p = policy((end0 - v + 1) as u64);
    p.max_jitter_threshold_ns = 1_000_000_000;
    let run = run("arrival-charge", &bytes, config_for(SSRC_A), p)?;
    assert_eq!(
        run.import.records()[end0 + 1].kind,
        fss_reference::ingest::rtpdump::RtpDumpKind::CapturedPrefix
    );
    let windows = run.report.windows();
    assert_eq!(
        (windows[0].start_seq, windows[0].end_seq),
        (ext(v), ext(end0))
    );
    witness(&windows[0])?;
    assert!(windows[0].interval.latest < at(offset));
    assert!(windows[1].interval.earliest < at(offset) && at(offset) <= windows[1].interval.latest);
    let ev = evidence(&windows[1])?;
    assert_eq!(ev.lost_dimensions, vec![LOST_PACKET_REFUSED.to_owned()]);
    assert_eq!(windows[1].missing_positions, 0);
    caplog(
        "unsequenced_fault_by_arrival",
        &ev.lost_dimensions.join("+"),
    );
    Ok(())
}

/// Probe P4 (review mutant E): an SSRC change where the new generation's first windowed sequence
/// is exactly the old generation's last + 1. Both windows verify, yet a query spanning both
/// generations is refused as outside one run, with that exact variant (the shared stored-witness
/// rule would refuse too, but for a different reason, hiding the mutant).
///
/// Planted negative: treating sequence-contiguous windows of different generations as one run.
#[test]
fn query_across_a_contiguous_generation_boundary_is_outside_one_run() -> TestResult {
    let a = packetize(2, MAX_PAYLOAD, 100, SSRC_A, 90_000, 0);
    let a_end = a.last().ok_or("empty")?.offset_ms;
    let v = first_vcl(&a)?;
    let b_first = (100 + a.len() - v) as u16;
    let b = packetize(2, MAX_PAYLOAD, b_first, SSRC_B, 900_000, a_end + 40);
    let mut planned = a.clone();
    planned.extend(b.iter().cloned());
    let run = run(
        "contiguous-generations",
        &dump_planned(&planned),
        config_for(SSRC_A),
        policy(1_000),
    )?;
    let windows = run.report.windows();
    assert_eq!(windows.len(), 2);
    assert_eq!((windows[0].generation, windows[1].generation), (1, 2));
    assert_eq!(
        windows[0].end_seq + 1,
        windows[1].start_seq,
        "precondition: contiguous"
    );
    witness(&windows[0])?;
    witness(&windows[1])?;
    let across = interval(windows[0].interval.earliest, windows[1].interval.latest)?;
    assert_eq!(
        run.report.absence_over(across),
        RtpAbsenceAnswer::NotCertified(RtpAbsenceRefusal::OutsideVerifiedCoverage)
    );
    caplog("contiguous_generations_outside", &kinds_text(&run.report));
    Ok(())
}

/// Probe P5 (review mutant H): a query inside the generation that starts before the first frame
/// (the pre-first-frame packets arrive 40 ms earlier) and ends inside the verified window, and a
/// query that starts inside the window and ends after it, are both refused as outside verified
/// coverage, with that exact variant. A query inside the window reaches the stored-witness rule.
///
/// Planted negative: dropping the query-bounds check against the verified run.
#[test]
fn query_reaching_outside_the_verified_run_is_outside_coverage() -> TestResult {
    let mut planned = packetize(2, MAX_PAYLOAD, 65_534, SSRC_A, 90_000, 0);
    let v = first_vcl(&planned)?;
    for p in planned.iter_mut().skip(v) {
        p.offset_ms += 40;
    }
    let run = run(
        "query-bounds",
        &dump_planned(&planned),
        config_for(SSRC_A),
        policy(1_000),
    )?;
    let windows = run.report.windows();
    assert_eq!(windows.len(), 1);
    let w = &windows[0];
    witness(w)?;
    assert_eq!(w.interval.earliest, at(40));
    let g = &run.report.generations()[0];
    assert_eq!(g.interval.earliest, at(0));
    let before = interval(at(20), w.interval.latest)?;
    assert_eq!(
        run.report.absence_over(before),
        RtpAbsenceAnswer::NotCertified(RtpAbsenceRefusal::OutsideVerifiedCoverage)
    );
    let after = interval(
        w.interval.earliest,
        TimestampNs(w.interval.latest.0 + 1_000_000),
    )?;
    assert_eq!(
        run.report.absence_over(after),
        RtpAbsenceAnswer::NotCertified(RtpAbsenceRefusal::OutsideVerifiedCoverage)
    );
    assert_eq!(
        run.report.absence_over(w.interval),
        RtpAbsenceAnswer::NotCertified(RtpAbsenceRefusal::StoredWitnessRule(
            ContractError::CoverageUncertified
        ))
    );
    caplog("query_bounds_outside", "outside_verified_coverage");
    Ok(())
}
