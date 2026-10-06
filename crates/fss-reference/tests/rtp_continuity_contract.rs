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
    AcquisitionStateKind, CaptureInterval, ContractError, CoverageContinuity, EventId,
    EventReadResult, EventRevisionStore, LedgerAnchor, SensorId, SourceId, StreamId, TimestampNs,
};
use fss_core::{DeviceId, SensorCapsule};
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

fn caplog(step: &str, observed: &str) {
    println!(
        "CAPLOG {{\"bead\":\"fss-2h5zq.30\",\"step\":\"{step}\",\"verdict\":\"pass\",\"observed\":\"{observed}\"}}"
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
/// (d) omitting the session `verify_continuity` call (state-kind assertion).
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
    assert!(w.coverage_witness.certifies_absence());
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
/// which refuses the recorded capsules' estimated clock; later clean windows are refused
/// re-verification by the core; the first capsule after the gap has `gap_before`.
///
/// Planted negatives: (a) counting a lost position as observed (`observed_packet_loss`);
/// (b) evaluating only the first overlapping window (spanning query); (c) certifying from the
/// session alone without the stored rule (clean query answer); (d) re-verifying across the gap
/// (later windows); (e) the importer clearing `gap_before` after a loss.
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
    // Later clean windows: the core refuses to re-verify across the gap.
    let later = &windows[gap_index + 1..];
    assert!(!later.is_empty());
    assert!(
        later
            .iter()
            .all(|w| !matches!(w.outcome, RtpWindowOutcome::Verified { .. }))
    );
    assert!(later.iter().any(|w| matches!(
        &w.outcome,
        RtpWindowOutcome::CleanNotVerified { refusal } if refusal.contains("sequence gap")
    )));
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
            "{}|{}|{}",
            kinds_text(report),
            ev.evidence_digest(),
            gap.lost_dimensions.join("+")
        ),
    );
    Ok(())
}

/// fss-3qlsa regression: the verified window's certifying coverage witness and the gap window's
/// gapped witness are registered in both orders in the core event store; an absence read over the
/// source domain is never certified, while the certifying witness alone does certify (so the
/// refusal is the gap's doing).
///
/// Planted negatives: (a) the gap window carrying a continuous coverage witness; (b) the store
/// evaluating only the first registered witness (certifying-first order).
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
    let mut alone = EventRevisionStore::new(LedgerAnchor::genesis("site:rtp-store"));
    alone.register_coverage_witness(
        alone.current_anchor().clone(),
        verified.coverage.clone(),
        TimestampNs(1),
    )?;
    assert!(matches!(
        alone.read_event_in_domain(&absent, domain.as_str(), None)?,
        EventReadResult::AbsentWithCoverage(_)
    ));
    for order in [[verified, gap], [gap, verified]] {
        let mut store = EventRevisionStore::new(LedgerAnchor::genesis("site:rtp-store"));
        for (i, window) in order.iter().enumerate() {
            store.register_coverage_witness(
                store.current_anchor().clone(),
                window.coverage.clone(),
                TimestampNs(1 + i as i128),
            )?;
        }
        match store.read_event_in_domain(&absent, domain.as_str(), None)? {
            EventReadResult::NotObservable { .. } => {}
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
/// Planted negatives: (a) the replay refusing the new SSRC (no second generation); (b) reusing the
/// generation (`stream_generation` ordering); (c) the importer not fencing the restart
/// (`gap_before`); (d) an absence run spanning the generation boundary.
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
/// the next clean window is refused re-verification by the core (its witness chain must start
/// right after the last verified window), and absence over it is not certified.
///
/// Planted negatives: (a) not comparing jitter against the threshold (window verified);
/// (b) overriding the core refusal (next window verified).
#[test]
fn jitter_step_degrades_and_the_core_refuses_reverification() -> TestResult {
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
    match &windows[3].outcome {
        RtpWindowOutcome::CleanNotVerified { refusal } => assert!(refusal.contains("sequence gap")),
        other => return Err(format!("expected a core refusal, got {other:?}").into()),
    }
    assert!(windows[3].lost_dimensions.is_empty());
    assert!(matches!(
        run.report.absence_over(windows[3].interval),
        RtpAbsenceAnswer::NotCertified(_)
    ));
    caplog(
        "jitter_degraded_not_reverified",
        &ev.lost_dimensions.join("+"),
    );
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
