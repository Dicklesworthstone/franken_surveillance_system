#![forbid(unsafe_code)]
//! The canonical FIXH264 rtpdump fixture family (clean, loss, reorder, duplicate, ssrc_reset,
//! truncated_last_record, large_gap) through `prepare_rtp_import`: every record's sequence class
//! and delivery is the one the committed fixture manifest predicts, and the access-unit capsules
//! and their `gap_before` fences follow from it (fss-2h5zq.27 review r1 item 6).
//!
//! The committed bytes and `fixture_manifest.json` are first proven identical to the generator,
//! so the generator's packet descriptors ARE the manifest predictions used below.
mod rtpdump_support;
use std::path::PathBuf;

use fss_core::{ContentDigest, SensorId, StreamId, TimestampNs};
use fss_packet::H264Status;
use fss_reference::ingest::rtpdump::import::*;
use fss_reference::ingest::rtpdump::replay::RestartCause;
use fss_reference::media_fixture::{
    H264AnnexBStream, H264FixtureParams, MediaFixtureError, RtpdumpFixture, RtpdumpParams,
    build_rtp_manifest_json, generate_h264_annexb, generate_rtpdump_clean,
    generate_rtpdump_duplicate, generate_rtpdump_large_gap, generate_rtpdump_loss,
    generate_rtpdump_reorder, generate_rtpdump_ssrc_reset, generate_rtpdump_truncated_last_record,
};
use rtpdump_support::*;

type GenFn = fn(&H264AnnexBStream, &RtpdumpParams) -> Result<RtpdumpFixture, MediaFixtureError>;
use AccessUnitEnd::{Fence, InputEnd, Marker};

/// What the manifest implies for one variant through the import.
struct Expect {
    name: &'static str,
    generate: GenFn,
    /// Records whose own `gap_before` fence is set: every probation record (no admitted
    /// predecessor), the first delivered packet after a missing sequence (`missing_sequences`, or
    /// the reorder variant's late seq 0), a discontinuity suspicion and each restart record.
    gapped_records: &'static [usize],
    /// Records the replay deliberately classifies differently from the bare kernel prediction:
    /// at the first `RestartRequired` prediction the replay opens generation + 1 and re-observes
    /// the packet there (review r1 item 1), so the following packets start a fresh epoch.
    reclassified: &'static [(usize, &'static str, bool)],
    /// `(record, cause)` of every new stream generation.
    restarts: &'static [(usize, RestartCause)],
    /// `(NAL count, closure, gap_before, generation)` of each access unit capsule.
    units: &'static [(usize, AccessUnitEnd, bool, u64)],
    /// Clean container EOF (false only for the truncated final record).
    clean_end: bool,
}

const EXPECT: [Expect; 7] = [
    // AU0 at 90000: AUD SPS PPS SEI IDR(FU-A) IDR(single, marker); then four [AUD, P] units.
    Expect {
        name: "clean.rtp",
        generate: generate_rtpdump_clean,
        gapped_records: &[0],
        reclassified: &[],
        restarts: &[],
        units: &[
            (6, Marker, true, 1),
            (2, Marker, false, 1),
            (2, Marker, false, 1),
            (2, Marker, false, 1),
            (2, Marker, false, 1),
        ],
        clean_end: true,
    },
    // seq 1 (SEI) missing: the FU-A start (record 3) is fenced, cutting AU0 after PPS; the IDR
    // pair starts a new, fenced unit at the same RTP timestamp.
    Expect {
        name: "loss.rtp",
        generate: generate_rtpdump_loss,
        gapped_records: &[0, 3],
        reclassified: &[],
        restarts: &[],
        units: &[
            (3, Fence, true, 1),
            (2, Marker, true, 1),
            (2, Marker, false, 1),
            (2, Marker, false, 1),
            (2, Marker, false, 1),
            (2, Marker, false, 1),
        ],
        clean_end: true,
    },
    // seq 1 arrives before seq 0: SEI is fenced (seq 0 missing at that time), the late STAP-A is
    // Reordered and ignored (not delivered, not a fence), so SPS/PPS never become NALs.
    Expect {
        name: "reorder.rtp",
        generate: generate_rtpdump_reorder,
        gapped_records: &[0, 2],
        reclassified: &[],
        restarts: &[],
        units: &[
            (1, Fence, true, 1),
            (3, Marker, true, 1),
            (2, Marker, false, 1),
            (2, Marker, false, 1),
            (2, Marker, false, 1),
            (2, Marker, false, 1),
        ],
        clean_end: true,
    },
    // A duplicate is neither delivered nor a fence: grouping equals the clean variant.
    Expect {
        name: "duplicate.rtp",
        generate: generate_rtpdump_duplicate,
        gapped_records: &[0],
        reclassified: &[],
        restarts: &[],
        units: &[
            (6, Marker, true, 1),
            (2, Marker, false, 1),
            (2, Marker, false, 1),
            (2, Marker, false, 1),
            (2, Marker, false, 1),
        ],
        clean_end: true,
    },
    // Generation 1 delivers AUD SPS PPS SEI without a marker; the SSRC change opens generation 2
    // (record 4, its probation packet), fencing the open unit; [AUD, IDR] is a fenced gen-2 unit.
    Expect {
        name: "ssrc_reset.rtp",
        generate: generate_rtpdump_ssrc_reset,
        gapped_records: &[0, 4],
        reclassified: &[],
        restarts: &[(4, RestartCause::SsrcChange)],
        units: &[(4, Fence, true, 1), (2, Marker, true, 2)],
        clean_end: true,
    },
    // The final record (seq 12, P slice) is cut inside its header: the last unit holds only the
    // AUD and closes at input end; the container end is a framing refusal, not EOF.
    Expect {
        name: "truncated_last_record.rtp",
        generate: generate_rtpdump_truncated_last_record,
        gapped_records: &[0],
        reclassified: &[],
        restarts: &[],
        units: &[
            (6, Marker, true, 1),
            (2, Marker, false, 1),
            (2, Marker, false, 1),
            (2, Marker, false, 1),
            (1, InputEnd, false, 1),
        ],
        clean_end: false,
    },
    // seq 3501: DiscontinuitySuspected (not delivered, fences AU0); 3502: the kernel's
    // RestartRequired opens generation 2, where it is re-observed as Probation; 3503 is then
    // that epoch's Baseline and is delivered as a fenced gen-2 unit closed at input end.
    Expect {
        name: "large_gap.rtp",
        generate: generate_rtpdump_large_gap,
        gapped_records: &[0, 4, 5],
        reclassified: &[(5, "Probation", false), (6, "Baseline", true)],
        restarts: &[(5, RestartCause::SequenceRestart)],
        units: &[(4, Fence, true, 1), (1, InputEnd, true, 2)],
        clean_end: true,
    },
];

fn repo_root() -> Result<PathBuf, Error> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .ok_or_else(|| "missing repository root".into())
}

fn fixtures() -> Result<Vec<RtpdumpFixture>, Error> {
    let annexb = generate_h264_annexb(&H264FixtureParams::default())?;
    let params = RtpdumpParams::default();
    let dir = repo_root()?.join("tests/fixtures/media/rtp");
    let mut out = Vec::new();
    for e in &EXPECT {
        let f = (e.generate)(&annexb, &params)?;
        assert_eq!(f.filename, e.name);
        assert_eq!(
            std::fs::read(dir.join(e.name))?,
            f.bytes,
            "{} on disk",
            e.name
        );
        out.push(f);
    }
    let manifest = std::fs::read_to_string(dir.join("fixture_manifest.json"))?;
    assert_eq!(
        manifest,
        build_rtp_manifest_json(&out, &params),
        "committed manifest is the generator's predictions"
    );
    Ok(out)
}

fn scope() -> Result<RtpImportScope, Error> {
    Ok(RtpImportScope {
        sensor: SensorId::parse("sensor:rtp-fixh264")?,
        stream: StreamId::parse("stream:rtp-fixh264")?,
        receive_time: TimestampNs(3_000_000_000),
    })
}

/// Every FIXH264 variant's records are classified, delivered, fenced and restarted exactly as the
/// manifest predicts, and its access-unit capsules (counts, closures, `gap_before`, generations)
/// follow; the whole original file is retained and every capsule binds its exact source bytes.
///
/// Planted negatives: (a) a replay that refuses the second SSRC instead of restarting
/// (ssrc_reset gen-2 classes and unit fail); (b) capsules that ignore a sequence gap (loss
/// `gap_before` / Fence unit fails); (c) treating a duplicate or a late reordered packet as a
/// fence (duplicate / reorder units fail); (d) per-NAL capsules (unit counts fail); (e) a
/// truncated tail relabelled as clean EOF.
#[test]
fn fixh264_rtpdump_variants_match_their_manifest_predictions() -> TestResult {
    let cx = cx()?;
    let fixtures = fixtures()?;
    for (e, f) in EXPECT.iter().zip(&fixtures) {
        let name = e.name;
        let plan = prepare_rtp_import(
            &f.bytes,
            scope()?,
            config_for(RtpdumpParams::default().ssrc),
            RtpImportLimits::default(),
            &cx,
        )?;
        let report = plan.report();
        assert_eq!(report.input_bytes(), f.bytes.len(), "{name}");
        assert_eq!(report.input_digest(), ContentDigest::sha256(&f.bytes));
        assert_eq!(report.records().len(), f.packets.len(), "{name} records");
        assert_eq!(
            matches!(report.end(), ImportEnd::Ended),
            e.clean_end,
            "{name}"
        );
        assert_eq!(f.is_truncated, !e.clean_end, "{name}");
        // No fragment is interrupted anywhere in the family: nothing is retired.
        assert!(report.final_discard().is_none(), "{name}");
        for (i, (record, d)) in report.records().iter().zip(&f.packets).enumerate() {
            assert_eq!(record.ssrc, d.ssrc, "{name} record {i} ssrc");
            assert_eq!(record.timestamp, Some(d.timestamp), "{name} record {i}");
            assert_eq!(record.source.len(), d.packet_len + 8, "{name} record {i}");
            let (class, delivered) = e.reclassified.iter().find(|(r, ..)| *r == i).map_or(
                (d.expected_sequence_class.as_str(), d.expected_delivered),
                |r| (r.1, r.2),
            );
            let observed = record
                .sequence
                .map(|o| format!("{:?}", o.class))
                .ok_or(format!("{name} record {i} has no sequence observation"))?;
            assert_eq!(observed, class, "{name} record {i} class");
            let pushed = matches!(
                record.disposition,
                RecordDisposition::H264(H264Status::Complete | H264Status::FragmentPending)
            );
            assert_eq!(pushed, delivered, "{name} record {i} delivery");
            assert_eq!(
                record.gap_before,
                e.gapped_records.contains(&i),
                "{name} record {i} gap_before"
            );
            let restart = e.restarts.iter().find(|(r, _)| *r == i).map(|r| r.1);
            assert_eq!(record.restart, restart, "{name} record {i} restart");
            assert!(record.expired.is_none() && record.discarded.is_none());
        }
        let units: Vec<(usize, AccessUnitEnd, bool, u64)> = report
            .access_units()
            .iter()
            .map(|u| (u.nals.len(), u.end, u.capsule.gap_before, u.generation))
            .collect();
        assert_eq!(units, e.units, "{name} access units");
        for u in report.access_units() {
            assert_eq!(
                u.capsule.source_digest,
                ContentDigest::sha256(&f.bytes[u.source.clone()])
            );
            assert_eq!(u.capsule.frame_count, 0);
            assert!(
                report.nals()[u.nals.clone()]
                    .iter()
                    .all(|n| n.timestamp == u.timestamp)
            );
        }
    }
    Ok(())
}

/// The loss variant's missing sequence is retained as accounting, and the duplicate's second
/// copy stays inside the unit's retained envelope rather than being cropped out.
///
/// Planted negatives: (a) dropping the missing-sequence count; (b) a capsule envelope that skips
/// the intervening duplicate record.
#[test]
fn loss_accounting_and_duplicate_envelopes_are_retained() -> TestResult {
    let cx = cx()?;
    let fixtures = fixtures()?;
    let ssrc = RtpdumpParams::default().ssrc;
    let loss = &fixtures[1];
    assert_eq!(loss.missing_sequences, [1]);
    let plan = prepare_rtp_import(
        &loss.bytes,
        scope()?,
        config_for(ssrc),
        RtpImportLimits::default(),
        &cx,
    )?;
    assert_eq!(
        plan.report().stats().missing,
        loss.missing_sequences.len() as u64
    );
    let dup = &fixtures[3];
    let plan = prepare_rtp_import(
        &dup.bytes,
        scope()?,
        config_for(ssrc),
        RtpImportLimits::default(),
        &cx,
    )?;
    let report = plan.report();
    let duplicate = report
        .records()
        .iter()
        .position(|r| {
            r.sequence
                .is_some_and(|o| format!("{:?}", o.class) == "Duplicate")
        })
        .ok_or("duplicate record")?;
    let unit = &report.access_units()[0];
    let span = &report.records()[duplicate].source;
    assert!(unit.source.start <= span.start && span.end <= unit.source.end);
    Ok(())
}
