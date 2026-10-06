#![forbid(unsafe_code)]
//! Recorded-RTP capsules are per access unit (RTP timestamp + marker grouping), each bound to the
//! exact original record bytes that carried its NALs (fss-2h5zq.27 review r1 item 3).
mod rtpdump_support;
use fss_core::{ContentDigest, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::rtpdump::import::*;
use rtpdump_support::*;

const SSRC: u32 = 7;
/// Forces FU-A for the 595..2591-byte slices of the fixture while SPS/PPS stay single-NAL.
const MAX_PAYLOAD: usize = 300;

fn scope() -> Result<RtpImportScope, Error> {
    Ok(RtpImportScope {
        sensor: SensorId::parse("sensor:rtp-au")?,
        stream: StreamId::parse("stream:rtp-au")?,
        receive_time: TimestampNs(5_000_000_000),
    })
}

fn prepare(bytes: &[u8]) -> Result<RtpImportReport, Error> {
    let cx = cx()?;
    let plan = prepare_rtp_import(
        bytes,
        scope()?,
        config_for(SSRC),
        RtpImportLimits::default(),
        &cx,
    )?;
    Ok(plan.report().clone())
}

/// Every unit's NALs are contiguous, cover all NALs exactly once, share generation and
/// timestamp, point back at their unit, and its capsule binds exactly the original record
/// envelopes from its first to its last carrying record.
fn assert_exact_custody(report: &RtpImportReport, bytes: &[u8]) -> Result<(), Error> {
    let mut next = 0;
    for (index, unit) in report.access_units().iter().enumerate() {
        assert_eq!(unit.nals.start, next, "units must tile the NAL list");
        assert!(
            unit.nals.end > unit.nals.start,
            "a unit holds at least one NAL"
        );
        next = unit.nals.end;
        let nals = &report.nals()[unit.nals.clone()];
        let mut first_record = usize::MAX;
        let mut last_record = 0;
        for nal in nals {
            assert_eq!(nal.access_unit, index);
            assert_eq!(nal.timestamp, unit.timestamp);
            for span in &nal.spans {
                assert_eq!(report.records()[span.record].generation, unit.generation);
                first_record = first_record.min(span.record);
                last_record = last_record.max(span.record);
            }
        }
        let expected =
            report.records()[first_record].source.start..report.records()[last_record].source.end;
        assert_eq!(unit.source, expected);
        assert_eq!(
            unit.capsule.source_digest,
            ContentDigest::sha256(&bytes[unit.source.clone()])
        );
        assert_eq!(unit.capsule.frame_count, 0);
        assert_eq!(unit.capsule.sequence, index as u64);
        assert_eq!(unit.capsule.clock_basis, fss_core::ClockBasis::Estimated);
    }
    assert_eq!(next, report.nals().len());
    Ok(())
}

/// One recorded copy of the fixture (SPS PPS SEI IDR | P | P | SPS PPS IDR) with per-picture RTP
/// timestamps and the marker on each picture's final packet yields exactly four access units,
/// each closed by its marker, with NAL counts 4, 1, 1, 3.
///
/// Planted negatives: (a) per-NAL capsules (the pre-fix behavior: nine capsules); (b) grouping
/// that ignores the marker and the timestamp (one capsule).
#[test]
fn marker_and_timestamp_group_nals_into_access_unit_capsules() -> TestResult {
    let planned = packetize(1, MAX_PAYLOAD, 65_534, SSRC, 90_000, 0);
    let bytes = dump_planned(&planned);
    let report = prepare(&bytes)?;
    assert_eq!(report.nals().len(), nals().len());
    let sizes: Vec<usize> = report.access_units().iter().map(|u| u.nals.len()).collect();
    assert_eq!(sizes, [4, 1, 1, 3]);
    assert!(
        report
            .access_units()
            .iter()
            .all(|u| u.end == AccessUnitEnd::Marker)
    );
    let stamps: Vec<u32> = report.access_units().iter().map(|u| u.timestamp).collect();
    assert_eq!(stamps, [90_000, 93_600, 97_200, 100_800]);
    // Only the file entry is fenced; nothing else in a clean recording is.
    let gaps: Vec<bool> = report
        .access_units()
        .iter()
        .map(|u| u.capsule.gap_before)
        .collect();
    assert_eq!(gaps, [true, false, false, false]);
    assert_exact_custody(&report, &bytes)?;
    Ok(())
}

/// Without any marker bit, a unit is closed by the next NAL's different RTP timestamp, and the
/// last one by input end; the closure reason says the sender's own end claim was absent.
///
/// Planted negative: marker-only grouping (one unit holding all nine NALs).
#[test]
fn timestamp_change_closes_a_unit_whose_marker_is_absent() -> TestResult {
    let mut planned = packetize(1, MAX_PAYLOAD, 65_534, SSRC, 90_000, 0);
    for p in &mut planned {
        p.marker = false;
    }
    let bytes = dump_planned(&planned);
    let report = prepare(&bytes)?;
    let ends: Vec<AccessUnitEnd> = report.access_units().iter().map(|u| u.end).collect();
    assert_eq!(
        ends,
        [
            AccessUnitEnd::TimestampChange,
            AccessUnitEnd::TimestampChange,
            AccessUnitEnd::TimestampChange,
            AccessUnitEnd::InputEnd,
        ]
    );
    let sizes: Vec<usize> = report.access_units().iter().map(|u| u.nals.len()).collect();
    assert_eq!(sizes, [4, 1, 1, 3]);
    assert_exact_custody(&report, &bytes)?;
    Ok(())
}

/// A lost packet inside a picture (the PPS of the second IDR picture) fences the unit: the NALs
/// before the loss close as a `Fence` unit, and the IDR after it starts a new unit whose capsule
/// carries `gap_before`, although both share one RTP timestamp. NALs never join a unit across a
/// continuity fence.
///
/// Planted negatives: (a) ignoring the fence (one unit [SPS, IDR] without `gap_before`); (b)
/// dropping `gap_before` on the post-loss capsule.
#[test]
fn a_continuity_fence_splits_a_unit_and_fences_the_next_capsule() -> TestResult {
    let mut planned = packetize(1, MAX_PAYLOAD, 65_534, SSRC, 90_000, 0);
    // Second SPS is the first NAL of picture 3; the PPS right after it is lost.
    let second_sps = planned
        .iter()
        .enumerate()
        .filter(|(_, p)| p.payload.first().is_some_and(|h| h & 31 == 7))
        .map(|(i, _)| i)
        .nth(1)
        .ok_or("fixture has two SPS packets")?;
    assert_eq!(planned[second_sps + 1].payload[0] & 31, 8);
    planned.remove(second_sps + 1);
    let bytes = dump_planned(&planned);
    let report = prepare(&bytes)?;
    let units = report.access_units();
    let sizes: Vec<usize> = units.iter().map(|u| u.nals.len()).collect();
    assert_eq!(sizes, [4, 1, 1, 1, 1]);
    assert_eq!(units[3].end, AccessUnitEnd::Fence);
    assert_eq!(units[3].timestamp, units[4].timestamp);
    assert!(!units[3].capsule.gap_before);
    assert!(units[4].capsule.gap_before);
    assert_eq!(units[4].end, AccessUnitEnd::Marker);
    assert_eq!(report.nals()[units[3].nals.start].timestamp, 100_800);
    assert_exact_custody(&report, &bytes)?;
    Ok(())
}

/// Capsule identities and ledger staging are per unit: the manifest holds each NAL digest plus
/// one source envelope and one capsule object per unit (plus the report metadata), and capsule
/// ids count units.
///
/// Planted negative: per-NAL capsule objects (nine capsule objects in the manifest, ids up to
/// `:000008`).
#[test]
fn manifest_and_capsule_ids_are_per_access_unit() -> TestResult {
    let cx = cx()?;
    let planned = packetize(1, MAX_PAYLOAD, 65_534, SSRC, 90_000, 0);
    let bytes = dump_planned(&planned);
    let plan = prepare_rtp_import(
        &bytes,
        scope()?,
        config_for(SSRC),
        RtpImportLimits::default(),
        &cx,
    )?;
    let report = plan.report();
    let ids: Vec<&str> = report
        .access_units()
        .iter()
        .map(|u| u.capsule.capsule_id.as_str())
        .collect();
    assert_eq!(ids.len(), 4);
    for (i, id) in ids.iter().enumerate() {
        assert!(id.ends_with(&format!(":{i:06}")), "{id}");
    }
    let children = plan.manifest().children();
    for unit in report.access_units() {
        assert!(children.contains(&unit.capsule_object));
        assert!(children.contains(&unit.capsule.source_digest));
    }
    let mut expected: Vec<ContentDigest> = report
        .chunk_digests()
        .iter()
        .copied()
        .chain(report.nals().iter().map(|n| n.digest))
        .chain(
            report
                .access_units()
                .iter()
                .flat_map(|u| [u.capsule.source_digest, u.capsule_object]),
        )
        .collect();
    // The object manifest also lists its metadata (the canonical report) as a child.
    expected.push(ContentDigest::sha256(plan.report_bytes()));
    expected.sort_unstable();
    expected.dedup();
    assert_eq!(children, expected.as_slice());
    Ok(())
}
