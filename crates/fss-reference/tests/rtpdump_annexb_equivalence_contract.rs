#![forbid(unsafe_code)]
//! AC1 of fss-2h5zq.27: the recorded-RTP import reproduces the Annex-B NAL bytes exactly.
//!
//! The FIXH264 clean rtpdump is packetized from the canonical Annex-B fixture; importing it through
//! `prepare_rtp_import` must yield the same NAL sequence byte for byte, and every NAL's source span
//! must stay inside its access unit's custody envelope. Planted negatives: a depacketizer that
//! drops or reorders a NAL, or an access-unit envelope cropped short of its NALs.
mod rtpdump_support;
use fss_core::{ContentDigest, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::rtpdump::import::*;
use fss_reference::media_fixture::{
    H264FixtureParams, RtpdumpParams, generate_h264_annexb, generate_rtpdump_clean,
};
use rtpdump_support::*;

#[test]
fn clean_rtp_import_nals_equal_the_annexb_fixture_nals() -> TestResult {
    let cx = cx()?;
    let annexb = generate_h264_annexb(&H264FixtureParams::default())?;
    let committed = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/media/h264/clean.264"),
    )?;
    assert_eq!(
        committed, annexb.bytes,
        "generator must equal the committed clean.264"
    );
    let params = RtpdumpParams::default();
    let clean = generate_rtpdump_clean(&annexb, &params)?;
    let plan = prepare_rtp_import(
        &clean.bytes,
        RtpImportScope {
            sensor: SensorId::parse("sensor:annexb-equivalence")?,
            stream: StreamId::parse("stream:annexb-equivalence")?,
            receive_time: TimestampNs(3_000_000_000),
        },
        config_for(params.ssrc),
        RtpImportLimits::default(),
        &cx,
    )?;
    let imported: Vec<ContentDigest> = plan.report().nals().iter().map(|n| n.digest).collect();
    let expected: Vec<ContentDigest> = annexb
        .nals
        .iter()
        .map(|n| ContentDigest::sha256(&n.wire_bytes))
        .collect();
    assert!(!expected.is_empty());
    assert_eq!(imported, expected);
    for unit in plan.report().access_units() {
        let nals = plan
            .report()
            .nals()
            .get(unit.nals.clone())
            .ok_or("access unit names NALs outside the report")?;
        assert!(!nals.is_empty());
        for nal in nals {
            assert!(unit.source.start <= nal.source.start && nal.source.end <= unit.source.end);
        }
    }
    Ok(())
}
