#![forbid(unsafe_code)]
//! Source-preserving GOP segmentation and failure ownership contracts.

use fss_container::{
    demux::{AvcMp4, DemuxLimits},
    flv_avc::SourceKey,
};
use fss_packet::extended_flv::{
    Limits as FlvLimits,
    stream::{Framer, Next, SourceRecord},
};
use fss_reference::unifi_direct::recording::{Error, Limits, Push, Recorder, SourceDisposition};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const BASELINE: &[u8] = include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264");
const KEY: SourceKey = SourceKey {
    connection: 7,
    generation: 1,
};

fn tag(kind: u8, timestamp: u32, payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut out = vec![
        kind,
        (n >> 16) as u8,
        (n >> 8) as u8,
        n as u8,
        (timestamp >> 16) as u8,
        (timestamp >> 8) as u8,
        timestamp as u8,
        (timestamp >> 24) as u8,
        0,
        0,
        0,
    ];
    out.extend_from_slice(payload);
    out.extend_from_slice(&(11_u32 + n as u32).to_be_bytes());
    out
}

fn fixture(
    start: u32,
    preroll: bool,
    duplicate_idr: bool,
) -> Result<(Vec<u8>, Vec<SourceRecord>), Box<dyn std::error::Error>> {
    fixture_with_variable_intervals(start, preroll, duplicate_idr, false)
}

fn fixture_with_variable_intervals(
    start: u32,
    preroll: bool,
    duplicate_idr: bool,
    variable: bool,
) -> Result<(Vec<u8>, Vec<SourceRecord>), Box<dyn std::error::Error>> {
    fixture_with_audio_intervals(start, preroll, duplicate_idr, variable, None)
}

fn fixture_with_audio_intervals(
    start: u32,
    preroll: bool,
    duplicate_idr: bool,
    variable: bool,
    audio_step: Option<u32>,
) -> Result<(Vec<u8>, Vec<SourceRecord>), Box<dyn std::error::Error>> {
    fixture_with_policy(start, preroll, duplicate_idr, variable, audio_step, false)
}

fn fixture_with_policy(
    start: u32,
    preroll: bool,
    duplicate_idr: bool,
    variable: bool,
    audio_step: Option<u32>,
    av_flag: bool,
) -> Result<(Vec<u8>, Vec<SourceRecord>), Box<dyn std::error::Error>> {
    let nals: Vec<_> = fss_codec_h264::annex_b_nal_units(BASELINE).collect();
    let sps = nals.iter().copied().find(|n| n[0] & 31 == 7).ok_or("SPS")?;
    let pps = nals.iter().copied().find(|n| n[0] & 31 == 8).ok_or("PPS")?;
    let vcl: Vec<_> = nals
        .into_iter()
        .filter(|n| matches!(n[0] & 31, 1 | 5))
        .collect();
    if vcl.len() != 4 || vcl[0][0] & 31 != 5 {
        return Err("unexpected baseline fixture".into());
    }
    let mut config = vec![0x17, 0, 0, 0, 0, 1, sps[1], sps[2], sps[3], 0xff, 0xe1];
    config.extend_from_slice(&u16::try_from(sps.len())?.to_be_bytes());
    config.extend_from_slice(sps);
    config.push(1);
    config.extend_from_slice(&u16::try_from(pps.len())?.to_be_bytes());
    config.extend_from_slice(pps);
    let mut wire = b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
    wire.extend(tag(9, 0, &config));
    let count = if duplicate_idr { 2 } else { 7 };
    for i in 0..count {
        let offset = if variable {
            (i as u32 * 100) / 3
        } else {
            i as u32 * 40
        };
        let timestamp = start.wrapping_add(offset);
        if av_flag {
            let mut trailer = [0; 16];
            trailer[11] = 1;
            wire.extend(trailer);
        } else {
            wire.extend([0x77; 3]);
        }
        let audio_timestamp = audio_step
            .map(|step| start.wrapping_add(i as u32 * step))
            .unwrap_or(timestamp);
        wire.extend(tag(8, audio_timestamp, &[0xaf, 1, 2]));
        let nal = if duplicate_idr {
            vcl[0]
        } else if preroll && i == 0 {
            vcl[1]
        } else {
            vcl[(i - usize::from(preroll)) % 3]
        };
        let mut payload = vec![0x17, 1, 0, 0, 0];
        payload.extend_from_slice(&u32::try_from(nal.len())?.to_be_bytes());
        payload.extend_from_slice(nal);
        if av_flag {
            wire.extend([0; 16]);
        } else {
            wire.extend([0x77; 2]);
        }
        wire.extend(tag(9, timestamp, &payload));
    }
    let mode = if av_flag {
        fss_packet::extended_flv::stream::SearchMode::StructuredTrailer16AvFlag
    } else {
        fss_packet::extended_flv::stream::SearchMode::Conservative
    };
    let mut framer = Framer::with_mode(FlvLimits::default(), 1024 * 1024, mode)?;
    framer.append(0, &wire)?;
    let mut records = Vec::new();
    while let Next::Record(record) = framer.take()? {
        records.push(record);
    }
    Ok((wire, records))
}

#[test]
fn direct_flv_recording_retains_variable_camera_shaped_intervals() -> TestResult {
    // Independent synthetic NAL data with 33/34 ms intervals, motivated by
    // the live G4 relay's observed 2,970/3,060 tick RTP spacings. This is not
    // a retained physical camera stream or evidence of a direct handshake.
    let (wire, records) = fixture_with_variable_intervals(u32::MAX - 50, false, false, true)?;
    let mut recorder = Recorder::new(KEY, Limits::default())?;
    let audio_bytes = [0x14, 0x08];
    let audio = fss_packet::extended_flv::aac::Configuration::parse_explicit(&audio_bytes)?;
    assert!(recorder.av_initialization(&audio)?.is_none());
    let mut durations = Vec::new();
    let mut original = Vec::new();
    let mut initialization = None;
    let mut segments = 0;
    for record in records {
        match recorder.push(record).map_err(|r| r.reason)? {
            Push::Source {
                record,
                disposition,
            } => {
                if disposition == SourceDisposition::Configuration {
                    initialization =
                        Some(recorder.initialization().ok_or("init")?.bytes().to_vec());
                    let av = recorder.av_initialization(&audio)?.ok_or("A/V init")?;
                    assert_eq!(&av.bytes()[av.audio_configuration_range()], &audio_bytes);
                    assert_ne!(av.bytes(), recorder.initialization().ok_or("init")?.bytes());
                }
                original.extend_from_slice(record.bytes());
            }
            Push::Buffered => {}
            Push::Segment(segment) => {
                durations.extend(segment.fragment().samples().iter().map(|s| s.duration_ms));
                for source in segment.source() {
                    original.extend_from_slice(source.bytes());
                }
                let mut mp4 = initialization.as_ref().ok_or("init")?.clone();
                mp4.extend_from_slice(segment.fragment().bytes());
                let movie = AvcMp4::parse(&mp4, None, DemuxLimits::default())?;
                let raw = movie.annex_b(0, 3)?;
                let mut decoder =
                    fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
                let mut frames = decoder.decode_annex_b(raw.bytes())?;
                frames.extend(decoder.finish()?);
                assert_eq!(frames.len(), 3);
                segments += 1;
            }
        }
    }
    for source in recorder.retire().pending {
        original.extend_from_slice(source.bytes());
    }
    assert_eq!(segments, 2);
    assert_eq!(durations, [33, 33, 34, 33, 33, 34]);
    assert_eq!(original, wire);
    Ok(())
}

#[test]
fn av_owner_preserves_segment_source_and_rolls_back_failed_clock_attempts() -> TestResult {
    use fss_container::{Mp4Error, Mp4Limits};
    use fss_packet::extended_flv::{aac, aac_clock};
    use fss_reference::unifi_direct::av_recording;

    // Deliberately synthetic: 40 ms video and 64 ms AAC timestamps exercise
    // independent clocks without claiming these samples are synchronized.
    let (wire, records) = fixture_with_audio_intervals(0, false, false, false, Some(64))?;
    let bytes = [0x14, 0x08];
    let config = aac::Configuration::parse_explicit(&bytes)?;
    let mut recorder = Recorder::new(KEY, Limits::default())?;
    let mut initialization = None;
    let mut segments = Vec::new();
    for record in records {
        match recorder.push(record).map_err(|refusal| refusal.reason)? {
            Push::Source {
                disposition: SourceDisposition::Configuration,
                ..
            } => initialization = recorder.av_initialization(&config)?,
            Push::Segment(segment) => segments.push(segment),
            _ => {}
        }
    }
    assert_eq!(segments.len(), 2);
    let init = initialization.ok_or("missing initialization")?;
    let limits = Mp4Limits::default();
    let mut too_small = av_recording::Muxer::new(&init, &config, 0, 0, 8, 1, limits)?;
    assert!(matches!(
        too_small.fragment(&init, &segments[0]),
        Err(av_recording::Error::Limit)
    ));
    let mut muxer = av_recording::Muxer::new(&init, &config, 0, 0, 8, 8, limits)?;
    let first = muxer.fragment(&init, &segments[0])?;
    assert_eq!(first.audio().len(), 2);
    let mut video_clip = recorder
        .initialization()
        .ok_or("video init")?
        .bytes()
        .to_vec();
    video_clip.extend_from_slice(segments[0].fragment().bytes());
    fss_container::flv_av::verify_archived_initialization(
        &video_clip,
        init.bytes(),
        &config,
        limits,
    )?;
    fss_container::flv_av::verify_archived_fragment(
        segments[0].fragment().bytes(),
        first.bytes(),
        first.audio(),
        limits,
    )?;
    let mut wrong_init = init.bytes().to_vec();
    wrong_init[init.audio_configuration_range().start] ^= 1;
    assert!(
        fss_container::flv_av::verify_archived_initialization(
            &video_clip,
            &wrong_init,
            &config,
            limits
        )
        .is_err()
    );
    let mut wrong_table = first.bytes().to_vec();
    let old_moof = u32::from_be_bytes(segments[0].fragment().bytes()[0..4].try_into()?) as usize;
    wrong_table[old_moof + 67] ^= 1;
    assert!(
        fss_container::flv_av::verify_archived_fragment(
            segments[0].fragment().bytes(),
            &wrong_table,
            first.audio(),
            limits,
        )
        .is_err()
    );
    for end in [
        0,
        7,
        old_moof,
        old_moof + 7,
        old_moof + 23,
        old_moof + 43,
        old_moof + 63,
        first.bytes().len() - 1,
    ] {
        assert!(
            fss_container::flv_av::verify_archived_fragment(
                segments[0].fragment().bytes(),
                &first.bytes()[..end],
                first.audio(),
                limits,
            )
            .is_err()
        );
    }
    let mut impossible_mapping = first.audio().to_vec();
    impossible_mapping[0].target = usize::MAX - 1..usize::MAX;
    impossible_mapping[0].decode_ticks = u64::MAX;
    assert!(
        fss_container::flv_av::verify_archived_fragment(
            segments[0].fragment().bytes(),
            first.bytes(),
            &impossible_mapping,
            limits,
        )
        .is_err()
    );
    for mapping in first.audio() {
        assert_eq!(
            &wire[mapping.source.start as usize..mapping.source.end as usize],
            &first.bytes()[mapping.target.clone()]
        );
    }
    assert!(matches!(
        muxer.fragment(&init, &segments[0]),
        Err(av_recording::Error::Clock(aac_clock::Error::Timeline))
    ));
    let (_, other_records) = fixture_with_audio_intervals(0, false, false, false, Some(64))?;
    let mut other = Recorder::new(
        SourceKey {
            connection: 8,
            generation: 1,
        },
        Limits::default(),
    )?;
    for record in other_records.into_iter().take(2) {
        assert!(matches!(
            other.push(record).map_err(|refusal| refusal.reason)?,
            Push::Source { .. }
        ));
    }
    let wrong_init = other.av_initialization(&config)?.ok_or("other init")?;
    assert!(matches!(
        muxer.fragment(&wrong_init, &segments[1]),
        Err(av_recording::Error::Mux(Mp4Error::StreamMismatch))
    ));
    let second = muxer.fragment(&init, &segments[1])?;
    assert_eq!(second.audio().len(), 3);
    assert_eq!(second.video().sequence(), 2);
    let mut renewable = av_recording::Muxer::new(&init, &config, 0, 0, 2, 8, limits)?;
    let initial = renewable.fragment(&init, &segments[0])?;
    assert_eq!(initial.bytes(), first.bytes());
    assert_eq!(renewable.remaining_audio_frames(), 0);
    assert!(matches!(
        renewable.fragment(&init, &segments[1]),
        Err(av_recording::Error::Clock(aac_clock::Error::Limit))
    ));
    assert_eq!(renewable.remaining_audio_frames(), 0);
    renewable.extend_audio_limit(3)?;
    let continued = renewable.fragment(&init, &segments[1])?;
    assert_eq!(continued.bytes(), second.bytes());
    assert_eq!(continued.audio(), second.audio());
    assert_eq!(renewable.remaining_audio_frames(), 0);
    for mapping in second.audio() {
        assert_eq!(
            &wire[mapping.source.start as usize..mapping.source.end as usize],
            &second.bytes()[mapping.target.clone()]
        );
    }
    assert!(!recorder.retire().pending.is_empty());
    Ok(())
}

#[test]
fn av_owner_retains_in_band_audio_configuration_binding() -> TestResult {
    use fss_container::Mp4Limits;
    use fss_core::ContentDigest;
    use fss_packet::extended_flv::{aac, aac_track};
    use fss_reference::unifi_direct::av_recording;

    let (mut wire, original) = fixture(0, false, false)?;
    let insertion = usize::try_from(original[1].offset())? + original[1].bytes().len();
    let mut audio_configuration = vec![0x77; 3];
    audio_configuration.extend(tag(8, 0, &[0xaf, 0, 0x14, 0x08]));
    wire.splice(insertion..insertion, audio_configuration);
    let mut framer = Framer::new(FlvLimits::default(), 1024 * 1024)?;
    framer.append(0, &wire)?;
    let mut track = aac_track::Track::new(FlvLimits::default(), aac::Limits::default());
    let mut recorder = Recorder::new(KEY, Limits::default())?;
    let mut captured = None;
    while let Next::Record(record) = framer.take()? {
        let observation = track.observe(&record)?;
        if let Push::Source { record, .. } = recorder.push(record).map_err(|r| r.reason)?
            && matches!(&observation, aac_track::Observation::Configuration { .. })
        {
            captured = Some((observation, record));
            break;
        }
    }
    let (observation, record) = captured.ok_or("missing audio configuration")?;
    let binding =
        observation.bind_configuration(&record, FlvLimits::default(), aac::Limits::default())?;
    let initialization = recorder
        .av_initialization(binding.configuration())?
        .ok_or("missing A/V initialization")?;
    let owner = av_recording::Muxer::from_source(
        &initialization,
        &binding,
        0,
        0,
        8,
        8,
        Mp4Limits::default(),
    )?;
    let source = owner.source_binding().ok_or("missing source binding")?;
    assert_eq!(source.epoch, 1);
    assert_eq!(source.record_offset, record.offset());
    assert_eq!(source.record_bytes, record.bytes().len());
    assert_eq!(source.record_digest, ContentDigest::sha256(record.bytes()));
    assert_eq!(source.configuration_source, binding.source());
    assert_eq!(
        &wire[source.configuration_source.start as usize..source.configuration_source.end as usize],
        binding.configuration().bytes()
    );
    let explicit = av_recording::Muxer::new(
        &initialization,
        binding.configuration(),
        0,
        0,
        8,
        8,
        Mp4Limits::default(),
    )?;
    assert!(explicit.source_binding().is_none());
    Ok(())
}

#[test]
fn idr_segments_preserve_every_record_across_rollover_and_decode() -> TestResult {
    let (wire, records) = fixture(u32::MAX - 50, false, false)?;
    let mut recorder = Recorder::new(KEY, Limits::default())?;
    let mut original = Vec::new();
    let mut segments = 0;
    let mut initialization = None;
    for record in records {
        match recorder.push(record).map_err(|r| r.reason)? {
            Push::Source {
                record,
                disposition,
            } => {
                if disposition == SourceDisposition::Configuration {
                    initialization = Some(
                        recorder
                            .initialization()
                            .ok_or("missing initialization")?
                            .bytes()
                            .to_vec(),
                    );
                }
                original.extend_from_slice(record.bytes());
            }
            Push::Buffered => {}
            Push::Segment(segment) => {
                assert_eq!(segment.fragment().sequence(), segments + 1);
                assert_eq!(segment.fragment().samples().len(), 3);
                assert!(!segment.lookahead_copies().is_empty());
                let mut witness_offset = segment.source().last().ok_or("missing source")?.offset()
                    + segment
                        .source()
                        .last()
                        .ok_or("missing source")?
                        .bytes()
                        .len() as u64;
                for witness in segment.lookahead_copies() {
                    assert_eq!(witness.offset(), witness_offset);
                    let end = witness_offset as usize + witness.bytes().len();
                    assert_eq!(&wire[witness_offset as usize..end], witness.bytes());
                    witness_offset = end as u64;
                }
                for record in segment.source() {
                    original.extend_from_slice(record.bytes());
                }
                let mut mp4 = initialization.as_ref().ok_or("missing init")?.clone();
                mp4.extend_from_slice(segment.fragment().bytes());
                let movie = AvcMp4::parse(&mp4, None, DemuxLimits::default())?;
                let raw = movie.annex_b(0, 3)?;
                let mut decoder =
                    fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
                let mut frames = decoder.decode_annex_b(raw.bytes())?;
                frames.extend(decoder.finish()?);
                assert_eq!(frames.len(), 3);
                segments += 1;
            }
        }
    }
    let tail = recorder.retire();
    assert!(!tail.fenced);
    assert!(tail.source_bytes > 0);
    for record in tail.pending {
        original.extend_from_slice(record.bytes());
    }
    assert_eq!(segments, 2);
    assert_eq!(original, wire);
    Ok(())
}

#[test]
fn non_idr_preroll_is_returned_before_recording_starts() -> TestResult {
    let (_, records) = fixture(0, true, false)?;
    let mut recorder = Recorder::new(KEY, Limits::default())?;
    let mut preroll_video = 0;
    let mut segment_count = 0;
    for record in records {
        let is_video = matches!(
            record.kind(),
            fss_packet::extended_flv::stream::RecordKind::Candidate { tag_kind: 9, .. }
        );
        match recorder.push(record).map_err(|r| r.reason)? {
            Push::Source {
                disposition: SourceDisposition::PreRoll,
                ..
            } if is_video => preroll_video += 1,
            Push::Segment(_) => segment_count += 1,
            _ => {}
        }
    }
    assert_eq!(preroll_video, 1);
    assert_eq!(segment_count, 1);
    assert!(!recorder.retire().fenced);
    Ok(())
}

#[test]
fn capacity_refusal_preserves_unaccepted_and_buffered_source() -> TestResult {
    let (_, records) = fixture(0, false, false)?;
    let mut recorder = Recorder::new(
        KEY,
        Limits {
            max_records: 1,
            ..Limits::default()
        },
    )?;
    let mut accepted_bytes = 0;
    let mut refusal = None;
    for record in records {
        match recorder.push(record) {
            Ok(Push::Source { record, .. }) => accepted_bytes += record.bytes().len(),
            Ok(Push::Buffered) => {}
            Ok(Push::Segment(_)) => return Err("unexpected segment".into()),
            Err(error) => {
                refusal = Some(error);
                break;
            }
        }
    }
    let refusal = refusal.ok_or("missing refusal")?;
    assert_eq!(refusal.reason, Error::Limit);
    let unaccepted = refusal.unaccepted.ok_or("missing unaccepted record")?;
    let tail = recorder.retire();
    assert!(tail.fenced);
    assert_eq!(tail.pending.len(), 1);
    assert_eq!(tail.source_bytes, tail.pending[0].bytes().len());
    assert_eq!(tail.pending[0].offset() as usize, accepted_bytes);
    assert_eq!(
        unaccepted.offset() as usize,
        accepted_bytes + tail.source_bytes
    );
    Ok(())
}

#[test]
fn failed_fragment_keeps_trigger_record_in_retirement() -> TestResult {
    let (wire, records) = fixture(0, false, true)?;
    let mut recorder = Recorder::new(KEY, Limits::default())?;
    let mut released = Vec::new();
    let mut refused = false;
    for record in records {
        match recorder.push(record) {
            Ok(Push::Source { record, .. }) => released.extend_from_slice(record.bytes()),
            Ok(Push::Buffered) => {}
            Ok(Push::Segment(_)) => return Err("duplicate picture was emitted".into()),
            Err(error) => {
                assert!(matches!(
                    error.reason,
                    Error::Mux(fss_container::Mp4Error::UnverifiedPicture)
                ));
                assert!(error.unaccepted.is_none());
                refused = true;
                break;
            }
        }
    }
    let tail = recorder.retire();
    assert!(refused && tail.fenced);
    for record in tail.pending {
        released.extend_from_slice(record.bytes());
    }
    assert_eq!(released, wire);
    Ok(())
}

#[test]
fn witness_budget_refusal_retains_all_source_without_fragment() -> TestResult {
    let (wire, records) = fixture(0, false, false)?;
    let mut recorder = Recorder::new(
        KEY,
        Limits {
            max_witness_bytes: 1,
            ..Limits::default()
        },
    )?;
    let mut retained = Vec::new();
    let mut refused = false;
    for record in records {
        match recorder.push(record) {
            Ok(Push::Source { record, .. }) => retained.extend_from_slice(record.bytes()),
            Ok(Push::Buffered) => {}
            Ok(Push::Segment(_)) => return Err("oversize witness was emitted".into()),
            Err(error) => {
                assert_eq!(error.reason, Error::Limit);
                assert!(error.unaccepted.is_none());
                refused = true;
                break;
            }
        }
    }
    let tail = recorder.retire();
    assert!(refused && tail.fenced);
    for record in tail.pending {
        retained.extend_from_slice(record.bytes());
    }
    assert_eq!(retained, wire[..retained.len()]);
    Ok(())
}

#[test]
fn evidence_graph_binds_configuration_source_witness_and_derivative() -> TestResult {
    use fss_core::ContentDigest;
    use fss_reference::unifi_direct::evidence::{
        Error as EvidenceError, Limits as EvidenceLimits, Prepared,
    };
    use std::collections::BTreeSet;

    let (_, records) = fixture(0, false, false)?;
    let mut recorder = Recorder::new(KEY, Limits::default())?;
    let mut header = None;
    let mut configuration = None;
    for record in records {
        match recorder.push(record).map_err(|r| r.reason)? {
            Push::Source {
                record,
                disposition: SourceDisposition::Header,
            } => header = Some(record),
            Push::Source {
                record,
                disposition: SourceDisposition::Configuration,
            } => configuration = Some(record),
            Push::Segment(segment) => {
                let config = configuration.as_ref().ok_or("missing config")?;
                let init = recorder.initialization().ok_or("missing init")?;
                let retention = ContentDigest::sha256(b"synthetic retention decision");
                let plan =
                    Prepared::new(&segment, config, init, retention, EvidenceLimits::default())?;
                let repeat =
                    Prepared::new(&segment, config, init, retention, EvidenceLimits::default())?;
                assert_eq!(plan.manifest().root(), repeat.manifest().root());
                assert_eq!(plan.metadata(), repeat.metadata());
                let mut visited = BTreeSet::new();
                plan.visit_objects(|digest, bytes| {
                    assert_eq!(digest, ContentDigest::sha256(bytes));
                    visited.insert(digest);
                });
                assert_eq!(
                    visited,
                    plan.manifest().children().iter().copied().collect()
                );
                assert!(
                    Prepared::new(
                        &segment,
                        header.as_ref().ok_or("missing header")?,
                        init,
                        retention,
                        EvidenceLimits::default()
                    )
                    .is_err()
                );
                assert_eq!(
                    Prepared::new(
                        &segment,
                        config,
                        init,
                        retention,
                        EvidenceLimits {
                            max_bytes: 1,
                            ..EvidenceLimits::default()
                        }
                    )
                    .unwrap_err(),
                    EvidenceError::Limit
                );
                let other = Prepared::new(
                    &segment,
                    config,
                    init,
                    ContentDigest::sha256(b"another retention decision"),
                    EvidenceLimits::default(),
                )?;
                assert_ne!(plan.manifest().root(), other.manifest().root());
                return Ok(());
            }
            _ => {}
        }
    }
    Err("no segment produced".into())
}

#[test]
fn ledger_publication_requires_capture_bounds_and_retention_authority() -> TestResult {
    ledger_publication_fixture(false)
}

#[test]
fn ledger_publication_round_trips_av_flag_framed_source() -> TestResult {
    ledger_publication_fixture(true)
}

fn ledger_publication_fixture(av_flag: bool) -> TestResult {
    use fss_core::{
        BudgetVector, CaptureInterval, ContentDigest, OperationId, RootAuthoritySpec, TimestampNs,
        region::ContextAuthority,
    };
    use fss_geometry::WorkBudget;
    use fss_publication::{RootLedgerOutcome, RootLedgerState};
    use fss_reference::{
        ReferenceDeployment, ReplayCx,
        unifi_direct::{
            archive::{self, ReadAuthority, RetainAuthority},
            evidence::{Limits as EvidenceLimits, Prepared},
        },
    };
    use std::{cell::Cell, path::PathBuf};
    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    struct Access {
        allowed: Cell<bool>,
        calls: Cell<usize>,
        deny_at: Cell<usize>,
        read_calls: Cell<usize>,
        deny_read_at: Cell<usize>,
        retention: ContentDigest,
    }
    impl RetainAuthority for Access {
        fn permits(&self, retention: ContentDigest, _: ContentDigest) -> bool {
            let calls = self.calls.get() + 1;
            self.calls.set(calls);
            self.allowed.get() && calls < self.deny_at.get() && self.retention == retention
        }
    }
    impl ReadAuthority for Access {
        fn permits(&self, retention: ContentDigest, _: ContentDigest) -> bool {
            let calls = self.read_calls.get() + 1;
            self.read_calls.set(calls);
            self.allowed.get() && calls < self.deny_read_at.get() && self.retention == retention
        }
    }
    let path = std::env::temp_dir().join(format!(
        "fss-unifi-archive-{}-{av_flag}-fixture",
        std::process::id()
    ));
    std::fs::create_dir(&path)?;
    let temp = Temp(path);
    let context = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:unifi-archive-test".into(),
        operation_id: OperationId::parse("operation:unifi-archive-test")?,
        principal: "principal:unifi-archive-test".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"site:unifi-archive-test"),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&context, temp.0.clone())?;
    let mut deployment =
        ReferenceDeployment::open(&temp.0.join("deployment"), "site:unifi-archive-test", &cx)?;
    let retention = ContentDigest::sha256(b"synthetic retention authority");
    let access = Access {
        allowed: Cell::new(false),
        calls: Cell::new(0),
        deny_at: Cell::new(usize::MAX),
        read_calls: Cell::new(0),
        deny_read_at: Cell::new(usize::MAX),
        retention,
    };
    let (_, records) = fixture_with_policy(0, false, false, false, None, av_flag)?;
    let mut recorder = Recorder::new(KEY, Limits::default())?;
    let mut configuration = None;
    for record in records {
        match recorder.push(record).map_err(|r| r.reason)? {
            Push::Source {
                record,
                disposition: SourceDisposition::Configuration,
            } => configuration = Some(record),
            Push::Segment(segment) => {
                if av_flag {
                    assert!(segment.source().iter().any(|record| matches!(
                        record.kind(),
                        fss_packet::extended_flv::stream::RecordKind::Candidate {
                            policy: fss_packet::extended_flv::stream::SearchMode::StructuredTrailer16AvFlag,
                            ..
                        }
                    )));
                }
                let config = configuration.as_ref().ok_or("missing config")?;
                let init = recorder.initialization().ok_or("missing init")?;
                let unknown =
                    Prepared::new(&segment, config, init, retention, EvidenceLimits::default())?;
                assert!(matches!(
                    archive::publish(
                        &unknown,
                        &mut deployment,
                        &access,
                        archive::Limits::default(),
                        &mut WorkBudget::new(4_000_000_000),
                        &cx
                    ),
                    Err(archive::Error::UnknownCapture)
                ));
                let capture = CaptureInterval::new(TimestampNs(1), TimestampNs(10))?;
                let plan = Prepared::new_with_capture(
                    &segment,
                    config,
                    init,
                    retention,
                    Some(capture),
                    EvidenceLimits::default(),
                )?;
                assert!(matches!(
                    archive::publish(
                        &plan,
                        &mut deployment,
                        &access,
                        archive::Limits::default(),
                        &mut WorkBudget::new(4_000_000_000),
                        &cx
                    ),
                    Err(archive::Error::Denied)
                ));
                assert!(deployment.ledger().batches().is_empty());
                let pin = archive::Pin::from_plan(&plan).ok_or("missing pin")?;
                let config_digest = ContentDigest::sha256(config.bytes());
                access.allowed.set(true);
                assert!(matches!(
                    archive::read_object(
                        &mut deployment,
                        pin,
                        config_digest,
                        &access,
                        archive::Limits::default(),
                        &mut WorkBudget::new(4_000_000_000),
                        &cx
                    ),
                    Err(archive::Error::NotCommitted)
                ));

                access.calls.set(0);
                access.deny_at.set(3);
                assert!(matches!(
                    archive::publish(
                        &plan,
                        &mut deployment,
                        &access,
                        archive::Limits::default(),
                        &mut WorkBudget::new(4_000_000_000),
                        &cx
                    ),
                    Err(archive::Error::Denied)
                ));
                assert!(deployment.ledger().batches().is_empty());
                assert!(
                    deployment
                        .publisher()
                        .root(&archive::slot(&plan)?)
                        .is_none()
                );
                access.calls.set(0);
                access.deny_at.set(usize::MAX);
                let first = archive::publish(
                    &plan,
                    &mut deployment,
                    &access,
                    archive::Limits::default(),
                    &mut WorkBudget::new(4_000_000_000),
                    &cx,
                )?;
                assert_eq!(first.outcome, RootLedgerOutcome::Committed);
                let again = archive::publish(
                    &plan,
                    &mut deployment,
                    &access,
                    archive::Limits::default(),
                    &mut WorkBudget::new(4_000_000_000),
                    &cx,
                )?;
                assert_eq!(again.outcome, RootLedgerOutcome::AlreadyLedgered);
                assert_eq!(first.root, again.root);
                assert_eq!(deployment.ledger().batches().len(), 1);
                drop(deployment);
                let mut reopened = ReferenceDeployment::open(
                    &temp.0.join("deployment"),
                    "site:unifi-archive-test",
                    &cx,
                )?;
                assert!(
                    matches!(reopened.ledgered_publisher().state(&archive::slot(&plan)?)?, RootLedgerState::Ledgered { root, .. } if root == plan.manifest().root())
                );
                plan.visit_objects(|digest, original| {
                    assert_eq!(reopened.publisher().spool().read(digest).unwrap(), original);
                });
                assert_eq!(
                    archive::read_object(
                        &mut reopened,
                        pin,
                        config_digest,
                        &access,
                        archive::Limits::default(),
                        &mut WorkBudget::new(4_000_000_000),
                        &cx
                    )?,
                    config.bytes()
                );
                let clip = archive::read_clip(
                    &mut reopened,
                    pin,
                    &access,
                    archive::Limits::default(),
                    &mut WorkBudget::new(10_000_000_000),
                    &cx,
                )?;
                assert_eq!(clip.capture(), capture);
                assert_eq!(clip.samples(), 3);
                let mut expected = init.bytes().to_vec();
                expected.extend_from_slice(segment.fragment().bytes());
                assert_eq!(clip.bytes(), expected);
                let movie = AvcMp4::parse(clip.bytes(), None, DemuxLimits::default())?;
                let annex_b = movie.annex_b(0, clip.samples())?;
                let mut decoder =
                    fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
                let mut frames = decoder.decode_annex_b(annex_b.bytes())?;
                frames.extend(decoder.finish()?);
                assert_eq!(frames.len(), 3);
                assert!(matches!(
                    archive::read_clip(
                        &mut reopened,
                        pin,
                        &access,
                        archive::Limits::default(),
                        &mut WorkBudget::new(1),
                        &cx,
                    ),
                    Err(archive::Error::Work(_))
                ));
                access.read_calls.set(0);
                access.deny_read_at.set(8);
                assert!(matches!(
                    archive::read_clip(
                        &mut reopened,
                        pin,
                        &access,
                        archive::Limits::default(),
                        &mut WorkBudget::new(10_000_000_000),
                        &cx,
                    ),
                    Err(archive::Error::Denied)
                ));
                assert_eq!(access.read_calls.get(), 8);
                access.deny_read_at.set(usize::MAX);
                access.allowed.set(false);
                assert!(matches!(
                    archive::read_clip(
                        &mut reopened,
                        pin,
                        &access,
                        archive::Limits::default(),
                        &mut WorkBudget::new(10_000_000_000),
                        &cx,
                    ),
                    Err(archive::Error::Denied)
                ));
                assert!(matches!(
                    archive::read_object(
                        &mut reopened,
                        pin,
                        config_digest,
                        &access,
                        archive::Limits::default(),
                        &mut WorkBudget::new(4_000_000_000),
                        &cx
                    ),
                    Err(archive::Error::Denied)
                ));
                access.allowed.set(true);
                let wrong_pin = archive::Pin {
                    capture: CaptureInterval::point(TimestampNs(999)),
                    ..pin
                };
                assert!(matches!(
                    archive::read_clip(
                        &mut reopened,
                        wrong_pin,
                        &access,
                        archive::Limits::default(),
                        &mut WorkBudget::new(10_000_000_000),
                        &cx,
                    ),
                    Err(archive::Error::Mismatch)
                ));
                assert!(matches!(
                    archive::read_object(
                        &mut reopened,
                        wrong_pin,
                        config_digest,
                        &access,
                        archive::Limits::default(),
                        &mut WorkBudget::new(4_000_000_000),
                        &cx
                    ),
                    Err(archive::Error::Mismatch)
                ));
                assert!(matches!(
                    archive::read_object(
                        &mut reopened,
                        pin,
                        ContentDigest::sha256(b"outside graph"),
                        &access,
                        archive::Limits::default(),
                        &mut WorkBudget::new(4_000_000_000),
                        &cx
                    ),
                    Err(archive::Error::Mismatch)
                ));
                // Only this isolated temporary fixture is corrupted.
                let fragment_digest = ContentDigest::sha256(segment.fragment().bytes());
                let fragment_path = reopened.publisher().spool().object_path(fragment_digest);
                std::fs::write(fragment_path, b"corrupt fixture")?;
                assert!(
                    archive::read_clip(
                        &mut reopened,
                        pin,
                        &access,
                        archive::Limits::default(),
                        &mut WorkBudget::new(10_000_000_000),
                        &cx,
                    )
                    .is_err()
                );
                return Ok(());
            }
            _ => {}
        }
    }
    Err("no segment produced".into())
}

#[test]
fn av_evidence_publishes_and_reopens_exact_source_objects() -> TestResult {
    use fss_container::Mp4Limits;
    use fss_core::{
        BudgetVector, CanonicalDecoder, CaptureInterval, ContentDigest, OperationId,
        RootAuthoritySpec, TimestampNs, region::ContextAuthority,
    };
    use fss_geometry::WorkBudget;
    use fss_object::ObjectManifest;
    use fss_packet::extended_flv::{aac, aac_track};
    use fss_publication::{RootLedgerOutcome, SlotName};
    use fss_reference::{
        ReferenceDeployment, ReplayCx,
        unifi_direct::{
            archive::{self, ReadAuthority, RetainAuthority},
            av_evidence::PreparedAv,
            av_recording,
            evidence::{Limits as EvidenceLimits, Prepared},
        },
    };
    use std::{cell::Cell, path::PathBuf};
    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    struct Access {
        allowed: Cell<bool>,
        retention: ContentDigest,
        read_calls: Cell<usize>,
        deny_read_at: Cell<usize>,
    }
    impl RetainAuthority for Access {
        fn permits(&self, retention: ContentDigest, _: ContentDigest) -> bool {
            self.allowed.get() && retention == self.retention
        }
    }
    impl ReadAuthority for Access {
        fn permits(&self, retention: ContentDigest, _: ContentDigest) -> bool {
            let calls = self.read_calls.get() + 1;
            self.read_calls.set(calls);
            self.allowed.get() && retention == self.retention && calls < self.deny_read_at.get()
        }
    }

    let (mut wire, original) = fixture_with_audio_intervals(0, false, false, false, Some(64))?;
    let insertion = usize::try_from(original[1].offset())? + original[1].bytes().len();
    let mut config_wire = vec![0x77; 3];
    config_wire.extend(tag(8, 0, &[0xaf, 0, 0x14, 0x08]));
    wire.splice(insertion..insertion, config_wire);
    let mut framer = Framer::new(FlvLimits::default(), 1024 * 1024)?;
    framer.append(0, &wire)?;
    let mut track = aac_track::Track::new(FlvLimits::default(), aac::Limits::default());
    let mut recorder = Recorder::new(KEY, Limits::default())?;
    let mut video_configuration = None;
    let mut audio_configuration = None;
    let mut segment = None;
    while let Next::Record(record) = framer.take()? {
        let observation = track.observe(&record)?;
        match recorder.push(record).map_err(|r| r.reason)? {
            Push::Source {
                record,
                disposition: SourceDisposition::Configuration,
            } => video_configuration = Some(record),
            Push::Source { record, .. }
                if matches!(observation, aac_track::Observation::Configuration { .. }) =>
            {
                audio_configuration = Some((observation, record))
            }
            Push::Segment(value) => {
                segment = Some(value);
                break;
            }
            _ => {}
        }
    }
    let segment = segment.ok_or("missing segment")?;
    let (observation, audio_record) = audio_configuration.ok_or("missing audio configuration")?;
    let bound = observation.bind_configuration(
        &audio_record,
        FlvLimits::default(),
        aac::Limits::default(),
    )?;
    let video_init = recorder
        .initialization()
        .ok_or("missing video initialization")?;
    let av_init = recorder
        .av_initialization(bound.configuration())?
        .ok_or("missing A/V initialization")?;
    let mut muxer =
        av_recording::Muxer::from_source(&av_init, &bound, 0, 0, 8, 8, Mp4Limits::default())?;
    let fragment = muxer.fragment(&av_init, &segment)?;
    let retention = ContentDigest::sha256(b"synthetic av retention");
    let capture = CaptureInterval::new(TimestampNs(1), TimestampNs(10))?;
    let video = Prepared::new_with_capture(
        &segment,
        video_configuration
            .as_ref()
            .ok_or("missing video configuration")?,
        video_init,
        retention,
        Some(capture),
        EvidenceLimits::default(),
    )?;
    let av = PreparedAv::new(
        &video,
        &bound,
        &av_init,
        &fragment,
        EvidenceLimits::default(),
    )?;
    assert_eq!(
        av.audio_configuration_origin(),
        fss_reference::unifi_direct::av_evidence::AudioConfigurationOrigin::InBand
    );
    let supplied = PreparedAv::new_with_unverified_audio_configuration(
        &video,
        bound.configuration(),
        &av_init,
        &fragment,
        EvidenceLimits::default(),
    )?;
    assert_eq!(
        supplied.audio_configuration_origin(),
        fss_reference::unifi_direct::av_evidence::AudioConfigurationOrigin::SuppliedUnverified
    );
    assert_ne!(av.manifest().root(), supplied.manifest().root());
    assert!(
        supplied
            .manifest()
            .children()
            .contains(&ContentDigest::sha256(bound.configuration().bytes()))
    );
    let wrong_configuration = aac::Configuration::parse_explicit(&[0x12, 0x10])?;
    assert!(matches!(
        PreparedAv::new_with_unverified_audio_configuration(
            &video,
            &wrong_configuration,
            &av_init,
            &fragment,
            EvidenceLimits::default()
        ),
        Err(fss_reference::unifi_direct::av_evidence::Error::Mismatch)
    ));
    let (_, other_records) = fixture_with_audio_intervals(0, false, false, false, Some(64))?;
    let mut other = Recorder::new(
        SourceKey {
            connection: 8,
            generation: 1,
        },
        Limits::default(),
    )?;
    for record in other_records.into_iter().take(2) {
        let _ = other.push(record).map_err(|refusal| refusal.reason)?;
    }
    let other_init = other
        .av_initialization(bound.configuration())?
        .ok_or("missing other A/V initialization")?;
    assert!(matches!(
        PreparedAv::new(
            &video,
            &bound,
            &other_init,
            &fragment,
            EvidenceLimits::default()
        ),
        Err(fss_reference::unifi_direct::av_evidence::Error::Mismatch)
    ));
    assert!(matches!(
        PreparedAv::new(
            &video,
            &bound,
            &av_init,
            &fragment,
            EvidenceLimits {
                max_bytes: 1,
                ..EvidenceLimits::default()
            }
        ),
        Err(fss_reference::unifi_direct::av_evidence::Error::Limit)
    ));

    let path = std::env::temp_dir().join(format!("fss-unifi-av-archive-{}", std::process::id()));
    std::fs::create_dir(&path)?;
    let temp = Temp(path);
    let context = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:unifi-av-archive-test".into(),
        operation_id: OperationId::parse("operation:unifi-av-archive-test")?,
        principal: "principal:unifi-av-archive-test".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"site:unifi-av-archive-test"),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&context, temp.0.clone())?;
    let mut deployment = ReferenceDeployment::open(
        &temp.0.join("deployment"),
        "site:unifi-av-archive-test",
        &cx,
    )?;
    let access = Access {
        allowed: Cell::new(false),
        retention,
        read_calls: Cell::new(0),
        deny_read_at: Cell::new(usize::MAX),
    };
    let pin = archive::Pin::from_av_plan(&av).ok_or("missing pin")?;
    let supplied_pin = archive::Pin::from_av_plan(&supplied).ok_or("missing supplied pin")?;
    let mut work = WorkBudget::new(4_000_000_000);
    assert!(matches!(
        archive::publish_av(
            &av,
            &mut deployment,
            &access,
            archive::Limits::default(),
            &mut work,
            &cx
        ),
        Err(archive::Error::Denied)
    ));
    access.allowed.set(true);
    assert_eq!(
        archive::publish_av(
            &av,
            &mut deployment,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx
        )?
        .outcome,
        RootLedgerOutcome::Committed
    );
    assert_eq!(
        archive::publish_av(
            &supplied,
            &mut deployment,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx
        )?
        .outcome,
        RootLedgerOutcome::Committed
    );
    drop(deployment);
    let mut reopened = ReferenceDeployment::open(
        &temp.0.join("deployment"),
        "site:unifi-av-archive-test",
        &cx,
    )?;
    av.visit_objects(|digest, bytes| {
        assert_eq!(reopened.publisher().spool().read(digest).unwrap(), bytes);
    });
    let digest = ContentDigest::sha256(fragment.bytes());
    let in_band = archive::read_av_audio_configuration(
        &mut reopened,
        pin,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &cx,
    )?;
    let unverified = archive::read_av_audio_configuration(
        &mut reopened,
        supplied_pin,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &cx,
    )?;
    assert_eq!(in_band.origin, av.audio_configuration_origin());
    assert_eq!(in_band.claimed_epoch, Some(1));
    assert_eq!(unverified.origin, supplied.audio_configuration_origin());
    assert_eq!(unverified.claimed_epoch, None);
    assert_eq!(in_band.digest, unverified.digest);
    let mapped = archive::verify_av_audio_source_mapping(
        &mut reopened,
        pin,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(20_000_000_000),
        &cx,
    )?;
    let mapped_unverified = archive::verify_av_audio_source_mapping(
        &mut reopened,
        supplied_pin,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(20_000_000_000),
        &cx,
    )?;
    assert_eq!(mapped.configuration_origin, in_band.origin);
    assert_eq!(mapped_unverified.configuration_origin, unverified.origin);
    assert_eq!(mapped.frames, fragment.audio().len());
    assert_eq!(mapped.frames, mapped_unverified.frames);
    assert_eq!(mapped.sample_rate, bound.configuration().sample_rate());
    assert_eq!(mapped.first_decode_ticks, fragment.audio()[0].decode_ticks);
    // Even though the spool permits 64 MiB objects, source records here are
    // small. The reader must stay within this bounded end-to-end work budget.
    let mut bounded_work = WorkBudget::new(3_000_000_000);
    let av_clip = archive::read_av_clip(
        &mut reopened,
        pin,
        &access,
        archive::Limits::default(),
        &mut bounded_work,
        &cx,
    )?;
    assert!(bounded_work.used() < 3_000_000_000);
    let mut expected_av = av_init.bytes().to_vec();
    expected_av.extend_from_slice(fragment.bytes());
    assert_eq!(av_clip.bytes(), expected_av);
    assert_eq!(av_clip.capture(), capture);
    assert_eq!(av_clip.audio(), mapped);
    assert_eq!(av_clip.video_samples(), segment.fragment().samples().len());
    let supplied_clip = archive::read_av_clip(
        &mut reopened,
        supplied_pin,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(20_000_000_000),
        &cx,
    )?;
    assert_eq!(supplied_clip.bytes(), expected_av);
    assert_eq!(
        supplied_clip.audio().configuration_origin,
        unverified.origin
    );
    access.read_calls.set(0);
    access.deny_read_at.set(8);
    assert!(matches!(
        archive::read_av_clip(
            &mut reopened,
            pin,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(20_000_000_000),
            &cx
        ),
        Err(archive::Error::Denied)
    ));
    assert_eq!(access.read_calls.get(), 8);
    access.deny_read_at.set(usize::MAX);
    assert!(matches!(
        archive::read_av_clip(
            &mut reopened,
            pin,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(1),
            &cx
        ),
        Err(archive::Error::Work(_))
    ));
    let wrong_capture = archive::Pin {
        capture: CaptureInterval::point(TimestampNs(999)),
        ..pin
    };
    assert!(matches!(
        archive::read_av_clip(
            &mut reopened,
            wrong_capture,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(20_000_000_000),
            &cx
        ),
        Err(archive::Error::Mismatch)
    ));

    // Forge a complete, content-addressed graph with an incorrect first audio
    // target. Both synthetic AAC bodies contain the same byte, so byte equality
    // alone would not detect the wrong sample-table location.
    let mut forged_metadata = av.metadata().to_vec();
    let mut d = CanonicalDecoder::new(&forged_metadata);
    assert_eq!(d.text()?, "fss.unifi-direct.flv-av-evidence.v1");
    assert_eq!(d.digest()?, retention);
    assert!(d.bool()?);
    let _ = d.i128()?;
    let _ = d.i128()?;
    let _ = d.digest()?;
    assert_eq!(d.u8()?, 0);
    let _ = d.u64()?;
    let _ = d.u64()?;
    let _ = d.u64()?;
    let _ = d.digest()?;
    match d.u8()? {
        1 => {
            let _ = d.u8()?;
            let _ = d.u32()?;
        }
        2 => {
            let _ = d.u64()?;
            let _ = d.u8()?;
            let _ = d.u32()?;
            let _ = d.bool()?;
            let _ = d.bool()?;
            let _ = d.u8()?;
        }
        _ => return Err("unexpected configuration record".into()),
    }
    let _ = d.u64()?;
    let _ = d.u64()?;
    let _ = d.digest()?;
    let _ = d.digest()?;
    let initialization_length_offset = d.offset();
    let declared_initialization_length = d.u64()?;
    assert_eq!(
        declared_initialization_length as usize,
        av_init.bytes().len()
    );
    let _ = d.digest()?;
    let _ = d.u64()?;
    let _ = d.u64()?;
    assert!(d.u64()? >= 2);
    let _ = d.u64()?;
    let _ = d.u64()?;
    let start_offset = d.offset();
    let first_start = d.u64()?;
    let end_offset = d.offset();
    let first_end = d.u64()?;
    assert_eq!(first_start as usize, fragment.audio()[0].target.start);
    assert_eq!(first_end as usize, fragment.audio()[0].target.end);
    assert_eq!(
        fragment
            .bytes()
            .get(first_start as usize..first_end as usize),
        fragment
            .bytes()
            .get((first_start + 1) as usize..(first_end + 1) as usize)
    );
    forged_metadata[start_offset..start_offset + 8]
        .copy_from_slice(&(first_start + 1).to_be_bytes());
    forged_metadata[end_offset..end_offset + 8].copy_from_slice(&(first_end + 1).to_be_bytes());
    let old_metadata = av
        .manifest()
        .metadata_digest()
        .ok_or("missing metadata digest")?;
    let forged_digest = ContentDigest::sha256(&forged_metadata);
    assert_eq!(reopened.stage_payload(&forged_metadata)?, forged_digest);
    let children: Vec<_> = av
        .manifest()
        .children()
        .iter()
        .copied()
        .filter(|d| *d != old_metadata)
        .collect();
    let forged_manifest = ObjectManifest::new(av.manifest().kind(), children, Some(forged_digest))?;
    let hex: String = forged_manifest
        .root()
        .bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let forged_slot = SlotName::parse(&format!("uflv1-{hex}"))?;
    assert_eq!(
        reopened
            .ledgered_publisher()
            .publish_and_commit(&forged_slot, &forged_manifest, capture)?
            .outcome,
        RootLedgerOutcome::Committed
    );
    let forged_pin = archive::Pin {
        root: forged_manifest.root(),
        ..pin
    };
    assert!(
        archive::read_av_clip(
            &mut reopened,
            forged_pin,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(20_000_000_000),
            &cx,
        )
        .is_err()
    );

    // A content-addressed graph can also lie about the object length. The
    // reader's per-object bound must reject that declaration before returning
    // any bytes, even though the object itself remains intact in the spool.
    let mut short_metadata = av.metadata().to_vec();
    short_metadata[initialization_length_offset..initialization_length_offset + 8]
        .copy_from_slice(&(declared_initialization_length - 1).to_be_bytes());
    let short_digest = ContentDigest::sha256(&short_metadata);
    assert_eq!(reopened.stage_payload(&short_metadata)?, short_digest);
    let short_children: Vec<_> = av
        .manifest()
        .children()
        .iter()
        .copied()
        .filter(|d| *d != old_metadata)
        .collect();
    let short_manifest =
        ObjectManifest::new(av.manifest().kind(), short_children, Some(short_digest))?;
    let short_hex: String = short_manifest
        .root()
        .bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let short_slot = SlotName::parse(&format!("uflv1-{short_hex}"))?;
    assert_eq!(
        reopened
            .ledgered_publisher()
            .publish_and_commit(&short_slot, &short_manifest, capture)?
            .outcome,
        RootLedgerOutcome::Committed
    );
    let short_result = archive::read_av_clip(
        &mut reopened,
        archive::Pin {
            root: short_manifest.root(),
            ..pin
        },
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(20_000_000_000),
        &cx,
    );
    match short_result {
        Err(archive::Error::Storage(error)) => assert!(matches!(
            error.downcast_ref::<fss_object::SpoolError>(),
            Some(fss_object::SpoolError::Corrupt {
                digest,
                kind: fss_object::CorruptionKind::DeclaredLengthExceedsLimit { declared, maximum }
            }) if *digest == ContentDigest::sha256(av_init.bytes())
                && *declared == declared_initialization_length
                && *maximum == declared_initialization_length - 1
        )),
        _ => return Err("short object declaration did not reach the spool bound".into()),
    }
    let video_clip = archive::read_av_video_clip(
        &mut reopened,
        pin,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(10_000_000_000),
        &cx,
    )?;
    let mut expected_video = video_init.bytes().to_vec();
    expected_video.extend_from_slice(segment.fragment().bytes());
    assert_eq!(video_clip.bytes(), expected_video);
    assert_eq!(video_clip.capture(), capture);
    let movie = AvcMp4::parse(video_clip.bytes(), None, DemuxLimits::default())?;
    let annex_b = movie.annex_b(0, video_clip.samples())?;
    let mut decoder = fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
    let mut frames = decoder.decode_annex_b(annex_b.bytes())?;
    frames.extend(decoder.finish()?);
    assert_eq!(frames.len(), video_clip.samples());
    assert_eq!(
        archive::read_av_object(
            &mut reopened,
            pin,
            digest,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx
        )?,
        fragment.bytes()
    );
    assert!(matches!(
        archive::read_object(
            &mut reopened,
            pin,
            digest,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx
        ),
        Err(archive::Error::Mismatch)
    ));
    access.allowed.set(false);
    assert!(matches!(
        archive::read_av_clip(
            &mut reopened,
            pin,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(20_000_000_000),
            &cx
        ),
        Err(archive::Error::Denied)
    ));
    assert!(matches!(
        archive::verify_av_audio_source_mapping(
            &mut reopened,
            pin,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(20_000_000_000),
            &cx
        ),
        Err(archive::Error::Denied)
    ));
    assert!(matches!(
        archive::read_av_video_clip(
            &mut reopened,
            pin,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(10_000_000_000),
            &cx
        ),
        Err(archive::Error::Denied)
    ));
    assert!(matches!(
        archive::read_av_audio_configuration(
            &mut reopened,
            supplied_pin,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx
        ),
        Err(archive::Error::Denied)
    ));
    assert!(matches!(
        archive::read_av_object(
            &mut reopened,
            pin,
            digest,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx
        ),
        Err(archive::Error::Denied)
    ));
    access.allowed.set(true);
    assert!(matches!(
        archive::read_av_object(
            &mut reopened,
            pin,
            ContentDigest::sha256(b"outside av graph"),
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx
        ),
        Err(archive::Error::Mismatch)
    ));
    let first_audio_offset = fragment.audio()[0].source.start;
    let audio_source = segment
        .source()
        .iter()
        .find(|record| {
            first_audio_offset >= record.offset()
                && first_audio_offset < record.offset() + record.bytes().len() as u64
        })
        .ok_or("missing audio source")?;
    let audio_path = reopened
        .publisher()
        .spool()
        .object_path(ContentDigest::sha256(audio_source.bytes()));
    std::fs::write(&audio_path, b"corrupt audio source fixture")?;
    assert!(
        archive::read_av_clip(
            &mut reopened,
            pin,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(20_000_000_000),
            &cx,
        )
        .is_err()
    );
    assert!(
        archive::verify_av_audio_source_mapping(
            &mut reopened,
            pin,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(20_000_000_000),
            &cx,
        )
        .is_err()
    );
    std::fs::write(audio_path, audio_source.bytes())?;
    let av_fragment_path = reopened.publisher().spool().object_path(digest);
    std::fs::write(&av_fragment_path, b"corrupt A/V fragment fixture")?;
    assert!(
        archive::verify_av_audio_source_mapping(
            &mut reopened,
            pin,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(20_000_000_000),
            &cx,
        )
        .is_err()
    );
    std::fs::write(av_fragment_path, fragment.bytes())?;
    let video_fragment = ContentDigest::sha256(segment.fragment().bytes());
    let video_path = reopened.publisher().spool().object_path(video_fragment);
    std::fs::write(video_path, b"corrupt video fixture")?;
    assert!(
        archive::read_av_video_clip(
            &mut reopened,
            pin,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(10_000_000_000),
            &cx
        )
        .is_err()
    );
    // Corrupt only the isolated fixture and require a failed read.
    let object_path = reopened.publisher().spool().object_path(digest);
    std::fs::write(object_path, b"corrupt A/V fixture")?;
    assert!(
        archive::read_av_object(
            &mut reopened,
            pin,
            digest,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx
        )
        .is_err()
    );
    Ok(())
}
