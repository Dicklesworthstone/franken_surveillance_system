#![forbid(unsafe_code)]
//! Sender-clock mapping from original records in a synthetic completed segment.

use fss_container::{Mp4Limits, flv_av, flv_avc::SourceKey};
use fss_packet::extended_flv::{
    Limits as FlvLimits, aac, aac_track,
    stream::{Framer, Next},
};
use fss_reference::unifi_direct::{
    av_recording,
    recording::{self, Push, Recorder},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const BASELINE: &[u8] = include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264");

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

fn first_segment(
    start: u32,
    include_audio: bool,
    audio_skew: u32,
    config: &aac::Configuration<'_>,
) -> Result<(recording::Segment, flv_av::Initialization), Box<dyn std::error::Error>> {
    first_segment_with_cycle(start, include_audio, audio_skew, config, 3)
}

fn first_segment_with_cycle(
    start: u32,
    include_audio: bool,
    audio_skew: u32,
    config: &aac::Configuration<'_>,
    cycle: usize,
) -> Result<(recording::Segment, flv_av::Initialization), Box<dyn std::error::Error>> {
    let (mut segments, init, _) =
        segments_with_cycle(start, include_audio, audio_skew, config, cycle)?;
    Ok((segments.remove(0), init))
}

fn segments_with_cycle(
    start: u32,
    include_audio: bool,
    audio_skew: u32,
    config: &aac::Configuration<'_>,
    cycle: usize,
) -> Result<
    (
        Vec<recording::Segment>,
        flv_av::Initialization,
        fss_packet::extended_flv::stream::SourceRecord,
    ),
    Box<dyn std::error::Error>,
> {
    let (segments, init, video, _) = segments_with_in_band(
        start,
        include_audio,
        audio_skew,
        config,
        cycle,
        false,
        false,
    )?;
    Ok((segments, init, video))
}

type InBandFixture = (
    Vec<recording::Segment>,
    flv_av::Initialization,
    fss_packet::extended_flv::stream::SourceRecord,
    Option<(
        aac_track::Observation,
        fss_packet::extended_flv::stream::SourceRecord,
    )>,
);

fn segments_with_in_band(
    start: u32,
    include_audio: bool,
    audio_skew: u32,
    config: &aac::Configuration<'_>,
    cycle: usize,
    in_band: bool,
    mutate_second_video: bool,
) -> Result<InBandFixture, Box<dyn std::error::Error>> {
    let (input, picture_cycle): (&[u8], usize) = if cycle == 1 {
        (
            include_bytes!(
                "../../../experiments/unifi_tls_05_server_lab/tests/fixtures/synthetic_g4_resolution.264"
            ),
            4,
        )
    } else {
        (BASELINE, cycle)
    };
    let nals: Vec<_> = fss_codec_h264::annex_b_nal_units(input).collect();
    let sps = nals.iter().copied().find(|n| n[0] & 31 == 7).ok_or("SPS")?;
    let pps = nals.iter().copied().find(|n| n[0] & 31 == 8).ok_or("PPS")?;
    let pictures: Vec<_> = nals
        .into_iter()
        .filter(|n| matches!(n[0] & 31, 1 | 5))
        .collect();
    if pictures.len() != 4 || pictures[0][0] & 31 != 5 {
        return Err("fixture picture layout".into());
    }
    let mut avc = vec![0x17, 0, 0, 0, 0, 1, sps[1], sps[2], sps[3], 0xff, 0xe1];
    avc.extend_from_slice(&u16::try_from(sps.len())?.to_be_bytes());
    avc.extend_from_slice(sps);
    avc.push(1);
    avc.extend_from_slice(&u16::try_from(pps.len())?.to_be_bytes());
    avc.extend_from_slice(pps);
    let mut wire = b"FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
    wire.extend(tag(9, start, &avc));
    if in_band {
        wire.extend(tag(8, start, &[0xaf, 0, 0x14, 0x08]));
    }
    for i in 0..8_u32 {
        if include_audio {
            wire.extend(tag(
                8,
                start.wrapping_add(i * 64).wrapping_add(audio_skew),
                &[0xaf, 1, 2],
            ));
        }
        let nal = pictures[i as usize % picture_cycle];
        let mut data = vec![0x17, 1, 0, 0, 0];
        data.extend_from_slice(&u32::try_from(nal.len())?.to_be_bytes());
        data.extend_from_slice(nal);
        if mutate_second_video && i == 1 {
            *data.last_mut().ok_or("empty picture")? ^= 1;
        }
        wire.extend(tag(9, start.wrapping_add(i * 40), &data));
    }
    let mut framer = Framer::new(FlvLimits::default(), 1024 * 1024)?;
    framer.append(0, &wire)?;
    let mut recorder = Recorder::new(
        SourceKey {
            connection: 1,
            generation: 1,
        },
        recording::Limits::default(),
    )?;
    let mut segments = Vec::new();
    let mut video_configuration = None;
    let mut audio_configuration = None;
    let mut track = aac_track::Track::new(FlvLimits::default(), aac::Limits::default());
    while let Next::Record(record) = framer.take()? {
        let observation = track.observe(&record)?;
        match recorder.push(record).map_err(|r| r.reason)? {
            Push::Source {
                record,
                disposition: recording::SourceDisposition::Configuration,
            } => video_configuration = Some(record),
            Push::Source { record, .. }
                if matches!(observation, aac_track::Observation::Configuration { .. }) =>
            {
                audio_configuration = Some((observation, record));
            }
            Push::Segment(segment) => {
                segments.push(segment);
                if segments.len() == 2 {
                    let init = recorder
                        .av_initialization(config)?
                        .ok_or("A/V initialization")?;
                    return Ok((
                        segments,
                        init,
                        video_configuration.ok_or("video configuration")?,
                        audio_configuration,
                    ));
                }
            }
            _ => (),
        }
    }
    Err("fewer than two complete segments".into())
}

#[test]
fn in_band_lookahead_binds_configuration_and_initial_video_only() -> TestResult {
    let config = aac::Configuration::parse_explicit(&[0x14, 0x08])?;
    let (segments, init, video_configuration, audio) =
        segments_with_in_band(10_000, true, 0, &config, 1, true, false)?;
    let (observation, record) = audio.ok_or("audio configuration")?;
    let bound =
        observation.bind_configuration(&record, FlvLimits::default(), aac::Limits::default())?;
    let (mut muxer, witness) = av_recording::Muxer::from_source_lookahead(
        &init,
        &bound,
        &segments[0],
        2_000,
        0,
        32,
        32,
        Mp4Limits::default(),
    )?;
    let binding = muxer.source_binding().ok_or("source binding")?;
    assert_eq!(binding.epoch, bound.epoch());
    assert_eq!(binding.record_offset, record.offset());
    assert_eq!(
        binding.record_digest,
        fss_core::ContentDigest::sha256(record.bytes())
    );
    assert_eq!(binding.configuration_source, bound.source());
    assert_eq!(witness.sender_timestamp_ms, 10_064);
    let fragment = muxer.fragment_without_audio(&init, &segments[0])?;
    assert!(fragment.audio().is_empty());
    let video_muxer = fss_container::flv_avc::Muxer::new(
        segments[0].fragment().key(),
        &video_configuration,
        Mp4Limits::default(),
    )?;
    let limits = fss_reference::unifi_direct::evidence::Limits::default();
    let video = fss_reference::unifi_direct::evidence::Prepared::new(
        &segments[0],
        &video_configuration,
        video_muxer.initialization(),
        fss_core::ContentDigest::sha256(b"in-band no-audio retention"),
        limits,
    )?;
    let prepared = fss_reference::unifi_direct::av_evidence::PreparedAvVideoOnly::new(
        &video, &bound, &init, &fragment, limits,
    )?;
    assert_eq!(
        prepared.manifest().kind(),
        "unifi-direct-flv-av-video-only-v1"
    );
    assert!(!muxer.fragment(&init, &segments[1])?.audio().is_empty());
    Ok(())
}

#[test]
fn lookahead_clock_keeps_initial_no_audio_segment_and_witness_distinct() -> TestResult {
    let config = aac::Configuration::parse_explicit(&[0x14, 0x08])?;
    let (segments, init, video_configuration) = segments_with_cycle(10_000, true, 0, &config, 1)?;
    let segment = &segments[0];
    assert_eq!(
        av_recording::segment_sender_clock_origin(segment, &config, 2_000),
        Err(av_recording::Error::NoAudio)
    );
    let observed = av_recording::lookahead_sender_clock_origin(segment, &config, 2_000)?;
    assert_eq!(
        (
            observed.origin.audio_minus_video_ms,
            observed.sender_timestamp_ms
        ),
        (64, 10_064)
    );
    let exact = segment
        .lookahead_copies()
        .iter()
        .find(|record| record.offset() == observed.record_offset)
        .ok_or("missing witness")?;
    assert_eq!(observed.record_bytes, exact.bytes().len());
    assert_eq!(
        observed.record_digest,
        fss_core::ContentDigest::sha256(exact.bytes())
    );
    let (mut muxer, bound) = av_recording::Muxer::from_lookahead(
        &init,
        &config,
        segment,
        2_000,
        0,
        32,
        32,
        Mp4Limits::default(),
    )?;
    assert_eq!(bound, observed);
    let (altered, _, _) = segments_with_cycle(10_000, true, 1, &config, 1)?;
    assert!(matches!(
        muxer.fragment(&init, &segments[1]),
        Err(av_recording::Error::Alignment)
    ));
    assert!(matches!(
        muxer.fragment_without_audio(&init, &altered[0]),
        Err(av_recording::Error::Alignment)
    ));
    let fragment = muxer.fragment_without_audio(&init, segment)?;
    assert!(fragment.audio().is_empty());
    flv_av::verify_archived_video_only_fragment(
        segment.fragment().bytes(),
        fragment.bytes(),
        Mp4Limits::default(),
    )?;
    let video_muxer = fss_container::flv_avc::Muxer::new(
        segment.fragment().key(),
        &video_configuration,
        Mp4Limits::default(),
    )?;
    let retention = fss_core::ContentDigest::sha256(b"synthetic no-audio retention");
    let limits = fss_reference::unifi_direct::evidence::Limits::default();
    let video_evidence = fss_reference::unifi_direct::evidence::Prepared::new(
        segment,
        &video_configuration,
        video_muxer.initialization(),
        retention,
        limits,
    )?;
    assert!(fss_reference::unifi_direct::av_evidence::PreparedAv::new_with_unverified_audio_configuration(
        &video_evidence, &config, &init, &fragment, limits,
    ).is_err());
    let candidate = fss_reference::unifi_direct::av_evidence::PreparedAvVideoOnly::new_with_unverified_audio_configuration(
        &video_evidence, &config, &init, &fragment, limits,
    )?;
    assert_eq!(
        candidate.manifest().kind(),
        "unifi-direct-flv-av-video-only-v1"
    );
    let mut metadata = fss_core::CanonicalDecoder::new(candidate.metadata());
    assert_eq!(
        metadata.text()?,
        "fss.unifi-direct.flv-av-video-only-evidence.v1"
    );
    assert_eq!(metadata.digest()?, retention);
    assert!(!metadata.bool()?);
    assert_eq!(metadata.digest()?, video_evidence.manifest().root());
    assert_eq!(metadata.u8()?, 0);
    assert!(!metadata.bool()?);
    assert_eq!(metadata.u8()?, 1); // Supplied AAC configuration is unverified.
    assert_eq!(
        metadata.digest()?,
        fss_core::ContentDigest::sha256(config.bytes())
    );
    assert_eq!(
        metadata.digest()?,
        fss_core::ContentDigest::sha256(init.bytes())
    );
    assert_eq!(metadata.u64()?, init.bytes().len() as u64);
    assert_eq!(
        metadata.digest()?,
        fss_core::ContentDigest::sha256(fragment.bytes())
    );
    assert_eq!(metadata.u64()?, fragment.bytes().len() as u64);
    assert_eq!(metadata.u64()?, 0); // Video mappings require no offset shift.
    assert_eq!(metadata.u64()?, 0); // No emitted AAC mappings.
    metadata.ensure_finished()?;
    let mut objects = 0;
    candidate.visit_objects(|_, _| objects += 1);
    assert!(objects >= 5);
    {
        use fss_core::{
            BudgetVector, ContentDigest, OperationId, RootAuthoritySpec, region::ContextAuthority,
        };
        use fss_geometry::WorkBudget;
        use fss_object::{
            HostSpoolIo,
            effect_journal::{EffectJournalLimits, FileEffectJournal},
        };
        use fss_reference::{ReferenceDeployment, ReplayCx, unifi_direct::archive};
        use std::{path::PathBuf, sync::Arc};
        struct Temp(PathBuf);
        impl Drop for Temp {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        struct Access(ContentDigest, bool);
        impl archive::RetainAuthority for Access {
            fn permits(&self, retention: ContentDigest, _: ContentDigest) -> bool {
                self.1 && retention == self.0
            }
        }
        impl archive::ReadAuthority for Access {
            fn permits(&self, retention: ContentDigest, _: ContentDigest) -> bool {
                self.1 && retention == self.0
            }
        }
        let temp =
            Temp(std::env::temp_dir().join(format!("fss-noaudio-archive-{}", std::process::id())));
        std::fs::create_dir(&temp.0)?;
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:noaudio-archive".into(),
            operation_id: OperationId::parse("operation:noaudio-archive")?,
            principal: "principal:fixture".into(),
            capabilities: vec!["ADP-REPLAY-001".into()],
            deadline: None,
            priority: 1,
            budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"noaudio archive fixture"),
            generation: 1,
        })?;
        let cx = ReplayCx::from_context_authority(&authority, temp.0.clone())?;
        let mut deployment =
            ReferenceDeployment::open(&temp.0.join("deployment"), "site:noaudio", &cx)?;
        let store = FileEffectJournal::create(
            temp.0.join("journal"),
            EffectJournalLimits::default(),
            Arc::new(HostSpoolIo),
        )?;
        let scope = ContentDigest::sha256(b"noaudio scope");
        let mut journal =
            archive::journal::UnknownTimeJournal::create(Box::new(store), scope, &cx)?;
        let journal_min = journal.anchor();
        let store = FileEffectJournal::create(
            temp.0.join("keeper"),
            EffectJournalLimits::default(),
            Arc::new(HostSpoolIo),
        )?;
        let mut keeper =
            archive::journal::UnknownTimeAnchorKeeper::create(Box::new(store), &journal, &cx)?;
        let keeper_min = keeper.anchor();
        let pin =
            archive::UnknownTimePin::from_av_video_only_plan(&candidate).ok_or("unknown pin")?;
        assert!(matches!(
            archive::publish_unknown_time_av_video_only_anchored(
                &candidate,
                &mut deployment,
                &Access(retention, false),
                archive::Limits::default(),
                &mut WorkBudget::new(4_000_000_000),
                &cx,
                &mut journal,
                &mut keeper,
            ),
            Err(archive::UnknownTimePublishError::Archive(
                archive::Error::Denied
            ))
        ));
        assert_eq!(journal.pending(), Some(pin));
        let receipt = archive::publish_unknown_time_av_video_only_anchored(
            &candidate,
            &mut deployment,
            &Access(retention, true),
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
            &mut journal,
            &mut keeper,
        )?;
        assert_eq!(receipt.root, pin.root);
        assert_eq!(journal.confirmed(), Some(pin));
        assert_eq!(keeper.target(), journal.anchor());
        drop(keeper);
        drop(journal);
        let store = FileEffectJournal::open(
            temp.0.join("journal"),
            EffectJournalLimits::default(),
            Arc::new(HostSpoolIo),
            journal_min,
        )?;
        let mut journal =
            archive::journal::UnknownTimeJournal::reopen(Box::new(store), scope, journal_min, &cx)?;
        let store = FileEffectJournal::open(
            temp.0.join("keeper"),
            EffectJournalLimits::default(),
            Arc::new(HostSpoolIo),
            keeper_min,
        )?;
        let mut keeper = archive::journal::UnknownTimeAnchorKeeper::reopen(
            Box::new(store),
            &journal,
            keeper_min,
            &cx,
        )?;
        assert_eq!(journal.replay_pin(), Some(pin));
        assert_eq!(keeper.target(), journal.anchor());
        drop(deployment);
        let mut reopened =
            ReferenceDeployment::open(&temp.0.join("deployment"), "site:noaudio", &cx)?;
        assert!(matches!(
            archive::read_unknown_time_av_any(
                &mut reopened,
                pin,
                &Access(retention, false),
                archive::Limits::default(),
                &mut WorkBudget::new(20_000_000_000),
                &cx,
            ),
            Err(archive::Error::Denied)
        ));
        assert!(matches!(
            archive::read_unknown_time_av_any(
                &mut reopened,
                pin,
                &Access(retention, true),
                archive::Limits::default(),
                &mut WorkBudget::new(20_000_000_000),
                &cx,
            )?,
            archive::RecoveredUnknownTimeAv::VideoOnly(_)
        ));
        let object_limits = archive::StagedAvLimits {
            max_objects: 8192,
            max_object_bytes: 64 * 1024 * 1024,
            max_total_bytes: 256 * 1024 * 1024,
        };
        assert!(matches!(
            archive::replay_confirmed_unknown_time_av_anchored(
                &mut reopened,
                &Access(retention, false),
                &Access(retention, true),
                archive::Limits::default(),
                object_limits,
                &mut WorkBudget::new(20_000_000_000),
                &cx,
                &mut journal,
                &mut keeper,
            ),
            Err(archive::ConfirmedAvReplayError::Readback(
                archive::Error::Denied
            ))
        ));
        assert_eq!(journal.replay_pin(), Some(pin));
        let replayed = archive::replay_confirmed_unknown_time_av_anchored(
            &mut reopened,
            &Access(retention, true),
            &Access(retention, true),
            archive::Limits::default(),
            object_limits,
            &mut WorkBudget::new(20_000_000_000),
            &cx,
            &mut journal,
            &mut keeper,
        )?;
        assert_eq!(
            replayed.outcome,
            fss_publication::RootLedgerOutcome::AlreadyLedgered
        );
        assert_eq!(journal.replay_pin(), None);
        assert_eq!(journal.confirmed(), Some(pin));
        assert!(matches!(
            archive::read_unknown_time_av_video_only_clip(
                &mut reopened,
                pin,
                &Access(retention, false),
                archive::Limits::default(),
                &mut WorkBudget::new(20_000_000_000),
                &cx,
            ),
            Err(archive::Error::Denied)
        ));
        struct Revoke(std::cell::Cell<usize>);
        impl archive::ReadAuthority for Revoke {
            fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
                let n = self.0.get();
                self.0.set(n + 1);
                n < 5
            }
        }
        let revoke = Revoke(std::cell::Cell::new(0));
        assert!(matches!(
            archive::read_unknown_time_av_video_only_clip(
                &mut reopened,
                pin,
                &revoke,
                archive::Limits::default(),
                &mut WorkBudget::new(20_000_000_000),
                &cx,
            ),
            Err(archive::Error::Denied)
        ));
        assert!(revoke.0.get() > 5);
        assert!(matches!(
            archive::read_unknown_time_av_clip(
                &mut reopened,
                pin,
                &Access(retention, true),
                archive::Limits::default(),
                &mut WorkBudget::new(20_000_000_000),
                &cx,
            ),
            Err(archive::Error::Mismatch)
        ));
        let recovered = archive::read_unknown_time_av_video_only_clip(
            &mut reopened,
            pin,
            &Access(retention, true),
            archive::Limits::default(),
            &mut WorkBudget::new(20_000_000_000),
            &cx,
        )?;
        assert_eq!(recovered.video_samples(), 1);
        assert_eq!(recovered.claimed_source(), segment.fragment().key());
        assert_eq!(
            recovered.configuration_origin(),
            fss_reference::unifi_direct::av_evidence::AudioConfigurationOrigin::SuppliedUnverified
        );
        let mut expected = init.bytes().to_vec();
        expected.extend_from_slice(fragment.bytes());
        assert_eq!(recovered.bytes(), expected);

        // Exercise the actual transactional muxer route, including a refused
        // first publication and a changed witness before the same-root retry.
        let (inner, _) = av_recording::Muxer::from_lookahead(
            &init,
            &config,
            segment,
            2_000,
            0,
            32,
            32,
            Mp4Limits::default(),
        )?;
        let mut transactional =
            archive::UnknownTimeMuxer::new(inner).map_err(|_| "muxer refused")?;
        let store = FileEffectJournal::create(
            temp.0.join("tx-journal"),
            EffectJournalLimits::default(),
            Arc::new(HostSpoolIo),
        )?;
        let mut tx_journal = archive::journal::UnknownTimeJournal::create(
            Box::new(store),
            ContentDigest::sha256(b"noaudio tx scope"),
            &cx,
        )?;
        let store = FileEffectJournal::create(
            temp.0.join("tx-keeper"),
            EffectJournalLimits::default(),
            Arc::new(HostSpoolIo),
        )?;
        let mut tx_keeper =
            archive::journal::UnknownTimeAnchorKeeper::create(Box::new(store), &tx_journal, &cx)?;
        let mut tx_deployment =
            ReferenceDeployment::open(&temp.0.join("tx-deployment"), "site:noaudio-tx", &cx)?;
        let first_input = archive::UnknownTimeAvSegment {
            segment,
            video_configuration: &video_configuration,
            video_initialization: video_muxer.initialization(),
            av_initialization: &init,
            audio: archive::AvSegmentAudio::SuppliedUnverified(&config),
            retention,
            evidence_limits: limits,
        };
        let altered_input = archive::UnknownTimeAvSegment {
            segment: &altered[0],
            audio: archive::AvSegmentAudio::SuppliedUnverified(&config),
            ..first_input
        };
        let remaining = transactional.remaining_audio_frames();
        assert!(matches!(
            archive::publish_next_unknown_time_av_segment_anchored(
                &first_input,
                &mut transactional,
                &mut tx_deployment,
                &Access(retention, false),
                archive::Limits::default(),
                &mut WorkBudget::new(4_000_000_000),
                &cx,
                &mut tx_journal,
                &mut tx_keeper,
            ),
            Err(archive::UnknownTimeSegmentError::Publication(
                archive::UnknownTimePublishError::Archive(archive::Error::Denied)
            ))
        ));
        assert_eq!(transactional.pending(), Some(pin));
        assert_eq!(transactional.remaining_audio_frames(), remaining);
        assert!(matches!(
            archive::publish_next_unknown_time_av_segment_anchored(
                &altered_input,
                &mut transactional,
                &mut tx_deployment,
                &Access(retention, true),
                archive::Limits::default(),
                &mut WorkBudget::new(4_000_000_000),
                &cx,
                &mut tx_journal,
                &mut tx_keeper,
            ),
            Err(archive::UnknownTimeSegmentError::Media(
                av_recording::Error::Alignment
            ))
        ));
        assert_eq!(transactional.pending(), Some(pin));
        let first = archive::publish_next_unknown_time_av_segment_anchored(
            &first_input,
            &mut transactional,
            &mut tx_deployment,
            &Access(retention, true),
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
            &mut tx_journal,
            &mut tx_keeper,
        )?;
        assert_eq!(first.pin, pin);
        assert_eq!(first.kind, archive::UnknownTimeAvKind::VideoOnly);
        assert_eq!(transactional.remaining_audio_frames(), remaining);
        let second_input = archive::UnknownTimeAvSegment {
            segment: &segments[1],
            audio: archive::AvSegmentAudio::SuppliedUnverified(&config),
            ..first_input
        };
        let second = archive::publish_next_unknown_time_av_segment_anchored(
            &second_input,
            &mut transactional,
            &mut tx_deployment,
            &Access(retention, true),
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
            &mut tx_journal,
            &mut tx_keeper,
        )?;
        assert_eq!(second.kind, archive::UnknownTimeAvKind::AudioVideo);
        assert_eq!(transactional.remaining_audio_frames(), remaining - 1);
        // A different source branch keeps the first boundary record unchanged
        // but alters the next copied video record. Both roots must be valid on
        // their own; joining roots from these branches must be refused.
        let (fork, fork_init, _, _) =
            segments_with_in_band(10_000, true, 0, &config, 1, false, true)?;
        assert_eq!(
            segment.lookahead_copies()[0].bytes(),
            fork[1].source()[0].bytes()
        );
        assert_ne!(
            segment.lookahead_copies()[1].bytes(),
            fork[1].source()[1].bytes()
        );
        assert_eq!(init.bytes(), fork_init.bytes());
        let (fork_muxer, _) = av_recording::Muxer::from_lookahead(
            &fork_init,
            &config,
            &fork[0],
            2_000,
            0,
            32,
            32,
            Mp4Limits::default(),
        )?;
        let mut fork_muxer =
            archive::UnknownTimeMuxer::new(fork_muxer).map_err(|_| "fork muxer")?;
        let store = FileEffectJournal::create(
            temp.0.join("fork-journal"),
            EffectJournalLimits::default(),
            Arc::new(HostSpoolIo),
        )?;
        let mut fork_journal = archive::journal::UnknownTimeJournal::create(
            Box::new(store),
            ContentDigest::sha256(b"fork scope"),
            &cx,
        )?;
        let store = FileEffectJournal::create(
            temp.0.join("fork-keeper"),
            EffectJournalLimits::default(),
            Arc::new(HostSpoolIo),
        )?;
        let mut fork_keeper =
            archive::journal::UnknownTimeAnchorKeeper::create(Box::new(store), &fork_journal, &cx)?;
        let fork_first = archive::UnknownTimeAvSegment {
            segment: &fork[0],
            audio: archive::AvSegmentAudio::SuppliedUnverified(&config),
            ..first_input
        };
        archive::publish_next_unknown_time_av_segment_anchored(
            &fork_first,
            &mut fork_muxer,
            &mut tx_deployment,
            &Access(retention, true),
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
            &mut fork_journal,
            &mut fork_keeper,
        )?;
        let fork_second_input = archive::UnknownTimeAvSegment {
            segment: &fork[1],
            audio: archive::AvSegmentAudio::SuppliedUnverified(&config),
            ..first_input
        };
        let fork_second = archive::publish_next_unknown_time_av_segment_anchored(
            &fork_second_input,
            &mut fork_muxer,
            &mut tx_deployment,
            &Access(retention, true),
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
            &mut fork_journal,
            &mut fork_keeper,
        )?;
        assert!(
            archive::read_unknown_time_av_clip(
                &mut tx_deployment,
                fork_second.pin,
                &Access(retention, true),
                archive::Limits::default(),
                &mut WorkBudget::new(20_000_000_000),
                &cx,
            )
            .is_ok()
        );
        let sequence_limits = archive::AvSequenceLimits {
            max_fragments: 2,
            max_bytes: 8 * 1024 * 1024,
        };
        let pins = [first.pin, second.pin];
        assert!(matches!(
            archive::read_unknown_time_av_sequence(
                &mut tx_deployment,
                &[first.pin, fork_second.pin],
                &Access(retention, true),
                archive::Limits::default(),
                sequence_limits,
                &mut WorkBudget::new(100_000_000_000),
                &cx,
            ),
            Err(archive::Error::Mismatch)
        ));
        assert!(matches!(
            archive::read_unknown_time_av_sequence(
                &mut tx_deployment,
                &pins,
                &Access(retention, false),
                archive::Limits::default(),
                sequence_limits,
                &mut WorkBudget::new(100_000_000_000),
                &cx,
            ),
            Err(archive::Error::Denied)
        ));
        struct DenySecond(ContentDigest);
        impl archive::ReadAuthority for DenySecond {
            fn permits(&self, _: ContentDigest, root: ContentDigest) -> bool {
                root != self.0
            }
        }
        assert!(matches!(
            archive::read_unknown_time_av_sequence(
                &mut tx_deployment,
                &pins,
                &DenySecond(second.pin.root),
                archive::Limits::default(),
                sequence_limits,
                &mut WorkBudget::new(100_000_000_000),
                &cx,
            ),
            Err(archive::Error::Denied)
        ));
        assert!(matches!(
            archive::read_unknown_time_av_sequence(
                &mut tx_deployment,
                &pins,
                &Access(retention, true),
                archive::Limits::default(),
                archive::AvSequenceLimits {
                    max_fragments: 1,
                    max_bytes: sequence_limits.max_bytes
                },
                &mut WorkBudget::new(100_000_000_000),
                &cx,
            ),
            Err(archive::Error::Limit)
        ));
        assert!(matches!(
            archive::read_unknown_time_av_sequence(
                &mut tx_deployment,
                &[second.pin, first.pin],
                &Access(retention, true),
                archive::Limits::default(),
                sequence_limits,
                &mut WorkBudget::new(100_000_000_000),
                &cx,
            ),
            Err(archive::Error::Mismatch)
        ));
        assert!(matches!(
            archive::read_unknown_time_av_sequence(
                &mut tx_deployment,
                &[first.pin, first.pin],
                &Access(retention, true),
                archive::Limits::default(),
                sequence_limits,
                &mut WorkBudget::new(100_000_000_000),
                &cx,
            ),
            Err(archive::Error::Mismatch)
        ));
        let sequence = archive::read_unknown_time_av_sequence(
            &mut tx_deployment,
            &pins,
            &Access(retention, true),
            archive::Limits::default(),
            sequence_limits,
            &mut WorkBudget::new(100_000_000_000),
            &cx,
        )?;
        assert_eq!(sequence.parts().len(), 2);
        assert!(sequence.parts()[0].audio.is_none());
        assert_eq!(
            sequence.parts()[1]
                .audio
                .ok_or("missing audio mapping")?
                .frames,
            1
        );
        assert_eq!(sequence.parts()[0].pin, first.pin);
        assert_eq!(sequence.parts()[1].pin, second.pin);
        let second_clip = archive::read_unknown_time_av_clip(
            &mut tx_deployment,
            second.pin,
            &Access(retention, true),
            archive::Limits::default(),
            &mut WorkBudget::new(20_000_000_000),
            &cx,
        )?;
        let mut expected_sequence = recovered.bytes().to_vec();
        expected_sequence.extend_from_slice(&second_clip.bytes()[init.bytes().len()..]);
        assert_eq!(sequence.bytes(), expected_sequence);
        assert!(
            archive::read_unknown_time_av_video_only_clip(
                &mut tx_deployment,
                first.pin,
                &Access(retention, true),
                archive::Limits::default(),
                &mut WorkBudget::new(20_000_000_000),
                &cx,
            )
            .is_ok()
        );
        assert!(
            archive::read_unknown_time_av_clip(
                &mut tx_deployment,
                second.pin,
                &Access(retention, true),
                archive::Limits::default(),
                &mut WorkBudget::new(20_000_000_000),
                &cx,
            )
            .is_ok()
        );
    }
    assert!(matches!(
        muxer.fragment(&init, &altered[1]),
        Err(av_recording::Error::Alignment)
    ));
    let next = muxer.fragment(&init, &segments[1])?;
    assert_eq!(next.video().sequence(), 2);
    assert_eq!(next.audio().len(), 1);
    let expected_frame = fss_packet::extended_flv::aac_adts::source_frame(
        &config,
        exact,
        FlvLimits::default(),
        aac::Limits::default(),
    )?
    .ok_or("missing witnessed audio frame")?;
    assert_eq!(next.audio()[0].source, expected_frame.body_range());
    let audio_video_evidence = fss_reference::unifi_direct::evidence::Prepared::new(
        &segments[1],
        &video_configuration,
        video_muxer.initialization(),
        retention,
        limits,
    )?;
    assert!(fss_reference::unifi_direct::av_evidence::PreparedAvVideoOnly::new_with_unverified_audio_configuration(
        &audio_video_evidence, &config, &init, &next, limits,
    ).is_err());
    let (absent, _) = first_segment_with_cycle(10_000, false, 0, &config, 1)?;
    assert_eq!(
        av_recording::lookahead_sender_clock_origin(&absent, &config, 2_000),
        Err(av_recording::Error::NoAudio)
    );
    let (with_audio, init) = first_segment(10_000, true, 0, &config)?;
    assert_eq!(
        av_recording::lookahead_sender_clock_origin(&with_audio, &config, 2_000),
        Err(av_recording::Error::Configuration)
    );
    let mut muxer = av_recording::Muxer::new(&init, &config, 0, 0, 32, 32, Mp4Limits::default())?;
    assert!(matches!(
        muxer.fragment_without_audio(&init, &with_audio),
        Err(av_recording::Error::Configuration)
    ));
    Ok(())
}

#[test]
fn source_segment_origin_is_used_by_the_muxer() -> TestResult {
    let config = aac::Configuration::parse_explicit(&[0x14, 0x08])?;
    let (segment, init) = first_segment(10_000, true, 0, &config)?;
    let origin = av_recording::segment_sender_clock_origin(&segment, &config, 2_000)?;
    assert_eq!(
        (origin.audio_minus_video_ms, origin.audio_ticks),
        (64, 161_024)
    );
    let mut muxer = av_recording::Muxer::new(
        &init,
        &config,
        origin.audio_ticks,
        0,
        32,
        32,
        Mp4Limits::default(),
    )?;
    let fragment = muxer.fragment(&init, &segment)?;
    assert_eq!(fragment.audio()[0].decode_ticks, 161_024);
    assert_eq!(segment.fragment().samples()[0].decode_time_ms, 10_000);
    flv_av::verify_archived_fragment(
        segment.fragment().bytes(),
        fragment.bytes(),
        fragment.audio(),
        Mp4Limits::default(),
    )?;
    Ok(())
}

#[test]
fn segment_origin_handles_wrap_and_refuses_missing_or_distant_audio() -> TestResult {
    let config = aac::Configuration::parse_explicit(&[0x14, 0x08])?;
    let (wrapped, _) = first_segment(u32::MAX - 50, true, 0, &config)?;
    let origin = av_recording::segment_sender_clock_origin(&wrapped, &config, 2_000)?;
    assert_eq!(origin.audio_minus_video_ms, 64);
    assert_eq!(origin.audio_ticks, (u64::from(u32::MAX) - 50 + 64) * 16);
    let (missing, _) = first_segment(10_000, false, 0, &config)?;
    assert_eq!(
        av_recording::segment_sender_clock_origin(&missing, &config, 2_000),
        Err(av_recording::Error::NoAudio)
    );
    let (distant, _) = first_segment(10_000, true, 5_000, &config)?;
    assert_eq!(
        av_recording::segment_sender_clock_origin(&distant, &config, 2_000),
        Err(av_recording::Error::Alignment)
    );
    Ok(())
}

#[cfg(unix)]
#[test]
#[ignore = "explicit synthetic output path required for independent MP4 probe"]
fn emit_synthetic_sender_clock_mp4_for_independent_probe() -> TestResult {
    use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt, path::PathBuf};

    let path =
        PathBuf::from(std::env::var_os("FSS_SYNTHETIC_MP4_OUTPUT").ok_or("missing output path")?);
    if !path.is_absolute() {
        return Err("output path must be absolute".into());
    }
    let config = aac::Configuration::parse_explicit(&[0x14, 0x08])?;
    let (segment, init) = first_segment(10_000, true, 0, &config)?;
    let origin = av_recording::segment_sender_clock_origin(&segment, &config, 2_000)?;
    let mut muxer = av_recording::Muxer::new(
        &init,
        &config,
        origin.audio_ticks,
        0,
        32,
        32,
        Mp4Limits::default(),
    )?;
    let fragment = muxer.fragment(&init, &segment)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(init.bytes())?;
    file.write_all(fragment.bytes())?;
    file.sync_all()?;
    Ok(())
}
