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

#[test]
fn consecutive_av_segments_publish_and_reopen_with_contiguous_audio() -> TestResult {
    use fss_container::Mp4Limits;
    use fss_core::{
        BudgetVector, CaptureInterval, ContentDigest, OperationId, RootAuthoritySpec, TimestampNs,
        region::ContextAuthority,
    };
    use fss_geometry::WorkBudget;
    use fss_packet::extended_flv::aac;
    use fss_publication::RootLedgerOutcome;
    use fss_reference::{
        ReferenceDeployment, ReplayCx,
        unifi_direct::{
            archive::{self, ReadAuthority, RetainAuthority},
            av_evidence::{AudioConfigurationOrigin, PreparedAv},
            av_recording,
            evidence::{Limits as EvidenceLimits, Prepared},
        },
    };
    use std::path::PathBuf;

    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    struct Access(ContentDigest);
    impl RetainAuthority for Access {
        fn permits(&self, retention: ContentDigest, _: ContentDigest) -> bool {
            retention == self.0
        }
    }
    impl ReadAuthority for Access {
        fn permits(&self, retention: ContentDigest, _: ContentDigest) -> bool {
            retention == self.0
        }
    }

    // Synthetic 40 ms AVC and 64 ms AAC clocks. Capture intervals are
    // fixture inputs, not a claim about camera wall-clock time or coverage.
    let (_, records) = fixture_with_audio_intervals(0, false, false, false, Some(64))?;
    let config_bytes = [0x14, 0x08];
    let config = aac::Configuration::parse_explicit(&config_bytes)?;
    let mut recorder = Recorder::new(KEY, Limits::default())?;
    let mut video_source = None;
    let mut segments = Vec::new();
    for record in records {
        match recorder.push(record).map_err(|refusal| refusal.reason)? {
            Push::Source {
                record,
                disposition: SourceDisposition::Configuration,
            } => {
                video_source = Some(record);
            }
            Push::Segment(segment) => segments.push(segment),
            _ => {}
        }
    }
    assert_eq!(segments.len(), 2);
    let video_init = recorder
        .initialization()
        .ok_or("missing video initialization")?;
    let av_init = recorder
        .av_initialization(&config)?
        .ok_or("missing A/V initialization")?;
    let mut muxer = av_recording::Muxer::new(&av_init, &config, 0, 0, 8, 8, Mp4Limits::default())?;
    let first_fragment = muxer.fragment(&av_init, &segments[0])?;
    let second_fragment = muxer.fragment(&av_init, &segments[1])?;
    let retention = ContentDigest::sha256(b"synthetic multi-segment retention");
    let first_capture = CaptureInterval::new(TimestampNs(1), TimestampNs(10))?;
    let second_capture = CaptureInterval::new(TimestampNs(11), TimestampNs(20))?;
    let video_source = video_source
        .as_ref()
        .ok_or("missing video configuration source")?;
    let first_video = Prepared::new_with_capture(
        &segments[0],
        video_source,
        video_init,
        retention,
        Some(first_capture),
        EvidenceLimits::default(),
    )?;
    let second_video = Prepared::new_with_capture(
        &segments[1],
        video_source,
        video_init,
        retention,
        Some(second_capture),
        EvidenceLimits::default(),
    )?;
    let first = PreparedAv::new_with_unverified_audio_configuration(
        &first_video,
        &config,
        &av_init,
        &first_fragment,
        EvidenceLimits::default(),
    )?;
    let second = PreparedAv::new_with_unverified_audio_configuration(
        &second_video,
        &config,
        &av_init,
        &second_fragment,
        EvidenceLimits::default(),
    )?;
    let first_pin = archive::Pin::from_av_plan(&first).ok_or("first pin")?;
    let second_pin = archive::Pin::from_av_plan(&second).ok_or("second pin")?;
    assert_ne!(first.manifest().root(), second.manifest().root());

    let temp = Temp(
        std::env::temp_dir().join(format!("fss-unifi-av-multisegment-{}", std::process::id())),
    );
    std::fs::create_dir(&temp.0)?;
    let context = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:unifi-av-multisegment".into(),
        operation_id: OperationId::parse("operation:unifi-av-multisegment")?,
        principal: "principal:unifi-av-multisegment".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"site:unifi-av-multisegment"),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&context, temp.0.clone())?;
    let access = Access(retention);
    let mut deployment = ReferenceDeployment::open(
        &temp.0.join("deployment"),
        "site:unifi-av-multisegment",
        &cx,
    )?;
    for plan in [&first, &second] {
        assert_eq!(
            archive::publish_av(
                plan,
                &mut deployment,
                &access,
                archive::Limits::default(),
                &mut WorkBudget::new(4_000_000_000),
                &cx
            )?
            .outcome,
            RootLedgerOutcome::Committed
        );
    }
    drop(deployment);
    let mut reopened = ReferenceDeployment::open(
        &temp.0.join("deployment"),
        "site:unifi-av-multisegment",
        &cx,
    )?;
    let first_read = archive::read_av_clip(
        &mut reopened,
        first_pin,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(20_000_000_000),
        &cx,
    )?;
    let second_read = archive::read_av_clip(
        &mut reopened,
        second_pin,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(20_000_000_000),
        &cx,
    )?;
    assert_eq!(first_read.capture(), first_capture);
    assert_eq!(second_read.capture(), second_capture);
    assert_eq!(
        first_read.audio().configuration_origin,
        AudioConfigurationOrigin::SuppliedUnverified
    );
    assert_eq!(
        second_read.audio().configuration_origin,
        AudioConfigurationOrigin::SuppliedUnverified
    );
    assert_eq!(
        first_read.audio().end_decode_ticks,
        second_read.audio().first_decode_ticks
    );
    let mut expected_first = av_init.bytes().to_vec();
    expected_first.extend_from_slice(first_fragment.bytes());
    let mut expected_second = av_init.bytes().to_vec();
    expected_second.extend_from_slice(second_fragment.bytes());
    assert_eq!(first_read.bytes(), expected_first);
    assert_eq!(second_read.bytes(), expected_second);

    let sequence_limits = archive::AvSequenceLimits {
        max_fragments: 2,
        max_bytes: 1024 * 1024,
    };
    let read_sequence = |deployment: &mut ReferenceDeployment,
                         pins: &[archive::Pin],
                         authority: &dyn ReadAuthority,
                         limits: archive::AvSequenceLimits| {
        archive::read_av_sequence(
            deployment,
            pins,
            authority,
            archive::Limits::default(),
            limits,
            &mut WorkBudget::new(100_000_000_000),
            &cx,
        )
    };
    let joined = read_sequence(
        &mut reopened,
        &[first_pin, second_pin],
        &access,
        sequence_limits,
    )?;
    let mut expected_joined = expected_first.clone();
    expected_joined.extend_from_slice(second_fragment.bytes());
    assert_eq!(joined.bytes(), expected_joined);
    assert_eq!(joined.parts().len(), 2);
    assert_eq!(joined.parts()[0].pin, first_pin);
    assert_eq!(joined.parts()[1].pin, second_pin);
    assert_eq!(
        joined.parts()[1].audio.configuration_origin,
        AudioConfigurationOrigin::SuppliedUnverified
    );
    let movie = AvcMp4::parse(joined.bytes(), None, DemuxLimits::default())?;
    assert_eq!(movie.samples().len(), 6);
    let annex = movie.annex_b(0, 6)?;
    let mut decoder = fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
    let mut frames = decoder.decode_annex_b(annex.bytes())?;
    frames.extend(decoder.finish()?);
    assert_eq!(frames.len(), 6);
    for pins in [&[second_pin, first_pin][..], &[first_pin, first_pin][..]] {
        assert!(matches!(
            read_sequence(&mut reopened, pins, &access, sequence_limits),
            Err(archive::Error::Mismatch)
        ));
    }
    assert!(matches!(
        read_sequence(&mut reopened, &[], &access, sequence_limits),
        Err(archive::Error::Limit)
    ));
    assert!(matches!(
        read_sequence(
            &mut reopened,
            &[first_pin, second_pin],
            &access,
            archive::AvSequenceLimits {
                max_fragments: 1,
                ..sequence_limits
            }
        ),
        Err(archive::Error::Limit)
    ));
    assert!(matches!(
        read_sequence(
            &mut reopened,
            &[first_pin, second_pin],
            &access,
            archive::AvSequenceLimits {
                max_bytes: 1,
                ..sequence_limits
            }
        ),
        Err(archive::Error::Limit)
    ));

    struct RevokeFirstAfterSecond {
        first: ContentDigest,
        second: ContentDigest,
        seen_second: std::cell::Cell<bool>,
    }
    impl ReadAuthority for RevokeFirstAfterSecond {
        fn permits(&self, _: ContentDigest, root: ContentDigest) -> bool {
            if root == self.second {
                self.seen_second.set(true);
            }
            root != self.first || !self.seen_second.get()
        }
    }
    let revoke = RevokeFirstAfterSecond {
        first: first_pin.root,
        second: second_pin.root,
        seen_second: std::cell::Cell::new(false),
    };
    assert!(matches!(
        read_sequence(
            &mut reopened,
            &[first_pin, second_pin],
            &revoke,
            sequence_limits
        ),
        Err(archive::Error::Denied)
    ));

    // Derive directly into a separate archive. A refused or budget-exhausted
    // publication must not consume the segment's audio/video mux position.
    struct DenyRetention;
    impl RetainAuthority for DenyRetention {
        fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
            false
        }
    }
    let mut target = ReferenceDeployment::open(
        &temp.0.join("transactional"),
        "site:unifi-av-multisegment",
        &cx,
    )?;
    let mut transactional =
        av_recording::Muxer::new(&av_init, &config, 0, 0, 8, 8, Mp4Limits::default())?;
    let first_input = archive::AvSegmentPublication {
        segment: &segments[0],
        video_configuration: video_source,
        video_initialization: video_init,
        av_initialization: &av_init,
        audio: archive::AvSegmentAudio::SuppliedUnverified(&config),
        retention,
        capture: first_capture,
        evidence_limits: EvidenceLimits::default(),
    };
    let second_input = archive::AvSegmentPublication {
        segment: &segments[1],
        video_configuration: video_source,
        video_initialization: video_init,
        av_initialization: &av_init,
        audio: archive::AvSegmentAudio::SuppliedUnverified(&config),
        retention,
        capture: second_capture,
        evidence_limits: EvidenceLimits::default(),
    };
    let before = transactional.remaining_audio_frames();
    let denied = archive::publish_next_av_segment(
        &first_input,
        &mut transactional,
        &mut target,
        &DenyRetention,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &cx,
    );
    assert!(
        matches!(denied, Err(archive::AvSegmentPublishError::Archive { pin, source: archive::Error::Denied }) if pin == first_pin)
    );
    assert_eq!(transactional.remaining_audio_frames(), before);
    assert_eq!(transactional.pending_publication(), Some(first_pin));
    assert!(matches!(
        transactional.fragment(&av_init, &segments[0]),
        Err(av_recording::Error::PublicationPending)
    ));
    assert!(matches!(
        transactional.extend_audio_limit(1),
        Err(av_recording::Error::PublicationPending)
    ));
    struct CountRetention(std::cell::Cell<usize>);
    impl RetainAuthority for CountRetention {
        fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
            self.0.set(self.0.get() + 1);
            true
        }
    }
    let different_capture = archive::AvSegmentPublication {
        segment: &segments[0],
        video_configuration: video_source,
        video_initialization: video_init,
        av_initialization: &av_init,
        audio: archive::AvSegmentAudio::SuppliedUnverified(&config),
        retention,
        capture: CaptureInterval::new(TimestampNs(2), TimestampNs(10))?,
        evidence_limits: EvidenceLimits::default(),
    };
    let count_access = CountRetention(std::cell::Cell::new(0));
    let mismatched = archive::publish_next_av_segment(
        &different_capture,
        &mut transactional,
        &mut target,
        &count_access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &cx,
    );
    assert!(
        matches!(mismatched, Err(archive::AvSegmentPublishError::PendingMismatch { expected, proposed }) if expected == first_pin && proposed != first_pin)
    );
    assert_eq!(count_access.0.get(), 0);
    assert_eq!(transactional.pending_publication(), Some(first_pin));
    let budget_refusal = archive::publish_next_av_segment(
        &first_input,
        &mut transactional,
        &mut target,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(0),
        &cx,
    );
    assert!(
        matches!(budget_refusal, Err(archive::AvSegmentPublishError::Archive { pin, source: archive::Error::Work(_) }) if pin == first_pin)
    );
    assert_eq!(transactional.remaining_audio_frames(), before);
    struct PanicDuringStaging(std::cell::Cell<usize>);
    impl RetainAuthority for PanicDuringStaging {
        fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
            let calls = self.0.get() + 1;
            self.0.set(calls);
            assert!(calls < 3, "synthetic staging interruption");
            true
        }
    }
    // The first attempted effect on a fresh muxer must establish the fence
    // before a callback can unwind, not merely preserve an older fence.
    let mut panic_muxer =
        av_recording::Muxer::new(&av_init, &config, 0, 0, 8, 8, Mp4Limits::default())?;
    let mut panic_target = ReferenceDeployment::open(
        &temp.0.join("panic-interruption"),
        "site:unifi-av-multisegment",
        &cx,
    )?;
    let first_panic = PanicDuringStaging(std::cell::Cell::new(0));
    let first_interruption = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        archive::publish_next_av_segment(
            &first_input,
            &mut panic_muxer,
            &mut panic_target,
            &first_panic,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
        )
    }));
    assert!(first_interruption.is_err());
    assert_eq!(panic_muxer.pending_publication(), Some(first_pin));
    assert_eq!(panic_muxer.remaining_audio_frames(), before);
    let panic_retry = archive::publish_next_av_segment(
        &first_input,
        &mut panic_muxer,
        &mut panic_target,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &cx,
    )?;
    assert_eq!(panic_retry.pin, first_pin);
    assert_eq!(panic_retry.receipt.outcome, RootLedgerOutcome::Committed);
    assert_eq!(panic_muxer.pending_publication(), None);

    let panic_staging = PanicDuringStaging(std::cell::Cell::new(0));
    let interruption = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        archive::publish_next_av_segment(
            &first_input,
            &mut transactional,
            &mut target,
            &panic_staging,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
        )
    }));
    assert!(interruption.is_err());
    assert_eq!(transactional.pending_publication(), Some(first_pin));
    assert_eq!(transactional.remaining_audio_frames(), before);
    struct RevokeDuringStaging(std::cell::Cell<usize>);
    impl RetainAuthority for RevokeDuringStaging {
        fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
            let calls = self.0.get() + 1;
            self.0.set(calls);
            calls < 3
        }
    }
    let revoke_staging = RevokeDuringStaging(std::cell::Cell::new(0));
    let partial = archive::publish_next_av_segment(
        &first_input,
        &mut transactional,
        &mut target,
        &revoke_staging,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &cx,
    );
    assert!(
        matches!(partial, Err(archive::AvSegmentPublishError::Archive { pin, source: archive::Error::Denied }) if pin == first_pin)
    );
    assert_eq!(transactional.remaining_audio_frames(), before);
    assert_eq!(
        target
            .publisher()
            .spool()
            .read(ContentDigest::sha256(video_source.bytes()))?,
        video_source.bytes()
    );
    assert!(matches!(
        archive::read_av_clip(
            &mut target,
            first_pin,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(20_000_000_000),
            &cx,
        ),
        Err(archive::Error::NotCommitted)
    ));
    let first_committed = archive::publish_next_av_segment(
        &first_input,
        &mut transactional,
        &mut target,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &cx,
    )?;
    assert_eq!(first_committed.pin, first_pin);
    assert_eq!(
        first_committed.receipt.outcome,
        RootLedgerOutcome::Committed
    );
    assert_eq!(transactional.pending_publication(), None);
    let after_first = transactional.remaining_audio_frames();
    assert!(after_first < before);
    assert!(matches!(
        archive::publish_next_av_segment(
            &first_input,
            &mut transactional,
            &mut target,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx
        ),
        Err(archive::AvSegmentPublishError::Media(_))
    ));
    assert_eq!(transactional.remaining_audio_frames(), after_first);
    let second_committed = archive::publish_next_av_segment(
        &second_input,
        &mut transactional,
        &mut target,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &cx,
    )?;
    assert_eq!(second_committed.pin, second_pin);
    assert_eq!(
        second_committed.receipt.outcome,
        RootLedgerOutcome::Committed
    );
    let recovered = read_sequence(
        &mut target,
        &[first_committed.pin, second_committed.pin],
        &access,
        sequence_limits,
    )?;
    assert_eq!(recovered.bytes(), expected_joined);

    // Reconstructing the muxer after an uncertain acknowledgment uses the
    // same roots; the ledger returns idempotent receipts rather than new roots.
    let mut replay = av_recording::Muxer::new(&av_init, &config, 0, 0, 8, 8, Mp4Limits::default())?;
    for (input, expected_pin) in [(&first_input, first_pin), (&second_input, second_pin)] {
        let result = archive::publish_next_av_segment(
            input,
            &mut replay,
            &mut target,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
        )?;
        assert_eq!(result.pin, expected_pin);
        assert_eq!(result.receipt.outcome, RootLedgerOutcome::AlreadyLedgered);
    }

    // A file-backed intent survives owner loss; raw source and muxer state in
    // this synthetic fixture are reconstructed separately by the caller.
    use fss_object::{
        HostSpoolIo,
        effect_journal::{EffectJournalLimits, FileEffectJournal},
    };
    use fss_runtime::effect_journal::{
        EffectJournalPin, EffectJournalStore, EffectPersistenceError,
    };
    use std::sync::Arc;
    // Unknown capture time can advance across two segments, while a denied
    // first attempt retains the exact candidate and leaves its clock intact.
    let unknown_scope = ContentDigest::sha256(b"unknown-time transactional fixture");
    let unknown_journal_path = temp.0.join("unknown-transaction-journal");
    let unknown_keeper_path = temp.0.join("unknown-transaction-keeper");
    let store = FileEffectJournal::create(
        &unknown_journal_path,
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut unknown_journal =
        archive::journal::UnknownTimeJournal::create(Box::new(store), unknown_scope, &cx)?;
    let journal_min = unknown_journal.anchor();
    let store = FileEffectJournal::create(
        &unknown_keeper_path,
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut unknown_keeper =
        archive::journal::UnknownTimeAnchorKeeper::create(Box::new(store), &unknown_journal, &cx)?;
    let keeper_min = unknown_keeper.anchor();
    let mut unknown_target = ReferenceDeployment::open(
        &temp.0.join("unknown-transaction-target"),
        "site:unifi-av-multisegment",
        &cx,
    )?;
    let inner = av_recording::Muxer::new(&av_init, &config, 0, 0, 8, 8, Mp4Limits::default())?;
    let mut unknown_muxer = archive::UnknownTimeMuxer::new(inner).map_err(|_| "muxer not idle")?;
    let first_unknown_input = archive::UnknownTimeAvSegment {
        segment: &segments[0],
        video_configuration: video_source,
        video_initialization: video_init,
        av_initialization: &av_init,
        audio: archive::AvSegmentAudio::SuppliedUnverified(&config),
        retention,
        evidence_limits: EvidenceLimits::default(),
    };
    let second_unknown_input = archive::UnknownTimeAvSegment {
        segment: &segments[1],
        video_configuration: video_source,
        video_initialization: video_init,
        av_initialization: &av_init,
        audio: archive::AvSegmentAudio::SuppliedUnverified(&config),
        retention,
        evidence_limits: EvidenceLimits::default(),
    };
    let before = unknown_muxer.remaining_audio_frames();
    assert!(matches!(
        archive::publish_next_unknown_time_av_segment_anchored(
            &first_unknown_input,
            &mut unknown_muxer,
            &mut unknown_target,
            &DenyRetention,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
            &mut unknown_journal,
            &mut unknown_keeper,
        ),
        Err(archive::UnknownTimeSegmentError::Publication(
            archive::UnknownTimePublishError::Archive(archive::Error::Denied)
        ))
    ));
    let pending = unknown_muxer.pending().ok_or("unknown candidate missing")?;
    assert_eq!(unknown_journal.pending(), Some(pending));
    assert_eq!(unknown_muxer.remaining_audio_frames(), before);
    assert!(
        archive::publish_next_unknown_time_av_segment_anchored(
            &second_unknown_input,
            &mut unknown_muxer,
            &mut unknown_target,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
            &mut unknown_journal,
            &mut unknown_keeper,
        )
        .is_err()
    );
    assert_eq!(unknown_muxer.pending(), Some(pending));
    assert_eq!(unknown_muxer.remaining_audio_frames(), before);
    let first_unknown = archive::publish_next_unknown_time_av_segment_anchored(
        &first_unknown_input,
        &mut unknown_muxer,
        &mut unknown_target,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &cx,
        &mut unknown_journal,
        &mut unknown_keeper,
    )?;
    assert_eq!(first_unknown.pin, pending);
    assert_eq!(unknown_muxer.pending(), None);
    let second_unknown = archive::publish_next_unknown_time_av_segment_anchored(
        &second_unknown_input,
        &mut unknown_muxer,
        &mut unknown_target,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &cx,
        &mut unknown_journal,
        &mut unknown_keeper,
    )?;
    assert_ne!(first_unknown.pin, second_unknown.pin);
    for (index, pin) in [first_unknown.pin, second_unknown.pin]
        .into_iter()
        .enumerate()
    {
        let clip = archive::read_unknown_time_av_clip(
            &mut unknown_target,
            pin,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(20_000_000_000),
            &cx,
        )?;
        assert_eq!(
            clip.video_samples(),
            segments[index].fragment().samples().len()
        );
        assert!(clip.audio().frames > 0);
    }
    assert_eq!(unknown_journal.confirmed(), Some(second_unknown.pin));
    assert_eq!(unknown_keeper.target(), unknown_journal.anchor());
    drop(unknown_keeper);
    drop(unknown_journal);
    let store = FileEffectJournal::open(
        &unknown_journal_path,
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
        journal_min,
    )?;
    let unknown_journal = archive::journal::UnknownTimeJournal::reopen(
        Box::new(store),
        unknown_scope,
        journal_min,
        &cx,
    )?;
    let store = FileEffectJournal::open(
        &unknown_keeper_path,
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
        keeper_min,
    )?;
    let unknown_keeper = archive::journal::UnknownTimeAnchorKeeper::reopen(
        Box::new(store),
        &unknown_journal,
        keeper_min,
        &cx,
    )?;
    assert_eq!(unknown_journal.replay_pin(), Some(second_unknown.pin));
    assert_eq!(unknown_keeper.target(), unknown_journal.anchor());
    drop(unknown_keeper);
    drop(unknown_journal);

    let scope = ContentDigest::sha256(b"synthetic unifi intent scope");
    let journal_path = temp.0.join("av-intent-journal");
    let store = FileEffectJournal::create(
        &journal_path,
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut journal = archive::journal::Journal::create(Box::new(store), scope, &cx)?;
    let genesis = journal.anchor();
    let mut journal_target =
        ReferenceDeployment::open(&temp.0.join("journaled"), "site:unifi-av-multisegment", &cx)?;
    let mut journal_muxer =
        av_recording::Muxer::new(&av_init, &config, 0, 0, 8, 8, Mp4Limits::default())?;
    assert!(matches!(archive::publish_next_av_segment_journaled(
        &first_input, &mut journal_muxer, &mut journal_target, &DenyRetention,
        archive::Limits::default(), &mut WorkBudget::new(4_000_000_000), &cx, &mut journal,
    ), Err(archive::AvSegmentPublishError::Archive { pin, source: archive::Error::Denied }) if pin == first_pin));
    assert_eq!(journal.pending(), Some(first_pin));
    assert!(matches!(
        archive::verify_staged_av_candidate(
            &journal_target,
            &journal,
            &access,
            archive::StagedAvLimits {
                max_objects: 8192,
                max_object_bytes: 1024 * 1024,
                max_total_bytes: 8 * 1024 * 1024
            },
            &mut WorkBudget::new(100_000_000_000),
            &cx,
        ),
        Err(archive::Error::Storage(_))
    ));
    let pending_anchor = journal.anchor();
    drop(journal);
    drop(journal_muxer);
    drop(journal_target);
    let store = FileEffectJournal::open(
        &journal_path,
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
        genesis,
    )?;
    let mut journal = archive::journal::Journal::reopen(Box::new(store), scope, genesis, &cx)?;
    assert_eq!(journal.pending(), Some(first_pin));
    let mut journal_target =
        ReferenceDeployment::open(&temp.0.join("journaled"), "site:unifi-av-multisegment", &cx)?;
    let mut journal_muxer =
        av_recording::Muxer::new(&av_init, &config, 0, 0, 8, 8, Mp4Limits::default())?;
    assert!(matches!(archive::publish_next_av_segment_journaled(
        &different_capture, &mut journal_muxer, &mut journal_target, &count_access,
        archive::Limits::default(), &mut WorkBudget::new(4_000_000_000), &cx, &mut journal,
    ), Err(archive::AvSegmentPublishError::PendingMismatch { expected, .. }) if expected == first_pin));
    assert_eq!(journal_muxer.pending_publication(), Some(first_pin));
    let committed = archive::publish_next_av_segment_journaled(
        &first_input,
        &mut journal_muxer,
        &mut journal_target,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &cx,
        &mut journal,
    )?;
    assert_eq!(committed.pin, first_pin);
    assert_eq!(committed.receipt.outcome, RootLedgerOutcome::Committed);
    assert_eq!(journal.pending(), None);
    assert_eq!(journal.confirmed(), Some(first_pin));
    assert!(matches!(
        journal_muxer.fragment(&av_init, &segments[1]),
        Err(av_recording::Error::JournalRequired)
    ));
    assert!(matches!(
        archive::publish_next_av_segment(
            &second_input,
            &mut journal_muxer,
            &mut journal_target,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
        ),
        Err(archive::AvSegmentPublishError::JournalScope)
    ));
    let other_store = FileEffectJournal::create(
        temp.0.join("other-intent-journal"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut other_journal = archive::journal::Journal::create(
        Box::new(other_store),
        ContentDigest::sha256(b"other scope"),
        &cx,
    )?;
    assert!(matches!(
        archive::publish_next_av_segment_journaled(
            &second_input,
            &mut journal_muxer,
            &mut journal_target,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
            &mut other_journal,
        ),
        Err(archive::AvSegmentPublishError::JournalScope)
    ));
    assert_eq!(other_journal.pending(), None);
    drop(other_journal);
    drop(journal);
    let store = FileEffectJournal::open(
        &journal_path,
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
        pending_anchor,
    )?;
    let journal = archive::journal::Journal::reopen(Box::new(store), scope, pending_anchor, &cx)?;
    assert_eq!(journal.confirmed(), Some(first_pin));
    drop(journal);

    // Force a lost journal acknowledgment after the archive's actual commit.
    // Cold reopening discovers the already-durable confirmation and preserves
    // the actual archive receipt returned with the journal error.
    #[derive(Debug)]
    struct LoseConfirmation {
        inner: FileEffectJournal,
        fenced: bool,
        lose_sequence: u64,
    }
    impl EffectJournalStore for LoseConfirmation {
        fn head(&self) -> Option<EffectJournalPin> {
            self.inner.head()
        }
        fn records(&self) -> &[Vec<u8>] {
            self.inner.records()
        }
        fn contains(&self, pin: EffectJournalPin) -> bool {
            self.inner.contains(pin)
        }
        fn reserve_capacity(
            &mut self,
            count: usize,
            bytes: usize,
        ) -> Result<(), EffectPersistenceError> {
            if self.fenced {
                return Err(EffectPersistenceError::Poisoned);
            }
            self.inner.reserve_capacity(count, bytes)
        }
        fn append(
            &mut self,
            expected: Option<EffectJournalPin>,
            record: &[u8],
        ) -> Result<EffectJournalPin, EffectPersistenceError> {
            if self.fenced {
                return Err(EffectPersistenceError::Poisoned);
            }
            let pin = self.inner.append(expected, record)?;
            if pin.sequence == self.lose_sequence {
                self.fenced = true;
                return Err(EffectPersistenceError::Storage(
                    "synthetic lost acknowledgment".into(),
                ));
            }
            Ok(pin)
        }
    }
    // Each file-backed keeper records the intent before any archive access,
    // and the confirmation after a real receipt. Lose each acknowledgment in
    // turn, then reopen both owners and reconcile the same root.
    for lost_sequence in [2_u64, 3] {
        let journal_path = temp.0.join(format!("anchored-journal-{lost_sequence}"));
        let keeper_path = temp.0.join(format!("anchored-keeper-{lost_sequence}"));
        let target_path = temp.0.join(format!("anchored-target-{lost_sequence}"));
        let store = FileEffectJournal::create(
            &journal_path,
            EffectJournalLimits::default(),
            Arc::new(HostSpoolIo),
        )?;
        let mut journal = archive::journal::Journal::create(Box::new(store), scope, &cx)?;
        let journal_genesis = journal.anchor();
        let store = FileEffectJournal::create(
            &keeper_path,
            EffectJournalLimits::default(),
            Arc::new(HostSpoolIo),
        )?;
        let mut keeper = archive::journal::AnchorKeeper::create(
            Box::new(LoseConfirmation {
                inner: store,
                fenced: false,
                lose_sequence: lost_sequence,
            }),
            &journal,
            &cx,
        )?;
        let keeper_genesis = keeper.anchor();
        assert_eq!(keeper.target(), journal_genesis);
        let mut target =
            ReferenceDeployment::open(&target_path, "site:unifi-av-multisegment", &cx)?;
        let mut muxer =
            av_recording::Muxer::new(&av_init, &config, 0, 0, 8, 8, Mp4Limits::default())?;
        let counted = CountRetention(std::cell::Cell::new(0));
        let result = archive::publish_next_av_segment_anchored(
            &first_input,
            &mut muxer,
            &mut target,
            &counted,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
            &mut journal,
            &mut keeper,
        );
        if lost_sequence == 2 {
            assert!(
                matches!(result, Err(archive::AvSegmentPublishError::AnchorBefore { pin, .. }) if pin == first_pin)
            );
            assert_eq!(counted.0.get(), 0);
            assert_eq!(journal.pending(), Some(first_pin));
        } else {
            assert!(
                matches!(result, Err(archive::AvSegmentPublishError::AnchorAfterCommit { pin, receipt, .. }) if pin == first_pin && receipt.outcome == RootLedgerOutcome::Committed)
            );
            assert_eq!(journal.confirmed(), Some(first_pin));
        }
        assert_eq!(muxer.pending_publication(), Some(first_pin));
        drop(keeper);
        drop(journal);
        drop(target);
        drop(muxer);
        let store = FileEffectJournal::open(
            &journal_path,
            EffectJournalLimits::default(),
            Arc::new(HostSpoolIo),
            journal_genesis,
        )?;
        let mut journal =
            archive::journal::Journal::reopen(Box::new(store), scope, journal_genesis, &cx)?;
        let store = FileEffectJournal::open(
            &keeper_path,
            EffectJournalLimits::default(),
            Arc::new(HostSpoolIo),
            keeper_genesis,
        )?;
        let mut keeper =
            archive::journal::AnchorKeeper::reopen(Box::new(store), &journal, keeper_genesis, &cx)?;
        assert_eq!(keeper.target(), journal.anchor());
        let mut target =
            ReferenceDeployment::open(&target_path, "site:unifi-av-multisegment", &cx)?;
        let mut muxer =
            av_recording::Muxer::new(&av_init, &config, 0, 0, 8, 8, Mp4Limits::default())?;
        let receipt = archive::publish_next_av_segment_anchored(
            &first_input,
            &mut muxer,
            &mut target,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
            &mut journal,
            &mut keeper,
        )?;
        assert_eq!(
            receipt.receipt.outcome,
            if lost_sequence == 2 {
                RootLedgerOutcome::Committed
            } else {
                RootLedgerOutcome::AlreadyLedgered
            }
        );
        assert_eq!(keeper.target(), journal.anchor());
        assert_eq!(muxer.pending_publication(), None);
        let keeper_minimum = keeper.anchor();
        drop(keeper);
        drop(journal);
        let store = FileEffectJournal::open(
            &journal_path,
            EffectJournalLimits::default(),
            Arc::new(HostSpoolIo),
            journal_genesis,
        )?;
        let journal =
            archive::journal::Journal::reopen(Box::new(store), scope, journal_genesis, &cx)?;
        let store = FileEffectJournal::open(
            &keeper_path,
            EffectJournalLimits::default(),
            Arc::new(HostSpoolIo),
            keeper_minimum,
        )?;
        let keeper =
            archive::journal::AnchorKeeper::reopen(Box::new(store), &journal, keeper_minimum, &cx)?;
        assert_eq!(keeper.target(), journal.anchor());
        drop(keeper);
        // A valid but shorter same-scope journal cannot satisfy the keeper's
        // retained later prefix, even when its own genesis is valid.
        let short_store = FileEffectJournal::create(
            temp.0.join(format!("short-journal-{lost_sequence}")),
            EffectJournalLimits::default(),
            Arc::new(HostSpoolIo),
        )?;
        let short = archive::journal::Journal::create(Box::new(short_store), scope, &cx)?;
        let store = FileEffectJournal::open(
            &keeper_path,
            EffectJournalLimits::default(),
            Arc::new(HostSpoolIo),
            keeper_minimum,
        )?;
        assert!(matches!(
            archive::journal::AnchorKeeper::reopen(Box::new(store), &short, keeper_minimum, &cx),
            Err(archive::journal::Error::Invalid)
        ));
    }
    let lost_path = temp.0.join("av-lost-ack-journal");
    let store = FileEffectJournal::create(
        &lost_path,
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut journal = archive::journal::Journal::create(
        Box::new(LoseConfirmation {
            inner: store,
            fenced: false,
            lose_sequence: 3,
        }),
        scope,
        &cx,
    )?;
    let genesis = journal.anchor();
    let mut lost_target =
        ReferenceDeployment::open(&temp.0.join("lost-ack"), "site:unifi-av-multisegment", &cx)?;
    let mut lost_muxer =
        av_recording::Muxer::new(&av_init, &config, 0, 0, 8, 8, Mp4Limits::default())?;
    let lost = archive::publish_next_av_segment_journaled(
        &first_input,
        &mut lost_muxer,
        &mut lost_target,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &cx,
        &mut journal,
    );
    assert!(
        matches!(lost, Err(archive::AvSegmentPublishError::JournalAfterCommit { pin, receipt, .. }) if pin == first_pin && receipt.outcome == RootLedgerOutcome::Committed)
    );
    assert_eq!(journal.pending(), Some(first_pin));
    assert_eq!(journal.anchor().sequence, 2);
    assert_eq!(lost_muxer.pending_publication(), Some(first_pin));
    drop(journal);
    drop(lost_muxer);
    drop(lost_target);
    let store = FileEffectJournal::open(
        &lost_path,
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
        genesis,
    )?;
    let mut journal = archive::journal::Journal::reopen(Box::new(store), scope, genesis, &cx)?;
    assert_eq!(journal.confirmed(), Some(first_pin));
    assert_eq!(journal.anchor().sequence, 3);
    let mut lost_target =
        ReferenceDeployment::open(&temp.0.join("lost-ack"), "site:unifi-av-multisegment", &cx)?;
    let mut lost_muxer =
        av_recording::Muxer::new(&av_init, &config, 0, 0, 8, 8, Mp4Limits::default())?;
    assert_eq!(journal.replay_pin(), Some(first_pin));
    assert!(matches!(archive::publish_next_av_segment_journaled(
        &different_capture, &mut lost_muxer, &mut lost_target, &access,
        archive::Limits::default(), &mut WorkBudget::new(4_000_000_000), &cx, &mut journal,
    ), Err(archive::AvSegmentPublishError::PendingMismatch { expected, .. }) if expected == first_pin));
    let retried = archive::publish_next_av_segment_journaled(
        &first_input,
        &mut lost_muxer,
        &mut lost_target,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &cx,
        &mut journal,
    )?;
    assert_eq!(retried.receipt.outcome, RootLedgerOutcome::AlreadyLedgered);
    assert_eq!(journal.anchor().sequence, 3);
    assert_eq!(journal.replay_pin(), None);
    assert_eq!(lost_muxer.pending_publication(), None);
    drop(journal);
    let store = FileEffectJournal::open(
        &lost_path,
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
        genesis,
    )?;
    assert!(matches!(
        archive::journal::Journal::reopen(
            Box::new(store),
            ContentDigest::sha256(b"wrong synthetic scope"),
            genesis,
            &cx,
        ),
        Err(archive::journal::Error::Invalid)
    ));

    // A lost acknowledgment for the candidate itself occurs before any
    // archive effect, but the durable journal may already contain the pin.
    let candidate_path = temp.0.join("av-lost-candidate-journal");
    let store = FileEffectJournal::create(
        &candidate_path,
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut journal = archive::journal::Journal::create(
        Box::new(LoseConfirmation {
            inner: store,
            fenced: false,
            lose_sequence: 2,
        }),
        scope,
        &cx,
    )?;
    let genesis = journal.anchor();
    let mut candidate_target = ReferenceDeployment::open(
        &temp.0.join("lost-candidate"),
        "site:unifi-av-multisegment",
        &cx,
    )?;
    let mut candidate_muxer =
        av_recording::Muxer::new(&av_init, &config, 0, 0, 8, 8, Mp4Limits::default())?;
    assert!(matches!(archive::publish_next_av_segment_journaled(
        &first_input, &mut candidate_muxer, &mut candidate_target, &access,
        archive::Limits::default(), &mut WorkBudget::new(4_000_000_000), &cx, &mut journal,
    ), Err(archive::AvSegmentPublishError::JournalBefore { pin, .. }) if pin == first_pin));
    assert_eq!(journal.anchor(), genesis);
    assert_eq!(candidate_muxer.pending_publication(), Some(first_pin));
    assert!(matches!(
        archive::read_av_clip(
            &mut candidate_target,
            first_pin,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(20_000_000_000),
            &cx,
        ),
        Err(archive::Error::NotCommitted)
    ));
    drop(journal);
    drop(candidate_muxer);
    drop(candidate_target);
    let store = FileEffectJournal::open(
        &candidate_path,
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
        genesis,
    )?;
    let mut journal = archive::journal::Journal::reopen(Box::new(store), scope, genesis, &cx)?;
    assert_eq!(journal.pending(), Some(first_pin));
    let mut candidate_target = ReferenceDeployment::open(
        &temp.0.join("lost-candidate"),
        "site:unifi-av-multisegment",
        &cx,
    )?;
    let mut candidate_muxer =
        av_recording::Muxer::new(&av_init, &config, 0, 0, 8, 8, Mp4Limits::default())?;
    let committed = archive::publish_next_av_segment_journaled(
        &first_input,
        &mut candidate_muxer,
        &mut candidate_target,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &cx,
        &mut journal,
    )?;
    assert_eq!(committed.receipt.outcome, RootLedgerOutcome::Committed);
    assert_eq!(journal.confirmed(), Some(first_pin));
    drop(journal);

    // Interrupt only after the complete source graph and its manifest have
    // been staged, then reopen both stores and independently recover originals.
    let staged_path = temp.0.join("av-staged-journal");
    let store = FileEffectJournal::create(
        &staged_path,
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut staged_journal = archive::journal::Journal::create(Box::new(store), scope, &cx)?;
    let staged_genesis = staged_journal.anchor();
    let mut staged_target = ReferenceDeployment::open(
        &temp.0.join("staged-recovery"),
        "site:unifi-av-multisegment",
        &cx,
    )?;
    let mut staged_muxer =
        av_recording::Muxer::new(&av_init, &config, 0, 0, 8, 8, Mp4Limits::default())?;
    let mut payload_count = 0usize;
    first.visit_objects(|_, _| payload_count += 1);
    struct DenyAfterCompleteStage {
        calls: std::cell::Cell<usize>,
        allow: usize,
    }
    impl RetainAuthority for DenyAfterCompleteStage {
        fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
            let calls = self.calls.get() + 1;
            self.calls.set(calls);
            calls <= self.allow
        }
    }
    let stage_gate = DenyAfterCompleteStage {
        calls: std::cell::Cell::new(0),
        allow: payload_count + 2,
    };
    let stopped = archive::publish_next_av_segment_journaled(
        &first_input,
        &mut staged_muxer,
        &mut staged_target,
        &stage_gate,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &cx,
        &mut staged_journal,
    );
    assert!(
        matches!(stopped, Err(archive::AvSegmentPublishError::Archive { pin, source: archive::Error::Denied }) if pin == first_pin)
    );
    assert_eq!(staged_journal.pending(), Some(first_pin));
    drop(staged_journal);
    drop(staged_muxer);
    drop(staged_target);
    let store = FileEffectJournal::open(
        &staged_path,
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
        staged_genesis,
    )?;
    let mut staged_journal =
        archive::journal::Journal::reopen(Box::new(store), scope, staged_genesis, &cx)?;
    let mut staged_target = ReferenceDeployment::open(
        &temp.0.join("staged-recovery"),
        "site:unifi-av-multisegment",
        &cx,
    )?;
    let staged_limits = archive::StagedAvLimits {
        max_objects: 8192,
        max_object_bytes: 1024 * 1024,
        max_total_bytes: 8 * 1024 * 1024,
    };
    let candidate = archive::verify_staged_av_candidate(
        &staged_target,
        &staged_journal,
        &access,
        staged_limits,
        &mut WorkBudget::new(100_000_000_000),
        &cx,
    )?;
    assert_eq!(candidate.pin(), first_pin);
    assert!(candidate.total_bytes() > 0);
    assert_eq!(
        candidate.claimed_source(),
        (
            KEY.connection,
            KEY.generation,
            segments[0].fragment().sequence()
        )
    );
    let descriptor = |record: &SourceRecord| archive::StagedSourceRecord {
        offset: record.offset(),
        length: record.bytes().len(),
        digest: ContentDigest::sha256(record.bytes()),
    };
    assert_eq!(candidate.configuration(), descriptor(video_source));
    let expected_records: Vec<_> = segments[0].source().iter().map(descriptor).collect();
    let expected_witness: Vec<_> = segments[0]
        .lookahead_copies()
        .iter()
        .map(descriptor)
        .collect();
    assert_eq!(candidate.records(), expected_records.as_slice());
    assert_eq!(candidate.witness(), expected_witness.as_slice());
    for record in std::iter::once(video_source)
        .chain(segments[0].source())
        .chain(segments[0].lookahead_copies())
    {
        let bytes = archive::read_staged_av_object(
            &staged_target,
            &staged_journal,
            &candidate,
            ContentDigest::sha256(record.bytes()),
            &access,
            &mut WorkBudget::new(100_000_000_000),
            &cx,
        )?;
        assert_eq!(bytes, record.bytes());
    }
    assert!(matches!(
        archive::verify_staged_av_candidate(
            &staged_target,
            &staged_journal,
            &access,
            archive::StagedAvLimits {
                max_total_bytes: 1,
                ..staged_limits
            },
            &mut WorkBudget::new(100_000_000_000),
            &cx,
        ),
        Err(archive::Error::Limit)
    ));
    assert!(matches!(
        archive::read_staged_av_object(
            &staged_target,
            &staged_journal,
            &candidate,
            ContentDigest::sha256(b"foreign object"),
            &access,
            &mut WorkBudget::new(100_000_000_000),
            &cx,
        ),
        Err(archive::Error::Mismatch)
    ));
    struct DenyRead;
    impl ReadAuthority for DenyRead {
        fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
            false
        }
    }
    assert!(matches!(
        archive::read_staged_av_object(
            &staged_target,
            &staged_journal,
            &candidate,
            first_pin.root,
            &DenyRead,
            &mut WorkBudget::new(100_000_000_000),
            &cx,
        ),
        Err(archive::Error::Denied)
    ));
    let source_digest = ContentDigest::sha256(video_source.bytes());
    let source_path = staged_target.publisher().spool().object_path(source_digest);
    let source_envelope = std::fs::read(&source_path)?;
    std::fs::write(&source_path, b"synthetic corrupt staged source")?;
    assert!(
        archive::read_staged_av_object(
            &staged_target,
            &staged_journal,
            &candidate,
            source_digest,
            &access,
            &mut WorkBudget::new(100_000_000_000),
            &cx,
        )
        .is_err()
    );
    assert!(
        archive::verify_staged_av_candidate(
            &staged_target,
            &staged_journal,
            &access,
            staged_limits,
            &mut WorkBudget::new(100_000_000_000),
            &cx,
        )
        .is_err()
    );
    std::fs::write(source_path, source_envelope)?;
    let mut staged_muxer =
        av_recording::Muxer::new(&av_init, &config, 0, 0, 8, 8, Mp4Limits::default())?;
    let completed = archive::publish_next_av_segment_journaled(
        &first_input,
        &mut staged_muxer,
        &mut staged_target,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &cx,
        &mut staged_journal,
    )?;
    assert_eq!(completed.receipt.outcome, RootLedgerOutcome::Committed);
    assert!(matches!(
        archive::read_staged_av_object(
            &staged_target,
            &staged_journal,
            &candidate,
            first_pin.root,
            &access,
            &mut WorkBudget::new(100_000_000_000),
            &cx,
        ),
        Err(archive::Error::RecoveryRequired)
    ));
    drop(staged_journal);

    // A correctly stored record cannot confirm a root that was never prepared.
    let invalid_path = temp.0.join("av-invalid-history-journal");
    let store = FileEffectJournal::create(
        &invalid_path,
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let journal = archive::journal::Journal::create(Box::new(store), scope, &cx)?;
    let genesis = journal.anchor();
    drop(journal);
    let mut store = FileEffectJournal::open(
        &invalid_path,
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
        genesis,
    )?;
    let mut bad = fss_core::CanonicalEncoder::new();
    bad.text("fss.unifi-direct.av-publication-intent.v1");
    bad.digest(scope);
    bad.u8(2);
    bad.digest(first_pin.root);
    bad.digest(first_pin.retention);
    bad.i128(first_pin.capture.earliest.0);
    bad.i128(first_pin.capture.latest.0);
    store.append(Some(genesis), &bad.finish_checked()?)?;
    drop(store);
    let store = FileEffectJournal::open(
        &invalid_path,
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
        genesis,
    )?;
    assert!(matches!(
        archive::journal::Journal::reopen(Box::new(store), scope, genesis, &cx),
        Err(archive::journal::Error::Invalid)
    ));

    // Exercise the supervisor-to-archive handoff with actual owned segments:
    // a denied attempt retains the first and refuses a second until retry.
    use fss_reference::unifi_direct::av_sink;
    let store = FileEffectJournal::create(
        temp.0.join("sink-journal"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut journal = archive::journal::Journal::create(Box::new(store), scope, &cx)?;
    let store = FileEffectJournal::create(
        temp.0.join("sink-keeper"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut keeper = archive::journal::AnchorKeeper::create(Box::new(store), &journal, &cx)?;
    let mut target = ReferenceDeployment::open(
        &temp.0.join("sink-target"),
        "site:unifi-av-multisegment",
        &cx,
    )?;
    let muxer = av_recording::Muxer::new(&av_init, &config, 0, 0, 8, 8, Mp4Limits::default())?;
    let mut sink = av_sink::Sink::new(
        video_source,
        av_init,
        av_sink::Audio::SuppliedUnverified(&config),
        muxer,
        retention,
        EvidenceLimits::default(),
    );
    let mut originals = segments.into_iter();
    let first_segment = originals.next().ok_or("missing first segment")?;
    let second_segment = originals.next().ok_or("missing second segment")?;
    assert!(sink.offer(first_segment, first_capture).is_ok());
    let refused = match sink.offer(second_segment, second_capture) {
        Err(refused) => refused,
        Ok(()) => return Err("sink accepted a second pending segment".into()),
    };
    assert_eq!(refused.reason, av_sink::RefusalReason::Pending);
    assert!(matches!(
        sink.flush(
            video_init,
            &mut target,
            &DenyRetention,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
            &mut journal,
            &mut keeper
        ),
        Err(archive::AvSegmentPublishError::Archive {
            source: archive::Error::Denied,
            ..
        })
    ));
    assert!(sink.has_pending());
    let retirement = sink.retire();
    assert_eq!(
        retirement.pending.as_ref().map(|(_, capture)| *capture),
        Some(first_capture)
    );
    let mut sink = av_sink::Sink::resume(
        video_source,
        av_sink::Audio::SuppliedUnverified(&config),
        retention,
        EvidenceLimits::default(),
        retirement,
    );
    assert!(sink.has_pending());
    let published = sink
        .flush(
            video_init,
            &mut target,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
            &mut journal,
            &mut keeper,
        )?
        .ok_or("missing first receipt")?;
    assert_eq!(published.pin, first_pin);
    assert!(!sink.has_pending());
    assert!(sink.offer(refused.segment, refused.capture).is_ok());
    let published = sink
        .flush(
            video_init,
            &mut target,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
            &mut journal,
            &mut keeper,
        )?
        .ok_or("missing second receipt")?;
    assert_eq!(published.pin, second_pin);
    assert!(!sink.has_pending());
    let sequence = archive::read_av_sequence(
        &mut target,
        &[first_pin, second_pin],
        &access,
        archive::Limits::default(),
        sequence_limits,
        &mut WorkBudget::new(100_000_000_000),
        &cx,
    )?;
    assert_eq!(sequence.parts().len(), 2);
    assert!(sink.retire().pending.is_none());
    Ok(())
}

#[test]
fn owned_archive_handoff_moves_source_and_reconciles_in_joined_worker() -> TestResult {
    use fss_container::Mp4Limits;
    use fss_core::{
        BudgetVector, CaptureInterval, ContentDigest, OperationId, RootAuthoritySpec, TimestampNs,
        region::ContextAuthority,
    };
    use fss_geometry::WorkBudget;
    use fss_object::{
        HostSpoolIo,
        effect_journal::{EffectJournalLimits, FileEffectJournal},
    };
    use fss_packet::extended_flv::aac;
    use fss_reference::{
        ReferenceDeployment, ReplayCx,
        unifi_direct::{archive, av_owned_sink, av_recording, av_sink, evidence},
    };
    use std::{path::PathBuf, sync::Arc};

    // The owned media handoff must be movable; this is not proof of an async worker.
    fn assert_send<T: Send>() {}
    assert_send::<av_owned_sink::OwnedSink>();
    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    struct Retention(bool);
    impl archive::RetainAuthority for Retention {
        fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
            self.0
        }
    }
    impl archive::ReadAuthority for Retention {
        fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
            self.0
        }
    }

    let (_, records) = fixture_with_audio_intervals(0, false, false, false, Some(64))?;
    let mut recorder = Recorder::new(KEY, Limits::default())?;
    let mut video_configuration = None;
    let mut segments = Vec::new();
    for record in records {
        match recorder.push(record).map_err(|refusal| refusal.reason)? {
            Push::Source {
                record,
                disposition: SourceDisposition::Configuration,
            } => video_configuration = Some(record),
            Push::Segment(segment) => segments.push(segment),
            _ => (),
        }
    }
    assert_eq!(segments.len(), 2);
    let audio_bytes = [0x14, 0x08];
    let config = aac::Configuration::parse_explicit(&audio_bytes)?;
    let av_init = recorder
        .av_initialization(&config)?
        .ok_or("missing A/V init")?;
    let muxer = av_recording::Muxer::new(&av_init, &config, 0, 0, 8, 8, Mp4Limits::default())?;
    let retention = ContentDigest::sha256(b"owned synthetic retention");
    let mut sink = av_owned_sink::OwnedSink::new(av_owned_sink::Inputs {
        video_configuration: video_configuration.ok_or("missing video configuration")?,
        av_initialization: av_init,
        audio: av_owned_sink::Audio::SuppliedUnverified(audio_bytes),
        muxer,
        retention,
        evidence_limits: evidence::Limits::default(),
        video_limits: Mp4Limits::default(),
    })
    .map_err(|_| "owned sink construction failed")?;
    let mut source = segments.into_iter();
    let first = source.next().ok_or("missing first source")?;
    let second = source.next().ok_or("missing second source")?;
    let first_capture = CaptureInterval::new(TimestampNs(1), TimestampNs(10))?;
    let second_capture = CaptureInterval::new(TimestampNs(11), TimestampNs(20))?;
    assert!(sink.offer(first, first_capture).is_ok());
    let refused = match sink.offer(second, second_capture) {
        Err(refused) => refused,
        Ok(()) => return Err("owned sink accepted two pending segments".into()),
    };
    assert_eq!(refused.reason, av_sink::RefusalReason::Pending);
    let temp =
        Temp(std::env::temp_dir().join(format!("fss-unifi-owned-handoff-{}", std::process::id())));
    std::fs::create_dir(&temp.0)?;
    let context = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:owned-handoff".into(),
        operation_id: OperationId::parse("operation:owned-handoff")?,
        principal: "principal:fixture".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 1,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"site:owned-handoff"),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&context, temp.0.clone())?;
    let deployment =
        ReferenceDeployment::open(&temp.0.join("deployment"), "site:owned-handoff", &cx)?;
    let store = FileEffectJournal::create(
        temp.0.join("journal"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let journal = archive::journal::Journal::create(
        Box::new(store),
        ContentDigest::sha256(b"owned handoff scope"),
        &cx,
    )?;
    let store = FileEffectJournal::create(
        temp.0.join("keeper"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let keeper = archive::journal::AnchorKeeper::create(Box::new(store), &journal, &cx)?;
    let result = std::thread::scope(|scope| {
        scope
            .spawn(move || -> Result<(), String> {
                let (mut deployment, mut journal, mut keeper) = (deployment, journal, keeper);
                let denied = sink.flush(
                    &mut deployment,
                    &Retention(false),
                    archive::Limits::default(),
                    &mut WorkBudget::new(4_000_000_000),
                    &cx,
                    &mut journal,
                    &mut keeper,
                );
                if !matches!(
                    denied,
                    Err(av_owned_sink::FlushError::Archive(
                        archive::AvSegmentPublishError::Archive {
                            source: archive::Error::Denied,
                            ..
                        }
                    ))
                ) {
                    return Err("expected retention refusal".into());
                }
                let retirement = sink.retire();
                if retirement.pending.is_none() {
                    return Err("pending source lost".into());
                }
                let mut sink =
                    av_owned_sink::OwnedSink::resume(retirement).map_err(|_| "resume refused")?;
                let first = sink
                    .flush(
                        &mut deployment,
                        &Retention(true),
                        archive::Limits::default(),
                        &mut WorkBudget::new(4_000_000_000),
                        &cx,
                        &mut journal,
                        &mut keeper,
                    )
                    .map_err(|error| format!("first publication: {error:?}"))?
                    .ok_or("missing first receipt")?;
                if sink.offer(refused.segment, refused.capture).is_err() {
                    return Err("second source refused".into());
                }
                let second = sink
                    .flush(
                        &mut deployment,
                        &Retention(true),
                        archive::Limits::default(),
                        &mut WorkBudget::new(4_000_000_000),
                        &cx,
                        &mut journal,
                        &mut keeper,
                    )
                    .map_err(|error| format!("second publication: {error:?}"))?
                    .ok_or("missing second receipt")?;
                let result = archive::read_av_sequence(
                    &mut deployment,
                    &[first.pin, second.pin],
                    &Retention(true),
                    archive::Limits::default(),
                    archive::AvSequenceLimits {
                        max_fragments: 2,
                        max_bytes: 1024 * 1024,
                    },
                    &mut WorkBudget::new(100_000_000_000),
                    &cx,
                )
                .map_err(|error| format!("readback: {error:?}"))?;
                if result.parts().len() != 2 || sink.has_pending() {
                    return Err("owned handoff did not finish".into());
                }
                Ok(())
            })
            .join()
    })
    .map_err(|_| "owned worker panicked")?;
    result.map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
    Ok(())
}

#[test]
fn owned_unknown_time_sink_preserves_source_and_retries() -> TestResult {
    use fss_container::Mp4Limits;
    use fss_core::{
        BudgetVector, CaptureInterval, ContentDigest, OperationId, RootAuthoritySpec, TimestampNs,
        region::ContextAuthority,
    };
    use fss_geometry::WorkBudget;
    use fss_object::{
        HostSpoolIo,
        effect_journal::{EffectJournalLimits, FileEffectJournal},
    };
    use fss_reference::{
        ReferenceDeployment, ReplayCx,
        unifi_direct::{archive, av_owned_sink, av_sink, evidence},
    };
    use std::{path::PathBuf, sync::Arc};
    fn assert_send<T: Send>() {}
    assert_send::<av_owned_sink::UnknownTimeOwnedSink>();
    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    struct Retention(bool);
    impl archive::RetainAuthority for Retention {
        fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
            self.0
        }
    }
    impl archive::ReadAuthority for Retention {
        fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
            self.0
        }
    }
    let (_, records) = fixture_with_audio_intervals(0, false, false, false, Some(64))?;
    let mut recorder = Recorder::new(KEY, Limits::default())?;
    let mut video = None;
    let mut segments = Vec::new();
    for record in records {
        match recorder.push(record).map_err(|r| r.reason)? {
            Push::Source {
                record,
                disposition: SourceDisposition::Configuration,
            } => video = Some(record),
            Push::Segment(segment) => segments.push(segment),
            _ => {}
        }
    }
    let mut segments = segments.into_iter();
    let first = segments.next().ok_or("missing first segment")?;
    let second = segments.next().ok_or("missing second segment")?;
    let first_digest = ContentDigest::sha256(first.fragment().bytes());
    let bootstrap = av_owned_sink::OwnedSink::bootstrap(av_owned_sink::BootstrapInputs {
        video_configuration: video.ok_or("missing video configuration")?,
        audio: av_owned_sink::Audio::SuppliedUnverified([0x14, 0x08]),
        first_segment: first,
        retention: ContentDigest::sha256(b"unknown owned sink retention"),
        policy: av_owned_sink::BootstrapPolicy {
            allow_initial_video_only: false, max_separation_ms: 5_000,
            jitter_ms: 0,
            max_epoch_frames: 8,
            max_audio_frames: 8,
            media_limits: Mp4Limits::default(),
            evidence_limits: evidence::Limits::default(),
        },
    })
    .map_err(|_| "bootstrap refused")?;
    // A known-time pending segment prevents changing modes and is returned intact.
    let mut known = bootstrap.sink;
    assert!(
        known
            .offer(
                bootstrap.first_segment,
                CaptureInterval::point(TimestampNs(1))
            )
            .is_ok()
    );
    let known = match known.into_unknown_time() {
        Err(known) => known,
        Ok(_) => return Err("converted a pending known-time sink".into()),
    };
    let retirement = known.retire();
    let (first, _) = retirement.pending.ok_or("known source lost")?;
    assert_eq!(
        ContentDigest::sha256(first.fragment().bytes()),
        first_digest
    );
    let known = av_owned_sink::OwnedSink::new(retirement.inputs).map_err(|_| "rebuild refused")?;
    let mut sink = known
        .into_unknown_time()
        .map_err(|_| "unknown conversion refused")?;
    assert!(sink.offer(first).is_ok());
    let refused = match sink.offer(second) {
        Err(refused) => refused,
        Ok(()) => return Err("accepted a second pending source".into()),
    };
    assert_eq!(refused.reason, av_sink::RefusalReason::Pending);
    let temp =
        Temp(std::env::temp_dir().join(format!("fss-unifi-unknown-owned-{}", std::process::id())));
    std::fs::create_dir(&temp.0)?;
    let context = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:unknown-owned".into(),
        operation_id: OperationId::parse("operation:unknown-owned")?,
        principal: "principal:fixture".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 1,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"site:unknown-owned"),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&context, temp.0.clone())?;
    let mut deployment =
        ReferenceDeployment::open(&temp.0.join("deployment"), "site:unknown-owned", &cx)?;
    let store = FileEffectJournal::create(
        temp.0.join("journal"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut journal = archive::journal::UnknownTimeJournal::create(
        Box::new(store),
        ContentDigest::sha256(b"unknown owned scope"),
        &cx,
    )?;
    let store = FileEffectJournal::create(
        temp.0.join("keeper"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut keeper =
        archive::journal::UnknownTimeAnchorKeeper::create(Box::new(store), &journal, &cx)?;
    assert!(matches!(
        sink.flush(
            &mut deployment,
            &Retention(false),
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
            &mut journal,
            &mut keeper,
        ),
        Err(av_owned_sink::UnknownTimeFlushError::Archive(
            archive::UnknownTimeSegmentError::Publication(
                archive::UnknownTimePublishError::Archive(archive::Error::Denied)
            )
        ))
    ));
    let pending_pin = journal.pending().ok_or("missing pending pin")?;
    let retirement = sink.retire();
    assert_eq!(
        ContentDigest::sha256(
            retirement
                .pending
                .as_ref()
                .ok_or("pending source lost")?
                .fragment()
                .bytes()
        ),
        first_digest
    );
    let mut sink =
        av_owned_sink::UnknownTimeOwnedSink::resume(retirement).map_err(|_| "resume refused")?;
    let first = sink
        .flush(
            &mut deployment,
            &Retention(true),
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
            &mut journal,
            &mut keeper,
        )
        .map_err(|e| format!("first publication: {e:?}"))?
        .ok_or("first receipt missing")?;
    assert_eq!(first.pin, pending_pin);
    assert!(sink.offer(refused.segment).is_ok());
    let second = sink
        .flush(
            &mut deployment,
            &Retention(true),
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
            &mut journal,
            &mut keeper,
        )
        .map_err(|e| format!("second publication: {e:?}"))?
        .ok_or("second receipt missing")?;
    assert_ne!(first.pin, second.pin);
    for pin in [first.pin, second.pin] {
        let clip = archive::read_unknown_time_av_clip(
            &mut deployment,
            pin,
            &Retention(true),
            archive::Limits::default(),
            &mut WorkBudget::new(20_000_000_000),
            &cx,
        )?;
        assert!(clip.video_samples() > 0 && clip.audio().frames > 0);
    }
    assert!(!sink.has_pending());
    assert!(sink.retire().pending.is_none());
    Ok(())
}

#[test]
fn async_archive_worker_drains_cancelled_publication_and_retries() -> TestResult {
    use asupersync::{
        runtime::{RuntimeBuilder, yield_now},
        time::timeout,
    };
    use fss_container::Mp4Limits;
    use fss_core::{
        BudgetVector, CaptureInterval, ContentDigest, OperationId, RegionId, RegionKind,
        RootAuthoritySpec, RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
        region::ContextAuthority,
    };
    use fss_geometry::WorkBudget;
    use fss_object::{
        HostSpoolIo,
        effect_journal::{EffectJournalLimits, FileEffectJournal},
    };
    use fss_packet::extended_flv::aac;
    use fss_reference::{
        ReferenceDeployment, ReplayCx,
        unifi_direct::{
            archive, av_owned_sink, av_recording, av_worker, evidence, metered::MeteredClock,
        },
    };
    use fss_runtime::{
        authority::AuthorityCx,
        execution::{TaskCompletion, TaskSpec, run_owned_async},
    };
    use std::{
        future::{Future, poll_fn},
        path::PathBuf,
        pin::pin,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::Poll,
        time::Duration,
    };

    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    struct Retention {
        allow: AtomicBool,
        block: AtomicBool,
        entered: AtomicBool,
    }
    impl archive::RetainAuthority for Retention {
        fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
            self.entered.store(true, Ordering::Release);
            for _ in 0..2500 {
                if !self.block.load(Ordering::Acquire) {
                    return self.allow.load(Ordering::Acquire);
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            false
        }
    }
    impl archive::ReadAuthority for Retention {
        fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
            self.allow.load(Ordering::Acquire)
        }
    }
    struct Unblock(Arc<Retention>);
    impl Drop for Unblock {
        fn drop(&mut self) {
            self.0.block.store(false, Ordering::Release);
        }
    }

    let (_, records) = fixture_with_audio_intervals(0, false, false, false, Some(64))?;
    let mut recorder = Recorder::new(KEY, Limits::default())?;
    let mut configuration = None;
    let mut segments = Vec::new();
    for record in records {
        match recorder.push(record).map_err(|refusal| refusal.reason)? {
            Push::Source {
                record,
                disposition: SourceDisposition::Configuration,
            } => configuration = Some(record),
            Push::Segment(segment) => segments.push(segment),
            _ => (),
        }
    }
    assert_eq!(segments.len(), 2);
    let audio = [0x14, 0x08];
    let config = aac::Configuration::parse_explicit(&audio)?;
    let init = recorder
        .av_initialization(&config)?
        .ok_or("missing initialization")?;
    let muxer = av_recording::Muxer::new(&init, &config, 0, 0, 8, 8, Mp4Limits::default())?;
    let retention = ContentDigest::sha256(b"async worker retention");
    let sink = av_owned_sink::OwnedSink::new(av_owned_sink::Inputs {
        video_configuration: configuration.ok_or("missing configuration")?,
        av_initialization: init,
        audio: av_owned_sink::Audio::SuppliedUnverified(audio),
        muxer,
        retention,
        evidence_limits: evidence::Limits::default(),
        video_limits: Mp4Limits::default(),
    })
    .map_err(|_| "owned sink construction failed")?;
    let mut segments = segments.into_iter();
    let first = segments.next().ok_or("missing first segment")?;
    let second = segments.next().ok_or("missing second segment")?;
    let first_capture = CaptureInterval::new(TimestampNs(1), TimestampNs(10))?;
    let second_capture = CaptureInterval::new(TimestampNs(11), TimestampNs(20))?;
    let temp =
        Temp(std::env::temp_dir().join(format!("fss-unifi-async-archive-{}", std::process::id())));
    std::fs::create_dir(&temp.0)?;
    let budget = BudgetVector::builder()
        .bytes(128 * 1024 * 1024)
        .storage_operations(10_000)
        .build()?;
    let replay_context = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:async-archive-replay".into(),
        operation_id: OperationId::parse("operation:async-archive-replay")?,
        principal: "principal:fixture".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 1,
        budgets: budget,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"site:async-archive"),
        generation: 1,
    })?;
    let replay = ReplayCx::from_context_authority(&replay_context, temp.0.clone())?;
    let deployment =
        ReferenceDeployment::open(&temp.0.join("deployment"), "site:async-archive", &replay)?;
    let store = FileEffectJournal::create(
        temp.0.join("journal"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let journal = archive::journal::Journal::create(
        Box::new(store),
        ContentDigest::sha256(b"async worker scope"),
        &replay,
    )?;
    let store = FileEffectJournal::create(
        temp.0.join("keeper"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let keeper = archive::journal::AnchorKeeper::create(Box::new(store), &journal, &replay)?;
    let access = Arc::new(Retention {
        allow: AtomicBool::new(false),
        block: AtomicBool::new(true),
        entered: AtomicBool::new(false),
    });
    let _unblock = Unblock(Arc::clone(&access));
    let retain: Arc<dyn archive::RetainAuthority + Send + Sync> = access.clone();
    let mut worker = av_worker::Worker::new(av_worker::Parts {
        sink,
        deployment,
        journal,
        keeper,
        replay,
        authority: retain,
        limits: archive::Limits::default(),
        work_limit: 4_000_000_000,
    })
    .map_err(|_| "invalid worker limits")?;
    assert!(worker.offer(first, first_capture).is_ok());
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:async-archive".into(),
            operation_id: OperationId::parse("operation:async-archive")?,
            principal: "principal:fixture".into(),
            capabilities: vec![
                RuntimeGrant::ObjectStage.as_str().into(),
                RuntimeGrant::ObjectPublish.as_str().into(),
            ],
            deadline: None,
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"site:async-archive"),
            generation: 1,
        },
        RegionId::new("region:async-archive")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:async-archive")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |task, cx| {
                let output: Result<(), String> = async {
                    let clock =
                        MeteredClock::new(task, cx, TimestampNs(3)).map_err(|e| e.to_string())?;
                    let cost = BudgetVector::builder()
                        .bytes(1024 * 1024)
                        .storage_operations(1000)
                        .build()
                        .map_err(|e| e.to_string())?;
                    let other_cx = cx.clone();
                    if !matches!(
                        worker.start(task, &other_cx, clock, "fixture:archive", &cost),
                        Err(av_worker::StartError::Context)
                    ) {
                        return Err("foreign runtime context was accepted".into());
                    }
                    worker
                        .start(task, cx, clock, "fixture:archive", &cost)
                        .map_err(|e| format!("start: {e:?}"))?;
                    timeout(cx.now(), Duration::from_secs(5), async {
                        while !access.entered.load(Ordering::Acquire) {
                            yield_now().await;
                        }
                    })
                    .await
                    .map_err(|_| "archive did not enter worker")?;
                    let rejected = match worker.offer(second, second_capture) {
                        Err(av_worker::OfferRefusal::Busy { segment, capture }) => {
                            (segment, capture)
                        }
                        _ => return Err("worker did not apply backpressure".into()),
                    };
                    worker.abort();
                    timeout(cx.now(), Duration::from_secs(5), async {
                        while !worker.cancellation_observed() {
                            yield_now().await;
                        }
                    })
                    .await
                    .map_err(|_| "worker cancellation was not observed")?;
                    let pending = poll_fn(|context| {
                        let mut wait = pin!(worker.join());
                        Poll::Ready(wait.as_mut().poll(context).is_pending())
                    })
                    .await;
                    if !pending {
                        return Err("worker joined before blocking retention released".into());
                    }
                    worker = match worker.retire() {
                        Err(worker) => worker,
                        Ok(_) => return Err("worker retired before its closure drained".into()),
                    };
                    access.block.store(false, Ordering::Release);
                    let completion = timeout(cx.now(), Duration::from_secs(5), worker.join())
                        .await
                        .map_err(|_| "worker drain timed out")?
                        .ok_or("worker completion missing")?;
                    if completion.runtime.is_err() {
                        return Err(
                            "cancelled coordinator did not preserve its drained result".into()
                        );
                    }
                    if !matches!(
                        completion.outcome,
                        av_worker::Outcome::Publication(av_worker::Publication::Refused {
                            stage: av_worker::FailureStage::Archive,
                            reason: av_worker::FailureReason::CancelledOrDenied,
                            ..
                        })
                    ) {
                        return Err("cancelled archive outcome not retained".into());
                    }
                    access.allow.store(true, Ordering::Release);
                    worker
                        .start(task, cx, clock, "fixture:archive", &cost)
                        .map_err(|e| format!("retry: {e:?}"))?;
                    let completion = worker.join().await.ok_or("first receipt missing")?;
                    if completion.runtime.is_err() {
                        return Err("first coordinator failed".into());
                    }
                    let first = match completion.outcome {
                        av_worker::Outcome::Publication(av_worker::Publication::Published(
                            value,
                        )) => value.pin,
                        _ => return Err("first archive retry failed".into()),
                    };
                    if worker.offer(rejected.0, rejected.1).is_err() {
                        return Err("second source refused".into());
                    }
                    worker
                        .start(task, cx, clock, "fixture:archive", &cost)
                        .map_err(|e| format!("second start: {e:?}"))?;
                    let completion = worker.join().await.ok_or("second receipt missing")?;
                    if completion.runtime.is_err() {
                        return Err("second coordinator failed".into());
                    }
                    let second = match completion.outcome {
                        av_worker::Outcome::Publication(av_worker::Publication::Published(
                            value,
                        )) => value.pin,
                        _ => return Err("second archive failed".into()),
                    };
                    let retirement = worker.retire().map_err(|_| "worker failed to retire")?;
                    if retirement.fenced {
                        return Err("successful worker was fenced".into());
                    }
                    let mut parts = retirement.parts;
                    let sequence = archive::read_av_sequence(
                        &mut parts.deployment,
                        &[first, second],
                        access.as_ref(),
                        archive::Limits::default(),
                        archive::AvSequenceLimits {
                            max_fragments: 2,
                            max_bytes: 1024 * 1024,
                        },
                        &mut WorkBudget::new(100_000_000_000),
                        &parts.replay,
                    )
                    .map_err(|e| format!("readback: {e}"))?;
                    if sequence.parts().len() != 2 {
                        return Err("sequence incomplete".into());
                    }
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("archive worker fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(60_000_000_000),
                }
            },
        )
        .await?;
        run.receipt?;
        run.output
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })
    })?;
    Ok(())
}

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
    av_owner_with_configuration(&[0x14, 0x08])
}

#[test]
fn av_owner_preserves_explicit_absent_sbr_configuration() -> TestResult {
    av_owner_with_configuration(&[0x14, 0x08, 0x56, 0xe5, 0x00])
}

fn av_owner_with_configuration(bytes: &[u8]) -> TestResult {
    use fss_container::{Mp4Error, Mp4Limits};
    use fss_packet::extended_flv::{aac, aac_clock};
    use fss_reference::unifi_direct::av_recording;

    // Deliberately synthetic: 40 ms video and 64 ms AAC timestamps exercise
    // independent clocks without claiming these samples are synchronized.
    let (wire, records) = fixture_with_audio_intervals(0, false, false, false, Some(64))?;
    let config = aac::Configuration::parse_explicit(bytes)?;
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
    av_owner_in_band_configuration(&[0x14, 0x08])
}

#[test]
fn av_owner_retains_in_band_absent_sbr_configuration_binding() -> TestResult {
    av_owner_in_band_configuration(&[0x14, 0x08, 0x56, 0xe5, 0x00])
}

fn av_owner_in_band_configuration(config_bytes: &[u8]) -> TestResult {
    use fss_container::Mp4Limits;
    use fss_core::ContentDigest;
    use fss_packet::extended_flv::{aac, aac_track};
    use fss_reference::unifi_direct::av_recording;

    let (mut wire, original) = fixture(0, false, false)?;
    let insertion = usize::try_from(original[1].offset())? + original[1].bytes().len();
    let mut audio_configuration = vec![0x77; 3];
    let mut payload = vec![0xaf, 0];
    payload.extend_from_slice(config_bytes);
    audio_configuration.extend(tag(8, 0, &payload));
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
    assert_eq!(binding.configuration().bytes(), config_bytes);
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
    use fss_object::{
        HostSpoolIo, ObjectManifest,
        effect_journal::{EffectJournalLimits, FileEffectJournal},
    };
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
    use fss_runtime::effect_journal::{
        EffectJournalPin, EffectJournalStore, EffectPersistenceError,
    };
    use std::{cell::Cell, path::PathBuf, sync::Arc};
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
    let origin = av_recording::segment_sender_clock_origin(&segment, bound.configuration(), 5_000)?;
    assert_eq!(origin.audio_minus_video_ms, 64);
    let mut muxer = av_recording::Muxer::from_source(
        &av_init,
        &bound,
        origin.audio_ticks,
        0,
        8,
        8,
        Mp4Limits::default(),
    )?;
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
    // Unknown physical time remains explicit through publication and cold
    // reopening. The full ledger validity does not narrow that uncertainty.
    let unknown_video = Prepared::new(
        &segment,
        video_configuration
            .as_ref()
            .ok_or("missing video configuration")?,
        video_init,
        retention,
        EvidenceLimits::default(),
    )?;
    let unknown_av = PreparedAv::new(
        &unknown_video,
        &bound,
        &av_init,
        &fragment,
        EvidenceLimits::default(),
    )?;
    let unknown_pin =
        archive::UnknownTimePin::from_av_plan(&unknown_av).ok_or("missing unknown-time pin")?;
    assert!(archive::Pin::from_av_plan(&unknown_av).is_none());
    assert!(archive::UnknownTimePin::from_av_plan(&av).is_none());

    // Interrupt after the original unknown-time source graph is staged, then
    // reopen both journal chains and recover the exact originals before retry.
    let journal_path = temp.0.join("unknown-time-journal");
    let keeper_path = temp.0.join("unknown-time-keeper");
    let target_path = temp.0.join("unknown-time-journal-target");
    let scope = ContentDigest::sha256(b"unknown-time journal fixture");
    let store = FileEffectJournal::create(
        &journal_path,
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut journal = archive::journal::UnknownTimeJournal::create(Box::new(store), scope, &cx)?;
    let journal_genesis = journal.anchor();
    let store = FileEffectJournal::create(
        &keeper_path,
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut keeper =
        archive::journal::UnknownTimeAnchorKeeper::create(Box::new(store), &journal, &cx)?;
    let keeper_genesis = keeper.anchor();
    let mut journal_target =
        ReferenceDeployment::open(&target_path, "site:unifi-av-archive-test", &cx)?;
    let mut payload_count = 0usize;
    unknown_av.visit_objects(|_, _| payload_count += 1);
    struct DenyAfterStage {
        calls: Cell<usize>,
        allow: usize,
    }
    impl RetainAuthority for DenyAfterStage {
        fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
            let calls = self.calls.get() + 1;
            self.calls.set(calls);
            calls <= self.allow
        }
    }
    let stage_gate = DenyAfterStage {
        calls: Cell::new(0),
        allow: payload_count + 2,
    };
    assert!(matches!(
        archive::publish_unknown_time_av_anchored(
            &unknown_av,
            &mut journal_target,
            &stage_gate,
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
    assert_eq!(journal.pending(), Some(unknown_pin));
    assert_eq!(keeper.target(), journal.anchor());
    drop(keeper);
    drop(journal);
    drop(journal_target);

    // Known-time journal readers must not accept an unknown-time domain.
    let store = FileEffectJournal::open(
        &journal_path,
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
        journal_genesis,
    )?;
    assert!(
        archive::journal::Journal::reopen(Box::new(store), scope, journal_genesis, &cx).is_err()
    );
    let store = FileEffectJournal::open(
        &journal_path,
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
        journal_genesis,
    )?;
    let mut journal =
        archive::journal::UnknownTimeJournal::reopen(Box::new(store), scope, journal_genesis, &cx)?;
    let store = FileEffectJournal::open(
        &keeper_path,
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
        keeper_genesis,
    )?;
    let mut keeper = archive::journal::UnknownTimeAnchorKeeper::reopen(
        Box::new(store),
        &journal,
        keeper_genesis,
        &cx,
    )?;
    assert_eq!(journal.pending(), Some(unknown_pin));
    assert_eq!(keeper.target(), journal.anchor());
    let mut journal_target =
        ReferenceDeployment::open(&target_path, "site:unifi-av-archive-test", &cx)?;
    access.allowed.set(true);
    let candidate = archive::verify_staged_unknown_time_av_candidate(
        &journal_target,
        &journal,
        &access,
        archive::StagedAvLimits {
            max_objects: 8192,
            max_object_bytes: 1024 * 1024,
            max_total_bytes: 8 * 1024 * 1024,
        },
        &mut WorkBudget::new(100_000_000_000),
        &cx,
    )?;
    assert_eq!(candidate.pin(), unknown_pin);
    for record in std::iter::once(
        video_configuration
            .as_ref()
            .ok_or("missing video configuration")?,
    )
    .chain(segment.source())
    .chain(segment.lookahead_copies())
    {
        assert_eq!(
            archive::read_staged_unknown_time_av_object(
                &journal_target,
                &journal,
                &candidate,
                ContentDigest::sha256(record.bytes()),
                &access,
                &mut WorkBudget::new(100_000_000_000),
                &cx,
            )?,
            record.bytes()
        );
    }
    let receipt = archive::publish_unknown_time_av_anchored(
        &unknown_av,
        &mut journal_target,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &cx,
        &mut journal,
        &mut keeper,
    )?;
    assert_eq!(receipt.root, unknown_pin.root);
    assert_eq!(journal.pending(), None);
    assert_eq!(journal.confirmed(), Some(unknown_pin));
    assert_eq!(keeper.target(), journal.anchor());
    assert!(matches!(
        archive::read_staged_unknown_time_av_object(
            &journal_target,
            &journal,
            &candidate,
            unknown_pin.root,
            &access,
            &mut WorkBudget::new(100_000_000_000),
            &cx,
        ),
        Err(archive::Error::RecoveryRequired)
    ));
    // Lose each keeper acknowledgment after it is durably appended. A cold
    // reopen must classify the already-stored prefix and replay the same root.
    #[derive(Debug)]
    struct LoseUnknownAnchorAck {
        inner: FileEffectJournal,
        lose_sequence: u64,
        fenced: bool,
    }
    impl EffectJournalStore for LoseUnknownAnchorAck {
        fn head(&self) -> Option<EffectJournalPin> {
            self.inner.head()
        }
        fn records(&self) -> &[Vec<u8>] {
            self.inner.records()
        }
        fn contains(&self, pin: EffectJournalPin) -> bool {
            self.inner.contains(pin)
        }
        fn reserve_capacity(
            &mut self,
            count: usize,
            bytes: usize,
        ) -> Result<(), EffectPersistenceError> {
            if self.fenced {
                return Err(EffectPersistenceError::Poisoned);
            }
            self.inner.reserve_capacity(count, bytes)
        }
        fn append(
            &mut self,
            expected: Option<EffectJournalPin>,
            record: &[u8],
        ) -> Result<EffectJournalPin, EffectPersistenceError> {
            if self.fenced {
                return Err(EffectPersistenceError::Poisoned);
            }
            let pin = self.inner.append(expected, record)?;
            if pin.sequence == self.lose_sequence {
                self.fenced = true;
                return Err(EffectPersistenceError::Storage(
                    "synthetic lost acknowledgment".into(),
                ));
            }
            Ok(pin)
        }
    }
    for lost_sequence in [2_u64, 3] {
        let jp = temp.0.join(format!("unknown-lost-journal-{lost_sequence}"));
        let kp = temp.0.join(format!("unknown-lost-keeper-{lost_sequence}"));
        let tp = temp.0.join(format!("unknown-lost-target-{lost_sequence}"));
        let store =
            FileEffectJournal::create(&jp, EffectJournalLimits::default(), Arc::new(HostSpoolIo))?;
        let mut journal =
            archive::journal::UnknownTimeJournal::create(Box::new(store), scope, &cx)?;
        let jmin = journal.anchor();
        let store =
            FileEffectJournal::create(&kp, EffectJournalLimits::default(), Arc::new(HostSpoolIo))?;
        let mut keeper = archive::journal::UnknownTimeAnchorKeeper::create(
            Box::new(LoseUnknownAnchorAck {
                inner: store,
                lose_sequence: lost_sequence,
                fenced: false,
            }),
            &journal,
            &cx,
        )?;
        let kmin = keeper.anchor();
        let mut target = ReferenceDeployment::open(&tp, "site:unifi-av-archive-test", &cx)?;
        let result = archive::publish_unknown_time_av_anchored(
            &unknown_av,
            &mut target,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
            &mut journal,
            &mut keeper,
        );
        if lost_sequence == 2 {
            assert!(matches!(
                result,
                Err(archive::UnknownTimePublishError::BeforePublication(_))
            ));
            assert_eq!(journal.pending(), Some(unknown_pin));
        } else {
            assert!(
                matches!(result, Err(archive::UnknownTimePublishError::AfterPublication { receipt, .. })
                if receipt.outcome == RootLedgerOutcome::Committed)
            );
            assert_eq!(journal.confirmed(), Some(unknown_pin));
        }
        drop(keeper);
        drop(journal);
        drop(target);
        let store = FileEffectJournal::open(
            &jp,
            EffectJournalLimits::default(),
            Arc::new(HostSpoolIo),
            jmin,
        )?;
        let mut journal =
            archive::journal::UnknownTimeJournal::reopen(Box::new(store), scope, jmin, &cx)?;
        let store = FileEffectJournal::open(
            &kp,
            EffectJournalLimits::default(),
            Arc::new(HostSpoolIo),
            kmin,
        )?;
        let mut keeper = archive::journal::UnknownTimeAnchorKeeper::reopen(
            Box::new(store),
            &journal,
            kmin,
            &cx,
        )?;
        assert_eq!(keeper.target(), journal.anchor());
        let mut target = ReferenceDeployment::open(&tp, "site:unifi-av-archive-test", &cx)?;
        let receipt = archive::publish_unknown_time_av_anchored(
            &unknown_av,
            &mut target,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
            &mut journal,
            &mut keeper,
        )?;
        assert_eq!(receipt.root, unknown_pin.root);
        assert_eq!(
            receipt.outcome,
            if lost_sequence == 2 {
                RootLedgerOutcome::Committed
            } else {
                RootLedgerOutcome::AlreadyLedgered
            }
        );
        assert_eq!(journal.confirmed(), Some(unknown_pin));
        assert_eq!(journal.replay_pin(), None);
        assert_eq!(keeper.target(), journal.anchor());
    }
    access.allowed.set(false);
    let unknown_path = temp.0.join("unknown-time-deployment");
    let mut unknown_target =
        ReferenceDeployment::open(&unknown_path, "site:unifi-av-archive-test", &cx)?;
    assert!(matches!(
        archive::publish_unknown_time_av(
            &unknown_av,
            &mut unknown_target,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
        ),
        Err(archive::Error::Denied)
    ));
    assert!(unknown_target.ledger().batches().is_empty());
    access.allowed.set(true);
    let unknown_video_pin = archive::UnknownTimePin::from_plan(&unknown_video)
        .ok_or("missing unknown-time video pin")?;
    assert!(archive::Pin::from_plan(&unknown_video).is_none());
    assert!(archive::UnknownTimePin::from_plan(&video).is_none());
    assert!(matches!(
        archive::publish_unknown_time(
            &video,
            &mut unknown_target,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
        ),
        Err(archive::Error::Mismatch)
    ));
    let video_receipt = archive::publish_unknown_time(
        &unknown_video,
        &mut unknown_target,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &cx,
    )?;
    assert_eq!(video_receipt.root, unknown_video_pin.root);
    let config = video_configuration
        .as_ref()
        .ok_or("missing video configuration")?;
    assert_eq!(
        archive::read_unknown_time_object(
            &mut unknown_target,
            unknown_video_pin,
            ContentDigest::sha256(config.bytes()),
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
        )?,
        config.bytes()
    );
    // A root ledgered by another path with a narrow interval must not be
    // silently accepted as a fully unknown-time recording on retry or read.
    let mut narrowed = ReferenceDeployment::open(
        &temp.0.join("unknown-time-narrowed"),
        "site:unifi-av-archive-test",
        &cx,
    )?;
    unknown_video.visit_objects(|digest, bytes| {
        assert_eq!(narrowed.stage_payload(bytes).unwrap(), digest);
    });
    narrowed.ledgered_publisher().publish_and_commit(
        &archive::slot(&unknown_video)?,
        unknown_video.manifest(),
        CaptureInterval::point(TimestampNs(1)),
    )?;
    assert!(matches!(
        archive::read_unknown_time_object(
            &mut narrowed,
            unknown_video_pin,
            ContentDigest::sha256(config.bytes()),
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
        ),
        Err(archive::Error::Mismatch)
    ));
    assert!(matches!(
        archive::publish_unknown_time(
            &unknown_video,
            &mut narrowed,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
        ),
        Err(archive::Error::Mismatch)
    ));
    assert!(matches!(
        archive::publish_unknown_time_av(
            &av,
            &mut unknown_target,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
        ),
        Err(archive::Error::Mismatch)
    ));
    let first = archive::publish_unknown_time_av(
        &unknown_av,
        &mut unknown_target,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &cx,
    )?;
    let again = archive::publish_unknown_time_av(
        &unknown_av,
        &mut unknown_target,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &cx,
    )?;
    assert_eq!(first.root, unknown_pin.root);
    assert_eq!(again.outcome, RootLedgerOutcome::AlreadyLedgered);
    let batch = unknown_target
        .ledger()
        .batches()
        .last()
        .ok_or("missing ledger batch")?;
    assert_eq!(batch.deltas.len(), 1);
    assert_eq!(batch.deltas[0].validity.earliest, TimestampNs::MIN);
    assert_eq!(batch.deltas[0].validity.latest, TimestampNs::MAX);
    drop(unknown_target);
    let mut unknown_target =
        ReferenceDeployment::open(&unknown_path, "site:unifi-av-archive-test", &cx)?;
    let fragment_digest = ContentDigest::sha256(fragment.bytes());
    assert_eq!(
        archive::read_unknown_time_av_object(
            &mut unknown_target,
            unknown_pin,
            fragment_digest,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
        )?,
        fragment.bytes()
    );
    let unknown_clip = archive::read_unknown_time_av_clip(
        &mut unknown_target,
        unknown_pin,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(10_000_000_000),
        &cx,
    )?;
    let mut expected_unknown = av_init.bytes().to_vec();
    expected_unknown.extend_from_slice(fragment.bytes());
    assert_eq!(unknown_clip.bytes(), expected_unknown);
    assert_eq!(
        unknown_clip.video_samples(),
        segment.fragment().samples().len()
    );
    assert!(unknown_clip.audio().frames > 0);
    let unknown_video = archive::read_unknown_time_av_video_clip(
        &mut unknown_target,
        unknown_pin,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(10_000_000_000),
        &cx,
    )?;
    let mut expected_unknown_video = video_init.bytes().to_vec();
    expected_unknown_video.extend_from_slice(segment.fragment().bytes());
    assert_eq!(unknown_video.bytes(), expected_unknown_video);
    assert_eq!(unknown_video.samples(), segment.fragment().samples().len());
    assert_eq!(unknown_video.claimed_source(), KEY);
    assert!(!format!("{unknown_video:?}").contains("ftyp"));
    let forged_known_pin = archive::Pin {
        root: unknown_pin.root,
        retention: unknown_pin.retention,
        capture: CaptureInterval::new(TimestampNs::MIN, TimestampNs::MAX)?,
    };
    assert!(matches!(
        archive::read_av_object(
            &mut unknown_target,
            forged_known_pin,
            fragment_digest,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
        ),
        Err(archive::Error::Mismatch)
    ));
    assert!(matches!(
        archive::read_av_clip(
            &mut unknown_target,
            forged_known_pin,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(10_000_000_000),
            &cx,
        ),
        Err(archive::Error::Mismatch)
    ));
    access.allowed.set(false);
    assert!(matches!(
        archive::read_unknown_time_av_object(
            &mut unknown_target,
            unknown_pin,
            fragment_digest,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
        ),
        Err(archive::Error::Denied)
    ));
    assert!(matches!(
        archive::read_unknown_time_av_clip(
            &mut unknown_target,
            unknown_pin,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(10_000_000_000),
            &cx,
        ),
        Err(archive::Error::Denied)
    ));
    assert!(matches!(
        archive::read_unknown_time_av_video_clip(
            &mut unknown_target,
            unknown_pin,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(10_000_000_000),
            &cx,
        ),
        Err(archive::Error::Denied)
    ));
    access.allowed.set(false);
    let pin = archive::Pin::from_av_plan(&av).ok_or("missing pin")?;
    let supplied_pin = archive::Pin::from_av_plan(&supplied).ok_or("missing supplied pin")?;

    // In-band configuration must remain bound to the muxer and to the
    // published source graph; a provenance mismatch may not advance it.
    let mut inband_muxer = av_recording::Muxer::from_source(
        &av_init,
        &bound,
        origin.audio_ticks,
        0,
        8,
        8,
        Mp4Limits::default(),
    )?;
    let mut inband_target = ReferenceDeployment::open(
        &temp.0.join("transactional-inband"),
        "site:unifi-av-archive-test",
        &cx,
    )?;
    let inband_input = archive::AvSegmentPublication {
        segment: &segment,
        video_configuration: video_configuration
            .as_ref()
            .ok_or("missing video configuration")?,
        video_initialization: video_init,
        av_initialization: &av_init,
        audio: archive::AvSegmentAudio::InBand(&bound),
        retention,
        capture,
        evidence_limits: EvidenceLimits::default(),
    };
    let supplied_input = archive::AvSegmentPublication {
        audio: archive::AvSegmentAudio::SuppliedUnverified(bound.configuration()),
        ..inband_input
    };
    let remaining = inband_muxer.remaining_audio_frames();
    assert!(matches!(
        archive::publish_next_av_segment(
            &supplied_input,
            &mut inband_muxer,
            &mut inband_target,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
        ),
        Err(archive::AvSegmentPublishError::Binding)
    ));
    assert_eq!(inband_muxer.remaining_audio_frames(), remaining);
    let inband_input = archive::AvSegmentPublication {
        audio: archive::AvSegmentAudio::InBand(&bound),
        ..supplied_input
    };
    access.allowed.set(true);
    let result = archive::publish_next_av_segment(
        &inband_input,
        &mut inband_muxer,
        &mut inband_target,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &cx,
    )?;
    assert_eq!(result.pin, pin);
    assert_eq!(result.receipt.outcome, RootLedgerOutcome::Committed);
    let forged_unknown = archive::UnknownTimePin {
        root: pin.root,
        retention: pin.retention,
    };
    assert!(matches!(
        archive::read_unknown_time_av_object(
            &mut inband_target,
            forged_unknown,
            ContentDigest::sha256(fragment.bytes()),
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
        ),
        Err(archive::Error::Mismatch)
    ));
    let recovered_config = archive::read_av_audio_configuration(
        &mut inband_target,
        result.pin,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &cx,
    )?;
    assert_eq!(
        recovered_config.origin,
        fss_reference::unifi_direct::av_evidence::AudioConfigurationOrigin::InBand
    );
    assert_eq!(recovered_config.claimed_epoch, Some(1));
    access.allowed.set(false);

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
    // Rebind the original in-band AAC configuration from fully owned inputs.
    // This proves the owned path preserves its provenance classification.
    use fss_reference::unifi_direct::{av_bootstrap, av_owned_sink, pipeline};
    let mut collector = av_bootstrap::Collector::new(
        None,
        retention,
        av_owned_sink::BootstrapPolicy {
            allow_initial_video_only: false, max_separation_ms: 5_000,
            jitter_ms: 0,
            max_epoch_frames: 8,
            max_audio_frames: 8,
            media_limits: Mp4Limits::default(),
            evidence_limits: EvidenceLimits::default(),
        },
    );
    assert!(!collector.ready());
    assert!(matches!(
        collector.collect(
            Push::Source {
                record: video_configuration.ok_or("missing owned video configuration")?,
                disposition: SourceDisposition::Configuration
            },
            None
        ),
        av_bootstrap::Collected::Retained
    ));
    assert!(matches!(
        collector.collect(
            Push::Source {
                record: audio_record,
                disposition: SourceDisposition::PreRoll
            },
            Some(pipeline::AudioEvent::Observed(observation))
        ),
        av_bootstrap::Collected::Retained
    ));
    assert!(matches!(
        collector.collect(Push::Segment(segment), None),
        av_bootstrap::Collected::Retained
    ));
    assert!(collector.ready());
    let inputs = collector
        .into_inputs()
        .map_err(|_| "collector incomplete")?;
    let bootstrap = av_owned_sink::OwnedSink::bootstrap(inputs)
        .map_err(|_| "in-band owned sink bootstrap failed")?;
    assert_eq!(bootstrap.origin.audio_ticks, 1024);
    let mut owned = bootstrap.sink;
    assert!(owned.offer(bootstrap.first_segment, capture).is_ok());
    let mut owned_target = ReferenceDeployment::open(
        &temp.0.join("owned-inband"),
        "site:unifi-av-archive-test",
        &cx,
    )?;
    let store = FileEffectJournal::create(
        temp.0.join("owned-inband-journal"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut journal = archive::journal::Journal::create(
        Box::new(store),
        ContentDigest::sha256(b"owned in-band scope"),
        &cx,
    )?;
    let store = FileEffectJournal::create(
        temp.0.join("owned-inband-anchor"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut keeper = archive::journal::AnchorKeeper::create(Box::new(store), &journal, &cx)?;
    access.allowed.set(true);
    let published = owned
        .flush(
            &mut owned_target,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
            &mut journal,
            &mut keeper,
        )
        .map_err(|error| format!("owned in-band publication: {error:?}"))?
        .ok_or("missing owned in-band receipt")?;
    assert_eq!(published.pin, pin);
    let recovered = archive::read_av_audio_configuration(
        &mut owned_target,
        published.pin,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &cx,
    )?;
    assert_eq!(
        recovered.origin,
        fss_reference::unifi_direct::av_evidence::AudioConfigurationOrigin::InBand
    );
    assert_eq!(recovered.claimed_epoch, Some(1));
    assert!(!owned.has_pending());
    Ok(())
}

// Laboratory replay only: the input may contain a synthetic header and codec
// configuration. Capture time remains unknown; the private temporary archive
// must never be treated as authenticated physical camera evidence.
fn worker_replay_bounded_input(wire: &[u8]) -> TestResult {
    use asupersync::runtime::RuntimeBuilder;
    use fss_container::Mp4Limits;
    use fss_core::{
        BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
        RuntimeGrant, TaskId, TaskOutcome, TimestampNs, region::ContextAuthority,
    };
    use fss_geometry::WorkBudget;
    use fss_object::{
        HostSpoolIo,
        effect_journal::{EffectJournalLimits, FileEffectJournal},
    };
    use fss_packet::extended_flv::{
        aac,
        stream::{MAX_BUFFER_BYTES, SearchMode},
    };
    use fss_reference::{
        ReferenceDeployment, ReplayCx,
        unifi_direct::{
            archive, av_bootstrap, av_evidence::AudioConfigurationOrigin, av_owned_sink,
            av_recording, av_worker, evidence, metered::MeteredClock,
        },
    };
    use fss_runtime::{
        authority::AuthorityCx,
        execution::{TaskCompletion, TaskSpec, run_owned_async},
    };
    use std::{path::PathBuf, sync::Arc};

    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    struct Access(ContentDigest);
    impl archive::RetainAuthority for Access {
        fn permits(&self, retention: ContentDigest, _: ContentDigest) -> bool {
            retention == self.0
        }
    }
    impl archive::ReadAuthority for Access {
        fn permits(&self, retention: ContentDigest, _: ContentDigest) -> bool {
            retention == self.0
        }
    }

    if wire.is_empty() || wire.len() > MAX_BUFFER_BYTES {
        return Err("bounded replay input refused".into());
    }
    let mut framer = Framer::with_mode(
        FlvLimits::default(),
        MAX_BUFFER_BYTES,
        SearchMode::ZeroStreamId,
    )?;
    framer.append(0, wire)?;
    let mut recorder = Recorder::new(KEY, Limits::default())?;
    let limits = Mp4Limits::default();
    let retention = ContentDigest::sha256(b"private replay fixture retention");
    let mut collector = av_bootstrap::Collector::new(
        Some([0x14, 0x08]),
        retention,
        av_owned_sink::BootstrapPolicy {
            allow_initial_video_only: false, max_separation_ms: 5_000,
            jitter_ms: 5,
            max_epoch_frames: 1_000_000,
            max_audio_frames: limits.max_samples,
            media_limits: limits,
            evidence_limits: evidence::Limits::default(),
        },
    );
    let mut passthrough = Vec::new();
    while let Next::Record(record) = framer.take()? {
        let push = recorder.push(record).map_err(|refusal| refusal.reason)?;
        match collector.collect(push, None) {
            av_bootstrap::Collected::Retained => (),
            av_bootstrap::Collected::Forward {
                push: Push::Source { record, .. },
                audio: None,
            } => passthrough.push(record),
            av_bootstrap::Collected::Forward {
                push: Push::Buffered,
                audio: None,
            } => (),
            _ => return Err("unexpected collector result".into()),
        }
        if collector.ready() {
            break;
        }
    }
    let mut inputs = collector
        .into_inputs()
        .map_err(|_| "no completed source segment")?;
    for record in passthrough
        .iter()
        .chain(std::iter::once(&inputs.video_configuration))
        .chain(inputs.first_segment.source())
        .chain(inputs.first_segment.lookahead_copies())
    {
        let start = usize::try_from(record.offset())?;
        let end = start
            .checked_add(record.bytes().len())
            .ok_or("source range overflow")?;
        if wire.get(start..end) != Some(record.bytes()) {
            return Err("original source mismatch".into());
        }
    }
    let video_samples = inputs.first_segment.fragment().samples().len();
    let audio_bytes = [0x14, 0x08];
    let audio = aac::Configuration::parse_explicit(&audio_bytes)?;
    let expected_origin =
        av_recording::segment_sender_clock_origin(&inputs.first_segment, &audio, 5_000)?;
    inputs.audio = av_owned_sink::Audio::SuppliedUnverified([0, 0]);
    let refusal = match av_owned_sink::OwnedSink::bootstrap(inputs) {
        Err(refusal) => refusal,
        Ok(_) => return Err("invalid configuration was accepted".into()),
    };
    if refusal.reason != av_owned_sink::BootstrapError::AudioConfiguration {
        return Err("wrong bootstrap refusal".into());
    }
    let mut inputs = refusal.inputs;
    inputs.audio = av_owned_sink::Audio::SuppliedUnverified(audio_bytes);
    let temp =
        Temp(std::env::temp_dir().join(format!("fss-g4-worker-replay-{}", std::process::id())));
    std::fs::create_dir(&temp.0)?;
    let budget = BudgetVector::builder()
        .bytes(128 * 1024 * 1024)
        .storage_operations(10_000)
        .build()?;
    let replay_authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:private-camera-worker-replay".into(),
        operation_id: OperationId::parse("operation:private-camera-worker-replay")?,
        principal: "principal:fixture".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 1,
        budgets: budget,
        privacy_scope: "privacy:fixture".into(),
        retention_scope: "retention:fixture".into(),
        anchor_universe: ContentDigest::sha256(b"private camera worker replay"),
        generation: 1,
    })?;
    let replay = ReplayCx::from_context_authority(&replay_authority, temp.0.clone())?;
    let mut deployment = ReferenceDeployment::open(
        &temp.0.join("deployment"),
        "site:private-camera-replay",
        &replay,
    )?;
    // Exercise unknown-time publication with these same bounded source bytes.
    // Configuration and framing provenance remain the fixture's limitations.
    {
        let video_init = recorder
            .initialization()
            .ok_or("missing video initialization")?;
        let av_init = recorder
            .av_initialization(&audio)?
            .ok_or("missing A/V initialization")?;
        let mut muxer = av_recording::Muxer::new(
            &av_init,
            &audio,
            expected_origin.audio_ticks,
            5,
            1_000_000,
            limits.max_samples,
            limits,
        )?;
        let fragment = muxer.fragment(&av_init, &inputs.first_segment)?;
        let video = evidence::Prepared::new(
            &inputs.first_segment,
            &inputs.video_configuration,
            video_init,
            retention,
            evidence::Limits::default(),
        )?;
        let av = fss_reference::unifi_direct::av_evidence::PreparedAv::new_with_unverified_audio_configuration(
            &video, &audio, &av_init, &fragment, evidence::Limits::default(),
        )?;
        let pin = archive::UnknownTimePin::from_av_plan(&av).ok_or("unknown-time pin missing")?;
        let access = Access(retention);
        let journal_path = temp.0.join("unknown-time-journal");
        let keeper_path = temp.0.join("unknown-time-keeper");
        let scope = ContentDigest::sha256(b"private unknown-time replay scope");
        let store = FileEffectJournal::create(
            &journal_path,
            EffectJournalLimits::default(),
            Arc::new(HostSpoolIo),
        )?;
        let mut journal =
            archive::journal::UnknownTimeJournal::create(Box::new(store), scope, &replay)?;
        let journal_genesis = journal.anchor();
        let store = FileEffectJournal::create(
            &keeper_path,
            EffectJournalLimits::default(),
            Arc::new(HostSpoolIo),
        )?;
        let mut keeper =
            archive::journal::UnknownTimeAnchorKeeper::create(Box::new(store), &journal, &replay)?;
        let keeper_genesis = keeper.anchor();
        let inner = av_recording::Muxer::new(
            &av_init,
            &audio,
            expected_origin.audio_ticks,
            5,
            1_000_000,
            limits.max_samples,
            limits,
        )?;
        let mut transactional =
            archive::UnknownTimeMuxer::new(inner).map_err(|_| "unknown-time muxer not idle")?;
        let input = archive::UnknownTimeAvSegment {
            segment: &inputs.first_segment,
            video_configuration: &inputs.video_configuration,
            video_initialization: video_init,
            av_initialization: &av_init,
            audio: archive::AvSegmentAudio::SuppliedUnverified(&audio),
            retention,
            evidence_limits: evidence::Limits::default(),
        };
        let published = archive::publish_next_unknown_time_av_segment_anchored(
            &input,
            &mut transactional,
            &mut deployment,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(100_000_000_000),
            &replay,
            &mut journal,
            &mut keeper,
        )?;
        if published.pin != pin
            || published.receipt.root != pin.root
            || transactional.pending().is_some()
        {
            return Err("unknown-time root mismatch".into());
        }
        drop(keeper);
        drop(journal);
        let store = FileEffectJournal::open(
            &journal_path,
            EffectJournalLimits::default(),
            Arc::new(HostSpoolIo),
            journal_genesis,
        )?;
        let journal = archive::journal::UnknownTimeJournal::reopen(
            Box::new(store),
            scope,
            journal_genesis,
            &replay,
        )?;
        let store = FileEffectJournal::open(
            &keeper_path,
            EffectJournalLimits::default(),
            Arc::new(HostSpoolIo),
            keeper_genesis,
        )?;
        let keeper = archive::journal::UnknownTimeAnchorKeeper::reopen(
            Box::new(store),
            &journal,
            keeper_genesis,
            &replay,
        )?;
        if journal.confirmed() != Some(pin) || keeper.target() != journal.anchor() {
            return Err("unknown-time journal recovery mismatch".into());
        }
        let digest = ContentDigest::sha256(fragment.bytes());
        let recovered = archive::read_unknown_time_av_object(
            &mut deployment,
            pin,
            digest,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(100_000_000_000),
            &replay,
        )?;
        if recovered != fragment.bytes() {
            return Err("unknown-time fragment mismatch".into());
        }
        let clip = archive::read_unknown_time_av_clip(
            &mut deployment,
            pin,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(100_000_000_000),
            &replay,
        )?;
        if clip.video_samples() != video_samples || clip.audio().frames == 0 {
            return Err("unknown-time source mapping mismatch".into());
        }
        let count = clip.video_samples().min(3);
        let movie = AvcMp4::parse(clip.bytes(), None, DemuxLimits::default())?;
        let annex = movie.annex_b(0, count)?;
        let mut decoder = fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
        let mut frames = decoder.decode_annex_b(annex.bytes())?;
        frames.extend(decoder.finish()?);
        if frames.len() != count {
            return Err("unknown-time decoded frame count mismatch".into());
        }
    }
    // The asynchronous worker must commit a fresh root, not merely reopen the
    // graph just published by the separate transactional replay above.
    drop(deployment);
    let deployment = ReferenceDeployment::open(
        &temp.0.join("worker-deployment"),
        "site:private-camera-replay",
        &replay,
    )?;
    let bootstrap =
        av_owned_sink::OwnedSink::bootstrap(inputs).map_err(|_| "owned sink bootstrap refused")?;
    if bootstrap.origin != expected_origin {
        return Err("sender-clock origin mismatch".into());
    }
    let sink = bootstrap
        .sink
        .into_unknown_time()
        .map_err(|_| "unknown sink conversion failed")?;
    let segment = bootstrap.first_segment;
    let store = FileEffectJournal::create(
        temp.0.join("journal"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let journal = archive::journal::UnknownTimeJournal::create(
        Box::new(store),
        ContentDigest::sha256(b"private camera replay scope"),
        &replay,
    )?;
    let store = FileEffectJournal::create(
        temp.0.join("keeper"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let keeper =
        archive::journal::UnknownTimeAnchorKeeper::create(Box::new(store), &journal, &replay)?;
    let access = Arc::new(Access(retention));
    let policy: Arc<dyn archive::RetainAuthority + Send + Sync> = access.clone();
    let mut worker = av_worker::UnknownTimeWorker::new(av_worker::UnknownTimeParts {
        sink,
        deployment,
        journal,
        keeper,
        replay,
        authority: policy,
        limits: archive::Limits::default(),
        work_limit: 100_000_000_000,
    })
    .map_err(|_| "worker limits refused")?;
    worker.offer(segment).map_err(|_| "source offer refused")?;
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:private-camera-worker".into(),
            operation_id: OperationId::parse("operation:private-camera-worker")?,
            principal: "principal:fixture".into(),
            capabilities: vec![
                RuntimeGrant::ObjectStage.as_str().into(),
                RuntimeGrant::ObjectPublish.as_str().into(),
            ],
            deadline: None,
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:fixture".into(),
            retention_scope: "retention:fixture".into(),
            anchor_universe: ContentDigest::sha256(b"private camera worker replay"),
            generation: 1,
        },
        RegionId::new("region:private-camera-worker")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let run = run_owned_async(&mut authority, &mut tree,
            TaskSpec { task_id: TaskId::new("task:private-camera-worker")?, started_at: TimestampNs(2) }, &cx,
            async |task, cx| {
                let result: Result<(), String> = async {
                    let clock = MeteredClock::new(task, cx, TimestampNs(3)).map_err(|e| e.to_string())?;
                    let cost = BudgetVector::builder().bytes(4 * 1024 * 1024).storage_operations(1000).build().map_err(|e|e.to_string())?;
                    worker.start(task, cx, clock, "fixture:camera-replay", &cost).map_err(|e|format!("start: {e:?}"))?;
                    let completion = worker.join().await.ok_or("missing worker completion")?;
                    if completion.runtime.is_err() { return Err("archive task failed".into()); }
                    let pin = match completion.outcome {
                        av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Published(value))
                            if value.receipt.outcome == fss_publication::RootLedgerOutcome::Committed => value.pin,
                        av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Refused { stage, reason, .. }) => return Err(format!("archive refused: {stage:?} {reason:?}")),
                        _ => return Err("archive outcome not confirmed".into()),
                    };
                    let retired = worker.retire().map_err(|_| "worker did not retire")?;
                    if retired.fenced { return Err("worker fenced".into()); }
                    let mut parts = retired.parts;
                    let clip = archive::read_unknown_time_av_clip(&mut parts.deployment, pin, access.as_ref(), archive::Limits::default(),
                        &mut WorkBudget::new(100_000_000_000), &parts.replay).map_err(|e|format!("readback: {e}"))?;
                    if clip.video_samples() != video_samples || clip.audio().frames == 0 || clip.audio().configuration_origin != AudioConfigurationOrigin::SuppliedUnverified {
                        return Err("recovered source mapping mismatch".into());
                    }
                    let count = clip.video_samples().min(3);
                    let movie = AvcMp4::parse(clip.bytes(), None, DemuxLimits::default()).map_err(|e| format!("demux: {e}"))?;
                    let annex = movie.annex_b(0, count).map_err(|e| format!("annex-b: {e}"))?;
                    let mut decoder = fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default()).map_err(|e| format!("decoder: {e}"))?;
                    let mut frames = decoder.decode_annex_b(annex.bytes()).map_err(|e| format!("video decode: {e}"))?;
                    frames.extend(decoder.finish().map_err(|e| format!("video finish: {e}"))?);
                    if frames.len() != count { return Err("decoded frame count mismatch".into()); }
                    println!("worker_replay=passed video_samples={} audio_frames={} decoded_video_frames={} capture_bounds=unknown audio_configuration=unverified",clip.video_samples(),clip.audio().frames,frames.len());
                    Ok(())
                }.await;
                let outcome = if result.is_ok() { TaskOutcome::Success } else { TaskOutcome::Failed("private replay failed".into()) };
                TaskCompletion { output: result, outcome, completed_at: TimestampNs(60_000_000_000) }
            }).await?;
        run.receipt?;
        run.output.map_err(|e| -> Box<dyn std::error::Error> { e.into() })
    })?;
    Ok(())
}

#[test]
fn owned_archive_worker_replays_bounded_synthetic_av() -> TestResult {
    let (wire, _) = fixture_with_policy(0, false, false, false, Some(64), true)?;
    worker_replay_bounded_input(&wire)
}

#[test]
#[ignore = "requires private bounded replay input on stdin"]
fn owner_camera_worker_replay_from_stdin() -> TestResult {
    use std::io::Read;
    let mut wire = Vec::new();
    std::io::stdin()
        .lock()
        .take((8 * 1024 * 1024 + 1) as u64)
        .read_to_end(&mut wire)?;
    worker_replay_bounded_input(&wire)
}

#[test]
fn owned_sink_bootstrap_rejects_late_or_mismatched_sources_without_losing_them() -> TestResult {
    use fss_container::Mp4Limits;
    use fss_core::{CaptureInterval, ContentDigest, TimestampNs};
    use fss_reference::unifi_direct::{av_owned_sink, evidence};

    let (_, records) = fixture_with_audio_intervals(0, false, false, false, Some(64))?;
    let mut recorder = Recorder::new(KEY, Limits::default())?;
    let mut header = None;
    let mut video = None;
    let mut segments = Vec::new();
    for record in records {
        match recorder.push(record).map_err(|refusal| refusal.reason)? {
            Push::Source {
                record,
                disposition: SourceDisposition::Header,
            } => header = Some(record),
            Push::Source {
                record,
                disposition: SourceDisposition::Configuration,
            } => video = Some(record),
            Push::Segment(segment) => segments.push(segment),
            _ => (),
        }
    }
    let mut segments = segments.into_iter();
    let first = segments.next().ok_or("first segment missing")?;
    let second = segments.next().ok_or("second segment missing")?;
    let first_digest = ContentDigest::sha256(first.fragment().bytes());
    let second_digest = ContentDigest::sha256(second.fragment().bytes());
    let mut inputs = av_owned_sink::BootstrapInputs {
        video_configuration: video.ok_or("video configuration missing")?,
        audio: av_owned_sink::Audio::SuppliedUnverified([0x14, 0x08]),
        first_segment: second,
        retention: ContentDigest::sha256(b"bootstrap fixture retention"),
        policy: av_owned_sink::BootstrapPolicy {
            allow_initial_video_only: false, max_separation_ms: 5_000,
            jitter_ms: 0,
            max_epoch_frames: 8,
            max_audio_frames: 8,
            media_limits: Mp4Limits::default(),
            evidence_limits: evidence::Limits::default(),
        },
    };
    let refusal = match av_owned_sink::OwnedSink::bootstrap(inputs) {
        Err(refusal) => refusal,
        Ok(_) => return Err("late segment was accepted".into()),
    };
    assert_eq!(refusal.reason, av_owned_sink::BootstrapError::Sequence);
    inputs = refusal.inputs;
    assert_eq!(
        ContentDigest::sha256(inputs.first_segment.fragment().bytes()),
        second_digest
    );
    let recovered_second = std::mem::replace(&mut inputs.first_segment, first);
    assert_eq!(
        ContentDigest::sha256(recovered_second.fragment().bytes()),
        second_digest
    );
    let correct_video = std::mem::replace(
        &mut inputs.video_configuration,
        header.ok_or("header missing")?,
    );
    let refusal = match av_owned_sink::OwnedSink::bootstrap(inputs) {
        Err(refusal) => refusal,
        Ok(_) => return Err("mismatched video source was accepted".into()),
    };
    assert_eq!(refusal.reason, av_owned_sink::BootstrapError::VideoBinding);
    inputs = refusal.inputs;
    assert_eq!(
        ContentDigest::sha256(inputs.first_segment.fragment().bytes()),
        first_digest
    );
    inputs.video_configuration = correct_video;
    let bootstrap =
        av_owned_sink::OwnedSink::bootstrap(inputs).map_err(|_| "valid bootstrap refused")?;
    assert_eq!(bootstrap.origin.audio_ticks, 1024);
    assert!(!bootstrap.sink.has_pending());
    let mut sink = bootstrap.sink;
    let capture = CaptureInterval::new(TimestampNs(1), TimestampNs(2))?;
    assert!(sink.offer(bootstrap.first_segment, capture).is_ok());
    let (retained, bounds) = sink.retire().pending.ok_or("first segment lost")?;
    assert_eq!(bounds, capture);
    assert_eq!(
        ContentDigest::sha256(retained.fragment().bytes()),
        first_digest
    );
    Ok(())
}

#[test]
fn collector_preserves_mismatches_later_segments_and_interrupted_custody() -> TestResult {
    use fss_container::Mp4Limits;
    use fss_core::ContentDigest;
    use fss_packet::extended_flv::{aac, aac_track};
    use fss_reference::unifi_direct::{av_bootstrap, av_owned_sink, evidence, pipeline};

    let policy = av_owned_sink::BootstrapPolicy {
        allow_initial_video_only: false, max_separation_ms: 5_000,
        jitter_ms: 0,
        max_epoch_frames: 8,
        max_audio_frames: 8,
        media_limits: Mp4Limits::default(),
        evidence_limits: evidence::Limits::default(),
    };
    let retention = ContentDigest::sha256(b"collector retention");
    let incomplete = av_bootstrap::Collector::new(Some([0x14, 0x08]), retention, policy);
    let incomplete = match incomplete.into_inputs() {
        Err(value) => value.0,
        Ok(_) => return Err("incomplete collector accepted".into()),
    };
    let parts = incomplete.into_parts();
    assert_eq!(parts.retention, retention);
    assert!(parts.video.is_none() && parts.first_segment.is_none());
    assert!(matches!(
        parts.audio,
        Some(av_owned_sink::Audio::SuppliedUnverified([0x14, 0x08]))
    ));

    let (mut wire, original) = fixture_with_audio_intervals(0, false, false, false, Some(64))?;
    let insertion = usize::try_from(original[1].offset())? + original[1].bytes().len();
    let mut config_wire = vec![0x77; 3];
    config_wire.extend(tag(8, 0, &[0xaf, 0, 0x14, 0x08]));
    wire.splice(insertion..insertion, config_wire);
    let mut framer = Framer::new(FlvLimits::default(), 1024 * 1024)?;
    framer.append(0, &wire)?;
    let mut track = aac_track::Track::new(FlvLimits::default(), aac::Limits::default());
    let mut recorder = Recorder::new(KEY, Limits::default())?;
    let mut collector = av_bootstrap::Collector::new(None, retention, policy);
    let mut other_record = None;
    let mut mismatched = false;
    let mut forwarded_header = false;
    let mut forwarded_later = false;
    while let Next::Record(record) = framer.take()? {
        let observation = track.observe(&record)?;
        let event = match observation {
            aac_track::Observation::Header | aac_track::Observation::Other => None,
            value => Some(pipeline::AudioEvent::Observed(value)),
        };
        let push = recorder.push(record).map_err(|r| r.reason)?;
        if let Push::Source {
            record,
            disposition: SourceDisposition::Configuration,
        } = &push
        {
            other_record = Some(record.try_duplicate()?);
            let mut interrupted =
                av_bootstrap::Collector::new(Some([0x14, 0x08]), retention, policy);
            let digest = ContentDigest::sha256(record.bytes());
            assert!(matches!(
                interrupted.collect(
                    Push::Source {
                        record: record.try_duplicate()?,
                        disposition: SourceDisposition::Configuration
                    },
                    None
                ),
                av_bootstrap::Collected::Retained
            ));
            let interrupted = match interrupted.into_inputs() {
                Err(value) => value.0,
                Ok(_) => return Err("interrupted collector accepted".into()),
            };
            assert_eq!(
                ContentDigest::sha256(
                    interrupted
                        .into_parts()
                        .video
                        .ok_or("interrupted source lost")?
                        .bytes()
                ),
                digest
            );
        }
        let (push, event) = if matches!(
            event,
            Some(pipeline::AudioEvent::Observed(
                aac_track::Observation::Configuration { .. }
            ))
        ) {
            let wrong = other_record.take().ok_or("missing mismatched source")?;
            let wrong_digest = ContentDigest::sha256(wrong.bytes());
            let event = match collector.collect(
                Push::Source {
                    record: wrong,
                    disposition: SourceDisposition::PreRoll,
                },
                event,
            ) {
                av_bootstrap::Collected::Forward {
                    push: Push::Source { record, .. },
                    audio: Some(event),
                } => {
                    assert_eq!(ContentDigest::sha256(record.bytes()), wrong_digest);
                    event
                }
                _ => return Err("mismatched source or observation lost".into()),
            };
            mismatched = true;
            (push, Some(event))
        } else {
            (push, event)
        };
        if let av_bootstrap::Collected::Forward { push, audio: _ } = collector.collect(push, event)
        {
            match push {
                Push::Source {
                    disposition: SourceDisposition::Header,
                    ..
                } => forwarded_header = true,
                Push::Segment(_) => {
                    forwarded_later = true;
                    break;
                }
                _ => (),
            }
        }
    }
    assert!(mismatched && forwarded_header && forwarded_later && collector.ready());
    let inputs = collector
        .into_inputs()
        .map_err(|_| "collector lost original inputs")?;
    assert!(matches!(inputs.audio, av_owned_sink::Audio::InBand { .. }));
    let bootstrap =
        av_owned_sink::OwnedSink::bootstrap(inputs).map_err(|_| "collector inputs refused")?;
    assert_eq!(bootstrap.origin.audio_ticks, 1024);
    Ok(())
}

#[test]
fn async_unknown_time_worker_drains_cancelled_publication_and_retries() -> TestResult {
    use asupersync::{
        runtime::{RuntimeBuilder, yield_now},
        time::timeout,
    };
    use fss_container::Mp4Limits;
    use fss_core::{
        BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
        RuntimeGrant, TaskId, TaskOutcome, TimestampNs, region::ContextAuthority,
    };
    use fss_geometry::WorkBudget;
    use fss_object::{
        HostSpoolIo,
        effect_journal::{EffectJournalLimits, FileEffectJournal},
    };
    use fss_packet::extended_flv::aac;
    use fss_reference::{
        ReferenceDeployment, ReplayCx,
        unifi_direct::{
            archive, av_owned_sink, av_recording, av_worker, evidence, metered::MeteredClock,
        },
    };
    use fss_runtime::{
        authority::AuthorityCx,
        execution::{TaskCompletion, TaskSpec, run_owned_async},
    };
    use std::{
        future::{Future, poll_fn},
        path::PathBuf,
        pin::pin,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::Poll,
        time::Duration,
    };

    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    struct Retention {
        allow: AtomicBool,
        block: AtomicBool,
        entered: AtomicBool,
    }
    impl archive::RetainAuthority for Retention {
        fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
            self.entered.store(true, Ordering::Release);
            for _ in 0..2500 {
                if !self.block.load(Ordering::Acquire) {
                    return self.allow.load(Ordering::Acquire);
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            false
        }
    }
    impl archive::ReadAuthority for Retention {
        fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
            self.allow.load(Ordering::Acquire)
        }
    }
    struct Unblock(Arc<Retention>);
    impl Drop for Unblock {
        fn drop(&mut self) {
            self.0.block.store(false, Ordering::Release);
        }
    }

    let (_, records) = fixture_with_audio_intervals(0, false, false, false, Some(64))?;
    let mut recorder = Recorder::new(KEY, Limits::default())?;
    let mut configuration = None;
    let mut segments = Vec::new();
    for record in records {
        match recorder.push(record).map_err(|refusal| refusal.reason)? {
            Push::Source {
                record,
                disposition: SourceDisposition::Configuration,
            } => configuration = Some(record),
            Push::Segment(segment) => segments.push(segment),
            _ => (),
        }
    }
    assert_eq!(segments.len(), 2);
    let audio = [0x14, 0x08];
    let config = aac::Configuration::parse_explicit(&audio)?;
    let init = recorder
        .av_initialization(&config)?
        .ok_or("missing initialization")?;
    let muxer = av_recording::Muxer::new(&init, &config, 0, 0, 8, 8, Mp4Limits::default())?;
    let retention = ContentDigest::sha256(b"async worker retention");
    let sink = av_owned_sink::OwnedSink::new(av_owned_sink::Inputs {
        video_configuration: configuration.ok_or("missing configuration")?,
        av_initialization: init,
        audio: av_owned_sink::Audio::SuppliedUnverified(audio),
        muxer,
        retention,
        evidence_limits: evidence::Limits::default(),
        video_limits: Mp4Limits::default(),
    })
    .map_err(|_| "owned sink construction failed")?
    .into_unknown_time()
    .map_err(|_| "unknown sink conversion failed")?;
    let mut segments = segments.into_iter();
    let first = segments.next().ok_or("missing first segment")?;
    let second = segments.next().ok_or("missing second segment")?;
    let temp = Temp(std::env::temp_dir().join(format!(
        "fss-unifi-async-unknown-archive-{}",
        std::process::id()
    )));
    std::fs::create_dir(&temp.0)?;
    let budget = BudgetVector::builder()
        .bytes(128 * 1024 * 1024)
        .storage_operations(10_000)
        .build()?;
    let replay_context = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:async-archive-replay".into(),
        operation_id: OperationId::parse("operation:async-archive-replay")?,
        principal: "principal:fixture".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 1,
        budgets: budget,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"site:async-archive"),
        generation: 1,
    })?;
    let replay = ReplayCx::from_context_authority(&replay_context, temp.0.clone())?;
    let deployment =
        ReferenceDeployment::open(&temp.0.join("deployment"), "site:async-archive", &replay)?;
    let store = FileEffectJournal::create(
        temp.0.join("journal"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let journal = archive::journal::UnknownTimeJournal::create(
        Box::new(store),
        ContentDigest::sha256(b"async worker scope"),
        &replay,
    )?;
    let store = FileEffectJournal::create(
        temp.0.join("keeper"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let keeper =
        archive::journal::UnknownTimeAnchorKeeper::create(Box::new(store), &journal, &replay)?;
    let access = Arc::new(Retention {
        allow: AtomicBool::new(false),
        block: AtomicBool::new(true),
        entered: AtomicBool::new(false),
    });
    let _unblock = Unblock(Arc::clone(&access));
    let retain: Arc<dyn archive::RetainAuthority + Send + Sync> = access.clone();
    let mut worker = av_worker::UnknownTimeWorker::new(av_worker::UnknownTimeParts {
        sink,
        deployment,
        journal,
        keeper,
        replay,
        authority: retain,
        limits: archive::Limits::default(),
        work_limit: 4_000_000_000,
    })
    .map_err(|_| "invalid worker limits")?;
    assert!(worker.offer(first).is_ok());
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:async-archive".into(),
            operation_id: OperationId::parse("operation:async-archive")?,
            principal: "principal:fixture".into(),
            capabilities: vec![
                RuntimeGrant::ObjectStage.as_str().into(),
                RuntimeGrant::ObjectPublish.as_str().into(),
            ],
            deadline: None,
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"site:async-archive"),
            generation: 1,
        },
        RegionId::new("region:async-archive")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:async-archive")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |task, cx| {
                let output: Result<(), String> = async {
                    let clock =
                        MeteredClock::new(task, cx, TimestampNs(3)).map_err(|e| e.to_string())?;
                    let cost = BudgetVector::builder()
                        .bytes(1024 * 1024)
                        .storage_operations(1000)
                        .build()
                        .map_err(|e| e.to_string())?;
                    let other_cx = cx.clone();
                    if !matches!(
                        worker.start(task, &other_cx, clock, "fixture:archive", &cost),
                        Err(av_worker::StartError::Context)
                    ) {
                        return Err("foreign runtime context was accepted".into());
                    }
                    worker
                        .start(task, cx, clock, "fixture:archive", &cost)
                        .map_err(|e| format!("start: {e:?}"))?;
                    timeout(cx.now(), Duration::from_secs(5), async {
                        while !access.entered.load(Ordering::Acquire) {
                            yield_now().await;
                        }
                    })
                    .await
                    .map_err(|_| "archive did not enter worker")?;
                    let rejected = match worker.offer(second) {
                        Err(av_worker::UnknownTimeOfferRefusal::Busy(segment)) => segment,
                        _ => return Err("worker did not apply backpressure".into()),
                    };
                    worker.abort();
                    timeout(cx.now(), Duration::from_secs(5), async {
                        while !worker.cancellation_observed() {
                            yield_now().await;
                        }
                    })
                    .await
                    .map_err(|_| "worker cancellation was not observed")?;
                    let pending = poll_fn(|context| {
                        let mut wait = pin!(worker.join());
                        Poll::Ready(wait.as_mut().poll(context).is_pending())
                    })
                    .await;
                    if !pending {
                        return Err("worker joined before blocking retention released".into());
                    }
                    worker = match worker.retire() {
                        Err(worker) => worker,
                        Ok(_) => return Err("worker retired before its closure drained".into()),
                    };
                    access.block.store(false, Ordering::Release);
                    let completion = timeout(cx.now(), Duration::from_secs(5), worker.join())
                        .await
                        .map_err(|_| "worker drain timed out")?
                        .ok_or("worker completion missing")?;
                    if completion.runtime.is_err() {
                        return Err(
                            "cancelled coordinator did not preserve its drained result".into()
                        );
                    }
                    if !matches!(
                        completion.outcome,
                        av_worker::UnknownTimeOutcome::Publication(
                            av_worker::UnknownTimePublication::Refused {
                                stage: av_worker::UnknownTimeFailureStage::Archive,
                                reason: av_worker::FailureReason::CancelledOrDenied,
                                ..
                            }
                        )
                    ) {
                        return Err("cancelled archive outcome not retained".into());
                    }
                    access.allow.store(true, Ordering::Release);
                    worker
                        .start(task, cx, clock, "fixture:archive", &cost)
                        .map_err(|e| format!("retry: {e:?}"))?;
                    let completion = worker.join().await.ok_or("first receipt missing")?;
                    if completion.runtime.is_err() {
                        return Err("first coordinator failed".into());
                    }
                    let first = match completion.outcome {
                        av_worker::UnknownTimeOutcome::Publication(
                            av_worker::UnknownTimePublication::Published(value),
                        ) => value.pin,
                        _ => return Err("first archive retry failed".into()),
                    };
                    if worker.offer(rejected).is_err() {
                        return Err("second source refused".into());
                    }
                    worker
                        .start(task, cx, clock, "fixture:archive", &cost)
                        .map_err(|e| format!("second start: {e:?}"))?;
                    let completion = worker.join().await.ok_or("second receipt missing")?;
                    if completion.runtime.is_err() {
                        return Err("second coordinator failed".into());
                    }
                    let second = match completion.outcome {
                        av_worker::UnknownTimeOutcome::Publication(
                            av_worker::UnknownTimePublication::Published(value),
                        ) => value.pin,
                        _ => return Err("second archive failed".into()),
                    };
                    let retirement = worker.retire().map_err(|_| "worker failed to retire")?;
                    if retirement.fenced {
                        return Err("successful worker was fenced".into());
                    }
                    let mut parts = retirement.parts;
                    for pin in [first, second] {
                        let clip = archive::read_unknown_time_av_clip(
                            &mut parts.deployment,
                            pin,
                            access.as_ref(),
                            archive::Limits::default(),
                            &mut WorkBudget::new(100_000_000_000),
                            &parts.replay,
                        )
                        .map_err(|e| format!("readback: {e}"))?;
                        if clip.video_samples() == 0 || clip.audio().frames == 0 {
                            return Err("unknown-time clip incomplete".into());
                        }
                    }
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("archive worker fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(60_000_000_000),
                }
            },
        )
        .await?;
        run.receipt?;
        run.output
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })
    })?;
    Ok(())
}
