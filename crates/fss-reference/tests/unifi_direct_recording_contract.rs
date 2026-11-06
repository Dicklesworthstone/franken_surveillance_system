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
        let offset = if variable { (i as u32 * 100) / 3 } else { i as u32 * 40 };
        let timestamp = start.wrapping_add(offset);
        wire.extend([0x77; 3]);
        wire.extend(tag(8, timestamp, &[0xaf, 1, 2]));
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
        wire.extend([0x77; 2]);
        wire.extend(tag(9, timestamp, &payload));
    }
    let mut framer = Framer::new(FlvLimits::default(), 1024 * 1024)?;
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
    let mut durations = Vec::new();
    let mut original = Vec::new();
    let mut initialization = None;
    let mut segments = 0;
    for record in records {
        match recorder.push(record).map_err(|r| r.reason)? {
            Push::Source { record, disposition } => {
                if disposition == SourceDisposition::Configuration {
                    initialization = Some(recorder.initialization().ok_or("init")?.bytes().to_vec());
                }
                original.extend_from_slice(record.bytes());
            }
            Push::Buffered => {}
            Push::Segment(segment) => {
                durations.extend(segment.fragment().samples().iter().map(|s| s.duration_ms));
                for source in segment.source() { original.extend_from_slice(source.bytes()); }
                let mut mp4 = initialization.as_ref().ok_or("init")?.clone();
                mp4.extend_from_slice(segment.fragment().bytes());
                let movie = AvcMp4::parse(&mp4, None, DemuxLimits::default())?;
                let raw = movie.annex_b(0, 3)?;
                let mut decoder = fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
                let mut frames = decoder.decode_annex_b(raw.bytes())?;
                frames.extend(decoder.finish()?);
                assert_eq!(frames.len(), 3);
                segments += 1;
            }
        }
    }
    for source in recorder.retire().pending { original.extend_from_slice(source.bytes()); }
    assert_eq!(segments, 2);
    assert_eq!(durations, [33, 33, 34, 33, 33, 34]);
    assert_eq!(original, wire);
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
    let path =
        std::env::temp_dir().join(format!("fss-unifi-archive-{}-fixture", std::process::id()));
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
    let (_, records) = fixture(0, false, false)?;
    let mut recorder = Recorder::new(KEY, Limits::default())?;
    let mut configuration = None;
    for record in records {
        match recorder.push(record).map_err(|r| r.reason)? {
            Push::Source {
                record,
                disposition: SourceDisposition::Configuration,
            } => configuration = Some(record),
            Push::Segment(segment) => {
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
