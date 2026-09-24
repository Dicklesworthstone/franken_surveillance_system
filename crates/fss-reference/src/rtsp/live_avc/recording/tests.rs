#![forbid(unsafe_code)]
//! Native loopback -> real AVC syntax/packet assembly -> source-linked recording -> local custody.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::time::Duration;

use fss_core::{ContentDigest, SensorId, StreamId};
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel, SlotName};
use crate::rtsp::recording::{PreparedRecording, RecordingRole};
use crate::rtsp::recording::local::{RecordingPublication, RecordingProgress, load_recording};
use crate::rtsp::recording_capture::PictureTimingRequest;
use crate::rtsp::recording_collector::CollectionStop;
use crate::rtsp::live_avc::tests::{Authority, KEY, credentials, description, response, scope};
use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn recording(limits: CollectorLimits) -> TestResult<LiveRecordingConfig> {
    Ok(LiveRecordingConfig {
        scope: RecordingScope { sensor: SensorId::parse("sensor:live-fixture")?,
            stream: StreamId::parse("stream:live-fixture")?, generation: KEY.generation,
            anchor: ContentDigest::sha256(b"live owner anchor"),
            receive_clock: ContentDigest::sha256(b"live receive clock epoch") },
        payload_type: 96, time_scale: 90_000, limits,
    })
}
fn timing(decode_time: u64) -> RecordingTiming { RecordingTiming { decode_time, duration: 3_600, composition_offset: 0 } }
fn nals() -> Vec<&'static [u8]> {
    let bytes: &'static [u8] = include_bytes!("../../../../../fss-packet/tests/fixtures/avc/baseline.264");
    let mut out = Vec::new(); let mut start = None; let mut at = 0;
    while at + 3 <= bytes.len() {
        let prefix = if bytes.get(at..at + 4) == Some(&[0, 0, 0, 1]) { 4 }
            else if bytes[at..at + 3] == [0, 0, 1] { 3 } else { 0 };
        if prefix != 0 {
            if let Some(begin) = start {
                let mut end = at; while end > begin && bytes[end - 1] == 0 { end -= 1; }
                if begin < end { out.push(&bytes[begin..end]); }
            }
            start = Some(at + prefix); at += prefix;
        } else { at += 1; }
    }
    if let Some(begin) = start && begin < bytes.len() { out.push(&bytes[begin..]); }
    out
}
fn rtp(sequence: u16, timestamp: u32, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x80, 96 | if marker { 128 } else { 0 }];
    bytes.extend_from_slice(&sequence.to_be_bytes()); bytes.extend_from_slice(&timestamp.to_be_bytes());
    bytes.extend_from_slice(&KEY.ssrc.to_be_bytes()); bytes.extend_from_slice(payload); bytes
}
fn wire(datagram: &[u8]) -> TestResult<Vec<u8>> {
    let len = u16::try_from(datagram.len())?;
    let mut bytes = vec![b'$', 0]; bytes.extend_from_slice(&len.to_be_bytes()); bytes.extend_from_slice(datagram);
    Ok(bytes)
}
struct Fixture { driver: LiveAvcRecording, peer: TcpStream, authority: Authority }
impl Fixture {
    fn new(chunk: usize, limits: CollectorLimits) -> TestResult<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let (mut config, authority) = scope(listener.local_addr()?)?;
        config.transport.chunk_bytes = chunk;
        let driver = LiveAvcRecording::connect(config, recording(limits)?, 0, &authority)?;
        let (peer, _) = listener.accept()?;
        peer.set_read_timeout(Some(Duration::from_secs(2)))?;
        peer.set_write_timeout(Some(Duration::from_secs(2)))?;
        peer.set_nodelay(true)?;
        Ok(Self { driver, peer, authority })
    }
    fn command(&mut self, command: ClientCommand, now: u64) -> TestResult<u32> {
        let queued = self.driver.request(command, &credentials()?, [now.to_le_bytes()[0].wrapping_add(40); 16], now, &self.authority)?;
        for _ in 0..32_768 {
            match self.driver.poll(SocketReadiness { readable: false, writable: true }, now, &self.authority)? {
                LiveRecordingStep::Network(LiveAvcStep::Write(TcpWriteStep::Sent { cseq, bytes })) => {
                    assert_eq!((cseq, bytes), (queued.cseq, queued.bytes));
                    let mut original = vec![0; bytes]; self.peer.read_exact(&mut original)?;
                    return Ok(cseq);
                }
                LiveRecordingStep::Network(LiveAvcStep::Write(TcpWriteStep::Advanced { .. }) | LiveAvcStep::Pending(_)) => {},
                _ => return Err("unexpected output during explicit command dispatch".into()),
            }
        }
        Err("command send bound".into())
    }
    fn receive(&mut self, bytes: &[u8], now: u64) -> TestResult<Vec<LiveRecordingStep>> {
        self.peer.write_all(bytes)?;
        let mut originals = Vec::new(); let mut outputs = Vec::new();
        for _ in 0..32_768 {
            let step = self.driver.poll(SocketReadiness { readable: true, writable: false }, now, &self.authority)?;
            match step {
                LiveRecordingStep::Network(LiveAvcStep::Wire(chunk)) => {
                    originals.extend_from_slice(chunk.expose()); assert_eq!(chunk.admitted_ns(), now);
                }
                LiveRecordingStep::Network(LiveAvcStep::Pending(wait)) => {
                    if originals.len() == bytes.len() && wait.wake_at_ns.is_none_or(|at| at > now) {
                        assert_eq!(originals, bytes); return Ok(outputs);
                    }
                    std::thread::yield_now();
                }
                other => {
                    let stop = match &other {
                        LiveRecordingStep::Stopped { .. } => true,
                        LiveRecordingStep::Capture { event, .. } => matches!(**event,
                            CapturePoll::TimingRequired(_) | CapturePoll::Backpressure(_)
                            | CapturePoll::Stopped { .. } | CapturePoll::Ended { .. }),
                        _ => false,
                    };
                    outputs.push(other);
                    if stop { assert_eq!(originals, bytes); return Ok(outputs); }
                }
            }
        }
        Err("bounded live recording receive did not drain".into())
    }
    fn playing(chunk: usize, limits: CollectorLimits) -> TestResult<Self> {
        let mut f = Self::new(chunk, limits)?;
        let seq = f.command(ClientCommand::Describe, 0)?;
        f.receive(&response(seq, "Content-Type: application/sdp\r\n", description()), 1)?;
        let seq = f.command(ClientCommand::Setup, 2)?;
        f.receive(&response(seq, "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n", ""), 3)?;
        let seq = f.command(ClientCommand::Play, 4)?;
        f.receive(&response(seq, "Session: fixture\r\n", ""), 5)?;
        assert_eq!(f.driver.state(), ClientState::Playing);
        Ok(f)
    }
    fn idr(&mut self) -> TestResult<(Vec<u8>, PictureTimingRequest)> {
        let data = nals(); let sps = data.iter().find(|n| n[0] & 31 == 7).ok_or("missing SPS")?;
        let idr = data.iter().find(|n| n[0] & 31 == 5).ok_or("missing real IDR")?;
        // The first sequential packet establishes probation; it is still returned as original wire.
        self.receive(&wire(&rtp(1, 9_000, false, sps))?, 10)?;
        let original = rtp(2, 9_000, true, idr);
        let outputs = self.receive(&wire(&original)?, 11)?;
        let request = outputs.iter().find_map(|step| match step {
            LiveRecordingStep::Capture { event, .. } => match **event {
                CapturePoll::TimingRequired(request) => Some(request), _ => None,
            },
            _ => None,
        }).ok_or("real IDR did not request independent timing")?;
        Ok((original, request))
    }
    fn completed_window(&mut self) -> TestResult<PreparedRecording> {
        let (_, request) = self.idr()?;
        assert!(request.idr); assert_eq!(request.rtp_timestamp, 9_000);
        assert!(matches!(self.driver.supply_timing(timing(700), 12, &self.authority)?, TimedCapture::Collected { .. }));
        assert!(self.driver.seal(13, &self.authority)?);
        match self.driver.poll(SocketReadiness::default(), 13, &self.authority)? {
            LiveRecordingStep::Capture { event, connection: None } => match *event {
                CapturePoll::Window(window) => Ok(window),
                _ => Err("prepared recording not returned before further network input".into()),
            },
            _ => Err("prepared recording not returned before further network input".into()),
        }
    }
}

#[test]
fn invalid_recording_generation_refuses_before_network_authority() -> TestResult {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let (config, authority) = scope(listener.local_addr()?)?;
    let mut recording = recording(CollectorLimits::default())?; recording.scope.generation += 1;
    let error = LiveAvcRecording::connect(config, recording, 0, &authority).err().ok_or("accepted mismatched generation")?;
    assert_eq!(error.reason, LiveRecordingError::Capture(CaptureError::Collection(CollectorError::Configuration)));
    assert!(!error.connection_attempted);
    Ok(())
}

#[test]
fn actual_socket_picture_requests_timing_and_backpressures_further_reads() -> TestResult {
    let mut f = Fixture::playing(7, CollectorLimits::default())?;
    let (original, picture) = f.idr()?;
    assert_eq!(picture.key, KEY);
    let reads = f.driver.totals().ok_or("missing totals")?.read_calls;
    f.peer.write_all(b"must not be read while timing is pending")?;
    for now in 12..16 {
        assert!(matches!(f.driver.poll(SocketReadiness { readable: true, writable: true }, now, &f.authority)?,
            LiveRecordingStep::Capture { event, connection: None }
                if matches!(*event, CapturePoll::TimingRequired(request) if request == picture)));
    }
    assert_eq!(f.driver.totals().ok_or("missing totals")?.read_calls, reads);
    let retired = f.driver.cancel().ok_or("missing cancellation")?;
    assert!(retired.capture.picture.is_some());
    assert!(retired.capture.collection.pending.sources.iter().any(|s| s.bytes() == original));
    assert!(retired.connection.ok_or("lost network retirement")?.protocol.client.session.remote_session_may_exist);
    assert!(f.driver.cancel().is_none());
    Ok(())
}

#[test]
fn timing_refusal_preserves_picture_and_does_not_substitute_rtp_or_arrival_time() -> TestResult {
    let mut f = Fixture::playing(4096, CollectorLimits::default())?;
    let (_, picture) = f.idr()?;
    let mut bad = timing(700); bad.duration = 0;
    let error = f.driver.supply_timing(bad, 12, &f.authority).err().ok_or("zero duration accepted")?;
    assert!(error.retirement.is_none());
    assert!(matches!(f.driver.poll(SocketReadiness::default(), 12, &f.authority)?,
        LiveRecordingStep::Capture { event, .. }
            if matches!(*event, CapturePoll::TimingRequired(request) if request == picture)));
    let _ = f.driver.supply_timing(timing(700), 13, &f.authority)?;
    assert!(f.driver.seal(14, &f.authority)?);
    let LiveRecordingStep::Capture { event, .. } =
        f.driver.poll(SocketReadiness::default(), 14, &f.authority)? else { return Err("window missing".into()); };
    let CapturePoll::Window(window) = *event else { return Err("window missing".into()); };
    assert_eq!(window.summary().decode_interval, 700..4300);
    assert_eq!(window.summary().time_scale, 90_000);
    Ok(())
}

#[test]
fn timing_deadline_stops_the_socket_and_retains_unsealed_source() -> TestResult {
    let mut f = Fixture::playing(4096, CollectorLimits::default())?;
    let (original, _) = f.idr()?;
    let deadline = 11 + crate::rtsp::recording_capture::MAX_PENDING_EVENT_AGE_NS;
    let step = f.driver.poll(SocketReadiness::default(), deadline, &f.authority)?;
    let LiveRecordingStep::Capture { event, connection: Some(connection) } = step
        else { return Err("timing expiry did not close both layers".into()); };
    let CapturePoll::Stopped { reason: CollectionStop::Deadline, retained, .. } = *event
        else { return Err("timing expiry did not close both layers".into()); };
    assert!(retained.picture.is_some());
    assert!(retained.collection.pending.sources.iter().any(|source| source.bytes() == original));
    assert!(connection.protocol.client.session.remote_session_may_exist);
    assert!(matches!(f.driver.poll(SocketReadiness::default(), deadline, &f.authority)?, LiveRecordingStep::Ended));
    Ok(())
}

#[test]
fn revocation_during_timing_wait_closes_without_reading_more_media() -> TestResult {
    let mut f = Fixture::playing(4096, CollectorLimits::default())?;
    let (original, _) = f.idr()?;
    let reads = f.driver.totals().ok_or("missing totals")?.read_calls;
    f.authority.revoked.set(true);
    let error = f.driver.poll(SocketReadiness { readable: true, writable: false }, 12, &f.authority)
        .err().ok_or("revoked session delivered a picture")?;
    let retired = error.retirement.ok_or("revocation lost source")?;
    assert_eq!(retired.connection.as_ref().ok_or("missing network retirement")?.transport.totals.read_calls, reads);
    assert!(retired.capture.collection.pending.sources.iter().any(|source| source.bytes() == original));
    assert!(retired.capture.picture.is_some());
    Ok(())
}

#[test]
fn collection_pressure_never_reads_ahead_and_sealing_releases_the_bounded_prefix() -> TestResult {
    let mut f = Fixture::playing(4096, CollectorLimits { max_packets: 1, ..CollectorLimits::default() })?;
    f.idr()?; let _ = f.driver.supply_timing(timing(0), 12, &f.authority)?;
    let data = nals(); let predicted = data.iter().find(|n| n[0] & 31 == 1).ok_or("missing P slice")?;
    let outputs = f.receive(&wire(&rtp(3, 12_600, true, predicted))?, 13)?;
    assert!(outputs.iter().any(|step| matches!(step,
        LiveRecordingStep::Capture { event, .. }
            if matches!(**event, CapturePoll::Backpressure(CollectorError::Capacity)))));
    let reads = f.driver.totals().ok_or("missing totals")?.read_calls;
    assert!(matches!(f.driver.poll(SocketReadiness { readable: true, writable: true }, 13, &f.authority)?,
        LiveRecordingStep::Capture { event, .. } if matches!(*event, CapturePoll::Backpressure(_))));
    assert_eq!(f.driver.totals().ok_or("missing totals")?.read_calls, reads);
    assert!(f.driver.seal(14, &f.authority)?);
    assert!(matches!(f.driver.poll(SocketReadiness::default(), 14, &f.authority)?,
        LiveRecordingStep::Capture { event, .. } if matches!(*event, CapturePoll::Window(_))));
    // The unconsumed next source event is still owned and can now enter the empty collector.
    assert!(matches!(f.driver.poll(SocketReadiness::default(), 14, &f.authority)?,
        LiveRecordingStep::Capture { event, .. } if matches!(*event, CapturePoll::Receiver(_))));
    assert_eq!(f.driver.collector().retained_packets(), 1);
    Ok(())
}

struct RunDirectory(std::path::PathBuf);
impl RunDirectory {
    fn new() -> TestResult<Self> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        for _ in 0..128 {
            let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("fss-live-recording-{}-{id}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {},
                Err(e) => return Err(e.into()),
            }
        }
        Err("exclusive test directory capacity exhausted".into())
    }
}
impl Drop for RunDirectory { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }

#[test]
fn socket_recording_publishes_source_first_and_reopens_with_identical_root_and_bytes() -> TestResult {
    let mut expected_root = None;
    for chunk in [1, 7, 4096] {
        let mut f = Fixture::playing(chunk, CollectorLimits::default())?;
        let window = f.completed_window()?;
        if let Some(root) = expected_root { assert_eq!(window.manifest().root(), root); }
        else { expected_root = Some(window.manifest().root()); }
        assert_eq!(window.summary().packets, 1); assert_eq!(window.summary().samples, 1);
        let run = RunDirectory::new()?;
        let path = run.0.join("publication");
        let limits = LocalPublicationLimits::new(8, 16, 8, 64,
            SpoolLimits::new(64, 4 * 1024 * 1024, 1024 * 1024, 64));
        let slot = SlotName::parse("live-avc-window")?;
        {
            let mut publisher = LocalRootPublisher::open(&path, limits)?;
            {
                let mut job = RecordingPublication::new(&window, &mut publisher, slot.clone(), window.byte_len(), 100)?;
                assert!(matches!(job.step(14, &NeverCancel)?,
                    RecordingProgress::ChildStaged { role: RecordingRole::Source, remaining: 3, .. }));
                for at in 15..18 { let _ = job.step(at, &NeverCancel)?; }
            }
            assert!(publisher.root(&slot).is_none());
            let mut job = RecordingPublication::new(&window, &mut publisher, slot.clone(), window.byte_len(), 100)?;
            let mut published = false;
            for at in 18..23 {
                if let RecordingProgress::Published(receipt) = job.step(at, &NeverCancel)? {
                    assert_eq!(receipt.root, window.manifest().root()); published = true;
                }
            }
            assert!(published);
        }
        let publisher = LocalRootPublisher::open(&path, limits)?;
        let recovered = load_recording(&publisher, &slot, window.manifest().root(), &window.summary().scope, &NeverCancel)?;
        assert_eq!(recovered.objects().source, window.objects().source);
        assert_eq!(recovered.objects().media, window.objects().media);
        assert_eq!(recovered.summary(), window.summary());
        assert!(f.driver.cancel().is_some());
    }
    Ok(())
}

#[test]
fn actual_eof_drains_completed_window_without_fabricating_another_picture() -> TestResult {
    let mut f = Fixture::playing(4096, CollectorLimits::default())?;
    f.idr()?; let _ = f.driver.supply_timing(timing(700), 12, &f.authority)?;
    f.peer.shutdown(Shutdown::Write)?;
    let mut windows = 0; let mut saw_eof = false; let mut closed = false;
    for _ in 0..2048 {
        match f.driver.poll(SocketReadiness { readable: true, writable: false }, 13, &f.authority)? {
            LiveRecordingStep::Network(LiveAvcStep::InputEnded) => saw_eof = true,
            LiveRecordingStep::Capture { event, .. } => match *event {
                CapturePoll::Window(window) => {
                    assert!(saw_eof); windows += 1; assert_eq!(window.summary().samples, 1);
                }
                CapturePoll::Ended { .. } => { closed = true; break; }
                _ => std::thread::yield_now(),
            },
            LiveRecordingStep::Stopped { .. } => return Err("clean EOF incorrectly became a source failure".into()),
            _ => std::thread::yield_now(),
        }
    }
    assert!(closed); assert_eq!(windows, 1);
    assert!(matches!(f.driver.poll(SocketReadiness::default(), 13, &f.authority)?, LiveRecordingStep::Ended));
    Ok(())
}

#[test]
fn wrong_stream_fault_stops_capture_without_sealing_pending_pictures() -> TestResult {
    let mut f = Fixture::playing(4096, CollectorLimits::default())?;
    let (original, _) = f.idr()?;
    let _ = f.driver.supply_timing(timing(0), 12, &f.authority)?;
    let data = nals(); let predicted = data.iter().find(|n| n[0] & 31 == 1).ok_or("missing P slice")?;
    let mut packet = rtp(3, 12_600, true, predicted);
    packet[8..12].copy_from_slice(&8_u32.to_be_bytes()); // not the owner's fixed SSRC
    let events = f.receive(&wire(&packet)?, 13)?;
    let stopped = events.into_iter().find_map(|step| match step {
        LiveRecordingStep::Stopped { trigger, retained } => Some((trigger, retained)), _ => None,
    }).ok_or("wrong stream did not stop the recording owner")?;
    assert!(matches!(*stopped.0, LiveAvcStep::Protocol { transport: Some(_), .. }));
    assert!(stopped.1.collection.ready.is_none());
    assert_eq!(stopped.1.collection.pending.pictures.len(), 1);
    assert!(stopped.1.collection.pending.sources.iter().any(|s| s.bytes() == original));
    assert!(matches!(f.driver.poll(SocketReadiness::default(), 13, &f.authority)?, LiveRecordingStep::Ended));
    Ok(())
}

#[test]
fn eof_mid_fragment_never_becomes_a_completed_recording() -> TestResult {
    let mut f = Fixture::playing(7, CollectorLimits::default())?;
    let data = nals();
    let sps = data.iter().find(|n| n[0] & 31 == 7).ok_or("missing SPS")?;
    let idr = data.iter().find(|n| n[0] & 31 == 5).ok_or("missing IDR")?;
    f.receive(&wire(&rtp(1, 9_000, false, sps))?, 10)?;
    let mut start = vec![(idr[0] & 0x60) | 28, (idr[0] & 31) | 128];
    start.extend_from_slice(&idr[1..(1 + idr.len() / 2)]);
    let incomplete = rtp(2, 9_000, false, &start);
    f.receive(&wire(&incomplete)?, 11)?;
    f.peer.shutdown(Shutdown::Write)?;
    let mut terminal = false;
    for _ in 0..2048 {
        match f.driver.poll(SocketReadiness { readable: true, writable: false }, 12, &f.authority)? {
            LiveRecordingStep::Capture { event, .. } => match *event {
                CapturePoll::Window(_) | CapturePoll::TimingRequired(_) => {
                    return Err("incomplete FU-A acquired invented picture or recording boundary".into());
                }
                CapturePoll::Stopped { retained, .. } => {
                    assert!(retained.collection.ready.is_none());
                    assert!(retained.collection.pending.sources.iter().any(|s| s.bytes() == incomplete));
                    terminal = true; break;
                }
                CapturePoll::Ended { .. } => { terminal = true; break; }
                _ => std::thread::yield_now(),
            },
            LiveRecordingStep::Stopped { retained, .. } => {
                assert!(retained.collection.ready.is_none()); terminal = true; break;
            }
            _ => std::thread::yield_now(),
        }
    }
    assert!(terminal);
    Ok(())
}
