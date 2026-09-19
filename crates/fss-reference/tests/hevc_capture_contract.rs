#![forbid(unsafe_code)]
//! Supplied TCP -> real RTSP/HEVC -> collection -> existing durable readback contracts.
mod hevc_recording_support;
use hevc_recording_support::*;
use fss_packet::{H265Limits, ReorderLimits, StreamKey};
use fss_packet::hevc::HevcAssemblyLimits;
use fss_reference::rtsp::authentication::{DigestCredentials, DigestPolicy};
use fss_reference::rtsp::client::{ClientCommand as C, ClientConfig};
use fss_reference::rtsp::framed::MAX_WIRE_CHUNK;
use fss_reference::rtsp::hevc_client::{HevcClientPoll, pictures::{RtspHevcPictureClient, HevcPictureClientPoll as Event}};
use fss_reference::rtsp::hevc_recording_collector::HevcRecordingCollector;
use fss_reference::rtsp::hevc_recording_capture::{CaptureError, HevcRecordingCapture,
    HevcCapturePoll as P, TimedHevcCapture, MAX_PENDING_EVENT_AGE_NS};
use fss_reference::rtsp::recording::hevc::{PreparedHevcRecording, verify_hevc_recording};
use fss_reference::rtsp::recording_collector::{CollectorError as E, CollectorLimits, CollectionStop};

type TestResult = Result<(), Error>;
const KEY: StreamKey = StreamKey { ingress: 1, generation: 1, ssrc: SSRC };
fn config() -> ClientConfig {
    ClientConfig { presentation_uri: "rtsp://fixture.local/live/".into(),
        control_root_uri: "rtsp://fixture.local/live".into(), media_index: 0, channels: (0, 1),
        response_timeout_ns: 10_000_000_000, default_session_timeout_seconds: 60 }
}
fn response(cseq: u32, fields: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut wire = format!("RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n", body.len());
    for (key, value) in fields { wire.push_str(&format!("{key}: {value}\r\n")); }
    wire.push_str("\r\n"); let mut wire = wire.into_bytes(); wire.extend_from_slice(body); wire
}
fn framed(channel: u8, bytes: &[u8]) -> Vec<u8> {
    let mut wire = vec![b'$', channel]; wire.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    wire.extend_from_slice(bytes); wire
}
fn waiting(event: &Event, now: u64) -> bool {
    matches!(event, Event::Pending { wake_at_ns } if wake_at_ns.is_none_or(|at| at > now)) || matches!(event, Event::Client { event, .. }
        if matches!(event.as_ref(), HevcClientPoll::AuthenticationRequired { .. }
            | HevcClientPoll::Backpressure { .. } | HevcClientPoll::KeepAliveDue))
}
fn control(client: &mut RtspHevcPictureClient, wire: &[u8], now: u64) -> Result<Vec<Event>, Error> {
    client.ingest(wire, now)?; let mut out = Vec::new();
    for _ in 0..1000 {
        let event = client.poll(now)?; let stop = waiting(&event, now); out.push(event);
        if stop { return Ok(out); }
    }
    Err("control drain bound".into())
}
fn client(digest: bool) -> Result<RtspHevcPictureClient, Error> {
    let mut client = if digest {
        RtspHevcPictureClient::with_digest(config(), KEY, ReorderLimits::default(), H265Limits::default(),
            HevcAssemblyLimits::default(), "test-realm", DigestPolicy::default())?
    } else { RtspHevcPictureClient::new(config(), KEY, ReorderLimits::default(), H265Limits::default(), HevcAssemblyLimits::default())? };
    let credentials = DigestCredentials::new("test-user", "test-password")?;
    let request = if digest { client.request_digest(C::Describe, &credentials, [1; 16], 0)? }
        else { client.request(C::Describe, 0)? };
    let mut cseq = request.cseq();
    if digest {
        let raw = b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Digest realm=\"test-realm\", nonce=\"test-nonce\", algorithm=SHA-256, qop=\"auth\"\r\nContent-Length: 0\r\n\r\n";
        control(&mut client, raw, 1)?;
        cseq = client.respond_digest(&credentials, [2; 16], 2)?.request.cseq();
        assert!(matches!(client.poll(2)?, Event::Pending { .. }));
    }
    let sdp = b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 98\r\na=rtpmap:98 H265/90000\r\na=control:track\r\n";
    control(&mut client, &response(cseq, &[("Content-Type", "application/sdp")], sdp), 3)?;
    let setup = if digest { client.request_digest(C::Setup, &credentials, [3; 16], 4)? }
        else { client.request(C::Setup, 4)? };
    control(&mut client, &response(setup.cseq(), &[("Session", "test-session;timeout=60"),
        ("Transport", "RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7")], &[]), 5)?;
    let play = if digest { client.request_digest(C::Play, &credentials, [4; 16], 6)? }
        else { client.request(C::Play, 6)? };
    control(&mut client, &response(play.cseq(), &[("Session", "test-session")], &[]), 7)?;
    Ok(client)
}
fn input() -> Result<Vec<Packet>, Error> {
    let mut input = packets()?;
    for (i, p) in input.iter_mut().enumerate() {
        p.sequence = i as u64 + 1;
        p.bytes[2..4].copy_from_slice(&(p.sequence as u16).to_be_bytes());
    }
    Ok(input)
}
struct Harness {
    client: RtspHevcPictureClient,
    capture: HevcRecordingCapture,
    output: Vec<P>,
    timed: Vec<TimedHevcCapture>,
}
impl Harness {
    fn new(digest: bool, limits: CollectorLimits) -> Result<Self, Error> {
        let collector = HevcRecordingCollector::new(scope()?, KEY, PT, configuration()?, 90_000, limits)?;
        let mut h = Self { client: client(digest)?, capture: HevcRecordingCapture::new(collector), output: Vec::new(), timed: Vec::new() };
        h.feed(&framed(0, &packet(0, 0, false, &nals()?[0]).bytes), 10, true)?; // probation, not recording source
        Ok(h)
    }
    fn feed(&mut self, wire: &[u8], now: u64, automatic_timing: bool) -> Result<(), Error> {
        for chunk in wire.chunks(MAX_WIRE_CHUNK) {
            self.client.ingest(chunk, now)?;
            self.pump(now, automatic_timing)?;
        }
        Ok(())
    }
    fn pump(&mut self, now: u64, automatic_timing: bool) -> Result<(), Error> {
        for _ in 0..1000 {
            let event = self.client.poll(now)?; let stop = waiting(&event, now);
            self.capture.offer(event, now)?;
            if self.drain(now, automatic_timing)? || stop { return Ok(()); }
        }
        Err("upstream drain bound".into())
    }
    fn drain(&mut self, now: u64, automatic_timing: bool) -> Result<bool, Error> {
        for _ in 0..1000 {
            let output = self.capture.poll(now)?;
            if matches!(&output, P::TimingRequired(_)) && automatic_timing {
                let t = timings(self.timed.len() + 1)[self.timed.len()];
                self.timed.push(self.capture.supply_timing(t, now)?);
                continue;
            }
            let idle = matches!(&output, P::Pending { .. });
            let blocked = matches!(&output, P::TimingRequired(_) | P::Backpressure { .. } | P::Stopped { .. } | P::Ended { .. });
            self.output.push(output);
            if idle || blocked { return Ok(blocked); }
        }
        Err("capture drain bound".into())
    }
    fn windows(&self) -> Vec<&PreparedHevcRecording> {
        self.output.iter().filter_map(|p| match p { P::Window(w) => Some(w), _ => None }).collect()
    }
}

#[test]
fn plain_and_digest_tcp_streams_collect_identical_media_without_changing_authentication() -> TestResult {
    let mut roots = Vec::new();
    for digest in [false, true] {
        let mut h = Harness::new(digest, CollectorLimits::default())?;
        for (i, p) in input()?.iter().enumerate() { h.feed(&framed(0, &p.bytes), 20 + i as u64, true)?; }
        h.client.finish(); h.pump(40, true)?;
        let windows = h.windows(); assert_eq!(windows.len(), 2); assert_eq!(h.timed.len(), 4);
        for w in &windows { verify_hevc_recording(w.manifest(), w.objects(), &scope()?)?; }
        roots.push(windows.iter().map(|w| w.manifest().root()).collect::<Vec<_>>());
        assert!(matches!(h.output.last(), Some(P::Ended { retained: Some(_) })));
        assert!(matches!(h.capture.poll(41)?, P::Ended { retained: None }));
    }
    assert_eq!(roots[0], roots[1]);
    Ok(())
}

#[test]
fn timing_is_explicit_retryable_and_does_not_refresh_the_held_picture_deadline() -> TestResult {
    let mut h = Harness::new(false, CollectorLimits::default())?;
    for (i, p) in input()?[..5].iter().enumerate() { h.feed(&framed(0, &p.bytes), 20 + i as u64, false)?; }
    let deadline = h.capture.next_wake_ns();
    let mut wrong = timings(1)[0]; wrong.duration = 0;
    assert!(matches!(h.capture.supply_timing(wrong, 25), Err(CaptureError::Collection(E::Timeline))));
    assert_eq!(h.capture.next_wake_ns(), deadline);
    assert!(matches!(h.capture.poll(25)?, P::TimingRequired(request) if request.idr && request.rtp_timestamp == 0));
    let original = h.capture.supply_timing(timings(1)[0], 25)?;
    assert!(matches!(original.event.as_ref(), Event::Assembly { .. }));
    assert_eq!(h.capture.collector().retained_samples(), 1);
    Ok(())
}

#[test]
fn expired_timing_returns_the_picture_and_all_originals_without_an_eof_seal() -> TestResult {
    let mut h = Harness::new(false, CollectorLimits::default())?;
    for (i, p) in input()?[..5].iter().enumerate() { h.feed(&framed(0, &p.bytes), 20 + i as u64, false)?; }
    let at = 24 + MAX_PENDING_EVENT_AGE_NS;
    assert_eq!(h.capture.next_wake_ns(), Some(at));
    assert!(matches!(h.capture.supply_timing(timings(1)[0], at), Err(CaptureError::Collection(E::Deadline))));
    let P::Stopped { reason, retained, .. } = h.capture.poll(at)? else { return Err("timing did not expire".into()); };
    assert_eq!(reason, CollectionStop::Deadline);
    assert_eq!(retained.collection.sources.len(), 5);
    assert!(retained.collection.ready.is_none());
    assert!(matches!(retained.event.as_deref(), Some(Event::Assembly { .. })));
    Ok(())
}

#[test]
fn packet_gap_is_fenced_before_seal_and_preserves_the_invalidating_event() -> TestResult {
    let mut h = Harness::new(false, CollectorLimits::default())?;
    let input = input()?;
    for (i, p) in input[..5].iter().enumerate() { h.feed(&framed(0, &p.bytes), 20 + i as u64, true)?; }
    h.feed(&framed(0, &input[6].bytes), 30, true)?; // omit sequence six
    let now = 30 + ReorderLimits::default().max_delay_ns;
    let gap = h.client.poll(now)?;
    assert!(matches!(&gap, Event::Gap { .. }));
    h.capture.offer(gap, now)?;
    assert!(matches!(h.capture.seal(now), Err(CaptureError::Backpressure)));
    let P::Stopped { reason, retained, .. } = h.capture.poll(now)? else { return Err("gap not fenced".into()); };
    assert_eq!(reason, CollectionStop::InputDiscontinuity);
    assert!(retained.collection.ready.is_none());
    assert_eq!(retained.collection.pictures.len(), 1);
    assert!(matches!(retained.event.as_deref(), Some(Event::Gap { .. })));
    Ok(())
}

#[test]
fn incomplete_fu_eof_cannot_flush_the_preceding_pending_recording() -> TestResult {
    let mut h = Harness::new(false, CollectorLimits::default())?;
    for (i, p) in input()?[..5].iter().enumerate() { h.feed(&framed(0, &p.bytes), 20 + i as u64, true)?; }
    let start = packet(6, 36_000, false, &[0x62, 1, 0x81, 1]);
    h.feed(&framed(0, &start.bytes), 30, true)?;
    h.client.finish(); h.pump(31, true)?;
    assert!(h.windows().is_empty());
    let Some(P::Stopped { retained, .. }) = h.output.last() else { return Err("incomplete EOF not fenced".into()); };
    assert_eq!(retained.collection.sources.len(), 6);
    assert!(retained.collection.ready.is_none());
    assert!(matches!(retained.event.as_deref(), Some(Event::Ended { .. })));
    Ok(())
}

#[test]
fn malformed_rtcp_does_not_discard_valid_video_collection() -> TestResult {
    let mut h = Harness::new(false, CollectorLimits::default())?;
    for (i, p) in input()?[..5].iter().enumerate() { h.feed(&framed(0, &p.bytes), 20 + i as u64, true)?; }
    h.feed(&framed(1, &[0x80, 201, 0]), 25, true)?;
    assert_eq!(h.capture.collector().retained_samples(), 1);
    assert_eq!(h.capture.collector().retained_packets(), 5);
    assert!(h.output.iter().any(|p| matches!(p, P::Receiver(e) if matches!(e.as_ref(),
        Event::Client { event, work: None } if matches!(event.as_ref(), HevcClientPoll::Rtcp { validation: Err(_), .. })))));
    h.capture.seal(25)?; h.drain(25, true)?;
    assert_eq!(h.windows().len(), 1);
    Ok(())
}

#[test]
fn source_capacity_holds_exact_event_without_advancing_or_busy_polling() -> TestResult {
    let mut h = Harness::new(false, CollectorLimits { max_packets: 1, ..CollectorLimits::default() })?;
    let input = input()?;
    h.feed(&framed(0, &input[0].bytes), 20, true)?;
    h.feed(&framed(0, &input[1].bytes), 21, true)?;
    assert!(matches!(h.output.last(), Some(P::Backpressure { reason: E::Capacity, .. })));
    assert_eq!(h.capture.next_wake_ns(), Some(21 + MAX_PENDING_EVENT_AGE_NS));
    assert_eq!(h.capture.collector().retained_packets(), 1);
    let retired = h.capture.cancel();
    assert_eq!(retired.collection.sources[0].bytes(), input[0].bytes);
    assert!(matches!(retired.event.as_deref(), Some(Event::Source { source, .. }) if source.bytes() == input[1].bytes));
    assert!(matches!(h.capture.poll(22)?, P::Ended { retained: None }));
    Ok(())
}

#[test]
fn eob_picture_keeps_remote_uncertainty_and_seals_only_after_explicit_timing() -> TestResult {
    let mut h = Harness::new(false, CollectorLimits::default())?;
    let mut input = input()?;
    input.last_mut().ok_or("EOS")?.bytes[12] = 37 << 1;
    for (i, p) in input.iter().enumerate() { h.feed(&framed(0, &p.bytes), 20 + i as u64, true)?; }
    assert_eq!(h.windows().len(), 2);
    assert!(matches!(h.output.last(), Some(P::Ended { .. })));
    assert!(matches!(h.timed.last().ok_or("EOB picture")?.event.as_ref(),
        Event::Assembly { retirement: Some(r), .. } if r.client.session.remote_session_may_exist));
    Ok(())
}

#[test]
fn tcp_partitioning_keeps_media_and_sample_selection_identical() -> TestResult {
    let wire: Vec<_> = input()?.iter().flat_map(|p| framed(0, &p.bytes)).collect();
    let mut expected = None;
    for width in [1, 7, 31, 128, MAX_WIRE_CHUNK] {
        let mut h = Harness::new(false, CollectorLimits::default())?;
        for chunk in wire.chunks(width) { h.feed(chunk, 20, true)?; }
        h.client.finish(); h.pump(21, true)?;
        let roots: Vec<_> = h.windows().iter().map(|w| w.manifest().root()).collect();
        assert_eq!(roots.len(), 2);
        if let Some(previous) = &expected { assert_eq!(&roots, previous); } else { expected = Some(roots); }
    }
    Ok(())
}

#[test]
fn collected_windows_publish_and_reopen_through_the_existing_storage_owner() -> TestResult {
    use fss_object::SpoolLimits;
    use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel, SlotName};
    use fss_reference::rtsp::recording::local::{RecordingProgress, RecordingPublication};
    use fss_reference::rtsp::recording::hevc::local::load_hevc_recording;
    let mut h = Harness::new(false, CollectorLimits::default())?;
    for (i, p) in input()?.iter().enumerate() { h.feed(&framed(0, &p.bytes), 20 + i as u64, true)?; }
    h.client.finish(); h.pump(40, true)?;
    let windows = h.windows(); assert_eq!(windows.len(), 2);
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("hevc_capture_storage");
    match std::fs::remove_dir_all(&path) {
        Ok(()) => {}, Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}, Err(e) => return Err(e.into()),
    }
    let limits = LocalPublicationLimits::new(8, 16, 8, 64, SpoolLimits::new(64, 4 * 1024 * 1024, 1024 * 1024, 64));
    {
        let mut publisher = LocalRootPublisher::open(&path, limits)?;
        for (i, window) in windows.iter().enumerate() {
            let slot = SlotName::parse(format!("hevc-window-{i}").as_str())?;
            let mut job = RecordingPublication::new(window.publication_plan(), &mut publisher, slot, window.byte_len(), 100)?;
            for time in 0..4 { assert!(matches!(job.step(time, &NeverCancel)?, RecordingProgress::ChildStaged { .. })); }
            assert!(matches!(job.step(4, &NeverCancel)?, RecordingProgress::Published(_)));
        }
    }
    let publisher = LocalRootPublisher::open(&path, limits)?;
    for (i, window) in windows.iter().enumerate() {
        let slot = SlotName::parse(format!("hevc-window-{i}").as_str())?;
        let loaded = load_hevc_recording(&publisher, &slot, window.manifest().root(), &scope()?, &NeverCancel)?;
        assert_eq!(loaded.objects().source, window.objects().source);
        assert_eq!(loaded.objects().media, window.objects().media);
        assert_eq!(loaded.samples(), window.samples());
    }
    Ok(())
}
