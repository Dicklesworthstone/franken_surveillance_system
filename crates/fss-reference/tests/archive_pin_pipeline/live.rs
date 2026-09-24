#![forbid(unsafe_code)]
//! Native loopback handshake, actual encoded AVC, independent pins and real publication.
use super::*;
use fss_packet::{StreamKey, avc::AvcReceiveLimits};
use fss_reference::rtsp::archive_pins::live::*;
use fss_reference::rtsp::authentication::{DigestCredentials, DigestPolicy};
use fss_reference::rtsp::client::{ClientCommand, ClientConfig, ClientState};
use fss_reference::rtsp::live_archive::{LiveArchiveConfig, LiveArchiveStep};
use fss_reference::rtsp::live_avc::recording::{LiveRecordingConfig, LiveRecordingStep};
use fss_reference::rtsp::live_avc::{LiveAvcConfig, LiveAvcStep, SocketReadiness};
use fss_reference::rtsp::recording_capture::CapturePoll;
use fss_reference::rtsp::recording_collector::{CollectorLimits, RecordingTiming};
use fss_reference::rtsp::tcp::{
    TcpAuthority, TcpBinding, TcpDenial, TcpLimits, TcpOperation, TcpSecurityPolicy, TcpWriteStep,
};
use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::time::Duration;
const LEASE: u64 = 100_000_000_000;
struct Authority {
    binding: TcpBinding,
    checks: Cell<u64>,
    revoked: Cell<bool>,
}
impl TcpAuthority for Authority {
    fn checkpoint(
        &self,
        binding: &TcpBinding,
        _: TcpOperation,
        now: u64,
        until: u64,
    ) -> Result<(), TcpDenial> {
        self.checks.set(self.checks.get() + 1);
        if binding != &self.binding {
            return Err(TcpDenial::Unauthorized);
        }
        if self.revoked.get() {
            return Err(TcpDenial::Revoked);
        }
        if until != LEASE || now >= until {
            return Err(TcpDenial::Deadline);
        }
        Ok(())
    }
}
fn config(
    peer: std::net::SocketAddr,
) -> Test<(
    LiveAvcConfig,
    LiveRecordingConfig,
    LiveArchiveConfig,
    Authority,
)> {
    let key = StreamKey {
        ingress: 31,
        generation: 1,
        ssrc: 7,
    };
    let binding = TcpBinding::new(
        key,
        peer,
        "camera.local",
        TcpSecurityPolicy::OwnerApprovedPlaintext,
    )?;
    let authority = Authority {
        binding: binding.clone(),
        checks: Cell::new(0),
        revoked: Cell::new(false),
    };
    let live = LiveAvcConfig {
        protocol: ClientConfig {
            presentation_uri: "rtsp://camera.local/live/".into(),
            control_root_uri: "rtsp://camera.local/live".into(),
            media_index: 0,
            channels: (0, 1),
            response_timeout_ns: 10_000_000_000,
            default_session_timeout_seconds: 60,
        },
        binding,
        transport: TcpLimits::default(),
        media: AvcReceiveLimits::default(),
        realm: "fixture-camera".into(),
        digest_policy: DigestPolicy::default(),
        deadline_ns: LEASE,
        max_steps: 100_000,
    };
    let recording = LiveRecordingConfig {
        scope: scope()?,
        payload_type: 96,
        time_scale: 90_000,
        limits: CollectorLimits::default(),
    };
    let archive = LiveArchiveConfig {
        namespace: namespace()?,
        limits: ArchiveLimits {
            windows_per_page: 1,
            ..limits()
        },
        max_window_bytes: 1024 * 1024,
        max_steps: 100_000,
        publication_deadline_ns: 2 * LEASE,
        max_storage_pause_ns: 1_000_000_000,
    };
    Ok((live, recording, archive, authority))
}
fn credentials() -> Test<DigestCredentials<'static>> {
    Ok(DigestCredentials::new("fixture-user", "fixture-password")?)
}
fn response(cseq: u32, headers: &str, body: &str) -> Vec<u8> {
    format!(
        "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n{headers}\r\n{body}",
        body.len()
    )
    .into_bytes()
}
const SDP: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=,aM4PLIA=\r\na=control:trackID=0\r\n";
struct Fixture<'a, 'p> {
    driver: JournaledLiveAvcArchive<'a, 'p>,
    peer: TcpStream,
    authority: Authority,
}
impl<'a, 'p> Fixture<'a, 'p> {
    fn playing(p: &'a mut LocalRootPublisher, pins: &'p mut ArchivePinJournal) -> Test<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let (live, recording, archive, authority) = config(listener.local_addr()?)?;
        let driver = JournaledLiveAvcArchive::connect(
            live,
            recording,
            archive,
            ArchiveWorkLimits::default(),
            p,
            pins,
            0,
            &authority,
            &NeverCancel,
        )?;
        let (peer, _) = listener.accept()?;
        peer.set_read_timeout(Some(Duration::from_secs(2)))?;
        peer.set_write_timeout(Some(Duration::from_secs(2)))?;
        peer.set_nodelay(true)?;
        let mut f = Self {
            driver,
            peer,
            authority,
        };
        assert!(matches!(
            f.driver
                .poll(SocketReadiness::default(), 0, &f.authority, &NeverCancel)?,
            JournaledLiveArchiveStep::Live(LiveArchiveStep::Archive(
                ArchiveWriteProgress::Ready { .. }
            ))
        ));
        let seq = f.command(ClientCommand::Describe, 0)?;
        f.receive(&response(seq, "Content-Type: application/sdp\r\n", SDP), 1)?;
        let seq = f.command(ClientCommand::Setup, 2)?;
        f.receive(&response(seq, "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n", ""), 3)?;
        let seq = f.command(ClientCommand::Play, 4)?;
        f.receive(&response(seq, "Session: fixture\r\n", ""), 5)?;
        assert_eq!(f.driver.state(), ClientState::Playing);
        Ok(f)
    }
    fn command(&mut self, command: ClientCommand, now: u64) -> Test<u32> {
        let request = self.driver.request(
            command,
            &credentials()?,
            [40; 16],
            now,
            &self.authority,
            &NeverCancel,
        )?;
        for _ in 0..4096 {
            match self.driver.poll(
                SocketReadiness {
                    readable: false,
                    writable: true,
                },
                now,
                &self.authority,
                &NeverCancel,
            )? {
                JournaledLiveArchiveStep::Live(LiveArchiveStep::Recording(step)) => match *step {
                    LiveRecordingStep::Network(LiveAvcStep::Write(TcpWriteStep::Sent {
                        cseq,
                        bytes,
                    })) => {
                        assert_eq!(cseq, request.cseq);
                        self.peer.read_exact(&mut vec![0; bytes])?;
                        return Ok(cseq);
                    }
                    LiveRecordingStep::Network(
                        LiveAvcStep::Write(TcpWriteStep::Advanced { .. }) | LiveAvcStep::Pending(_),
                    ) => {}
                    other => return Err(format!("unexpected command step {other:?}").into()),
                },
                other => return Err(format!("unexpected command output {other:?}").into()),
            }
        }
        Err("bounded command did not send".into())
    }
    fn receive(&mut self, bytes: &[u8], now: u64) -> Test<bool> {
        self.peer.write_all(bytes)?;
        let mut count = 0;
        for _ in 0..4096 {
            match self.driver.poll(
                SocketReadiness {
                    readable: true,
                    writable: false,
                },
                now,
                &self.authority,
                &NeverCancel,
            )? {
                JournaledLiveArchiveStep::Live(LiveArchiveStep::Recording(step)) => match *step {
                    LiveRecordingStep::Network(LiveAvcStep::Wire(chunk)) => {
                        count += chunk.expose().len();
                    }
                    LiveRecordingStep::Network(LiveAvcStep::Pending(wait)) => {
                        if count == bytes.len() && wait.wake_at_ns.is_none_or(|t| t > now) {
                            return Ok(false);
                        }
                        std::thread::yield_now();
                    }
                    LiveRecordingStep::Capture { event, .. }
                        if matches!(*event, CapturePoll::TimingRequired(_)) =>
                    {
                        assert_eq!(count, bytes.len());
                        return Ok(true);
                    }
                    LiveRecordingStep::Stopped { .. } | LiveRecordingStep::Ended => {
                        return Err("source stopped".into());
                    }
                    _ => {}
                },
                other => return Err(format!("unexpected receive output {other:?}").into()),
            }
        }
        Err("bounded receive did not drain".into())
    }
    fn datagram(&mut self, bytes: &[u8], now: u64) -> Test<bool> {
        let mut wire = vec![b'$', 0];
        wire.extend_from_slice(&u16::try_from(bytes.len())?.to_be_bytes());
        wire.extend_from_slice(bytes);
        self.receive(&wire, now)
    }
    fn window(&mut self) -> Test {
        let f = fixture(31, true)?;
        let first = f.packets.first().ok_or("no originals")?;
        self.datagram(&recording_support::packet(0, false, &first.2[12..]), 6)?;
        let mut timing = false;
        for (i, (_, _, bytes)) in f.packets.iter().enumerate() {
            timing |= self.datagram(bytes, 7 + i as u64)?;
        }
        assert!(timing);
        let _ = self.driver.supply_timing(
            RecordingTiming {
                decode_time: 700,
                duration: 3600,
                composition_offset: 0,
            },
            100,
            &self.authority,
            &NeverCancel,
        )?;
        assert!(self.driver.seal(101, &self.authority, &NeverCancel)?);
        assert!(matches!(
            self.driver.poll(
                SocketReadiness::default(),
                101,
                &self.authority,
                &NeverCancel
            )?,
            JournaledLiveArchiveStep::Live(LiveArchiveStep::WindowAccepted(_))
        ));
        Ok(())
    }
}
#[test]
fn live_camera_source_crosses_both_journal_barriers_without_socket_read_ahead() -> Test {
    let path = fresh("live_complete")?;
    let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
    let mut pins = ArchivePinJournal::create(
        path.join("pins"),
        pin_scope()?,
        ArchivePinLimits::default(),
        &NeverCancel,
    )?;
    let mut f = Fixture::playing(&mut p, &mut pins)?;
    f.window()?;
    let reads = f.driver.totals().ok_or("totals")?.read_calls;
    f.peer
        .write_all(b"must not be consumed during archive and pin writes")?;
    let mut candidates = 0;
    let mut confirmed = 0;
    let mut ready = false;
    for _ in 0..64 {
        match f.driver.poll(
            SocketReadiness {
                readable: true,
                writable: true,
            },
            101,
            &f.authority,
            &NeverCancel,
        )? {
            JournaledLiveArchiveStep::Checkpoint(progress)
                if matches!(*progress, JournaledArchiveProgress::PinPersisted { .. }) =>
            {
                candidates += 1
            }
            JournaledLiveArchiveStep::Checkpoint(progress)
                if matches!(*progress, JournaledArchiveProgress::WorkConfirmed { .. }) =>
            {
                confirmed += 1
            }
            JournaledLiveArchiveStep::Live(LiveArchiveStep::Archive(
                ArchiveWriteProgress::Ready { .. },
            )) => {
                ready = true;
                break;
            }
            JournaledLiveArchiveStep::Live(LiveArchiveStep::Archive(_)) => {}
            other => return Err(format!("unexpected storage output {other:?}").into()),
        }
        assert_eq!(f.driver.totals().ok_or("totals")?.read_calls, reads);
    }
    assert!(ready);
    assert_eq!((candidates, confirmed), (2, 2));
    assert_eq!(f.driver.totals().ok_or("totals")?.read_calls, reads);
    assert_eq!(f.driver.journal_anchor().sequence, 5);
    let retired = f.driver.cancel().ok_or("retirement")?;
    assert!(retired.live.live.recording.is_some());
    assert!(retired.unrecorded_confirmation.is_none());
    drop(f);
    pins.require_settled(&p, ArchiveWorkLimits::default(), &NeverCancel)?;
    let snapshot = ArchiveSnapshot::load(&p, namespace()?, limits(), &NeverCancel)?;
    assert_eq!(snapshot.indexed_windows(), 1);
    Ok(())
}
#[test]
fn independent_pin_failure_closes_live_socket_and_keeps_unpublished_original() -> Test {
    let path = fresh("live_confirmation_failure")?;
    let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
    let mut pins = ArchivePinJournal::create(
        path.join("pins"),
        pin_scope()?,
        ArchivePinLimits {
            max_records: 2,
            ..ArchivePinLimits::default()
        },
        &NeverCancel,
    )?;
    let mut f = Fixture::playing(&mut p, &mut pins)?;
    f.window()?;
    let _ = f
        .driver
        .poll(SocketReadiness::default(), 101, &f.authority, &NeverCancel)?;
    let error = f
        .driver
        .poll(SocketReadiness::default(), 101, &f.authority, &NeverCancel)
        .err()
        .ok_or("confirmation bypassed")?;
    assert!(matches!(
        error.reason,
        JournaledLiveArchiveError::Pins(ArchivePinError::Limit)
    ));
    let r = error.retirement.ok_or("source retirement lost")?;
    assert!(r.unrecorded_confirmation.is_some());
    assert!(r.pins.candidate().is_some());
    let archive = r.live.live.archive.ok_or("archive retirement lost")?;
    assert!(archive.pending.is_some());
    assert!(archive.snapshot.windows().is_empty());
    assert_eq!(f.driver.state(), ClientState::Closed);
    assert!(matches!(
        f.driver
            .poll(SocketReadiness::default(), 102, &f.authority, &NeverCancel)?,
        JournaledLiveArchiveStep::Live(LiveArchiveStep::Ended)
    ));
    drop(f);
    assert!(p.root(&namespace()?.window_slot(0)?).is_none());
    Ok(())
}
#[test]
fn wrong_pin_scope_prevents_any_live_connection_attempt() -> Test {
    let path = fresh("live_wrong_scope")?;
    let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
    let wrong = ArchivePinScope {
        archive_namespace: ContentDigest::sha256(b"other camera"),
        ..pin_scope()?
    };
    let mut pins = ArchivePinJournal::create(
        path.join("pins"),
        wrong,
        ArchivePinLimits::default(),
        &NeverCancel,
    )?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let (live, recording, archive, authority) = config(listener.local_addr()?)?;
    let error = JournaledLiveAvcArchive::connect(
        live,
        recording,
        archive,
        ArchiveWorkLimits::default(),
        &mut p,
        &mut pins,
        0,
        &authority,
        &NeverCancel,
    )
    .err()
    .ok_or("scope was accepted")?;
    assert!(!error.connection_attempted);
    assert_eq!(authority.checks.get(), 0);
    Ok(())
}
#[test]
fn revoked_camera_authority_cannot_be_bypassed_by_persisting_its_candidate() -> Test {
    let path = fresh("live_revocation")?;
    let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
    let mut pins = ArchivePinJournal::create(
        path.join("pins"),
        pin_scope()?,
        ArchivePinLimits::default(),
        &NeverCancel,
    )?;
    let mut f = Fixture::playing(&mut p, &mut pins)?;
    f.window()?;
    let _ = f
        .driver
        .poll(SocketReadiness::default(), 101, &f.authority, &NeverCancel)?;
    let anchor = f.driver.journal_anchor();
    f.authority.revoked.set(true);
    let error = f
        .driver
        .poll(
            SocketReadiness {
                readable: true,
                writable: true,
            },
            102,
            &f.authority,
            &NeverCancel,
        )
        .err()
        .ok_or("revoked camera continued")?;
    assert!(error.retirement.is_some());
    assert_eq!(f.driver.journal_anchor(), anchor);
    assert_eq!(f.driver.state(), ClientState::Closed);
    drop(f);
    assert!(p.visible_roots().next().is_none());
    Ok(())
}
