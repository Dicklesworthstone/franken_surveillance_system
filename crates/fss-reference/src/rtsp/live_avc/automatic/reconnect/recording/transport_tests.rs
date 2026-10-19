#![forbid(unsafe_code)]
//! Native loopback contracts: complete source-linked recording, EOF drain,
//! immutable old output, and pre-connect aggregate admission on a fresh epoch.

use super::*;
use crate::rtsp::avc_client::AvcClientPoll;
use crate::rtsp::avc_client::authenticated::DigestAvcPoll;
use crate::rtsp::client::{ClientCommand, ClientProgress, ClientState};
use crate::rtsp::live_avc::automatic::reconnect::{
    ReconnectBudgetDimension, ReconnectBudgetRefusal,
};
use crate::rtsp::live_avc::tests::{credentials, description, response, scope};
use crate::rtsp::recording::PreparedRecording;
use crate::rtsp::recording_capture::PictureTimingRequest;
use crate::rtsp::recording_collector::CollectorLimits;
use crate::rtsp::tcp::{TcpDenial, TcpOperation, TcpWriteStep};
use fss_core::{ContentDigest, SensorId, StreamId};
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::time::Duration;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Grant {
    binding: TcpBinding,
    deadline: u64,
}
impl TcpAuthority for Grant {
    fn checkpoint(
        &self,
        binding: &TcpBinding,
        _: TcpOperation,
        now: u64,
        deadline: u64,
    ) -> Result<(), TcpDenial> {
        if binding != &self.binding {
            return Err(TcpDenial::Unauthorized);
        }
        if deadline != self.deadline || now >= deadline {
            return Err(TcpDenial::Deadline);
        }
        Ok(())
    }
}

fn template(generation: u64) -> TestResult<LiveRecordingConfig> {
    Ok(LiveRecordingConfig {
        scope: RecordingScope {
            sensor: SensorId::parse("sensor:budget-loopback")?,
            stream: StreamId::parse("stream:budget-loopback")?,
            generation,
            anchor: ContentDigest::sha256(b"budget loopback source authority"),
            receive_clock: ContentDigest::sha256(b"budget loopback initial receive clock"),
        },
        payload_type: 96,
        time_scale: 90_000,
        limits: CollectorLimits::default(),
    })
}

fn nals() -> Vec<&'static [u8]> {
    let bytes: &'static [u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fss-packet/tests/fixtures/avc/baseline.264"
    ));
    let mut out = Vec::new();
    let mut start = None;
    let mut at = 0;
    while at + 3 <= bytes.len() {
        let prefix = if bytes.get(at..at + 4) == Some(&[0, 0, 0, 1]) {
            4
        } else if bytes[at..at + 3] == [0, 0, 1] {
            3
        } else {
            0
        };
        if prefix != 0 {
            if let Some(begin) = start {
                let mut end = at;
                while end > begin && bytes[end - 1] == 0 {
                    end -= 1;
                }
                if begin < end {
                    out.push(&bytes[begin..end]);
                }
            }
            start = Some(at + prefix);
            at += prefix;
        } else {
            at += 1;
        }
    }
    if let Some(begin) = start
        && begin < bytes.len()
    {
        out.push(&bytes[begin..]);
    }
    out
}

fn source_frame(sequence: u16, marker: bool, payload: &[u8]) -> TestResult<Vec<u8>> {
    let mut rtp = vec![0x80, 96 | if marker { 128 } else { 0 }];
    rtp.extend_from_slice(&sequence.to_be_bytes());
    rtp.extend_from_slice(&9_000_u32.to_be_bytes());
    rtp.extend_from_slice(&7_u32.to_be_bytes());
    rtp.extend_from_slice(payload);
    let mut wire = vec![b'$', 0];
    wire.extend_from_slice(&u16::try_from(rtp.len())?.to_be_bytes());
    wire.extend_from_slice(&rtp);
    Ok(wire)
}

struct Fixture {
    listener: TcpListener,
    peer: TcpStream,
    owner: SupervisedAvcRecording,
    grant: Grant,
    scope: RecordingScope,
    one: ReconnectBudget,
    nonce: u128,
}
impl Fixture {
    fn new(affordable_attempts: u32) -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let (mut config, _) = scope(listener.local_addr()?)?;
        config.transport.chunk_bytes = 17;
        let grant = Grant {
            binding: config.binding.clone(),
            deadline: config.deadline_ns,
        };
        let template = template(config.binding.key().generation)?;
        let scope = template.scope.clone();
        let one = ReconnectBudget::for_attempts(config.transport, config.max_steps, 1)?;
        let budget =
            ReconnectBudget::for_attempts(config.transport, config.max_steps, affordable_attempts)?;
        let policy = ReconnectPolicy {
            max_attempts: 3,
            initial_backoff_ns: 10,
            max_backoff_ns: 100,
            deadline_ns: config.deadline_ns,
            max_steps: 100_000,
        };
        let mut owner = SupervisedAvcRecording::new_with_budget(
            config.binding.clone(),
            template,
            policy,
            budget,
            0,
        )?;
        assert_eq!(owner.connect(config, scope.clone(), 0, &grant)?.ordinal, 1);
        let (peer, _) = listener.accept()?;
        peer.set_read_timeout(Some(Duration::from_secs(2)))?;
        peer.set_write_timeout(Some(Duration::from_secs(2)))?;
        peer.set_nodelay(true)?;
        Ok(Self {
            listener,
            peer,
            owner,
            grant,
            scope,
            one,
            nonce: 0,
        })
    }

    fn poll(
        &mut self,
        now: u64,
        readable: bool,
        writable: bool,
    ) -> TestResult<SupervisedRecordingStep> {
        self.nonce += 1;
        Ok(self.owner.poll(
            SocketReadiness { readable, writable },
            &credentials()?,
            self.nonce.to_be_bytes(),
            now,
            &self.grant,
        )?)
    }

    fn command(&mut self, now: u64, expected: ClientCommand) -> TestResult<u32> {
        let queued = match self.poll(now, false, false)? {
            SupervisedRecordingStep::Recording {
                output: AutomaticRecordingStep::Queued(queued),
                ..
            } => queued,
            _ => return Err("automatic recording did not queue expected command".into()),
        };
        assert_eq!(queued.command, expected);
        for _ in 0..32_768 {
            if let SupervisedRecordingStep::Recording {
                output:
                    AutomaticRecordingStep::Recording(LiveRecordingStep::Network(LiveAvcStep::Write(
                        TcpWriteStep::Sent { cseq, bytes },
                    ))),
                ..
            } = self.poll(now, false, true)?
            {
                assert_eq!(cseq, queued.cseq);
                assert_eq!(bytes, queued.bytes);
                let mut request = vec![0; bytes];
                self.peer.read_exact(&mut request)?;
                assert!(
                    !request
                        .windows(b"Authorization:".len())
                        .any(|w| w == b"Authorization:")
                );
                return Ok(cseq);
            }
        }
        Err("bounded native request did not finish".into())
    }

    fn accept(&mut self, bytes: &[u8], now: u64, expected: ClientState) -> TestResult {
        self.peer.write_all(bytes)?;
        let mut original = Vec::new();
        for _ in 0..32_768 {
            match self.poll(now, true, false)? {
                SupervisedRecordingStep::Recording {
                    output:
                        AutomaticRecordingStep::Recording(LiveRecordingStep::Network(
                            LiveAvcStep::Wire(chunk),
                        )),
                    ..
                } => original.extend_from_slice(chunk.expose()),
                SupervisedRecordingStep::Recording {
                    output:
                        AutomaticRecordingStep::Recording(LiveRecordingStep::Network(
                            LiveAvcStep::Protocol {
                                event: DigestAvcPoll::Client { event, .. },
                                transport: None,
                            },
                        )),
                    ..
                } if matches!(*event, AvcClientPoll::Control(ClientProgress::Accepted(state))
                    if state == expected) =>
                {
                    assert_eq!(original, bytes);
                    return Ok(());
                }
                _ => std::thread::yield_now(),
            }
        }
        Err("bounded native negotiation did not finish".into())
    }

    fn playing(&mut self) -> TestResult {
        let cseq = self.command(0, ClientCommand::Describe)?;
        self.accept(
            &response(cseq, "Content-Type: application/sdp\r\n", description()),
            1,
            ClientState::Described,
        )?;
        let cseq = self.command(2, ClientCommand::Setup)?;
        self.accept(&response(cseq, "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n", ""), 3, ClientState::Ready)?;
        let cseq = self.command(4, ClientCommand::Play)?;
        self.accept(
            &response(cseq, "Session: fixture\r\n", ""),
            5,
            ClientState::Playing,
        )
    }

    fn source(&mut self, wire: &[u8], now: u64) -> TestResult<Option<PictureTimingRequest>> {
        self.peer.write_all(wire)?;
        let mut original = Vec::new();
        for _ in 0..32_768 {
            match self.poll(now, true, false)? {
                SupervisedRecordingStep::Recording {
                    output:
                        AutomaticRecordingStep::Recording(LiveRecordingStep::Network(
                            LiveAvcStep::Wire(chunk),
                        )),
                    ..
                } => original.extend_from_slice(chunk.expose()),
                SupervisedRecordingStep::Recording {
                    output:
                        AutomaticRecordingStep::Recording(LiveRecordingStep::Capture { event, .. }),
                    ..
                } => match *event {
                    CapturePoll::TimingRequired(request) => {
                        assert_eq!(original, wire);
                        return Ok(Some(request));
                    }
                    CapturePoll::Stopped { .. } => return Err("source capture stopped".into()),
                    _ => {}
                },
                SupervisedRecordingStep::Recording {
                    output:
                        AutomaticRecordingStep::Recording(LiveRecordingStep::Network(
                            LiveAvcStep::Pending(wait),
                        )),
                    ..
                } if original.len() == wire.len() && wait.wake_at_ns.is_none_or(|at| at > now) => {
                    assert_eq!(original, wire);
                    return Ok(None);
                }
                _ => std::thread::yield_now(),
            }
        }
        Err("bounded native source did not drain".into())
    }

    fn record_and_drain_eof(&mut self) -> TestResult<PreparedRecording> {
        self.playing()?;
        let data = nals();
        let sps = data
            .iter()
            .find(|nal| nal[0] & 31 == 7)
            .ok_or("missing SPS")?;
        let idr = data
            .iter()
            .find(|nal| nal[0] & 31 == 5)
            .ok_or("missing IDR")?;
        assert!(self.source(&source_frame(1, false, sps)?, 10)?.is_none());
        let request = self
            .source(&source_frame(2, true, idr)?, 11)?
            .ok_or("native picture did not request timing")?;
        assert_eq!(request.key, self.grant.binding.key());
        assert!(request.idr);
        self.peer.shutdown(Shutdown::Write)?;
        // Even a socket whose peer has closed stays behind the held timing request.
        assert!(
            matches!(self.poll(12, true, true)?, SupervisedRecordingStep::Recording {
            output: AutomaticRecordingStep::Recording(LiveRecordingStep::Capture { event, .. }), ..
        } if matches!(*event, CapturePoll::TimingRequired(held) if held == request))
        );
        assert!(matches!(
            self.owner.supply_timing(
                request.key,
                RecordingTiming {
                    decode_time: 700,
                    duration: 3_600,
                    composition_offset: 0,
                },
                13,
                &self.grant
            )?,
            TimedCapture::Collected { .. }
        ));
        let mut window = None;
        let mut socket_eof = false;
        let mut protocol_retired = false;
        let mut capture_ended = false;
        for _ in 0..32_768 {
            match self.poll(14, true, false)? {
                SupervisedRecordingStep::Recording {
                    output:
                        AutomaticRecordingStep::Recording(LiveRecordingStep::Network(
                            LiveAvcStep::InputEnded,
                        )),
                    ..
                } => {
                    socket_eof = true;
                    assert_eq!(self.owner.status(), ReconnectStatus::Active(request.key));
                }
                SupervisedRecordingStep::Recording {
                    output:
                        AutomaticRecordingStep::Recording(LiveRecordingStep::Network(
                            LiveAvcStep::Protocol {
                                transport: Some(transport),
                                ..
                            },
                        )),
                    ..
                } => {
                    assert!(transport.totals.peer_eof);
                    protocol_retired = true;
                    assert_eq!(self.owner.status(), ReconnectStatus::Active(request.key));
                    let refused = self
                        .owner
                        .acknowledge_retirement(14, &self.grant)
                        .err()
                        .ok_or("protocol EOF bypassed recording drain")?;
                    assert!(matches!(
                        refused.reason,
                        SupervisedRecordingError::Supervisor(ReconnectRefusal::NoRetirement)
                    ));
                }
                SupervisedRecordingStep::Recording {
                    output:
                        AutomaticRecordingStep::Recording(LiveRecordingStep::Capture { event, .. }),
                    ..
                } => match *event {
                    CapturePoll::Window(prepared) => {
                        assert!(window.is_none());
                        window = Some(prepared);
                        assert_eq!(self.owner.status(), ReconnectStatus::Active(request.key));
                    }
                    CapturePoll::Ended { .. } => {
                        capture_ended = true;
                        break;
                    }
                    CapturePoll::Stopped { .. } => return Err("EOF lost complete recording".into()),
                    _ => {}
                },
                _ => std::thread::yield_now(),
            }
        }
        assert!(socket_eof && protocol_retired && capture_ended);
        assert_eq!(self.owner.status(), ReconnectStatus::Retired(request.key));
        assert_eq!(self.owner.resource_budget().reserved(), self.one);
        let window = window.ok_or("EOF did not transfer prepared recording")?;
        assert_eq!(window.summary().samples, 1);
        assert_eq!(window.summary().packets, 1);
        assert_eq!(window.summary().decode_interval, 700..4300);
        Ok(window)
    }

    fn next_config(&self) -> TestResult<(LiveAvcConfig, RecordingScope, Grant)> {
        let (mut config, _) = scope(self.listener.local_addr()?)?;
        config.binding = self.owner.expected_binding().clone();
        config.transport.chunk_bytes = 17;
        let mut scope = self.scope.clone();
        scope.generation = config.binding.key().generation;
        scope.receive_clock = ContentDigest::sha256(b"separately declared second receive clock");
        let grant = Grant {
            binding: config.binding.clone(),
            deadline: config.deadline_ns,
        };
        Ok((config, scope, grant))
    }
}

#[test]
fn complete_recording_survives_eof_when_aggregate_budget_refuses_the_next_socket() -> TestResult {
    let mut fixture = Fixture::new(1)?;
    let window = fixture.record_and_drain_eof()?;
    let root = window.manifest().root();
    fixture.owner.acknowledge_retirement(100, &fixture.grant)?;
    let reserved = fixture.owner.resource_budget();
    assert_eq!(fixture.owner.next_wake_ns(), Some(110));
    let (config, scope, grant) = fixture.next_config()?;
    fixture.listener.set_nonblocking(true)?;
    let failure = fixture
        .owner
        .connect(config, scope, 110, &grant)
        .err()
        .ok_or("recording retirement replenished native capacity")?;
    assert!(matches!(
        failure.reason,
        SupervisedRecordingError::Supervisor(ReconnectRefusal::Resources(
            ReconnectBudgetRefusal::Exhausted(ReconnectBudgetDimension::ReceivedBytes)
        ))
    ));
    assert!(failure.retirement.is_none());
    assert_eq!(
        fixture
            .listener
            .accept()
            .err()
            .ok_or("budget denial opened next socket")?
            .kind(),
        ErrorKind::WouldBlock
    );
    assert_eq!(fixture.owner.resource_budget(), reserved);
    assert_eq!(window.manifest().root(), root);
    assert_eq!(window.summary().samples, 1);
    assert!(fixture.owner.cancel().is_none());
    Ok(())
}

#[test]
fn another_granted_recording_generation_does_not_adopt_or_refund_prior_output() -> TestResult {
    let mut fixture = Fixture::new(2)?;
    let window = fixture.record_and_drain_eof()?;
    let root = window.manifest().root();
    let previous = fixture.grant.binding.key();
    fixture.owner.acknowledge_retirement(100, &fixture.grant)?;
    let (config, scope, grant) = fixture.next_config()?;
    let attempt = fixture.owner.connect(config, scope, 110, &grant)?;
    let (_peer, _) = fixture.listener.accept()?;
    assert_eq!(attempt.ordinal, 2);
    assert_eq!(attempt.key.generation, previous.generation + 1);
    assert_eq!(attempt.previous, Some((previous, 100)));
    assert_eq!(fixture.owner.resource_budget().admitted_attempts(), 2);
    assert_eq!(
        fixture
            .owner
            .resource_budget()
            .remaining()
            .ok_or("missing grant")?
            .received_bytes,
        0
    );
    match fixture.owner.poll(
        SocketReadiness::default(),
        &credentials()?,
        [23; 16],
        110,
        &grant,
    )? {
        SupervisedRecordingStep::Recording {
            key,
            output: AutomaticRecordingStep::Queued(queued),
        } => {
            assert_eq!(key, attempt.key);
            assert_eq!(queued.command, ClientCommand::Describe);
            assert_eq!(queued.cseq, 1);
        }
        _ => return Err("new recording reused old protocol state".into()),
    }
    assert_eq!(window.manifest().root(), root);
    assert_eq!(window.summary().decode_interval, 700..4300);
    let reserved = fixture.owner.resource_budget();
    let (_, retired) = fixture
        .owner
        .cancel()
        .ok_or("new recording retirement missing")?;
    assert!(
        retired
            .connection
            .ok_or("new network retirement missing")?
            .transport
            .request
            .is_some()
    );
    assert_eq!(fixture.owner.resource_budget(), reserved);
    Ok(())
}
