#![forbid(unsafe_code)]
//! Native loopback contracts for the manifest-bound, non-retaining RTSP probe owner.

use std::cell::Cell;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use fss_core::ContentDigest;
use fss_packet::StreamKey;
use fss_reference::rtsp::authentication::{DigestCredentials, DigestPolicy};
use fss_reference::rtsp::client::{ClientCloseReceipt, ClientConfig, ClientError};
use fss_reference::rtsp::tcp::{
    SocketReadiness, TcpAuthority, TcpBinding, TcpDenial, TcpError, TcpLimits, TcpOperation,
    TcpSecurityPolicy, TcpTotals,
};
use fss_reference::site::live_probe::{
    LiveSiteProbe, LiveSiteProbeConfig, MAX_PROBE_SENT_BYTES, MAX_PROBE_STEPS,
    MAX_PROBE_WIRE_BYTES, ProbeAccounting, ProbeDigestConfig, ProbeError, ProbeFailure, ProbeStep,
};
use fss_reference::site::probe_observation::ObservationError;
use fss_reference::site::{ProbeCodec, SiteAuthentication, SiteManifest, SiteProbeReceipt};

type Test = Result<(), Box<dyn std::error::Error>>;
const FIRST_TIMESTAMP: u32 = 0xffff_f000;
const FRAME_TICKS: u32 = 3600;
const AVC_DESCRIPTION: &[u8] = include_bytes!("../../../fixtures/site_probe/avc.describe.rtsp");
const HEVC_DESCRIPTION: &[u8] = include_bytes!("../../../fixtures/site_probe/hevc.describe.rtsp");
const AVC_RTP: &[u8] = include_bytes!("../../../fixtures/site_probe/avc.rtpdump");
const HEVC_RTP: &[u8] = include_bytes!("../../../fixtures/site_probe/hevc.rtpdump");
const JPEG_DESCRIPTION: &[u8] = include_bytes!("../../../fixtures/site_probe/jpeg.describe.rtsp");
const JPEG_RTP: &[u8] = include_bytes!("../../../fixtures/site_probe/jpeg.rtpdump");
const AVC_SPS: &str = "Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=";
const AVC_PPS: &str = "aM4PLIA=";
const HEVC_VPS: &str = "QAEMAf//AWAAAAMAkAAAAwAAAwAekoCQ";
const HEVC_SPS: &str = "QgEBAWAAAAMAkAAAAwAAAwAeoCCBBZZKuTC8BaAgAAADACAAAAMBQQ==";
const HEVC_FIELD_SPS: &str = "QgEBAWAAAAMAkAAAAwAAAwAeoCCBBZZKuTC8BaEgAAADACAAAAMBQQ==";
const HEVC_PPS: &str = "RAHBcaGkgA==";
const SSRC: u32 = 0x0102_0304;
const REALM: &str = "site-fixture-realm";
const SERVER_CANARY: &str = "PRIVATE_SERVER_ID_NEVER_ECHO";
const SESSION_CANARY: &str = "PRIVATE_SESSION_NEVER_ECHO";
const PASSWORD: &str = "PRIVATE_PASSWORD_NEVER_ECHO";
const MANIFEST: &str = include_str!("../../../fixtures/site/manifest.v1.json");

#[derive(Clone, Copy, Default)]
enum MediaFault {
    #[default]
    None,
    Sender,
    Sequence,
    Cadence,
    MissingMarker,
    ForeignChannel,
    Truncated,
}

#[derive(Clone, Copy, Default)]
enum CloseMode {
    #[default]
    Acknowledge,
    Drop,
    WrongCseq,
}

#[derive(Clone, Copy)]
struct Scenario {
    codec: ProbeCodec,
    digest: bool,
    wrong_realm: bool,
    media_fault: MediaFault,
    close: CloseMode,
    late_media: bool,
    chunks: usize,
}

impl Default for Scenario {
    fn default() -> Self {
        Self {
            codec: ProbeCodec::Avc,
            digest: false,
            wrong_realm: false,
            media_fault: MediaFault::None,
            close: CloseMode::Acknowledge,
            late_media: false,
            chunks: usize::MAX,
        }
    }
}

#[derive(Default)]
struct ServerLog {
    methods: Vec<String>,
    cseqs: Vec<u32>,
    signed_requests: usize,
}

struct Permit {
    binding: TcpBinding,
    denial: Cell<Option<TcpDenial>>,
    calls: Cell<u64>,
}

impl TcpAuthority for Permit {
    fn checkpoint(
        &self,
        binding: &TcpBinding,
        _operation: TcpOperation,
        now_ns: u64,
        deadline_ns: u64,
    ) -> Result<(), TcpDenial> {
        self.calls.set(self.calls.get() + 1);
        if *binding != self.binding {
            return Err(TcpDenial::Unauthorized);
        }
        if let Some(denial) = self.denial.get() {
            return Err(denial);
        }
        if now_ns >= deadline_ns {
            return Err(TcpDenial::Deadline);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct Completion {
    receipt: SiteProbeReceipt,
    totals: TcpTotals,
    close: ClientCloseReceipt,
    accounting: ProbeAccounting,
}

fn manifest(peer: SocketAddr, digest: bool) -> Result<SiteManifest, Box<dyn std::error::Error>> {
    let mut manifest = SiteManifest::parse(MANIFEST)?;
    manifest.sources.truncate(1);
    let source = &mut manifest.sources[0];
    source.peer = peer;
    source.authority = peer.to_string();
    if digest {
        source.authentication = Some(SiteAuthentication {
            credential_file: PathBuf::from("/tmp/site-probe-fixture-secret-is-never-opened"),
            realm: REALM.to_owned(),
            legacy_md5: false,
            legacy_no_qop: false,
        });
    }
    manifest.validate()?;
    Ok(manifest)
}

fn config(manifest: &SiteManifest, codec: ProbeCodec) -> Result<LiveSiteProbeConfig, TcpError> {
    let source = &manifest.sources[0];
    Ok(LiveSiteProbeConfig {
        source_index: 0,
        protocol: ClientConfig {
            presentation_uri: format!("rtsp://{}/live/main", source.authority),
            control_root_uri: format!("rtsp://{}/live", source.authority),
            media_index: 0,
            channels: (0, 1),
            response_timeout_ns: 3_000_000_000,
            default_session_timeout_seconds: 60,
        },
        binding: TcpBinding::new(
            StreamKey {
                ingress: 41,
                generation: 1,
                ssrc: 0,
            },
            source.peer,
            &source.authority,
            TcpSecurityPolicy::OwnerApprovedPlaintext,
        )?
        .with_auto_ssrc(),
        transport: TcpLimits {
            max_received_bytes: MAX_PROBE_WIRE_BYTES,
            max_sent_bytes: MAX_PROBE_SENT_BYTES,
            max_io_calls: MAX_PROBE_STEPS,
            max_request_bytes: 32 * 1024,
            chunk_bytes: 4096,
            connect_timeout_ns: 1_000_000_000,
        },
        codec,
        payload_type: Some(fixture_payload_type(codec)),
        deadline_ns: 10_000_000_000,
        max_steps: MAX_PROBE_STEPS,
        stop_after_pictures: 3,
        digest: source
            .authentication
            .as_ref()
            .map(|auth| ProbeDigestConfig {
                realm: auth.realm.clone(),
                policy: DigestPolicy::default(),
            }),
    })
}

fn read_request(socket: &mut TcpStream, log: &mut ServerLog) -> io::Result<Option<(u32, bool)>> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() == 8192 {
            return Err(io::Error::other("fixture request bound"));
        }
        let mut byte = [0];
        if socket.read(&mut byte)? == 0 {
            return Ok(None);
        }
        bytes.push(byte[0]);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| io::Error::other("fixture UTF-8"))?;
    let method = text
        .split_whitespace()
        .next()
        .ok_or_else(|| io::Error::other("fixture method"))?;
    let cseq = text
        .split("\r\n")
        .find_map(|line| line.strip_prefix("CSeq: "))
        .ok_or_else(|| io::Error::other("fixture correlation"))?
        .parse::<u32>()
        .map_err(|_| io::Error::other("fixture correlation number"))?;
    let signed = text.contains("\r\nAuthorization: Digest ");
    log.methods.push(method.to_owned());
    log.cseqs.push(cseq);
    log.signed_requests += usize::from(signed);
    // The fixture inspects header presence without returning credentials, URIs or session IDs.
    if text.contains(PASSWORD) {
        return Err(io::Error::other("plaintext credential escaped"));
    }
    Ok(Some((cseq, signed)))
}

fn response(cseq: u32, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n{headers}Content-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn write_chunks(socket: &mut TcpStream, bytes: &[u8], chunk_size: usize) -> io::Result<()> {
    for chunk in bytes.chunks(chunk_size) {
        socket.write_all(chunk)?;
    }
    Ok(())
}

fn fixture_ssrc(codec: ProbeCodec) -> u32 {
    match codec {
        ProbeCodec::Avc => 0x1122_3344,
        ProbeCodec::Hevc => 0x5566_7788,
        ProbeCodec::Jpeg => 0x99aa_bbcc,
    }
}

fn fixture_payload_type(codec: ProbeCodec) -> u8 {
    match codec {
        ProbeCodec::Avc => 96,
        ProbeCodec::Hevc => 98,
        ProbeCodec::Jpeg => 26,
    }
}

fn sdp(codec: ProbeCodec) -> &'static [u8] {
    let response = match codec {
        ProbeCodec::Avc => AVC_DESCRIPTION,
        ProbeCodec::Hevc => HEVC_DESCRIPTION,
        ProbeCodec::Jpeg => JPEG_DESCRIPTION,
    };
    let body = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .expect("checked-in RTSP response has a body separator")
        + 4;
    &response[body..]
}

fn scenario_sdp(scenario: Scenario) -> io::Result<Vec<u8>> {
    let original = std::str::from_utf8(sdp(scenario.codec))
        .map_err(|_| io::Error::other("checked-in SDP UTF-8"))?;
    let changed = match scenario.media_fault {
        MediaFault::AvcField | MediaFault::AvcMbaff => {
            let field_sps = if matches!(scenario.media_fault, MediaFault::AvcField) {
                "Z0IAH/QUIJA="
            } else {
                "Z0IAH/QUIZA="
            };
            original
                .replace(AVC_SPS, field_sps)
                .replace(AVC_PPS, "aM44gA==")
        }
        MediaFault::HevcField => original.replace(HEVC_SPS, HEVC_FIELD_SPS),
        _ => original.to_owned(),
    };
    Ok(changed.into_bytes())
}

fn fixture_packets(codec: ProbeCodec) -> io::Result<Vec<Vec<u8>>> {
    let bytes = match codec {
        ProbeCodec::Avc => AVC_RTP,
        ProbeCodec::Hevc => HEVC_RTP,
        ProbeCodec::Jpeg => JPEG_RTP,
    };
    let mut reader = RtpDumpReader::new(bytes, RtpDumpLimits::default())
        .map_err(|_| io::Error::other("checked-in RTPdump header"))?;
    let mut packets = Vec::new();
    while let Some(record) = reader
        .next_record()
        .map_err(|_| io::Error::other("checked-in RTPdump record"))?
    {
        if record.kind() != RtpDumpKind::Rtp {
            return Err(io::Error::other("fixture must contain complete RTP"));
        }
        let packet = RtpPacket::parse(record.packet(), PacketLimits::default())
            .map_err(|_| io::Error::other("checked-in RTP packet"))?;
        if packet.ssrc() != fixture_ssrc(codec) || packet.payload().is_empty() {
            return Err(io::Error::other("checked-in RTP fixture identity"));
        }
        // Keep every original header, wrap, parameter NAL and fragment byte intact.
        packets.push(record.packet().to_vec());
    }
    Ok(packets)
}

fn scenario_packets(scenario: Scenario) -> io::Result<Vec<Vec<u8>>> {
    if matches!(
        scenario.media_fault,
        MediaFault::MarkerOnly | MediaFault::ForgedSlice
    ) {
        let mut packets = Vec::new();
        for index in 0u16..4 {
            let payload_type = fixture_payload_type(scenario.codec);
            let mut packet = vec![0x80, 0x80 | payload_type];
            packet.extend_from_slice(&65534u16.wrapping_add(index).to_be_bytes());
            packet.extend_from_slice(
                &FIRST_TIMESTAMP
                    .wrapping_add(u32::from(index) * FRAME_TICKS)
                    .to_be_bytes(),
            );
            packet.extend_from_slice(&fixture_ssrc(scenario.codec).to_be_bytes());
            let payload: &[u8] = match (scenario.codec, scenario.media_fault) {
                (ProbeCodec::Hevc, MediaFault::MarkerOnly) => &[0x46, 1, 0x50],
                (_, MediaFault::MarkerOnly) => &[9, 0xf0],
                (ProbeCodec::Hevc, _) => &[0x26, 1, 0x80],
                _ => &[0x65, 0, 0x80],
            };
            packet.extend_from_slice(payload);
            packets.push(packet);
        }
        return Ok(packets);
    }
    let mut packets = fixture_packets(scenario.codec)?;
    match scenario.media_fault {
        MediaFault::NoEos => {
            let eos = packets
                .pop()
                .ok_or_else(|| io::Error::other("fixture EOS"))?;
            if scenario.codec != ProbeCodec::Hevc || eos.get(12..) != Some(&[0x48, 1, 0x80][..]) {
                return Err(io::Error::other("checked-in native HEVC EOS"));
            }
        }
        MediaFault::Truncated => {
            // The corrupt interleaved suffix is before any possible sample boundary.
            // A later unobserved tail is intentionally a different contract.
            packets.truncate(2);
        }
        _ => {}
    }
    let parameter_kind = if scenario.codec == ProbeCodec::Hevc {
        32
    } else {
        7
    };
    let mut parameter_changed = false;
    for (index, bytes) in packets.iter_mut().enumerate() {
        let parsed = RtpPacket::parse(bytes, PacketLimits::default())
            .map_err(|_| io::Error::other("fixture mutation input"))?;
        let timestamp = parsed.timestamp();
        let sequence = parsed.sequence();
        let payload = parsed.payload_range();
        let kind = if scenario.codec == ProbeCodec::Hevc {
            (parsed.payload()[0] >> 1) & 63
        } else {
            parsed.payload()[0] & 31
        };
        match scenario.media_fault {
            MediaFault::Sender => {
                bytes[8..12]
                    .copy_from_slice(&fixture_ssrc(scenario.codec).wrapping_add(1).to_be_bytes());
            }
            MediaFault::Sequence if index == 1 => {
                bytes[2..4].copy_from_slice(&sequence.wrapping_add(1).to_be_bytes());
            }
            MediaFault::Cadence if timestamp == FIRST_TIMESTAMP.wrapping_add(2 * FRAME_TICKS) => {
                bytes[4..8].copy_from_slice(&timestamp.wrapping_add(100).to_be_bytes());
            }
            MediaFault::MissingMarker => bytes[1] &= 0x7f,
            MediaFault::ParameterDrift if !parameter_changed && kind == parameter_kind => {
                bytes[payload.end - 1] ^= 1;
                parameter_changed = true;
            }
            MediaFault::HevcField if kind == 33 => {
                // Exactly the native-parser-confirmed VUI field_seq_flag counterexample.
                bytes[payload.start + 28] ^= 1;
                parameter_changed = true;
            }
            _ => {}
        }
    }
    if matches!(
        scenario.media_fault,
        MediaFault::ParameterDrift | MediaFault::HevcField
    ) && !parameter_changed
    {
        return Err(io::Error::other(
            "fixture parameter mutation was not applied",
        ));
    }
    Ok(packets)
fn sdp(codec: ProbeCodec) -> &'static [u8] {
    if codec == ProbeCodec::Hevc {
        concat!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\n",
            "a=control:*\r\nm=video 0 RTP/AVP 98\r\na=control:trackID=1\r\n",
            "a=rtpmap:98 H265/90000\r\n",
            "a=fmtp:98 sprop-vps=QAEBAg==;sprop-sps=QgECAw==;sprop-pps=RAEDBA==\r\n"
        )
        .as_bytes()
    } else {
        concat!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\n",
            "a=control:*\r\nm=video 0 RTP/AVP 96\r\na=control:trackID=1\r\n",
            "a=rtpmap:96 H264/90000\r\n",
            "a=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0IAHw==,aAA=\r\n"
        )
        .as_bytes()
    }
}

fn interleaved(channel: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![b'$', channel];
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn rtp(codec: ProbeCodec, index: u16, fault: MediaFault) -> Vec<u8> {
    let payload = if codec == ProbeCodec::Hevc { 98 } else { 96 };
    let marker = !(matches!(fault, MediaFault::MissingMarker) && index == 1);
    let mut bytes = vec![0x80, payload | if marker { 0x80 } else { 0 }];
    let sequence = if matches!(fault, MediaFault::Sequence) && index == 1 {
        10
    } else {
        index
    };
    let timestamp = if matches!(fault, MediaFault::Cadence) && index == 2 {
        7300
    } else {
        u32::from(index) * 3600
    };
    let sender = if matches!(fault, MediaFault::Sender) {
        SSRC + 1
    } else {
        SSRC
    };
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&timestamp.to_be_bytes());
    bytes.extend_from_slice(&sender.to_be_bytes());
    bytes.extend_from_slice(if codec == ProbeCodec::Hevc {
        &[0x26, 1, 0x80]
    } else {
        &[0x65, 0, 0x80]
    });
    bytes
}

fn serve(listener: TcpListener, scenario: Scenario) -> io::Result<ServerLog> {
    let (mut socket, _) = listener.accept()?;
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
    socket.set_write_timeout(Some(Duration::from_secs(3)))?;
    let mut log = ServerLog::default();
    let mut challenged = false;
    for method in ["OPTIONS", "DESCRIBE", "SETUP", "PLAY", "TEARDOWN"] {
        let Some((mut cseq, signed)) = read_request(&mut socket, &mut log)? else {
            return Ok(log);
        };
        if log.methods.last().map(String::as_str) != Some(method) {
            return Err(io::Error::other("unexpected fixture method"));
        }
        if scenario.digest && !challenged {
            assert!(!signed);
            let realm = if scenario.wrong_realm {
                "foreign-realm"
            } else {
                REALM
            };
            let challenge = format!(
                "RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\nWWW-Authenticate: Digest realm=\"{realm}\",nonce=\"fixture-nonce\",algorithm=SHA-256,qop=\"auth\"\r\nContent-Length: 0\r\n\r\n"
            );
            write_chunks(&mut socket, challenge.as_bytes(), scenario.chunks)?;
            challenged = true;
            let Some((retry, signed)) = read_request(&mut socket, &mut log)? else {
                return Ok(log);
            };
            if retry != cseq + 1
                || !signed
                || log.methods.last().map(String::as_str) != Some(method)
            {
                return Err(io::Error::other("invalid fixture Digest retry"));
            }
            cseq = retry;
        } else if scenario.digest && !signed {
            return Err(io::Error::other("lost fixture Digest context"));
        }
        let bytes = match method {
            "DESCRIBE" => response(
                cseq,
                &format!("Content-Type: application/sdp\r\nServer: {SERVER_CANARY}\r\n"),
                sdp(scenario.codec),
            ),
            "SETUP" => response(
                cseq,
                &format!(
                    "Session: {SESSION_CANARY};timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc={SSRC:08x}\r\n"
                ),
                &[],
            ),
            "PLAY" | "TEARDOWN" => response(
                if method == "TEARDOWN" && matches!(scenario.close, CloseMode::WrongCseq) {
                    cseq + 1
                } else {
                    cseq
                },
                &format!("Session: {SESSION_CANARY}\r\n"),
                &[],
            ),
            _ => response(cseq, "", &[]),
        };
        if method == "TEARDOWN" {
            if matches!(scenario.close, CloseMode::Drop) {
                return Ok(log);
            }
            if scenario.late_media {
                write_chunks(
                    &mut socket,
                    &interleaved(0, &rtp(scenario.codec, 3, MediaFault::None)),
                    scenario.chunks,
                )?;
                write_chunks(
                    &mut socket,
                    &interleaved(1, b"excluded-rtcp-tail"),
                    scenario.chunks,
                )?;
            }
        }
        write_chunks(&mut socket, &bytes, scenario.chunks)?;
        if method == "PLAY" {
            // Deliberately not a valid RTCP packet: this channel is excluded, not trusted timing.
            let mut frames = interleaved(1, b"excluded-rtcp");
            for index in 0..3 {
                let channel = if matches!(scenario.media_fault, MediaFault::ForeignChannel) {
                    4
                } else {
                    0
                };
                frames.extend_from_slice(&interleaved(
                    channel,
                    &rtp(scenario.codec, index, scenario.media_fault),
                ));
            }
            if matches!(scenario.media_fault, MediaFault::Truncated) {
                frames.truncate(frames.len() - 1);
                write_chunks(&mut socket, &frames, scenario.chunks)?;
                return Ok(log);
            }
            write_chunks(&mut socket, &frames, scenario.chunks)?;
        }
    }
    Ok(log)
}

fn drive(
    probe: &mut LiveSiteProbe<'_>,
    authority: &Permit,
    digest: bool,
) -> Result<Result<Completion, ProbeFailure>, io::Error> {
    let start = Instant::now();
    let credentials = DigestCredentials::new("fixture-user", PASSWORD)
        .map_err(|_| io::Error::other("fixture credentials"))?;
    let mut credential_calls = 0u8;
    for _ in 0..20_000 {
        let now = start.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
        let borrowed = if probe.needs_credentials() {
            assert!(digest);
            credential_calls += 1;
            Some(&credentials)
        } else {
            None
        };
        match probe.step(
            SocketReadiness {
                readable: true,
                writable: true,
            },
            now,
            borrowed,
            [credential_calls; 16],
            authority,
        ) {
            Ok(ProbeStep::Progress) => {}
            Ok(ProbeStep::Pending { wake_at_ns, .. }) => {
                assert!(wake_at_ns.is_some());
                thread::sleep(Duration::from_millis(1));
            }
            Ok(ProbeStep::Complete {
                receipt,
                totals,
                close,
                accounting,
            }) => {
                assert!(!probe.needs_credentials());
                assert!(probe.cancel().is_none());
                let repeated =
                    probe.step(SocketReadiness::default(), now, None, [0; 16], authority);
                assert!(matches!(
                    repeated,
                    Err(ProbeFailure {
                        reason: ProbeError::Closed,
                        retirement: None
                    })
                ));
                return Ok(Ok(Completion {
                    receipt,
                    totals,
                    close,
                    accounting,
                }));
            }
            Err(error) => return Ok(Err(error)),
        }
    }
    Err(io::Error::other("fixture driver did not terminate"))
}

fn run(
    scenario: Scenario,
) -> Result<(Result<Completion, ProbeFailure>, ServerLog), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let manifest = manifest(listener.local_addr()?, scenario.digest)?;
    let mut config = config(&manifest, scenario.codec)?;
    if scenario.chunks == 1 {
        config.transport.chunk_bytes = 7;
    }
    let permit = Permit {
        binding: config.binding.clone(),
        denial: Cell::new(None),
        calls: Cell::new(0),
    };
    thread::scope(|scope| {
        let server = scope.spawn(move || serve(listener, scenario));
        let mut probe = LiveSiteProbe::connect(&manifest, config, 0, &permit)?;
        let result = drive(&mut probe, &permit, scenario.digest)?;
        assert!(permit.calls.get() > 4);
        drop(probe);
        let log = server
            .join()
            .map_err(|_| io::Error::other("fixture server panic"))??;
        if let Ok(completed) = &result {
            completed.receipt.validate_for(&manifest)?;
        }
        Ok((result, log))
    })
}

fn assert_fixture_measurement(completed: &Completion, codec: ProbeCodec, late: bool) -> Test {
    assert_eq!(completed.receipt.codec, codec);
    assert_eq!(completed.receipt.ssrc, fixture_ssrc(codec));
    assert_eq!(completed.receipt.observed_frames, 3);
    assert_eq!(completed.receipt.frame_duration_ticks, FRAME_TICKS);
    assert_eq!(completed.receipt.first_rtp_timestamp, FIRST_TIMESTAMP);
    assert_eq!(
        completed.receipt.last_rtp_timestamp,
        FIRST_TIMESTAMP.wrapping_add(2 * FRAME_TICKS)
    );
    assert_eq!(completed.receipt.payload_type, fixture_payload_type(codec));
    assert_eq!(
        completed.receipt.sdp_digest,
        ContentDigest::sha256(sdp(codec))
    );
    let encoded: &[&str] = match codec {
        ProbeCodec::Avc => &[AVC_SPS, AVC_PPS],
        ProbeCodec::Hevc => &[HEVC_VPS, HEVC_SPS, HEVC_PPS],
        ProbeCodec::Jpeg => &[],
    };
    let expected = encoded
        .iter()
        .map(|value| decode_base64(value).map(|bytes| ContentDigest::sha256(&bytes)))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(completed.receipt.parameter_set_digests, expected);

    let packets = fixture_packets(codec)?;
    let sent_packets = packets.len() as u64;
    let sent_bytes: u64 = packets.iter().map(|packet| packet.len() as u64).sum();
    let late_bytes = if late {
        packets.first().ok_or("fixture late packet")?.len() as u64
            + b"excluded-rtcp-tail".len() as u64
    } else {
        0
    };
    let accounting = completed.accounting;
    assert!(accounting.rtp_packets > u64::from(completed.receipt.observed_frames));
    assert!(accounting.rtp_packets <= sent_packets);
    assert!(accounting.rtp_bytes <= sent_bytes);
    assert_eq!(
        accounting.closing_frames_excluded,
        sent_packets - accounting.rtp_packets + if late { 2 } else { 0 }
    );
    assert_eq!(
        accounting.closing_bytes_excluded,
        sent_bytes - accounting.rtp_bytes + late_bytes
    );
    assert_eq!(accounting.rtcp_frames_excluded, 1);
    assert_eq!(
        accounting.rtcp_bytes_excluded,
        b"excluded-rtcp".len() as u64
    );
    assert_eq!(accounting.unfinished_fragment_bytes_excluded, 0);
    assert!(accounting.unverified_nal_bytes_excluded <= accounting.rtp_bytes);
    if codec != ProbeCodec::Avc {
        // HEVC EOS or the complete final JPEG closes the sample without inventing a tail.
        assert_eq!(accounting.unverified_nal_bytes_excluded, 0);
        assert_eq!(accounting.rtp_packets, sent_packets);
    }
    assert_eq!(
        accounting.discarded_wire_bytes,
        completed.totals.received_bytes
    );
    Ok(())
}

#[test]
fn native_avc_sample_waits_for_teardown_and_records_omission() -> Test {
    let (result, log) = run(Scenario::default())?;
    let completed = result?;
    assert_eq!(
        log.methods,
        ["OPTIONS", "DESCRIBE", "SETUP", "PLAY", "TEARDOWN"]
    );
    assert_eq!(log.cseqs, [1, 2, 3, 4, 5]);
    assert_eq!(completed.receipt.codec, ProbeCodec::Avc);
    assert_eq!(completed.receipt.ssrc, SSRC);
    assert_eq!(completed.receipt.observed_frames, 3);
    assert_eq!(completed.receipt.frame_duration_ticks, 3600);
    assert_eq!(
        completed.receipt.sdp_digest,
        ContentDigest::sha256(sdp(ProbeCodec::Avc))
    );
    assert_eq!(completed.accounting.rtp_packets, 3);
    assert_eq!(completed.accounting.rtcp_frames_excluded, 1);
    assert_eq!(completed.accounting.control_responses, 5);
    assert_eq!(
        completed.accounting.discarded_wire_bytes,
        completed.totals.received_bytes
    );
    assert!(!completed.close.remote_session_may_exist);
    assert_eq!(completed.close.pending_cseq, None);
    assert!(
        completed
            .receipt
            .server_identity
            .starts_with("server-header:sha256:")
    );
    let debug = format!("{completed:?}");
    for canary in [SERVER_CANARY, SESSION_CANARY, PASSWORD, "/live/main"] {
        assert!(!debug.contains(canary));
    }
    Ok(())
}

#[test]
fn native_hevc_uses_exact_selected_parameter_sets_without_decoding() -> Test {
    let (result, _) = run(Scenario {
        codec: ProbeCodec::Hevc,
        ..Scenario::default()
    })?;
    let completed = result?;
    assert_eq!(completed.receipt.codec, ProbeCodec::Hevc);
    assert_eq!(completed.receipt.payload_type, 98);
    assert_eq!(
        completed.receipt.parameter_set_digests,
        vec![
            ContentDigest::sha256(&[0x40, 1, 1, 2]),
            ContentDigest::sha256(&[0x42, 1, 2, 3]),
            ContentDigest::sha256(&[0x44, 1, 3, 4]),
        ]
    );
    Ok(())
}

#[test]
fn native_jpeg_completes_fragmented_authenticated_probe_and_waits_for_teardown() -> Test {
    let (result, log) = run(Scenario {
        codec: ProbeCodec::Jpeg,
        digest: true,
        chunks: 1,
        late_media: true,
        ..Scenario::default()
    })?;
    let completed = result?;
    assert_fixture_measurement(&completed, ProbeCodec::Jpeg, true)?;
    assert_eq!(
        log.methods,
        [
            "OPTIONS", "OPTIONS", "DESCRIBE", "SETUP", "PLAY", "TEARDOWN"
        ]
    );
    assert_eq!(log.signed_requests, 5);
    assert_eq!(completed.accounting.rtp_packets, 6);
    assert_eq!(completed.accounting.control_responses, 6);
    assert!(!completed.close.remote_session_may_exist);
    for canary in [SERVER_CANARY, SESSION_CANARY, PASSWORD, "/live/main"] {
        assert!(!format!("{completed:?}").contains(canary));
    }
    Ok(())
}

#[test]
fn partial_socket_requests_and_chunked_responses_preserve_one_receipt() -> Test {
    let (result, log) = run(Scenario {
        chunks: 1,
        late_media: true,
        ..Scenario::default()
    })?;
    let completed = result?;
    assert_eq!(
        log.methods
            .iter()
            .filter(|method| *method == "TEARDOWN")
            .count(),
        1
    );
    assert_eq!(completed.receipt.observed_frames, 3);
    assert_eq!(completed.accounting.rtp_packets, 3);
    assert_eq!(completed.accounting.closing_frames_excluded, 2);
    assert_eq!(
        completed.accounting.closing_bytes_excluded,
        15 + b"excluded-rtcp-tail".len() as u64
    );
    assert!(!completed.close.remote_session_may_exist);
    Ok(())
}

#[test]
fn digest_challenge_borrows_credentials_only_for_bounded_requests() -> Test {
    let (result, log) = run(Scenario {
        digest: true,
        ..Scenario::default()
    })?;
    let completed = result?;
    assert_eq!(
        log.methods,
        [
            "OPTIONS", "OPTIONS", "DESCRIBE", "SETUP", "PLAY", "TEARDOWN"
        ]
    );
    assert_eq!(log.cseqs, [1, 2, 3, 4, 5, 6]);
    assert_eq!(log.signed_requests, 5);
    assert_eq!(completed.accounting.control_responses, 6);
    assert!(!completed.close.remote_session_may_exist);
    Ok(())
}

#[test]
fn foreign_realm_refuses_without_a_signed_request_or_secret_output() -> Test {
    let (result, log) = run(Scenario {
        digest: true,
        wrong_realm: true,
        ..Scenario::default()
    })?;
    let Err(error) = result else {
        return Err("foreign realm was accepted".into());
    };
    assert!(matches!(error.reason, ProbeError::Authentication(_)));
    assert_eq!(log.methods, ["OPTIONS"]);
    assert_eq!(log.signed_requests, 0);
    let retired = error.retirement.as_ref().ok_or("missing retirement")?;
    assert!(!retired.close.remote_session_may_exist);
    assert!(retired.totals.received_bytes > 0);
    assert_eq!(
        retired.accounting.discarded_wire_bytes,
        retired.totals.received_bytes
    );
    for canary in ["foreign-realm", "fixture-nonce", PASSWORD] {
        assert!(!format!("{error:?}").contains(canary));
    }
    Ok(())
}

#[test]
fn sender_gaps_cadence_and_channel_faults_never_publish_a_sample() -> Test {
    for codec in [ProbeCodec::Avc, ProbeCodec::Jpeg] {
        for (fault, expected) in [
            (
                MediaFault::Sender,
                ProbeError::Observation(ObservationError::Continuity),
            ),
            (
                MediaFault::Sequence,
                ProbeError::Observation(ObservationError::Continuity),
            ),
            (
                MediaFault::Cadence,
                ProbeError::Observation(ObservationError::Cadence),
            ),
            (
                MediaFault::ForeignChannel,
                ProbeError::Session(ClientError::MediaNotAdmitted),
            ),
        ] {
            let (result, log) = run(Scenario {
                codec,
                media_fault: fault,
                ..Scenario::default()
            })?;
            let Err(error) = result else {
                return Err("malformed sample was accepted".into());
            };
            assert_eq!(error.reason, expected);
            let retired = error.retirement.ok_or("missing retirement")?;
            assert!(retired.close.remote_session_may_exist);
            assert!(!retired.teardown_acknowledged);
            assert!(!log.methods.iter().any(|method| method == "TEARDOWN"));
        }
fn sender_gaps_cadence_marker_and_channel_faults_never_publish_a_sample() -> Test {
    for (fault, expected) in [
        (
            MediaFault::Sender,
            ProbeError::Observation(ObservationError::Continuity),
        ),
        (
            MediaFault::Sequence,
            ProbeError::Observation(ObservationError::Continuity),
        ),
        (
            MediaFault::Cadence,
            ProbeError::Observation(ObservationError::Cadence),
        ),
        (
            MediaFault::MissingMarker,
            ProbeError::Observation(ObservationError::Continuity),
        ),
        (
            MediaFault::ForeignChannel,
            ProbeError::Session(ClientError::MediaNotAdmitted),
        ),
    ] {
        let (result, log) = run(Scenario {
            media_fault: fault,
            ..Scenario::default()
        })?;
        let Err(error) = result else {
            return Err("malformed sample was accepted".into());
        };
        assert_eq!(error.reason, expected);
        let retired = error.retirement.ok_or("missing retirement")?;
        assert!(retired.close.remote_session_may_exist);
        assert!(!retired.teardown_acknowledged);
        assert!(!log.methods.iter().any(|method| method == "TEARDOWN"));
    }
    Ok(())
}

#[test]
fn complete_sample_without_matching_teardown_ack_remains_indeterminate() -> Test {
    for codec in [ProbeCodec::Avc, ProbeCodec::Jpeg] {
        for close in [CloseMode::Drop, CloseMode::WrongCseq] {
            let (result, log) = run(Scenario {
                codec,
                close,
                ..Scenario::default()
            })?;
            let Err(error) = result else {
                return Err("unacknowledged close was accepted".into());
            };
            let retired = error.retirement.ok_or("missing retirement")?;
            assert!(retired.close.remote_session_may_exist);
            assert_eq!(retired.close.pending_cseq, Some(5));
            assert!(retired.accounting.rtp_packets > 3);
            assert!(!retired.teardown_acknowledged);
            assert_eq!(
                log.methods
                    .iter()
                    .filter(|method| *method == "TEARDOWN")
                    .count(),
                1
            );
        }
    for close in [CloseMode::Drop, CloseMode::WrongCseq] {
        let (result, log) = run(Scenario {
            close,
            ..Scenario::default()
        })?;
        let Err(error) = result else {
            return Err("unacknowledged close was accepted".into());
        };
        let retired = error.retirement.ok_or("missing retirement")?;
        assert!(retired.close.remote_session_may_exist);
        assert_eq!(retired.close.pending_cseq, Some(5));
        assert_eq!(retired.accounting.rtp_packets, 3);
        assert!(!retired.teardown_acknowledged);
        assert_eq!(
            log.methods
                .iter()
                .filter(|method| *method == "TEARDOWN")
                .count(),
            1
        );
    }
    Ok(())
}

#[test]
fn truncated_interleaved_tail_is_not_clean_completion() -> Test {
    let (result, _) = run(Scenario {
        media_fault: MediaFault::Truncated,
        ..Scenario::default()
    })?;
    let Err(error) = result else {
        return Err("truncated source was accepted".into());
    };
    assert!(matches!(error.reason, ProbeError::Wire(_)));
    assert!(
        error
            .retirement
            .ok_or("missing retirement")?
            .close
            .remote_session_may_exist
    );
    Ok(())
}

#[test]
fn jpeg_marked_invalid_payload_and_truncated_transport_never_publish_receipts() -> Test {
    for media_fault in [MediaFault::MarkerOnly, MediaFault::Truncated] {
        let (result, log) = run(Scenario {
            codec: ProbeCodec::Jpeg,
            media_fault,
            ..Scenario::default()
        })?;
        let Err(error) = result else {
            return Err("invalid JPEG probe was accepted".into());
        };
        let retired = error.retirement.ok_or("missing JPEG retirement")?;
        assert!(retired.close.remote_session_may_exist);
        assert!(!retired.teardown_acknowledged);
        assert!(!log.methods.iter().any(|method| method == "TEARDOWN"));
    }
    Ok(())
}

#[test]
fn native_boundaries_without_rtp_markers_confirm_a_prefix_and_exclude_its_tail() -> Test {
    for codec in [ProbeCodec::Avc, ProbeCodec::Hevc] {
        let (result, log) = run(Scenario {
            codec,
            media_fault: MediaFault::MissingMarker,
            ..Scenario::default()
        })?;
        let completed = result?;
        assert_fixture_measurement(&completed, codec, false)?;
        assert_eq!(log.methods.last().map(String::as_str), Some("TEARDOWN"));
        assert!(!completed.close.remote_session_may_exist);
        if codec == ProbeCodec::Avc {
            // The fourth access unit starts the next group while confirming the third.
            // It remains an excluded derivative tail, never a fourth observed picture.
            assert!(completed.accounting.unverified_nal_bytes_excluded > 0);
            assert!(completed.accounting.closing_frames_excluded > 0);
        }
    }
    Ok(())
}

#[test]
fn marked_metadata_and_forged_slice_prefixes_cannot_mint_live_picture_receipts() -> Test {
    for codec in [ProbeCodec::Avc, ProbeCodec::Hevc] {
        for media_fault in [MediaFault::MarkerOnly, MediaFault::ForgedSlice] {
            let (result, log) = run(Scenario {
                codec,
                media_fault,
                ..Scenario::default()
            })?;
            let Err(error) = result else {
                return Err("marked non-picture payloads created a receipt".into());
            };
            assert!(matches!(
                error.reason,
                ProbeError::Observation(_) | ProbeError::Incomplete
            ));
            let retired = error.retirement.ok_or("missing retirement")?;
            assert!(retired.close.remote_session_may_exist);
            assert!(!retired.teardown_acknowledged);
            assert!(!log.methods.iter().any(|method| method == "TEARDOWN"));
            assert_eq!(
                retired.accounting.discarded_wire_bytes,
                retired.totals.received_bytes
            );
        }
    }
    Ok(())
}

#[test]
fn three_hevc_marker_timestamps_without_the_native_eos_boundary_remain_incomplete() -> Test {
    let (result, log) = run(Scenario {
        codec: ProbeCodec::Hevc,
        media_fault: MediaFault::NoEos,
        ..Scenario::default()
    })?;
    let Err(error) = result else {
        return Err("HEVC marker replaced the missing native picture boundary".into());
    };
    assert_eq!(error.reason, ProbeError::Incomplete);
    let retired = error.retirement.ok_or("missing retirement")?;
    assert_eq!(
        retired.accounting.rtp_packets,
        fixture_packets(ProbeCodec::Hevc)?.len() as u64 - 1
    );
    assert!(retired.close.remote_session_may_exist);
    assert!(!retired.teardown_acknowledged);
    assert_eq!(log.methods, ["OPTIONS", "DESCRIBE", "SETUP", "PLAY"]);
    Ok(())
}

#[test]
fn inband_parameter_drift_refuses_real_avc_and_hevc_samples() -> Test {
    for codec in [ProbeCodec::Avc, ProbeCodec::Hevc] {
        let (result, log) = run(Scenario {
            codec,
            media_fault: MediaFault::ParameterDrift,
            ..Scenario::default()
        })?;
        let Err(error) = result else {
            return Err("changed in-band parameter bytes were accepted".into());
        };
        assert_eq!(
            error.reason,
            ProbeError::Observation(ObservationError::Negotiation)
        );
        let retired = error.retirement.ok_or("missing retirement")?;
        assert!(retired.close.remote_session_may_exist);
        assert!(!retired.teardown_acknowledged);
        assert_eq!(log.methods, ["OPTIONS", "DESCRIBE", "SETUP", "PLAY"]);
    }
    Ok(())
}

#[test]
fn field_and_mbaff_descriptions_refuse_before_setup_or_media() -> Test {
    for (codec, media_fault) in [
        (ProbeCodec::Avc, MediaFault::AvcField),
        (ProbeCodec::Avc, MediaFault::AvcMbaff),
        (ProbeCodec::Hevc, MediaFault::HevcField),
    ] {
        let (result, log) = run(Scenario {
            codec,
            media_fault,
            ..Scenario::default()
        })?;
        let Err(error) = result else {
            return Err("field-coded source was presented as frame cadence".into());
        };
        assert_eq!(
            error.reason,
            ProbeError::Observation(ObservationError::Negotiation)
        );
        let retired = error.retirement.ok_or("missing retirement")?;
        assert!(!retired.close.remote_session_may_exist);
        assert!(!retired.teardown_acknowledged);
        assert_eq!(retired.accounting.rtp_packets, 0);
        assert_eq!(log.methods, ["OPTIONS", "DESCRIBE"]);
    }
    Ok(())
}

#[test]
fn invalid_scope_and_authentication_drift_refuse_before_connect() -> Test {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let manifest = manifest(listener.local_addr()?, false)?;
    for change in 0..7 {
        let mut options = config(&manifest, ProbeCodec::Avc)?;
        let permit = Permit {
            binding: options.binding.clone(),
            denial: Cell::new(None),
            calls: Cell::new(0),
        };
        match change {
            0 => options.protocol.presentation_uri.push_str("/foreign"),
            1 => options.stop_after_pictures = 2,
            2 => options.transport.max_received_bytes = MAX_PROBE_WIRE_BYTES + 1,
            3 => {
                options.digest = Some(ProbeDigestConfig {
                    realm: REALM.into(),
                    policy: DigestPolicy::default(),
                })
            }
            4 => options.payload_type = Some(26),
            5 => options.deadline_ns = 60_000_000_001,
            _ => {
                options.binding = TcpBinding::new(
                    StreamKey {
                        generation: manifest.sources[0].generation + 1,
                        ..options.binding.key()
                    },
                    options.binding.peer(),
                    options.binding.authority(),
                    TcpSecurityPolicy::OwnerApprovedPlaintext,
                )?
                .with_auto_ssrc();
            }
        }
        let Err(error) = LiveSiteProbe::connect(&manifest, options, 0, &permit) else {
            return Err("invalid preflight connected".into());
        };
        assert!(!error.connection_attempted);
        assert_eq!(permit.calls.get(), 0);
        assert_eq!(
            listener.accept().err().map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
    }
    Ok(())
}

#[test]
fn authority_refusal_before_connect_has_no_connection_attempt() -> Test {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let manifest = manifest(listener.local_addr()?, false)?;
    let options = config(&manifest, ProbeCodec::Avc)?;
    let permit = Permit {
        binding: options.binding.clone(),
        denial: Cell::new(Some(TcpDenial::Unauthorized)),
        calls: Cell::new(0),
    };
    let Err(error) = LiveSiteProbe::connect(&manifest, options, 0, &permit) else {
        return Err("unauthorized connection escaped".into());
    };
    assert_eq!(
        error.reason,
        ProbeError::Transport(TcpError::Denied(TcpDenial::Unauthorized))
    );
    assert!(!error.connection_attempted);
    assert_eq!(permit.calls.get(), 1);
    assert_eq!(
        listener.accept().err().map(|error| error.kind()),
        Some(io::ErrorKind::WouldBlock)
    );
    Ok(())
}

#[test]
fn revoked_authority_and_step_budget_close_once_without_hidden_teardown() -> Test {
    for denied in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let manifest = manifest(listener.local_addr()?, false)?;
        let mut options = config(&manifest, ProbeCodec::Avc)?;
        options.max_steps = 1;
        let permit = Permit {
            binding: options.binding.clone(),
            denial: Cell::new(None),
            calls: Cell::new(0),
        };
        let mut probe = LiveSiteProbe::connect(&manifest, options, 0, &permit)?;
        let (mut peer, _) = listener.accept()?;
        peer.set_read_timeout(Some(Duration::from_millis(500)))?;
        if denied {
            permit.denial.set(Some(TcpDenial::Revoked));
        } else {
            assert!(matches!(
                probe.step(SocketReadiness::default(), 0, None, [0; 16], &permit)?,
                ProbeStep::Progress
            ));
        }
        let Err(error) = probe.step(
            SocketReadiness {
                readable: true,
                writable: true,
            },
            1,
            None,
            [0; 16],
            &permit,
        ) else {
            return Err("revoked/exhausted probe progressed".into());
        };
        assert_eq!(
            error.reason,
            if denied {
                ProbeError::Transport(TcpError::Denied(TcpDenial::Revoked))
            } else {
                ProbeError::WorkBudget
            }
        );
        let retired = error.retirement.ok_or("missing retirement")?;
        assert_eq!(retired.totals.sent_bytes, 0);
        assert!(!retired.teardown_acknowledged);
        assert!(probe.cancel().is_none());
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte)?, 0);
    }
    Ok(())
}

#[test]
fn deadline_and_clock_regression_are_terminal_before_next_socket_effect() -> Test {
    for time in [5, 10_000_000_000] {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let manifest = manifest(listener.local_addr()?, false)?;
        let options = config(&manifest, ProbeCodec::Avc)?;
        let permit = Permit {
            binding: options.binding.clone(),
            denial: Cell::new(None),
            calls: Cell::new(0),
        };
        let mut probe = LiveSiteProbe::connect(&manifest, options, 10, &permit)?;
        let (mut peer, _) = listener.accept()?;
        peer.set_read_timeout(Some(Duration::from_millis(500)))?;
        let Err(error) = probe.step(
            SocketReadiness {
                readable: true,
                writable: true,
            },
            time,
            None,
            [0; 16],
            &permit,
        ) else {
            return Err("invalid owner time progressed".into());
        };
        assert_eq!(
            error.reason,
            if time == 5 {
                ProbeError::ClockReversed
            } else {
                ProbeError::Transport(TcpError::Deadline)
            }
        );
        assert_eq!(
            error
                .retirement
                .ok_or("missing retirement")?
                .totals
                .sent_bytes,
            0
        );
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte)?, 0);
    }
    Ok(())
}
