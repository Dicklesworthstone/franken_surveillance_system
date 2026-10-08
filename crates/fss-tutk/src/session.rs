//! Sans-IO TUTK-NEW session driver: discovery → DTLS → AV login → K-command
//! auth → stream. No sockets, no threads, no clocks: the owner pumps
//! datagrams and time in, and takes datagrams and typed events out.
//!
//! Sequencing mirrors the live-proven Python reference client (LAB-2026-10-07)
//! and go2rtc: discovery seq 0→1→2→3 with ticket echo and session-port
//! adoption, login1 then login2 10 ms later, ACK after the login response and
//! every IOCTRL/channel message plus a 100 ms ticker while streaming, 1 s
//! IOCTRL retransmits until the K-response arrives, K10010 video (and audio
//! only when explicitly enabled) to start the stream.
//!
//! Bounded everything: event queue, pending frames, phase deadlines, retry
//! counters. A drop is always counted and surfaced — never silent.

use crate::av::{self, AvPacket, FrameInfo, FrameReassembler, CHANNEL_AUDIO};
use crate::av_stream::{AvStreamParser, StreamMsg};
use crate::dtls::DtlsClient;
use crate::wire::{self, NewProto, CHANNEL_MAIN, CMD_KEEPALIVE, MAGIC_NEWPROTO};

/// Default per-phase deadline (10 s, matching the reference client).
pub const PHASE_TIMEOUT_NS: u64 = 10_000_000_000;
/// Discovery resend interval (2 s).
pub const DISCOVERY_INTERVAL_NS: u64 = 2_000_000_000;
/// Discovery attempts before Failed.
pub const DISCOVERY_ATTEMPTS: u32 = 5;
/// IOCTRL retransmit interval while awaiting a K-response (1 s).
pub const RESEND_INTERVAL_NS: u64 = 1_000_000_000;
/// DTLS flight retransmit interval (RFC 6347; 1 s, bounded).
pub const DTLS_RESEND_INTERVAL_NS: u64 = 1_000_000_000;
/// DTLS flight retransmit cap before the phase deadline fires.
pub const DTLS_RESEND_MAX: u32 = 5;
/// Streaming ACK ticker interval (100 ms).
pub const ACK_TICKER_NS: u64 = 100_000_000;
/// Delay between login1 and login2 (10 ms, per go2rtc).
pub const LOGIN2_DELAY_NS: u64 = 10_000_000;
/// Cap on queued events awaiting the owner.
pub const EVENT_QUEUE_MAX: usize = 1024;
/// Cap on incomplete frames held by the reassembler.
pub const PENDING_FRAMES_MAX: usize = 64;

/// Owner-supplied session configuration.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// 20-character device UID.
    pub uid: String,
    /// Device ENR string (secret-adjacent; never logged or persisted here).
    pub enr: String,
    /// Device MAC as "AABBCCDDEEFF" or colon-separated.
    pub mac: String,
    /// Request and keep audio (privacy default: false — video only).
    pub audio: bool,
    /// Use the NUL-truncated legacy PSK derivation (interop fallback).
    pub psk_truncated: bool,
    /// Seed for the session's deterministic randomness (client random,
    /// ephemeral key, session id). The owner picks this; it is never
    /// derived from secrets.
    pub seed: u64,
    /// Known-good compatibility tuples `(model, firmware)` per plan §8.8.
    /// An unknown tuple — or a camera self-reporting a non-"normal"
    /// `cameraInfo.type` — fails closed at K-auth: quarantine event, terminal
    /// failure, and NO stream-start is ever dispatched. An empty list refuses
    /// every camera (default-deny).
    pub known_tuples: Vec<(String, String)>,
}

/// A reassembled access unit with receive timing and continuity context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssembledFrame {
    /// AV channel (`CHANNEL_I_VIDEO`/`CHANNEL_P_VIDEO`/`CHANNEL_AUDIO`).
    pub channel: u8,
    /// Camera frame number.
    pub frame_no: u32,
    /// Assembled access-unit payload (codec passthrough; never transcoded).
    pub au: Vec<u8>,
    /// Camera FRAMEINFO when the trailer validated.
    pub info: Option<FrameInfo>,
    /// Host receive time of the frame's first packet (ns).
    pub first_recv_ns: u64,
    /// Host receive time of the frame's last packet (ns).
    pub last_recv_ns: u64,
    /// Number of wire packets the frame arrived in.
    pub packets: u16,
    /// A continuity gap (frame-number jump or dropped pending frame) precedes.
    pub gap_before: bool,
}

/// Typed session outcomes for the owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    /// Discovery handshake completed; session lives on the adopted port.
    DiscoveryComplete {
        /// Server-assigned session ticket.
        ticket: u16,
        /// Session id the camera echoed.
        session_id: [u8; 8],
    },
    /// DTLS 1.2 handshake finished; the channel is encrypted.
    DtlsEstablished,
    /// Camera accepted the AV login.
    LoginAccepted {
        /// Advertised capability bitfield.
        capabilities: u32,
        /// Whether intercom (two-way audio) is supported.
        two_way_audio: bool,
    },
    /// Camera refused the AV login (expiry/revocation shape).
    LoginRejected {
        /// Camera refusal code (`0x20` = expiry/revocation shape).
        response_type: u8,
    },
    /// K-command auth succeeded; raw K10003 JSON payload included.
    KAuthComplete {
        /// Raw K10003 JSON payload (the auth receipt witness).
        camera_info: String,
    },
    /// K-command auth refused (`connectionRes` verbatim).
    KAuthRejected {
        /// `connectionRes` verbatim.
        connection_res: String,
    },

    /// Camera authenticated but its (model, firmware) tuple — or a
    /// self-reported non-"normal" `cameraInfo.type` — is absent from the
    /// owner-supplied allowlist; the session fails closed BEFORE any stream
    /// request is dispatched (plan §8.8 unknown-tuple quarantine).
    KAuthQuarantined {
        /// Camera-reported model.
        model: String,
        /// Camera-reported firmware.
        firmware: String,
        /// Why the tuple was quarantined.
        detail: String,
    },
    /// K10011 received; media stream is running. The exact acceptance
    /// payload is the witness for the acquisition ledger.
    StreamStarted {
        /// Exact K10011 acceptance bytes (the ledger witness).
        payload: Vec<u8>,
    },
    /// One reassembled media frame (video always; audio only if enabled).
    Frame(AssembledFrame),
    /// Terminal failure at a named stage with a concrete reason.
    Failed {
        /// Stage where the session failed.
        stage: &'static str,
        /// Concrete failure reason.
        reason: String,
    },
}

/// Phase names for external state reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseName {
    /// Discovery handshake (seq 0..=3) in progress.
    Discovery,
    /// DTLS 1.2 handshake in progress.
    Dtls,
    /// AV login exchange in progress.
    Login,
    /// K-command challenge/response in progress.
    KAuth,
    /// K10010/K10011 stream negotiation in progress.
    StreamStart,
    /// Media streaming.
    Streaming,
    /// Session over (failure, cancellation, or close).
    Terminal,
}

/// Monotone session counters (drops are always visible here).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionStats {
    /// Reassembled video frames emitted.
    pub video_frames: u64,
    /// Audio frames dropped because the privacy gate kept audio off.
    pub audio_frames_dropped: u64,
    /// Continuity gaps observed (frame-number jumps, evictions, drops).
    pub continuity_gaps: u64,
    /// msgACK frames sent.
    pub acks_sent: u64,
    /// Incomplete frames evicted under the pending-frames bound.
    pub pending_frames_dropped: u64,
    /// Frame events dropped under the event-queue bound.
    pub events_dropped: u64,
    /// Bytes consumed by stream resync.
    pub resync_bytes: u64,
}

/// Deterministic xorshift64* for session randomness.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn bytes(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Discovery,
    Dtls,
    Login,
    KAuth,
    StreamStart,
    Streaming,
    Terminal,
}

/// Sans-IO TUTK-NEW session. See module docs for the pump contract.
pub struct TutkSession {
    cfg: SessionConfig,
    proto: NewProto,
    rng: Rng,
    phase: Phase,
    phase_deadline: u64,
    now_ns: u64,
    outgoing: std::collections::VecDeque<Vec<u8>>,
    events: std::collections::VecDeque<SessionEvent>,
    // discovery
    session_id: [u8; 8],
    ticket: u16,
    discovery_attempts: u32,
    discovery_next_ns: u64,
    discovery_seq: u16,
    // dtls
    dtls: Option<DtlsClient>,
    dtls_flight: Vec<Vec<u8>>,
    dtls_flight_next_ns: Option<u64>,
    dtls_flight_retries: u32,
    login2_due_ns: Option<u64>,
    // av state
    parser: AvStreamParser,
    reasm: FrameReassembler,
    avseq: u32,
    subchannel: u16,
    ack_flags: u16,
    rx_seq_start: u16,
    rx_seq_end: u16,
    rx_seq_init: bool,
    ack_ticker_next_ns: Option<u64>,
    resend_frame: Option<Vec<u8>>,
    resend_next_ns: Option<u64>,
    audio_started: bool,
    // per-packet frame timing + continuity
    pkt_times: std::collections::BTreeMap<(u8, u32), (u64, u64, u16)>, // (first,last,count)
    last_frame_no: Option<u32>,
    gap_pending: bool,
    stats: SessionStats,
}

impl TutkSession {
    /// New session; queues the first discovery request immediately.
    #[must_use]
    pub fn new(cfg: SessionConfig) -> Option<Self> {
        let proto = NewProto::new(&cfg.uid, &cfg.enr, &cfg.mac)?;
        let mut rng = Rng(cfg.seed | 1);
        let mut r2 = [0u8; 2];
        rng.bytes(&mut r2);
        let session_id = wire::new_session_id(r2);
        let mut s = Self {
            cfg,
            proto,
            rng,
            phase: Phase::Discovery,
            phase_deadline: 0,
            now_ns: 0,
            outgoing: Default::default(),
            events: Default::default(),
            session_id,
            ticket: 0,
            discovery_attempts: 0,
            discovery_next_ns: 0,
            discovery_seq: 0,
            dtls: None,
            dtls_flight: Vec::new(),
            dtls_flight_next_ns: None,
            dtls_flight_retries: 0,
            login2_due_ns: None,
            parser: AvStreamParser::new(),
            reasm: FrameReassembler::new(),
            avseq: 0,
            subchannel: 0,
            ack_flags: 0,
            rx_seq_start: 0,
            rx_seq_end: 0,
            rx_seq_init: false,
            ack_ticker_next_ns: None,
            resend_frame: None,
            resend_next_ns: None,
            audio_started: false,
            pkt_times: Default::default(),
            last_frame_no: None,
            gap_pending: false,
            stats: SessionStats::default(),
        };
        let pkt = s.proto.build_discovery(0, 0, &s.session_id).ok()?;
        s.outgoing.push_back(pkt.to_vec());
        s.discovery_attempts = 1;
        s.discovery_next_ns = DISCOVERY_INTERVAL_NS;
        s.phase_deadline = DISCOVERY_INTERVAL_NS * (DISCOVERY_ATTEMPTS as u64 + 1);
        Some(s)
    }

    /// Current phase name for state reporting.
    #[must_use]
    pub fn phase(&self) -> PhaseName {
        match self.phase {
            Phase::Discovery => PhaseName::Discovery,
            Phase::Dtls => PhaseName::Dtls,
            Phase::Login => PhaseName::Login,
            Phase::KAuth => PhaseName::KAuth,
            Phase::StreamStart => PhaseName::StreamStart,
            Phase::Streaming => PhaseName::Streaming,
            Phase::Terminal => PhaseName::Terminal,
        }
    }

    /// Monotone counters (drops always visible).
    #[must_use]
    pub fn stats(&self) -> SessionStats {
        self.stats
    }

    /// Session id chosen at construction (echoed by the camera).
    #[must_use]
    pub fn session_id(&self) -> [u8; 8] {
        self.session_id
    }

    /// Take the next datagram to send, if any.
    pub fn poll_send(&mut self) -> Option<Vec<u8>> {
        self.outgoing.pop_front()
    }

    /// Take the next typed event, if any.
    pub fn poll_event(&mut self) -> Option<SessionEvent> {
        self.events.pop_front()
    }

    /// Drive timers: discovery resends, DTLS/login/K deadlines, IOCTRL
    /// retransmits, the 100 ms ACK ticker. Call at least every 10 ms.
    pub fn advance(&mut self, now_ns: u64) {
        self.now_ns = now_ns;
        if self.phase == Phase::Terminal {
            return;
        }
        match self.phase {
            Phase::Discovery => {
                if self.discovery_seq == 0 && now_ns >= self.discovery_next_ns {
                    if self.discovery_attempts >= DISCOVERY_ATTEMPTS {
                        self.fail("discovery", "camera did not answer seq=0");
                        return;
                    }
                    if let Ok(pkt) = self.proto.build_discovery(0, 0, &self.session_id) {
                        self.outgoing.push_back(pkt.to_vec());
                    }
                    self.discovery_attempts += 1;
                    self.discovery_next_ns = now_ns + DISCOVERY_INTERVAL_NS;
                }
                if now_ns >= self.phase_deadline {
                    self.fail("discovery", "handshake deadline exceeded");
                }
            }
            Phase::Dtls | Phase::Login | Phase::KAuth | Phase::StreamStart => {
                if now_ns >= self.phase_deadline {
                    let stage = match self.phase {
                        Phase::Dtls => "dtls",
                        Phase::Login => "login",
                        Phase::KAuth => "kauth",
                        _ => "stream-start",
                    };
                    self.fail(stage, "phase deadline exceeded");
                    return;
                }
                if self.phase == Phase::Dtls
                    && let (Some(next), false) = (
                        self.dtls_flight_next_ns,
                        self.dtls_flight.is_empty(),
                    )
                    && now_ns >= next
                {
                    if self.dtls_flight_retries >= DTLS_RESEND_MAX {
                        self.fail("dtls", "flight retransmit budget exhausted");
                        return;
                    }
                    let (ticket, sid) = (self.ticket, self.session_id);
                    for dgram in self.dtls_flight.clone() {
                        let wrapped = self.proto.wrap_dtls(&dgram, ticket, &sid, CHANNEL_MAIN);
                        self.outgoing.push_back(wrapped);
                    }
                    self.dtls_flight_retries += 1;
                    self.dtls_flight_next_ns = Some(now_ns + DTLS_RESEND_INTERVAL_NS);
                }
                if let Some(due) = self.login2_due_ns
                    && now_ns >= due
                {
                    self.login2_due_ns = None;
                    self.send_login2();
                }
                if let (Some(frame), Some(next)) = (self.resend_frame.clone(), self.resend_next_ns)
                    && now_ns >= next
                {
                    self.send_appdata(&frame);
                    self.resend_next_ns = Some(now_ns + RESEND_INTERVAL_NS);
                }
            }
            Phase::Streaming => {
                if let Some(next) = self.ack_ticker_next_ns
                    && now_ns >= next
                {
                    self.send_ack();
                    self.ack_ticker_next_ns = Some(now_ns + ACK_TICKER_NS);
                }
            }
            Phase::Terminal => {}
        }
    }

    /// Feed one received UDP datagram (caller-owned IO).
    pub fn feed_datagram(&mut self, data: &[u8], now_ns: u64) {
        self.now_ns = now_ns;
        if self.phase == Phase::Terminal || data.is_empty() {
            return;
        }
        match self.phase {
            Phase::Discovery => self.feed_discovery(data, now_ns),
            Phase::Dtls => self.feed_dtls(data, now_ns),
            _ => self.feed_appdata_wrapped(data, now_ns),
        }
    }

    /// Ask the session to close (DTLS close_notify, then terminal).
    pub fn close(&mut self) {
        if let Some(d) = self.dtls.as_mut() {
            d.close();
            self.drain_dtls_out();
        }
        self.phase = Phase::Terminal;
    }

    // -- discovery ----------------------------------------------------------

    fn feed_discovery(&mut self, data: &[u8], now_ns: u64) {
        let resp = match self.proto.parse_discovery(data) {
            Ok(r) => r,
            Err(_) => return,
        };
        if resp.direction != wire::DIR_RESPONSE || resp.session_id != self.session_id {
            return;
        }
        match (self.discovery_seq, resp.seq) {
            (0, 1) => {
                self.ticket = resp.ticket;
                if let Ok(pkt) = self.proto.build_discovery(2, self.ticket, &self.session_id) {
                    self.outgoing.push_back(pkt.to_vec());
                }
                self.discovery_seq = 2;
                self.phase_deadline = now_ns + DISCOVERY_INTERVAL_NS * DISCOVERY_ATTEMPTS as u64;
            }
            (2, 3) if resp.ticket == self.ticket => {
                let sid = self.session_id;
                let ticket = self.ticket;
                self.events.push_back(SessionEvent::DiscoveryComplete {
                    ticket,
                    session_id: sid,
                });
                self.start_dtls(now_ns);
            }
            _ => {}
        }
    }

    // -- dtls ---------------------------------------------------------------

    fn start_dtls(&mut self, now_ns: u64) {
        let psk = if self.cfg.psk_truncated {
            wire::derive_psk_truncated(&self.cfg.enr)
        } else {
            wire::derive_psk(&self.cfg.enr).to_vec()
        };
        let mut cr = [0u8; 32];
        self.rng.bytes(&mut cr);
        let mut es = [0u8; 32];
        self.rng.bytes(&mut es);
        match DtlsClient::new(&psk, cr, es) {
            Some(mut c) => {
                c.start();
                self.dtls = Some(c);
                self.phase = Phase::Dtls;
                self.drain_dtls_out();
                self.phase_deadline = now_ns + PHASE_TIMEOUT_NS;
            }
            None => self.fail("dtls", "empty PSK"),
        }
    }

    fn feed_dtls(&mut self, data: &[u8], now_ns: u64) {
        let (payload, _auth_ok, _chan) = match self.proto.unwrap_dtls(data, false) {
            Ok(v) => v,
            Err(_) => return,
        };
        let dtls = match self.dtls.as_mut() {
            Some(d) => d,
            None => return,
        };
        if let Err(e) = dtls.feed_datagram(payload) {
            self.fail("dtls", &format!("{e:?}"));
            return;
        }
        self.drain_dtls_out();
        let established = self.dtls.as_ref().is_some_and(|d| d.established());
        if established {
            self.events.push_back(SessionEvent::DtlsEstablished);
            self.phase = Phase::Login;
            self.phase_deadline = now_ns + PHASE_TIMEOUT_NS;
            self.send_login1();
            self.login2_due_ns = Some(now_ns + LOGIN2_DELAY_NS);
        }
    }

    fn drain_dtls_out(&mut self) {
        let (ticket, sid) = (self.ticket, self.session_id);
        if let Some(d) = self.dtls.as_mut() {
            let mut flight = Vec::new();
            while let Some(dgram) = d.poll_send() {
                flight.push(dgram);
            }
            if !flight.is_empty() && self.phase == Phase::Dtls {
                // RFC 6347 retransmission: cache the LATEST flight; resend it
                // on schedule until the peer answers (bounded).
                self.dtls_flight = flight.clone();
                self.dtls_flight_next_ns = Some(self.now_ns + DTLS_RESEND_INTERVAL_NS);
            }
            for dgram in flight {
                let wrapped = self.proto.wrap_dtls(&dgram, ticket, &sid, CHANNEL_MAIN);
                self.outgoing.push_back(wrapped);
            }
        }
    }

    // -- appdata phases (login, kauth, stream-start, streaming) -------------

    fn feed_appdata_wrapped(&mut self, data: &[u8], now_ns: u64) {
        // keepalive: session-level liveness; no echo by default (matches
        // reference client default cfg echo_keepalive=false).
        if data.len() >= 6
            && u16::from_le_bytes([data[0], data[1]]) == MAGIC_NEWPROTO
            && u16::from_le_bytes([data[4], data[5]]) == CMD_KEEPALIVE
        {
            return;
        }
        let (payload, _auth, _chan) = match self.proto.unwrap_dtls(data, false) {
            Ok(v) => v,
            Err(_) => return,
        };
        let msgs = {
            let dtls = match self.dtls.as_mut() {
                Some(d) => d,
                None => return,
            };
            match dtls.recv_appdata(payload) {
                Ok(plain) => plain,
                Err(_) => return,
            }
        };
        if msgs.is_empty() {
            return;
        }
        let parsed = match self.parser.feed(&msgs) {
            Ok(m) => m,
            Err(_) => {
                self.fail("av-stream", "buffer overflow without progress");
                return;
            }
        };
        for msg in parsed {
            self.handle_msg(msg, now_ns);
            if self.phase == Phase::Terminal {
                return;
            }
        }
        self.stats.resync_bytes = self.parser.dropped_bytes();
    }

    fn handle_msg(&mut self, msg: StreamMsg, now_ns: u64) {
        match msg {
            StreamMsg::Ack(_) => {}
            StreamMsg::LoginResp(resp) => {
                if self.phase != Phase::Login {
                    return;
                }
                if resp.success {
                    self.send_ack();
                    self.ack_ticker_next_ns = Some(now_ns + ACK_TICKER_NS);
                    self.events.push_back(SessionEvent::LoginAccepted {
                        capabilities: resp.capabilities,
                        two_way_audio: resp.two_way_audio != 0,
                    });
                    self.phase = Phase::KAuth;
                    self.phase_deadline = now_ns + PHASE_TIMEOUT_NS;
                    self.send_k10000();
                } else {
                    self.events.push_back(SessionEvent::LoginRejected {
                        response_type: resp.response_type,
                    });
                    self.fail("login", "camera rejected AV login");
                }
            }
            StreamMsg::Ioctrl(cmd, payload, wseq) => {
                self.track_rx(wseq);
                self.send_ack();
                match self.phase {
                    Phase::KAuth => self.handle_kauth(cmd, &payload, now_ns),
                    Phase::StreamStart => self.handle_stream_start(cmd, &payload, now_ns),
                    _ => {}
                }
            }
            StreamMsg::ChanMsg(_, _wseq) => {
                self.send_ack();
            }
            StreamMsg::Packet(pkt) => self.handle_packet(pkt, now_ns),
        }
    }

    fn handle_kauth(&mut self, cmd: u16, payload: &[u8], now_ns: u64) {
        match cmd {
            10001 => {
                self.resend_frame = None;
                self.resend_next_ns = None;
                let (status, challenge) = match av::parse_k10001(payload) {
                    Ok(v) => v,
                    Err(_) => {
                        self.fail("kauth", "malformed K10001");
                        return;
                    }
                };
                if !matches!(status, 1 | 3 | 6) {
                    self.fail("kauth", "camera reports unusable status");
                    return;
                }
                let response = match av::k_challenge_response(status, &challenge, &self.cfg.enr) {
                    Ok(r) => r,
                    Err(_) => {
                        self.fail("kauth", "challenge response failed");
                        return;
                    }
                };
                let mut sid4 = [0u8; 4];
                self.rng.bytes(&mut sid4);
                let hl = av::build_k10002(&response, sid4, true, self.cfg.audio);
                self.send_hl(hl);
            }
            10003 => {
                self.resend_frame = None;
                self.resend_next_ns = None;
                let info = match av::parse_k10003(payload) {
                    Ok(s) => s.to_string(),
                    Err(_) => {
                        self.fail("kauth", "malformed K10003");
                        return;
                    }
                };
                if !json_connection_res_ok(&info) {
                    let res = extract_json_field(&info, "connectionRes").unwrap_or_default();
                    self.events.push_back(SessionEvent::KAuthRejected {
                        connection_res: res,
                    });
                    self.fail("kauth", "authentication failed");
                    return;
                }
                // Plan §8.8: unknown (model, firmware) tuples fail closed
                // here — before any stream request exists to cancel. The
                // cameraInfo.type field is codec info on live firmware
                // (e.g. "H264"), NOT a health signal; the tuple allowlist is
                // the quarantine mechanism.
                let model = extract_json_field(&info, "model").unwrap_or_default();
                let firmware = extract_json_field(&info, "firmware").unwrap_or_default();
                let known = self
                    .cfg
                    .known_tuples
                    .iter()
                    .any(|(m, f)| *m == model && *f == firmware);
                if !known {
                    let detail = "tuple not in owner allowlist".to_string();
                    self.events.push_back(SessionEvent::KAuthQuarantined {
                        model,
                        firmware,
                        detail: detail.clone(),
                    });
                    self.fail("kauth", &format!("unknown tuple quarantined ({detail})"));
                    return;
                }
                self.events.push_back(SessionEvent::KAuthComplete { camera_info: info });
                self.phase = Phase::StreamStart;
                self.phase_deadline = now_ns + PHASE_TIMEOUT_NS;
                let hl = av::build_k10010(1, true);
                self.send_hl(hl);
            }
            _ => {}
        }
    }

    fn handle_stream_start(&mut self, cmd: u16, payload: &[u8], _now_ns: u64) {
        if cmd != 10011 {
            return;
        }
        self.resend_frame = None;
        self.resend_next_ns = None;
        if self.cfg.audio && !self.audio_started {
            self.audio_started = true;
            let hl = av::build_k10010(2, true);
            self.send_hl(hl);
            return;
        }
        self.events.push_back(SessionEvent::StreamStarted { payload: payload.to_vec() });
        self.phase = Phase::Streaming;
    }

    // -- packets, continuity, reassembly -------------------------------------

    fn handle_packet(&mut self, pkt: AvPacket, now_ns: u64) {
        if self.phase != Phase::Streaming && self.phase != Phase::StreamStart {
            return;
        }
        if pkt.channel == CHANNEL_AUDIO && !self.cfg.audio {
            self.stats.audio_frames_dropped += 1;
            return;
        }
        let key = (pkt.channel, pkt.frame_no);
        let entry = self.pkt_times.entry(key).or_insert((now_ns, now_ns, 0));
        entry.1 = now_ns;
        entry.2 += 1;
        // bound pending reassembly state
        if self.reasm.pending() >= PENDING_FRAMES_MAX {
            self.drop_oldest_pending();
        }
        let done = self.reasm.add(&pkt);
        if let Some((channel, frame_no, au, info)) = done {
            let (first, last, count) = self.pkt_times.remove(&key).unwrap_or((now_ns, now_ns, 1));
            let gap = self.compute_gap(frame_no);
            if gap {
                self.stats.continuity_gaps += 1;
            }
            if self.events.len() >= EVENT_QUEUE_MAX {
                self.stats.events_dropped += 1;
                self.gap_pending = true;
                return;
            }
            self.stats.video_frames += 1;
            self.events.push_back(SessionEvent::Frame(AssembledFrame {
                channel,
                frame_no,
                au,
                info,
                first_recv_ns: first,
                last_recv_ns: last,
                packets: count,
                gap_before: gap,
            }));
        }
    }

    fn compute_gap(&mut self, frame_no: u32) -> bool {
        let gap = match self.last_frame_no {
            None => self.gap_pending,
            Some(last) => frame_no != last.wrapping_add(1) || self.gap_pending,
        };
        self.last_frame_no = Some(frame_no);
        self.gap_pending = false;
        gap
    }

    fn drop_oldest_pending(&mut self) {
        // FrameReassembler holds no eviction API; drop our oldest tracked
        // frame by clearing the whole reassembler — the pending incompletes
        // are unrecoverable anyway, and the jump is counted as a gap.
        self.reasm = FrameReassembler::new();
        self.pkt_times.clear();
        self.gap_pending = true;
        self.stats.pending_frames_dropped += 1;
    }

    // -- senders --------------------------------------------------------------

    fn next_avseq(&mut self) -> u32 {
        let v = self.avseq;
        self.avseq = self.avseq.wrapping_add(1);
        v
    }

    fn next_subchannel(&mut self) -> u16 {
        let v = self.subchannel;
        self.subchannel = self.subchannel.wrapping_add(1);
        v
    }

    fn track_rx(&mut self, wseq: u16) {
        if wseq > self.rx_seq_end || self.rx_seq_end == 0xFFFF {
            self.rx_seq_end = wseq;
        }
    }

    fn send_appdata(&mut self, data: &[u8]) {
        if let Some(d) = self.dtls.as_mut()
            && d.send_appdata(data).is_ok()
        {
            self.drain_dtls_out();
        }
    }

    fn send_ack(&mut self) {
        self.ack_flags = self.ack_flags.wrapping_add(1);
        let ts_ms = (self.now_ns / 1_000_000) as u16;
        let avseq = self.next_avseq();
        let frame = av::build_ack(
            avseq,
            self.rx_seq_start,
            self.rx_seq_end,
            self.ack_flags,
            ts_ms,
        );
        self.send_appdata(&frame);
        if self.rx_seq_init {
            self.rx_seq_start = self.rx_seq_end;
        }
        self.rx_seq_init = true;
        self.stats.acks_sent += 1;
    }

    fn send_login1(&mut self) {
        let mut rid = [0u8; 4];
        self.rng.bytes(&mut rid);
        let login1 = av::build_av_login1(&self.cfg.enr, rid);
        self.send_appdata(&login1);
    }

    fn send_login2(&mut self) {
        let mut rid = [0u8; 4];
        self.rng.bytes(&mut rid);
        let login1 = av::build_av_login1(&self.cfg.enr, rid);
        let login2 = av::build_av_login2(&login1);
        self.send_appdata(&login2);
    }

    fn send_hl(&mut self, hl_msg: Vec<u8>) {
        let avseq = self.next_avseq();
        let sub = self.next_subchannel();
        let frame = av::build_ioctrl(avseq, sub, &hl_msg);
        self.send_appdata(&frame);
        self.resend_frame = Some(frame);
        self.resend_next_ns = Some(self.now_ns + RESEND_INTERVAL_NS);
    }

    fn send_k10000(&mut self) {
        let hl = av::build_k10000();
        self.send_hl(hl);
    }

    fn fail(&mut self, stage: &'static str, reason: &str) {
        if self.phase == Phase::Terminal {
            return;
        }
        self.events.push_back(SessionEvent::Failed {
            stage,
            reason: reason.to_string(),
        });
        self.phase = Phase::Terminal;
    }
}

/// `connectionRes == "1"` in the K10003 JSON (verbatim compare, no parser).
fn json_connection_res_ok(json: &str) -> bool {
    extract_json_field(json, "connectionRes").is_some_and(|v| v == "1")
}

/// Extract a `"field":"value"` string value (K10003 is flat camera JSON).
fn extract_json_field(json: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\"");
    let start = json.find(&needle)? + needle.len();
    let rest = json[start..].trim_start_matches([':', ' ', '\t']);
    if let Some(hex) = rest.strip_prefix('"') {
        let end = hex.find('"')?;
        return Some(hex[..end].to_string());
    }
    // numeric / bare token
    let end = rest
        .find([',', '}', ']'])
        .unwrap_or(rest.len());
    Some(rest[..end].trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_field_extraction() {
        let j = r#"{"connectionRes":"1","cameraInfo":{"basicInfo":{"model":"HL_CAM4"}}}"#;
        assert_eq!(extract_json_field(j, "connectionRes").as_deref(), Some("1"));
        assert!(json_connection_res_ok(j));
        let bad = r#"{"connectionRes":"3"}"#;
        assert!(!json_connection_res_ok(bad));
    }

    #[test]
    fn rng_is_deterministic() {
        let mut a = Rng(7);
        let mut b = Rng(7);
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        a.bytes(&mut x);
        b.bytes(&mut y);
        assert_eq!(x, y);
        assert_ne!(x, [0u8; 32]);
    }

    fn test_cfg() -> SessionConfig {
        SessionConfig {
            uid: "SIMCAMSIMCAMSIMCAM11".to_string(),
            enr: "sim-enr-16byte!!".to_string(),
            mac: "00AA11BB22CC".to_string(),
            audio: false,
            psk_truncated: false,
            seed: 99,
            known_tuples: vec![("SIM-CAM".to_string(), "9.99.0.SIM".to_string())],
        }
    }

    /// Drive discovery to completion with scripted camera responses; returns
    /// the session in DTLS phase and the count of DTLS datagrams queued.
    fn session_in_dtls() -> (TutkSession, usize) {
        let mut s = TutkSession::new(test_cfg()).unwrap();
        let first = s.poll_send().expect("discovery seq=0 queued");
        assert_eq!(first.len(), 52);
        // camera answers seq=1 with ticket 0x42
        let resp1 = s.proto.build_discovery_response(1, 0x42, &s.session_id);
        s.feed_datagram(&resp1, 100_000_000);
        // session queues seq=2 echo
        let echo = s.poll_send().expect("seq=2 echo queued");
        assert_eq!(echo.len(), 52);
        // camera completes with seq=3
        let resp3 = s.proto.build_discovery_response(3, 0x42, &s.session_id);
        s.feed_datagram(&resp3, 200_000_000);
        assert!(matches!(s.phase(), PhaseName::Dtls));
        let ev = s.poll_event();
        assert!(matches!(ev, Some(SessionEvent::DiscoveryComplete { ticket: 0x42, .. })), "{ev:?}");
        // first DTLS flight (ClientHello) is queued, wrapped
        let mut dtls_dgrams = 0;
        let mut first_flight = Vec::new();
        while let Some(d) = s.poll_send() {
            dtls_dgrams += 1;
            first_flight.push(d);
        }
        assert!(dtls_dgrams >= 1, "ClientHello flight queued");
        (s, dtls_dgrams)
    }

    #[test]
    fn discovery_handshake_drives_to_dtls() {
        let (s, _) = session_in_dtls();
        assert!(matches!(s.phase(), PhaseName::Dtls));
    }

    #[test]
    fn dtls_flight_retransmits_bounded_then_fails() {
        let (mut s, initial) = session_in_dtls();
        let mut retransmits = 0u32;
        // no peer answers; advance through resend schedule (1s) x budget (5)
        for step in 1..=6u64 {
            let t = 200_000_000 + step * 1_000_000_000; // 1.2s, 2.2s, ...
            s.advance(t);
            let mut n = 0;
            while s.poll_send().is_some() {
                n += 1;
            }
            if n > 0 {
                retransmits += 1;
                assert_eq!(n, initial, "retransmit resends the whole flight");
            }
            if s.phase() == PhaseName::Terminal {
                break;
            }
        }
        assert_eq!(retransmits, DTLS_RESEND_MAX, "retransmits={retransmits} phase={:?}", s.phase());
        // budget exhausted: next resend point fails the session
        s.advance(200_000_000 + 7 * 1_000_000_000);
        assert!(matches!(s.phase(), PhaseName::Terminal));
        let ev = s.poll_event();
        assert!(
            matches!(ev, Some(SessionEvent::Failed { stage: "dtls", .. })),
            "{ev:?}"
        );
    }
}
