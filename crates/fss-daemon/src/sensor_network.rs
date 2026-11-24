#![forbid(unsafe_code)]
//! Real pure-Rust single-session network camera drivers (`Rtsp`, `OnvifHttp`, `Tutk`,
//! `UniFiProtect`) for `SensorRegion`.
//!
//! Semantic plane: `"authority"`.
//!
//! # Honesty Invariant
//! This module NEVER fabricates synthetic or blank frames on network adapters. Every emitted
//! [`CameraFrame`] carries real encoded wire access units (H.264 Annex-B or JPEG bytes), their
//! exact SHA-256 digest, and real pure-Rust decoded pixels (`fss-codec-h264` or `fss-codec-mjpeg`).
//! Adapters whose session bootstrap credentials are not provisioned (`Tutk`, `UniFiProtect`) fail
//! closed with an explicit typed [`SensorDisconnectReason::DriverError`].

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fss_codec_h264::{Decoder as H264Decoder, DecoderLimits as H264DecoderLimits};
use fss_codec_mjpeg::color::{RgbDecodeLimits, decode_rgb};
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeError as JpegDecodeError};
use fss_core::{ContentDigest, SensorId, StreamId};
use fss_pack::MediaCodec;
use fss_packet::StreamKey;
use fss_packet::avc::{
    AvcAssemblyOutput, AvcAssemblyStep, AvcPictureGroup, AvcReceiveLimits, AvcReceivePoll,
};
use fss_reference::ingest::model_pool::FramePixelInput;
use fss_reference::rtsp::authentication::{DigestCredentials, DigestPolicy};
use fss_reference::rtsp::avc_client::AvcClientPoll;
use fss_reference::rtsp::avc_client::authenticated::DigestAvcPoll;
use fss_reference::rtsp::client::ClientConfig;
use fss_reference::rtsp::live_avc::automatic::{AutomaticAvcConnection, AutomaticAvcStep};
use fss_reference::rtsp::live_avc::{LiveAvcConfig, LiveAvcError, LiveAvcStep, SocketReadiness};
use fss_reference::rtsp::tcp::{
    TcpAuthority, TcpBinding, TcpDenial, TcpLimits, TcpOperation, TcpSecurityPolicy,
};
use fss_vault::{SecretBytes, SecretId};

use crate::manifest::{CameraAdapterKind, CameraManifestEntry};
use crate::sensor::{
    CameraFrame, SensorDisconnectReason, SensorDriver, SensorDriverEvent, sanitize_stream_segment,
};

const MAX_RTSP_POLL_STEPS_PER_TICK: usize = 32;
const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;
const MAX_HTTP_BUFFER_BYTES: usize = 8 * 1024 * 1024;
const HTTP_READ_CHUNK_BYTES: usize = 32 * 1024;
const MAX_HTTP_READ_CALLS_PER_TICK: usize = 16;
const RTSP_SESSION_LEASE_NS: u64 = 24 * 3_600 * 1_000_000_000;
const RTSP_MAX_STEPS: u64 = 100_000_000;

struct DaemonRtspAuthority {
    expected_peer: SocketAddr,
}

impl TcpAuthority for DaemonRtspAuthority {
    fn checkpoint(
        &self,
        binding: &TcpBinding,
        _operation: TcpOperation,
        now_ns: u64,
        deadline_ns: u64,
    ) -> Result<(), TcpDenial> {
        if binding.peer() != self.expected_peer {
            return Err(TcpDenial::Unauthorized);
        }
        if now_ns >= deadline_ns {
            return Err(TcpDenial::Deadline);
        }
        Ok(())
    }
}

struct RtspSessionState {
    conn: AutomaticAvcConnection,
    authority: DaemonRtspAuthority,
    decoder: H264Decoder,
    started: Instant,
    last_elapsed_ns: u64,
    sent_param_sets: bool,
}

struct HttpMjpegSessionState {
    stream: TcpStream,
    pending_request: Vec<u8>,
    write_offset: usize,
    headers_parsed: bool,
    single_image_mode: bool,
    eof_observed: bool,
    read_buf: Vec<u8>,
}

enum ActiveSession {
    Disconnected,
    Rtsp(Box<RtspSessionState>),
    HttpMjpeg(Box<HttpMjpegSessionState>),
}

/// Heterogeneous single-session network camera driver (`Rtsp`, `OnvifHttp`, `Tutk`, `UniFiProtect`).
///
/// Enforces strictly `<= 1` active upstream socket per camera, never logs plaintext credentials,
/// and never fabricates synthetic blank frames.
pub struct NetworkAdapterDriver {
    sensor_id: SensorId,
    adapter: CameraAdapterKind,
    endpoint: String,
    primary_zone: String,
    dimensions: [u32; 2],
    secret_id: Option<SecretId>,
    vault_username: Option<String>,
    vault_password: Option<SecretBytes>,
    generation: u64,
    sequence: u64,
    total_connections: u64,
    peer_addr: Option<SocketAddr>,
    stream_id: Option<StreamId>,
    session: ActiveSession,
    pending_frames: VecDeque<Arc<CameraFrame>>,
    step_counter: u64,
}

impl NetworkAdapterDriver {
    /// Creates a real single-session network adapter driver for a validated [`CameraManifestEntry`].
    #[must_use]
    pub fn new(entry: &CameraManifestEntry) -> Self {
        let peer_addr = parse_endpoint_socket_addr(&entry.endpoint, entry.adapter);
        Self {
            sensor_id: entry.sensor_id.clone(),
            adapter: entry.adapter,
            endpoint: entry.endpoint.clone(),
            primary_zone: entry.primary_zone.clone(),
            dimensions: entry.dimensions,
            secret_id: entry.secret_id.clone(),
            vault_username: None,
            vault_password: None,
            generation: 0,
            sequence: 0,
            total_connections: 0,
            peer_addr,
            stream_id: None,
            session: ActiveSession::Disconnected,
            pending_frames: VecDeque::new(),
            step_counter: 0,
        }
    }

    /// Attaches vault-resolved credentials (`SecretBytes`, zeroized on drop) for Digest/Basic auth.
    #[must_use]
    pub fn with_vault_credentials(
        mut self,
        username: impl Into<String>,
        password: SecretBytes,
    ) -> Self {
        self.vault_username = Some(username.into());
        self.vault_password = Some(password);
        self
    }

    /// Returns the non-secret configured endpoint descriptor.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Returns the optional non-secret vault handle identifier bound to this camera.
    #[must_use]
    pub const fn secret_id(&self) -> Option<&SecretId> {
        self.secret_id.as_ref()
    }

    fn connect_rtsp(
        &mut self,
        generation: u64,
        addr: SocketAddr,
    ) -> Result<(), SensorDisconnectReason> {
        let Some(authority_str) = extract_endpoint_authority(&self.endpoint) else {
            return Err(SensorDisconnectReason::DriverError(
                "invalid RTSP endpoint authority".to_owned(),
            ));
        };
        let control_root_uri = format!("rtsp://{authority_str}/");
        let stream_key = StreamKey {
            ingress: 1,
            generation: generation.max(1),
            ssrc: 0,
        };
        let binding = TcpBinding::new(
            stream_key,
            addr,
            &authority_str,
            TcpSecurityPolicy::OwnerApprovedPlaintext,
        )
        .map_err(|_| {
            SensorDisconnectReason::DriverError("invalid RTSP TCP route binding".to_owned())
        })?
        .with_auto_ssrc();

        let protocol = ClientConfig {
            presentation_uri: self.endpoint.clone(),
            control_root_uri,
            media_index: 0,
            channels: (0, 1),
            response_timeout_ns: 5_000_000_000,
            default_session_timeout_seconds: 60,
        };
        let transport = TcpLimits {
            connect_timeout_ns: 1_000_000_000,
            ..TcpLimits::default()
        };
        let config = LiveAvcConfig {
            protocol,
            binding,
            transport,
            media: AvcReceiveLimits::default(),
            realm: "fss".to_owned(),
            digest_policy: DigestPolicy {
                allow_legacy_md5: true,
                allow_legacy_no_qop: true,
            },
            deadline_ns: RTSP_SESSION_LEASE_NS,
            max_steps: RTSP_MAX_STEPS,
        };
        let authority = DaemonRtspAuthority {
            expected_peer: addr,
        };
        let conn =
            AutomaticAvcConnection::connect(config, 0, &authority).map_err(|err| {
                match err.reason {
                    LiveAvcError::Configuration => SensorDisconnectReason::DriverError(
                        "invalid RTSP live connection configuration".to_owned(),
                    ),
                    _ => SensorDisconnectReason::NetworkDrop,
                }
            })?;
        let decoder = H264Decoder::new(H264DecoderLimits::default()).map_err(|_| {
            SensorDisconnectReason::DriverError(
                "failed initializing pure-Rust H.264 decoder".to_owned(),
            )
        })?;
        self.session = ActiveSession::Rtsp(Box::new(RtspSessionState {
            conn,
            authority,
            decoder,
            started: Instant::now(),
            last_elapsed_ns: 0,
            sent_param_sets: false,
        }));
        Ok(())
    }

    fn connect_http_mjpeg(&mut self, addr: SocketAddr) -> Result<(), SensorDisconnectReason> {
        let stream = TcpStream::connect_timeout(&addr, Duration::from_millis(500))
            .map_err(|_| SensorDisconnectReason::NetworkDrop)?;
        stream
            .set_nonblocking(true)
            .map_err(|_| SensorDisconnectReason::NetworkDrop)?;

        let host_header =
            extract_endpoint_authority(&self.endpoint).unwrap_or_else(|| addr.to_string());
        let path_and_query = extract_endpoint_path_and_query(&self.endpoint);
        let mut req = format!(
            "GET {path_and_query} HTTP/1.1\r\nHost: {host_header}\r\nAccept: multipart/x-mixed-replace, image/jpeg\r\nConnection: keep-alive\r\n"
        );
        if let (Some(user), Some(pass)) = (&self.vault_username, &self.vault_password)
            && let Ok(pass_str) = std::str::from_utf8(pass.as_slice())
        {
            let encoded = encode_basic_auth(user, pass_str);
            req.push_str("Authorization: Basic ");
            req.push_str(&encoded);
            req.push_str("\r\n");
        }
        req.push_str("\r\n");

        let mut req_bytes = req.into_bytes();
        let mut write_offset = 0_usize;
        let mut stream = stream;
        while write_offset < req_bytes.len() {
            match stream.write(&req_bytes[write_offset..]) {
                Ok(0) => return Err(SensorDisconnectReason::NetworkDrop),
                Ok(n) => write_offset = write_offset.saturating_add(n),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Err(SensorDisconnectReason::NetworkDrop),
            }
        }
        if write_offset >= req_bytes.len() {
            req_bytes.clear();
            write_offset = 0;
        }

        self.session = ActiveSession::HttpMjpeg(Box::new(HttpMjpegSessionState {
            stream,
            pending_request: req_bytes,
            write_offset,
            headers_parsed: false,
            single_image_mode: false,
            eof_observed: false,
            read_buf: Vec::with_capacity(64 * 1024),
        }));
        Ok(())
    }

    fn poll_rtsp(&mut self, now_ns: i128) -> SensorDriverEvent {
        let has_creds = self.vault_username.is_some() && self.vault_password.is_some();
        let (user_str, pass_str) = match (&self.vault_username, &self.vault_password) {
            (Some(u), Some(p)) => (u.as_str(), std::str::from_utf8(p.as_slice()).unwrap_or("")),
            _ => ("unauthenticated", ""),
        };
        let Ok(creds) = DigestCredentials::new(user_str, pass_str) else {
            self.disconnect();
            return SensorDriverEvent::Disconnected(SensorDisconnectReason::AuthFailure);
        };

        let mut extracted_groups: Vec<AvcPictureGroup> = Vec::new();
        let mut disconnect_reason: Option<SensorDisconnectReason> = None;

        if let ActiveSession::Rtsp(state) = &mut self.session {
            for _ in 0..MAX_RTSP_POLL_STEPS_PER_TICK {
                let raw_elapsed =
                    u64::try_from(state.started.elapsed().as_nanos()).unwrap_or(u64::MAX / 2);
                let elapsed_ns = raw_elapsed.max(state.last_elapsed_ns);
                state.last_elapsed_ns = elapsed_ns;

                self.step_counter = self.step_counter.saturating_add(1);
                let cnonce = derive_cnonce(
                    self.sensor_id.as_str(),
                    self.generation,
                    self.step_counter,
                    now_ns,
                );

                match state.conn.poll(
                    SocketReadiness {
                        readable: true,
                        writable: true,
                    },
                    &creds,
                    cnonce,
                    elapsed_ns,
                    &state.authority,
                ) {
                    Ok(AutomaticAvcStep::Queued(_)) => {}
                    Ok(AutomaticAvcStep::Live(LiveAvcStep::Wire(_)))
                    | Ok(AutomaticAvcStep::Live(LiveAvcStep::Write(_))) => {}
                    Ok(AutomaticAvcStep::Live(LiveAvcStep::Pending(_))) => break,
                    Ok(AutomaticAvcStep::Live(LiveAvcStep::InputEnded | LiveAvcStep::Ended)) => {
                        disconnect_reason = Some(SensorDisconnectReason::NetworkDrop);
                        break;
                    }
                    Ok(AutomaticAvcStep::Live(LiveAvcStep::Protocol { event, transport })) => {
                        match event {
                            DigestAvcPoll::AuthenticationRequired { .. } => {
                                if !has_creds {
                                    disconnect_reason = Some(SensorDisconnectReason::AuthFailure);
                                    break;
                                }
                            }
                            DigestAvcPoll::Fault { .. } => {
                                disconnect_reason = Some(SensorDisconnectReason::AuthFailure);
                                break;
                            }
                            DigestAvcPoll::Client { event, .. } => match *event {
                                AvcClientPoll::Media(AvcReceivePoll::Picture(pic)) => {
                                    extracted_groups.push(pic);
                                    break;
                                }
                                AvcClientPoll::Media(AvcReceivePoll::Assembly(
                                    AvcAssemblyStep::Accepted(AvcAssemblyOutput {
                                        picture: Some(pic),
                                        ..
                                    }),
                                )) => {
                                    extracted_groups.push(pic);
                                    break;
                                }
                                AvcClientPoll::Media(AvcReceivePoll::Ended { .. })
                                | AvcClientPoll::Ended { .. }
                                | AvcClientPoll::Fault { .. } => {
                                    disconnect_reason = Some(SensorDisconnectReason::NetworkDrop);
                                    break;
                                }
                                _ => {}
                            },
                        }
                        if transport.is_some() {
                            disconnect_reason = Some(SensorDisconnectReason::NetworkDrop);
                            break;
                        }
                    }
                    Err(failure) => {
                        disconnect_reason = Some(match failure.reason {
                            LiveAvcError::Protocol(_) => SensorDisconnectReason::AuthFailure,
                            _ => SensorDisconnectReason::NetworkDrop,
                        });
                        break;
                    }
                }
            }
        }

        if let Some(reason) = disconnect_reason {
            self.disconnect();
            return SensorDriverEvent::Disconnected(reason);
        }

        for group in extracted_groups {
            self.decode_rtsp_picture_group(group, now_ns);
        }

        if let Some(frame) = self.pending_frames.pop_front() {
            SensorDriverEvent::Frame(frame)
        } else {
            SensorDriverEvent::Idle
        }
    }

    fn decode_rtsp_picture_group(&mut self, group: AvcPictureGroup, now_ns: i128) {
        let Some(stream_id) = self.stream_id.clone() else {
            return;
        };
        let ActiveSession::Rtsp(state) = &mut self.session else {
            return;
        };

        let contains_idr = group.nals().iter().any(|n| n.nal_type() == 5);
        let mut annex_b = Vec::with_capacity(group.byte_len().saturating_add(128));
        if !state.sent_param_sets || contains_idr {
            annex_b.extend_from_slice(&[0, 0, 0, 1]);
            annex_b.extend_from_slice(group.sps().nal_bytes());
            annex_b.extend_from_slice(&[0, 0, 0, 1]);
            annex_b.extend_from_slice(group.pps().nal_bytes());
            state.sent_param_sets = true;
        }
        for nal in group.nals() {
            annex_b.extend_from_slice(&[0, 0, 0, 1]);
            annex_b.extend_from_slice(nal.bytes());
        }

        let Ok(pictures) = state.decoder.decode_annex_b(&annex_b) else {
            return;
        };
        let source_digest = ContentDigest::sha256(&annex_b);
        let media_pts_ns = (i128::from(group.timestamp()).saturating_mul(1_000_000_000)) / 90_000;
        let discontinuity = group.discontinuity_before();

        for pic in pictures {
            self.sequence = self.sequence.saturating_add(1);
            let dims = [pic.width(), pic.height()];
            self.dimensions = dims;
            self.pending_frames.push_back(Arc::new(CameraFrame {
                sensor_id: self.sensor_id.clone(),
                stream_generation: self.generation,
                stream_id: stream_id.clone(),
                sequence: self.sequence,
                media_pts_ns,
                host_receive_ns: now_ns,
                rtt_jitter_ns: 10_000_000,
                node_clock_uncertainty_ns: 2_000_000,
                codec: MediaCodec::H264,
                is_keyframe: pic.is_idr(),
                discontinuity_before: discontinuity || (self.generation > 1 && self.sequence == 1),
                dimensions: dims,
                encoded_payload: annex_b.clone(),
                pixels: FramePixelInput::Luma {
                    pixels: pic.luma().to_vec(),
                },
                source_digest,
                zone_id: self.primary_zone.clone(),
                synthetic_detections: Vec::new(),
            }));
        }
    }

    fn poll_http_mjpeg(&mut self, now_ns: i128) -> SensorDriverEvent {
        let Some(stream_id) = self.stream_id.clone() else {
            self.disconnect();
            return SensorDriverEvent::Disconnected(SensorDisconnectReason::NetworkDrop);
        };

        let mut extracted_jpeg: Option<Vec<u8>> = None;
        let mut disconnect_reason: Option<SensorDisconnectReason> = None;

        if let ActiveSession::HttpMjpeg(state) = &mut self.session {
            // 1. Flush any unsent HTTP GET request bytes non-blockingly.
            while state.write_offset < state.pending_request.len() {
                match state
                    .stream
                    .write(&state.pending_request[state.write_offset..])
                {
                    Ok(0) => {
                        disconnect_reason = Some(SensorDisconnectReason::NetworkDrop);
                        break;
                    }
                    Ok(n) => state.write_offset = state.write_offset.saturating_add(n),
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => {
                        disconnect_reason = Some(SensorDisconnectReason::NetworkDrop);
                        break;
                    }
                }
            }

            // 2. Read available bytes into the bounded buffer.
            if disconnect_reason.is_none() && !state.eof_observed {
                let mut tmp = [0_u8; HTTP_READ_CHUNK_BYTES];
                for _ in 0..MAX_HTTP_READ_CALLS_PER_TICK {
                    if state.read_buf.len() >= MAX_HTTP_BUFFER_BYTES {
                        break;
                    }
                    match state.stream.read(&mut tmp) {
                        Ok(0) => {
                            state.eof_observed = true;
                            break;
                        }
                        Ok(n) => {
                            let allowed =
                                MAX_HTTP_BUFFER_BYTES.saturating_sub(state.read_buf.len());
                            let take = n.min(allowed);
                            state.read_buf.extend_from_slice(&tmp[..take]);
                        }
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                        Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                        Err(_) => {
                            disconnect_reason = Some(SensorDisconnectReason::NetworkDrop);
                            break;
                        }
                    }
                }
            }

            // 3. Parse HTTP response headers once.
            if disconnect_reason.is_none() && !state.headers_parsed {
                if let Some(header_end) = find_subsequence(&state.read_buf, b"\r\n\r\n") {
                    let header_bytes = &state.read_buf[..header_end];
                    match parse_http_response_headers(header_bytes) {
                        Ok(HttpHeaderOutcome::Ok { is_single_jpeg }) => {
                            state.headers_parsed = true;
                            state.single_image_mode = is_single_jpeg;
                            state.read_buf.drain(..header_end + 4);
                        }
                        Ok(HttpHeaderOutcome::Unauthorized) => {
                            disconnect_reason = Some(SensorDisconnectReason::AuthFailure);
                        }
                        Ok(HttpHeaderOutcome::BadStatus(code)) => {
                            disconnect_reason = Some(SensorDisconnectReason::DriverError(format!(
                                "http endpoint returned status {code}"
                            )));
                        }
                        Err(reason) => {
                            disconnect_reason = Some(SensorDisconnectReason::DriverError(reason));
                        }
                    }
                } else if state.read_buf.len() > MAX_HTTP_HEADER_BYTES {
                    disconnect_reason = Some(SensorDisconnectReason::DriverError(
                        "HTTP response header exceeded 16 KiB bound".to_owned(),
                    ));
                } else if state.eof_observed {
                    disconnect_reason = Some(SensorDisconnectReason::NetworkDrop);
                }
            }

            // 4. Extract one complete JPEG frame (`FF D8 .. FF D9`) from the body.
            if disconnect_reason.is_none() && state.headers_parsed {
                if let Some(jpeg) = extract_next_jpeg_frame(&mut state.read_buf) {
                    extracted_jpeg = Some(jpeg);
                } else if state.eof_observed {
                    disconnect_reason = Some(SensorDisconnectReason::NetworkDrop);
                } else if state.read_buf.len() >= MAX_HTTP_BUFFER_BYTES {
                    disconnect_reason = Some(SensorDisconnectReason::DriverError(
                        "HTTP MJPEG stream exceeded 8 MiB buffer bound without valid JPEG frame"
                            .to_owned(),
                    ));
                }
            }
        }

        if let Some(jpeg_bytes) = extracted_jpeg {
            let source_digest = ContentDigest::sha256(&jpeg_bytes);
            let rgb_limits = RgbDecodeLimits::default();
            let mut budget = DecodeBudget::new(rgb_limits.rgb_work_bound());
            let decoded = match decode_rgb(
                &jpeg_bytes,
                source_digest.bytes(),
                ComponentInterpretation::YCbCr,
                rgb_limits,
                &mut budget,
            ) {
                Ok(img) => Ok(img),
                Err(JpegDecodeError::Unsupported) => {
                    let mut gray_budget = DecodeBudget::new(rgb_limits.rgb_work_bound());
                    decode_rgb(
                        &jpeg_bytes,
                        source_digest.bytes(),
                        ComponentInterpretation::Grayscale,
                        rgb_limits,
                        &mut gray_budget,
                    )
                }
                Err(err) => Err(err),
            };
            match decoded {
                Ok(img) => {
                    self.sequence = self.sequence.saturating_add(1);
                    let dims = img.dimensions();
                    self.dimensions = dims;
                    let frame = Arc::new(CameraFrame {
                        sensor_id: self.sensor_id.clone(),
                        stream_generation: self.generation,
                        stream_id,
                        sequence: self.sequence,
                        media_pts_ns: now_ns,
                        host_receive_ns: now_ns,
                        rtt_jitter_ns: 10_000_000,
                        node_clock_uncertainty_ns: 2_000_000,
                        codec: MediaCodec::Mjpeg,
                        is_keyframe: true,
                        discontinuity_before: self.generation > 1 && self.sequence == 1,
                        dimensions: dims,
                        encoded_payload: jpeg_bytes,
                        pixels: FramePixelInput::Rgb {
                            pixels: img.pixels().to_vec(),
                        },
                        source_digest,
                        zone_id: self.primary_zone.clone(),
                        synthetic_detections: Vec::new(),
                    });
                    if let ActiveSession::HttpMjpeg(state) = &self.session
                        && state.single_image_mode
                        && state.eof_observed
                    {
                        self.disconnect();
                    }
                    return SensorDriverEvent::Frame(frame);
                }
                Err(err) => {
                    self.disconnect();
                    return SensorDriverEvent::Disconnected(SensorDisconnectReason::DriverError(
                        format!("pure-Rust JPEG decode failed: {err}"),
                    ));
                }
            }
        }

        if let Some(reason) = disconnect_reason {
            self.disconnect();
            return SensorDriverEvent::Disconnected(reason);
        }

        SensorDriverEvent::Idle
    }
}

impl SensorDriver for NetworkAdapterDriver {
    fn connect(&mut self, generation: u64) -> Result<(), SensorDisconnectReason> {
        if !matches!(self.session, ActiveSession::Disconnected) {
            self.disconnect();
        }
        let stream_name = format!(
            "stream:{}:g{generation}",
            sanitize_stream_segment(self.sensor_id.as_str())
        );
        let stream_id = StreamId::parse(stream_name).map_err(|_| {
            SensorDisconnectReason::DriverError(
                "failed constructing canonical stream id".to_owned(),
            )
        })?;
        let Some(addr) = self.peer_addr else {
            return Err(SensorDisconnectReason::NetworkDrop);
        };

        match self.adapter {
            CameraAdapterKind::Rtsp => {
                self.connect_rtsp(generation, addr)?;
            }
            CameraAdapterKind::OnvifHttp => {
                self.connect_http_mjpeg(addr)?;
            }
            CameraAdapterKind::Tutk => {
                return Err(SensorDisconnectReason::DriverError(
                    "TUTK P2P adapter requires device enrollment/DTLS session driver (refusing to emit synthetic frames)".to_owned(),
                ));
            }
            CameraAdapterKind::UniFiProtect => {
                return Err(SensorDisconnectReason::DriverError(
                    "UniFi Protect adapter requires TLS controller bootstrap session (use native RTSP endpoint or custom driver; refusing to emit synthetic frames)".to_owned(),
                ));
            }
            CameraAdapterKind::Synthetic => {
                return Err(SensorDisconnectReason::DriverError(
                    "synthetic cameras must use SyntheticCameraDriver".to_owned(),
                ));
            }
        }

        self.stream_id = Some(stream_id);
        self.generation = generation;
        self.sequence = 0;
        self.pending_frames.clear();
        self.total_connections = self.total_connections.saturating_add(1);
        Ok(())
    }

    fn poll_frame(&mut self, now_ns: i128) -> SensorDriverEvent {
        if let Some(frame) = self.pending_frames.pop_front() {
            return SensorDriverEvent::Frame(frame);
        }
        match self.session {
            ActiveSession::Disconnected => {
                SensorDriverEvent::Disconnected(SensorDisconnectReason::NetworkDrop)
            }
            ActiveSession::Rtsp(_) => self.poll_rtsp(now_ns),
            ActiveSession::HttpMjpeg(_) => self.poll_http_mjpeg(now_ns),
        }
    }

    fn disconnect(&mut self) {
        if let ActiveSession::Rtsp(mut state) =
            std::mem::replace(&mut self.session, ActiveSession::Disconnected)
        {
            let _ = state.conn.cancel();
        }
        self.pending_frames.clear();
    }

    fn active_session_count(&self) -> u32 {
        u32::from(!matches!(self.session, ActiveSession::Disconnected))
    }

    fn total_connections(&self) -> u64 {
        self.total_connections
    }

    fn adapter_kind(&self) -> CameraAdapterKind {
        self.adapter
    }
}

enum HttpHeaderOutcome {
    Ok { is_single_jpeg: bool },
    Unauthorized,
    BadStatus(u16),
}

fn parse_http_response_headers(raw: &[u8]) -> Result<HttpHeaderOutcome, String> {
    let text = std::str::from_utf8(raw).map_err(|_| "non-UTF-8 HTTP response header".to_owned())?;
    let mut lines = text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| "empty HTTP response".to_owned())?;
    let mut parts = status_line.split_whitespace();
    let proto = parts
        .next()
        .ok_or_else(|| "missing HTTP version".to_owned())?;
    if !proto.starts_with("HTTP/1.") {
        return Err("unsupported HTTP response version".to_owned());
    }
    let code: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "malformed HTTP status code".to_owned())?;
    if code == 401 || code == 403 {
        return Ok(HttpHeaderOutcome::Unauthorized);
    }
    if code != 200 {
        return Ok(HttpHeaderOutcome::BadStatus(code));
    }
    let mut is_single_jpeg = false;
    for line in lines {
        if let Some((name, val)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("content-type")
        {
            let lower = val.trim().to_ascii_lowercase();
            if lower.starts_with("image/jpeg") {
                is_single_jpeg = true;
            }
        }
    }
    Ok(HttpHeaderOutcome::Ok { is_single_jpeg })
}

fn extract_next_jpeg_frame(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    let soi = find_subsequence(buf, &[0xFF, 0xD8])?;
    if soi > 0 {
        buf.drain(..soi);
    }
    // Walk JPEG marker segments so embedded APP/EXIF thumbnails (`FF D9` inside a segment)
    // never prematurely truncate the outer camera frame.
    let mut pos = 2_usize;
    let mut in_scan = false;
    while pos + 1 < buf.len() {
        if in_scan {
            if buf[pos] != 0xFF {
                pos += 1;
                continue;
            }
            // Skip fill bytes (`FF FF ...`).
            let mut mpos = pos + 1;
            while mpos < buf.len() && buf[mpos] == 0xFF {
                mpos += 1;
            }
            if mpos >= buf.len() {
                return None;
            }
            let marker = buf[mpos];
            if marker == 0x00 || (0xD0..=0xD7).contains(&marker) {
                // Byte-stuffed 0xFF or RSTn restart marker inside entropy scan.
                pos = mpos + 1;
                continue;
            }
            if marker == 0xD9 {
                let frame_end = mpos + 1;
                let frame = buf[..frame_end].to_vec();
                buf.drain(..frame_end);
                return Some(frame);
            }
            // Another marker (e.g., progressive multi-scan DHT/SOS) resumes marker parsing.
            in_scan = false;
            pos = mpos - 1;
            continue;
        }

        if buf[pos] != 0xFF {
            pos += 1;
            continue;
        }
        let mut mpos = pos + 1;
        while mpos < buf.len() && buf[mpos] == 0xFF {
            mpos += 1;
        }
        if mpos >= buf.len() {
            return None;
        }
        let marker = buf[mpos];
        if marker == 0xD9 {
            let frame_end = mpos + 1;
            let frame = buf[..frame_end].to_vec();
            buf.drain(..frame_end);
            return Some(frame);
        }
        if marker == 0x00 || marker == 0x01 || (0xD0..=0xD8).contains(&marker) {
            pos = mpos + 1;
            continue;
        }
        // Length-prefixed marker segment: 2-byte big-endian length includes itself (>= 2).
        if mpos + 2 >= buf.len() {
            return None;
        }
        let seg_len = usize::from(u16::from_be_bytes([buf[mpos + 1], buf[mpos + 2]]));
        if seg_len < 2 {
            // Corrupt segment length: discard SOI so next scan advances cleanly.
            buf.drain(..2);
            return None;
        }
        let next_pos = mpos + 1 + seg_len;
        if next_pos > buf.len() {
            return None;
        }
        pos = next_pos;
        if marker == 0xDA {
            in_scan = true;
        }
    }
    None
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn extract_endpoint_authority(endpoint: &str) -> Option<String> {
    let rest = endpoint.split_once("://").map_or(endpoint, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty() {
        None
    } else {
        Some(authority.to_owned())
    }
}

fn extract_endpoint_path_and_query(endpoint: &str) -> String {
    let rest = endpoint.split_once("://").map_or(endpoint, |(_, r)| r);
    match rest.find('/') {
        Some(pos) => {
            let tail = &rest[pos..];
            tail.split('#').next().unwrap_or("/").to_owned()
        }
        None => "/".to_owned(),
    }
}

fn parse_endpoint_socket_addr(endpoint: &str, adapter: CameraAdapterKind) -> Option<SocketAddr> {
    let rest = endpoint.split_once("://").map_or(endpoint, |(_, r)| r);
    let host_port = rest.split(['/', '?', '#']).next()?;
    if let Ok(addr) = host_port.parse::<SocketAddr>() {
        return Some(addr);
    }
    let default_port = match adapter {
        CameraAdapterKind::Rtsp => 554,
        CameraAdapterKind::OnvifHttp => 80,
        CameraAdapterKind::UniFiProtect => 7441,
        CameraAdapterKind::Tutk => 32100,
        CameraAdapterKind::Synthetic => return None,
    };
    format!("{host_port}:{default_port}")
        .parse::<SocketAddr>()
        .ok()
}

fn derive_cnonce(sensor_id: &str, generation: u64, step: u64, now_ns: i128) -> [u8; 16] {
    let mut input = Vec::with_capacity(sensor_id.len() + 32);
    input.extend_from_slice(b"fss.daemon.rtsp.cnonce:");
    input.extend_from_slice(sensor_id.as_bytes());
    input.extend_from_slice(&generation.to_be_bytes());
    input.extend_from_slice(&step.to_be_bytes());
    input.extend_from_slice(&now_ns.to_be_bytes());
    let digest = ContentDigest::sha256(&input);
    let mut out = [0_u8; 16];
    out.copy_from_slice(&digest.bytes()[..16]);
    out
}

fn encode_basic_auth(username: &str, password: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut raw = Vec::with_capacity(username.len() + password.len() + 1);
    raw.extend_from_slice(username.as_bytes());
    raw.push(b':');
    raw.extend_from_slice(password.as_bytes());
    let mut out = String::with_capacity(raw.len().div_ceil(3) * 4);
    let mut idx = 0;
    while idx < raw.len() {
        let b0 = raw[idx];
        let b1 = if idx + 1 < raw.len() { raw[idx + 1] } else { 0 };
        let b2 = if idx + 2 < raw.len() { raw[idx + 2] } else { 0 };
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        if idx + 1 < raw.len() {
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if idx + 2 < raw.len() {
            out.push(TABLE[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
        idx += 3;
    }
    // Zeroize temporary raw credential buffer before dropping.
    raw.fill(0);
    out
}
