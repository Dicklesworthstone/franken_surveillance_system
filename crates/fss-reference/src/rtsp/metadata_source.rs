#![forbid(unsafe_code)]
//! Bounded native metadata source witness, independent of XML interpretation.
//!
//! Original SDP and complete interleaved frames are retained. Control responses
//! contribute hashes and typed observations; their raw headers, authentication
//! challenges and session tokens are not retained here. This is not a complete
//! TCP transcript or a camera authenticity/coverage certificate. The rtpdump view
//! is an explicitly derived millisecond replay; original nanosecond observations
//! remain in this separately identified canonical source.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, ContractError, DigestAlgorithm};
use fss_packet::StreamKey;

use super::client::{
    ClientCodec, ClientCommand, ClientConfig, ClientProgress, ClientState, RtspClientSession,
};
use super::framed::RtspWireFrame;
use super::tcp::{TcpBinding, TcpSecurityPolicy};
use super::{RtspEvent, RtspHeaders, RtspResponse};

/// Distinct from both owner-file rtpdump and XML import source identities.
pub const SOURCE_DOMAIN: &str = "fss.onvif_native_rtsp_metadata_source.v1";
/// Maximum complete canonical source, including its bounded metadata and checksum.
pub const MAX_SOURCE_BYTES: usize = 8 * 1024 * 1024;
/// Maximum retained complete interleaved frames in one finite acquisition.
pub const MAX_RECORDS: usize = 16_384;
/// Independent control-response ceiling, so small packet budgets permit negotiation.
pub const MAX_CONTROLS: usize = 1024;
const MAGIC: &[u8] = b"FSSONMS1";
const MAX_DESCRIPTION: usize = 65_536;
const MAX_FRAME: usize = 65_535 + 4;
const CHECKSUM_BYTES: usize = 33;
const RTPDUMP_HEADER: &[u8] = b"#!rtpplay1.0 fss-native-metadata/0\n";

/// Explicit finite acquisition scope; these bytes grant no network or storage authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeMetadataConfig {
    /// Immutable owner approval, independently checked by the native effect owner.
    pub approval: ContentDigest,
    /// Exact presentation, control subtree, media ordinal and interleaved channel pair.
    pub protocol: ClientConfig,
    /// Exact address/authority/stream generation and explicit plaintext policy.
    pub binding: TcpBinding,
    /// Owner-pinned uncompressed ONVIF dynamic payload type.
    pub payload_type: u8,
    /// Owner receive-clock value at monotonic zero; origin + local ns is never camera capture time.
    pub receive_origin_ns: i128,
    /// First monotonic local observation in this finite attempt.
    pub started_ns: u64,
    /// Complete canonical byte budget, at most MAX_SOURCE_BYTES.
    pub max_source_bytes: usize,
    /// Complete interleaved frame budget, at most MAX_RECORDS.
    pub max_records: usize,
}

impl NativeMetadataConfig {
    /// Pure scope validation using the real session and native route contracts.
    pub fn validate(&self) -> Result<(), NativeMetadataSourceError> {
        if self.approval.algorithm() != DigestAlgorithm::Sha256
            || self.approval.is_laboratory()
            || !(1..=MAX_SOURCE_BYTES).contains(&self.max_source_bytes)
            || !(1..=MAX_RECORDS).contains(&self.max_records)
            || self.protocol.presentation_uri.len() > 2048
            || self.protocol.control_root_uri.len() > 2048
            || authority(&self.protocol.presentation_uri) != Some(self.binding.authority())
            || authority(&self.protocol.control_root_uri) != Some(self.binding.authority())
        {
            return Err(NativeMetadataSourceError::Configuration);
        }
        self.receive_origin_ns
            .checked_add(i128::from(self.started_ns))
            .ok_or(NativeMetadataSourceError::Clock)?;
        RtspClientSession::with_codec_and_payload_type(
            self.protocol.clone(),
            ClientCodec::OnvifMetadata,
            self.payload_type,
        )
        .map_err(|_| NativeMetadataSourceError::Configuration)?;
        Ok(())
    }
}

/// Fixed terminal vocabulary; camera-controlled strings can never become stop codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeMetadataStop {
    /// The explicitly approved finite target was reached.
    TargetReached,
    /// The native peer reached EOF; pending media remains independently classified.
    Eof,
    /// Source, record, socket-work or output budget was exhausted.
    InputLimit,
    /// An owner, request, session or media deadline ended the attempt.
    Timeout,
    /// RTSP, framing, source binding or packet semantics refused progress.
    Protocol,
    /// Authentication policy refused progress.
    Authentication,
    /// A live authority checkpoint refused or revoked the attempt.
    Authority,
    /// Source publication failed; this witness does not assert durable storage.
    Storage,
    /// The owner cancelled finite acquisition.
    Cancelled,
    /// Native transport failed without clean EOF.
    Transport,
    /// A retained prefix while the live attempt continues; never a completed capture.
    Checkpoint,
}
impl NativeMetadataStop {
    /// Stable machine-readable code, without any server text.
    pub const fn code(self) -> &'static str {
        match self {
            Self::TargetReached => "target_reached",
            Self::Eof => "eof",
            Self::InputLimit => "input_limit",
            Self::Timeout => "timeout",
            Self::Protocol => "protocol",
            Self::Authentication => "authentication",
            Self::Authority => "authority",
            Self::Storage => "storage",
            Self::Cancelled => "cancelled",
            Self::Transport => "transport",
            Self::Checkpoint => "checkpoint",
        }
    }
    fn tag(self) -> u8 {
        match self {
            Self::TargetReached => 1,
            Self::Eof => 2,
            Self::InputLimit => 3,
            Self::Timeout => 4,
            Self::Protocol => 5,
            Self::Authentication => 6,
            Self::Authority => 7,
            Self::Storage => 8,
            Self::Cancelled => 9,
            Self::Transport => 10,
            Self::Checkpoint => 11,
        }
    }
    fn decode(tag: u8) -> Result<Self, NativeMetadataSourceError> {
        Ok(match tag {
            1 => Self::TargetReached,
            2 => Self::Eof,
            3 => Self::InputLimit,
            4 => Self::Timeout,
            5 => Self::Protocol,
            6 => Self::Authentication,
            7 => Self::Authority,
            8 => Self::Storage,
            9 => Self::Cancelled,
            10 => Self::Transport,
            11 => Self::Checkpoint,
            _ => return Err(NativeMetadataSourceError::Canonical),
        })
    }
}

/// Payload-free source-owner refusal. The previously retained prefix remains owned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeMetadataSourceError {
    /// Invalid approval, route, stream, scope or finite budget.
    Configuration,
    /// Wrong source kind, already finished, or admission stopped after source omission.
    State,
    /// Receive/end observation reversed or falls outside the finite acquisition interval.
    Clock,
    /// Invalid control observation or inconsistent protocol progress history.
    Control,
    /// Selected SDP or its control URI resolution violates the existing session contract.
    Description,
    /// The complete canonical source or observation count cannot fit its fixed budget.
    Limit,
    /// Bounded allocation failed before the new observation could be retained.
    Allocation,
    /// Unknown, corrupt, noncanonical or incompatible durable bytes.
    Canonical,
    /// A derived replay cannot fit its independently bounded output.
    Projection,
    /// A fixed-width count or byte calculation cannot be represented.
    Exhausted,
}
impl fmt::Display for NativeMetadataSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "native metadata source refusal: {self:?}")
    }
}
impl std::error::Error for NativeMetadataSourceError {}
impl From<ContractError> for NativeMetadataSourceError {
    fn from(_: ContractError) -> Self {
        Self::Canonical
    }
}

/// Original accepted SDP and the bounded base/location inputs to its URI decision.
#[derive(Clone, Eq, PartialEq)]
pub struct NativeMetadataDescription {
    ordinal: u32,
    received_ns: u64,
    bytes: Vec<u8>,
    content_base: Option<String>,
    content_location: Option<String>,
}
impl NativeMetadataDescription {
    /// Original DESCRIBE body, not its payload-selection projection.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Global observation ordinal of the matching accepted DESCRIBE response.
    pub fn ordinal(&self) -> u32 {
        self.ordinal
    }
    /// Final original body-byte receipt observation.
    pub fn received_ns(&self) -> u64 {
        self.received_ns
    }
}
impl fmt::Debug for NativeMetadataDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeMetadataDescription")
            .field("ordinal", &self.ordinal)
            .field("received_ns", &self.received_ns)
            .field("byte_len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// Hash-only control observation. No raw authentication/session headers are stored.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeMetadataControl {
    ordinal: u32,
    received_ns: u64,
    status: u16,
    cseq: Option<u32>,
    progress: Option<ClientProgress>,
    wire_bytes: usize,
    wire_digest: ContentDigest,
}
impl NativeMetadataControl {
    /// Global source observation order, shared with original interleaved frames.
    pub fn ordinal(&self) -> u32 {
        self.ordinal
    }
    /// Original response final-byte observation.
    pub fn received_ns(&self) -> u64 {
        self.received_ns
    }
    /// Original numeric response status, never a server reason string.
    pub fn status(&self) -> u16 {
        self.status
    }
    /// Parsed correlation when present and valid.
    pub fn cseq(&self) -> Option<u32> {
        self.cseq
    }
    /// Actual accepted progress, or None for an explicitly observed rejected/challenge response.
    pub fn progress(&self) -> Option<ClientProgress> {
        self.progress
    }
    /// Original complete response byte length.
    pub fn wire_bytes(&self) -> usize {
        self.wire_bytes
    }
    /// SHA-256 of exact original response bytes; the bytes are deliberately not copied here.
    pub fn wire_digest(&self) -> ContentDigest {
        self.wire_digest
    }
}

/// Exact reason an original frame can or cannot appear in the derived rtpdump.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeMetadataProjection {
    /// Selected RTP channel with representable original length/time.
    Rtp,
    /// Selected RTCP channel with representable original length/time.
    Rtcp,
    /// Original unknown channel retained; never reclassified as selected RTP.
    WrongChannel,
    /// Original datagram exceeds the rtpdump 16-bit record-length limit.
    PacketTooLarge,
    /// Millisecond offset cannot fit the frozen rtpdump u32 field.
    TimeOverflow,
    /// A zero-byte RTP record cannot use rtpdump's zero plen RTCP discriminator.
    EmptyRtp,
}

/// One exact original complete interleaved frame. Debug excludes all payload bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct NativeMetadataRecord {
    ordinal: u32,
    received_ns: u64,
    wire: Vec<u8>,
}
impl NativeMetadataRecord {
    /// Global source observation order.
    pub fn ordinal(&self) -> u32 {
        self.ordinal
    }
    /// Original final-byte receipt, without millisecond rounding.
    pub fn received_ns(&self) -> u64 {
        self.received_ns
    }
    /// Exact original interleaved channel, including refused channels.
    pub fn channel(&self) -> u8 {
        self.wire[1]
    }
    /// Exact original datagram, excluding only the four-byte interleaved envelope.
    pub fn bytes(&self) -> &[u8] {
        &self.wire[4..]
    }
    /// Exact original interleaved envelope and datagram together.
    pub fn expose_wire(&self) -> &[u8] {
        &self.wire
    }
    /// Deterministic projection classification under the source's pinned configuration.
    pub fn projection(&self, config: &NativeMetadataConfig) -> NativeMetadataProjection {
        if self.channel() != config.protocol.channels.0
            && self.channel() != config.protocol.channels.1
        {
            return NativeMetadataProjection::WrongChannel;
        }
        if self.bytes().len() > 65_527 {
            return NativeMetadataProjection::PacketTooLarge;
        }
        if self.received_ns < config.started_ns
            || (self.received_ns - config.started_ns) / 1_000_000 > u64::from(u32::MAX)
        {
            return NativeMetadataProjection::TimeOverflow;
        }
        if self.channel() == config.protocol.channels.1 {
            NativeMetadataProjection::Rtcp
        } else if self.bytes().is_empty() {
            NativeMetadataProjection::EmptyRtp
        } else {
            NativeMetadataProjection::Rtp
        }
    }
}
impl fmt::Debug for NativeMetadataRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeMetadataRecord")
            .field("ordinal", &self.ordinal)
            .field("received_ns", &self.received_ns)
            .field("channel", &self.channel())
            .field("byte_len", &self.bytes().len())
            .finish_non_exhaustive()
    }
}

/// Finite original-frame source plus exact scope, timestamps and typed control history.
#[derive(Clone)]
pub struct NativeMetadataSource {
    config: NativeMetadataConfig,
    description: Option<NativeMetadataDescription>,
    controls: Vec<NativeMetadataControl>,
    records: Vec<NativeMetadataRecord>,
    ended_ns: Option<u64>,
    stop: Option<NativeMetadataStop>,
    omitted_observations: u64,
    omitted_bytes: u64,
    omitted_received_ns: u64,
    unprocessed_wire_bytes: u64,
    retained_bytes: usize,
    last_received_ns: u64,
    state: ClientState,
}
impl fmt::Debug for NativeMetadataSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeMetadataSource")
            .field("config", &self.config)
            .field("controls", &self.controls.len())
            .field("records", &self.records.len())
            .field("stop", &self.stop)
            .field("source_bytes", &self.retained_bytes)
            .field("omitted_observations", &self.omitted_observations)
            .finish_non_exhaustive()
    }
}

impl NativeMetadataSource {
    /// Freeze scope and byte/record ceilings before observing source bytes.
    pub fn new(config: NativeMetadataConfig) -> Result<Self, NativeMetadataSourceError> {
        config.validate()?;
        let mut source = Self {
            last_received_ns: config.started_ns,
            omitted_received_ns: config.started_ns,
            config,
            description: None,
            controls: Vec::new(),
            records: Vec::new(),
            ended_ns: None,
            stop: None,
            omitted_observations: 0,
            omitted_bytes: 0,
            unprocessed_wire_bytes: 0,
            retained_bytes: 0,
            state: ClientState::Idle,
        };
        source.retained_bytes = source
            .encode_body(source.config.started_ns, NativeMetadataStop::Checkpoint)?
            .len()
            + CHECKSUM_BYTES;
        if source.retained_bytes > source.config.max_source_bytes {
            return Err(NativeMetadataSourceError::Limit);
        }
        Ok(source)
    }

    /// Retain hash/typed progress of a response already accepted by the real session.
    /// A DESCRIBE acceptance also retains and independently validates its original SDP.
    pub fn observe_control(
        &mut self,
        progress: &ClientProgress,
        frame: &RtspWireFrame,
    ) -> Result<(), NativeMetadataSourceError> {
        self.observe_response(Some(*progress), frame)
    }

    /// Retain hash/status of a challenge or rejected response without labeling it accepted.
    /// Raw Session, authentication challenge and other response headers are not copied.
    pub fn observe_rejected_control(
        &mut self,
        frame: &RtspWireFrame,
    ) -> Result<(), NativeMetadataSourceError> {
        self.observe_response(None, frame)
    }

    fn observe_response(
        &mut self,
        progress: Option<ClientProgress>,
        frame: &RtspWireFrame,
    ) -> Result<(), NativeMetadataSourceError> {
        self.admit(frame.received_ns())?;
        let response = match frame.event() {
            RtspEvent::Response(value)
            | RtspEvent::AuthRequired {
                response: value, ..
            } => value,
            _ => return Err(NativeMetadataSourceError::State),
        };
        let next_state = control_transition(self.state, progress, response.status_code)?;
        let cseq = response.headers.cseq().and_then(Result::ok);
        if progress.is_some() && cseq.is_none() {
            return Err(NativeMetadataSourceError::Control);
        }
        let ordinal = self.next_ordinal()?;
        let control = NativeMetadataControl {
            ordinal,
            received_ns: frame.received_ns(),
            status: response.status_code,
            cseq,
            progress,
            wire_bytes: frame.expose_wire().len(),
            wire_digest: ContentDigest::sha256(frame.expose_wire()),
        };
        let description = if progress == Some(ClientProgress::Accepted(ClientState::Described)) {
            if self.description.is_some() || response.body.len() > MAX_DESCRIPTION {
                return Err(NativeMetadataSourceError::Description);
            }
            let value = NativeMetadataDescription {
                ordinal,
                received_ns: frame.received_ns(),
                bytes: copy_bytes(&response.body)?,
                content_base: field(response, "Content-Base")?,
                content_location: field(response, "Content-Location")?,
            };
            validate_description(&self.config, &value)?;
            Some(value)
        } else {
            None
        };
        let mut encoded = CanonicalEncoder::new();
        encode_control(&mut encoded, &control);
        let mut extra = encoded.finish_checked()?.len();
        if let Some(value) = &description {
            let mut encoded = CanonicalEncoder::new();
            encode_description(&mut encoded, Some(value));
            extra = extra
                .checked_add(encoded.finish_checked()?.len() - 1)
                .ok_or(NativeMetadataSourceError::Exhausted)?;
        }
        if self.controls.len() >= MAX_CONTROLS {
            return self.omit(
                frame.expose_wire().len(),
                frame.received_ns(),
                NativeMetadataSourceError::Limit,
            );
        }
        self.reserve(extra, frame.expose_wire().len(), frame.received_ns())?;
        if self.controls.try_reserve(1).is_err() {
            return self.omit(
                frame.expose_wire().len(),
                frame.received_ns(),
                NativeMetadataSourceError::Allocation,
            );
        }
        self.controls.push(control);
        if description.is_some() {
            self.description = description;
        }
        self.retained_bytes += extra;
        self.last_received_ns = frame.received_ns();
        self.state = next_state;
        Ok(())
    }

    /// Retain every complete original interleaved frame, including wrong-channel,
    /// malformed RTP/RTCP, duplicate, probation and unrepresentable replay records.
    /// This does not claim that the protocol or packet owner admitted the frame.
    pub fn observe_interleaved(
        &mut self,
        frame: &RtspWireFrame,
    ) -> Result<(), NativeMetadataSourceError> {
        self.admit(frame.received_ns())?;
        let RtspEvent::Interleaved { channel, span } = frame.event() else {
            return Err(NativeMetadataSourceError::State);
        };
        let wire = frame.expose_wire();
        if !valid_wire(wire) || wire[1] != *channel || &wire[4..] != span.as_slice() {
            return Err(NativeMetadataSourceError::Canonical);
        }
        if self.records.len() >= self.config.max_records {
            return self.omit(
                wire.len(),
                frame.received_ns(),
                NativeMetadataSourceError::Limit,
            );
        }
        let extra = 4 + 8 + 8 + wire.len();
        self.reserve(extra, wire.len(), frame.received_ns())?;
        let record = NativeMetadataRecord {
            ordinal: self.next_ordinal()?,
            received_ns: frame.received_ns(),
            wire: match copy_bytes(wire) {
                Ok(bytes) => bytes,
                Err(error) => return self.omit(wire.len(), frame.received_ns(), error),
            },
        };
        if self.records.try_reserve(1).is_err() {
            return self.omit(
                wire.len(),
                frame.received_ns(),
                NativeMetadataSourceError::Allocation,
            );
        }
        self.records.push(record);
        self.retained_bytes += extra;
        self.last_received_ns = frame.received_ns();
        Ok(())
    }

    /// Seal this finite source or a cloned prefix checkpoint. No network or publication occurs.
    pub fn finish(
        &mut self,
        ended_ns: u64,
        stop: NativeMetadataStop,
    ) -> Result<(), NativeMetadataSourceError> {
        if self.stop.is_some() {
            return Err(NativeMetadataSourceError::State);
        }
        if ended_ns < self.last_received_ns {
            return Err(NativeMetadataSourceError::Clock);
        }
        self.config
            .receive_origin_ns
            .checked_add(i128::from(ended_ns))
            .ok_or(NativeMetadataSourceError::Clock)?;
        self.ended_ns = Some(ended_ns);
        self.stop = Some(stop);
        self.validate()
    }

    /// Immutable owner scope; URIs/address are sensitive metadata and grant no authority.
    pub fn config(&self) -> &NativeMetadataConfig {
        &self.config
    }
    /// Original accepted SDP, absent if negotiation never reached that boundary.
    pub fn description(&self) -> Option<&NativeMetadataDescription> {
        self.description.as_ref()
    }
    /// All complete retained original frames in their arrival order.
    pub fn records(&self) -> &[NativeMetadataRecord] {
        &self.records
    }
    /// Typed/hash-only control observations, without raw authentication or session headers.
    pub fn controls(&self) -> &[NativeMetadataControl] {
        &self.controls
    }
    /// Fixed acquisition source mode, distinct from owner-file import.
    pub const fn source_mode(&self) -> &'static str {
        "native_rtsp_tcp"
    }
    /// Finite acquisition start in the owner monotonic clock.
    pub fn started_ns(&self) -> u64 {
        self.config.started_ns
    }
    /// Final local observation, absent until sealed.
    pub fn ended_ns(&self) -> Option<u64> {
        self.ended_ns
    }
    /// Fixed stop classification, absent until sealed.
    pub fn stop(&self) -> Option<NativeMetadataStop> {
        self.stop
    }
    /// Observations refused at the bounded source admission boundary. Admission then stops.
    pub fn omitted_observations(&self) -> u64 {
        self.omitted_observations
    }
    /// Exact byte count of the one complete observation refused by source admission.
    pub fn omitted_bytes(&self) -> u64 {
        self.omitted_bytes
    }
    /// Original receive observation of the complete frame refused by the source cap.
    /// This still bounds the acquisition interval even though its bytes could not fit.
    pub fn omitted_received_ns(&self) -> Option<u64> {
        (self.omitted_observations != 0).then_some(self.omitted_received_ns)
    }
    /// TCP/intake bytes retired before complete frame observations were available.
    /// Their contents are deliberately outside this source's complete-frame contract.
    pub fn unprocessed_wire_bytes(&self) -> u64 {
        self.unprocessed_wire_bytes
    }

    /// Account for an explicit terminal parser/socket suffix without persisting raw
    /// authentication/control material. This makes capture processing incomplete.
    /// The caller must count disjoint retired byte ranges exactly once.
    pub fn record_unprocessed_wire(
        &mut self,
        bytes: usize,
    ) -> Result<(), NativeMetadataSourceError> {
        if self.stop.is_some() {
            return Err(NativeMetadataSourceError::State);
        }
        self.unprocessed_wire_bytes = self
            .unprocessed_wire_bytes
            .checked_add(bytes as u64)
            .ok_or(NativeMetadataSourceError::Exhausted)?;
        Ok(())
    }
    /// Original retained frames that cannot appear in the derived rtpdump.
    pub fn projection_omissions(&self) -> usize {
        self.records
            .iter()
            .filter(|record| {
                !matches!(
                    record.projection(&self.config),
                    NativeMetadataProjection::Rtp | NativeMetadataProjection::Rtcp
                )
            })
            .count()
    }

    /// Capture/projection completeness only. XML usefulness, gaps, source authenticity
    /// and physical coverage require their independent replay/semantic owners.
    pub fn processing_complete(&self) -> bool {
        if !matches!(
            self.stop,
            Some(NativeMetadataStop::TargetReached | NativeMetadataStop::Eof)
        ) || self.description.is_none()
            || self.omitted_observations != 0
            || self.unprocessed_wire_bytes != 0
            || self.projection_omissions() != 0
            || !self
                .records
                .iter()
                .any(|record| record.channel() == self.config.protocol.channels.0)
            || self
                .controls
                .iter()
                .any(|control| control.progress.is_none() && control.status != 401)
        {
            return false;
        }
        self.history()
            .is_ok_and(|(ever_playing, outside_playing)| ever_playing && !outside_playing)
    }

    /// Independently validate canonical ownership, scope, order, bounds and description.
    /// A valid failure/checkpoint witness is not a successful acquisition.
    pub fn validate(&self) -> Result<(), NativeMetadataSourceError> {
        self.config.validate()?;
        let ended = self.ended_ns.ok_or(NativeMetadataSourceError::State)?;
        if self.stop.is_none() || ended < self.config.started_ns {
            return Err(NativeMetadataSourceError::State);
        }
        self.config
            .receive_origin_ns
            .checked_add(i128::from(ended))
            .ok_or(NativeMetadataSourceError::Clock)?;
        if self.records.len() > self.config.max_records
            || self.controls.len() > MAX_CONTROLS
            || self.retained_bytes > self.config.max_source_bytes
            || self.omitted_observations > 1
            || (self.omitted_observations == 0 && self.omitted_bytes != 0)
        {
            return Err(NativeMetadataSourceError::Limit);
        }
        let described = self
            .controls
            .iter()
            .filter(|control| {
                control.progress == Some(ClientProgress::Accepted(ClientState::Described))
            })
            .collect::<Vec<_>>();
        match (&self.description, described.as_slice()) {
            (None, []) => {}
            (Some(description), [control])
                if description.ordinal == control.ordinal
                    && description.received_ns == control.received_ns =>
            {
                validate_description(&self.config, description)?
            }
            _ => return Err(NativeMetadataSourceError::Description),
        }
        self.history()?;
        let latest = self
            .controls
            .last()
            .map(|value| value.received_ns)
            .into_iter()
            .chain(self.records.last().map(|value| value.received_ns))
            .max()
            .unwrap_or(self.config.started_ns);
        if (self.omitted_observations == 0 && self.omitted_received_ns != self.config.started_ns)
            || (self.omitted_observations != 0
                && (self.omitted_received_ns < latest || self.omitted_received_ns > ended))
        {
            return Err(NativeMetadataSourceError::Clock);
        }
        for control in &self.controls {
            if control.wire_digest.algorithm() != DigestAlgorithm::Sha256
                || control.wire_digest.is_laboratory()
                || control.wire_bytes == 0
                || control.wire_bytes > 131_072
                || (control.progress.is_some() && control.cseq.is_none())
            {
                return Err(NativeMetadataSourceError::Control);
            }
        }
        if self.records.iter().any(|record| !valid_wire(&record.wire)) {
            return Err(NativeMetadataSourceError::Canonical);
        }
        Ok(())
    }

    /// Complete deterministic v1 bytes with a trailing SHA-256 integrity checksum.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, NativeMetadataSourceError> {
        self.validate()?;
        let mut bytes = self.encode_body(
            self.ended_ns.ok_or(NativeMetadataSourceError::State)?,
            self.stop.ok_or(NativeMetadataSourceError::State)?,
        )?;
        let mut checksum = CanonicalEncoder::new();
        checksum.digest(ContentDigest::sha256(&bytes));
        bytes
            .try_reserve(CHECKSUM_BYTES)
            .map_err(|_| NativeMetadataSourceError::Allocation)?;
        bytes.extend_from_slice(&checksum.finish_checked()?);
        if bytes.len() != self.retained_bytes || bytes.len() > self.config.max_source_bytes {
            return Err(NativeMetadataSourceError::Limit);
        }
        Ok(bytes)
    }

    /// Strict bounded decode. No trailing bytes, unknown tags, changed checksum or
    /// noncanonical ownership/SDP/clock interpretation is accepted.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeMetadataSourceError> {
        if bytes.len() > MAX_SOURCE_BYTES || bytes.len() < CHECKSUM_BYTES {
            return Err(NativeMetadataSourceError::Limit);
        }
        let (body, trailer) = bytes.split_at(bytes.len() - CHECKSUM_BYTES);
        let mut checksum = CanonicalDecoder::new(trailer);
        if checksum.digest()? != ContentDigest::sha256(body) {
            return Err(NativeMetadataSourceError::Canonical);
        }
        checksum.ensure_finished()?;
        let mut d = CanonicalDecoder::new(body);
        if d.bytes()? != MAGIC || d.u32()? != 1 || d.text()? != SOURCE_DOMAIN {
            return Err(NativeMetadataSourceError::Canonical);
        }
        let config = decode_config(&mut d)?;
        config.validate()?;
        if bytes.len() > config.max_source_bytes {
            return Err(NativeMetadataSourceError::Limit);
        }
        let ended_ns = d.u64()?;
        let stop = NativeMetadataStop::decode(d.u8()?)?;
        let omitted_observations = d.u64()?;
        let omitted_bytes = d.u64()?;
        let omitted_received_ns = d.u64()?;
        let unprocessed_wire_bytes = d.u64()?;
        let description = if d.bool()? {
            let ordinal = d.u32()?;
            let received_ns = d.u64()?;
            let bytes = bounded_copy(d.bytes()?, MAX_DESCRIPTION)?;
            let content_base = decode_optional_text(&mut d)?;
            let content_location = decode_optional_text(&mut d)?;
            Some(NativeMetadataDescription {
                ordinal,
                received_ns,
                bytes,
                content_base,
                content_location,
            })
        } else {
            None
        };
        let controls_len = d.u32()? as usize;
        if controls_len > MAX_CONTROLS {
            return Err(NativeMetadataSourceError::Limit);
        }
        let mut controls = Vec::new();
        controls
            .try_reserve(controls_len)
            .map_err(|_| NativeMetadataSourceError::Allocation)?;
        for _ in 0..controls_len {
            controls.push(NativeMetadataControl {
                ordinal: d.u32()?,
                received_ns: d.u64()?,
                status: u16::try_from(d.u32()?).map_err(|_| NativeMetadataSourceError::Control)?,
                cseq: if d.bool()? { Some(d.u32()?) } else { None },
                progress: decode_progress(&mut d)?,
                wire_bytes: usize::try_from(d.u64()?)
                    .map_err(|_| NativeMetadataSourceError::Limit)?,
                wire_digest: d.digest()?,
            });
        }
        let records_len = d.u32()? as usize;
        if records_len > config.max_records {
            return Err(NativeMetadataSourceError::Limit);
        }
        let mut records = Vec::new();
        records
            .try_reserve(records_len)
            .map_err(|_| NativeMetadataSourceError::Allocation)?;
        for _ in 0..records_len {
            let ordinal = d.u32()?;
            let received_ns = d.u64()?;
            let wire = bounded_copy(d.bytes()?, MAX_FRAME)?;
            if !valid_wire(&wire) {
                return Err(NativeMetadataSourceError::Canonical);
            }
            records.push(NativeMetadataRecord {
                ordinal,
                received_ns,
                wire,
            });
        }
        d.ensure_finished()?;
        let mut source = Self {
            last_received_ns: config.started_ns,
            state: ClientState::Idle,
            config,
            description,
            controls,
            records,
            ended_ns: Some(ended_ns),
            stop: Some(stop),
            omitted_observations,
            omitted_bytes,
            omitted_received_ns,
            unprocessed_wire_bytes,
            retained_bytes: bytes.len(),
        };
        source.validate()?;
        source.last_received_ns = source
            .controls
            .last()
            .map(|value| value.received_ns)
            .into_iter()
            .chain(source.records.last().map(|value| value.received_ns))
            .chain(source.omitted_received_ns())
            .max()
            .unwrap_or(source.config.started_ns);
        if source.canonical_bytes()? != bytes {
            return Err(NativeMetadataSourceError::Canonical);
        }
        Ok(source)
    }

    /// Derived exact-datagram rtpdump with zero header clock and floor millisecond
    /// offsets relative to started_ns. Frames with an explicit nonrepresentable
    /// projection classification stay in this source and increment projection_omissions.
    /// Callers must expose that count and processing_complete; this view is not the source.
    pub fn rtpdump(&self) -> Result<Vec<u8>, NativeMetadataSourceError> {
        self.validate()?;
        let mut output = Vec::new();
        output
            .try_reserve(self.retained_bytes)
            .map_err(|_| NativeMetadataSourceError::Allocation)?;
        output.extend_from_slice(RTPDUMP_HEADER);
        output.extend_from_slice(&[0; 16]);
        for record in &self.records {
            let projection = record.projection(&self.config);
            if !matches!(
                projection,
                NativeMetadataProjection::Rtp | NativeMetadataProjection::Rtcp
            ) {
                continue;
            }
            let packet = record.bytes();
            output.extend_from_slice(&((packet.len() + 8) as u16).to_be_bytes());
            output.extend_from_slice(
                &(if projection == NativeMetadataProjection::Rtcp {
                    0
                } else {
                    packet.len() as u16
                })
                .to_be_bytes(),
            );
            output.extend_from_slice(
                &(((record.received_ns - self.config.started_ns) / 1_000_000) as u32).to_be_bytes(),
            );
            output.extend_from_slice(packet);
        }
        if output.len() > MAX_SOURCE_BYTES {
            return Err(NativeMetadataSourceError::Projection);
        }
        Ok(output)
    }

    fn admit(&self, received_ns: u64) -> Result<(), NativeMetadataSourceError> {
        if self.stop.is_some() || self.omitted_observations != 0 {
            return Err(NativeMetadataSourceError::State);
        }
        if received_ns < self.last_received_ns {
            return Err(NativeMetadataSourceError::Clock);
        }
        Ok(())
    }
    fn next_ordinal(&self) -> Result<u32, NativeMetadataSourceError> {
        u32::try_from(self.controls.len() + self.records.len())
            .map_err(|_| NativeMetadataSourceError::Exhausted)
    }
    fn reserve(
        &mut self,
        extra: usize,
        refused_bytes: usize,
        received_ns: u64,
    ) -> Result<(), NativeMetadataSourceError> {
        if extra
            > self
                .config
                .max_source_bytes
                .saturating_sub(self.retained_bytes)
        {
            self.omit(refused_bytes, received_ns, NativeMetadataSourceError::Limit)
        } else {
            Ok(())
        }
    }
    fn omit(
        &mut self,
        bytes: usize,
        received_ns: u64,
        error: NativeMetadataSourceError,
    ) -> Result<(), NativeMetadataSourceError> {
        self.omitted_observations = 1;
        self.omitted_bytes = bytes as u64;
        self.omitted_received_ns = received_ns;
        self.last_received_ns = received_ns;
        Err(error)
    }
    fn history(&self) -> Result<(bool, bool), NativeMetadataSourceError> {
        let (mut control_index, mut record_index) = (0, 0);
        let (mut state, mut at) = (ClientState::Idle, self.config.started_ns);
        let (mut playing, mut outside) = (false, false);
        for ordinal in 0..self.controls.len() + self.records.len() {
            let control = self.controls.get(control_index);
            let record = self.records.get(record_index);
            let use_control = match (control, record) {
                (Some(a), Some(b)) => a.ordinal < b.ordinal,
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => return Err(NativeMetadataSourceError::Canonical),
            };
            let (stored_ordinal, received) = if use_control {
                let value = control.ok_or(NativeMetadataSourceError::Canonical)?;
                state = control_transition(state, value.progress, value.status)?;
                playing |= state == ClientState::Playing;
                control_index += 1;
                (value.ordinal, value.received_ns)
            } else {
                let value = record.ok_or(NativeMetadataSourceError::Canonical)?;
                outside |= state != ClientState::Playing;
                record_index += 1;
                (value.ordinal, value.received_ns)
            };
            if stored_ordinal as usize != ordinal {
                return Err(NativeMetadataSourceError::Canonical);
            }
            if received < at || self.ended_ns.is_some_and(|end| received > end) {
                return Err(NativeMetadataSourceError::Clock);
            }
            at = received;
        }
        Ok((playing, outside))
    }
    fn encode_body(
        &self,
        ended_ns: u64,
        stop: NativeMetadataStop,
    ) -> Result<Vec<u8>, NativeMetadataSourceError> {
        let mut e = CanonicalEncoder::new();
        e.bytes(MAGIC);
        e.u32(1);
        e.text(SOURCE_DOMAIN);
        encode_config(&mut e, &self.config);
        e.u64(ended_ns);
        e.u8(stop.tag());
        e.u64(self.omitted_observations);
        e.u64(self.omitted_bytes);
        e.u64(self.omitted_received_ns);
        e.u64(self.unprocessed_wire_bytes);
        encode_description(&mut e, self.description.as_ref());
        e.u32(self.controls.len() as u32);
        for value in &self.controls {
            encode_control(&mut e, value);
        }
        e.u32(self.records.len() as u32);
        for value in &self.records {
            e.u32(value.ordinal);
            e.u64(value.received_ns);
            e.bytes(&value.wire);
        }
        Ok(e.finish_checked()?)
    }
}

fn valid_wire(wire: &[u8]) -> bool {
    wire.len() >= 4
        && wire.len() <= MAX_FRAME
        && wire[0] == b'$'
        && usize::from(u16::from_be_bytes([wire[2], wire[3]])) == wire.len() - 4
}
fn authority(uri: &str) -> Option<&str> {
    uri.strip_prefix("rtsp://")?.split('/').next()
}
fn copy_bytes(bytes: &[u8]) -> Result<Vec<u8>, NativeMetadataSourceError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(bytes.len())
        .map_err(|_| NativeMetadataSourceError::Allocation)?;
    output.extend_from_slice(bytes);
    Ok(output)
}
fn bounded_copy(bytes: &[u8], maximum: usize) -> Result<Vec<u8>, NativeMetadataSourceError> {
    if bytes.len() > maximum {
        return Err(NativeMetadataSourceError::Limit);
    }
    copy_bytes(bytes)
}
fn field(response: &RtspResponse, name: &str) -> Result<Option<String>, NativeMetadataSourceError> {
    let mut values = response
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name));
    let value = values.next();
    if values.next().is_some() {
        return Err(NativeMetadataSourceError::Description);
    }
    value
        .map(|value| text(value.value.as_str(), 2048))
        .transpose()
}
fn text(value: &str, max: usize) -> Result<String, NativeMetadataSourceError> {
    if value.len() > max {
        return Err(NativeMetadataSourceError::Limit);
    }
    let mut output = String::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| NativeMetadataSourceError::Allocation)?;
    output.push_str(value);
    Ok(output)
}
fn validate_description(
    config: &NativeMetadataConfig,
    value: &NativeMetadataDescription,
) -> Result<(), NativeMetadataSourceError> {
    if value.bytes.len() > MAX_DESCRIPTION {
        return Err(NativeMetadataSourceError::Description);
    }
    let mut session = RtspClientSession::with_codec_and_payload_type(
        config.protocol.clone(),
        ClientCodec::OnvifMetadata,
        config.payload_type,
    )
    .map_err(|_| NativeMetadataSourceError::Description)?;
    session
        .request(ClientCommand::Describe, 0)
        .map_err(|_| NativeMetadataSourceError::Description)?;
    // Revalidation input is deliberately derived. It is never presented as original wire.
    let mut headers = RtspHeaders::new();
    headers.insert("CSeq", "1");
    headers.insert("Content-Type", "application/sdp");
    headers.insert("Content-Length", value.bytes.len().to_string());
    if let Some(base) = &value.content_base {
        if base.len() > 2048 {
            return Err(NativeMetadataSourceError::Description);
        }
        headers.insert("Content-Base", base);
    }
    if let Some(location) = &value.content_location {
        if location.len() > 2048 {
            return Err(NativeMetadataSourceError::Description);
        }
        headers.insert("Content-Location", location);
    }
    let response = RtspResponse {
        version: "RTSP/1.0".into(),
        status_code: 200,
        reason: String::new(),
        headers,
        body: copy_bytes(&value.bytes)?,
        auth_challenge: None,
    };
    session
        .accept(&response, 0)
        .map_err(|_| NativeMetadataSourceError::Description)?;
    Ok(())
}
fn control_transition(
    current: ClientState,
    progress: Option<ClientProgress>,
    status: u16,
) -> Result<ClientState, NativeMetadataSourceError> {
    match progress {
        None if (100..=599).contains(&status) => Ok(current),
        Some(ClientProgress::Interim) if (100..200).contains(&status) => Ok(current),
        Some(ClientProgress::Accepted(next)) if status == 200 => {
            let valid = match next {
                ClientState::Idle => current == ClientState::Idle,
                ClientState::Described => current == ClientState::Idle,
                ClientState::Ready => {
                    matches!(current, ClientState::Described | ClientState::Ready)
                }
                ClientState::Playing => {
                    matches!(current, ClientState::Ready | ClientState::Playing)
                }
                ClientState::Closed => matches!(current, ClientState::Ready | ClientState::Playing),
                _ => false,
            };
            if valid {
                Ok(next)
            } else {
                Err(NativeMetadataSourceError::Control)
            }
        }
        _ => Err(NativeMetadataSourceError::Control),
    }
}
fn encode_progress(e: &mut CanonicalEncoder, progress: Option<ClientProgress>) {
    match progress {
        None => e.u8(0),
        Some(ClientProgress::Interim) => e.u8(1),
        Some(ClientProgress::Accepted(state)) => {
            e.u8(2);
            e.u8(match state {
                ClientState::Idle => 1,
                ClientState::Described => 2,
                ClientState::Ready => 3,
                ClientState::Playing => 4,
                ClientState::Closing => 5,
                ClientState::Closed => 6,
                ClientState::Failed => 7,
            });
        }
        Some(ClientProgress::KeepAliveDue) => e.u8(3),
        Some(ClientProgress::Pending) => e.u8(4),
    }
}
fn decode_progress(
    d: &mut CanonicalDecoder<'_>,
) -> Result<Option<ClientProgress>, NativeMetadataSourceError> {
    Ok(match d.u8()? {
        0 => None,
        1 => Some(ClientProgress::Interim),
        2 => Some(ClientProgress::Accepted(match d.u8()? {
            1 => ClientState::Idle,
            2 => ClientState::Described,
            3 => ClientState::Ready,
            4 => ClientState::Playing,
            6 => ClientState::Closed,
            _ => return Err(NativeMetadataSourceError::Control),
        })),
        _ => return Err(NativeMetadataSourceError::Control),
    })
}
fn encode_control(e: &mut CanonicalEncoder, value: &NativeMetadataControl) {
    e.u32(value.ordinal);
    e.u64(value.received_ns);
    e.u32(u32::from(value.status));
    e.bool(value.cseq.is_some());
    if let Some(cseq) = value.cseq {
        e.u32(cseq);
    }
    encode_progress(e, value.progress);
    e.u64(value.wire_bytes as u64);
    e.digest(value.wire_digest);
}
fn encode_description(e: &mut CanonicalEncoder, value: Option<&NativeMetadataDescription>) {
    e.bool(value.is_some());
    if let Some(value) = value {
        e.u32(value.ordinal);
        e.u64(value.received_ns);
        e.bytes(&value.bytes);
        encode_optional_text(e, value.content_base.as_deref());
        encode_optional_text(e, value.content_location.as_deref());
    }
}
fn encode_optional_text(e: &mut CanonicalEncoder, value: Option<&str>) {
    e.bool(value.is_some());
    if let Some(value) = value {
        e.text(value);
    }
}
fn decode_optional_text(
    d: &mut CanonicalDecoder<'_>,
) -> Result<Option<String>, NativeMetadataSourceError> {
    if d.bool()? {
        Ok(Some(text(d.text()?, 2048)?))
    } else {
        Ok(None)
    }
}
fn encode_config(e: &mut CanonicalEncoder, config: &NativeMetadataConfig) {
    e.digest(config.approval);
    e.text(&config.protocol.presentation_uri);
    e.text(&config.protocol.control_root_uri);
    e.u32(config.protocol.media_index as u32);
    e.u8(config.protocol.channels.0);
    e.u8(config.protocol.channels.1);
    e.u64(config.protocol.response_timeout_ns);
    e.u32(config.protocol.default_session_timeout_seconds);
    let key = config.binding.key();
    e.bytes(&key.ingress.to_be_bytes());
    e.u64(key.generation);
    e.u32(key.ssrc);
    match config.binding.peer() {
        SocketAddr::V4(peer) => {
            e.bytes(&peer.ip().octets());
            e.u32(u32::from(peer.port()));
            e.u32(0);
            e.u32(0);
        }
        SocketAddr::V6(peer) => {
            e.bytes(&peer.ip().octets());
            e.u32(u32::from(peer.port()));
            e.u32(peer.flowinfo());
            e.u32(peer.scope_id());
        }
    }
    e.text(config.binding.authority());
    e.u8(match config.binding.security() {
        TcpSecurityPolicy::OwnerApprovedPlaintext => 1,
    });
    e.u8(config.payload_type);
    e.i128(config.receive_origin_ns);
    e.u64(config.started_ns);
    e.u64(config.max_source_bytes as u64);
    e.u32(config.max_records as u32);
}
fn decode_config(
    d: &mut CanonicalDecoder<'_>,
) -> Result<NativeMetadataConfig, NativeMetadataSourceError> {
    let approval = d.digest()?;
    let protocol = ClientConfig {
        presentation_uri: text(d.text()?, 2048)?,
        control_root_uri: text(d.text()?, 2048)?,
        media_index: d.u32()? as usize,
        channels: (d.u8()?, d.u8()?),
        response_timeout_ns: d.u64()?,
        default_session_timeout_seconds: d.u32()?,
    };
    let key = StreamKey {
        ingress: u128::from_be_bytes(
            d.bytes()?
                .try_into()
                .map_err(|_| NativeMetadataSourceError::Canonical)?,
        ),
        generation: d.u64()?,
        ssrc: d.u32()?,
    };
    let octets = d.bytes()?;
    let port = u16::try_from(d.u32()?).map_err(|_| NativeMetadataSourceError::Configuration)?;
    let flow = d.u32()?;
    let scope = d.u32()?;
    let peer = match octets.len() {
        4 if flow == 0 && scope == 0 => SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(octets).map_err(|_| NativeMetadataSourceError::Canonical)?,
            )),
            port,
        ),
        16 => SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(
                <[u8; 16]>::try_from(octets).map_err(|_| NativeMetadataSourceError::Canonical)?,
            ),
            port,
            flow,
            scope,
        )),
        _ => return Err(NativeMetadataSourceError::Canonical),
    };
    let authority = text(d.text()?, 512)?;
    if d.u8()? != 1 {
        return Err(NativeMetadataSourceError::Configuration);
    }
    let binding = TcpBinding::new(
        key,
        peer,
        &authority,
        TcpSecurityPolicy::OwnerApprovedPlaintext,
    )
    .map_err(|_| NativeMetadataSourceError::Configuration)?;
    Ok(NativeMetadataConfig {
        approval,
        protocol,
        binding,
        payload_type: d.u8()?,
        receive_origin_ns: d.i128()?,
        started_ns: d.u64()?,
        max_source_bytes: usize::try_from(d.u64()?)
            .map_err(|_| NativeMetadataSourceError::Limit)?,
        max_records: d.u32()? as usize,
    })
}
