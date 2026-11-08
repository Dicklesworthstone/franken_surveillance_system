#![forbid(unsafe_code)]
//! Bounded, source-preserving interpretation of untrusted UniFi event claims.
//!
//! An event is not a verified identity, a confirmed detection, or evidence of
//! continuous coverage. The caller must bind source, admission and task time.

use asupersync::bytes::Bytes;
use fss_core::{
    ContentDigest,
    json_input::{self, Value},
};
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    fmt,
};

const MAX_DESCRIPTORS: usize = 64;
const MAX_LABEL_BYTES: usize = 128;
const MAX_INBOX_FRAMES: usize = 64;
const MAX_INBOX_BYTES: usize = 4 * 1024 * 1024;

/// Caller-owned, bounded custody for event and opt-in request frames during startup.
///
/// One session may bind it at a time. The owner retains this inbox after a
/// session failure or cancellation and must apply its own privacy policy when
/// accessing or disposing of retained frames. Already buffered but unparsed
/// transport bytes may be lost on retirement; this inbox does not establish
/// complete event coverage or identity.
pub struct StartupInbox {
    frames: RefCell<VecDeque<Frame>>,
    bytes: Cell<usize>,
    max_frames: usize,
    max_bytes: usize,
    bound: Cell<bool>,
}

impl StartupInbox {
    /// Bound memory and frame count. The byte budget must admit a maximum-sized
    /// management message so backpressure occurs before reading the next one.
    pub fn new(max_frames: usize, max_bytes: usize) -> Result<Self, Error> {
        if !(1..=MAX_INBOX_FRAMES).contains(&max_frames)
            || !(super::MAX_MESSAGE_BYTES..=MAX_INBOX_BYTES).contains(&max_bytes)
        {
            return Err(Error::Limit);
        }
        let mut frames = VecDeque::new();
        frames
            .try_reserve_exact(max_frames)
            .map_err(|_| Error::Limit)?;
        Ok(Self {
            frames: RefCell::new(frames),
            bytes: Cell::new(0),
            max_frames,
            max_bytes,
            bound: Cell::new(false),
        })
    }

    /// Number of untransferred frames in this caller-owned inbox.
    pub fn len(&self) -> usize {
        self.frames.borrow().len()
    }
    /// Whether no source frames remain in the inbox.
    pub fn is_empty(&self) -> bool {
        self.frames.borrow().is_empty()
    }
    /// Number of untransferred source bytes, excluding queue overhead.
    pub fn source_bytes(&self) -> usize {
        self.bytes.get()
    }
    /// Transfer the oldest frame to the owner; this performs no I/O or policy grant.
    pub fn take(&self) -> Option<Frame> {
        let frame = self.frames.borrow_mut().pop_front()?;
        self.bytes.set(self.bytes.get() - frame.source().len());
        Some(frame)
    }
    pub(crate) fn bind(&self) -> bool {
        if self.bound.get() || !self.is_empty() {
            return false;
        }
        self.bound.set(true);
        true
    }
    pub(crate) fn unbind(&self) {
        self.bound.set(false);
    }
    pub(crate) fn can_receive(&self) -> bool {
        self.len() < self.max_frames
            && self.bytes.get() <= self.max_bytes - super::MAX_MESSAGE_BYTES
    }
    // A shared immutable reference keeps the source in the caller's inbox.
    pub(crate) fn find(&self, id: u64, digest: ContentDigest) -> Option<Frame> {
        self.frames
            .borrow()
            .iter()
            .find(|frame| frame.message_id() == id && frame.digest() == digest)
            .cloned()
    }
    // Only the one bound session calls push, after can_receive and before any
    // further await. The pre-reserved queue never allocates on this path.
    pub(crate) fn push(&self, frame: Frame) {
        self.bytes.set(self.bytes.get() + frame.source().len());
        self.frames.borrow_mut().push_back(frame);
    }
}
impl fmt::Debug for StartupInbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StartupInbox")
            .field("frames", &self.len())
            .field("source_bytes", &self.source_bytes())
            .finish_non_exhaustive()
    }
}

/// A known camera event, unknown `Event*`, or opt-in unknown startup request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Smart object tracking event.
    SmartDetect,
    /// Smart object tracking event for a zone.
    SmartDetectZone,
    /// Explicit motion event.
    SmartMotion,
    /// Camera-claimed smart-audio event; its content and meaning remain unverified.
    SmartAudio,
    /// Analytics event; its meaning depends on the supplied payload.
    Analytics,
    /// Another event whose exact name remains in the source bytes.
    Other,
    /// An unknown uncorrelated startup request; this is not an event claim.
    StartupRequest,
}

impl Kind {
    pub(crate) fn from_name(name: &str) -> Self {
        match name {
            "EventSmartDetect" => Self::SmartDetect,
            "EventSmartDetectZone" => Self::SmartDetectZone,
            "EventSmartMotion" => Self::SmartMotion,
            "EventSmartAudio" => Self::SmartAudio,
            "EventAnalytics" => Self::Analytics,
            _ => Self::Other,
        }
    }
}

/// One complete source message, transferred to the task owner without logging
/// its contents. The digest binds these bytes, not the peer's identity.
#[derive(Clone, Eq, PartialEq)]
pub struct Frame {
    kind: Kind,
    message_id: u64,
    response_expected: bool,
    source: Bytes,
    digest: ContentDigest,
}

impl Frame {
    pub(crate) fn new(kind: Kind, message_id: u64, response_expected: bool, source: Bytes) -> Self {
        let digest = ContentDigest::sha256(&source);
        Self {
            kind,
            message_id,
            response_expected,
            source,
            digest,
        }
    }
    /// Event function classification.
    pub fn kind(&self) -> Kind {
        self.kind
    }
    /// Untrusted camera message identifier.
    pub fn message_id(&self) -> u64 {
        self.message_id
    }
    /// The sender requested a reply; no reply is generated here.
    pub fn response_expected(&self) -> bool {
        self.response_expected
    }
    /// Exact received JSON bytes. The owner must apply its privacy policy.
    pub fn source(&self) -> &[u8] {
        self.source.as_ref()
    }
    /// Digest of exactly [`Self::source`].
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// Parse bounded optional fields. On refusal the original source remains owned.
    pub fn interpret(&self) -> Result<Parsed, Error> {
        if self.kind == Kind::StartupRequest {
            return Err(Error::Invalid);
        }
        parse(&self.source)
    }
    /// Interpret bounded smart-audio claims without establishing their meaning.
    pub fn interpret_smart_audio(&self) -> Result<SmartAudio, Error> {
        if self.kind != Kind::SmartAudio {
            return Err(Error::Invalid);
        }
        interpret_smart_audio_source(&self.source)
    }
}

/// The exact, bounded payload for an explicitly requested event reply.
/// This is untrusted camera content and must not be logged.
pub(crate) struct ReplyParts {
    pub function: String,
    pub message_id: u64,
    pub payload: String,
}

/// Recheck the source envelope and construct the reference's echo payload.
/// The caller must separately bind these bytes to an observed session request.
pub(crate) fn reply_parts(
    source: &[u8],
    startup_request: bool,
) -> Result<ReplyParts, super::Error> {
    if source.len() > super::MAX_MESSAGE_BYTES {
        return Err(super::Error::InvalidJson);
    }
    let text = std::str::from_utf8(source).map_err(|_| super::Error::InvalidJson)?;
    let parsed = json_input::parse(text).map_err(|_| super::Error::InvalidJson)?;
    let fields = parsed.object().ok_or(super::Error::InvalidEnvelope)?;
    if super::text_field(fields, "from")? != "ubnt_avclient"
        || super::text_field(fields, "to")? != "UniFiVideo"
        || fields.get("responseExpected").and_then(Value::boolean) != Some(true)
    {
        return Err(super::Error::InvalidEnvelope);
    }
    let name = super::text_field(fields, "functionName")?;
    if name.is_empty()
        || name.starts_with("Event") == startup_request
        || name.len() > 96
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(super::Error::InvalidEnvelope);
    }
    if fields.contains_key("inResponseTo") && super::number(fields, "inResponseTo", true)? != 0 {
        return Err(super::Error::UnexpectedMessage);
    }
    let message_id = super::number(fields, "messageId", false)?;
    let payload = match fields.get("payload") {
        None | Some(Value::Null | Value::Bool(false)) => "{}".to_owned(),
        Some(Value::Text(value)) if value.is_empty() => "{}".to_owned(),
        Some(Value::Number(value)) if value.parse::<f64>().ok() == Some(0.0) => "{}".to_owned(),
        Some(value) => {
            let mut out = String::new();
            write_json(value, &mut out)?;
            out
        }
    };
    Ok(ReplyParts {
        function: name.to_owned(),
        message_id,
        payload,
    })
}

fn append_json(out: &mut String, value: &str) -> Result<(), super::Error> {
    if out
        .len()
        .checked_add(value.len())
        .is_none_or(|n| n > super::MAX_MESSAGE_BYTES)
    {
        return Err(super::Error::InvalidJson);
    }
    out.try_reserve(value.len())
        .map_err(|_| super::Error::InvalidJson)?;
    out.push_str(value);
    Ok(())
}

fn write_json_string(out: &mut String, value: &str) -> Result<(), super::Error> {
    append_json(out, "\"")?;
    for ch in value.chars() {
        match ch {
            '"' => append_json(out, "\\\"")?,
            '\\' => append_json(out, "\\\\")?,
            '\u{0}'..='\u{1f}' => append_json(out, &format!("\\u{:04x}", u32::from(ch)))?,
            _ => append_json(out, ch.encode_utf8(&mut [0; 4]))?,
        }
    }
    append_json(out, "\"")
}

fn write_json(value: &Value, out: &mut String) -> Result<(), super::Error> {
    match value {
        Value::Null => append_json(out, "null"),
        Value::Bool(value) => append_json(out, if *value { "true" } else { "false" }),
        Value::Number(value) => append_json(out, value),
        Value::Text(value) => write_json_string(out, value),
        Value::Array(values) => {
            append_json(out, "[")?;
            for (i, value) in values.iter().enumerate() {
                if i != 0 {
                    append_json(out, ",")?;
                }
                write_json(value, out)?;
            }
            append_json(out, "]")
        }
        Value::Object(values) => {
            append_json(out, "{")?;
            for (i, (key, value)) in values.iter().enumerate() {
                if i != 0 {
                    append_json(out, ",")?;
                }
                write_json_string(out, key)?;
                append_json(out, ":")?;
                write_json(value, out)?;
            }
            append_json(out, "}")
        }
    }
}
impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Frame")
            .field("kind", &self.kind)
            .field("message_id", &self.message_id)
            .field("response_expected", &self.response_expected)
            .field("source_len", &self.source.len())
            .finish_non_exhaustive()
    }
}

/// A recognized event edge, a missing edge, or an unrecognized edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Edge {
    /// Explicit entry.
    Enter,
    /// Movement update.
    Moving,
    /// Explicit departure.
    Leave,
    /// Package event.
    PackageDetected,
    /// Raw tracker noise as reported by the reference.
    None,
    /// Explicit motion start.
    Start,
    /// Explicit motion stop.
    Stop,
    /// Explicit motion pulse.
    Pulse,
    /// Field absent or null.
    Missing,
    /// A different string value.
    Other,
}

/// A camera-claimed object descriptor. Values remain unverified.
#[derive(Clone, PartialEq)]
pub struct Descriptor {
    /// Camera-provided object class, if present.
    pub object_type: Option<String>,
    /// Camera-provided confidence in the inclusive 0..100 range.
    pub confidence: Option<f64>,
    /// Camera-provided tracker identifier, if present.
    pub tracker_id: Option<String>,
    /// Camera-provided normalized 0..1000 coordinates, if present.
    pub coordinates: Option<[f64; 4]>,
    /// Camera-provided stationary flag; missing or unsupported remains unknown.
    pub stationary: Option<bool>,
}
impl fmt::Debug for Descriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Descriptor(<redacted>)")
    }
}

/// A bounded view of selected payload fields; the frame retains all other bytes.
#[derive(Clone, Debug, PartialEq)]
pub struct Parsed {
    /// Edge or event type reported by the camera.
    pub edge: Edge,
    /// Descriptor field, preserving absent versus present-empty.
    pub descriptors: Option<Vec<Descriptor>>,
}

/// Known fields in the observed smart-audio payload profile.
/// Names describe protocol fields, not validated clock or detection semantics.
#[repr(usize)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmartAudioField {
    /// Camera monotonic-clock claim.
    ClockMonotonic,
    /// Camera stream-clock claim.
    ClockStream,
    /// Camera stream-rate claim.
    ClockStreamRate,
    /// Camera wall-clock claim.
    ClockWall,
    /// Camera event identifier claim.
    EventId,
    /// Camera level claim labeled in decibels.
    LevelDb,
    /// Camera levels claim of unknown interpretation.
    Levels,
    /// Baby-cry alarm text.
    AlarmBabyCry,
    /// Bark alarm text.
    AlarmBark,
    /// Burglar alarm text.
    AlarmBurglar,
    /// Car-horn alarm text.
    AlarmCarHorn,
    /// Camera `alrmCmonx` text of unknown interpretation.
    AlarmCmonx,
    /// Glass-break alarm text.
    AlarmGlassBreak,
    /// Siren alarm text.
    AlarmSiren,
    /// Smoke alarm text.
    AlarmSmoke,
    /// Speech alarm text.
    AlarmSpeak,
    /// Loud-noise text.
    LoudNoise,
    /// Sound-loss text.
    SoundLoss,
}
const SMART_AUDIO_FIELDS: [(&str, bool); 18] = [
    ("clockMonotonic", true),
    ("clockStream", true),
    ("clockStreamRate", true),
    ("clockWall", true),
    ("eventId", true),
    ("leveldB", true),
    ("levels", true),
    ("alrmBabyCry", false),
    ("alrmBark", false),
    ("alrmBurglar", false),
    ("alrmCarHorn", false),
    ("alrmCmonx", false),
    ("alrmGlassBreak", false),
    ("alrmSiren", false),
    ("alrmSmoke", false),
    ("alrmSpeak", false),
    ("loudNoise", false),
    ("soundLoss", false),
];

/// Presence and source type of one untrusted camera field.
#[derive(Clone, PartialEq, Eq)]
pub enum SmartAudioClaim {
    /// Field absent from the payload.
    Missing,
    /// Field explicitly null.
    Null,
    /// An exact JSON number spelling; no units or numeric range are asserted.
    Number(String),
    /// An exact bounded text claim; no detection state is inferred.
    Text(String),
    /// A different type was present; the original source remains with the caller.
    Unsupported,
}
impl fmt::Debug for SmartAudioClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Missing => "Missing",
            Self::Null => "Null",
            Self::Number(_) => "Number(<redacted>)",
            Self::Text(_) => "Text(<redacted>)",
            Self::Unsupported => "Unsupported",
        })
    }
}

/// Whether the event supplied an object payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmartAudioPayload {
    /// Payload absent.
    Missing,
    /// Payload explicitly null.
    Null,
    /// Payload was an object.
    Object,
}

/// Bounded interpreted claims; original message custody remains separate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmartAudio {
    payload: SmartAudioPayload,
    fields: [SmartAudioClaim; SMART_AUDIO_FIELDS.len()],
    unknown_fields: usize,
}
impl SmartAudio {
    /// Presence of the payload itself.
    pub fn payload(&self) -> SmartAudioPayload {
        self.payload
    }
    /// A protocol field's claim; reading the value requires caller privacy authority.
    pub fn get(&self, field: SmartAudioField) -> &SmartAudioClaim {
        &self.fields[field as usize]
    }
    /// Number of other top-level payload fields; their source remains with the caller.
    pub fn unknown_fields(&self) -> usize {
        self.unknown_fields
    }
}

/// Interpret a bounded smart-audio envelope without establishing identity,
/// clock units, event truth, audio content, or status-string semantics.
pub fn interpret_smart_audio_source(source: &[u8]) -> Result<SmartAudio, Error> {
    if source.len() > super::MAX_MESSAGE_BYTES {
        return Err(Error::Limit);
    }
    let text = std::str::from_utf8(source).map_err(|_| Error::Invalid)?;
    let value = json_input::parse(text).map_err(|_| Error::Invalid)?;
    let fields = value.object().ok_or(Error::Invalid)?;
    if fields.get("functionName").and_then(Value::text) != Some("EventSmartAudio") {
        return Err(Error::Invalid);
    }
    let (payload, object) = match fields.get("payload") {
        None => (SmartAudioPayload::Missing, None),
        Some(Value::Null) => (SmartAudioPayload::Null, None),
        Some(Value::Object(v)) => (SmartAudioPayload::Object, Some(v)),
        _ => return Err(Error::Invalid),
    };
    let mut claims = std::array::from_fn(|_| SmartAudioClaim::Missing);
    let mut unknown_fields = 0;
    if let Some(object) = object {
        unknown_fields = object
            .keys()
            .filter(|key| {
                !SMART_AUDIO_FIELDS
                    .iter()
                    .any(|(known, _)| *known == key.as_str())
            })
            .count();
        for (index, (key, number)) in SMART_AUDIO_FIELDS.iter().enumerate() {
            claims[index] = match object.get(*key) {
                None => SmartAudioClaim::Missing,
                Some(Value::Null) => SmartAudioClaim::Null,
                Some(Value::Number(v)) if *number && v.len() <= MAX_LABEL_BYTES => {
                    SmartAudioClaim::Number(v.clone())
                }
                Some(Value::Text(v)) if !*number && v.len() <= MAX_LABEL_BYTES => {
                    SmartAudioClaim::Text(v.clone())
                }
                Some(Value::Number(v) | Value::Text(v)) if v.len() > MAX_LABEL_BYTES => {
                    return Err(Error::Limit);
                }
                Some(_) => SmartAudioClaim::Unsupported,
            };
        }
    }
    Ok(SmartAudio {
        payload,
        fields: claims,
        unknown_fields,
    })
}

/// Static, payload-free parse refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid JSON or wrong field type.
    Invalid,
    /// A configured field or collection bound was exceeded.
    Limit,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi event refusal: {self:?}")
    }
}
impl std::error::Error for Error {}

fn label(value: Option<&Value>, allow_number: bool) -> Result<Option<String>, Error> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Text(text)) if text.len() <= MAX_LABEL_BYTES => Ok(Some(text.clone())),
        Some(Value::Number(number)) if allow_number && number.len() <= MAX_LABEL_BYTES => {
            Ok(Some(number.clone()))
        }
        Some(Value::Text(_)) => Err(Error::Limit),
        Some(Value::Number(_)) if allow_number => Err(Error::Limit),
        _ => Err(Error::Invalid),
    }
}
fn bounded_number(value: &Value, max: f64) -> Result<f64, Error> {
    let Value::Number(number) = value else {
        return Err(Error::Invalid);
    };
    let number = number.parse::<f64>().map_err(|_| Error::Invalid)?;
    if number.is_finite() && (0.0..=max).contains(&number) {
        Ok(number)
    } else {
        Err(Error::Invalid)
    }
}

/// Interpret selected fields from a bounded source message. This does not
/// validate the envelope or establish the message's provenance.
pub fn interpret_source(source: &[u8]) -> Result<Parsed, Error> {
    if source.len() > super::MAX_MESSAGE_BYTES {
        return Err(Error::Limit);
    }
    let text = std::str::from_utf8(source).map_err(|_| Error::Invalid)?;
    let value = json_input::parse(text).map_err(|_| Error::Invalid)?;
    let fields = value.object().ok_or(Error::Invalid)?;
    let Some(payload) = fields.get("payload") else {
        return Ok(Parsed {
            edge: Edge::Missing,
            descriptors: None,
        });
    };
    if matches!(payload, Value::Null) {
        return Ok(Parsed {
            edge: Edge::Missing,
            descriptors: None,
        });
    }
    let payload = payload.object().ok_or(Error::Invalid)?;
    let event_type = match payload.get("eventType") {
        None | Some(Value::Null) => None,
        Some(Value::Text(s)) => Some(s.as_str()),
        _ => return Err(Error::Invalid),
    };
    let edge = match event_type {
        Some("pulse") => Edge::Pulse,
        _ => match payload.get("edgeType") {
            None | Some(Value::Null) => Edge::Missing,
            Some(Value::Text(s)) => match s.as_str() {
                "enter" => Edge::Enter,
                "moving" => Edge::Moving,
                "leave" => Edge::Leave,
                "packageDetected" => Edge::PackageDetected,
                "none" => Edge::None,
                "start" => Edge::Start,
                "stop" => Edge::Stop,
                "pulse" => Edge::Pulse,
                _ => Edge::Other,
            },
            _ => return Err(Error::Invalid),
        },
    };
    let descriptors = match payload.get("descriptors") {
        None | Some(Value::Null) => None,
        Some(Value::Array(items)) => {
            if items.len() > MAX_DESCRIPTORS {
                return Err(Error::Limit);
            }
            let mut descriptors = Vec::new();
            descriptors
                .try_reserve_exact(items.len())
                .map_err(|_| Error::Limit)?;
            for item in items {
                let fields = item.object().ok_or(Error::Invalid)?;
                let object_type = label(fields.get("objectType"), false)?;
                let tracker_id = label(fields.get("trackerID"), true)?;
                let confidence = match fields.get("confidenceLevel") {
                    None | Some(Value::Null) => None,
                    Some(v) => Some(bounded_number(v, 100.0)?),
                };
                let coordinates = match fields.get("coord") {
                    None | Some(Value::Null) => None,
                    Some(Value::Array(v)) if v.len() == 4 => Some([
                        bounded_number(&v[0], 1000.0)?,
                        bounded_number(&v[1], 1000.0)?,
                        bounded_number(&v[2], 1000.0)?,
                        bounded_number(&v[3], 1000.0)?,
                    ]),
                    _ => return Err(Error::Invalid),
                };
                let stationary = match fields.get("stationary") {
                    Some(Value::Bool(v)) => Some(*v),
                    Some(Value::Text(v)) if v == "true" => Some(true),
                    Some(Value::Text(v)) if v == "false" => Some(false),
                    Some(Value::Number(v)) if v == "1" => Some(true),
                    Some(Value::Number(v)) if v == "0" => Some(false),
                    _ => None,
                };
                descriptors.push(Descriptor {
                    object_type,
                    confidence,
                    tracker_id,
                    coordinates,
                    stationary,
                });
            }
            Some(descriptors)
        }
        _ => return Err(Error::Invalid),
    };
    Ok(Parsed { edge, descriptors })
}

fn parse(source: &[u8]) -> Result<Parsed, Error> {
    interpret_source(source)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smart_event_keeps_source_and_interprets_bounded_descriptor() -> Result<(), Error> {
        let source=br#"{"payload":{"edgeType":"enter","descriptors":[{"objectType":"person","trackerID":42,"confidenceLevel":80,"coord":[0,1,500,1000],"stationary":"false"}]}}"#.to_vec();
        let event = Frame::new(Kind::SmartDetect, 7, false, source.clone().into());
        let parsed = event.interpret()?;
        assert_eq!(event.source(), source);
        assert_eq!(event.digest(), ContentDigest::sha256(&source));
        assert_eq!(parsed.edge, Edge::Enter);
        let descriptor = &parsed.descriptors.ok_or(Error::Invalid)?[0];
        assert_eq!(descriptor.object_type.as_deref(), Some("person"));
        assert_eq!(descriptor.tracker_id.as_deref(), Some("42"));
        assert_eq!(descriptor.confidence, Some(80.0));
        assert_eq!(descriptor.coordinates, Some([0.0, 1.0, 500.0, 1000.0]));
        assert_eq!(descriptor.stationary, Some(false));
        assert!(!format!("{event:?} {descriptor:?}").contains("person"));
        Ok(())
    }

    #[test]
    fn missing_empty_unknown_and_pulse_remain_distinct() -> Result<(), Error> {
        let missing = parse(br#"{"payload":{}}"#)?;
        assert_eq!((missing.edge, missing.descriptors), (Edge::Missing, None));
        let empty = parse(br#"{"payload":{"edgeType":"future","descriptors":[]}}"#)?;
        assert_eq!((empty.edge, empty.descriptors), (Edge::Other, Some(vec![])));
        assert_eq!(
            parse(br#"{"payload":{"eventType":"pulse"}}"#)?.edge,
            Edge::Pulse
        );
        Ok(())
    }

    #[test]
    fn invalid_or_overflowing_claims_do_not_destroy_source() {
        let source = br#"{"payload":{"descriptors":[{"coord":[0,0,1001,1]}]}}"#.to_vec();
        let frame = Frame::new(Kind::SmartDetect, 3, true, source.clone().into());
        assert_eq!(frame.interpret(), Err(Error::Invalid));
        assert_eq!(frame.source(), source);
        assert!(frame.response_expected());
        let many = format!(
            "{{\"payload\":{{\"descriptors\":[{}]}}}}",
            vec!["{}"; 65].join(",")
        );
        assert_eq!(parse(many.as_bytes()), Err(Error::Limit));
        assert_eq!(
            parse(br#"{"payload":{"eventType":42}}"#),
            Err(Error::Invalid)
        );
    }
}
