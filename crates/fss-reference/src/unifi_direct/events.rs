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
use std::fmt;

const MAX_DESCRIPTORS: usize = 64;
const MAX_LABEL_BYTES: usize = 128;

/// A known camera function or an unknown `Event*` function.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Smart object tracking event.
    SmartDetect,
    /// Smart object tracking event for a zone.
    SmartDetectZone,
    /// Explicit motion event.
    SmartMotion,
    /// Analytics event; its meaning depends on the supplied payload.
    Analytics,
    /// Another event whose exact name remains in the source bytes.
    Other,
}

impl Kind {
    pub(crate) fn from_name(name: &str) -> Self {
        match name {
            "EventSmartDetect" => Self::SmartDetect,
            "EventSmartDetectZone" => Self::SmartDetectZone,
            "EventSmartMotion" => Self::SmartMotion,
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
        parse(&self.source)
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
