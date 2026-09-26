#![forbid(unsafe_code)]
//! What a deletion plan (or a deletion hold) covers: one import, one sensor or one event.
//!
//! The scope is the same notion for holds and plans, and it resolves to the same imports:
//!
//! - `import:sha256:HEX`: that one retained import;
//! - `sensor:ID`: every retained import whose sensor capsules name the sensor;
//! - `event:ID`: every retained import whose own deletion closure reaches one of the event's
//!   committed revisions (the event's evidence).
//!
//! A scoped plan's closure is the union of its member imports' closures, computed in one walk,
//! so an object only another member holds is deleted while an object anything outside the scope
//! still holds is retained. The scope kind and identity are bound into the sealed plan
//! (`fss.deletion_plan.v2`), so a sensor or event plan is never the digest of an import plan.
//!
//! No person or data-subject identity exists in this system: sensors are the most concrete
//! "subject" of retained evidence, and a scope never infers who was observed.

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, DigestAlgorithm, EventId, SensorId};

use super::DeletionError;

/// What one deletion plan or hold covers.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DeletionScope {
    /// One retained import.
    Import(ContentDigest),
    /// Every retained import whose capsules name this sensor.
    Sensor(SensorId),
    /// Every retained import whose deletion closure reaches this event's revisions.
    Event(EventId),
}

fn refused(reason: &'static str) -> DeletionError {
    DeletionError::HoldRequest(reason)
}

impl DeletionScope {
    /// Parses `import:sha256:HEX`, `sensor:ID` or `event:ID` (the hold `--scope` spelling).
    pub fn parse(text: &str) -> Result<Self, DeletionError> {
        if let Some(rest) = text.strip_prefix("import:") {
            let digest =
                ContentDigest::parse(rest).map_err(|_| refused("invalid import digest"))?;
            if digest.algorithm() != DigestAlgorithm::Sha256 {
                return Err(refused("an import scope names a SHA-256 import identity"));
            }
            Ok(Self::Import(digest))
        } else if let Some(rest) = text.strip_prefix("sensor:") {
            Ok(Self::Sensor(
                SensorId::parse(rest).map_err(|_| refused("invalid sensor identity"))?,
            ))
        } else if let Some(rest) = text.strip_prefix("event:") {
            Ok(Self::Event(
                EventId::parse(rest).map_err(|_| refused("invalid event identity"))?,
            ))
        } else {
            Err(refused(
                "a hold scope is import:sha256:HEX, sensor:ID or event:ID",
            ))
        }
    }

    /// Stable spelling (`import:sha256:...`, `sensor:ID`, `event:ID`).
    #[must_use]
    pub fn text(&self) -> String {
        match self {
            Self::Import(digest) => format!("import:{digest}"),
            Self::Sensor(sensor) => format!("sensor:{}", sensor.as_str()),
            Self::Event(event) => format!("event:{}", event.as_str()),
        }
    }

    /// Scope kind (`import`, `sensor`, `event`).
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Import(_) => "import",
            Self::Sensor(_) => "sensor",
            Self::Event(_) => "event",
        }
    }

    /// The identity alone (`sha256:...`, the sensor ID or the event ID).
    #[must_use]
    pub fn id(&self) -> String {
        match self {
            Self::Import(digest) => digest.to_text(),
            Self::Sensor(sensor) => sensor.as_str().to_owned(),
            Self::Event(event) => event.as_str().to_owned(),
        }
    }

    /// Canonical tag and identity (tag 1 import digest, 2 sensor text, 3 event text).
    pub(super) fn encode(&self, e: &mut CanonicalEncoder) {
        match self {
            Self::Import(digest) => {
                e.u8(1);
                e.digest(*digest);
            }
            Self::Sensor(sensor) => {
                e.u8(2);
                e.text(sensor.as_str());
            }
            Self::Event(event) => {
                e.u8(3);
                e.text(event.as_str());
            }
        }
    }

    /// Decodes [`Self::encode`]; anything else is a damaged record.
    pub(super) fn decode(d: &mut CanonicalDecoder<'_>) -> Result<Self, DeletionError> {
        Ok(match d.u8()? {
            1 => {
                let digest = d.digest()?;
                if digest.algorithm() != DigestAlgorithm::Sha256 {
                    return Err(DeletionError::RecordMismatch);
                }
                Self::Import(digest)
            }
            2 => Self::Sensor(SensorId::parse(d.text()?)?),
            3 => Self::Event(EventId::parse(d.text()?)?),
            _ => return Err(DeletionError::RecordMismatch),
        })
    }
}
