#![forbid(unsafe_code)]
//! What a deletion plan covers: one import, one sensor, one event, or an exact retention cohort.
//!
//! Sensor and event scopes retain their v2 encoding. Retention uses tag 4 only in v3 plans:
//! its immutable selection binds the owner request, every selected import, same-sensor
//! exclusions, capture bounds and source-metadata digests. Older readers refuse this scope.
//! No person or data-subject identity is inferred from a sensor or its recordings.

use fss_core::{
    CanonicalDecoder, CanonicalEncoder, ContentDigest, DigestAlgorithm, EventId, SensorId,
};

use super::DeletionError;
use super::retention::RetentionSelection;

/// What one deletion plan covers.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DeletionScope {
    /// One retained import.
    Import(ContentDigest),
    /// Every retained import whose capsules name this sensor.
    Sensor(SensorId),
    /// Every retained import whose deletion closure reaches this event's revisions.
    Event(EventId),
    /// Exactly the eligible imports of a freshly verified, owner-requested age selection.
    Retention(RetentionSelection),
}

impl DeletionScope {
    /// Stable scope spelling. Retention's bounded label is not its complete canonical identity;
    /// the plan encoding always includes the full selection, not just this display label.
    #[must_use]
    pub fn text(&self) -> String {
        match self {
            Self::Import(digest) => format!("import:{digest}"),
            Self::Sensor(sensor) => format!("sensor:{}", sensor.as_str()),
            Self::Event(event) => format!("event:{}", event.as_str()),
            Self::Retention(selection) => {
                format!("retention:{}", selection.request().sensor().as_str())
            }
        }
    }

    /// Scope kind (`import`, `sensor`, `event`, `retention`).
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Import(_) => "import",
            Self::Sensor(_) => "sensor",
            Self::Event(_) => "event",
            Self::Retention(_) => "retention",
        }
    }

    /// Display identity. Retention's full request and member set are inside the plan digest.
    #[must_use]
    pub fn id(&self) -> String {
        match self {
            Self::Import(digest) => digest.to_text(),
            Self::Sensor(sensor) => sensor.as_str().to_owned(),
            Self::Event(event) => event.as_str().to_owned(),
            Self::Retention(selection) => selection.request().sensor().as_str().to_owned(),
        }
    }

    /// Canonical tag and identity. Published tags 1..3 keep their exact bytes.
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
            Self::Retention(selection) => {
                e.u8(4);
                selection.encode(e);
            }
        }
    }

    /// Decodes the scope. The containing plan additionally enforces its version and member list.
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
            4 => Self::Retention(RetentionSelection::decode(d)?),
            _ => return Err(DeletionError::RecordMismatch),
        })
    }
}
