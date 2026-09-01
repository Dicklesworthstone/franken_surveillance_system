use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::digest::{CanonicalWriter, Digest, DigestError, domain_digest};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    SourcePublished,
    Observation,
    Coverage,
    Absence,
    Event,
    Effect,
    Obligation,
    Situation,
    Handoff,
}

impl RecordKind {
    const fn code(self) -> u8 {
        match self {
            Self::SourcePublished => 1,
            Self::Observation => 2,
            Self::Coverage => 3,
            Self::Absence => 4,
            Self::Event => 5,
            Self::Effect => 6,
            Self::Obligation => 7,
            Self::Situation => 8,
            Self::Handoff => 9,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRecord {
    pub sequence: u64,
    pub observed_at: u64,
    pub kind: RecordKind,
    pub source_digests: Vec<Digest>,
    pub payload_digest: Digest,
    pub previous_root: Digest,
    pub root: Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceAnchor {
    pub sequence: u64,
    pub observed_at: u64,
    pub root: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    Digest(DigestError),
    SequenceOverflow,
    TimeReversal { previous: u64, proposed: u64 },
    InvalidInterval { start: u64, end: u64 },
    MissingCoverage(String),
    CoverageGap { sensor: String, at: u64 },
    PresenceObserved { sensor: String, at: u64 },
}

impl fmt::Display for LedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Digest(error) => write!(formatter, "digest failure: {error}"),
            Self::SequenceOverflow => formatter.write_str("evidence sequence overflow"),
            Self::TimeReversal { previous, proposed } => write!(
                formatter,
                "evidence time moved backwards from {previous} to {proposed}"
            ),
            Self::InvalidInterval { start, end } => {
                write!(formatter, "invalid half-open interval [{start}, {end})")
            }
            Self::MissingCoverage(sensor) => {
                write!(formatter, "required sensor {sensor} has no coverage")
            }
            Self::CoverageGap { sensor, at } => {
                write!(formatter, "sensor {sensor} has a coverage gap at {at}")
            }
            Self::PresenceObserved { sensor, at } => write!(
                formatter,
                "presence was observed by sensor {sensor} at {at}"
            ),
        }
    }
}

impl std::error::Error for LedgerError {}

impl From<DigestError> for LedgerError {
    fn from(error: DigestError) -> Self {
        Self::Digest(error)
    }
}

#[derive(Debug, Clone)]
pub struct EvidenceLedger {
    records: Vec<EvidenceRecord>,
    root: Digest,
    last_time: u64,
}

impl Default for EvidenceLedger {
    fn default() -> Self {
        Self {
            records: Vec::new(),
            root: Digest::ZERO,
            last_time: 0,
        }
    }
}

impl EvidenceLedger {
    pub fn append(
        &mut self,
        observed_at: u64,
        kind: RecordKind,
        mut source_digests: Vec<Digest>,
        payload: &[u8],
    ) -> Result<EvidenceAnchor, LedgerError> {
        if !self.records.is_empty() && observed_at < self.last_time {
            return Err(LedgerError::TimeReversal {
                previous: self.last_time,
                proposed: observed_at,
            });
        }
        let sequence = u64::try_from(self.records.len())
            .map_err(|_| LedgerError::SequenceOverflow)?
            .checked_add(1)
            .ok_or(LedgerError::SequenceOverflow)?;
        source_digests.sort_unstable();
        source_digests.dedup();
        let payload_digest = domain_digest("fss-evidence-payload-v1", payload)?;
        let mut writer = CanonicalWriter::new("fss-evidence-record-v1")?;
        writer.push_digest(self.root);
        writer.push_u64(sequence);
        writer.push_u64(observed_at);
        writer.push_u8(kind.code());
        writer.push_u64(
            u64::try_from(source_digests.len()).map_err(|_| DigestError::FieldTooLarge)?,
        );
        for digest in &source_digests {
            writer.push_digest(*digest);
        }
        writer.push_digest(payload_digest);
        let root = writer.digest()?;
        self.records.push(EvidenceRecord {
            sequence,
            observed_at,
            kind,
            source_digests,
            payload_digest,
            previous_root: self.root,
            root,
        });
        self.root = root;
        self.last_time = observed_at;
        Ok(EvidenceAnchor {
            sequence,
            observed_at,
            root,
        })
    }

    #[must_use]
    pub fn anchor(&self) -> EvidenceAnchor {
        EvidenceAnchor {
            sequence: u64::try_from(self.records.len()).unwrap_or(u64::MAX),
            observed_at: self.last_time,
            root: self.root,
        }
    }

    #[must_use]
    pub fn records(&self) -> &[EvidenceRecord] {
        &self.records
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageInterval {
    pub sensor: String,
    pub failure_domain: String,
    pub start: u64,
    pub end: u64,
    pub continuous: bool,
}

impl CoverageInterval {
    pub fn new(
        sensor: impl Into<String>,
        failure_domain: impl Into<String>,
        start: u64,
        end: u64,
        continuous: bool,
    ) -> Result<Self, LedgerError> {
        if start >= end {
            return Err(LedgerError::InvalidInterval { start, end });
        }
        Ok(Self {
            sensor: sensor.into(),
            failure_domain: failure_domain.into(),
            start,
            end,
            continuous,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageCertificate {
    pub start: u64,
    pub end: u64,
    pub sensors: Vec<String>,
    pub failure_domains: Vec<String>,
    pub digest: Digest,
}

impl CoverageCertificate {
    pub fn build(
        required_sensors: &BTreeSet<String>,
        intervals: &[CoverageInterval],
        start: u64,
        end: u64,
    ) -> Result<Self, LedgerError> {
        if start >= end {
            return Err(LedgerError::InvalidInterval { start, end });
        }
        let mut domains = BTreeSet::new();
        for sensor in required_sensors {
            let mut spans: Vec<&CoverageInterval> = intervals
                .iter()
                .filter(|interval| interval.sensor == *sensor && interval.continuous)
                .collect();
            if spans.is_empty() {
                return Err(LedgerError::MissingCoverage(sensor.clone()));
            }
            spans.sort_by_key(|interval| (interval.start, interval.end));
            let mut cursor = start;
            for span in spans {
                if span.end <= cursor || span.start >= end {
                    continue;
                }
                if span.start > cursor {
                    return Err(LedgerError::CoverageGap {
                        sensor: sensor.clone(),
                        at: cursor,
                    });
                }
                cursor = cursor.max(span.end.min(end));
                domains.insert(span.failure_domain.clone());
                if cursor == end {
                    break;
                }
            }
            if cursor < end {
                return Err(LedgerError::CoverageGap {
                    sensor: sensor.clone(),
                    at: cursor,
                });
            }
        }

        let sensors: Vec<String> = required_sensors.iter().cloned().collect();
        let failure_domains: Vec<String> = domains.into_iter().collect();
        let mut writer = CanonicalWriter::new("fss-coverage-certificate-v1")?;
        writer.push_u64(start);
        writer.push_u64(end);
        writer.push_u64(u64::try_from(sensors.len()).map_err(|_| DigestError::FieldTooLarge)?);
        for sensor in &sensors {
            writer.push_str(sensor)?;
        }
        writer.push_u64(
            u64::try_from(failure_domains.len()).map_err(|_| DigestError::FieldTooLarge)?,
        );
        for domain in &failure_domains {
            writer.push_str(domain)?;
        }
        let digest = writer.digest()?;
        Ok(Self {
            start,
            end,
            sensors,
            failure_domains,
            digest,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ObservationClass {
    Empty,
    Homeowner,
    Raccoon,
    UnknownPerson,
}

impl ObservationClass {
    const fn code(self) -> u8 {
        match self {
            Self::Empty => 0,
            Self::Homeowner => 1,
            Self::Raccoon => 2,
            Self::UnknownPerson => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub sensor: String,
    pub failure_domain: String,
    pub at: u64,
    pub class: ObservationClass,
    pub confidence_basis_points: u16,
    pub source_digest: Digest,
}

impl Observation {
    pub fn digest(&self) -> Result<Digest, LedgerError> {
        let mut writer = CanonicalWriter::new("fss-observation-v1")?;
        writer.push_str(&self.sensor)?;
        writer.push_str(&self.failure_domain)?;
        writer.push_u64(self.at);
        writer.push_u8(self.class.code());
        writer.push_u32(u32::from(self.confidence_basis_points));
        writer.push_digest(self.source_digest);
        Ok(writer.digest()?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbsenceCertificate {
    pub class: ObservationClass,
    pub coverage: CoverageCertificate,
    pub anchor: EvidenceAnchor,
    pub digest: Digest,
}

pub fn certify_absence(
    class: ObservationClass,
    coverage: CoverageCertificate,
    observations: &[Observation],
    anchor: EvidenceAnchor,
) -> Result<AbsenceCertificate, LedgerError> {
    let authorized_sensors: BTreeSet<&str> = coverage.sensors.iter().map(String::as_str).collect();
    if let Some(observation) = observations.iter().find(|observation| {
        observation.class == class
            && observation.at >= coverage.start
            && observation.at < coverage.end
            && authorized_sensors.contains(observation.sensor.as_str())
    }) {
        return Err(LedgerError::PresenceObserved {
            sensor: observation.sensor.clone(),
            at: observation.at,
        });
    }
    let mut writer = CanonicalWriter::new("fss-absence-certificate-v1")?;
    writer.push_u8(class.code());
    writer.push_digest(coverage.digest);
    writer.push_u64(anchor.sequence);
    writer.push_digest(anchor.root);
    let digest = writer.digest()?;
    Ok(AbsenceCertificate {
        class,
        coverage,
        anchor,
        digest,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventDisposition {
    QuietCertified,
    BenignKnown,
    ProtectedResidual,
    CorroboratedThreat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventAssessment {
    pub disposition: EventDisposition,
    pub supporting_observations: Vec<Digest>,
    pub independent_failure_domains: Vec<String>,
    pub digest: Digest,
}

pub fn assess_event(
    observations: &[Observation],
    window_start: u64,
    window_end: u64,
) -> Result<EventAssessment, LedgerError> {
    if window_start >= window_end {
        return Err(LedgerError::InvalidInterval {
            start: window_start,
            end: window_end,
        });
    }
    let in_window: Vec<&Observation> = observations
        .iter()
        .filter(|observation| observation.at >= window_start && observation.at < window_end)
        .collect();
    let person: Vec<&Observation> = in_window
        .iter()
        .copied()
        .filter(|observation| observation.class == ObservationClass::UnknownPerson)
        .collect();
    let mut domains: BTreeMap<&str, &Observation> = BTreeMap::new();
    for observation in &person {
        domains
            .entry(observation.failure_domain.as_str())
            .and_modify(|existing| {
                if observation.confidence_basis_points > existing.confidence_basis_points {
                    *existing = observation;
                }
            })
            .or_insert(observation);
    }
    let disposition = if domains.len() >= 2 {
        EventDisposition::CorroboratedThreat
    } else if !person.is_empty() {
        EventDisposition::ProtectedResidual
    } else if in_window.iter().any(|observation| {
        matches!(
            observation.class,
            ObservationClass::Homeowner | ObservationClass::Raccoon
        )
    }) {
        EventDisposition::BenignKnown
    } else {
        EventDisposition::QuietCertified
    };
    let mut supporting_observations = Vec::new();
    for observation in domains.values() {
        supporting_observations.push(observation.digest()?);
    }
    if supporting_observations.is_empty() {
        for observation in &in_window {
            supporting_observations.push(observation.digest()?);
        }
        supporting_observations.sort_unstable();
        supporting_observations.dedup();
    }
    let independent_failure_domains: Vec<String> = domains.keys().map(|value| (*value).to_owned()).collect();
    let mut writer = CanonicalWriter::new("fss-event-assessment-v1")?;
    writer.push_u64(window_start);
    writer.push_u64(window_end);
    writer.push_u8(match disposition {
        EventDisposition::QuietCertified => 0,
        EventDisposition::BenignKnown => 1,
        EventDisposition::ProtectedResidual => 2,
        EventDisposition::CorroboratedThreat => 3,
    });
    writer.push_u64(
        u64::try_from(supporting_observations.len()).map_err(|_| DigestError::FieldTooLarge)?,
    );
    for digest in &supporting_observations {
        writer.push_digest(*digest);
    }
    writer.push_u64(
        u64::try_from(independent_failure_domains.len())
            .map_err(|_| DigestError::FieldTooLarge)?,
    );
    for domain in &independent_failure_domains {
        writer.push_str(domain)?;
    }
    let digest = writer.digest()?;
    Ok(EventAssessment {
        disposition,
        supporting_observations,
        independent_failure_domains,
        digest,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        CoverageCertificate, CoverageInterval, EventDisposition, EvidenceLedger, LedgerError,
        Observation, ObservationClass, RecordKind, assess_event, certify_absence,
    };
    use crate::digest::domain_digest;

    fn observation(sensor: &str, domain: &str, at: u64, class: ObservationClass) -> Observation {
        Observation {
            sensor: sensor.to_owned(),
            failure_domain: domain.to_owned(),
            at,
            class,
            confidence_basis_points: 9_000,
            source_digest: domain_digest("test-source", sensor.as_bytes()).expect("digest"),
        }
    }

    #[test]
    fn ledger_is_append_only_and_rejects_time_reversal() {
        let mut ledger = EvidenceLedger::default();
        let first = ledger
            .append(10, RecordKind::Observation, Vec::new(), b"first")
            .expect("first");
        let second = ledger
            .append(11, RecordKind::Event, vec![first.root], b"second")
            .expect("second");
        assert_eq!(second.sequence, 2);
        assert_ne!(first.root, second.root);
        assert!(matches!(
            ledger.append(9, RecordKind::Event, Vec::new(), b"past"),
            Err(LedgerError::TimeReversal { .. })
        ));
    }

    #[test]
    fn absence_requires_complete_continuous_coverage() {
        let required = BTreeSet::from(["cam-a".to_owned(), "cam-b".to_owned()]);
        let incomplete = vec![
            CoverageInterval::new("cam-a", "power-a", 0, 10, true).expect("interval"),
            CoverageInterval::new("cam-b", "power-b", 0, 4, true).expect("interval"),
            CoverageInterval::new("cam-b", "power-b", 5, 10, true).expect("interval"),
        ];
        assert!(matches!(
            CoverageCertificate::build(&required, &incomplete, 0, 10),
            Err(LedgerError::CoverageGap { .. })
        ));
        let complete = vec![
            CoverageInterval::new("cam-a", "power-a", 0, 10, true).expect("interval"),
            CoverageInterval::new("cam-b", "power-b", 0, 10, true).expect("interval"),
        ];
        let coverage = CoverageCertificate::build(&required, &complete, 0, 10).expect("coverage");
        let anchor = EvidenceLedger::default().anchor();
        certify_absence(ObservationClass::UnknownPerson, coverage, &[], anchor)
            .expect("absence");
    }

    #[test]
    fn observed_presence_blocks_absence_certificate() {
        let required = BTreeSet::from(["cam-a".to_owned()]);
        let intervals = vec![
            CoverageInterval::new("cam-a", "power-a", 0, 10, true).expect("interval")
        ];
        let coverage = CoverageCertificate::build(&required, &intervals, 0, 10).expect("coverage");
        let observations = vec![observation(
            "cam-a",
            "power-a",
            4,
            ObservationClass::UnknownPerson,
        )];
        assert!(matches!(
            certify_absence(
                ObservationClass::UnknownPerson,
                coverage,
                &observations,
                EvidenceLedger::default().anchor()
            ),
            Err(LedgerError::PresenceObserved { .. })
        ));
    }

    #[test]
    fn correlated_sources_do_not_fake_corroboration() {
        let observations = vec![
            observation("cam-a", "shared-power", 2, ObservationClass::UnknownPerson),
            observation("cam-b", "shared-power", 3, ObservationClass::UnknownPerson),
        ];
        let assessment = assess_event(&observations, 0, 10).expect("assessment");
        assert_eq!(assessment.disposition, EventDisposition::ProtectedResidual);
    }

    #[test]
    fn independent_failure_domains_corroborate() {
        let observations = vec![
            observation("cam-a", "power-a", 2, ObservationClass::UnknownPerson),
            observation("cam-b", "power-b", 3, ObservationClass::UnknownPerson),
        ];
        let assessment = assess_event(&observations, 0, 10).expect("assessment");
        assert_eq!(assessment.disposition, EventDisposition::CorroboratedThreat);
        assert_eq!(assessment.independent_failure_domains.len(), 2);
    }
}
