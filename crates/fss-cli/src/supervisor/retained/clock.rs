#![forbid(unsafe_code)]
//! Reopen the original time metadata without upgrading the source clock or its uncertainty.

use std::collections::BTreeMap;

use fss_core::{CanonicalDecode, CaptureInterval, ClockBasis, ContentDigest, SensorCapsule};
use fss_reference::ingest::package_event::{
    PackageDetectionRecord, PackageEventError, RecordFrame,
};
use fss_reference::ingest::recorded_decode::{
    MAX_RECORDED_DECODE_RECEIPT_BYTES, RecordedDecodeError,
};
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits};
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::{
    Error, MAX_RETAINED_SUPERVISOR_EVENTS, MAX_RETAINED_SUPERVISOR_OBSERVATIONS, Result,
    checkpoint, package_error,
};

struct ImportTime {
    root: ContentDigest,
    capture_time_label: String,
}

pub(super) struct SourceTime {
    pub(super) clock_basis: ClockBasis,
    pub(super) capture_time_label: String,
}

/// Each admitted capsule and import is read at most once under the deployment's shared cap.
#[derive(Default)]
pub(super) struct SourceClocks {
    capsules: BTreeMap<ContentDigest, SensorCapsule>,
    imports: BTreeMap<ContentDigest, ImportTime>,
    basis: Option<ClockBasis>,
}

impl SourceClocks {
    pub(super) fn read(
        &mut self,
        deployment: &ReferenceDeployment,
        record: &PackageDetectionRecord,
        frame: &RecordFrame,
        cx: &ReplayCx,
    ) -> Result<SourceTime> {
        checkpoint(cx)?;
        if !self.capsules.contains_key(&frame.capsule_digest) {
            if self.capsules.len() >= MAX_RETAINED_SUPERVISOR_OBSERVATIONS {
                return Err(Error::Limit("source capsule time metadata"));
            }
            let bytes = deployment
                .publisher()
                .spool()
                .read_bounded(frame.capsule_digest, MAX_RECORDED_DECODE_RECEIPT_BYTES)
                .map_err(|error| package_error(PackageEventError::Spool(error)))?;
            let capsule = SensorCapsule::from_canonical_bytes(&bytes)
                .map_err(|_| Error::Selection("source capsule time metadata is invalid"))?;
            self.capsules.insert(frame.capsule_digest, capsule);
        }
        let capsule = self
            .capsules
            .get(&frame.capsule_digest)
            .ok_or(Error::Selection(
                "source capsule time metadata is unavailable",
            ))?;
        let clock_basis = admit_clock(capsule, &frame.sensor_id, frame.capture, self.basis)?;
        if !self.imports.contains_key(&record.import_identity) {
            if self.imports.len() >= MAX_RETAINED_SUPERVISOR_EVENTS {
                return Err(Error::Limit("source import time metadata"));
            }
            let import = RetainedFileImport::open(
                deployment,
                record.import_identity,
                RetainedReadLimits::default(),
                cx,
            )
            .map_err(|error| {
                package_error(PackageEventError::Source(Box::new(
                    RecordedDecodeError::Source(Box::new(error)),
                )))
            })?;
            self.imports.insert(
                record.import_identity,
                ImportTime {
                    root: import.import_root(),
                    capture_time_label: import.manifest().capture_time_label.clone(),
                },
            );
        }
        let import = self
            .imports
            .get(&record.import_identity)
            .ok_or(Error::Selection(
                "source import time metadata is unavailable",
            ))?;
        if import.root != record.import_root
            || !matches!(
                import.capture_time_label.as_str(),
                "unknown" | "operator_assumption"
            )
        {
            return Err(Error::Selection("source import time metadata differs"));
        }
        self.basis = Some(clock_basis);
        Ok(SourceTime {
            clock_basis,
            capture_time_label: import.capture_time_label.clone(),
        })
    }
}

fn admit_clock(
    capsule: &SensorCapsule,
    expected_sensor: &str,
    expected_capture: CaptureInterval,
    previous: Option<ClockBasis>,
) -> Result<ClockBasis> {
    if capsule.sensor_id.as_str() != expected_sensor || capsule.capture != expected_capture {
        return Err(Error::Selection(
            "source capsule sensor or capture differs from the retained row",
        ));
    }
    match capsule.clock_basis {
        ClockBasis::DeviceMonotonic | ClockBasis::HostMonotonic => {
            return Err(Error::Selection(
                "source monotonic clock has no retained mapping",
            ));
        }
        ClockBasis::UtcDisciplined | ClockBasis::Estimated => {}
    }
    if previous.is_some_and(|basis| basis != capsule.clock_basis) {
        return Err(Error::Selection("selected source clock bases differ"));
    }
    Ok(capsule.clock_basis)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_core::{
        CanonicalEncode, CapsuleId, SensorId, SensorSourceBytesSpec, StreamId, TimestampNs,
    };

    type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn capsule(basis: ClockBasis) -> TestResult<SensorCapsule> {
        let original = SensorCapsule::from_source_bytes(SensorSourceBytesSpec {
            capsule_id: CapsuleId::parse("capsule:retained-clock")?,
            sensor_id: SensorId::parse("sensor:retained-clock")?,
            stream_id: StreamId::parse("stream:retained-clock")?,
            sequence: 0,
            capture: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
            receive_time: TimestampNs(30),
            clock_basis: basis,
            source: b"source",
            frame_count: 1,
            gap_before: false,
        })?;
        Ok(SensorCapsule::from_canonical_bytes(
            &original.canonical_bytes(),
        )?)
    }

    #[test]
    fn original_comparable_basis_and_capture_bounds_are_preserved() -> TestResult {
        for basis in [ClockBasis::UtcDisciplined, ClockBasis::Estimated] {
            let source = capsule(basis)?;
            assert_eq!(
                admit_clock(&source, source.sensor_id.as_str(), source.capture, None)?,
                basis
            );
            assert_eq!(
                admit_clock(
                    &source,
                    source.sensor_id.as_str(),
                    source.capture,
                    Some(basis),
                )?,
                basis
            );
            assert_eq!(source.capture.earliest, TimestampNs(10));
            assert_eq!(source.capture.latest, TimestampNs(20));
        }
        Ok(())
    }

    #[test]
    fn monotonic_clocks_require_a_mapping() -> TestResult {
        for basis in [ClockBasis::DeviceMonotonic, ClockBasis::HostMonotonic] {
            let source = capsule(basis)?;
            assert!(matches!(
                admit_clock(&source, source.sensor_id.as_str(), source.capture, None),
                Err(Error::Selection(_))
            ));
        }
        Ok(())
    }

    #[test]
    fn estimated_and_utc_bases_are_not_interchangeable() -> TestResult {
        for (current, previous) in [
            (ClockBasis::Estimated, ClockBasis::UtcDisciplined),
            (ClockBasis::UtcDisciplined, ClockBasis::Estimated),
        ] {
            let source = capsule(current)?;
            assert!(matches!(
                admit_clock(
                    &source,
                    source.sensor_id.as_str(),
                    source.capture,
                    Some(previous),
                ),
                Err(Error::Selection(_))
            ));
        }
        Ok(())
    }

    #[test]
    fn source_sensor_and_capture_cannot_be_rebound() -> TestResult {
        let source = capsule(ClockBasis::Estimated)?;
        assert!(matches!(
            admit_clock(&source, "sensor:another", source.capture, None),
            Err(Error::Selection(_))
        ));
        let narrower = CaptureInterval::new(TimestampNs(15), TimestampNs(15))?;
        assert!(matches!(
            admit_clock(&source, source.sensor_id.as_str(), narrower, None),
            Err(Error::Selection(_))
        ));
        Ok(())
    }
}
