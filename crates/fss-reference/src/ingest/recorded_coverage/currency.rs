#![forbid(unsafe_code)]
//! Current-authority checks for *new uses* of version-6 coverage approvals.
//!
//! Historical decoding is deliberately independent of current authority. Approval checking
//! and retention are not: an embedded screening receipt is not a lease on the privacy or
//! calibration generation. These checks run before staging and before the idempotent return.

use std::collections::BTreeMap;

use fss_core::{ContentDigest, SensorId};
use fss_geometry::CameraGeneration;

use super::{CoverageError, CoverageRecord, GenerationCurrency, PoseProvenance, PoseUncertainty};
use crate::ReferenceDeployment;
use crate::ingest::calibration_adoption::{RetainedAdoption, adopted_currency, retained_adoptions};
use crate::ingest::privacy_mask::current_mask;

fn refused(record: &CoverageRecord, reason: &'static str) -> CoverageError {
    CoverageError::Currency {
        sensor: record.sensor_id.clone(),
        reason,
    }
}

fn same_privacy(
    expected_digest: ContentDigest,
    expected_generation: u64,
    current_digest: ContentDigest,
    current_generation: u64,
) -> bool {
    expected_digest == current_digest && expected_generation == current_generation
}

fn same_adoption(currency: GenerationCurrency, current: Option<ContentDigest>) -> bool {
    match (currency, current) {
        (GenerationCurrency::AdoptedCurrent { receipt }, Some(actual)) => receipt == actual,
        (GenerationCurrency::Unasserted | GenerationCurrency::OwnerAsserted, None) => true,
        _ => false,
    }
}

/// Revalidation is scoped to the record's actual sensor/camera, not the global ledger head.
/// Unrelated event publications do not invalidate an otherwise unchanged approval.
pub(super) fn check_guard_current(
    deployment: &ReferenceDeployment,
    record: &CoverageRecord,
) -> Result<(), CoverageError> {
    let Some(receipt) = record
        .pose_uncertainty
        .as_ref()
        .and_then(PoseUncertainty::guard_receipt)
    else {
        // Legacy canonical bytes and their existing approval semantics are not reinterpreted.
        return Ok(());
    };
    // The caller validates the enclosing record first, including every receipt binding.
    let sensor = SensorId::parse(&record.sensor_id)?;
    let mask = current_mask(deployment, &sensor)
        .map_err(|_| refused(record, "current privacy authority could not be verified"))?;
    if !same_privacy(
        receipt.privacy_digest(),
        receipt.privacy_generation(),
        mask.digest(),
        mask.generation().unwrap_or(0),
    ) {
        return Err(refused(
            record,
            "privacy changed after full-camera screening; reanalyse",
        ));
    }
    let Some(PoseProvenance::SiteCalibration { currency, .. }) = record.pose_provenance else {
        return Err(refused(
            record,
            "full-camera receipt has no calibration provenance",
        ));
    };
    let adoptions = retained_adoptions(deployment).map_err(|_| {
        refused(
            record,
            "current calibration authority could not be verified",
        )
    })?;
    check_adoption_binding(
        &sensor,
        receipt.camera(),
        receipt.calibration_digest(),
        currency,
        &adoptions,
    )
    .map_err(|reason| refused(record, reason))?;
    Ok(())
}

// This is also checked in reverse: a newly invented camera handle must not evade
// the retained adoption of the very same sensor under its actual camera handle.
fn check_adoption_binding(
    sensor: &SensorId,
    camera: CameraGeneration,
    calibration: ContentDigest,
    currency: GenerationCurrency,
    adoptions: &BTreeMap<u64, Vec<RetainedAdoption>>,
) -> Result<(), &'static str> {
    for (handle, history) in adoptions {
        if *handle != camera.camera
            && history
                .last()
                .is_some_and(|current| current.receipt.sensor_id == *sensor)
        {
            return Err("sensor is adopted under a different camera; reanalyse");
        }
    }
    let current = adopted_currency(adoptions, calibration, sensor.as_str(), camera, || {
        Ok(sensor.clone())
    })
    .map_err(|_| "calibration or sensor adoption changed; reanalyse")?;
    if !same_adoption(currency, current.map(|adoption| adoption.digest)) {
        return Err("calibration adoption basis changed; reanalyse");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privacy_identity_and_generation_are_both_required() {
        let a = ContentDigest::sha256(b"mask-a");
        let b = ContentDigest::sha256(b"mask-b");
        for expected in [a, b] {
            for actual in [a, b] {
                for before in [0, 1, 2, u64::MAX] {
                    for now in [0, 1, 2, u64::MAX] {
                        assert_eq!(
                            same_privacy(expected, before, actual, now),
                            expected == actual && before == now,
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn owner_assertions_do_not_silently_become_retained_adoptions() {
        let receipt = ContentDigest::sha256(b"adoption");
        for currency in [
            GenerationCurrency::Unasserted,
            GenerationCurrency::OwnerAsserted,
        ] {
            assert!(same_adoption(currency, None));
            assert!(!same_adoption(currency, Some(receipt)));
        }
    }

    #[test]
    fn adopted_receipt_must_still_be_present_and_exact() {
        let a = ContentDigest::sha256(b"adoption-a");
        let b = ContentDigest::sha256(b"adoption-b");
        let currency = GenerationCurrency::AdoptedCurrent { receipt: a };
        assert!(same_adoption(currency, Some(a)));
        assert!(!same_adoption(currency, Some(b)));
        assert!(!same_adoption(currency, None));
    }

    #[test]
    fn exact_current_adoption_is_accepted_and_each_binding_drift_is_refused()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::ingest::calibration_adoption::AdoptionReceipt;
        let sensor = SensorId::parse("sensor:front")?;
        let camera = CameraGeneration {
            camera: 1,
            intrinsics: 2,
            extrinsics: 3,
        };
        let calibration = ContentDigest::sha256(b"calibration");
        let receipt = AdoptionReceipt {
            adoption: 1,
            camera_handle: 1,
            camera_name: "front".to_owned(),
            sensor_id: sensor.clone(),
            calibration_digest: calibration,
            twin_package: ContentDigest::sha256(b"twin"),
            intrinsics_generation: 2,
            extrinsics_generation: 3,
            supersedes: None,
        };
        let retained = RetainedAdoption {
            digest: receipt.digest(),
            receipt,
            committed_sequence: 10,
        };
        let currency = GenerationCurrency::AdoptedCurrent {
            receipt: retained.digest,
        };
        let good = BTreeMap::from([(camera.camera, vec![retained.clone()])]);
        assert!(check_adoption_binding(&sensor, camera, calibration, currency, &good).is_ok());
        for changed in 0..6 {
            let mut adoption = retained.clone();
            match changed {
                0 => adoption.receipt.sensor_id = SensorId::parse("sensor:other")?,
                1 => {
                    adoption.receipt.calibration_digest = ContentDigest::sha256(b"new calibration")
                }
                2 => adoption.receipt.intrinsics_generation += 1,
                3 => adoption.receipt.extrinsics_generation += 1,
                4 => adoption.digest = ContentDigest::sha256(b"different receipt"),
                _ => adoption.receipt.camera_handle = 2,
            }
            if changed != 4 {
                adoption.digest = adoption.receipt.digest();
            }
            let map = BTreeMap::from([(adoption.receipt.camera_handle, vec![adoption])]);
            assert!(
                check_adoption_binding(&sensor, camera, calibration, currency, &map).is_err(),
                "accepted binding change {changed}"
            );
        }
        // Without retained adoption, an explicit owner assertion remains an assertion.
        assert!(
            check_adoption_binding(
                &sensor,
                camera,
                calibration,
                GenerationCurrency::OwnerAsserted,
                &BTreeMap::new()
            )
            .is_ok()
        );
        // A camera with no history cannot reuse a sensor already owned by another camera.
        let invented = CameraGeneration {
            camera: 99,
            ..camera
        };
        assert!(
            check_adoption_binding(
                &sensor,
                invented,
                calibration,
                GenerationCurrency::OwnerAsserted,
                &good
            )
            .is_err()
        );
        Ok(())
    }
}
