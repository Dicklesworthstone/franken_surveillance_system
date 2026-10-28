#![forbid(unsafe_code)]
//! Immutable owner withdrawal records. This codec depends only on `fss-core` and `std`.

use std::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, DigestAlgorithm, ObjectId, SensorId,
};

/// Canonical domain of an immutable calibration invalidation receipt.
pub const INVALIDATION_RECEIPT_DOMAIN: &str = "fss.calibration_invalidation.v1";
/// Canonical domain of the exact owner approval retained as the authority witness.
pub const INVALIDATION_APPROVAL_DOMAIN: &str = "fss.calibration_invalidation_approval.v1";
/// Reserved authority object namespace; one immutable object per adopted receipt.
pub const INVALIDATION_OBJECT_PREFIX: &str = "object:calibration-invalidation:";
/// Receipt payload limit, checked before allocation by retained readers.
pub const MAX_INVALIDATION_RECEIPT_BYTES: usize = 2048;
/// Approval payload limit, checked before allocation by retained readers.
pub const MAX_INVALIDATION_APPROVAL_BYTES: usize = 256;
/// The receipt records owner authority, not an independently measured physical change.
pub const INVALIDATION_CLAIM: &str = "owner_withdrawal_not_a_physical_observation";
const MAGIC: &[u8; 8] = b"FSSINV01";

/// Bounded reasons for withdrawing an exact adopted camera calibration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidationReason {
    /// The camera's physical pose changed.
    CameraMoved,
    /// Lens, zoom, or focus changed.
    OpticsChanged,
    /// The image crop, scale, or pixel domain changed.
    CropChanged,
    /// Firmware changed the camera model or its interpretation.
    FirmwareChanged,
    /// Owner-observed residuals no longer support the calibration.
    ResidualDrift,
    /// The owner withdraws the calibration without asserting a physical diagnosis.
    OwnerRevoked,
}

impl InvalidationReason {
    /// Parses one exact documented reason token.
    pub fn parse(value: &str) -> Result<Self, InvalidationCodecError> {
        match value {
            "camera_moved" => Ok(Self::CameraMoved),
            "optics_changed" => Ok(Self::OpticsChanged),
            "crop_changed" => Ok(Self::CropChanged),
            "firmware_changed" => Ok(Self::FirmwareChanged),
            "residual_drift" => Ok(Self::ResidualDrift),
            "owner_revoked" => Ok(Self::OwnerRevoked),
            _ => Err(InvalidationCodecError::InvalidRecord(
                "unknown invalidation reason",
            )),
        }
    }

    /// Stable reason token used in approval and reporting.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CameraMoved => "camera_moved",
            Self::OpticsChanged => "optics_changed",
            Self::CropChanged => "crop_changed",
            Self::FirmwareChanged => "firmware_changed",
            Self::ResidualDrift => "residual_drift",
            Self::OwnerRevoked => "owner_revoked",
        }
    }
}

/// A malformed, noncanonical, or incorrectly bound withdrawal receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvalidationCodecError {
    /// A receipt invariant was violated.
    InvalidRecord(&'static str),
    /// An underlying canonical field is invalid.
    Contract(ContractError),
}

impl fmt::Display for InvalidationCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRecord(reason) => write!(f, "calibration invalidation: {reason}"),
            Self::Contract(error) => write!(f, "calibration invalidation: {error}"),
        }
    }
}
impl std::error::Error for InvalidationCodecError {}
impl From<ContractError> for InvalidationCodecError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}

pub(super) fn sha256_only(digest: ContentDigest) -> Result<(), ContractError> {
    if digest.algorithm() == DigestAlgorithm::Sha256 {
        Ok(())
    } else {
        Err(ContractError::UnsupportedDigestAlgorithm)
    }
}

/// A deployment/restore domain independent of unrelated authority appends.
#[must_use]
pub fn authority_domain(site_lineage: &str, ledger_epoch: u64) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text("fss.calibration_invalidation_authority.v1");
    e.text(site_lineage);
    e.u64(ledger_epoch);
    ContentDigest::sha256(&e.finish())
}

/// Exact immutable withdrawal of one adopted receipt, including its original camera bindings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidationReceipt {
    /// Deployment lineage and ledger epoch under which the owner approved withdrawal.
    pub authority_domain: ContentDigest,
    /// Camera's adoption generation being withdrawn.
    pub adoption: u64,
    /// Exact retained adoption receipt, not merely a camera name.
    pub adoption_digest: ContentDigest,
    /// Property-local camera handle.
    pub camera_handle: u64,
    /// Adopted physical source identity.
    pub sensor_id: SensorId,
    /// Exact calibration identity withdrawn for this camera.
    pub calibration_digest: ContentDigest,
    /// Withdrawn intrinsics generation.
    pub intrinsics_generation: u64,
    /// Withdrawn extrinsics generation.
    pub extrinsics_generation: u64,
    /// Owner's bounded diagnosis; it does not assert automatic detection.
    pub reason: InvalidationReason,
    /// Optional retained same-sensor capsule payload, verified before approval is consumed.
    /// Later source deletion cannot undo the owner withdrawal.
    pub evidence: Option<ContentDigest>,
}

impl InvalidationReceipt {
    /// Checks all local immutable-record invariants.
    pub fn validate(&self) -> Result<(), InvalidationCodecError> {
        if self.adoption == 0
            || self.camera_handle == 0
            || self.intrinsics_generation == 0
            || self.extrinsics_generation == 0
        {
            return Err(InvalidationCodecError::InvalidRecord(
                "adoption, handle and generations must be nonzero",
            ));
        }
        for digest in [
            self.authority_domain,
            self.adoption_digest,
            self.calibration_digest,
        ] {
            sha256_only(digest)?;
        }
        if let Some(evidence) = self.evidence {
            sha256_only(evidence)?;
        }
        Ok(())
    }

    /// Exact versioned canonical payload; does not reinterpret adoption receipt bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        e.bytes(MAGIC);
        e.u32(1);
        e.text(INVALIDATION_RECEIPT_DOMAIN);
        e.digest(self.authority_domain);
        e.u64(self.adoption);
        e.digest(self.adoption_digest);
        e.u64(self.camera_handle);
        self.sensor_id.encode_canonical(&mut e);
        e.digest(self.calibration_digest);
        e.u64(self.intrinsics_generation);
        e.u64(self.extrinsics_generation);
        e.text(self.reason.as_str());
        e.bool(self.evidence.is_some());
        if let Some(evidence) = self.evidence {
            e.digest(evidence);
        }
        e.finish()
    }

    /// SHA-256 of the exact canonical payload.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.to_bytes())
    }

    /// Strict canonical decoder against the retained payload digest.
    pub fn from_bytes(
        bytes: &[u8],
        expected: ContentDigest,
    ) -> Result<Self, InvalidationCodecError> {
        if bytes.len() > MAX_INVALIDATION_RECEIPT_BYTES || ContentDigest::sha256(bytes) != expected
        {
            return Err(InvalidationCodecError::InvalidRecord(
                "receipt size or authority digest mismatch",
            ));
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.bytes()? != MAGIC || d.u32()? != 1 || d.text()? != INVALIDATION_RECEIPT_DOMAIN {
            return Err(InvalidationCodecError::InvalidRecord(
                "unknown invalidation record format",
            ));
        }
        let value = Self {
            authority_domain: d.digest()?,
            adoption: d.u64()?,
            adoption_digest: d.digest()?,
            camera_handle: d.u64()?,
            sensor_id: SensorId::decode_canonical(&mut d)?,
            calibration_digest: d.digest()?,
            intrinsics_generation: d.u64()?,
            extrinsics_generation: d.u64()?,
            reason: InvalidationReason::parse(d.text()?)?,
            evidence: if d.bool()? { Some(d.digest()?) } else { None },
        };
        d.ensure_finished()?;
        value.validate()?;
        if value.to_bytes() != bytes {
            return Err(InvalidationCodecError::InvalidRecord(
                "noncanonical invalidation receipt",
            ));
        }
        Ok(value)
    }

    /// Stable machine-readable receipt, with the owner-authority limitation explicit.
    #[must_use]
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                "{{\"receipt_digest\":\"{}\",\"authority_domain\":\"{}\",",
                "\"adoption\":{},\"adoption_digest\":\"{}\",\"camera_handle\":{},",
                "\"sensor_id\":\"{}\",\"calibration_digest\":\"{}\",",
                "\"intrinsics_generation\":{},\"extrinsics_generation\":{},",
                "\"reason\":\"{}\",\"evidence\":{},\"claim\":\"{}\"}}"
            ),
            self.digest(),
            self.authority_domain,
            self.adoption,
            self.adoption_digest,
            self.camera_handle,
            self.sensor_id,
            self.calibration_digest,
            self.intrinsics_generation,
            self.extrinsics_generation,
            self.reason.as_str(),
            self.evidence
                .map_or_else(|| "null".to_owned(), |d| format!("\"{d}\"")),
            INVALIDATION_CLAIM,
        )
    }
}

/// Exact reviewed approval material, staged as the invalidation delta's witness.
#[must_use]
pub fn approval_bytes(receipt: &InvalidationReceipt) -> Vec<u8> {
    let mut e = CanonicalEncoder::new();
    e.text(INVALIDATION_APPROVAL_DOMAIN);
    e.digest(receipt.digest());
    e.finish()
}

/// Owner approval binds every receipt field and its deployment/restore domain.
#[must_use]
pub fn approval_digest(receipt: &InvalidationReceipt) -> ContentDigest {
    ContentDigest::sha256(&approval_bytes(receipt))
}

/// Legacy approvals remain byte-identical when there is no withdrawal. A recovery approval
/// binds the exact invalidation so an approval issued before withdrawal cannot restore currency.
#[must_use]
pub fn bind_recovery_approval(
    approval: ContentDigest,
    invalidations: impl IntoIterator<Item = (u64, Option<ContentDigest>)>,
) -> ContentDigest {
    let invalidations: Vec<_> = invalidations
        .into_iter()
        .filter_map(|(camera, invalidation)| invalidation.map(|digest| (camera, digest)))
        .collect();
    if invalidations.is_empty() {
        return approval;
    }
    let mut e = CanonicalEncoder::new();
    e.text("fss.calibration_adoption_recovery_approval.v1");
    e.digest(approval);
    e.u64(invalidations.len() as u64);
    for (camera, invalidation) in invalidations {
        e.u64(camera);
        e.digest(invalidation);
    }
    ContentDigest::sha256(&e.finish())
}

/// Reserved ledger object for one exact immutable adoption withdrawal.
pub fn invalidation_object_id(adoption_digest: ContentDigest) -> Result<ObjectId, ContractError> {
    sha256_only(adoption_digest)?;
    let digest = adoption_digest.to_string();
    let hex = digest
        .strip_prefix("sha256:")
        .ok_or(ContractError::InvalidDigest)?;
    ObjectId::parse(format!("{INVALIDATION_OBJECT_PREFIX}{hex}"))
}

/// One verified invalidation retained in a committed authority prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedInvalidation {
    /// Exact decoded owner withdrawal.
    pub receipt: InvalidationReceipt,
    /// Receipt payload digest.
    pub digest: ContentDigest,
    /// Commit sequence that made this withdrawal effective.
    pub committed_sequence: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn sample() -> Result<InvalidationReceipt, ContractError> {
        Ok(InvalidationReceipt {
            authority_domain: authority_domain("site:front", 2),
            adoption: 3,
            adoption_digest: ContentDigest::sha256(b"adoption"),
            camera_handle: 7,
            sensor_id: SensorId::parse("sensor:front")?,
            calibration_digest: ContentDigest::sha256(b"calibration"),
            intrinsics_generation: 4,
            extrinsics_generation: 5,
            reason: InvalidationReason::CameraMoved,
            evidence: Some(ContentDigest::sha256(b"capsule")),
        })
    }

    #[test]
    fn strict_codec_rejects_tampering_suffixes_and_unknown_versions() -> TestResult {
        let value = sample()?;
        let bytes = value.to_bytes();
        assert_eq!(
            InvalidationReceipt::from_bytes(&bytes, value.digest())?,
            value
        );
        for index in 0..bytes.len() {
            let mut tampered = bytes.clone();
            tampered[index] ^= 1;
            assert!(InvalidationReceipt::from_bytes(&tampered, value.digest()).is_err());
        }
        for index in [8, 16, 28] {
            let mut unknown = bytes.clone();
            unknown[index] ^= 1;
            assert!(
                InvalidationReceipt::from_bytes(&unknown, ContentDigest::sha256(&unknown)).is_err()
            );
        }
        let mut suffixed = bytes;
        suffixed.push(0);
        assert!(
            InvalidationReceipt::from_bytes(&suffixed, ContentDigest::sha256(&suffixed)).is_err()
        );
        Ok(())
    }

    #[test]
    fn reasons_are_bounded_and_every_reviewed_field_changes_approval() -> TestResult {
        let value = sample()?;
        let approved = approval_digest(&value);
        for reason in [
            InvalidationReason::CameraMoved,
            InvalidationReason::OpticsChanged,
            InvalidationReason::CropChanged,
            InvalidationReason::FirmwareChanged,
            InvalidationReason::ResidualDrift,
            InvalidationReason::OwnerRevoked,
        ] {
            assert_eq!(InvalidationReason::parse(reason.as_str())?, reason);
            let changed = InvalidationReceipt {
                reason,
                ..value.clone()
            };
            assert_eq!(
                approval_digest(&changed) == approved,
                reason == value.reason
            );
        }
        for unknown in [
            "",
            "CameraMoved",
            "camera_moved ",
            "automatic_detection",
            "bad\nreason",
        ] {
            assert!(InvalidationReason::parse(unknown).is_err());
        }
        for index in 0..10 {
            let mut changed = value.clone();
            match index {
                0 => changed.authority_domain = authority_domain("site:other", 2),
                1 => changed.authority_domain = authority_domain("site:front", 3),
                2 => changed.adoption += 1,
                3 => changed.adoption_digest = ContentDigest::sha256(b"other adoption"),
                4 => changed.camera_handle += 1,
                5 => changed.sensor_id = SensorId::parse("sensor:other")?,
                6 => changed.calibration_digest = ContentDigest::sha256(b"other calibration"),
                7 => changed.intrinsics_generation += 1,
                8 => changed.extrinsics_generation += 1,
                _ => changed.evidence = None,
            }
            assert_ne!(approval_digest(&changed), approved, "field {index}");
        }
        assert_eq!(ContentDigest::sha256(&approval_bytes(&value)), approved);
        assert_ne!(approved, value.digest());
        Ok(())
    }

    #[test]
    fn withdrawal_requires_fresh_recovery_approval_without_changing_legacy_approvals() -> TestResult
    {
        let old_approval = ContentDigest::sha256(b"pre-withdrawal adoption approval");
        let withdrawal = sample()?.digest();
        assert_eq!(bind_recovery_approval(old_approval, []), old_approval);
        assert_eq!(
            bind_recovery_approval(old_approval, [(7, None), (9, None)]),
            old_approval
        );
        let recovery = bind_recovery_approval(old_approval, [(7, Some(withdrawal)), (9, None)]);
        assert_ne!(recovery, old_approval);
        assert_eq!(
            recovery,
            bind_recovery_approval(old_approval, [(7, Some(withdrawal))])
        );
        assert_ne!(
            recovery,
            bind_recovery_approval(old_approval, [(9, Some(withdrawal))])
        );
        assert_ne!(
            recovery,
            bind_recovery_approval(
                old_approval,
                [(7, Some(ContentDigest::sha256(b"different withdrawal")))]
            )
        );
        assert_ne!(
            recovery,
            bind_recovery_approval(
                ContentDigest::sha256(b"different proposal"),
                [(7, Some(withdrawal))]
            )
        );
        assert_ne!(
            recovery,
            bind_recovery_approval(old_approval, [(7, Some(withdrawal)), (9, Some(withdrawal))])
        );
        Ok(())
    }

    #[test]
    fn zero_generations_and_oversized_receipts_fail() -> TestResult {
        let value = sample()?;
        for index in 0..4 {
            let mut changed = value.clone();
            match index {
                0 => changed.adoption = 0,
                1 => changed.camera_handle = 0,
                2 => changed.intrinsics_generation = 0,
                _ => changed.extrinsics_generation = 0,
            }
            let bytes = changed.to_bytes();
            assert!(
                InvalidationReceipt::from_bytes(&bytes, ContentDigest::sha256(&bytes)).is_err()
            );
        }
        let bytes = vec![0; MAX_INVALIDATION_RECEIPT_BYTES + 1];
        assert!(InvalidationReceipt::from_bytes(&bytes, ContentDigest::sha256(&bytes)).is_err());
        assert!(
            invalidation_object_id(value.adoption_digest)?
                .as_str()
                .starts_with(INVALIDATION_OBJECT_PREFIX)
        );
        Ok(())
    }
}
