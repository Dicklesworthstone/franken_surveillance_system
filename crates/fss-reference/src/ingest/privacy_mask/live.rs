#![forbid(unsafe_code)]
//! The sensor's current retained mask on live, recording and replay decode paths.
//!
//! Live HTTP acquisition (the learned HOG and RGB compositions), archived HTTP replay, HTTP
//! recording, `check-http` and RGB evidence replay never carry a sensor capsule of their own. The
//! owner names the sensor with a [`SensorMask`] (the sensor plus the deployment that retains its
//! `privacy_mask_policy` authority); each consumer resolves the sensor's *current* binding when it
//! decodes a frame, so a policy retained mid-capture applies from the next decoded frame and no
//! earlier receipt is rewritten.
//!
//! Enforcement is the single implementation in [`super::enforce`]: masked luma samples take
//! [`super::MASK_FILL_LUMA`], masked RGB pixels [`super::MASK_FILL_RGB`]; the owner's per-pixel
//! permission mask must also deny every masked pixel, or the frame is refused as unmasked access
//! (`ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001`). Raw source custody (retained HTTP/RTSP payloads,
//! original JPEG bytes inside an evidence envelope) stays unmasked custody; every derivation from
//! it is masked.
//!
//! Identity rule: without a policy every receipt, digest and record keeps its existing bytes and
//! carries the explicit no-policy marker as a typed field; with a policy the binding is folded
//! into the derived identity ([`MaskBinding::fold_identity`]), so lineages of different mask
//! generations never share an identity.

use std::fmt;

use fss_codec_mjpeg::{DecodeReceipt, DecodedLuma};
use fss_core::{ContentDigest, SensorId};
use fss_twin::redaction::{LumaRedaction, RedactionRefused};

use super::{MaskBinding, PrivacyMaskError, current_mask, lineage_digest};
use crate::ReferenceDeployment;

/// The explicit no-policy binding as a `'static` value, for inputs that borrow their binding
/// (laboratory fixtures and consumers of a sensor without a retained policy).
pub static NO_POLICY: MaskBinding = MaskBinding::NoPolicy;

/// The sensor whose current retained mask policy a live or replay consumer applies, and the
/// deployment that retains that authority. Naming the sensor is an owner declaration, like a
/// capture interval; the policy itself is always read from retained authority, never supplied.
#[derive(Clone, Copy)]
pub struct SensorMask<'a> {
    deployment: &'a ReferenceDeployment,
    sensor: &'a SensorId,
}

impl fmt::Debug for SensorMask<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SensorMask")
            .field("sensor", &self.sensor.as_str())
            .finish_non_exhaustive()
    }
}

impl<'a> SensorMask<'a> {
    /// Binds `sensor` to the deployment retaining its mask authority. Performs no I/O.
    #[must_use]
    pub fn new(deployment: &'a ReferenceDeployment, sensor: &'a SensorId) -> Self {
        Self { deployment, sensor }
    }

    /// The named sensor.
    #[must_use]
    pub fn sensor(&self) -> &SensorId {
        self.sensor
    }

    /// The sensor's current binding at this moment: its newest retained policy generation or
    /// the explicit no-policy marker. Damaged custody fails closed.
    pub fn resolve(&self) -> Result<MaskBinding, PrivacyMaskError> {
        current_mask(self.deployment, self.sensor)
    }
}

/// Copyable projection of a [`PrivacyMaskError`] for owners whose error types are `Copy`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaskRefusal {
    /// The request would serve or analyse pixels the sensor's current policy masks.
    UnmaskedAccess,
    /// The decoded frame differs from the policy's declared stream resolution.
    Resolution {
        /// Resolution the policy was declared for.
        declared: [u32; 2],
        /// Resolution of the decoded frame or permission grid.
        decoded: [u32; 2],
    },
    /// The mask could not be resolved from retained authority (damaged or unreadable custody).
    Unavailable,
}

impl MaskRefusal {
    /// Registered stable identity (registries/ERRORS.md), the same as the source error's.
    #[must_use]
    pub const fn stable_id(self) -> &'static str {
        match self {
            Self::UnmaskedAccess => "ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001",
            Self::Resolution { .. } => "ERR-PRIVACY-MASK-RESOLUTION-001",
            Self::Unavailable => "ERR-PRIVACY-MASK-001",
        }
    }
}

impl From<&PrivacyMaskError> for MaskRefusal {
    fn from(error: &PrivacyMaskError) -> Self {
        match error {
            PrivacyMaskError::UnmaskedAccessRefused => Self::UnmaskedAccess,
            PrivacyMaskError::ResolutionMismatch { declared, decoded } => Self::Resolution {
                declared: *declared,
                decoded: *decoded,
            },
            _ => Self::Unavailable,
        }
    }
}

impl From<PrivacyMaskError> for MaskRefusal {
    fn from(error: PrivacyMaskError) -> Self {
        Self::from(&error)
    }
}

impl fmt::Display for MaskRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "privacy mask refused the frame ({})", self.stable_id())
    }
}

impl std::error::Error for MaskRefusal {}

impl MaskBinding {
    /// Refuses ([`PrivacyMaskError::UnmaskedAccessRefused`]) an owner permission grid that admits
    /// any pixel this binding masks: analysing such a pixel as visible would be unmasked access.
    /// Without a policy every grid is accepted. The grid must match the declared resolution.
    pub fn refuse_admitted(
        &self,
        allowed: &[u8],
        dimensions: [u32; 2],
    ) -> Result<(), PrivacyMaskError> {
        if self.policy().is_none() {
            return Ok(());
        }
        let permitted = self.allowed(dimensions)?;
        if permitted.len() != allowed.len() {
            return Err(PrivacyMaskError::InvalidRecord);
        }
        if permitted
            .iter()
            .zip(allowed)
            .any(|(policy, owner)| *policy == 0 && *owner != 0)
        {
            return Err(PrivacyMaskError::UnmaskedAccessRefused);
        }
        Ok(())
    }

    /// Folds this binding into a derived 32-byte identity when a policy applies; without a
    /// policy the identity is returned unchanged (its bytes predate masking and stay pinned).
    #[must_use]
    pub fn fold_identity(&self, label: &str, base: [u8; 32]) -> [u8; 32] {
        match self.policy() {
            None => base,
            Some(_) => lineage_digest(
                label,
                ContentDigest::new(fss_core::DigestAlgorithm::Sha256, base),
                self.digest(),
            )
            .bytes(),
        }
    }

    /// Masks a complete native luma decode ([`Self::apply_luma`]) and re-receipts it: the
    /// returned receipt's `luma_sha256` names the masked plane, exactly as a retained decode's.
    pub fn mask_luma(&self, image: DecodedLuma) -> Result<MaskedLuma, PrivacyMaskError> {
        let dimensions = image.dimensions();
        let mut pixels = image.pixels().to_vec();
        let mut receipt = image.receipt();
        drop(image);
        if self.policy().is_some() {
            self.apply_luma(&mut pixels, dimensions)?;
            receipt = DecodeReceipt {
                luma_sha256: ContentDigest::sha256(&pixels).bytes(),
                ..receipt
            };
        }
        Ok(MaskedLuma {
            pixels,
            dimensions,
            receipt,
            mask_policy: self.policy_digest(),
            mask_generation: self.generation(),
        })
    }

    /// This binding as a decoded-plane redaction for the native JPEG pipeline: `None` without
    /// a policy (the unredacted pipeline, whose fingerprints stay unchanged).
    #[must_use]
    pub fn luma_redaction(&self) -> Option<&dyn LumaRedaction> {
        self.policy().map(|_| self as &dyn LumaRedaction)
    }

    /// Identity a redacted native JPEG decode records for this binding (`None` without policy).
    #[must_use]
    pub fn redaction_identity(&self) -> Option<[u8; 32]> {
        self.luma_redaction().map(LumaRedaction::identity)
    }
}

impl LumaRedaction for MaskBinding {
    fn identity(&self) -> [u8; 32] {
        self.digest().bytes()
    }
    fn redact(&self, luma: &mut [u8], dimensions: [u32; 2]) -> Result<(), RedactionRefused> {
        self.apply_luma(luma, dimensions)
            .map_err(|_| RedactionRefused)
    }
}

/// A native luma decode after the sensor's mask was applied; the only decoded-luma form live
/// and recording consumers return.
pub struct MaskedLuma {
    pixels: Vec<u8>,
    dimensions: [u32; 2],
    receipt: DecodeReceipt,
    mask_policy: Option<ContentDigest>,
    mask_generation: Option<u64>,
}

impl fmt::Debug for MaskedLuma {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MaskedLuma")
            .field("dimensions", &self.dimensions)
            .field("mask_policy", &self.mask_policy)
            .finish_non_exhaustive()
    }
}

impl MaskedLuma {
    /// Coded dimensions.
    #[must_use]
    pub fn dimensions(&self) -> [u32; 2] {
        self.dimensions
    }
    /// Tight row-major luma; masked samples hold the fixed fill.
    #[must_use]
    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }
    /// Codec receipt whose `luma_sha256` names [`Self::pixels`].
    #[must_use]
    pub fn receipt(&self) -> DecodeReceipt {
        self.receipt
    }
    /// Applied policy digest, or `None`: the explicit no-policy marker.
    #[must_use]
    pub fn mask_policy(&self) -> Option<ContentDigest> {
        self.mask_policy
    }
    /// Ledger generation of the applied policy, if any.
    #[must_use]
    pub fn mask_generation(&self) -> Option<u64> {
        self.mask_generation
    }
}

#[cfg(test)]
pub(crate) mod fixture;

#[cfg(test)]
mod tests;
