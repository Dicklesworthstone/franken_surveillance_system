#![forbid(unsafe_code)]
//! Exact replay recipe and approval material, independent of runtime and media implementations.
use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, ContractError, DigestAlgorithm};

/// Canonical bounded replay recipe domain.
pub const MONITOR_PACKAGE_DOMAIN: &str = "fss.recorded_calibration_monitor_package.v1";
/// Explicit approval for the complete measured receipt and derived graph.
pub const MONITOR_APPROVAL_DOMAIN: &str = "fss.recorded_calibration_monitor_approval.v1";
/// Maximum complete replay recipe bytes before decoding or allocation.
pub const MAX_MONITOR_RECIPE_BYTES: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Recipe {
    pub calibration_object: ContentDigest,
    pub calibration_identity: ContentDigest,
    pub camera_input: ContentDigest,
    pub camera_handle: u64,
    pub adoption: ContentDigest,
    pub localization: ContentDigest,
    pub localization_root: ContentDigest,
    pub localization_receipt: ContentDigest,
    pub receipt: ContentDigest,
}
fn digest(d: &mut CanonicalDecoder<'_>) -> Result<ContentDigest, ContractError> {
    let value = d.digest()?;
    if value.algorithm() != DigestAlgorithm::Sha256 || value.bytes() == [0; 32] {
        return Err(ContractError::InvalidDigest);
    }
    Ok(value)
}
impl Recipe {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        e.text(MONITOR_PACKAGE_DOMAIN);
        for digest in [
            self.calibration_object,
            self.calibration_identity,
            self.camera_input,
        ] {
            e.digest(digest);
        }
        e.u64(self.camera_handle);
        for digest in [
            self.adoption,
            self.localization,
            self.localization_root,
            self.localization_receipt,
            self.receipt,
        ] {
            e.digest(digest);
        }
        e.finish()
    }
    pub fn identity(&self) -> ContentDigest {
        ContentDigest::sha256(&self.encode())
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() > MAX_MONITOR_RECIPE_BYTES {
            return Err(ContractError::InvalidDigest);
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.text()? != MONITOR_PACKAGE_DOMAIN {
            return Err(ContractError::InvalidDigest);
        }
        let value = Self {
            calibration_object: digest(&mut d)?,
            calibration_identity: digest(&mut d)?,
            camera_input: digest(&mut d)?,
            camera_handle: d.u64()?,
            adoption: digest(&mut d)?,
            localization: digest(&mut d)?,
            localization_root: digest(&mut d)?,
            localization_receipt: digest(&mut d)?,
            receipt: digest(&mut d)?,
        };
        d.ensure_finished()?;
        if value.camera_handle == 0 || value.encode() != bytes {
            return Err(ContractError::InvalidDigest);
        }
        Ok(value)
    }
}
pub(super) fn approval_bytes(receipt: ContentDigest) -> Vec<u8> {
    let mut e = CanonicalEncoder::new();
    e.text(MONITOR_APPROVAL_DOMAIN);
    e.digest(receipt);
    e.finish()
}
pub(super) fn approval(receipt: ContentDigest) -> ContentDigest {
    ContentDigest::sha256(&approval_bytes(receipt))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_recipe_and_approval_bind_replay_inputs_and_reject_suffixes()
    -> Result<(), ContractError> {
        let d = ContentDigest::sha256(b"source");
        let value = Recipe {
            calibration_object: d,
            calibration_identity: d,
            camera_input: d,
            camera_handle: 21,
            adoption: d,
            localization: d,
            localization_root: d,
            localization_receipt: d,
            receipt: d,
        };
        let bytes = value.encode();
        assert_eq!(Recipe::decode(&bytes)?, value);
        let mut suffix = bytes.clone();
        suffix.push(0);
        assert!(Recipe::decode(&suffix).is_err());
        let mut zero = value.clone();
        zero.camera_handle = 0;
        assert!(Recipe::decode(&zero.encode()).is_err());
        let mut changed = value.clone();
        changed.adoption = ContentDigest::sha256(b"different adoption");
        assert_ne!(changed.identity(), value.identity());
        assert_ne!(
            approval(d),
            approval(ContentDigest::sha256(b"different observation"))
        );
        assert_ne!(approval(d), d);
        Ok(())
    }
}
