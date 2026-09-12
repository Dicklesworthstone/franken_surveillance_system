#![forbid(unsafe_code)]
//! Immutable model manifest v1 binary and canonical JSON contract (FSS-070 / fss-x4a.14.1).
//!
//! Provides the canonical `ModelManifestV1` type with:
//! - Content-addressed canonical model manifest binding model identity, immutable generation,
//!   weights digest, input/output schemas, calibration generation, and license/provenance record.
//! - Strict immutability guarantees: mutations produce a new generation that explicitly supersedes
//!   the prior generation; "latest" resolution is strictly rejected at all boundaries.
//! - Bit-identical round-tripping between versioned binary envelope (`FSMN` v1) and canonical JSON.
//! - Typed decode errors with no default-on-error and no alias forms.
//! - Hard size bounds with verified enforcement at bound and bound + 1.

use core::fmt;
use std::collections::BTreeSet;
use std::ops::Deref;
use std::str::FromStr;

use fss_core::{
    CalibrationGeneration, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder,
    ContentDigest, ContractError, ModelGeneration, SchemaId,
};

/// Format magic header for binary model manifest envelope (`FSMN`).
pub const MODEL_MANIFEST_MAGIC: [u8; 4] = *b"FSMN";

/// Binary format version for model manifest v1.
pub const MODEL_MANIFEST_VERSION_1: u16 = 1;

/// Canonical schema identifier for model manifest v1.
pub const MODEL_MANIFEST_SCHEMA: &str = "fss.model_manifest.v1";

/// Maximum allowed byte length for a model identity string.
pub const MAX_MODEL_ID_LEN: usize = 64;

/// Minimum allowed byte length for a model identity string (e.g. `MOD-A`).
pub const MIN_MODEL_ID_LEN: usize = 5;

/// Maximum allowed byte length for a model generation identifier.
pub const MAX_MODEL_GENERATION_LEN: usize = 256;

/// Minimum allowed byte length for a model generation identifier.
pub const MIN_MODEL_GENERATION_LEN: usize = 8;

/// Maximum allowed byte length for a schema identifier string.
pub const MAX_SCHEMA_ID_LEN: usize = 128;

/// Minimum allowed byte length for a schema identifier string.
pub const MIN_SCHEMA_ID_LEN: usize = 1;

/// Maximum allowed byte length for a calibration generation identifier.
pub const MAX_CALIBRATION_GENERATION_LEN: usize = 256;

/// Minimum allowed byte length for a calibration generation identifier.
pub const MIN_CALIBRATION_GENERATION_LEN: usize = 8;

/// Maximum allowed byte length for a license SPDX expression or identity.
pub const MAX_SPDX_LEN: usize = 128;

/// Minimum allowed byte length for a license SPDX expression.
pub const MIN_SPDX_LEN: usize = 1;

/// Maximum number of license restrictions permitted in a manifest.
pub const MAX_RESTRICTIONS_COUNT: usize = 64;

/// Maximum allowed byte length for an individual license restriction string.
pub const MAX_RESTRICTION_LEN: usize = 256;

/// Maximum allowed byte length for a provenance source identity string.
pub const MAX_SOURCE_IDENTITY_LEN: usize = 256;

/// Minimum allowed byte length for a provenance source identity string.
pub const MIN_SOURCE_IDENTITY_LEN: usize = 1;

/// Maximum number of artifact digests permitted in the provenance record.
pub const MAX_ARTIFACT_DIGESTS_COUNT: usize = 64;

/// Maximum allowed byte length for an upstream revision string.
pub const MAX_UPSTREAM_REVISION_LEN: usize = 128;

/// Maximum JSON nesting depth accepted by the manifest JSON decoder.
const MAX_JSON_DEPTH: usize = 16;

/// Floating alias refused wherever a model, supersedes, or calibration generation is named.
pub const LATEST_ALIAS: &str = "latest";

/// Rejects any identifier that names [`LATEST_ALIAS`] in any letter case and at any position.
///
/// The test is a case-insensitive substring match, so `latest`, `LATEST`, `Latest:v1`,
/// `model:latest:v1`, `model:detector:latest`, and `latest.weights` are all refused with
/// [`ModelManifestError::LatestNotResolvable`]. Model weights are only ever resolved through an
/// explicit immutable generation.
pub fn reject_latest_alias(value: &str) -> Result<(), ModelManifestError> {
    let alias = LATEST_ALIAS.as_bytes();
    if value
        .as_bytes()
        .windows(alias.len())
        .any(|window| window.eq_ignore_ascii_case(alias))
    {
        return Err(ModelManifestError::LatestNotResolvable);
    }
    Ok(())
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Typed decode and validation errors for model manifest operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelManifestError {
    /// Input data was truncated before reading required field or byte sequence.
    Truncated {
        /// Minimum bytes expected.
        expected_min: usize,
        /// Actual available bytes.
        actual: usize,
    },
    /// Unknown or unsupported encoding format version.
    UnknownVersion {
        /// Decoded version number, exactly as it appears in the envelope.
        version: u32,
    },
    /// Trailing unparsed bytes remaining after complete decode.
    TrailingBytes {
        /// Number of unconsumed bytes.
        count: usize,
    },
    /// A field length strictly exceeds its declared hard bound.
    OverLimitLength {
        /// Name of the offending field.
        field: &'static str,
        /// Hard limit bound.
        limit: usize,
        /// Actual observed length.
        actual: usize,
    },
    /// A field length lies strictly below its declared minimum bound.
    UnderLimitLength {
        /// Name of the offending field.
        field: &'static str,
        /// Minimum bound.
        minimum: usize,
        /// Actual observed length.
        actual: usize,
    },
    /// Non-canonical encoding (e.g. invalid discriminator, illegal magic).
    NonCanonicalEncoding {
        /// Diagnostic detail.
        detail: String,
    },
    /// Schema identity constant mismatch.
    SchemaMismatch {
        /// Expected schema identifier.
        expected: &'static str,
        /// Observed schema identifier.
        found: String,
    },
    /// JSON syntactic or semantic parse error.
    JsonError {
        /// Diagnostic detail.
        detail: String,
    },
    /// Field failed identifier syntax validation.
    InvalidIdentifier {
        /// Name of the field.
        field: &'static str,
        /// Diagnostic detail.
        detail: String,
    },
    /// Resolution of "latest" generation was attempted (forbidden by AGENTS.md).
    LatestNotResolvable,
    /// Model identity mismatch during supersedes validation.
    ModelIdMismatch {
        /// Expected model identity.
        expected: ModelId,
        /// Found model identity.
        found: ModelId,
    },
    /// Prior generation mismatch during supersedes validation.
    SupersedesMismatch {
        /// Expected prior generation.
        expected: Option<ModelGeneration>,
        /// Found prior generation.
        found: Option<ModelGeneration>,
    },
    /// Generation did not advance during supersedes validation.
    GenerationNotAdvanced {
        /// Generation identifier.
        generation: ModelGeneration,
    },
    /// Underlying contract error.
    Contract(ContractError),
}

impl fmt::Display for ModelManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                expected_min,
                actual,
            } => {
                write!(
                    f,
                    "truncated input: expected at least {expected_min} bytes, found {actual}"
                )
            }
            Self::UnknownVersion { version } => {
                write!(f, "unknown model manifest format version: {version}")
            }
            Self::TrailingBytes { count } => {
                write!(f, "trailing unconsumed bytes after decode: {count} bytes")
            }
            Self::OverLimitLength {
                field,
                limit,
                actual,
            } => {
                write!(
                    f,
                    "field '{field}' length exceeds limit: limit={limit}, actual={actual}"
                )
            }
            Self::UnderLimitLength {
                field,
                minimum,
                actual,
            } => {
                write!(
                    f,
                    "field '{field}' length below minimum: minimum={minimum}, actual={actual}"
                )
            }
            Self::NonCanonicalEncoding { detail } => {
                write!(f, "non-canonical encoding: {detail}")
            }
            Self::SchemaMismatch { expected, found } => {
                write!(f, "schema mismatch: expected '{expected}', found '{found}'")
            }
            Self::JsonError { detail } => {
                write!(f, "json parse error: {detail}")
            }
            Self::InvalidIdentifier { field, detail } => {
                write!(f, "invalid identifier in field '{field}': {detail}")
            }
            Self::LatestNotResolvable => {
                write!(
                    f,
                    "resolution of 'latest' is forbidden: model weights must be pinned to explicit immutable generations"
                )
            }
            Self::ModelIdMismatch { expected, found } => {
                write!(
                    f,
                    "model id mismatch: expected '{expected}', found '{found}'"
                )
            }
            Self::SupersedesMismatch { expected, found } => {
                write!(
                    f,
                    "supersedes mismatch: expected {expected:?}, found {found:?}"
                )
            }
            Self::GenerationNotAdvanced { generation } => {
                write!(
                    f,
                    "generation not advanced: successor must advance beyond '{generation}'"
                )
            }
            Self::Contract(err) => write!(f, "contract error: {err}"),
        }
    }
}

impl std::error::Error for ModelManifestError {}

impl From<ContractError> for ModelManifestError {
    fn from(err: ContractError) -> Self {
        Self::Contract(err)
    }
}

/// A validated model identity string matching `^MOD-[A-Z0-9-]+$`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ModelId(String);

impl ModelId {
    /// Canonical prefix for model identifiers.
    pub const PREFIX: &'static str = "MOD-";

    /// Parses and validates a model identity string.
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelManifestError> {
        let value = value.into();
        if value.len() < MIN_MODEL_ID_LEN {
            return Err(ModelManifestError::UnderLimitLength {
                field: "model_id",
                minimum: MIN_MODEL_ID_LEN,
                actual: value.len(),
            });
        }
        if value.len() > MAX_MODEL_ID_LEN {
            return Err(ModelManifestError::OverLimitLength {
                field: "model_id",
                limit: MAX_MODEL_ID_LEN,
                actual: value.len(),
            });
        }
        if !value.starts_with(Self::PREFIX) {
            return Err(ModelManifestError::InvalidIdentifier {
                field: "model_id",
                detail: format!("must start with '{}'", Self::PREFIX),
            });
        }
        for (idx, byte) in value.as_bytes().iter().enumerate().skip(Self::PREFIX.len()) {
            if !(byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'-') {
                return Err(ModelManifestError::InvalidIdentifier {
                    field: "model_id",
                    detail: format!(
                        "invalid character '{}' at byte index {}",
                        char::from(*byte),
                        idx
                    ),
                });
            }
        }
        Ok(Self(value))
    }

    /// Returns the raw identifier string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the wrapper and returns the inner String.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for ModelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Deref for ModelId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for ModelId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for ModelId {
    type Err = ModelManifestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<String> for ModelId {
    type Error = ModelManifestError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl TryFrom<&str> for ModelId {
    type Error = ModelManifestError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl CanonicalEncode for ModelId {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.0);
    }
}

impl CanonicalDecode for ModelId {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let text = decoder.text()?;
        Self::parse(text).map_err(|_| ContractError::InvalidIdentifier)
    }
}

/// Bounded license and provenance record bound into the immutable model manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelLicenseRecord {
    /// SPDX license identifier or proprietary identity string.
    pub spdx_or_identity: String,
    /// Optional digest of license legal text.
    pub text_digest: Option<ContentDigest>,
    /// Whether this model license has been explicitly reviewed and approved for use.
    pub use_approved: bool,
    /// Declared operational or commercial restrictions.
    pub restrictions: Vec<String>,
    /// Upstream source or repository identity.
    pub source_identity: String,
    /// Upstream artifact digests verifying the source package.
    pub artifact_digests: Vec<ContentDigest>,
    /// Upstream commit revision, tag, or version string if available.
    pub upstream_revision: Option<String>,
}

impl ModelLicenseRecord {
    /// Validates all structural bounds on the license and provenance record.
    pub fn validate(&self) -> Result<(), ModelManifestError> {
        if self.spdx_or_identity.len() < MIN_SPDX_LEN {
            return Err(ModelManifestError::UnderLimitLength {
                field: "license.spdx_or_identity",
                minimum: MIN_SPDX_LEN,
                actual: self.spdx_or_identity.len(),
            });
        }
        if self.spdx_or_identity.len() > MAX_SPDX_LEN {
            return Err(ModelManifestError::OverLimitLength {
                field: "license.spdx_or_identity",
                limit: MAX_SPDX_LEN,
                actual: self.spdx_or_identity.len(),
            });
        }
        if self.restrictions.len() > MAX_RESTRICTIONS_COUNT {
            return Err(ModelManifestError::OverLimitLength {
                field: "license.restrictions",
                limit: MAX_RESTRICTIONS_COUNT,
                actual: self.restrictions.len(),
            });
        }
        for (idx, restriction) in self.restrictions.iter().enumerate() {
            if restriction.is_empty() {
                return Err(ModelManifestError::UnderLimitLength {
                    field: "license.restrictions[i]",
                    minimum: 1,
                    actual: 0,
                });
            }
            if restriction.len() > MAX_RESTRICTION_LEN {
                return Err(ModelManifestError::OverLimitLength {
                    field: "license.restrictions[i]",
                    limit: MAX_RESTRICTION_LEN,
                    actual: restriction.len(),
                });
            }
            // Ensure no duplicate restrictions
            if self.restrictions[..idx].contains(restriction) {
                return Err(ModelManifestError::NonCanonicalEncoding {
                    detail: format!("duplicate license restriction: '{restriction}'"),
                });
            }
        }
        if self.source_identity.len() < MIN_SOURCE_IDENTITY_LEN {
            return Err(ModelManifestError::UnderLimitLength {
                field: "license.source_identity",
                minimum: MIN_SOURCE_IDENTITY_LEN,
                actual: self.source_identity.len(),
            });
        }
        if self.source_identity.len() > MAX_SOURCE_IDENTITY_LEN {
            return Err(ModelManifestError::OverLimitLength {
                field: "license.source_identity",
                limit: MAX_SOURCE_IDENTITY_LEN,
                actual: self.source_identity.len(),
            });
        }
        if self.artifact_digests.len() > MAX_ARTIFACT_DIGESTS_COUNT {
            return Err(ModelManifestError::OverLimitLength {
                field: "license.artifact_digests",
                limit: MAX_ARTIFACT_DIGESTS_COUNT,
                actual: self.artifact_digests.len(),
            });
        }
        if let Some(rev) = &self.upstream_revision {
            if rev.is_empty() {
                return Err(ModelManifestError::UnderLimitLength {
                    field: "license.upstream_revision",
                    minimum: 1,
                    actual: 0,
                });
            }
            if rev.len() > MAX_UPSTREAM_REVISION_LEN {
                return Err(ModelManifestError::OverLimitLength {
                    field: "license.upstream_revision",
                    limit: MAX_UPSTREAM_REVISION_LEN,
                    actual: rev.len(),
                });
            }
        }
        Ok(())
    }

    /// Canonical binary encoding for the license record.
    ///
    /// The record is validated first, so every count written is within its declared bound. An
    /// out-of-bound record is refused with a typed error; a count is never clamped or defaulted.
    pub fn encode_canonical(
        &self,
        encoder: &mut CanonicalEncoder,
    ) -> Result<(), ModelManifestError> {
        self.validate()?;
        let restriction_count = u32::try_from(self.restrictions.len()).map_err(|_| {
            ModelManifestError::OverLimitLength {
                field: "license.restrictions",
                limit: MAX_RESTRICTIONS_COUNT,
                actual: self.restrictions.len(),
            }
        })?;
        let artifact_count = u32::try_from(self.artifact_digests.len()).map_err(|_| {
            ModelManifestError::OverLimitLength {
                field: "license.artifact_digests",
                limit: MAX_ARTIFACT_DIGESTS_COUNT,
                actual: self.artifact_digests.len(),
            }
        })?;
        encoder.text(&self.spdx_or_identity);
        match &self.text_digest {
            Some(d) => {
                encoder.bool(true);
                encoder.digest(*d);
            }
            None => encoder.bool(false),
        }
        encoder.bool(self.use_approved);
        encoder.u32(restriction_count);
        for r in &self.restrictions {
            encoder.text(r);
        }
        encoder.text(&self.source_identity);
        encoder.u32(artifact_count);
        for d in &self.artifact_digests {
            encoder.digest(*d);
        }
        match &self.upstream_revision {
            Some(rev) => {
                encoder.bool(true);
                encoder.text(rev);
            }
            None => encoder.bool(false),
        }
        Ok(())
    }

    /// Decodes a license record from a canonical binary decoder.
    pub fn decode_canonical(
        decoder: &mut CanonicalDecoder<'_>,
    ) -> Result<Self, ModelManifestError> {
        let spdx = decoder
            .text()
            .map_err(ModelManifestError::Contract)?
            .to_string();
        let has_text_digest = decoder.bool().map_err(ModelManifestError::Contract)?;
        let text_digest = if has_text_digest {
            Some(decoder.digest().map_err(ModelManifestError::Contract)?)
        } else {
            None
        };
        let use_approved = decoder.bool().map_err(ModelManifestError::Contract)?;
        let r_count = decoder.u32().map_err(ModelManifestError::Contract)? as usize;
        if r_count > MAX_RESTRICTIONS_COUNT {
            return Err(ModelManifestError::OverLimitLength {
                field: "license.restrictions",
                limit: MAX_RESTRICTIONS_COUNT,
                actual: r_count,
            });
        }
        let mut restrictions = Vec::with_capacity(r_count);
        for _ in 0..r_count {
            let r = decoder
                .text()
                .map_err(ModelManifestError::Contract)?
                .to_string();
            restrictions.push(r);
        }
        let source_identity = decoder
            .text()
            .map_err(ModelManifestError::Contract)?
            .to_string();
        let a_count = decoder.u32().map_err(ModelManifestError::Contract)? as usize;
        if a_count > MAX_ARTIFACT_DIGESTS_COUNT {
            return Err(ModelManifestError::OverLimitLength {
                field: "license.artifact_digests",
                limit: MAX_ARTIFACT_DIGESTS_COUNT,
                actual: a_count,
            });
        }
        let mut artifact_digests = Vec::with_capacity(a_count);
        for _ in 0..a_count {
            let d = decoder.digest().map_err(ModelManifestError::Contract)?;
            artifact_digests.push(d);
        }
        let has_rev = decoder.bool().map_err(ModelManifestError::Contract)?;
        let upstream_revision = if has_rev {
            Some(
                decoder
                    .text()
                    .map_err(ModelManifestError::Contract)?
                    .to_string(),
            )
        } else {
            None
        };

        let record = Self {
            spdx_or_identity: spdx,
            text_digest,
            use_approved,
            restrictions,
            source_identity,
            artifact_digests,
            upstream_revision,
        };
        record.validate()?;
        Ok(record)
    }
}

/// Canonical, content-addressed model manifest v1.
///
/// A manifest is immutable once constructed: its fields are private, so no caller can rebind the
/// weights, calibration, license, or supersedes pointer of an existing generation in place.
///
/// ```compile_fail,E0616
/// fn mutate_in_place(manifest: &mut fss_object::ModelManifestV1, other: &fss_object::ModelManifestV1) {
///     manifest.weights_digest = other.weights_digest;
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelManifestV1 {
    /// Unique model family or architecture identity (e.g. `MOD-RFDETR-001`).
    model_id: ModelId,
    /// Immutable package generation identifier (e.g. `model:rfdetr:fp16:v1`).
    generation: ModelGeneration,
    /// Exact content digest of immutable model weight tensors.
    weights_digest: ContentDigest,
    /// Stable input tensor or schema identity.
    input_schema: SchemaId,
    /// Stable output prediction or schema identity.
    output_schema: SchemaId,
    /// Required sensor calibration generation.
    calibration_generation: CalibrationGeneration,
    /// License, approval, and supply-chain provenance record.
    license: ModelLicenseRecord,
    /// Generation identifier superseded by this manifest revision, if any.
    supersedes_generation: Option<ModelGeneration>,
}

impl ModelManifestV1 {
    /// Schema identity constant.
    pub const SCHEMA: &'static str = MODEL_MANIFEST_SCHEMA;

    /// Constructs and validates a root manifest generation that supersedes nothing.
    ///
    /// Later revisions are built only through [`Self::create_successor`], which binds the
    /// superseded generation. A manifest value is never modified after construction; a different
    /// manifest that reuses an existing generation is a custody conflict detected by the
    /// importer, not an in-place edit.
    pub fn new(
        model_id: ModelId,
        generation: ModelGeneration,
        weights_digest: ContentDigest,
        input_schema: SchemaId,
        output_schema: SchemaId,
        calibration_generation: CalibrationGeneration,
        license: ModelLicenseRecord,
    ) -> Result<Self, ModelManifestError> {
        let manifest = Self {
            model_id,
            generation,
            weights_digest,
            input_schema,
            output_schema,
            calibration_generation,
            license,
            supersedes_generation: None,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// Model family or architecture identity.
    #[must_use]
    pub const fn model_id(&self) -> &ModelId {
        &self.model_id
    }

    /// Immutable package generation identifier.
    #[must_use]
    pub const fn generation(&self) -> &ModelGeneration {
        &self.generation
    }

    /// Exact content digest of the model weight tensors.
    #[must_use]
    pub const fn weights_digest(&self) -> ContentDigest {
        self.weights_digest
    }

    /// Input tensor or schema identity.
    #[must_use]
    pub const fn input_schema(&self) -> &SchemaId {
        &self.input_schema
    }

    /// Output prediction or schema identity.
    #[must_use]
    pub const fn output_schema(&self) -> &SchemaId {
        &self.output_schema
    }

    /// Required sensor calibration generation.
    #[must_use]
    pub const fn calibration_generation(&self) -> &CalibrationGeneration {
        &self.calibration_generation
    }

    /// License, approval, and supply-chain provenance record.
    #[must_use]
    pub const fn license(&self) -> &ModelLicenseRecord {
        &self.license
    }

    /// Generation superseded by this revision, if any.
    #[must_use]
    pub const fn supersedes_generation(&self) -> Option<&ModelGeneration> {
        self.supersedes_generation.as_ref()
    }

    /// Validates all fields and bounds on the model manifest.
    ///
    /// No generation, supersedes pointer, or calibration generation may name [`LATEST_ALIAS`].
    pub fn validate(&self) -> Result<(), ModelManifestError> {
        reject_latest_alias(self.generation.as_str())?;
        reject_latest_alias(self.calibration_generation.as_str())?;
        if let Some(sup) = &self.supersedes_generation {
            reject_latest_alias(sup.as_str())?;
        }
        if self.generation.len() < MIN_MODEL_GENERATION_LEN {
            return Err(ModelManifestError::UnderLimitLength {
                field: "generation",
                minimum: MIN_MODEL_GENERATION_LEN,
                actual: self.generation.len(),
            });
        }
        if self.generation.len() > MAX_MODEL_GENERATION_LEN {
            return Err(ModelManifestError::OverLimitLength {
                field: "generation",
                limit: MAX_MODEL_GENERATION_LEN,
                actual: self.generation.len(),
            });
        }
        if self.input_schema.len() < MIN_SCHEMA_ID_LEN {
            return Err(ModelManifestError::UnderLimitLength {
                field: "input_schema",
                minimum: MIN_SCHEMA_ID_LEN,
                actual: self.input_schema.len(),
            });
        }
        if self.input_schema.len() > MAX_SCHEMA_ID_LEN {
            return Err(ModelManifestError::OverLimitLength {
                field: "input_schema",
                limit: MAX_SCHEMA_ID_LEN,
                actual: self.input_schema.len(),
            });
        }
        if self.output_schema.len() < MIN_SCHEMA_ID_LEN {
            return Err(ModelManifestError::UnderLimitLength {
                field: "output_schema",
                minimum: MIN_SCHEMA_ID_LEN,
                actual: self.output_schema.len(),
            });
        }
        if self.output_schema.len() > MAX_SCHEMA_ID_LEN {
            return Err(ModelManifestError::OverLimitLength {
                field: "output_schema",
                limit: MAX_SCHEMA_ID_LEN,
                actual: self.output_schema.len(),
            });
        }
        if self.calibration_generation.len() < MIN_CALIBRATION_GENERATION_LEN {
            return Err(ModelManifestError::UnderLimitLength {
                field: "calibration_generation",
                minimum: MIN_CALIBRATION_GENERATION_LEN,
                actual: self.calibration_generation.len(),
            });
        }
        if self.calibration_generation.len() > MAX_CALIBRATION_GENERATION_LEN {
            return Err(ModelManifestError::OverLimitLength {
                field: "calibration_generation",
                limit: MAX_CALIBRATION_GENERATION_LEN,
                actual: self.calibration_generation.len(),
            });
        }
        if let Some(sup) = &self.supersedes_generation {
            if sup.len() < MIN_MODEL_GENERATION_LEN {
                return Err(ModelManifestError::UnderLimitLength {
                    field: "supersedes_generation",
                    minimum: MIN_MODEL_GENERATION_LEN,
                    actual: sup.len(),
                });
            }
            if sup.len() > MAX_MODEL_GENERATION_LEN {
                return Err(ModelManifestError::OverLimitLength {
                    field: "supersedes_generation",
                    limit: MAX_MODEL_GENERATION_LEN,
                    actual: sup.len(),
                });
            }
            if sup == &self.generation {
                return Err(ModelManifestError::GenerationNotAdvanced {
                    generation: self.generation.clone(),
                });
            }
        }
        self.license.validate()?;
        Ok(())
    }

    /// Verifies that this manifest validly supersedes a prior manifest generation.
    pub fn supersedes(&self, prior: &Self) -> Result<(), ModelManifestError> {
        if self.model_id != prior.model_id {
            return Err(ModelManifestError::ModelIdMismatch {
                expected: self.model_id.clone(),
                found: prior.model_id.clone(),
            });
        }
        if self.supersedes_generation.as_ref() != Some(&prior.generation) {
            return Err(ModelManifestError::SupersedesMismatch {
                expected: Some(prior.generation.clone()),
                found: self.supersedes_generation.clone(),
            });
        }
        if self.generation == prior.generation {
            return Err(ModelManifestError::GenerationNotAdvanced {
                generation: self.generation.clone(),
            });
        }
        Ok(())
    }

    /// Resolves an immutable model generation from a query string.
    ///
    /// Any request naming [`LATEST_ALIAS`] in any case or position is rejected with
    /// [`ModelManifestError::LatestNotResolvable`] (see [`reject_latest_alias`]). The request is
    /// never trimmed or otherwise normalized: it must already be the exact generation spelling.
    pub fn resolve_generation(requested: &str) -> Result<ModelGeneration, ModelManifestError> {
        reject_latest_alias(requested)?;
        ModelGeneration::parse(requested).map_err(ModelManifestError::Contract)
    }

    /// Creates a successor manifest with an advanced generation superseding `self`.
    pub fn create_successor(
        &self,
        next_generation: ModelGeneration,
        new_weights: ContentDigest,
        calibration_generation: CalibrationGeneration,
        license: ModelLicenseRecord,
    ) -> Result<Self, ModelManifestError> {
        if next_generation == self.generation {
            return Err(ModelManifestError::GenerationNotAdvanced {
                generation: next_generation,
            });
        }
        let successor = Self {
            model_id: self.model_id.clone(),
            generation: next_generation,
            weights_digest: new_weights,
            input_schema: self.input_schema.clone(),
            output_schema: self.output_schema.clone(),
            calibration_generation,
            license,
            supersedes_generation: Some(self.generation.clone()),
        };
        successor.validate()?;
        Ok(successor)
    }

    /// Computes the content identity digest of this canonical model manifest.
    pub fn manifest_digest(&self) -> Result<ContentDigest, ModelManifestError> {
        Ok(ContentDigest::sha256(&self.to_canonical_bytes()?))
    }

    /// Serializes this manifest into the versioned binary canonical envelope (`FSMN` v1).
    ///
    /// The manifest is validated first and every encoder failure is returned typed; the envelope
    /// is never emitted with a clamped count or an empty body.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ModelManifestError> {
        self.validate()?;
        let mut out = Vec::with_capacity(1024);
        out.extend_from_slice(&MODEL_MANIFEST_MAGIC);
        out.extend_from_slice(&u32::from(MODEL_MANIFEST_VERSION_1).to_be_bytes());

        let mut encoder = CanonicalEncoder::new();
        encoder.text(Self::SCHEMA);

        self.model_id.encode_canonical(&mut encoder);
        self.generation.encode_canonical(&mut encoder);
        encoder.digest(self.weights_digest);
        self.input_schema.encode_canonical(&mut encoder);
        self.output_schema.encode_canonical(&mut encoder);
        self.calibration_generation.encode_canonical(&mut encoder);
        self.license.encode_canonical(&mut encoder)?;

        match &self.supersedes_generation {
            Some(sup) => {
                encoder.bool(true);
                sup.encode_canonical(&mut encoder);
            }
            None => encoder.bool(false),
        }

        out.extend_from_slice(&encoder.finish_checked()?);
        Ok(out)
    }

    /// Deserializes a manifest from its versioned binary canonical envelope (`FSMN` v1).
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ModelManifestError> {
        if bytes.len() < 8 {
            return Err(ModelManifestError::Truncated {
                expected_min: 8,
                actual: bytes.len(),
            });
        }
        let magic = &bytes[0..4];
        if magic != MODEL_MANIFEST_MAGIC {
            return Err(ModelManifestError::NonCanonicalEncoding {
                detail: format!("invalid magic header: expected 'FSMN', found {magic:?}"),
            });
        }

        let version = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if version != u32::from(MODEL_MANIFEST_VERSION_1) {
            return Err(ModelManifestError::UnknownVersion { version });
        }

        let mut decoder = CanonicalDecoder::new(&bytes[8..]);
        let schema = decoder.text().map_err(ModelManifestError::Contract)?;
        if schema != Self::SCHEMA {
            return Err(ModelManifestError::SchemaMismatch {
                expected: Self::SCHEMA,
                found: schema.to_string(),
            });
        }

        let model_id = ModelId::decode_canonical(&mut decoder)?;
        let generation = ModelGeneration::decode_canonical(&mut decoder)?;
        let weights_digest = decoder.digest().map_err(ModelManifestError::Contract)?;
        let input_schema = SchemaId::decode_canonical(&mut decoder)?;
        let output_schema = SchemaId::decode_canonical(&mut decoder)?;
        let calibration_generation = CalibrationGeneration::decode_canonical(&mut decoder)?;
        let license = ModelLicenseRecord::decode_canonical(&mut decoder)?;

        let has_supersedes = decoder.bool().map_err(ModelManifestError::Contract)?;
        let supersedes_generation = if has_supersedes {
            Some(ModelGeneration::decode_canonical(&mut decoder)?)
        } else {
            None
        };

        if decoder.remaining() > 0 {
            return Err(ModelManifestError::TrailingBytes {
                count: decoder.remaining(),
            });
        }

        let manifest = Self {
            model_id,
            generation,
            weights_digest,
            input_schema,
            output_schema,
            calibration_generation,
            license,
            supersedes_generation,
        };
        manifest.validate()?;
        if manifest.to_canonical_bytes()? != bytes {
            return Err(ModelManifestError::NonCanonicalEncoding {
                detail: "binary manifest does not re-encode to identical bytes".to_string(),
            });
        }
        Ok(manifest)
    }

    /// Emits a deterministic canonical JSON string projection with alphabetically sorted keys.
    ///
    /// Every property is always present; an absent optional value is written as `null`, never
    /// omitted, so the projection has exactly one spelling per manifest.
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let mut out = String::with_capacity(1024);
        out.push('{');

        // 1. calibrationGeneration
        out.push_str("\"calibrationGeneration\":");
        json_write_str(&mut out, self.calibration_generation.as_str());
        out.push(',');

        // 2. generation
        out.push_str("\"generation\":");
        json_write_str(&mut out, self.generation.as_str());
        out.push(',');

        // 3. inputSchema
        out.push_str("\"inputSchema\":");
        json_write_str(&mut out, self.input_schema.as_str());
        out.push(',');

        // 4. license
        out.push_str("\"license\":{");
        // license.artifactDigests
        out.push_str("\"artifactDigests\":[");
        for (i, d) in self.license.artifact_digests.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            json_write_str(&mut out, &d.to_string());
        }
        out.push_str("],\"restrictions\":[");
        // license.restrictions
        for (i, r) in self.license.restrictions.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            json_write_str(&mut out, r);
        }
        out.push_str("],\"sourceIdentity\":");
        json_write_str(&mut out, &self.license.source_identity);
        out.push_str(",\"spdxOrIdentity\":");
        json_write_str(&mut out, &self.license.spdx_or_identity);
        out.push_str(",\"textDigest\":");
        match &self.license.text_digest {
            Some(d) => json_write_str(&mut out, &d.to_string()),
            None => out.push_str("null"),
        }
        out.push_str(",\"upstreamRevision\":");
        match &self.license.upstream_revision {
            Some(rev) => json_write_str(&mut out, rev),
            None => out.push_str("null"),
        }
        out.push_str(",\"useApproved\":");
        out.push_str(if self.license.use_approved {
            "true"
        } else {
            "false"
        });
        out.push('}');
        out.push(',');

        // 5. modelId
        out.push_str("\"modelId\":");
        json_write_str(&mut out, self.model_id.as_str());
        out.push(',');

        // 6. outputSchema
        out.push_str("\"outputSchema\":");
        json_write_str(&mut out, self.output_schema.as_str());
        out.push(',');

        // 7. schema
        out.push_str("\"schema\":");
        json_write_str(&mut out, Self::SCHEMA);
        out.push(',');

        // 8. supersedesGeneration
        out.push_str("\"supersedesGeneration\":");
        match &self.supersedes_generation {
            Some(sup) => json_write_str(&mut out, sup.as_str()),
            None => out.push_str("null"),
        }
        out.push(',');

        // 9. weightsDigest
        out.push_str("\"weightsDigest\":");
        json_write_str(&mut out, &self.weights_digest.to_string());

        out.push('}');
        out
    }

    /// Parses a model manifest from canonical JSON with strict schema adherence.
    ///
    /// Every property is required, including `supersedesGeneration`, `license.textDigest`, and
    /// `license.upstreamRevision`, whose absent value is the explicit `null`. The input must be
    /// byte-identical to [`Self::to_canonical_json`] of the decoded manifest (sorted keys, no
    /// insignificant whitespace, canonical escapes), so every accepted document round-trips
    /// bit-identically and no alias spelling is admitted.
    pub fn from_canonical_json(json_str: &str) -> Result<Self, ModelManifestError> {
        let mut parser = JsonParser::new(json_str);
        let root = parser.parse_value(0)?;
        parser.skip_whitespace();
        if parser.pos < parser.input.len() {
            return Err(ModelManifestError::TrailingBytes {
                count: parser.input.len() - parser.pos,
            });
        }

        let obj = root.as_object()?;

        let mut calibration_generation: Option<CalibrationGeneration> = None;
        let mut generation: Option<ModelGeneration> = None;
        let mut input_schema: Option<SchemaId> = None;
        let mut license: Option<ModelLicenseRecord> = None;
        let mut model_id: Option<ModelId> = None;
        let mut output_schema: Option<SchemaId> = None;
        let mut schema: Option<String> = None;
        let mut supersedes_generation: Option<Option<ModelGeneration>> = None;
        let mut weights_digest: Option<ContentDigest> = None;

        let mut seen_keys = BTreeSet::new();

        for (k, v) in obj {
            if !seen_keys.insert(k.clone()) {
                return Err(ModelManifestError::JsonError {
                    detail: format!("duplicate key '{k}' in model manifest json"),
                });
            }
            match k.as_str() {
                "calibrationGeneration" => {
                    let s = v.as_str()?;
                    calibration_generation = Some(CalibrationGeneration::parse(s)?);
                }
                "generation" => {
                    let s = v.as_str()?;
                    generation = Some(ModelGeneration::parse(s)?);
                }
                "inputSchema" => {
                    let s = v.as_str()?;
                    input_schema = Some(SchemaId::parse(s)?);
                }
                "license" => {
                    license = Some(parse_license_json(v)?);
                }
                "modelId" => {
                    let s = v.as_str()?;
                    model_id = Some(ModelId::parse(s)?);
                }
                "outputSchema" => {
                    let s = v.as_str()?;
                    output_schema = Some(SchemaId::parse(s)?);
                }
                "schema" => {
                    let s = v.as_str()?;
                    schema = Some(s.to_string());
                }
                "supersedesGeneration" => {
                    let opt_s = v.as_opt_str()?;
                    supersedes_generation = match opt_s {
                        Some(s) => Some(Some(ModelGeneration::parse(s)?)),
                        None => Some(None),
                    };
                }
                "weightsDigest" => {
                    let s = v.as_str()?;
                    weights_digest = Some(
                        s.parse::<ContentDigest>()
                            .map_err(ModelManifestError::Contract)?,
                    );
                }
                other => {
                    return Err(ModelManifestError::JsonError {
                        detail: format!("unexpected property '{other}' in model manifest json"),
                    });
                }
            }
        }

        let schema_str = schema.ok_or_else(|| ModelManifestError::JsonError {
            detail: "missing required 'schema' property".to_string(),
        })?;
        if schema_str != Self::SCHEMA {
            return Err(ModelManifestError::SchemaMismatch {
                expected: Self::SCHEMA,
                found: schema_str,
            });
        }

        let model_id = model_id.ok_or_else(|| ModelManifestError::JsonError {
            detail: "missing required 'modelId' property".to_string(),
        })?;
        let generation = generation.ok_or_else(|| ModelManifestError::JsonError {
            detail: "missing required 'generation' property".to_string(),
        })?;
        let weights_digest = weights_digest.ok_or_else(|| ModelManifestError::JsonError {
            detail: "missing required 'weightsDigest' property".to_string(),
        })?;
        let input_schema = input_schema.ok_or_else(|| ModelManifestError::JsonError {
            detail: "missing required 'inputSchema' property".to_string(),
        })?;
        let output_schema = output_schema.ok_or_else(|| ModelManifestError::JsonError {
            detail: "missing required 'outputSchema' property".to_string(),
        })?;
        let calibration_generation =
            calibration_generation.ok_or_else(|| ModelManifestError::JsonError {
                detail: "missing required 'calibrationGeneration' property".to_string(),
            })?;
        let license = license.ok_or_else(|| ModelManifestError::JsonError {
            detail: "missing required 'license' property".to_string(),
        })?;
        let supersedes_generation =
            supersedes_generation.ok_or_else(|| ModelManifestError::JsonError {
                detail: "missing required 'supersedesGeneration' property".to_string(),
            })?;

        let manifest = Self {
            model_id,
            generation,
            weights_digest,
            input_schema,
            output_schema,
            calibration_generation,
            license,
            supersedes_generation,
        };
        manifest.validate()?;
        if manifest.to_canonical_json() != json_str {
            return Err(ModelManifestError::NonCanonicalEncoding {
                detail: "json manifest is not in canonical form".to_string(),
            });
        }
        Ok(manifest)
    }
}

fn parse_license_json(val: &JsonValue) -> Result<ModelLicenseRecord, ModelManifestError> {
    let obj = val.as_object()?;
    let mut spdx_or_identity: Option<String> = None;
    let mut text_digest: Option<Option<ContentDigest>> = None;
    let mut use_approved: Option<bool> = None;
    let mut restrictions: Option<Vec<String>> = None;
    let mut source_identity: Option<String> = None;
    let mut artifact_digests: Option<Vec<ContentDigest>> = None;
    let mut upstream_revision: Option<Option<String>> = None;

    let mut seen_keys = BTreeSet::new();

    for (k, v) in obj {
        if !seen_keys.insert(k.clone()) {
            return Err(ModelManifestError::JsonError {
                detail: format!("duplicate key '{k}' in license json"),
            });
        }
        match k.as_str() {
            "spdxOrIdentity" => {
                spdx_or_identity = Some(v.as_str()?.to_string());
            }
            "textDigest" => {
                let opt_s = v.as_opt_str()?;
                text_digest = match opt_s {
                    Some(s) => Some(Some(
                        s.parse::<ContentDigest>()
                            .map_err(ModelManifestError::Contract)?,
                    )),
                    None => Some(None),
                };
            }
            "useApproved" => {
                use_approved = Some(v.as_bool()?);
            }
            "restrictions" => {
                let arr = v.as_array()?;
                if arr.len() > MAX_RESTRICTIONS_COUNT {
                    return Err(ModelManifestError::OverLimitLength {
                        field: "license.restrictions",
                        limit: MAX_RESTRICTIONS_COUNT,
                        actual: arr.len(),
                    });
                }
                let mut list = Vec::with_capacity(arr.len());
                for item in arr {
                    list.push(item.as_str()?.to_string());
                }
                restrictions = Some(list);
            }
            "sourceIdentity" => {
                source_identity = Some(v.as_str()?.to_string());
            }
            "artifactDigests" => {
                let arr = v.as_array()?;
                if arr.len() > MAX_ARTIFACT_DIGESTS_COUNT {
                    return Err(ModelManifestError::OverLimitLength {
                        field: "license.artifact_digests",
                        limit: MAX_ARTIFACT_DIGESTS_COUNT,
                        actual: arr.len(),
                    });
                }
                let mut list = Vec::with_capacity(arr.len());
                for item in arr {
                    let d = item
                        .as_str()?
                        .parse::<ContentDigest>()
                        .map_err(ModelManifestError::Contract)?;
                    list.push(d);
                }
                artifact_digests = Some(list);
            }
            "upstreamRevision" => {
                let opt_s = v.as_opt_str()?;
                upstream_revision = Some(opt_s.map(|s| s.to_string()));
            }
            other => {
                return Err(ModelManifestError::JsonError {
                    detail: format!("unexpected property '{other}' in license json"),
                });
            }
        }
    }

    let record = ModelLicenseRecord {
        spdx_or_identity: spdx_or_identity.ok_or_else(|| ModelManifestError::JsonError {
            detail: "missing required 'spdxOrIdentity' in license".to_string(),
        })?,
        text_digest: text_digest.ok_or_else(|| ModelManifestError::JsonError {
            detail: "missing required 'textDigest' in license".to_string(),
        })?,
        use_approved: use_approved.ok_or_else(|| ModelManifestError::JsonError {
            detail: "missing required 'useApproved' in license".to_string(),
        })?,
        restrictions: restrictions.ok_or_else(|| ModelManifestError::JsonError {
            detail: "missing required 'restrictions' in license".to_string(),
        })?,
        source_identity: source_identity.ok_or_else(|| ModelManifestError::JsonError {
            detail: "missing required 'sourceIdentity' in license".to_string(),
        })?,
        artifact_digests: artifact_digests.ok_or_else(|| ModelManifestError::JsonError {
            detail: "missing required 'artifactDigests' in license".to_string(),
        })?,
        upstream_revision: upstream_revision.ok_or_else(|| ModelManifestError::JsonError {
            detail: "missing required 'upstreamRevision' in license".to_string(),
        })?,
    };
    record.validate()?;
    Ok(record)
}

fn json_write_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            control if u32::from(control) < 0x20 => {
                let code = u32::from(control) as usize;
                out.push_str("\\u00");
                out.push(char::from(HEX_DIGITS[code >> 4]));
                out.push(char::from(HEX_DIGITS[code & 0xf]));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

#[derive(Clone, Debug, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    fn as_str(&self) -> Result<&str, ModelManifestError> {
        match self {
            Self::String(s) => Ok(s.as_str()),
            _ => Err(ModelManifestError::JsonError {
                detail: "expected string".to_string(),
            }),
        }
    }

    fn as_opt_str(&self) -> Result<Option<&str>, ModelManifestError> {
        match self {
            Self::Null => Ok(None),
            Self::String(s) => Ok(Some(s.as_str())),
            _ => Err(ModelManifestError::JsonError {
                detail: "expected string or null".to_string(),
            }),
        }
    }

    fn as_bool(&self) -> Result<bool, ModelManifestError> {
        match self {
            Self::Bool(b) => Ok(*b),
            _ => Err(ModelManifestError::JsonError {
                detail: "expected boolean".to_string(),
            }),
        }
    }

    fn as_array(&self) -> Result<&[JsonValue], ModelManifestError> {
        match self {
            Self::Array(arr) => Ok(arr.as_slice()),
            _ => Err(ModelManifestError::JsonError {
                detail: "expected array".to_string(),
            }),
        }
    }

    fn as_object(&self) -> Result<&[(String, JsonValue)], ModelManifestError> {
        match self {
            Self::Object(pairs) => Ok(pairs.as_slice()),
            _ => Err(ModelManifestError::JsonError {
                detail: "expected object".to_string(),
            }),
        }
    }
}

struct JsonParser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            pos: 0,
        }
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.input.len() {
            let b = self.input[self.pos];
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip_whitespace();
        if self.pos < self.input.len() {
            Some(self.input[self.pos])
        } else {
            None
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<JsonValue, ModelManifestError> {
        if depth > MAX_JSON_DEPTH {
            return Err(ModelManifestError::JsonError {
                detail: "maximum json depth exceeded".to_string(),
            });
        }
        let b = self.peek().ok_or_else(|| ModelManifestError::Truncated {
            expected_min: self.pos + 1,
            actual: self.pos,
        })?;
        match b {
            b'"' => self.parse_string().map(JsonValue::String),
            b'{' => self.parse_object(depth + 1),
            b'[' => self.parse_array(depth + 1),
            b't' | b'f' => self.parse_bool().map(JsonValue::Bool),
            b'n' => self.parse_null().map(|_| JsonValue::Null),
            other => Err(ModelManifestError::JsonError {
                detail: format!("unexpected character in json: '{}'", char::from(other)),
            }),
        }
    }

    fn parse_null(&mut self) -> Result<(), ModelManifestError> {
        self.skip_whitespace();
        if self.input[self.pos..].starts_with(b"null") {
            self.pos += 4;
            Ok(())
        } else {
            Err(ModelManifestError::JsonError {
                detail: "expected 'null'".to_string(),
            })
        }
    }

    fn parse_bool(&mut self) -> Result<bool, ModelManifestError> {
        self.skip_whitespace();
        if self.input[self.pos..].starts_with(b"true") {
            self.pos += 4;
            Ok(true)
        } else if self.input[self.pos..].starts_with(b"false") {
            self.pos += 5;
            Ok(false)
        } else {
            Err(ModelManifestError::JsonError {
                detail: "expected boolean ('true' or 'false')".to_string(),
            })
        }
    }

    fn parse_string(&mut self) -> Result<String, ModelManifestError> {
        self.skip_whitespace();
        if self.pos >= self.input.len() || self.input[self.pos] != b'"' {
            return Err(ModelManifestError::JsonError {
                detail: "expected '\"'".to_string(),
            });
        }
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.input.len() {
            let b = self.input[self.pos];
            self.pos += 1;
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    if self.pos >= self.input.len() {
                        return Err(ModelManifestError::Truncated {
                            expected_min: self.pos + 1,
                            actual: self.pos,
                        });
                    }
                    let esc = self.input[self.pos];
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            if self.pos + 4 > self.input.len() {
                                return Err(ModelManifestError::Truncated {
                                    expected_min: self.pos + 4,
                                    actual: self.input.len(),
                                });
                            }
                            let hex_str = std::str::from_utf8(&self.input[self.pos..self.pos + 4])
                                .map_err(|_| ModelManifestError::JsonError {
                                    detail: "invalid utf8 in hex escape".to_string(),
                                })?;
                            self.pos += 4;
                            let codepoint = u32::from_str_radix(hex_str, 16).map_err(|_| {
                                ModelManifestError::JsonError {
                                    detail: format!("invalid unicode escape '\\u{hex_str}'"),
                                }
                            })?;
                            let ch = char::from_u32(codepoint).ok_or_else(|| {
                                ModelManifestError::JsonError {
                                    detail: format!(
                                        "invalid unicode scalar value U+{codepoint:04X}"
                                    ),
                                }
                            })?;
                            out.push(ch);
                        }
                        other => {
                            return Err(ModelManifestError::JsonError {
                                detail: format!(
                                    "invalid escape sequence '\\{}'",
                                    char::from(other)
                                ),
                            });
                        }
                    }
                }
                c if c < 0x20 => {
                    return Err(ModelManifestError::JsonError {
                        detail: format!("unescaped control character {c:#x} in json string"),
                    });
                }
                _ => {
                    // Safe UTF-8 decoding
                    let start = self.pos - 1;
                    while self.pos < self.input.len()
                        && self.input[self.pos] != b'"'
                        && self.input[self.pos] != b'\\'
                        && self.input[self.pos] >= 0x20
                    {
                        self.pos += 1;
                    }
                    let chunk =
                        std::str::from_utf8(&self.input[start..self.pos]).map_err(|_| {
                            ModelManifestError::JsonError {
                                detail: "invalid utf8 sequence in string".to_string(),
                            }
                        })?;
                    out.push_str(chunk);
                }
            }
        }
        Err(ModelManifestError::Truncated {
            expected_min: self.pos + 1,
            actual: self.pos,
        })
    }

    fn parse_array(&mut self, depth: usize) -> Result<JsonValue, ModelManifestError> {
        self.skip_whitespace();
        if self.pos >= self.input.len() || self.input[self.pos] != b'[' {
            return Err(ModelManifestError::JsonError {
                detail: "expected '['".to_string(),
            });
        }
        self.pos += 1;
        self.skip_whitespace();
        if self.pos < self.input.len() && self.input[self.pos] == b']' {
            self.pos += 1;
            return Ok(JsonValue::Array(Vec::new()));
        }

        let mut items = Vec::new();
        loop {
            let item = self.parse_value(depth)?;
            items.push(item);
            self.skip_whitespace();
            if self.pos >= self.input.len() {
                return Err(ModelManifestError::Truncated {
                    expected_min: self.pos + 1,
                    actual: self.pos,
                });
            }
            if self.input[self.pos] == b',' {
                self.pos += 1;
            } else if self.input[self.pos] == b']' {
                self.pos += 1;
                break;
            } else {
                return Err(ModelManifestError::JsonError {
                    detail: format!(
                        "expected ',' or ']' in array, found '{}'",
                        char::from(self.input[self.pos])
                    ),
                });
            }
        }
        Ok(JsonValue::Array(items))
    }

    fn parse_object(&mut self, depth: usize) -> Result<JsonValue, ModelManifestError> {
        self.skip_whitespace();
        if self.pos >= self.input.len() || self.input[self.pos] != b'{' {
            return Err(ModelManifestError::JsonError {
                detail: "expected '{'".to_string(),
            });
        }
        self.pos += 1;
        self.skip_whitespace();
        if self.pos < self.input.len() && self.input[self.pos] == b'}' {
            self.pos += 1;
            return Ok(JsonValue::Object(Vec::new()));
        }

        let mut pairs = Vec::new();
        loop {
            let key = self.parse_string()?;
            self.skip_whitespace();
            if self.pos >= self.input.len() || self.input[self.pos] != b':' {
                return Err(ModelManifestError::JsonError {
                    detail: "expected ':' after object key".to_string(),
                });
            }
            self.pos += 1;
            let val = self.parse_value(depth)?;
            pairs.push((key, val));
            self.skip_whitespace();
            if self.pos >= self.input.len() {
                return Err(ModelManifestError::Truncated {
                    expected_min: self.pos + 1,
                    actual: self.pos,
                });
            }
            if self.input[self.pos] == b',' {
                self.pos += 1;
            } else if self.input[self.pos] == b'}' {
                self.pos += 1;
                break;
            } else {
                return Err(ModelManifestError::JsonError {
                    detail: format!(
                        "expected ',' or '}}' in object, found '{}'",
                        char::from(self.input[self.pos])
                    ),
                });
            }
        }
        Ok(JsonValue::Object(pairs))
    }
}
