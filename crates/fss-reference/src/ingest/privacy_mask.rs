#![forbid(unsafe_code)]
//! Owner-declared, approval-gated privacy masks per sensor (GOAL-009), retained as authority.
//!
//! A [`PrivacyMaskPolicy`] names one sensor, the stream resolution its coordinates refer to, and
//! 1..=[`MAX_MASK_REGIONS`] axis-aligned rectangles in decoded-pixel coordinates. Each rectangle is
//! an fss-core [`RedactedRegion`] whose method is the existing
//! [`RedactionTransform::BoundingBoxRedact`] vocabulary (`transform:bounding_box_redact`); no
//! parallel privacy vocabulary is introduced. Polygons are not supported: a polygon must be
//! declared as its covering rectangles.
//!
//! Lifecycle, mirroring coverage retention: [`preview_mask`] computes the canonical policy digest
//! and an exact approval digest bound to the sensor's *current* retained policy (or its absence),
//! and writes nothing. [`declare_mask`] retains the policy only when presented that approval: one
//! spool object (the canonical policy bytes) and one `privacy_mask_policy` ledger delta on the
//! sensor's object (`object:privacy-mask:<sha256(sensor)>`), generation `n -> n + 1`, plane
//! authority. An approval computed against an older state is stale and refused before any write;
//! re-presenting the approval that retained the current policy, or declaring the current policy
//! again, writes nothing. There is no removal operation: a policy can only be replaced.
//!
//! [`current_mask`] resolves the sensor's current binding, [`MaskBinding::NoPolicy`] when none is
//! retained (an explicit marker, never a silent default). Enforcement on decoded planes lives in
//! [`enforce`]; coverage honesty over masked zones in [`coverage`].

use std::fmt;

use fss_core::{
    BatchId, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaptureInterval,
    ContentDigest, ContractError, DigestAlgorithm, EvidenceDelta, ObjectId, Plane, RedactedRegion,
    RedactionTransform, SensorId, TimestampNs,
};

use crate::reference_deployment::FAMILY_PRIVACY_MASK_POLICY;
use crate::{ReferenceDeployment, ReferenceError, ReplayCx};

/// Maximum rectangles in one policy.
pub const MAX_MASK_REGIONS: usize = 32;
/// Maximum canonical policy bytes.
pub const MAX_MASK_POLICY_BYTES: usize = 8_192;
/// Largest declared stream dimension (the decode ceilings).
pub const MAX_MASK_DIMENSION: u32 = 4_096;
/// Luma value written into every masked luma sample (video black, also dark in full range).
pub const MASK_FILL_LUMA: u8 = 16;
/// Chroma value written into every Cb/Cr sample that covers a masked luma sample (neutral).
pub const MASK_FILL_CHROMA: u8 = 128;
/// RGB value written into every masked pixel of an RGB decode or conversion.
pub const MASK_FILL_RGB: [u8; 3] = [16, 16, 16];

/// Canonical policy record domain.
pub const MASK_POLICY_DOMAIN: &str = "fss.privacy_mask_policy.v1";
/// Binding digest domain: the explicit no-policy marker or one retained policy digest.
pub const MASK_BINDING_DOMAIN: &str = "fss.privacy_mask_binding.v1";
/// Exact declaration approval domain (policy digest and the sensor's current retained state).
pub const MASK_APPROVAL_DOMAIN: &str = "fss.privacy_mask_approval.v1";
/// Lineage fold domain: a derived identity bound to one mask binding.
pub const MASK_LINEAGE_DOMAIN: &str = "fss.privacy_mask_lineage.v1";

const POLICY_MAGIC: &[u8] = b"FSSPMK01";
const POLICY_VERSION: u32 = 1;

/// Enforcement of a binding on decoded luma, chroma and RGB planes.
pub mod enforce;

/// Coverage honesty over masked zones.
pub mod coverage;

/// The sensor's current mask on live, recording and replay decode paths.
pub mod live;

fn hex(digest: ContentDigest) -> String {
    digest.bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// The existing redaction vocabulary entry that a rectangle mask applies.
#[must_use]
pub const fn mask_transform() -> RedactionTransform {
    RedactionTransform::BoundingBoxRedact
}

/// Typed refusal of mask declaration, resolution or enforcement.
#[derive(Debug)]
pub enum PrivacyMaskError {
    /// The declared policy is outside its contract.
    InvalidPolicy(&'static str),
    /// The approval matches neither this declaration against the current retained state nor
    /// the approval that retained the current policy.
    StaleApproval(ContentDigest),
    /// Decoded frame dimensions differ from the policy's declared stream resolution; nothing is
    /// decoded unmasked instead.
    ResolutionMismatch {
        /// Resolution the policy was declared for.
        declared: [u32; 2],
        /// Resolution of the decoded frame.
        decoded: [u32; 2],
    },
    /// The request would serve pixels not masked by the sensor's current policy: raw retained
    /// source export, or a decode retained under no or another mask policy.
    UnmaskedAccessRefused,
    /// A retained policy record or plane does not match its authority.
    InvalidRecord,
    /// Shared contract validation failed.
    Contract(ContractError),
    /// Spool or ledger refusal.
    Reference(Box<ReferenceError>),
    /// Retained custody could not be read.
    Spool(fss_object::SpoolError),
    /// Owner cancellation was observed before any write.
    Cancelled,
}

impl PrivacyMaskError {
    /// Registered stable identity (registries/ERRORS.md).
    #[must_use]
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::InvalidPolicy(_) => "ERR-PRIVACY-MASK-POLICY-001",
            Self::StaleApproval(_) => "ERR-PRIVACY-MASK-APPROVAL-STALE-001",
            Self::ResolutionMismatch { .. } => "ERR-PRIVACY-MASK-RESOLUTION-001",
            Self::UnmaskedAccessRefused => "ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001",
            Self::InvalidRecord
            | Self::Contract(_)
            | Self::Reference(_)
            | Self::Spool(_)
            | Self::Cancelled => "ERR-PRIVACY-MASK-001",
        }
    }
}

impl fmt::Display for PrivacyMaskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy(why) => write!(f, "invalid privacy mask policy: {why}"),
            Self::StaleApproval(digest) => write!(
                f,
                "privacy mask approval {digest} matches neither this declaration against the \
                 sensor's current retained policy nor the approval that retained it"
            ),
            Self::ResolutionMismatch { declared, decoded } => write!(
                f,
                "privacy mask declared for {}x{} but the decoded frame is {}x{}; refusing to \
                 serve unmasked pixels",
                declared[0], declared[1], decoded[0], decoded[1]
            ),
            Self::UnmaskedAccessRefused => f.write_str(
                "unmasked access refused: the sensor has a retained privacy mask policy and this \
                 request would serve pixels not masked by it (no override capability exists)",
            ),
            Self::InvalidRecord => f.write_str("retained privacy mask record mismatch"),
            Self::Contract(error) => write!(f, "privacy mask contract: {error}"),
            Self::Reference(error) => write!(f, "privacy mask retention: {error}"),
            Self::Spool(error) => write!(f, "privacy mask custody: {error}"),
            Self::Cancelled => f.write_str("privacy mask declaration cancelled"),
        }
    }
}

impl std::error::Error for PrivacyMaskError {}

impl From<ContractError> for PrivacyMaskError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

impl From<ReferenceError> for PrivacyMaskError {
    fn from(error: ReferenceError) -> Self {
        Self::Reference(Box::new(error))
    }
}

impl From<fss_object::SpoolError> for PrivacyMaskError {
    fn from(error: fss_object::SpoolError) -> Self {
        Self::Spool(error)
    }
}

/// One owner-declared, versioned mask policy for one sensor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyMaskPolicy {
    sensor_id: SensorId,
    width: u32,
    height: u32,
    regions: Vec<RedactedRegion>,
}

impl PrivacyMaskPolicy {
    /// Validates and builds a policy from `[x, y, width, height]` rectangles in decoded pixels
    /// at the declared stream resolution. Rectangles must be non-empty and inside the frame;
    /// order is canonicalized and duplicates are refused.
    pub fn new(
        sensor_id: SensorId,
        resolution: [u32; 2],
        rectangles: &[[u32; 4]],
    ) -> Result<Self, PrivacyMaskError> {
        let [width, height] = resolution;
        if width == 0 || height == 0 || width > MAX_MASK_DIMENSION || height > MAX_MASK_DIMENSION {
            return Err(PrivacyMaskError::InvalidPolicy(
                "stream resolution must be 1..4096 in each dimension",
            ));
        }
        if rectangles.is_empty() || rectangles.len() > MAX_MASK_REGIONS {
            return Err(PrivacyMaskError::InvalidPolicy(
                "a policy holds 1..32 rectangles",
            ));
        }
        let mut sorted = rectangles.to_vec();
        sorted.sort_unstable();
        if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(PrivacyMaskError::InvalidPolicy("duplicate rectangle"));
        }
        let mut regions = Vec::with_capacity(sorted.len());
        for [x, y, w, h] in sorted {
            if w == 0
                || h == 0
                || u64::from(x) + u64::from(w) > u64::from(width)
                || u64::from(y) + u64::from(h) > u64::from(height)
            {
                return Err(PrivacyMaskError::InvalidPolicy(
                    "every rectangle must be non-empty and inside the declared resolution",
                ));
            }
            regions.push(RedactedRegion::new(x, y, w, h, mask_transform().as_str())?);
        }
        let policy = Self {
            sensor_id,
            width,
            height,
            regions,
        };
        if policy.to_bytes().len() > MAX_MASK_POLICY_BYTES {
            return Err(PrivacyMaskError::InvalidPolicy("policy record too large"));
        }
        Ok(policy)
    }

    /// Sensor the policy applies to.
    #[must_use]
    pub fn sensor_id(&self) -> &SensorId {
        &self.sensor_id
    }

    /// Declared stream resolution `[width, height]`.
    #[must_use]
    pub fn resolution(&self) -> [u32; 2] {
        [self.width, self.height]
    }

    /// Masked rectangles in canonical order.
    #[must_use]
    pub fn regions(&self) -> &[RedactedRegion] {
        &self.regions
    }

    /// Exact canonical record bytes (the retained payload).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        e.bytes(POLICY_MAGIC);
        e.u32(POLICY_VERSION);
        e.text(MASK_POLICY_DOMAIN);
        self.sensor_id.encode_canonical(&mut e);
        e.u32(self.width);
        e.u32(self.height);
        e.u64(self.regions.len() as u64);
        for region in &self.regions {
            region.encode_canonical(&mut e);
        }
        e.finish()
    }

    /// Policy digest (SHA-256 of [`Self::to_bytes`]).
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.to_bytes())
    }

    /// Decodes exact retained bytes against their authority digest; non-canonical input fails.
    pub fn from_bytes(bytes: &[u8], expected: ContentDigest) -> Result<Self, PrivacyMaskError> {
        if bytes.len() > MAX_MASK_POLICY_BYTES || ContentDigest::sha256(bytes) != expected {
            return Err(PrivacyMaskError::InvalidRecord);
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.bytes()? != POLICY_MAGIC
            || d.u32()? != POLICY_VERSION
            || d.text()? != MASK_POLICY_DOMAIN
        {
            return Err(PrivacyMaskError::InvalidRecord);
        }
        let sensor_id = SensorId::decode_canonical(&mut d)?;
        let width = d.u32()?;
        let height = d.u32()?;
        let count = usize::try_from(d.u64()?)
            .ok()
            .filter(|count| *count <= MAX_MASK_REGIONS)
            .ok_or(PrivacyMaskError::InvalidRecord)?;
        let mut rectangles = Vec::with_capacity(count);
        for _ in 0..count {
            let region = RedactedRegion::decode_canonical(&mut d)?;
            if region.method() != mask_transform().as_str() {
                return Err(PrivacyMaskError::InvalidRecord);
            }
            rectangles.push([region.x(), region.y(), region.width(), region.height()]);
        }
        d.ensure_finished()?;
        let policy = Self::new(sensor_id, [width, height], &rectangles)
            .map_err(|_| PrivacyMaskError::InvalidRecord)?;
        if policy.to_bytes() != bytes {
            return Err(PrivacyMaskError::InvalidRecord);
        }
        Ok(policy)
    }
}

/// One retained policy generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedMaskPolicy {
    /// Decoded, validated policy.
    pub policy: PrivacyMaskPolicy,
    /// Retained payload digest (= policy digest).
    pub digest: ContentDigest,
    /// Ledger generation of the sensor's mask object.
    pub generation: u64,
}

/// The mask a decode applied: an explicit "no policy" marker, or one retained policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaskBinding {
    /// The sensor has no retained mask policy; decoded pixels are unmasked and marked so.
    NoPolicy,
    /// The sensor's current retained policy.
    Policy(Box<RetainedMaskPolicy>),
}

/// Binding digest of an optional policy digest (the explicit marker when `None`).
#[must_use]
pub fn binding_digest(policy: Option<ContentDigest>) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(MASK_BINDING_DOMAIN);
    match policy {
        None => e.u8(0),
        Some(digest) => {
            e.u8(1);
            e.digest(digest);
        }
    }
    ContentDigest::sha256(&e.finish())
}

/// Folds a mask binding into a derived identity, so lineages of different mask generations can
/// never share an identity.
#[must_use]
pub fn lineage_digest(label: &str, base: ContentDigest, binding: ContentDigest) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(MASK_LINEAGE_DOMAIN);
    e.text(label);
    e.digest(base);
    e.digest(binding);
    ContentDigest::sha256(&e.finish())
}

/// Canonical encoding of an optional policy digest inside a receipt: tag, then digest.
pub fn encode_marker(e: &mut CanonicalEncoder, policy: Option<ContentDigest>) {
    match policy {
        None => e.u8(0),
        Some(digest) => {
            e.u8(1);
            e.digest(digest);
        }
    }
}

/// Decodes [`encode_marker`]; unknown tags and non-SHA-256 digests fail.
pub fn decode_marker(d: &mut CanonicalDecoder<'_>) -> Result<Option<ContentDigest>, ContractError> {
    match d.u8()? {
        0 => Ok(None),
        1 => {
            let digest = d.digest()?;
            if digest.algorithm() != DigestAlgorithm::Sha256 {
                return Err(ContractError::InvalidIdentifier);
            }
            Ok(Some(digest))
        }
        _ => Err(ContractError::InvalidIdentifier),
    }
}

impl MaskBinding {
    /// Retained policy digest, or `None` for the explicit no-policy marker.
    #[must_use]
    pub fn policy_digest(&self) -> Option<ContentDigest> {
        match self {
            Self::NoPolicy => None,
            Self::Policy(retained) => Some(retained.digest),
        }
    }

    /// Binding digest bound into every derived identity.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        binding_digest(self.policy_digest())
    }

    /// Retained policy, if any.
    #[must_use]
    pub fn policy(&self) -> Option<&PrivacyMaskPolicy> {
        match self {
            Self::NoPolicy => None,
            Self::Policy(retained) => Some(&retained.policy),
        }
    }

    /// Ledger generation of the policy, if any.
    #[must_use]
    pub fn generation(&self) -> Option<u64> {
        match self {
            Self::NoPolicy => None,
            Self::Policy(retained) => Some(retained.generation),
        }
    }

    /// Stable spelling: `no_policy_declared` or `sensor_policy`.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::NoPolicy => "no_policy_declared",
            Self::Policy(_) => "sensor_policy",
        }
    }

    /// The applied transform from the existing redaction vocabulary, if any was applied.
    #[must_use]
    pub fn applied_transform(&self) -> Option<&'static str> {
        self.policy().map(|_| mask_transform().as_str())
    }

    /// Typed JSON object of the privacy transform applied to decoded pixels.
    #[must_use]
    pub fn to_json(&self) -> String {
        let quoted =
            |value: Option<String>| value.map_or_else(|| "null".to_owned(), |v| format!("\"{v}\""));
        let regions = self.policy().map_or_else(String::new, |policy| {
            policy
                .regions()
                .iter()
                .map(|r| format!("[{},{},{},{}]", r.x(), r.y(), r.width(), r.height()))
                .collect::<Vec<_>>()
                .join(",")
        });
        let resolution = self.policy().map_or_else(
            || "null".to_owned(),
            |policy| format!("[{},{}]", policy.resolution()[0], policy.resolution()[1]),
        );
        format!(
            "{{\"binding\":\"{}\",\"binding_digest\":\"{}\",\"applied_redaction_transform\":{},\"policy_digest\":{},\"policy_generation\":{},\"stream_resolution\":{},\"masked_rectangles\":[{}],\"fill\":{{\"luma\":{},\"chroma\":{},\"rgb\":[{},{},{}]}},\"unmasked_access\":\"refused\"}}",
            self.label(),
            self.digest(),
            quoted(self.applied_transform().map(str::to_owned)),
            quoted(self.policy_digest().map(|d| d.to_text())),
            self.generation()
                .map_or_else(|| "null".to_owned(), |g| g.to_string()),
            resolution,
            regions,
            MASK_FILL_LUMA,
            MASK_FILL_CHROMA,
            MASK_FILL_RGB[0],
            MASK_FILL_RGB[1],
            MASK_FILL_RGB[2],
        )
    }
}

/// Ledger object of a sensor's mask policy.
pub fn mask_object_id(sensor: &SensorId) -> Result<ObjectId, ContractError> {
    ObjectId::parse(format!(
        "object:privacy-mask:{}",
        hex(ContentDigest::sha256(sensor.as_str().as_bytes()))
    ))
}

/// Every retained generation of `sensor`'s mask object: (generation, payload, prior generation).
fn retained_generations(
    deployment: &ReferenceDeployment,
    sensor: &SensorId,
) -> Result<Vec<(u64, ContentDigest, Option<u64>)>, PrivacyMaskError> {
    let object = mask_object_id(sensor)?;
    let mut generations: Vec<(u64, ContentDigest, Option<u64>)> = deployment
        .ledger()
        .batches()
        .iter()
        .flat_map(|batch| batch.deltas.iter())
        .filter(|delta| delta.family == FAMILY_PRIVACY_MASK_POLICY && delta.object_id == object)
        .map(|delta| {
            (
                delta.new_generation,
                delta.payload_digest,
                delta.prior_generation,
            )
        })
        .collect();
    generations.sort_unstable();
    for (index, (generation, _, prior)) in generations.iter().enumerate() {
        let expected_prior = index.checked_sub(1).map(|p| p as u64 + 1);
        if *generation != index as u64 + 1 || *prior != expected_prior {
            return Err(PrivacyMaskError::InvalidRecord);
        }
    }
    Ok(generations)
}

fn read_policy(
    deployment: &ReferenceDeployment,
    sensor: &SensorId,
    generation: u64,
    digest: ContentDigest,
) -> Result<RetainedMaskPolicy, PrivacyMaskError> {
    let bytes = deployment.publisher().spool().read(digest)?;
    let policy = PrivacyMaskPolicy::from_bytes(&bytes, digest)?;
    if policy.sensor_id() != sensor {
        return Err(PrivacyMaskError::InvalidRecord);
    }
    Ok(RetainedMaskPolicy {
        policy,
        digest,
        generation,
    })
}

/// The sensor's current binding: its newest retained policy generation, or the explicit
/// no-policy marker. Damaged custody fails closed; it is never treated as "no policy".
pub fn current_mask(
    deployment: &ReferenceDeployment,
    sensor: &SensorId,
) -> Result<MaskBinding, PrivacyMaskError> {
    let generations = retained_generations(deployment, sensor)?;
    match generations.last() {
        None => Ok(MaskBinding::NoPolicy),
        Some((generation, digest, _)) => Ok(MaskBinding::Policy(Box::new(read_policy(
            deployment,
            sensor,
            *generation,
            *digest,
        )?))),
    }
}

/// Binding digests of every lineage the sensor's current binding superseded: the no-policy
/// marker and every earlier retained generation (empty when no policy is retained).
pub fn superseded_bindings(
    deployment: &ReferenceDeployment,
    sensor: &SensorId,
) -> Result<Vec<ContentDigest>, PrivacyMaskError> {
    let generations = retained_generations(deployment, sensor)?;
    let Some((_, current, _)) = generations.last() else {
        return Ok(Vec::new());
    };
    let mut out = vec![binding_digest(None)];
    for (_, digest, _) in &generations {
        if digest != current {
            out.push(binding_digest(Some(*digest)));
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

/// Fails closed with [`PrivacyMaskError::UnmaskedAccessRefused`] when the sensor has a retained
/// policy: the raw retained source cannot be masked without re-encoding, so it is not exported.
pub fn refuse_unmasked_source(
    deployment: &ReferenceDeployment,
    sensor: &SensorId,
) -> Result<(), PrivacyMaskError> {
    match current_mask(deployment, sensor)? {
        MaskBinding::NoPolicy => Ok(()),
        MaskBinding::Policy(_) => Err(PrivacyMaskError::UnmaskedAccessRefused),
    }
}

/// Exact approval of declaring `policy` over the sensor's current retained state.
#[must_use]
pub fn approval_digest(
    policy: ContentDigest,
    current: Option<(u64, ContentDigest)>,
) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(MASK_APPROVAL_DOMAIN);
    e.digest(policy);
    match current {
        None => e.u8(0),
        Some((generation, digest)) => {
            e.u8(1);
            e.u64(generation);
            e.digest(digest);
        }
    }
    ContentDigest::sha256(&e.finish())
}

/// Retention state of one declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaskDeclarationStatus {
    /// Previewed only; nothing is retained.
    Proposed,
    /// Retained by this call as a new generation.
    Retained,
    /// This exact policy is already the sensor's current policy; nothing was written.
    AlreadyCurrent,
}

impl MaskDeclarationStatus {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Retained => "retained",
            Self::AlreadyCurrent => "already_current",
        }
    }
}

/// Outcome of a preview or declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaskDeclaration {
    /// The declared policy.
    pub policy: PrivacyMaskPolicy,
    /// Its digest.
    pub policy_digest: ContentDigest,
    /// Exact approval that retains it over the state it was previewed against.
    pub approval: ContentDigest,
    /// Retention state.
    pub status: MaskDeclarationStatus,
    /// The sensor's policy generation after this call (`None`: still no policy).
    pub generation: Option<u64>,
    /// The policy digest this declaration replaces (`None`: no policy was retained).
    pub replaces: Option<ContentDigest>,
}

/// Previews a declaration: computes the policy and approval digests; writes nothing.
pub fn preview_mask(
    deployment: &ReferenceDeployment,
    policy: &PrivacyMaskPolicy,
) -> Result<MaskDeclaration, PrivacyMaskError> {
    let generations = retained_generations(deployment, policy.sensor_id())?;
    let digest = policy.digest();
    let current = generations.last().map(|(g, d, _)| (*g, *d));
    let already = current.is_some_and(|(_, d)| d == digest);
    // Validate the current record's custody before proposing to replace it.
    if let Some((generation, current_digest)) = current {
        read_policy(deployment, policy.sensor_id(), generation, current_digest)?;
    }
    Ok(MaskDeclaration {
        policy: policy.clone(),
        policy_digest: digest,
        approval: approval_digest(digest, current),
        status: if already {
            MaskDeclarationStatus::AlreadyCurrent
        } else {
            MaskDeclarationStatus::Proposed
        },
        generation: current.map(|(g, _)| g),
        replaces: current.map(|(_, d)| d).filter(|d| *d != digest),
    })
}

/// Retains `policy` as the sensor's next generation when `approval` is its exact approval over
/// the current retained state. Checked before any write. Declaring the current policy again,
/// or re-presenting the approval that retained it, writes nothing.
pub fn declare_mask(
    deployment: &mut ReferenceDeployment,
    policy: &PrivacyMaskPolicy,
    approval: ContentDigest,
    cx: &ReplayCx,
) -> Result<MaskDeclaration, PrivacyMaskError> {
    let preview = preview_mask(deployment, policy)?;
    let generations = retained_generations(deployment, policy.sensor_id())?;
    if preview.status == MaskDeclarationStatus::AlreadyCurrent {
        // The approval that retained the current generation was computed over its predecessor.
        let retained_over = generations.len().checked_sub(2).map(|index| {
            let (g, d, _) = generations[index];
            (g, d)
        });
        let original = approval_digest(preview.policy_digest, retained_over);
        if approval != preview.approval && approval != original {
            return Err(PrivacyMaskError::StaleApproval(approval));
        }
        return Ok(preview);
    }
    if approval != preview.approval {
        return Err(PrivacyMaskError::StaleApproval(approval));
    }
    cx.checkpoint("privacy_mask:declare")
        .map_err(|_| PrivacyMaskError::Cancelled)?;
    let bytes = policy.to_bytes();
    let payload = deployment.stage_payload(&bytes)?;
    if payload != preview.policy_digest {
        return Err(PrivacyMaskError::InvalidRecord);
    }
    let prior = generations.last().map(|(g, _, _)| *g);
    let generation = prior.map_or(1, |g| g + 1);
    let validity = CaptureInterval::new(TimestampNs(0), TimestampNs(i128::from(i64::MAX)))?;
    let delta = EvidenceDelta {
        delta_id: format!("delta:privacy-mask:{}", hex(approval)),
        family: FAMILY_PRIVACY_MASK_POLICY.to_owned(),
        object_id: mask_object_id(policy.sensor_id())?,
        prior_generation: prior,
        new_generation: generation,
        validity,
        plane: Plane::Authority,
        payload_digest: payload,
        witness_digest: None,
        operation_id: None,
    };
    let batch = BatchId::parse(format!("batch:privacy-mask:{}", hex(approval)))?;
    deployment.append_batch(batch, vec![delta], vec![payload], cx)?;
    cx.checkpoint_post_commit("privacy_mask:retained");
    Ok(MaskDeclaration {
        status: MaskDeclarationStatus::Retained,
        generation: Some(generation),
        ..preview
    })
}

#[cfg(test)]
mod tests;
