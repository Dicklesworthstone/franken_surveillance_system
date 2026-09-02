//! Canonical replay bundle and content-bound continuation cursor.

use std::error::Error;
use std::fmt;

use fss_core::{CapsuleId, ContentDigest, ContractError, LedgerAnchor, SensorId};
use fss_ledger::DurableReferenceLedger;
use fss_object::InMemoryObjectStore;

use crate::{
    DeliveryDirective, DeliveryMutation, DeliveryPlan, ReferenceCapture, ReferenceError,
    VirtualCameraSpec, run_reference_capture,
};

const MAGIC: [u8; 8] = *b"FSSRPL01";
const VERSION: u16 = 1;
const MAX_TEXT_BYTES: usize = 4_096;
const MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;
const CURSOR_DOMAIN: &[u8] = b"FSS-REPLAY-CURSOR-V1\0";

/// Canonical replay-bundle decoding or continuation failure.
#[derive(Debug)]
pub enum ReplayBundleError {
    /// Input ended before one complete field.
    UnexpectedEof,
    /// Replay magic is not recognized.
    InvalidMagic,
    /// Replay bundle version is unsupported.
    UnsupportedVersion(u16),
    /// One bounded field exceeds its frozen limit.
    BoundExceeded(&'static str),
    /// Text is not valid UTF-8.
    InvalidUtf8,
    /// A delivery-mutation tag is unknown.
    InvalidMutation(u8),
    /// Bytes remain after the one complete bundle.
    TrailingBytes,
    /// Bundle bytes do not match their terminal digest.
    BundleDigestMismatch,
    /// Replay is not scoped to a fresh authority ledger.
    NonGenesisAuthority,
    /// Cursor belongs to a different bundle or prefix.
    CursorMismatch,
    /// Cursor position lies beyond or behind the allowed range.
    CursorOutOfRange,
    /// Core stable-ID or interval contract failure.
    Contract(ContractError),
    /// Underlying deterministic replay failed.
    Reference(ReferenceError),
}

impl fmt::Display for ReplayBundleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => formatter.write_str("replay bundle unexpected EOF"),
            Self::InvalidMagic => formatter.write_str("replay bundle invalid magic"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "replay bundle unsupported version {version}")
            }
            Self::BoundExceeded(field) => {
                write!(formatter, "replay bundle bound exceeded: {field}")
            }
            Self::InvalidUtf8 => formatter.write_str("replay bundle invalid UTF-8"),
            Self::InvalidMutation(value) => {
                write!(formatter, "replay bundle invalid delivery mutation {value}")
            }
            Self::TrailingBytes => formatter.write_str("replay bundle trailing bytes"),
            Self::BundleDigestMismatch => formatter.write_str("replay bundle digest mismatch"),
            Self::NonGenesisAuthority => {
                formatter.write_str("replay requires a fresh authority ledger")
            }
            Self::CursorMismatch => formatter.write_str("replay cursor does not match bundle prefix"),
            Self::CursorOutOfRange => formatter.write_str("replay cursor is out of range"),
            Self::Contract(error) => write!(formatter, "replay bundle contract error: {error}"),
            Self::Reference(error) => write!(formatter, "replay execution error: {error}"),
        }
    }
}

impl Error for ReplayBundleError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::Reference(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ContractError> for ReplayBundleError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}

impl From<ReferenceError> for ReplayBundleError {
    fn from(value: ReferenceError) -> Self {
        Self::Reference(value)
    }
}

/// Self-verifying deterministic replay bundle containing only causal replay inputs.
///
/// Expected outputs deliberately do not live in this input object. Qualification executes the
/// same bundle in fresh deployments and compares independently retained output roots/receipts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayBundle {
    site_lineage: String,
    spec: VirtualCameraSpec,
    plan: DeliveryPlan,
}

impl ReplayBundle {
    /// Creates a bounded deterministic replay input bundle.
    pub fn new(
        site_lineage: impl Into<String>,
        spec: VirtualCameraSpec,
        plan: DeliveryPlan,
    ) -> Result<Self, ReplayBundleError> {
        let site_lineage = site_lineage.into();
        if site_lineage.is_empty() || site_lineage.len() > MAX_TEXT_BYTES {
            return Err(ReplayBundleError::BoundExceeded("site_lineage"));
        }
        spec.validate()?;
        plan.validate_against(spec.packet_count)?;
        Ok(Self {
            site_lineage,
            spec,
            plan,
        })
    }

    /// Deployment/site lineage used for a fresh replay ledger.
    #[must_use]
    pub fn site_lineage(&self) -> &str {
        &self.site_lineage
    }

    /// Frozen virtual-camera specification.
    #[must_use]
    pub const fn spec(&self) -> &VirtualCameraSpec {
        &self.spec
    }

    /// Frozen ordered delivery/fault plan.
    #[must_use]
    pub const fn plan(&self) -> &DeliveryPlan {
        &self.plan
    }

    /// Stable SHA-256 identity of canonical bundle body bytes.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.body_bytes())
    }

    /// Encodes one self-verifying bounded binary bundle.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.body_bytes();
        bytes.extend_from_slice(&self.digest().bytes());
        bytes
    }

    /// Decodes one canonical self-verifying replay bundle.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ReplayBundleError> {
        if bytes.len() > MAX_BUNDLE_BYTES {
            return Err(ReplayBundleError::BoundExceeded("bundle_bytes"));
        }
        if bytes.len() < 32 {
            return Err(ReplayBundleError::UnexpectedEof);
        }
        let body_len = bytes.len() - 32;
        let body = &bytes[..body_len];
        let mut named_digest = [0_u8; 32];
        named_digest.copy_from_slice(&bytes[body_len..]);
        if ContentDigest::sha256(body).bytes() != named_digest {
            return Err(ReplayBundleError::BundleDigestMismatch);
        }

        let mut reader = Reader::new(body);
        if reader.array::<8>()? != MAGIC {
            return Err(ReplayBundleError::InvalidMagic);
        }
        let version = reader.u16()?;
        if version != VERSION {
            return Err(ReplayBundleError::UnsupportedVersion(version));
        }
        let site_lineage = reader.text()?;
        let spec = VirtualCameraSpec {
            capture_id: CapsuleId::parse(reader.text()?)?,
            sensor_id: SensorId::parse(reader.text()?)?,
            seed: reader.u64()?,
            packet_count: reader.u32()?,
            packet_bytes: reader.usize_u32("packet_bytes")?,
            start_ns: reader.i128()?,
            period_ns: reader.u64()?,
            uncertainty_ns: reader.u64()?,
        };

        let directive_count = reader.usize_u32("delivery_directives")?;
        if directive_count > crate::MAX_DELIVERY_DIRECTIVES {
            return Err(ReplayBundleError::BoundExceeded("delivery_directives"));
        }
        let mut directives = Vec::with_capacity(directive_count);
        for _ in 0..directive_count {
            let source_sequence = reader.u64()?;
            let mutation = match reader.u8()? {
                0 => DeliveryMutation::Exact,
                1 => DeliveryMutation::FlipFirstBit,
                value => return Err(ReplayBundleError::InvalidMutation(value)),
            };
            directives.push(DeliveryDirective {
                source_sequence,
                mutation,
            });
        }
        reader.finish()?;
        Self::new(site_lineage, spec, DeliveryPlan::new(directives)?)
    }

    /// Executes this input bundle against a disposable fresh reference deployment.
    ///
    /// Replays are deliberately confined to a genesis authority state. This prevents an input
    /// bundle from accidentally becoming an append/mutation protocol for a live deployment.
    pub fn replay(
        &self,
        objects: &mut InMemoryObjectStore,
        ledger: &mut DurableReferenceLedger,
    ) -> Result<ReferenceCapture, ReplayBundleError> {
        if ledger.current().anchor != LedgerAnchor::genesis(self.site_lineage.clone()) {
            return Err(ReplayBundleError::NonGenesisAuthority);
        }
        Ok(run_reference_capture(
            &self.spec,
            &self.plan,
            objects,
            ledger,
        )?)
    }

    /// Creates the zero-position content-bound replay cursor.
    #[must_use]
    pub fn cursor(&self) -> ReplayCursor {
        ReplayCursor::at(self, 0)
    }

    fn body_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&VERSION.to_be_bytes());
        text(&mut out, &self.site_lineage);
        text(&mut out, self.spec.capture_id.as_str());
        text(&mut out, self.spec.sensor_id.as_str());
        out.extend_from_slice(&self.spec.seed.to_be_bytes());
        out.extend_from_slice(&self.spec.packet_count.to_be_bytes());
        out.extend_from_slice(&(self.spec.packet_bytes as u32).to_be_bytes());
        out.extend_from_slice(&self.spec.start_ns.to_be_bytes());
        out.extend_from_slice(&self.spec.period_ns.to_be_bytes());
        out.extend_from_slice(&self.spec.uncertainty_ns.to_be_bytes());
        out.extend_from_slice(&(self.plan.directives().len() as u32).to_be_bytes());
        for directive in self.plan.directives() {
            out.extend_from_slice(&directive.source_sequence.to_be_bytes());
            out.push(mutation_tag(directive.mutation));
        }
        out
    }
}

/// Content-bound continuation over the replay bundle's ordered delivery plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayCursor {
    bundle_digest: ContentDigest,
    next_directive: usize,
    prefix_digest: ContentDigest,
}

impl ReplayCursor {
    /// Bundle identity this cursor can resume.
    #[must_use]
    pub const fn bundle_digest(self) -> ContentDigest {
        self.bundle_digest
    }

    /// Zero-based next directive index.
    #[must_use]
    pub const fn next_directive(self) -> usize {
        self.next_directive
    }

    /// Digest of the exact ordered directive prefix already acknowledged.
    #[must_use]
    pub const fn prefix_digest(self) -> ContentDigest {
        self.prefix_digest
    }

    /// True when every delivery directive has been acknowledged.
    #[must_use]
    pub fn is_complete(self, bundle: &ReplayBundle) -> bool {
        self.validate(bundle).is_ok() && self.next_directive == bundle.plan.directives().len()
    }

    /// Validates bundle identity, index, and a freshly recomputed prefix digest.
    pub fn validate(self, bundle: &ReplayBundle) -> Result<(), ReplayBundleError> {
        if self.bundle_digest != bundle.digest() {
            return Err(ReplayBundleError::CursorMismatch);
        }
        if self.next_directive > bundle.plan.directives().len() {
            return Err(ReplayBundleError::CursorOutOfRange);
        }
        if self.prefix_digest != prefix_digest(bundle, self.next_directive) {
            return Err(ReplayBundleError::CursorMismatch);
        }
        Ok(())
    }

    /// Returns a cursor advanced to an exact later directive boundary.
    pub fn advance_to(
        self,
        bundle: &ReplayBundle,
        next_directive: usize,
    ) -> Result<Self, ReplayBundleError> {
        self.validate(bundle)?;
        if next_directive < self.next_directive
            || next_directive > bundle.plan.directives().len()
        {
            return Err(ReplayBundleError::CursorOutOfRange);
        }
        Ok(Self::at(bundle, next_directive))
    }

    fn at(bundle: &ReplayBundle, next_directive: usize) -> Self {
        Self {
            bundle_digest: bundle.digest(),
            next_directive,
            prefix_digest: prefix_digest(bundle, next_directive),
        }
    }
}

fn prefix_digest(bundle: &ReplayBundle, count: usize) -> ContentDigest {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CURSOR_DOMAIN);
    bytes.extend_from_slice(&bundle.digest().bytes());
    bytes.extend_from_slice(&(count as u64).to_be_bytes());
    for directive in &bundle.plan.directives()[..count] {
        bytes.extend_from_slice(&directive.source_sequence.to_be_bytes());
        bytes.push(mutation_tag(directive.mutation));
    }
    ContentDigest::sha256(&bytes)
}

fn mutation_tag(mutation: DeliveryMutation) -> u8 {
    match mutation {
        DeliveryMutation::Exact => 0,
        DeliveryMutation::FlipFirstBit => 1,
    }
}

fn text(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn finish(&self) -> Result<(), ReplayBundleError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(ReplayBundleError::TrailingBytes)
        }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], ReplayBundleError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(ReplayBundleError::UnexpectedEof)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ReplayBundleError::UnexpectedEof)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ReplayBundleError> {
        let mut value = [0_u8; N];
        value.copy_from_slice(self.take(N)?);
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, ReplayBundleError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ReplayBundleError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, ReplayBundleError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ReplayBundleError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn i128(&mut self) -> Result<i128, ReplayBundleError> {
        Ok(i128::from_be_bytes(self.array()?))
    }

    fn text(&mut self) -> Result<String, ReplayBundleError> {
        let length = self.usize_u32("text")?;
        if length > MAX_TEXT_BYTES {
            return Err(ReplayBundleError::BoundExceeded("text"));
        }
        let value = std::str::from_utf8(self.take(length)?)
            .map_err(|_| ReplayBundleError::InvalidUtf8)?;
        Ok(value.to_owned())
    }

    fn usize_u32(&mut self, field: &'static str) -> Result<usize, ReplayBundleError> {
        usize::try_from(self.u32()?).map_err(|_| ReplayBundleError::BoundExceeded(field))
    }
}
