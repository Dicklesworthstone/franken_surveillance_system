#![forbid(unsafe_code)]
//! Portable, bounded localization atlases; no I/O, activation, or image decoding.

use crate::{PropertyTwin, localization::{AtlasBinding, AtlasLandmark, AtlasReference,
    BinaryDescriptor, FeatureFrame, ImageFeature, ImageIdentity, LocalizationAtlas,
    LocalizationError, MAX_ATLAS_LANDMARKS, MAX_ATLAS_REFERENCES, MAX_IMAGE_FEATURES}};
use fss_core::ContentDigest;
use fss_geometry::{GeometryError, WorkBudget};

/// Hard ceiling on the whole archive, including its checksum.
pub const MAX_ATLAS_BYTES: usize = 8 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"FSATLAS1";
const MAX_BINDINGS: usize = MAX_ATLAS_REFERENCES * MAX_IMAGE_FEATURES;

/// Non-disclosing archive failures. Hash agreement is not source authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveError {
    /// Truncated, noncanonical, unknown, or inconsistent wire data.
    Format,
    /// Whole-file or trailer identity differs.
    Digest,
    /// Expected twin, descriptor generation, provenance, or semantic root differs.
    Basis,
    /// A byte, count, allocation, or output ceiling was exceeded.
    Limit,
    /// Invalid atlas inputs or a cancelled/exhausted geometry operation.
    Localization(LocalizationError),
}
impl From<LocalizationError> for ArchiveError {
    fn from(error: LocalizationError) -> Self { Self::Localization(error) }
}
impl From<GeometryError> for ArchiveError {
    fn from(error: GeometryError) -> Self { Self::Localization(error.into()) }
}
impl std::fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Format => "invalid atlas archive", Self::Digest => "atlas checksum mismatch",
            Self::Basis => "atlas archive basis mismatch", Self::Limit => "atlas archive limit exceeded",
            Self::Localization(_) => "atlas validation or bounded work failed",
        })
    }
}
impl std::error::Error for ArchiveError {}

/// Retained source-recipe and complete allowed-pixel-mask identities for one view.
/// These references are not proof that the private source files remain available.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferenceProvenance {
    /// Reference handle in this atlas, not an independent camera identity.
    pub reference: u64,
    /// Source record binding PTS/stream, map pose, image conversion, and selection.
    pub source_record: [u8; 32],
    /// Exact 0/1 allowed-pixel mask used when describing this reference image.
    pub allowed_mask: [u8; 32],
}

/// Owner-pinned identities, supplied independently from the bytes being imported.
#[derive(Clone, Copy, Debug)]
pub struct ArchiveExpectation {
    /// SHA-256 of the complete archive including its trailer.
    pub package: [u8; 32],
    /// Authoring manifest containing map/scene alignment and source recipe records.
    pub provenance: [u8; 32],
    /// Exact admitted descriptor construction/generation.
    pub descriptor: [u8; 32],
}

/// Fully validated, unactivated atlas and source bindings.
#[derive(Debug)]
pub struct ArchivedAtlas {
    atlas: LocalizationAtlas,
    references: Vec<ReferenceProvenance>,
    provenance: [u8; 32],
    package: [u8; 32],
}
impl ArchivedAtlas {
    /// Atlas ready for matching in the supplied immutable property's basis.
    pub fn atlas(&self) -> &LocalizationAtlas { &self.atlas }
    /// All source/mask bindings in reference-ID order.
    pub fn references(&self) -> &[ReferenceProvenance] { &self.references }
    /// Retained source manifest identity, not implicit permission to hydrate it.
    pub fn provenance(&self) -> [u8; 32] { self.provenance }
    /// Whole-file identity, distinct from the normalized atlas fingerprint.
    pub fn package(&self) -> [u8; 32] { self.package }
}

/// Serialize a complete atlas in canonical ID order, preserving unknown errors.
/// The caller owns create-only publication, source retention, and authorization.
pub fn encode_atlas(atlas: &LocalizationAtlas, provenance: [u8; 32],
    references: &[ReferenceProvenance], budget: &mut WorkBudget<'_>) -> Result<Vec<u8>, ArchiveError> {
    budget.charge(0)?;
    if provenance == [0; 32] || references.len() != atlas.references().len() { return Err(ArchiveError::Basis); }
    for (source, view) in references.iter().zip(atlas.references()) {
        budget.charge(1)?;
        if source.reference != view.id || source.source_record == [0; 32] || source.allowed_mask == [0; 32] {
            return Err(ArchiveError::Basis);
        }
    }
    let features: usize = atlas.references().iter().map(|r| r.frame.features().len()).sum();
    let capacity = 188 + atlas.landmarks().len() * 101 + references.len() * 180
        + features * 56 + atlas.bindings().len() * 24;
    if capacity > MAX_ATLAS_BYTES { return Err(ArchiveError::Limit); }
    budget.charge(capacity as u64)?;
    let mut b = Vec::new();
    b.try_reserve_exact(capacity).map_err(|_| ArchiveError::Limit)?;
    b.extend_from_slice(MAGIC); put64(&mut b, 0);
    b.extend_from_slice(&atlas.twin_digest());
    let first = atlas.references().first().ok_or(ArchiveError::Format)?;
    b.extend_from_slice(&first.frame.descriptor_domain());
    b.extend_from_slice(&atlas.digest()); b.extend_from_slice(&provenance);
    put32(&mut b, atlas.landmarks().len() as u32);
    put32(&mut b, references.len() as u32); put32(&mut b, atlas.bindings().len() as u32);
    for p in atlas.landmarks() {
        budget.charge(1)?;
        put64(&mut b, p.id); put64(&mut b, p.physical_group); put32(&mut b, p.feature);
        for x in p.world { put_float(&mut b, x); }
        b.extend_from_slice(&p.evidence); b.push(u8::from(p.error.is_some()));
        if let Some(error) = p.error { for x in error { put_float(&mut b, x); } }
    }
    for (r, source) in atlas.references().iter().zip(references) {
        budget.charge(1)?;
        put64(&mut b, r.id); let identity = r.frame.identity();
        for hash in [identity.exposure, identity.pixels, identity.image_domain] { b.extend_from_slice(&hash); }
        for n in identity.dimensions { put32(&mut b, n); }
        b.extend_from_slice(&source.source_record); b.extend_from_slice(&source.allowed_mask);
        put32(&mut b, r.frame.features().len() as u32);
        for f in r.frame.features() {
            budget.charge(1)?;
            put64(&mut b, f.id); for x in f.pixel { put_float(&mut b, x); }
            for word in f.descriptor.0 { put64(&mut b, word); }
        }
    }
    for v in atlas.bindings() {
        budget.charge(1)?;
        put64(&mut b, v.landmark); put64(&mut b, v.reference); put64(&mut b, v.image_feature);
    }
    let length = (b.len() - 16) as u64;
    b[8..16].copy_from_slice(&length.to_le_bytes());
    budget.charge(b.len() as u64)?;
    let checksum = ContentDigest::sha256(&b).bytes(); b.extend_from_slice(&checksum);
    budget.charge(0)?;
    Ok(b)
}

/// Validate exact bytes and every semantic association before returning any atlas.
/// Process-local geometry handles are resolved from `twin`, never read from disk.
pub fn decode_atlas(bytes: &[u8], twin: &PropertyTwin, expected: ArchiveExpectation,
    budget: &mut WorkBudget<'_>) -> Result<ArchivedAtlas, ArchiveError> {
    budget.charge(0)?;
    if bytes.len() > MAX_ATLAS_BYTES { return Err(ArchiveError::Limit); }
    if bytes.len() < 188 { return Err(ArchiveError::Format); }
    if [expected.package, expected.provenance, expected.descriptor].contains(&[0; 32]) { return Err(ArchiveError::Basis); }
    budget.charge(bytes.len() as u64 * 2)?;
    if ContentDigest::sha256(bytes).bytes() != expected.package { return Err(ArchiveError::Digest); }
    let end = bytes.len() - 32;
    if ContentDigest::sha256(&bytes[..end]).bytes().as_slice() != &bytes[end..] { return Err(ArchiveError::Digest); }
    let mut r = Reader { bytes: &bytes[..end], offset: 0 };
    if r.take(8)? != MAGIC || r.u64()? != (end - 16) as u64 { return Err(ArchiveError::Format); }
    if r.hash()? != twin.digest() || r.hash()? != expected.descriptor { return Err(ArchiveError::Basis); }
    let semantic = r.hash()?;
    if r.hash()? != expected.provenance { return Err(ArchiveError::Basis); }
    let np = r.count(MAX_ATLAS_LANDMARKS)?;
    let nr = r.count(MAX_ATLAS_REFERENCES)?;
    let nb = r.count(MAX_BINDINGS)?;
    r.require_bytes(np * 77 + nr * 180 + nb * 24)?;
    let mut landmarks = reserved(np)?;
    let mut last = 0;
    for _ in 0..np {
        budget.charge(1)?;
        let id = r.ordered_id(&mut last)?; let physical_group = r.u64()?; let feature = r.u32()?;
        let world = [r.float()?, r.float()?, r.float()?]; let evidence = r.hash()?;
        let error = match r.byte()? { 0 => None, 1 => Some([r.float()?, r.float()?, r.float()?]), _ => return Err(ArchiveError::Format) };
        landmarks.push(AtlasLandmark { id, physical_group, feature, world, evidence, error });
    }
    let mut views = reserved(nr)?; let mut references = reserved(nr)?; last = 0;
    for _ in 0..nr {
        budget.charge(1)?;
        let id = r.ordered_id(&mut last)?;
        let identity = ImageIdentity { exposure: r.hash()?, pixels: r.hash()?, image_domain: r.hash()?, dimensions: [r.u32()?, r.u32()?] };
        let source = ReferenceProvenance { reference: id, source_record: r.hash()?, allowed_mask: r.hash()? };
        let nf = r.count(MAX_IMAGE_FEATURES)?; r.require_bytes(nf * 56)?;
        let mut features = reserved(nf)?; let mut last_feature = 0;
        for _ in 0..nf {
            budget.charge(1)?;
            features.push(ImageFeature { id: r.ordered_id(&mut last_feature)?, pixel: [r.float()?, r.float()?],
                descriptor: BinaryDescriptor([r.u64()?, r.u64()?, r.u64()?, r.u64()?]) });
        }
        views.push(AtlasReference { id, frame: FeatureFrame::new(identity, expected.descriptor, features, budget)? });
        references.push(source);
    }
    r.require_bytes(nb * 24)?;
    let mut bindings = reserved(nb)?; let mut last_binding = (0, 0, 0);
    for _ in 0..nb {
        budget.charge(1)?;
        let key = (r.u64()?, r.u64()?, r.u64()?);
        if key <= last_binding { return Err(ArchiveError::Format); } last_binding = key;
        bindings.push(AtlasBinding { landmark: key.0, reference: key.1, image_feature: key.2 });
    }
    if r.offset != r.bytes.len() { return Err(ArchiveError::Format); }
    let atlas = LocalizationAtlas::new(twin, landmarks, views, bindings, budget)?;
    if atlas.digest() != semantic { return Err(ArchiveError::Basis); }
    budget.charge(0)?;
    Ok(ArchivedAtlas { atlas, references, provenance: expected.provenance, package: expected.package })
}
fn reserved<T>(count: usize) -> Result<Vec<T>, ArchiveError> {
    let mut value = Vec::new(); value.try_reserve_exact(count).map_err(|_| ArchiveError::Limit)?; Ok(value)
}
fn put32(b: &mut Vec<u8>, n: u32) { b.extend_from_slice(&n.to_le_bytes()); }
fn put64(b: &mut Vec<u8>, n: u64) { b.extend_from_slice(&n.to_le_bytes()); }
fn put_float(b: &mut Vec<u8>, n: f64) { put64(b, if n == 0.0 { 0 } else { n.to_bits() }); }
struct Reader<'a> { bytes: &'a [u8], offset: usize }
impl<'a> Reader<'a> {
    fn require_bytes(&self, n: usize) -> Result<(), ArchiveError> {
        if n > self.bytes.len() - self.offset { Err(ArchiveError::Format) } else { Ok(()) }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], ArchiveError> {
        self.require_bytes(n)?; let start = self.offset; self.offset += n; Ok(&self.bytes[start..self.offset])
    }
    fn byte(&mut self) -> Result<u8, ArchiveError> { Ok(self.take(1)?[0]) }
    fn u32(&mut self) -> Result<u32, ArchiveError> {
        let mut b = [0; 4]; b.copy_from_slice(self.take(4)?); Ok(u32::from_le_bytes(b))
    }
    fn u64(&mut self) -> Result<u64, ArchiveError> {
        let mut b = [0; 8]; b.copy_from_slice(self.take(8)?); Ok(u64::from_le_bytes(b))
    }
    fn hash(&mut self) -> Result<[u8; 32], ArchiveError> {
        let mut b = [0; 32]; b.copy_from_slice(self.take(32)?);
        if b == [0; 32] { return Err(ArchiveError::Basis); } Ok(b)
    }
    fn count(&mut self, max: usize) -> Result<usize, ArchiveError> {
        let n = self.u32()? as usize;
        if n == 0 { return Err(ArchiveError::Format); }
        if n > max { return Err(ArchiveError::Limit); } Ok(n)
    }
    fn ordered_id(&mut self, previous: &mut u64) -> Result<u64, ArchiveError> {
        let n = self.u64()?; if n <= *previous { return Err(ArchiveError::Format); } *previous = n; Ok(n)
    }
    fn float(&mut self) -> Result<f64, ArchiveError> {
        let bits = self.u64()?; let n = f64::from_bits(bits);
        if !n.is_finite() || bits == (1_u64 << 63) { return Err(ArchiveError::Format); } Ok(n)
    }
}
