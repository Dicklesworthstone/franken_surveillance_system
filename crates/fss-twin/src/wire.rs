#![forbid(unsafe_code)]

use fss_core::ContentDigest;
use fss_geometry::{GeometryBasis, IndexedTriangle, MeshLimits, TriangleMesh, WorkBudget};
use crate::{PropertyTwin, ScaleEvidence, SurfaceKind, TwinError, TwinFeature, TwinObject};

const MAGIC: &[u8; 8] = b"FSSTWIN1";
const MAX_BYTES: usize = 64 * 1024 * 1024;

/// Exact independently supplied input identities; checksums do not authenticate a producer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportExpectation {
    /// SHA-256 of the entire expected package.
    pub package_sha256: [u8; 32],
    /// SHA-256 of the exact saved authoring file.
    pub source_scene_sha256: [u8; 32],
    /// A fresh owner-resolved revision for these geometry bytes.
    pub basis: GeometryBasis,
}

/// Caller ceilings may narrow, never enlarge, this format's bounds.
#[derive(Clone, Copy, Debug)]
pub struct ImportLimits {
    /// Maximum total bytes, at most 64 MiB.
    pub bytes: usize,
    /// Maximum features, at most 65,536.
    pub features: usize,
    /// Maximum evaluated objects, at most 65,536.
    pub objects: usize,
    /// Maximum vertices, at most 262,144.
    pub vertices: usize,
    /// Maximum triangles, at most 524,288.
    pub triangles: usize,
}
impl Default for ImportLimits {
    fn default() -> Self {
        Self { bytes: MAX_BYTES, features: 65_536, objects: 65_536,
            vertices: 262_144, triangles: 524_288 }
    }
}

/// Validate all bytes and references, then construct one immutable geometry result.
///
/// No filesystem or external URI is opened. Failed/cancelled imports publish nothing.
/// A caller supplies authority and source custody separately before activation.
pub fn import_twin(bytes: &[u8], expected: ImportExpectation, limits: ImportLimits,
    budget: &mut WorkBudget<'_>) -> Result<PropertyTwin, TwinError> {
    budget.charge(0)?;
    if limits.bytes > MAX_BYTES || limits.features > 65_536 || limits.objects > 65_536
        || limits.vertices > 262_144 || limits.triangles > 524_288 || bytes.len() > limits.bytes {
        return Err(TwinError::Limit);
    }
    if bytes.len() < 48 || bytes.get(..8) != Some(MAGIC.as_slice()) {
        return Err(TwinError::Format);
    }
    let mut header = Reader { bytes: &bytes[8..16], offset: 0 };
    let body_len = usize::try_from(header.u64()?).map_err(|_| TwinError::Limit)?;
    let end = 16usize.checked_add(body_len).ok_or(TwinError::Limit)?;
    if end.checked_add(32) != Some(bytes.len()) { return Err(TwinError::Format); }
    // Charge before either bounded hash walk. No allocation precedes digest checks.
    budget.charge((bytes.len() as u64).saturating_mul(2))?;
    let digest = ContentDigest::sha256(bytes).bytes();
    if digest != expected.package_sha256
        || ContentDigest::sha256(&bytes[..end]).bytes().as_slice() != &bytes[end..] {
        return Err(TwinError::Digest);
    }
    let mut r = Reader { bytes: &bytes[16..end], offset: 0 };
    let source: [u8; 32] = r.take(32)?.try_into().map_err(|_| TwinError::Format)?;
    if source == [0; 32] || source != expected.source_scene_sha256 { return Err(TwinError::Basis); }
    let scope = r.text(2048)?;
    let epoch = r.text(128)?;
    let tag = r.u8()?;
    let factor = r.number()?;
    let scale_error = r.number()?;
    let scale = match tag {
        0 if factor == 0.0 && scale_error == -1.0 => ScaleEvidence::Relative,
        1 | 2 if factor > 0.0 && factor <= 1e9 && (scale_error == -1.0
            || (scale_error >= 0.0 && scale_error < factor)) => {
            let error = (scale_error >= 0.0).then_some(scale_error);
            if tag == 1 { ScaleEvidence::Estimated { metres_per_unit: factor, error } }
            else { ScaleEvidence::MeasuredAnchor { metres_per_unit: factor, error } }
        }
        _ => return Err(TwinError::Numeric),
    };
    let error = r.number()?;
    if error != -1.0 && !(0.0..=1e12).contains(&error) { return Err(TwinError::Numeric); }
    let geometry_error = (error >= 0.0).then_some(error);
    let nf = r.count(limits.features)?;
    let no = r.count(limits.objects)?;
    let nv = r.count(limits.vertices)?;
    let nt = r.count(limits.triangles)?;
    // Lower bound on required wire bytes rejects count bombs before reservation.
    let minimum = nf * 4 + no * 9 + nv * 24 + nt * 16;
    if minimum > r.bytes.len() - r.offset { return Err(TwinError::Format); }
    budget.charge((nf + no + nv + nt) as u64)?;
    let mut features: Vec<TwinFeature> = allocated(nf)?;
    for _ in 0..nf {
        budget.charge(1)?;
        let id = r.text(256)?;
        if features.last().is_some_and(|last| last.id >= id) { return Err(TwinError::Reference); }
        let surface = match r.u8()? {
            0 => SurfaceKind::Unknown, 1 => SurfaceKind::PedestrianPath,
            2 => SurfaceKind::Grass, 3 => SurfaceKind::Stairs,
            4 => SurfaceKind::Deck, 5 => SurfaceKind::Structure,
            _ => return Err(TwinError::Format),
        };
        features.push(TwinFeature { id, surface });
    }
    let mut objects: Vec<TwinObject> = allocated(no)?;
    for _ in 0..no {
        budget.charge(1)?;
        let id = r.text(256)?;
        if objects.last().is_some_and(|last| last.id >= id) { return Err(TwinError::Reference); }
        let feature = r.u32()?;
        if feature as usize >= nf { return Err(TwinError::Reference); }
        objects.push(TwinObject { id, feature, support: r.boolean()?, opaque: r.boolean()? });
    }
    let mut vertices = allocated(nv)?;
    for _ in 0..nv {
        budget.charge(1)?;
        vertices.push([r.number()?, r.number()?, r.number()?]);
    }
    let mut triangles = allocated(nt)?;
    let mut triangle_objects = allocated(nt)?;
    let mut used_objects = vec![false; no];
    let mut used_features = vec![false; nf];
    for _ in 0..nt {
        budget.charge(1)?;
        let indices = [r.u32()?, r.u32()?, r.u32()?];
        let object_index = r.u32()?;
        let object = objects.get(object_index as usize).ok_or(TwinError::Reference)?;
        used_objects[object_index as usize] = true;
        used_features[object.feature as usize] = true;
        triangles.push(IndexedTriangle { vertices: indices, feature: u64::from(object.feature) + 1,
            support: object.support, opaque: object.opaque });
        triangle_objects.push(object_index);
    }
    if r.offset != r.bytes.len() || used_objects.contains(&false) || used_features.contains(&false) {
        return Err(TwinError::Reference);
    }
    let mesh = TriangleMesh::from_indexed(expected.basis, &vertices, &triangles,
        MeshLimits { max_vertices: limits.vertices, max_triangles: limits.triangles }, budget)?;
    budget.charge(0)?;
    Ok(PropertyTwin { mesh, features, objects, vertices, triangles, triangle_objects,
        digest, source, scope, epoch, scale, geometry_error })
}

fn allocated<T>(count: usize) -> Result<Vec<T>, TwinError> {
    let mut result = Vec::new();
    result.try_reserve_exact(count).map_err(|_| TwinError::Limit)?;
    Ok(result)
}
struct Reader<'a> { bytes: &'a [u8], offset: usize }
impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], TwinError> {
        let end = self.offset.checked_add(length).ok_or(TwinError::Limit)?;
        let value = self.bytes.get(self.offset..end).ok_or(TwinError::Format)?;
        self.offset = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, TwinError> { Ok(self.take(1)?[0]) }
    fn u32(&mut self) -> Result<u32, TwinError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().map_err(|_| TwinError::Format)?))
    }
    fn u64(&mut self) -> Result<u64, TwinError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().map_err(|_| TwinError::Format)?))
    }
    fn number(&mut self) -> Result<f64, TwinError> {
        let n = f64::from_bits(self.u64()?);
        if !n.is_finite() || n.to_bits() == (-0.0f64).to_bits() { return Err(TwinError::Numeric); }
        Ok(n)
    }
    fn boolean(&mut self) -> Result<bool, TwinError> {
        match self.u8()? { 0 => Ok(false), 1 => Ok(true), _ => Err(TwinError::Format) }
    }
    fn count(&mut self, limit: usize) -> Result<usize, TwinError> {
        let count = self.u32()? as usize;
        if count == 0 || count > limit { return Err(TwinError::Limit); }
        Ok(count)
    }
    fn text(&mut self, max: usize) -> Result<String, TwinError> {
        let len = u16::from_le_bytes(self.take(2)?.try_into().map_err(|_| TwinError::Format)?) as usize;
        if len == 0 || len > max { return Err(TwinError::Limit); }
        let value = std::str::from_utf8(self.take(len)?).map_err(|_| TwinError::Format)?;
        if value.trim() != value || value.chars().any(char::is_control) { return Err(TwinError::Format); }
        Ok(value.to_owned())
    }
}
