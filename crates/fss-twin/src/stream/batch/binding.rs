#![forbid(unsafe_code)]
//! Complete reference-request binding, not a registered canonical durable format.
use super::*;
use crate::association::UnresolvedAssociation;

pub(super) fn request(session: [u8; 32], selection: &AssociationSelection<'_>,
    operation: BatchOperation, budget: &mut WorkBudget<'_>) -> Result<[u8; 32], BatchError> {
    let graph = selection.graph();
    let mut w = Writer::new(budget)?;
    w.raw(b"fss/track-set-assignment/reference/1\0")?;
    w.raw(&session)?; w.raw(&graph.twin_digest())?;
    w.integer(operation.sequence)?; w.raw(&operation.adjudication)?;
    let policy = selection.policy();
    w.raw(&policy.one_to_one_basis)?;
    w.integer(policy.maximum_per_factor as u64)?; w.integer(policy.maximum_materialized as u64)?;
    let frame = graph.frame();
    camera(&mut w, frame.camera)?;
    w.raw(&frame.evidence)?; w.integer(frame.exposure)?;
    for value in frame.capture { w.integer(value)?; }
    let options = graph.options();
    w.float(options.projection.near)?; w.float(options.projection.far)?;
    w.integer(options.projection.max_hypotheses as u64)?;
    for value in options.acceleration { w.float(value)?; }
    w.integer(options.maximum_gap_ns)?; w.integer(options.maximum_witnesses as u64)?;
    w.integer(graph.sources().len() as u64)?;
    for source in graph.sources() {
        receipt(&mut w, source.receipt())?;
        w.integer(source.observations().len() as u64)?;
        for observation in source.observations() { contact(&mut w, *observation)?; }
    }
    w.integer(graph.detections().len() as u64)?;
    for projection in graph.detections() {
        let detection = projection.detection();
        w.integer(detection.id)?; w.raw(&detection.evidence)?;
        for value in detection.pixel_min.into_iter().chain(detection.pixel_max) { w.float(value)?; }
        w.byte(u8::from(detection.visible_contact))?;
    }
    w.integer(graph.pairs().len() as u64)?;
    for pair in graph.pairs() {
        w.integer(pair.track())?; w.integer(pair.detection())?;
        for reason in [UnresolvedAssociation::MotionUnavailable, UnresolvedAssociation::CaptureOrder,
            UnresolvedAssociation::Gap, UnresolvedAssociation::ContactUnavailable,
            UnresolvedAssociation::UnknownBounds, UnresolvedAssociation::OcclusionConflict] {
            w.byte(u8::from(pair.unresolved().contains(reason)))?;
        }
        w.integer(pair.overlaps().len() as u64)?;
        for overlap in pair.overlaps() {
            w.integer(overlap.source_mode as u64)?; w.integer(u64::from(overlap.detection_triangle))?;
            for interval in overlap.position.0 { w.float(interval.lower())?; w.float(interval.upper())?; }
        }
    }
    w.integer(selection.assignment().links().len() as u64)?;
    for link in selection.assignment().links() { w.integer(link.track)?; w.integer(link.detection)?; }
    // Unmatched sets are uniquely determined by the full graph membership and links.
    w.budget.charge(w.bytes.len() as u64)?;
    let digest = ContentDigest::sha256(&w.bytes).bytes();
    w.budget.charge(0)?;
    Ok(digest)
}

fn camera(w: &mut Writer<'_, '_>, c: TrackingCamera) -> Result<(), BatchError> {
    for value in [c.camera, c.calibration, c.image_domain, c.clock, c.validity[0], c.validity[1]] { w.integer(value)?; }
    for row in c.pose.rotation() { for value in row { w.float(value)?; } }
    for value in c.pose.translation() { w.float(value)?; }
    for value in c.intrinsics.dimensions() { w.integer(u64::from(value))?; }
    for value in c.intrinsics.focal_lengths().into_iter().chain(c.intrinsics.principal_point()) { w.float(value)?; }
    w.byte(u8::from(c.error.is_some()))?;
    if let Some(error) = c.error {
        for value in error.centre.into_iter().chain([error.rotation_entry]).chain(error.focal).chain(error.principal) { w.float(value)?; }
    }
    Ok(())
}
fn receipt(w: &mut Writer<'_, '_>, r: TrackReceipt) -> Result<(), BatchError> {
    for value in [r.scope.track, r.scope.clock, r.scope.epoch, r.revision] { w.integer(value)?; }
    w.raw(&r.evidence)?;
    w.byte(match r.disposition {
        TrackDisposition::Seeded => 0, TrackDisposition::MotionUpdated => 1,
        TrackDisposition::ContactUnavailable => 2, TrackDisposition::SupportUnavailable => 3,
        TrackDisposition::TimeAmbiguous => 4, TrackDisposition::Gap => 5,
        TrackDisposition::AssociationRequired => 6,
    })?;
    w.byte(match r.projection_quality {
        ProjectionQuality::Bounded => 0, ProjectionQuality::NominalOnly => 1,
        ProjectionQuality::ContactUnknown => 2,
    })?;
    w.integer(r.supports as u64)?; w.integer(r.motion_modes as u64)
}
fn contact(w: &mut Writer<'_, '_>, o: ContactObservation) -> Result<(), BatchError> {
    w.raw(&o.evidence)?;
    for value in [o.track, o.camera, o.exposure, o.image_domain, o.clock, o.capture[0], o.capture[1]] { w.integer(value)?; }
    for value in o.pixel_min.into_iter().chain(o.pixel_max) { w.float(value)?; }
    w.byte(u8::from(o.visible_contact))
}
struct Writer<'a, 'b> { bytes: Vec<u8>, budget: &'a mut WorkBudget<'b> }
impl<'a, 'b> Writer<'a, 'b> {
    fn new(budget: &'a mut WorkBudget<'b>) -> Result<Self, BatchError> {
        budget.charge(1)?;
        Ok(Self { bytes: reserved(1_048_576)?, budget })
    }
    fn raw(&mut self, bytes: &[u8]) -> Result<(), BatchError> {
        if bytes.len() > 1_048_576 - self.bytes.len() { return Err(BatchError::Limit); }
        self.budget.charge(bytes.len() as u64)?;
        self.bytes.extend_from_slice(bytes); Ok(())
    }
    fn integer(&mut self, value: u64) -> Result<(), BatchError> { self.raw(&value.to_le_bytes()) }
    fn byte(&mut self, value: u8) -> Result<(), BatchError> { self.raw(&[value]) }
    fn float(&mut self, value: f64) -> Result<(), BatchError> {
        if !value.is_finite() { return Err(BatchError::InvalidInput); }
        self.integer(if value == 0.0 { 0 } else { value.to_bits() })
    }
}
