#![forbid(unsafe_code)]
//! Versioned reference fingerprints, not registered durable wire formats.
use super::{ContentDigest, ImageTrackObservation, ImageTrackingFrame, ImageZoneBasis,
    ImageZoneError, ImageZonePolicy, ImageZoneReport, ImageZoneSpec, WorkBudget, reserve};

pub(super) fn configuration(basis: ImageZoneBasis, policy: ImageZonePolicy,
    zones: &[ImageZoneSpec], budget: &mut WorkBudget<'_>) -> Result<[u8;32],ImageZoneError> {
    let mut b = reserve(256 + zones.len()*640)?;
    b.extend_from_slice(b"fss/image-zone-configuration/reference/1\0");
    for n in [basis.camera,basis.clock] { number(&mut b,n); }
    b.extend_from_slice(&basis.calibration); b.extend_from_slice(&basis.image_domain);
    for n in basis.dimensions { number(&mut b,u64::from(n)); }
    b.extend_from_slice(&policy.selection_evidence); number(&mut b,policy.maximum_sample_gap_ns);
    number(&mut b,zones.len() as u64);
    for zone in zones {
        number(&mut b,zone.id); number(&mut b,u64::from(zone.margin));
        b.push(u8::from(zone.dwell_ns.is_some()));
        if let Some(dwell) = zone.dwell_ns { number(&mut b,dwell); }
        number(&mut b,zone.vertices.len() as u64);
        for point in &zone.vertices { for n in point { number(&mut b,u64::from(*n)); } }
    }
    hash(&b,budget)
}
pub(super) fn seal(report: &mut ImageZoneReport, budget: &mut WorkBudget<'_>) -> Result<(),ImageZoneError> {
    // Upper bounds cover all optional full observations and every fixed-size field.
    let mut b = reserve(512 + report.cells.len()*1024 + report.events.len()*32)?;
    b.extend_from_slice(b"fss/image-zone-report/reference/1\0");
    for id in [report.prior,report.config,report.tracking] { b.extend_from_slice(&id); }
    frame(&mut b,report.frame);
    number(&mut b,report.cells.len() as u64);
    for cell in &report.cells {
        number(&mut b,cell.track); number(&mut b,cell.zone); b.push(cell.relation as u8);
        observation(&mut b,cell.last_observation); optional(&mut b,cell.dwell_start);
        b.push(u8::from(cell.sampled_span_ns.is_some()));
        if let Some(span) = cell.sampled_span_ns { for n in span { number(&mut b,n); } }
        number(&mut b,u64::from(cell.inside_samples));
    }
    number(&mut b,report.events.len() as u64);
    let mut event_bytes = reserve(1152)?;
    for event in &mut report.events {
        event_bytes.clear();
        event_bytes.extend_from_slice(b"fss/image-zone-event/reference/1\0");
        for id in [report.config,report.prior,report.tracking] { event_bytes.extend_from_slice(&id); }
        number(&mut event_bytes,event.track); number(&mut event_bytes,event.zone);
        event_bytes.push(event.kind as u8); event_bytes.push(event.relation as u8);
        optional(&mut event_bytes,event.from); observation(&mut event_bytes,event.to);
        event.digest = hash(&event_bytes,budget)?;
        b.extend_from_slice(&event.digest);
    }
    report.digest = hash(&b,budget)?;
    Ok(())
}
fn number(b: &mut Vec<u8>, n:u64) { b.extend_from_slice(&n.to_le_bytes()); }
fn frame(b:&mut Vec<u8>, f:ImageTrackingFrame) {
    let s = f.source;
    for id in [s.image.exposure,s.image.pixels,s.image.image_domain,s.calibration,
        f.detector,f.permission_mask,f.evidence] { b.extend_from_slice(&id); }
    for n in [s.camera,s.clock,u64::from(s.image.dimensions[0]),u64::from(s.image.dimensions[1]),
        s.capture[0],s.capture[1]] { number(b,n); }
    b.push(f.availability as u8);
}
fn observation(b:&mut Vec<u8>, o:ImageTrackObservation) {
    frame(b,o.frame); let d = o.detection;
    number(b,d.id); b.extend_from_slice(&d.evidence);
    for n in d.min.into_iter().chain(d.max) { number(b,u64::from(n)); }
    b.push(u8::from(d.partial));
}
fn optional(b:&mut Vec<u8>, o:Option<ImageTrackObservation>) {
    b.push(u8::from(o.is_some())); if let Some(o) = o { observation(b,o); }
}
fn hash(b:&[u8],budget:&mut WorkBudget<'_>) -> Result<[u8;32],ImageZoneError> {
    budget.charge(b.len() as u64)?;
    let digest = ContentDigest::sha256(b).bytes();
    budget.charge(0)?; Ok(digest)
}
