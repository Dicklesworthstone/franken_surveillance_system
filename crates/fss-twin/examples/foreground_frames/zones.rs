#![forbid(unsafe_code)]
//! Explicit image-zone replay and complete source-linked JSONL, not alert dispatch.
use std::collections::BTreeMap;
use std::io::Write;
use fss_geometry::WorkBudget;
use fss_twin::image_tracking::{ImageTrackObservation, ImageTracker};
use fss_twin::image_zones::{ImageZoneBasis, ImageZoneMonitor, ImageZonePolicy,
    ImageZoneReport, ImageZoneSpec, MAX_IMAGE_ZONES, MAX_ZONE_VERTICES};
use super::{Result, hash, hex};

pub(super) const SETTINGS:[&str;3]=["zone_selection_evidence","zone_maximum_sample_gap_ns","zones"];

// ID MARGIN DWELL_NS|off x,y x,y x,y [x,y ...]; next-zone ...
fn parse_zones(text:&str) -> Result<Vec<ImageZoneSpec>> {
    if text.len()>32768 { return Err("zone declaration exceeds byte limit".into()); }
    let mut zones=Vec::new(); zones.try_reserve_exact(MAX_IMAGE_ZONES)?;
    for declaration in text.split(';') {
        if zones.len()==MAX_IMAGE_ZONES { return Err("too many zones".into()); }
        let mut parts=declaration.split_whitespace();
        let id=parts.next().ok_or("missing zone ID")?.parse()?;
        let margin=parts.next().ok_or("missing zone margin")?.parse()?;
        let dwell=parts.next().ok_or("missing dwell policy")?;
        let dwell_ns=if dwell=="off" { None } else { Some(dwell.parse()?) };
        let mut vertices=Vec::new(); vertices.try_reserve_exact(MAX_ZONE_VERTICES)?;
        for point in parts {
            if vertices.len()==MAX_ZONE_VERTICES { return Err("too many zone vertices".into()); }
            let (x,y)=point.split_once(',').ok_or("expected x,y zone vertex")?;
            vertices.push([x.parse()?,y.parse()?]);
        }
        if vertices.len()<3 { return Err("a zone requires at least three vertices".into()); }
        zones.push(ImageZoneSpec { id,vertices,margin,dwell_ns });
    }
    Ok(zones)
}
pub(super) fn configure(settings:&BTreeMap<&str,&str>, tracker:&ImageTracker,
    basis:ImageZoneBasis,budget:&mut WorkBudget<'_>) -> Result<ImageZoneMonitor> {
    let get=|key|settings.get(key).copied().ok_or("missing zone setting");
    let policy=ImageZonePolicy { selection_evidence:hash(get("zone_selection_evidence")?)?,
        maximum_sample_gap_ns:get("zone_maximum_sample_gap_ns")?.parse()? };
    Ok(ImageZoneMonitor::new(tracker,basis,policy,&parse_zones(get("zones")?)?,budget)?)
}
pub(super) fn write_configuration(out:&mut impl Write, monitor:&ImageZoneMonitor) -> Result<()> {
    let b=monitor.basis(); let p=monitor.policy();
    write!(out,"{{\"kind\":\"zone_configuration\",\"config\":\"{}\",\"camera\":{},\"clock\":{},\"calibration\":\"{}\",\"image_domain\":\"{}\",\"dimensions\":{:?},\"selection_evidence\":\"{}\",\"maximum_sample_gap_ns\":{},\"zones\":[",
        hex(monitor.config_digest()),b.camera,b.clock,hex(b.calibration),hex(b.image_domain),b.dimensions,
        hex(p.selection_evidence),p.maximum_sample_gap_ns)?;
    for (i,z) in monitor.zones().iter().enumerate() {
        if i!=0 { write!(out,",")?; }
        write!(out,"{{\"id\":{},\"vertices\":{:?},\"margin\":{},\"dwell_ns\":",z.id,z.vertices,z.margin)?;
        if let Some(n)=z.dwell_ns { write!(out,"{n}")?; } else { write!(out,"null")?; }
        write!(out,"}}")?;
    }
    writeln!(out,"]}}")?; Ok(())
}
fn observation(out:&mut impl Write,o:ImageTrackObservation) -> Result<()> {
    let f=o.frame; let s=f.source; let d=o.detection;
    write!(out,"{{\"exposure\":\"{}\",\"pixels\":\"{}\",\"camera\":{},\"clock\":{},\"capture\":{:?},\"image_domain\":\"{}\",\"calibration\":\"{}\",\"dimensions\":{:?},\"detector\":\"{}\",\"mask\":\"{}\",\"foreground\":\"{}\",\"availability\":\"{:?}\",\"detection\":{},\"evidence\":\"{}\",\"min\":{:?},\"max\":{:?},\"partial\":{}}}",
        hex(s.image.exposure),hex(s.image.pixels),s.camera,s.clock,s.capture,hex(s.image.image_domain),
        hex(s.calibration),s.image.dimensions,hex(f.detector),hex(f.permission_mask),hex(f.evidence),
        f.availability,d.id,hex(d.evidence),d.min,d.max,d.partial)?;
    Ok(())
}
pub(super) fn write_report(out:&mut impl Write, report:&ImageZoneReport) -> Result<()> {
    let f=report.frame();
    write!(out,"{{\"kind\":\"zones\",\"report\":\"{}\",\"prior\":\"{}\",\"config\":\"{}\",\"tracking\":\"{}\",\"foreground\":\"{}\",\"exposure\":\"{}\",\"capture\":{:?},\"availability\":\"{:?}\",\"cells\":[",
        hex(report.digest()),hex(report.prior_digest()),hex(report.config_digest()),hex(report.tracking_digest()),
        hex(f.evidence),hex(f.source.image.exposure),f.source.capture,f.availability)?;
    for (i,c) in report.cells().iter().enumerate() {
        if i!=0 { write!(out,",")?; }
        write!(out,"{{\"track\":{},\"zone\":{},\"relation\":\"{:?}\",\"last_observation\":",c.track,c.zone,c.relation)?;
        observation(out,c.last_observation)?;
        write!(out,",\"dwell_start\":")?;
        if let Some(first)=c.dwell_start { observation(out,first)?; } else { write!(out,"null")?; }
        write!(out,",\"sampled_span_ns\":")?;
        if let Some(span)=c.sampled_span_ns { write!(out,"{span:?}")?; } else { write!(out,"null")?; }
        write!(out,",\"inside_samples\":{}}}",c.inside_samples)?;
    }
    write!(out,"],\"events\":[")?;
    for (i,e) in report.events().iter().enumerate() {
        if i!=0 { write!(out,",")?; }
        write!(out,"{{\"digest\":\"{}\",\"track\":{},\"zone\":{},\"event\":\"{:?}\",\"relation\":\"{:?}\",\"from\":",
            hex(e.digest),e.track,e.zone,e.kind,e.relation)?;
        if let Some(from)=e.from { observation(out,from)?; } else { write!(out,"null")?; }
        write!(out,",\"to\":")?; observation(out,e.to)?; write!(out,"}}")?;
    }
    writeln!(out,"]}}")?; Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use fss_twin::foreground::ForegroundSource;
    use fss_twin::image_tracking::{ImageDetection,ImageTrackingFrame,ImageTrackingPolicy,TrackingAvailability};
    use fss_twin::localization::ImageIdentity;
    fn work()->WorkBudget<'static> { WorkBudget::new(10_000_000) }
    fn tracker()->Result<ImageTracker> {
        Ok(ImageTracker::new([40;32],ImageTrackingPolicy { maximum_tracks:8,maximum_detections:8,
            maximum_exposures:64,minimum_observations:2,maximum_misses:2,maximum_gap_ns:100,
            maximum_speed:100,gate_padding:8,miss_cost:1000,ambiguity_margin:0 },&mut work())?)
    }
    fn basis()->ImageZoneBasis {
        ImageZoneBasis { camera:1,clock:2,calibration:[6;32],image_domain:[5;32],dimensions:[64,16] }
    }
    fn settings()->BTreeMap<&'static str,&'static str> {
        SETTINGS.into_iter().zip([
            "1111111111111111111111111111111111111111111111111111111111111111",
            "100","1 0 2 20,1 60,1 60,14 20,14;2 1 off 1,1 10,1 1,10",
        ]).collect()
    }
    #[test]
    fn explicit_multi_zone_configuration_preserves_geometry_and_policy()->Result<()> {
        let t=tracker()?; let m=configure(&settings(),&t,basis(),&mut work())?;
        assert_eq!(m.zones().len(),2); assert_eq!(m.zones()[0].dwell_ns,Some(2));
        assert_eq!(m.zones()[1].dwell_ns,None); assert_eq!(m.zones()[1].margin,1);
        let mut bytes=Vec::new(); write_configuration(&mut bytes,&m)?;
        let text=String::from_utf8(bytes)?;
        assert!(text.contains("\"dwell_ns\":null")); assert!(text.contains("\"maximum_sample_gap_ns\":100"));
        assert!(text.contains(&hex(m.config_digest()))); assert!(text.ends_with("]}\n"));
        Ok(())
    }
    #[test]
    fn incomplete_malformed_unbounded_or_nonconvex_zone_configuration_refuses()->Result<()> {
        for text in ["","1 0 off 1,1 2,2","1 0 off 1,1 2,2 3,3;","1 -1 off 1,1 2,2 3,3",
            "1 0 off 1,1 2,2 3,3,4","1 0 off 1,1 2,2 3,3;;"] {
            assert!(parse_zones(text).is_err());
        }
        let t=tracker()?; let mut values=settings();
        assert!(values.insert("zones","1 0 off 1,1 20,1 10,5 20,14 1,14").is_some());
        assert!(configure(&values,&t,basis(),&mut work()).is_err());
        assert!(values.remove("zone_selection_evidence").is_some());
        assert!(configure(&values,&t,basis(),&mut work()).is_err());
        let too_many=vec!["1 0 off 1,1 2,1 1,2";MAX_IMAGE_ZONES+1].join(";");
        assert!(parse_zones(&too_many).is_err());
        let too_many_points=format!("1 0 off {}",vec!["1,1";MAX_ZONE_VERTICES+1].join(" "));
        assert!(parse_zones(&too_many_points).is_err());
        Ok(())
    }
    #[test]
    fn output_keeps_interrupted_state_and_actual_source_instead_of_current_sighting()->Result<()> {
        let mut t=tracker()?; let mut m=configure(&settings(),&t,basis(),&mut work())?;
        let frame=|n:u8|ImageTrackingFrame { source:ForegroundSource { image:ImageIdentity {
            exposure:[n;32],pixels:[90;32],image_domain:[5;32],dimensions:[64,16] },camera:1,
            clock:2,calibration:[6;32],capture:[u64::from(n);2] },detector:[7;32],permission_mask:[8;32],
            evidence:[n+10;32],availability:TrackingAvailability::Available };
        let r=t.update(frame(1),&[ImageDetection { id:1,evidence:[80;32],min:[24,4],max:[28,8],partial:false }],&mut work())?;
        m.observe(&t,&r,&mut work())?;
        let r=t.update(frame(2),&[],&mut work())?;
        let report=m.observe(&t,&r,&mut work())?;
        let mut bytes=Vec::new(); write_report(&mut bytes,report)?;
        let text=String::from_utf8(bytes)?;
        assert_eq!(text.matches("\"relation\":\"Unobserved\"").count(),4);
        assert_eq!(text.matches("\"event\":\"ObservationInterrupted\"").count(),2);
        assert_eq!(text.matches("\"sampled_span_ns\":null").count(),2);
        assert!(text.contains(&format!("\"exposure\":\"{}\",\"capture\":[2, 2]",hex([2;32]))));
        assert!(text.contains(&format!("\"last_observation\":{{\"exposure\":\"{}\"",hex([1;32]))));
        assert!(!text.contains("LeftBetweenObservations")); assert!(text.ends_with("]}\n"));
        Ok(())
    }
}
