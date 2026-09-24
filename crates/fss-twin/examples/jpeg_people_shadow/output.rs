#![forbid(unsafe_code)]
//! Complete, quota-bounded JSONL projections of existing opaque receipts.
use super::Result;
use fss_twin::hog_scan::WindowDisposition;
use fss_twin::image_tracking::{ImageDetectionDisposition, ImageTrackObservation};
use fss_twin::screened_mjpeg::ForegroundStage;
use fss_twin::screening::tracking::hog::jpeg::JpegHogPipeline;
use std::io::{self, Write};

pub struct Limited<'a, W: Write> {
    writer: &'a mut W,
    remaining: usize,
}
impl<'a, W: Write> Limited<'a, W> {
    pub fn new(writer: &'a mut W, limit: usize) -> Self {
        Self {
            writer,
            remaining: limit,
        }
    }
}
impl<W: Write> Write for Limited<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(io::Error::other("complete-output byte limit"));
        }
        let n = self.writer.write(bytes)?;
        self.remaining -= n;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}
pub fn hex(id: [u8; 32]) -> String {
    id.iter().map(|n| format!("{n:02x}")).collect()
}
fn observation(out: &mut impl Write, value: ImageTrackObservation) -> Result<()> {
    let s = value.frame.source;
    let d = value.detection;
    write!(
        out,
        "{{\"camera\":{},\"clock\":{},\"capture\":{:?},\"exposure\":\"{}\",\"pixels\":\"{}\",\"image_domain\":\"{}\",\"calibration\":\"{}\",\"input\":\"{}\",\"detection\":{},\"evidence\":\"{}\",\"min\":{:?},\"max\":{:?},\"partial\":{}}}",
        s.camera,
        s.clock,
        s.capture,
        hex(s.image.exposure),
        hex(s.image.pixels),
        hex(s.image.image_domain),
        hex(s.calibration),
        hex(value.frame.evidence),
        d.id,
        hex(d.evidence),
        d.min,
        d.max,
        d.partial
    )?;
    Ok(())
}
pub fn current(out: &mut impl Write, pipeline: &JpegHogPipeline) -> Result<()> {
    let image = pipeline.image().ok_or("no accepted image to project")?;
    let screen = image.screening();
    let s = screen.source();
    let stamp = screen.stamp();
    writeln!(
        out,
        "{{\"kind\":\"source_screen\",\"image\":\"{}\",\"screen\":\"{}\",\"encoded\":\"{}\",\"exposure\":\"{}\",\"pixels\":\"{}\",\"image_domain\":\"{}\",\"dimensions\":{:?},\"camera\":{},\"clock\":{},\"capture\":{:?},\"sequence\":{},\"received_at_ns\":{},\"health\":\"{:?}\",\"flags\":{},\"analysis_due\":{},\"analysis_acknowledged\":false}}",
        hex(image.digest()),
        hex(screen.digest()),
        hex(image.source_receipt().source.encoded_sha256),
        hex(s.image.exposure),
        hex(s.image.pixels),
        hex(s.image.image_domain),
        s.image.dimensions,
        s.camera,
        s.clock,
        s.capture,
        stamp.sequence,
        stamp.received_at_ns,
        screen.health(),
        screen.flags().bits(),
        screen.analysis_due()
    )?;
    match image.foreground() {
        ForegroundStage::Complete(report) => writeln!(
            out,
            "{{\"kind\":\"foreground\",\"state\":\"complete\",\"image\":\"{}\",\"report\":\"{}\",\"assessment\":\"{:?}\",\"comparable_pixels\":{},\"changed_pixels\":{}}}",
            hex(image.digest()),
            hex(report.digest()),
            report.assessment(),
            report.comparable_pixels(),
            report.changed_pixels()
        )?,
        ForegroundStage::Refused(error) => writeln!(
            out,
            "{{\"kind\":\"foreground\",\"state\":\"refused\",\"image\":\"{}\",\"reason\":\"{error:?}\"}}",
            hex(image.digest())
        )?,
        ForegroundStage::NotConfigured => {
            return Err("required background was not configured".into());
        }
    }
    if let Some(scan) = pipeline.scan() {
        writeln!(
            out,
            "{{\"kind\":\"scan\",\"image\":\"{}\",\"report\":\"{}\",\"model\":\"{}\",\"generation\":\"{}\",\"mask\":\"{}\",\"windows\":{},\"selected\":{}}}",
            hex(image.digest()),
            hex(scan.digest()),
            hex(scan.model_digest()),
            hex(scan.generation()),
            hex(scan.mask_digest()),
            scan.windows().len(),
            scan.selected().count()
        )?;
        for (index, level) in scan.levels().iter().enumerate() {
            writeln!(
                out,
                "{{\"kind\":\"scale\",\"scan\":\"{}\",\"index\":{},\"dimensions\":{:?},\"pixels\":\"{}\",\"image_domain\":\"{}\",\"mask\":\"{}\",\"windows\":{}}}",
                hex(scan.digest()),
                index,
                level.dimensions,
                hex(level.source.image.pixels),
                hex(level.source.image.image_domain),
                hex(level.mask_digest),
                level.windows
            )?;
        }
        for window in scan.windows() {
            let (state, suppressed_by) = match window.disposition {
                WindowDisposition::Unobservable => ("unobservable", None),
                WindowDisposition::BelowThreshold => ("below_threshold", None),
                WindowDisposition::Selected => ("selected", None),
                WindowDisposition::Suppressed { by } => ("suppressed", Some(by)),
            };
            write!(
                out,
                "{{\"kind\":\"window\",\"scan\":\"{}\",\"id\":{},\"level\":{},\"origin\":{:?},\"min\":{:?},\"max\":{:?},\"state\":\"{state}\",\"margin\":",
                hex(scan.digest()),
                window.id,
                window.level,
                window.origin,
                window.source_min,
                window.source_max
            )?;
            if let Some(value) = window.margin {
                write!(out, "{value}")?;
            } else {
                write!(out, "null")?;
            }
            write!(out, ",\"suppressed_by\":")?;
            if let Some(id) = suppressed_by {
                write!(out, "{id}")?;
            } else {
                write!(out, "null")?;
            }
            writeln!(out, "}}")?;
        }
    }
    if let Some(report) = pipeline.tracking_report() {
        writeln!(
            out,
            "{{\"kind\":\"tracking\",\"report\":\"{}\",\"image\":\"{}\",\"availability\":\"{:?}\",\"detections\":{},\"candidates\":{},\"expired\":{}}}",
            hex(report.digest()),
            hex(image.digest()),
            report.frame().availability,
            report.decisions().len(),
            report.candidates().len(),
            report.expired().len()
        )?;
        for row in report.decisions() {
            let (state, track) = match row.disposition {
                ImageDetectionDisposition::Started(id) => ("started", Some(id)),
                ImageDetectionDisposition::Continued(id) => ("continued", Some(id)),
                ImageDetectionDisposition::Unresolved => ("unresolved", None),
                ImageDetectionDisposition::Unavailable => ("unavailable", None),
            };
            let d = row.detection;
            write!(
                out,
                "{{\"kind\":\"assignment\",\"tracking\":\"{}\",\"detection\":{},\"evidence\":\"{}\",\"min\":{:?},\"max\":{:?},\"partial\":{},\"state\":\"{state}\",\"track\":",
                hex(report.digest()),
                d.id,
                hex(d.evidence),
                d.min,
                d.max,
                d.partial
            )?;
            if let Some(id) = track {
                write!(out, "{id}")?;
            } else {
                write!(out, "null")?;
            }
            writeln!(out, "}}")?;
        }
        for row in report.candidates() {
            write!(
                out,
                "{{\"kind\":\"association_candidate\",\"tracking\":\"{}\",\"track\":{},\"detection\":{},\"selected\":{},\"ambiguous\":{},\"cost\":",
                hex(report.digest()),
                row.track,
                row.detection,
                row.selected,
                row.ambiguous
            )?;
            if let Some(cost) = row.cost {
                write!(out, "{cost}")?;
            } else {
                write!(out, "null")?;
            }
            writeln!(out, "}}")?;
        }
        for track in pipeline.zones().pipeline().tracker().tracks() {
            write!(
                out,
                "{{\"kind\":\"track\",\"tracking\":\"{}\",\"id\":{},\"state\":\"{:?}\",\"observations\":{},\"misses\":{},\"last_observation\":",
                hex(report.digest()),
                track.id(),
                track.state(),
                track.observations(),
                track.misses()
            )?;
            observation(out, track.latest())?;
            writeln!(out, "}}")?;
        }
        for expired in report.expired() {
            write!(
                out,
                "{{\"kind\":\"expired_track\",\"tracking\":\"{}\",\"id\":{},\"reason\":\"{:?}\",\"last_observation\":",
                hex(report.digest()),
                expired.track.id(),
                expired.reason
            )?;
            observation(out, expired.track.latest())?;
            writeln!(out, "}}")?;
        }
    }
    if let Some(report) = pipeline.zone_report() {
        writeln!(
            out,
            "{{\"kind\":\"zones\",\"report\":\"{}\",\"tracking\":\"{}\",\"config\":\"{}\",\"cells\":{},\"events\":{}}}",
            hex(report.digest()),
            hex(report.tracking_digest()),
            hex(report.config_digest()),
            report.cells().len(),
            report.events().len()
        )?;
        for cell in report.cells() {
            write!(
                out,
                "{{\"kind\":\"zone_cell\",\"report\":\"{}\",\"track\":{},\"zone\":{},\"relation\":\"{:?}\",\"inside_samples\":{},\"sampled_span_ns\":",
                hex(report.digest()),
                cell.track,
                cell.zone,
                cell.relation,
                cell.inside_samples
            )?;
            if let Some(span) = cell.sampled_span_ns {
                write!(out, "{span:?}")?;
            } else {
                write!(out, "null")?;
            }
            write!(out, ",\"last_observation\":")?;
            observation(out, cell.last_observation)?;
            write!(out, ",\"dwell_start\":")?;
            if let Some(start) = cell.dwell_start {
                observation(out, start)?;
            } else {
                write!(out, "null")?;
            }
            writeln!(out, "}}")?;
        }
        for event in report.events() {
            write!(
                out,
                "{{\"kind\":\"zone_event\",\"report\":\"{}\",\"event\":\"{}\",\"track\":{},\"zone\":{},\"event_kind\":\"{:?}\",\"relation\":\"{:?}\",\"from\":",
                hex(report.digest()),
                hex(event.digest),
                event.track,
                event.zone,
                event.kind,
                event.relation
            )?;
            if let Some(from) = event.from {
                observation(out, from)?;
            } else {
                write!(out, "null")?;
            }
            write!(out, ",\"to\":")?;
            observation(out, event.to)?;
            writeln!(out, "}}")?;
        }
    }
    Ok(())
}
