#![forbid(unsafe_code)]
//! Optional anonymous trajectory replay; the legacy foreground-only format is unchanged.
use super::{Result, hash, hex};
use fss_geometry::WorkBudget;
use fss_twin::image_tracking::{
    ImageDetectionDisposition, ImageTracker, ImageTrackingPolicy, ImageTrackingReport,
};
use std::collections::BTreeMap;
use std::io::Write;

pub(super) const SETTINGS: [&str; 11] = [
    "tracking_episode",
    "tracking_maximum_tracks",
    "tracking_maximum_detections",
    "tracking_maximum_exposures",
    "tracking_minimum_observations",
    "tracking_maximum_misses",
    "tracking_maximum_gap_ns",
    "tracking_maximum_speed",
    "tracking_gate_padding",
    "tracking_miss_cost",
    "tracking_ambiguity_margin",
];

pub(super) fn configure(
    settings: &BTreeMap<&str, &str>,
    budget: &mut WorkBudget<'_>,
) -> Result<ImageTracker> {
    let get = |key| settings.get(key).copied().ok_or("missing tracking setting");
    Ok(ImageTracker::new(
        hash(get("tracking_episode")?)?,
        ImageTrackingPolicy {
            maximum_tracks: get("tracking_maximum_tracks")?.parse()?,
            maximum_detections: get("tracking_maximum_detections")?.parse()?,
            maximum_exposures: get("tracking_maximum_exposures")?.parse()?,
            minimum_observations: get("tracking_minimum_observations")?.parse()?,
            maximum_misses: get("tracking_maximum_misses")?.parse()?,
            maximum_gap_ns: get("tracking_maximum_gap_ns")?.parse()?,
            maximum_speed: get("tracking_maximum_speed")?.parse()?,
            gate_padding: get("tracking_gate_padding")?.parse()?,
            miss_cost: get("tracking_miss_cost")?.parse()?,
            ambiguity_margin: get("tracking_ambiguity_margin")?.parse()?,
        },
        budget,
    )?)
}

pub(super) fn write_report(
    out: &mut impl Write,
    tracker: &ImageTracker,
    report: &ImageTrackingReport,
) -> Result<()> {
    let frame = report.frame();
    write!(
        out,
        "{{\"kind\":\"tracking\",\"report\":\"{}\",\"prior\":\"{}\",\"foreground\":\"{}\",\"exposure\":\"{}\",\"capture\":{:?},\"detector\":\"{}\",\"mask\":\"{}\",\"availability\":\"{:?}\",\"assignment_cost\":{},\"decisions\":[",
        hex(report.digest()),
        hex(report.prior_digest()),
        hex(frame.evidence),
        hex(frame.source.image.exposure),
        frame.source.capture,
        hex(frame.detector),
        hex(frame.permission_mask),
        frame.availability,
        report.assignment_cost()
    )?;
    for (i, decision) in report.decisions().iter().enumerate() {
        if i != 0 {
            write!(out, ",")?;
        }
        let (status, track) = match decision.disposition {
            ImageDetectionDisposition::Started(id) => ("started", Some(id)),
            ImageDetectionDisposition::Continued(id) => ("continued", Some(id)),
            ImageDetectionDisposition::Unresolved => ("unresolved", None),
            ImageDetectionDisposition::Unavailable => ("unavailable", None),
        };
        write!(
            out,
            "{{\"detection\":{},\"evidence\":\"{}\",\"status\":\"{}\",\"track\":",
            decision.detection.id,
            hex(decision.detection.evidence),
            status
        )?;
        if let Some(id) = track {
            write!(out, "{id}")?;
        } else {
            write!(out, "null")?;
        }
        write!(out, "}}")?;
    }
    write!(out, "],\"candidates\":[")?;
    for (i, candidate) in report.candidates().iter().enumerate() {
        if i != 0 {
            write!(out, ",")?;
        }
        write!(
            out,
            "{{\"track\":{},\"detection\":{},\"cost\":",
            candidate.track, candidate.detection
        )?;
        if let Some(cost) = candidate.cost {
            write!(out, "{cost}")?;
        } else {
            write!(out, "null")?;
        }
        write!(
            out,
            ",\"selected\":{},\"ambiguous\":{}}}",
            candidate.selected, candidate.ambiguous
        )?;
    }
    write!(out, "],\"tracks\":[")?;
    for (i, track) in tracker.tracks().iter().enumerate() {
        if i != 0 {
            write!(out, ",")?;
        }
        let observed = track.latest();
        write!(
            out,
            "{{\"id\":{},\"state\":\"{:?}\",\"observations\":{},\"misses\":{},\"min\":{:?},\"max\":{:?},\"partial\":{},\"last_observed_exposure\":\"{}\",\"last_observed_report\":\"{}\"}}",
            track.id(),
            track.state(),
            track.observations(),
            track.misses(),
            observed.detection.min,
            observed.detection.max,
            observed.detection.partial,
            hex(observed.frame.source.image.exposure),
            hex(observed.frame.evidence)
        )?;
    }
    write!(out, "],\"expired\":[")?;
    for (i, expired) in report.expired().iter().enumerate() {
        if i != 0 {
            write!(out, ",")?;
        }
        write!(
            out,
            "{{\"id\":{},\"reason\":\"{:?}\",\"last_observed_exposure\":\"{}\"}}",
            expired.track.id(),
            expired.reason,
            hex(expired.track.latest().frame.source.image.exposure)
        )?;
    }
    writeln!(out, "]}}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_core::ContentDigest;
    use fss_twin::foreground::ForegroundSource;
    use fss_twin::image_tracking::{ImageDetection, ImageTrackingFrame, TrackingAvailability};
    use fss_twin::localization::ImageIdentity;

    fn settings() -> BTreeMap<&'static str, &'static str> {
        SETTINGS
            .into_iter()
            .zip([
                "1111111111111111111111111111111111111111111111111111111111111111",
                "32",
                "32",
                "128",
                "3",
                "5",
                "2000000000",
                "500",
                "4",
                "2000",
                "10",
            ])
            .collect()
    }
    fn key(n: u64) -> [u8; 32] {
        ContentDigest::sha256(&n.to_le_bytes()).bytes()
    }
    fn frame(n: u64) -> ImageTrackingFrame {
        ImageTrackingFrame {
            source: ForegroundSource {
                image: ImageIdentity {
                    exposure: key(n),
                    pixels: key(100 + n),
                    image_domain: key(200),
                    dimensions: [64, 32],
                },
                camera: 1,
                calibration: key(300),
                clock: 1,
                capture: [n * 1_000_000_000; 2],
            },
            detector: key(400),
            permission_mask: key(500),
            evidence: key(600 + n),
            availability: TrackingAvailability::Available,
        }
    }
    #[test]
    fn explicit_configuration_is_required_and_range_checked() -> Result<()> {
        let mut values = settings();
        let mut budget = WorkBudget::new(100_000);
        let tracker = configure(&values, &mut budget)?;
        assert_eq!(tracker.policy().maximum_tracks, 32);
        assert_eq!(tracker.policy().ambiguity_margin, 10);
        assert_eq!(values.remove("tracking_miss_cost"), Some("2000"));
        assert!(configure(&values, &mut budget).is_err());
        let _ = values.insert("tracking_miss_cost", "0");
        assert!(configure(&values, &mut budget).is_err());
        Ok(())
    }
    #[test]
    fn operator_output_retains_candidates_unresolved_decisions_and_old_observations() -> Result<()>
    {
        let mut budget = WorkBudget::new(10_000_000);
        let mut tracker = configure(&settings(), &mut budget)?;
        let detection = |id, x, evidence| ImageDetection {
            id,
            evidence: key(evidence),
            min: [x, 10],
            max: [x + 4, 14],
            partial: false,
        };
        tracker.update(
            frame(1),
            &[detection(1, 10, 701), detection(2, 30, 702)],
            &mut budget,
        )?;
        let report = tracker.update(
            frame(2),
            &[detection(1, 20, 801), detection(2, 20, 802)],
            &mut budget,
        )?;
        let mut out = Vec::new();
        write_report(&mut out, &tracker, &report)?;
        let text = String::from_utf8(out)?;
        assert!(text.starts_with("{\"kind\":\"tracking\","));
        assert!(text.ends_with("]}\n"));
        assert_eq!(text.matches("\"status\":\"unresolved\"").count(), 2);
        assert_eq!(text.matches("\"ambiguous\":true").count(), 2);
        assert_eq!(text.matches("\"selected\":").count(), 4);
        assert_eq!(text.matches("\"state\":\"Coasting\"").count(), 2);
        assert_eq!(
            text.matches(&format!("\"last_observed_exposure\":\"{}\"", hex(key(1))))
                .count(),
            2
        );
        Ok(())
    }
}
