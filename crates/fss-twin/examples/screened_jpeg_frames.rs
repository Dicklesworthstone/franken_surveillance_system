#![forbid(unsafe_code)]
//! Owner-operated, read-only compressed JPEG replay. Not a live camera service or fss/1 command.
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeLimits};
use fss_core::ContentDigest;
use fss_geometry::{PinholeIntrinsics, WorkBudget};
use fss_twin::foreground::pipeline::FrameCapture;
use fss_twin::foreground::{BackgroundPolicy, ForegroundPolicy, MAX_FOREGROUND_PIXELS};
use fss_twin::image_tracking::{ImageDetectionDisposition, ImageTrackingPolicy};
use fss_twin::mjpeg::{
    JpegBackground, JpegFrameBinding, JpegReference, decode_rectified, decoded_image_domain,
};
use fss_twin::rectification::{LensDistortion, LumaRange, RectificationPlan, RectificationSpec};
use fss_twin::screened_mjpeg::{ForegroundStage, JpegScreeningQuery, screen_jpeg};
use fss_twin::screening::tracking::{ScreenedImageTracker, ScreenedTrackingReport};
use fss_twin::screening::{ScreeningMonitor, ScreeningPolicy, ScreeningStamp};
use std::collections::BTreeMap;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
/// Settings groups keyed by their manifest name, each holding its whitespace-separated fields.
type Settings<'a> = BTreeMap<&'a str, Vec<&'a str>>;
const GROUPS: [(&str, usize); 7] = [
    ("sensor", 8),
    ("image", 9),
    ("background", 5),
    ("foreground", 5),
    ("health", 14),
    ("tracking", 11),
    ("budgets", 7),
];
struct Row {
    query: bool,
    exposure: [u8; 32],
    capture: [u64; 2],
    sequence: u64,
    received: u64,
    jpeg: PathBuf,
    jpeg_hash: [u8; 32],
    mask: PathBuf,
    mask_hash: [u8; 32],
}
fn bytes(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() > limit as u64 {
        return Err("input file exceeds limit".into());
    }
    let mut data = Vec::new();
    data.try_reserve_exact(meta.len() as usize + 1)?;
    file.take(limit as u64 + 1).read_to_end(&mut data)?;
    if data.len() > limit {
        return Err("input grew beyond limit".into());
    }
    Ok(data)
}
fn hash(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err("expected a lowercase SHA-256 identity".into());
    }
    let mut digest = [0; 32];
    for (i, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * i..2 * i + 2], 16)?;
    }
    if digest == [0; 32] {
        return Err("zero identity".into());
    }
    Ok(digest)
}
fn hex(digest: [u8; 32]) -> String {
    digest.iter().map(|n| format!("{n:02x}")).collect()
}
fn confined(root: &Path, name: &str) -> Result<PathBuf> {
    let path = Path::new(name);
    if path.components().next().is_none()
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err("input path must remain below the manifest directory".into());
    }
    let resolved = root.join(path).canonicalize()?;
    if !resolved.starts_with(root) || !resolved.is_file() {
        return Err("input is outside the manifest directory".into());
    }
    Ok(resolved)
}
fn parse<'a>(text: &'a str, root: &Path) -> Result<(Settings<'a>, Vec<Row>)> {
    let mut lines = text
        .lines()
        .filter(|s| !s.trim().is_empty() && !s.trim_start().starts_with('#'));
    if lines.next() != Some("FSS_SCREENED_JPEG_REPLAY_1") {
        return Err("unsupported replay manifest".into());
    }
    let mut settings = BTreeMap::new();
    let mut rows = Vec::new();
    rows.try_reserve_exact(128)?;
    let mut saw_query = false;
    for line in lines {
        let p: Vec<_> = line.split_whitespace().collect();
        if let Some((_, count)) = GROUPS.iter().find(|(name, _)| *name == p[0]) {
            if !rows.is_empty() || p.len() != *count || settings.insert(p[0], p).is_some() {
                return Err("duplicate, late or malformed settings group".into());
            }
            continue;
        }
        if p.len() != 10 || !["reference", "query"].contains(&p[0]) || rows.len() == 128 {
            return Err("invalid or too many frame rows".into());
        }
        let query = p[0] == "query";
        if !query && saw_query {
            return Err("references must precede queries".into());
        }
        saw_query |= query;
        let capture = [p[2].parse()?, p[3].parse()?];
        if capture[0] > capture[1] {
            return Err("reversed capture interval".into());
        }
        let (sequence, received) = if query {
            (p[4].parse()?, p[5].parse()?)
        } else if p[4] == "-" && p[5] == "-" {
            (0, 0)
        } else {
            return Err("reference sequence and receive time must be '-'".into());
        };
        rows.push(Row {
            query,
            exposure: hash(p[1])?,
            capture,
            sequence,
            received,
            jpeg: confined(root, p[6])?,
            jpeg_hash: hash(p[7])?,
            mask: confined(root, p[8])?,
            mask_hash: hash(p[9])?,
        });
    }
    if settings.len() != GROUPS.len() || !saw_query {
        return Err("missing settings or query".into());
    }
    let references = rows.iter().take_while(|r| !r.query).count();
    if !(3..=31).contains(&references) {
        return Err("expected 3..31 selected references".into());
    }
    Ok((settings, rows))
}
fn write_tracks(
    out: &mut impl Write,
    owner: &ScreenedImageTracker,
    report: &ScreenedTrackingReport,
) -> Result<()> {
    let track = report.tracking();
    write!(
        out,
        "{{\"kind\":\"screened_tracking\",\"report\":\"{}\",\"prior\":\"{}\",\"input\":\"{}\",\"tracking\":\"{}\",\"availability\":\"{:?}\",\"skipped\":{},\"health_history_gap\":{},\"work_units\":{},\"decisions\":[",
        hex(report.digest()),
        hex(report.prior_digest()),
        hex(report.input_digest()),
        hex(track.digest()),
        track.frame().availability,
        report.skipped_sequences(),
        report.health_history_gap(),
        report.work_units()
    )?;
    for (i, decision) in track.decisions().iter().enumerate() {
        if i != 0 {
            write!(out, ",")?;
        }
        let (status, id) = match decision.disposition {
            ImageDetectionDisposition::Started(id) => ("started", Some(id)),
            ImageDetectionDisposition::Continued(id) => ("continued", Some(id)),
            ImageDetectionDisposition::Unresolved => ("unresolved", None),
            ImageDetectionDisposition::Unavailable => ("unavailable", None),
        };
        write!(
            out,
            "{{\"region\":{},\"evidence\":\"{}\",\"min\":{:?},\"max\":{:?},\"partial\":{},\"status\":\"{}\",\"track\":",
            decision.detection.id,
            hex(decision.detection.evidence),
            decision.detection.min,
            decision.detection.max,
            decision.detection.partial,
            status
        )?;
        if let Some(id) = id {
            write!(out, "{id}")?;
        } else {
            write!(out, "null")?;
        }
        write!(out, "}}")?;
    }
    write!(out, "],\"candidates\":[")?;
    for (i, candidate) in track.candidates().iter().enumerate() {
        if i != 0 {
            write!(out, ",")?;
        }
        write!(
            out,
            "{{\"track\":{},\"region\":{},\"selected\":{},\"ambiguous\":{},\"cost\":",
            candidate.track, candidate.detection, candidate.selected, candidate.ambiguous
        )?;
        if let Some(cost) = candidate.cost {
            write!(out, "{cost}")?;
        } else {
            write!(out, "null")?;
        }
        write!(out, "}}")?;
    }
    write!(out, "],\"tracks\":[")?;
    for (i, live) in owner.tracker().tracks().iter().enumerate() {
        if i != 0 {
            write!(out, ",")?;
        }
        let last = live.latest();
        write!(
            out,
            "{{\"id\":{},\"state\":\"{:?}\",\"observations\":{},\"misses\":{},\"last_exposure\":\"{}\",\"last_input\":\"{}\",\"last_capture\":{:?},\"min\":{:?},\"max\":{:?}}}",
            live.id(),
            live.state(),
            live.observations(),
            live.misses(),
            hex(last.frame.source.image.exposure),
            hex(last.frame.evidence),
            last.frame.source.capture,
            last.detection.min,
            last.detection.max
        )?;
    }
    write!(out, "],\"expired\":[")?;
    for (i, expired) in track.expired().iter().enumerate() {
        if i != 0 {
            write!(out, ",")?;
        }
        write!(
            out,
            "{{\"id\":{},\"reason\":\"{:?}\",\"last_exposure\":\"{}\"}}",
            expired.track.id(),
            expired.reason,
            hex(expired.track.latest().frame.source.image.exposure)
        )?;
    }
    writeln!(out, "]}}")?;
    Ok(())
}
fn run() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let manifest =
        PathBuf::from(args.next().ok_or("usage: screened_jpeg_frames MANIFEST")?).canonicalize()?;
    if args.next().is_some() {
        return Err("expected one manifest".into());
    }
    let text = String::from_utf8(bytes(&manifest, 65_536)?)?;
    let (settings, rows) = parse(&text, manifest.parent().ok_or("manifest has no parent")?)?;
    let s = &settings["sensor"];
    let image = &settings["image"];
    let bp = &settings["background"];
    let fp = &settings["foreground"];
    let hp = &settings["health"];
    let tp = &settings["tracking"];
    let limits = &settings["budgets"];
    let mut decode = DecodeBudget::new(limits[1].parse()?);
    let mut geometry = WorkBudget::new(limits[2].parse()?);
    let mut foreground = WorkBudget::new(limits[3].parse()?);
    let mut health = WorkBudget::new(limits[4].parse()?);
    let mut tracking = WorkBudget::new(limits[5].parse()?);
    let maximum_bytes: usize = limits[6].parse()?;
    if maximum_bytes == 0 || maximum_bytes > 16 * 1024 * 1024 {
        return Err("invalid JPEG byte ceiling".into());
    }
    let (width, height): (u32, u32) = (image[1].parse()?, image[2].parse()?);
    if width == 0 || height == 0 || width > 4096 || height > 4096 {
        return Err("invalid image dimensions".into());
    }
    let count = width as usize * height as usize;
    let refs = rows.iter().take_while(|r| !r.query).count();
    if count > MAX_FOREGROUND_PIXELS || refs * count > 4 * MAX_FOREGROUND_PIXELS {
        return Err("reference/image pixel ceiling exceeded".into());
    }
    let color = match image[8] {
        "grayscale" => ComponentInterpretation::Grayscale,
        "ycbcr" => ComponentInterpretation::YCbCr,
        _ => return Err("unknown component interpretation".into()),
    };
    let domain = hash(s[5])?;
    let calibration = hash(s[6])?;
    let (camera, clock, generation): (u64, u64, u64) =
        (s[1].parse()?, s[2].parse()?, s[3].parse()?);
    let intrinsics = PinholeIntrinsics::new(
        width,
        height,
        image[3].parse()?,
        image[4].parse()?,
        image[5].parse()?,
        image[6].parse()?,
    )?;
    let plan = RectificationPlan::compile(
        RectificationSpec {
            source: intrinsics,
            target: intrinsics,
            distortion: LensDistortion::Pinhole,
            maximum_radius: image[7].parse()?,
            source_domain: decoded_image_domain(domain, color),
            calibration,
            range: LumaRange::Full,
        },
        &mut geometry,
    )?;
    let foreground_policy = ForegroundPolicy {
        minimum_change: fp[1].parse()?,
        minimum_area: fp[2].parse()?,
        maximum_regions: fp[3].parse()?,
        widespread_per_mille: fp[4].parse()?,
    };
    let mut monitor = ScreeningMonitor::new(
        ScreeningPolicy {
            minimum_visible_pixels: hp[1].parse()?,
            dark_luma: hp[2].parse()?,
            bright_luma: hp[3].parse()?,
            extreme_per_mille: hp[4].parse()?,
            flat_range: hp[5].parse()?,
            repeat_frames: hp[6].parse()?,
            repeat_duration_ns: hp[7].parse()?,
            stall_after_ns: hp[8].parse()?,
            maximum_capture_uncertainty_ns: hp[9].parse()?,
            recovery_frames: hp[10].parse()?,
            minimum_analysis_interval_ns: hp[11].parse()?,
            sentinel_interval_ns: hp[12].parse()?,
            activity_hold_ns: hp[13].parse()?,
        },
        generation,
        s[4].parse()?,
    )?;
    let mut owner = ScreenedImageTracker::new(
        hash(s[7])?,
        generation,
        ImageTrackingPolicy {
            maximum_tracks: tp[1].parse()?,
            maximum_detections: tp[2].parse()?,
            maximum_exposures: tp[3].parse()?,
            minimum_observations: tp[4].parse()?,
            maximum_misses: tp[5].parse()?,
            maximum_gap_ns: tp[6].parse()?,
            maximum_speed: tp[7].parse()?,
            gate_padding: tp[8].parse()?,
            miss_cost: tp[9].parse()?,
            ambiguity_margin: tp[10].parse()?,
        },
        &mut tracking,
    )?;
    let decode_limits = DecodeLimits {
        maximum_bytes,
        maximum_pixels: count,
        ..DecodeLimits::default()
    };
    let binding = |row: &Row| JpegFrameBinding {
        encoded_sha256: row.jpeg_hash,
        exposure: row.exposure,
        allowed_mask: row.mask_hash,
        camera_image_domain: domain,
        calibration,
        interpretation: color,
    };
    let capture = |row: &Row| FrameCapture {
        camera,
        clock,
        capture: row.capture,
    };
    let load = |row: &Row| -> Result<(Vec<u8>, Vec<u8>)> {
        let jpeg = bytes(&row.jpeg, maximum_bytes)?;
        let mask = bytes(&row.mask, count)?;
        if mask.len() != count
            || ContentDigest::sha256(&jpeg).bytes() != row.jpeg_hash
            || ContentDigest::sha256(&mask).bytes() != row.mask_hash
        {
            return Err("file content binding mismatch".into());
        }
        Ok((jpeg, mask))
    };
    let mut references = Vec::new();
    references.try_reserve_exact(refs)?;
    for row in &rows[..refs] {
        let (jpeg, mask) = load(row)?;
        references.push(decode_rectified(
            &plan,
            &jpeg,
            &mask,
            binding(row),
            decode_limits,
            &mut decode,
            &mut geometry,
        )?);
    }
    let selected: Vec<_> = references
        .iter()
        .zip(&rows[..refs])
        .map(|(image, row)| JpegReference {
            image,
            capture: capture(row),
        })
        .collect();
    let model = JpegBackground::build(
        &plan,
        &selected,
        BackgroundPolicy {
            selection_evidence: hash(bp[1])?,
            validity: [bp[2].parse()?, bp[3].parse()?],
            maximum_spread: bp[4].parse()?,
        },
        &mut geometry,
    )?;
    drop(selected);
    drop(references);
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    writeln!(
        out,
        "{{\"kind\":\"replay_basis\",\"manifest\":\"{}\",\"camera\":{},\"clock\":{},\"generation\":{},\"episode\":\"{}\",\"durable_publication\":false}}",
        hex(ContentDigest::sha256(text.as_bytes()).bytes()),
        camera,
        clock,
        generation,
        s[7]
    )?;
    let mut completed = 0;
    for row in &rows[refs..] {
        let (jpeg, mask) = load(row)?;
        let result = screen_jpeg(
            &mut monitor,
            Some(&model),
            &plan,
            JpegScreeningQuery {
                bytes: &jpeg,
                mask: &mask,
                binding: binding(row),
                capture: capture(row),
                foreground_policy,
                decode_limits,
                stamp: ScreeningStamp {
                    stream_generation: generation,
                    sequence: row.sequence,
                    received_at_ns: row.received,
                    owner_requests_analysis: owner.requires_analysis(),
                },
            },
            &mut decode,
            &mut geometry,
            &mut foreground,
            &mut health,
        )?;
        let screen = result.screening();
        write!(
            out,
            "{{\"kind\":\"screened_frame\",\"input\":\"{}\",\"screen\":\"{}\",\"exposure\":\"{}\",\"encoded\":\"{}\",\"sequence\":{},\"capture\":{:?},\"received_at_ns\":{},\"health\":\"{:?}\",\"flags\":{},\"analysis_due\":{},\"analysis_completed\":false,\"foreground\":",
            hex(result.digest()),
            hex(screen.digest()),
            hex(row.exposure),
            hex(row.jpeg_hash),
            row.sequence,
            row.capture,
            row.received,
            screen.health(),
            screen.flags().bits(),
            screen.analysis_due()
        )?;
        match result.foreground() {
            ForegroundStage::Complete(report) => write!(
                out,
                "{{\"state\":\"complete\",\"report\":\"{}\",\"assessment\":\"{:?}\",\"comparable\":{},\"changed\":{},\"small_components\":{},\"small_pixels\":{}}}",
                hex(report.digest()),
                report.assessment(),
                report.comparable_pixels(),
                report.changed_pixels(),
                report.small_component_count(),
                report.small_component_pixels()
            )?,
            ForegroundStage::Refused(error) => {
                write!(out, "{{\"state\":\"refused\",\"reason\":\"{error:?}\"}}")?
            }
            ForegroundStage::NotConfigured => write!(out, "{{\"state\":\"not_configured\"}}")?,
        }
        writeln!(out, "}}")?;
        out.flush()?;
        // The health record above survives a tracking refusal; never label a prefix complete.
        match owner.update_jpeg(&result, &mut tracking) {
            Ok(report) => write_tracks(&mut out, &owner, &report)?,
            Err(error) => {
                writeln!(
                    out,
                    "{{\"kind\":\"tracking_refused\",\"input\":\"{}\",\"reason\":\"{error:?}\"}}",
                    hex(result.digest())
                )?;
                out.flush()?;
                return Err(Box::new(error));
            }
        }
        out.flush()?;
        completed += 1;
    }
    writeln!(
        out,
        "{{\"kind\":\"complete\",\"frames\":{},\"decode_units\":{},\"geometry_units\":{},\"foreground_units\":{},\"health_units\":{},\"tracking_units\":{},\"semantic_analyses_completed\":0}}",
        completed,
        decode.used(),
        geometry.used(),
        foreground.used(),
        health.used(),
        tracking.used()
    )?;
    out.flush()?;
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("screened JPEG replay failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manifest_rejects_unknown_duplicate_and_incomplete_configuration() {
        for text in [
            "",
            "FSS_SCREENED_JPEG_REPLAY_1\n",
            "FSS_SCREENED_JPEG_REPLAY_1\nunknown x\n",
            "FSS_SCREENED_JPEG_REPLAY_1\nimage 1 1 1 1 0 0 1 grayscale\nimage 1 1 1 1 0 0 1 grayscale\n",
        ] {
            assert!(parse(text, Path::new(".")).is_err());
        }
    }
    #[test]
    fn complete_explicit_manifest_preserves_original_capture_and_receive_order() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fss-codec-mjpeg/tests/fixtures")
            .canonicalize()?;
        let id = "01".repeat(32);
        let mut text = format!(
            "FSS_SCREENED_JPEG_REPLAY_1\nsensor 1 2 1 0 {id} {id} {id}\nimage 17 13 20 20 8.5 6.5 1 grayscale\nbackground {id} 0 1000 0\nforeground 10 1 64 1000\nhealth 16 10 245 900 2 3 20 100 5 1 5 40 10\ntracking 64 64 128 2 8 1000 100 8 100 0\nbudgets 100000 100000 100000 100000 100000 1024\n"
        );
        // Parser-only: these file paths exist; decode/hash validation belongs to run().
        for n in 1..=3 {
            text.push_str(&format!(
                "reference {id} {n} {n} - - background.jpg {id} gray.jpg {id}\n"
            ));
        }
        text.push_str(&format!(
            "query {id} 40 42 7 100 gray.jpg {id} gray.jpg {id}\n"
        ));
        let (settings, rows) = parse(&text, &root)?;
        assert_eq!(settings.len(), 7);
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[3].sequence, 7);
        assert_eq!(rows[3].capture, [40, 42]);
        assert_eq!(rows[3].received, 100);
        assert!(rows[3].query);
        Ok(())
    }
    #[test]
    fn identity_parser_rejects_unbound_and_noncanonical_inputs() -> Result<()> {
        assert_eq!(hash(&"01".repeat(32))?, [1; 32]);
        for value in [
            "00".repeat(32),
            "AB".repeat(32),
            "g0".repeat(32),
            "1".into(),
        ] {
            assert!(hash(&value).is_err());
        }
        Ok(())
    }
}
