#![forbid(unsafe_code)]
//! Owner-operated local learned-weight replay. Not a camera service or fss/1 endpoint.
use std::collections::BTreeMap;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_twin::foreground::ForegroundSource;
use fss_twin::hog::{HogModel, HOG_PARAMETERS, MAX_HOG_PIXELS};
use fss_twin::hog_scan::{HogScan, ScanLevel, ScanPolicy, WindowDisposition, scan_hog};
use fss_twin::localization::ImageIdentity;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const KEYS: [&str; 23] = ["pixels", "pixels_sha256", "mask", "mask_sha256", "weights", "weights_sha256",
    "provenance", "width", "height", "camera", "clock", "capture_earliest_ns", "capture_latest_ns", "exposure",
    "image_domain", "calibration", "levels", "minimum_margin", "stride", "suppression_iou_ppm",
    "maximum_windows", "maximum_candidates", "work_units"];
fn read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let f = File::open(path)?;
    if !f.metadata()?.is_file() || f.metadata()?.len() > maximum as u64 { return Err("input size/type refused".into()); }
    let mut bytes = Vec::new(); bytes.try_reserve_exact(maximum + 1)?;
    f.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > maximum { return Err("input grew beyond its bound".into()); }
    Ok(bytes)
}
fn confined(root: &Path, name: &str) -> Result<PathBuf> {
    let path = Path::new(name);
    if path.components().next().is_none() || path.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err("input must be relative to the manifest directory".into());
    }
    let path = root.join(path).canonicalize()?;
    if !path.starts_with(root) { return Err("input escapes the manifest directory".into()); }
    Ok(path)
}
fn digest(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("expected lowercase SHA-256".into());
    }
    let mut out = [0; 32];
    for (i, b) in out.iter_mut().enumerate() { *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?; }
    if out == [0; 32] { return Err("zero identity refused".into()); } Ok(out)
}
fn hex(d: [u8; 32]) -> String { d.iter().map(|b| format!("{b:02x}")).collect() }
fn pair(s: &str) -> Result<[u32; 2]> {
    let (w, h) = s.split_once('x').ok_or("expected WIDTHxHEIGHT")?;
    Ok([w.parse()?, h.parse()?])
}
fn settings(text: &str) -> Result<BTreeMap<&str, &str>> {
    let mut lines = text.lines().filter(|s| !s.trim().is_empty() && !s.starts_with('#'));
    if lines.next() != Some("FSS_HOG_SCAN_1") { return Err("unsupported scan manifest".into()); }
    let mut settings = BTreeMap::new();
    for line in lines {
        let (key, value) = line.split_once('=').ok_or("expected key=value")?;
        if !KEYS.contains(&key) || value.is_empty() || settings.insert(key, value).is_some() {
            return Err("unknown, duplicate or empty setting".into());
        }
    }
    if settings.len() != KEYS.len() { return Err("incomplete scan manifest".into()); } Ok(settings)
}
fn output(out: &mut impl Write, scan: &HogScan, used: u64) -> Result<()> {
    writeln!(out, "{{\"kind\":\"hog_scan\",\"report\":\"{}\",\"generation\":\"{}\",\"model\":\"{}\",\"exposure\":\"{}\",\"pixels\":\"{}\",\"mask\":\"{}\",\"capture\":{:?},\"dimensions\":{:?},\"meaning\":\"uncalibrated_model_windows_not_person_identity\"}}",
        hex(scan.digest()), hex(scan.generation()), hex(scan.model_digest()), hex(scan.source().image.exposure),
        hex(scan.source().image.pixels), hex(scan.mask_digest()), scan.source().capture, scan.source().image.dimensions)?;
    for (index, level) in scan.levels().iter().enumerate() {
        writeln!(out, "{{\"kind\":\"level\",\"index\":{},\"dimensions\":{:?},\"pixels\":\"{}\",\"image_domain\":\"{}\",\"mask\":\"{}\",\"windows\":{}}}",
            index, level.dimensions, hex(level.source.image.pixels), hex(level.source.image.image_domain), hex(level.mask_digest), level.windows)?;
    }
    for w in scan.windows() {
        write!(out, "{{\"kind\":\"window\",\"id\":{},\"level\":{},\"origin\":{:?},\"min\":{:?},\"max\":{:?},\"margin\":",
            w.id, w.level, w.origin, w.source_min, w.source_max)?;
        if let Some(margin) = w.margin { write!(out, "{margin}")?; } else { write!(out, "null")?; }
        match w.disposition {
            WindowDisposition::Unobservable => writeln!(out, ",\"state\":\"unobservable\"}}")?,
            WindowDisposition::BelowThreshold => writeln!(out, ",\"state\":\"below_threshold\"}}")?,
            WindowDisposition::Selected => writeln!(out, ",\"state\":\"selected\"}}")?,
            WindowDisposition::Suppressed { by } => writeln!(out, ",\"state\":\"suppressed\",\"by\":{by}}}")?,
        }
    }
    writeln!(out, "{{\"kind\":\"complete\",\"windows\":{},\"selected\":{},\"work_units\":{}}}", scan.windows().len(), scan.selected().count(), used)?;
    out.flush()?; Ok(())
}
fn run() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let manifest = PathBuf::from(args.next().ok_or("usage: hog_scan MANIFEST")?).canonicalize()?;
    if args.next().is_some() { return Err("expected one manifest".into()); }
    let root = manifest.parent().ok_or("manifest has no parent")?;
    let text = String::from_utf8(read(&manifest, 65_536)?)?; let values = settings(&text)?;
    let get = |k| values.get(k).copied().ok_or("missing setting");
    let dimensions = [get("width")?.parse::<u32>()?, get("height")?.parse::<u32>()?];
    if dimensions.iter().any(|n| *n == 0 || *n > 4096) { return Err("invalid image dimensions".into()); }
    let count = dimensions[0] as usize * dimensions[1] as usize;
    if count > MAX_HOG_PIXELS { return Err("image exceeds pixel limit".into()); }
    let pixels = read(&confined(root, get("pixels")?)?, count)?;
    let mask = read(&confined(root, get("mask")?)?, count)?;
    if pixels.len() != count || mask.len() != count
        || ContentDigest::sha256(&pixels).bytes() != digest(get("pixels_sha256")?)?
        || ContentDigest::sha256(&mask).bytes() != digest(get("mask_sha256")?)? {
        return Err("source size or digest mismatch".into());
    }
    let bytes = read(&confined(root, get("weights")?)?, HOG_PARAMETERS * 4)?;
    let mut budget = WorkBudget::new(get("work_units")?.parse()?);
    let model = HogModel::from_f32_le(&bytes, digest(get("weights_sha256")?)?, digest(get("provenance")?)?, &mut budget)?;
    let mut levels = Vec::new();
    for spec in get("levels")?.split(',') {
        if levels.len() == 16 { return Err("too many levels".into()); }
        levels.push(ScanLevel { dimensions: pair(spec)? });
    }
    let source = ForegroundSource { image: ImageIdentity { exposure: digest(get("exposure")?)?,
        pixels: digest(get("pixels_sha256")?)?, image_domain: digest(get("image_domain")?)?, dimensions },
        camera: get("camera")?.parse()?, clock: get("clock")?.parse()?, calibration: digest(get("calibration")?)?,
        capture: [get("capture_earliest_ns")?.parse()?, get("capture_latest_ns")?.parse()?] };
    let scan = scan_hog(source, &pixels, &mask, &model, &levels, ScanPolicy {
        stride: pair(get("stride")?)?, minimum_margin: get("minimum_margin")?.parse()?,
        suppression_iou_ppm: get("suppression_iou_ppm")?.parse()?, maximum_windows: get("maximum_windows")?.parse()?,
        maximum_candidates: get("maximum_candidates")?.parse()? }, &mut budget)?;
    let stdout = std::io::stdout(); let mut out = std::io::BufWriter::new(stdout.lock());
    output(&mut out, &scan, budget.used())
}
fn main() {
    if let Err(error) = run() { eprintln!("HOG scan refused: {error}"); std::process::exit(1); }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manifest_requires_every_setting_and_rejects_duplicate_unknown_keys() -> Result<()> {
        let mut text = String::from("FSS_HOG_SCAN_1\n");
        for key in KEYS { text.push_str(&format!("{key}=value\n")); }
        assert_eq!(settings(&text)?.len(), 23);
        assert!(settings(&(text.clone() + "camera=2\n")).is_err());
        assert!(settings(&(text + "unknown=value\n")).is_err());
        assert!(settings("FSS_HOG_SCAN_1\ncamera=1\n").is_err()); Ok(())
    }
    #[test]
    fn numeric_pairs_and_identities_are_not_silently_coerced() -> Result<()> {
        assert_eq!(pair("64x128")?, [64, 128]);
        assert!(pair("64x128x256").is_err()); assert!(pair("-1x128").is_err());
        assert!(digest(&"0".repeat(64)).is_err()); assert!(digest(&"A".repeat(64)).is_err());
        assert_eq!(digest(&"1".repeat(64))?, [17; 32]); Ok(())
    }
}
