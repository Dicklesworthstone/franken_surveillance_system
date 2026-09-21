#![forbid(unsafe_code)]
//! Bounded operator-owned replay inputs. Not a hostile-filesystem security boundary.
use super::Result;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use fss_codec_mjpeg::{ComponentInterpretation, DecodeLimits};
use fss_core::ContentDigest;
use fss_geometry::PinholeIntrinsics;
use fss_twin::foreground::{BackgroundPolicy, ForegroundPolicy, MAX_FOREGROUND_PIXELS};
use fss_twin::foreground::pipeline::FrameCapture;
use fss_twin::hog_scan::{ScanLevel, ScanPolicy, MAX_SCAN_LEVELS, MAX_SCAN_WINDOWS, MAX_SCAN_CANDIDATES};
use fss_twin::image_tracking::ImageTrackingPolicy;
use fss_twin::image_zones::{ImageZonePolicy, ImageZoneSpec, MAX_IMAGE_ZONES, MAX_ZONE_VERTICES};
use fss_twin::mjpeg::JpegFrameBinding;
use fss_twin::screening::ScreeningPolicy;

const GROUPS: [(&str, usize); 10] = [("sensor", 8), ("image", 9), ("background", 5),
    ("foreground", 5), ("health", 14), ("tracking", 11), ("budgets", 9),
    ("scan", 8), ("zone_policy", 3), ("model", 2)];

pub struct Row {
    pub query: bool, pub exposure: [u8; 32], pub capture: [u64; 2],
    pub sequence: u64, pub received: u64,
    jpeg: PathBuf, jpeg_hash: [u8; 32], mask: PathBuf, mask_hash: [u8; 32],
}
pub struct Config {
    pub camera: u64, pub clock: u64, pub generation: u64, pub started: u64,
    pub domain: [u8; 32], pub calibration: [u8; 32], pub episode: [u8; 32],
    pub dimensions: [u32; 2], pub intrinsics: PinholeIntrinsics, pub radius: f64,
    pub color: ComponentInterpretation, pub decode: DecodeLimits,
    pub background: BackgroundPolicy, pub foreground: ForegroundPolicy,
    pub health: ScreeningPolicy, pub tracking: ImageTrackingPolicy,
    pub scan: ScanPolicy, pub levels: Vec<ScanLevel>,
    pub zone_policy: ImageZonePolicy, pub zones: Vec<ImageZoneSpec>,
    pub units: [u64; 6], pub output_bytes: usize, pub rows: Vec<Row>, pub references: usize,
}
impl Config {
    pub fn capture(&self, row: &Row) -> FrameCapture {
        FrameCapture { camera: self.camera, clock: self.clock, capture: row.capture }
    }
    pub fn binding(&self, row: &Row) -> JpegFrameBinding {
        JpegFrameBinding { encoded_sha256: row.jpeg_hash, exposure: row.exposure,
            allowed_mask: row.mask_hash, camera_image_domain: self.domain,
            calibration: self.calibration, interpretation: self.color }
    }
    pub fn load(&self, row: &Row) -> Result<(Vec<u8>, Vec<u8>)> {
        let count = self.dimensions[0] as usize * self.dimensions[1] as usize;
        let jpeg = read(&row.jpeg, self.decode.maximum_bytes)?;
        let mask = read(&row.mask, count)?;
        if mask.len() != count || mask.iter().any(|n| *n > 1)
            || ContentDigest::sha256(&jpeg).bytes() != row.jpeg_hash
            || ContentDigest::sha256(&mask).bytes() != row.mask_hash {
            return Err("source content or permission binding mismatch".into());
        }
        Ok((jpeg, mask))
    }
}
pub fn read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = File::open(path)?; let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit as u64 { return Err("input file exceeds limit".into()); }
    let mut bytes = Vec::new(); bytes.try_reserve_exact(metadata.len() as usize + 1)?;
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit { return Err("input grew beyond limit".into()); }
    Ok(bytes)
}
pub fn hash(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return Err("expected canonical lowercase SHA-256".into());
    }
    let mut digest = [0; 32];
    for (i, byte) in digest.iter_mut().enumerate() { *byte = u8::from_str_radix(&value[2*i..2*i+2], 16)?; }
    if digest == [0; 32] { return Err("zero source identity".into()); }
    Ok(digest)
}
fn number<T: FromStr>(value: &str) -> Result<T> {
    value.parse().map_err(|_| "invalid numeric input".into())
}
fn confined(root: &Path, name: &str) -> Result<PathBuf> {
    let relative = Path::new(name);
    if relative.components().next().is_none()
        || relative.components().any(|part| !matches!(part, Component::Normal(_))) {
        return Err("input path must remain beneath manifest directory".into());
    }
    let path = root.join(relative).canonicalize()?;
    if !path.starts_with(root) || !path.is_file() { return Err("input escapes manifest directory".into()); }
    Ok(path)
}
fn dimensions(text: &str, separator: char) -> Result<[u32; 2]> {
    let (a, b) = text.split_once(separator).ok_or("expected coordinate pair")?;
    Ok([number(a)?, number(b)?])
}
fn pixels(size: [u32; 2]) -> Result<usize> {
    if size.iter().any(|n| *n == 0 || *n > 4096) { return Err("invalid grid dimensions".into()); }
    let count = size[0] as usize * size[1] as usize;
    if count > MAX_FOREGROUND_PIXELS { return Err("image pixel limit".into()); }
    Ok(count)
}
pub fn parse(text: &str, root: &Path) -> Result<Config> {
    if text.len() > 65_536 { return Err("manifest byte limit".into()); }
    let mut lines = text.lines().map(str::trim).filter(|s| !s.is_empty() && !s.starts_with('#'));
    if lines.next() != Some("FSS_JPEG_PEOPLE_SHADOW_1") { return Err("unsupported manifest".into()); }
    let mut settings = BTreeMap::new(); let mut rows: Vec<Row> = Vec::new();
    let mut zones = Vec::new(); let mut ids = BTreeSet::new();
    let mut saw_query = false;
    for line in lines {
        let p: Vec<_> = line.split_whitespace().collect();
        if let Some((_, count)) = GROUPS.iter().find(|(name, _)| *name == p[0]) {
            if !rows.is_empty() || p.len() != *count || settings.insert(p[0], p).is_some() {
                return Err("duplicate, late or malformed setting".into());
            }
        } else if p[0] == "zone" {
            if !rows.is_empty() || zones.len() == MAX_IMAGE_ZONES || !(7..=4+MAX_ZONE_VERTICES).contains(&p.len()) {
                return Err("invalid, late or excessive zone".into());
            }
            let vertices = p[4..].iter().map(|s| dimensions(s, ',')).collect::<Result<Vec<_>>>()?;
            zones.push(ImageZoneSpec { id: number(p[1])?, margin: number(p[2])?,
                dwell_ns: if p[3] == "-" { None } else { Some(number(p[3])?) }, vertices });
        } else {
            if p.len() != 10 || !["reference", "query"].contains(&p[0]) || rows.len() == 128 {
                return Err("invalid or excessive frame row".into());
            }
            let query = p[0] == "query";
            if !query && saw_query { return Err("references must precede queries".into()); }
            let exposure = hash(p[1])?;
            if !ids.insert(exposure) { return Err("exposure identity reused".into()); }
            let capture = [number(p[2])?, number(p[3])?];
            if capture[0] > capture[1] { return Err("reversed capture interval".into()); }
            let (sequence, received) = if query { (number::<u64>(p[4])?, number::<u64>(p[5])?) }
                else if p[4] == "-" && p[5] == "-" { (0, 0) }
                else { return Err("references require unassigned sequence and receive time".into()); };
            if query && (sequence == 0 || rows.last().is_some_and(|last|
                last.query && (sequence <= last.sequence || received < last.received))) {
                return Err("query sequence or receive time regressed".into());
            }
            saw_query |= query;
            rows.push(Row { query, exposure, capture, sequence, received,
                jpeg: confined(root, p[6])?, jpeg_hash: hash(p[7])?,
                mask: confined(root, p[8])?, mask_hash: hash(p[9])? });
        }
    }
    let references = rows.iter().take_while(|r| !r.query).count();
    if settings.len() != GROUPS.len() || !saw_query || !(3..=31).contains(&references) || zones.is_empty() {
        return Err("missing settings, zones, references or queries".into());
    }
    if settings["model"][1] != "opencv-people-shadow-1" { return Err("explicit pinned shadow model required".into()); }
    let s = &settings["sensor"]; let im = &settings["image"]; let bp = &settings["background"];
    let fp = &settings["foreground"]; let hp = &settings["health"]; let tp = &settings["tracking"];
    let b = &settings["budgets"]; let sp = &settings["scan"]; let zp = &settings["zone_policy"];
    let size = [number(im[1])?, number(im[2])?]; let count = pixels(size)?;
    if references * count > 4 * MAX_FOREGROUND_PIXELS { return Err("reference-set pixel limit".into()); }
    let color = match im[8] { "grayscale" => ComponentInterpretation::Grayscale,
        "ycbcr" => ComponentInterpretation::YCbCr, _ => return Err("unknown JPEG interpretation".into()) };
    let intrinsics = PinholeIntrinsics::new(size[0], size[1], number(im[3])?, number(im[4])?, number(im[5])?, number(im[6])?)?;
    let scan = ScanPolicy { stride: [number(sp[1])?, number(sp[2])?], minimum_margin: number(sp[3])?,
        suppression_iou_ppm: number(sp[4])?, maximum_windows: number(sp[5])?, maximum_candidates: number(sp[6])? };
    // Preflight the current fixed scanner contract so a bad frozen profile cannot consume source.
    if scan.stride.iter().any(|n| *n == 0 || *n > 4096 || *n % 8 != 0)
        || !scan.minimum_margin.is_finite() || scan.minimum_margin.abs() > 1e10
        || !(1..=1_000_000).contains(&scan.suppression_iou_ppm)
        || !(1..=MAX_SCAN_WINDOWS).contains(&scan.maximum_windows)
        || !(1..=MAX_SCAN_CANDIDATES).contains(&scan.maximum_candidates) {
        return Err("invalid frozen scan profile".into());
    }
    let mut levels = Vec::new(); let mut seen = BTreeSet::new(); let mut windows = 0_usize;
    for grid in sp[7].split(',') {
        if levels.len() == MAX_SCAN_LEVELS { return Err("scale-set limit".into()); }
        let d = dimensions(grid, 'x')?; pixels(d)?;
        if !seen.insert(d) { return Err("duplicate scale".into()); }
        if d[0] >= 64 && d[1] >= 128 {
            windows += ((d[0]-64)/scan.stride[0]+1) as usize * ((d[1]-128)/scan.stride[1]+1) as usize;
        }
        levels.push(ScanLevel { dimensions: d });
    }
    if windows == 0 || windows > scan.maximum_windows { return Err("no supported windows or complete-window limit".into()); }
    let maximum_bytes: usize = number(b[7])?; let output_bytes: usize = number(b[8])?;
    if maximum_bytes == 0 || maximum_bytes > 16*1024*1024 || output_bytes == 0 || output_bytes > 64*1024*1024 {
        return Err("invalid source/output byte ceiling".into());
    }
    Ok(Config {
        camera: number(s[1])?, clock: number(s[2])?, generation: number(s[3])?, started: number(s[4])?,
        domain: hash(s[5])?, calibration: hash(s[6])?, episode: hash(s[7])?,
        dimensions: size, intrinsics, radius: number(im[7])?, color,
        decode: DecodeLimits { maximum_bytes, maximum_pixels: count, ..DecodeLimits::default() },
        background: BackgroundPolicy { selection_evidence: hash(bp[1])?, validity: [number(bp[2])?, number(bp[3])?], maximum_spread: number(bp[4])? },
        foreground: ForegroundPolicy { minimum_change: number(fp[1])?, minimum_area: number(fp[2])?, maximum_regions: number(fp[3])?, widespread_per_mille: number(fp[4])? },
        health: ScreeningPolicy { minimum_visible_pixels: number(hp[1])?, dark_luma: number(hp[2])?, bright_luma: number(hp[3])?,
            extreme_per_mille: number(hp[4])?, flat_range: number(hp[5])?, repeat_frames: number(hp[6])?, repeat_duration_ns: number(hp[7])?,
            stall_after_ns: number(hp[8])?, maximum_capture_uncertainty_ns: number(hp[9])?, recovery_frames: number(hp[10])?,
            minimum_analysis_interval_ns: number(hp[11])?, sentinel_interval_ns: number(hp[12])?, activity_hold_ns: number(hp[13])? },
        tracking: ImageTrackingPolicy { maximum_tracks: number(tp[1])?, maximum_detections: number(tp[2])?, maximum_exposures: number(tp[3])?,
            minimum_observations: number(tp[4])?, maximum_misses: number(tp[5])?, maximum_gap_ns: number(tp[6])?,
            maximum_speed: number(tp[7])?, gate_padding: number(tp[8])?, miss_cost: number(tp[9])?, ambiguity_margin: number(tp[10])? },
        scan, levels, zone_policy: ImageZonePolicy { selection_evidence: hash(zp[1])?, maximum_sample_gap_ns: number(zp[2])? }, zones,
        units: [number(b[1])?, number(b[2])?, number(b[3])?, number(b[4])?, number(b[5])?, number(b[6])?],
        output_bytes, rows, references,
    })
}
