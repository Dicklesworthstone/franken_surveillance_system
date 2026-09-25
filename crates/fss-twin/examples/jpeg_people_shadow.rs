#![forbid(unsafe_code)]
//! Owner-operated local JPEG replay through real pretrained native inference.
//! No camera acquisition, production activation, durable publication or alert effect.
use fss_codec_mjpeg::DecodeBudget;
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_twin::image_zones::ImageZoneBasis;
use fss_twin::image_zones::pipeline::ImageZonePipeline;
use fss_twin::mjpeg::{JpegBackground, JpegReference, decode_rectified, decoded_image_domain};
use fss_twin::pretrained_hog::load_opencv_people_candidate;
use fss_twin::rectification::{LensDistortion, LumaRange, RectificationPlan, RectificationSpec};
use fss_twin::screened_mjpeg::JpegScreeningQuery;
use fss_twin::screening::ScreeningStamp;
use fss_twin::screening::tracking::hog::jpeg::{JpegHogConfig, JpegHogPipeline, JpegHogProgress};
use std::error::Error;
use std::io::Write;
use std::path::{Path, PathBuf};
#[path = "jpeg_people_shadow/input.rs"]
mod input;
#[path = "jpeg_people_shadow/output.rs"]
mod output;
#[cfg(test)]
#[path = "jpeg_people_shadow/tests.rs"]
mod tests;
type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn execute(text: &str, root: &Path, writer: &mut impl Write) -> Result<()> {
    let config = input::parse(text, root)?;
    let mut decode = DecodeBudget::new(config.units[0]);
    let mut geometry = WorkBudget::new(config.units[1]);
    let mut foreground = WorkBudget::new(config.units[2]);
    let mut health = WorkBudget::new(config.units[3]);
    let mut inference = WorkBudget::new(config.units[4]);
    let mut downstream = WorkBudget::new(config.units[5]);
    let plan = RectificationPlan::compile(
        RectificationSpec {
            source: config.intrinsics,
            target: config.intrinsics,
            distortion: LensDistortion::Pinhole,
            maximum_radius: config.radius,
            source_domain: decoded_image_domain(config.domain, config.color),
            calibration: config.calibration,
            range: LumaRange::Full,
        },
        &mut geometry,
    )?;
    let mut references = Vec::new();
    references.try_reserve_exact(config.references)?;
    for row in &config.rows[..config.references] {
        let (jpeg, mask) = config.load(row)?;
        references.push(decode_rectified(
            &plan,
            &jpeg,
            &mask,
            config.binding(row),
            config.decode,
            &mut decode,
            &mut geometry,
        )?);
    }
    let image_domain = references[0].frame().identity().image_domain;
    let selected: Vec<_> = references
        .iter()
        .zip(&config.rows[..config.references])
        .map(|(image, row)| JpegReference {
            image,
            capture: config.capture(row),
        })
        .collect();
    let background = JpegBackground::build(&plan, &selected, config.background, &mut geometry)?;
    drop(selected);
    drop(references);
    let zones = ImageZonePipeline::new(
        config.episode,
        config.tracking,
        ImageZoneBasis {
            camera: config.camera,
            clock: config.clock,
            calibration: config.calibration,
            image_domain,
            dimensions: config.dimensions,
        },
        config.zone_policy,
        &config.zones,
        &mut downstream,
    )?;
    let model = load_opencv_people_candidate(&mut inference)?;
    let mut pipeline = JpegHogPipeline::new(
        zones,
        model,
        JpegHogConfig {
            stream_generation: config.generation,
            started_at_ns: config.started,
            screening: config.health,
            levels: &config.levels,
            scan: config.scan,
        },
        &mut downstream,
    )?;
    let mut out = output::Limited::new(writer, config.output_bytes);
    writeln!(
        out,
        "{{\"kind\":\"shadow_basis\",\"manifest\":\"{}\",\"episode\":\"{}\",\"generation\":{},\"model\":\"{}\",\"weights\":\"{}\",\"provenance\":\"{}\",\"candidate\":\"opencv-people-shadow-1\",\"durable_publication\":false,\"effect_authority\":false,\"qualified_detector\":false}}",
        output::hex(ContentDigest::sha256(text.as_bytes()).bytes()),
        output::hex(config.episode),
        config.generation,
        output::hex(pipeline.model().digest()),
        output::hex(pipeline.model().weights_digest()),
        output::hex(pipeline.model().provenance())
    )?;
    let mut completed = 0;
    for row in &config.rows[config.references..] {
        let (jpeg, mask) = config.load(row)?;
        let progress = pipeline.observe(
            Some(&background),
            &plan,
            JpegScreeningQuery {
                bytes: &jpeg,
                mask: &mask,
                binding: config.binding(row),
                capture: config.capture(row),
                foreground_policy: config.foreground,
                decode_limits: config.decode,
                stamp: ScreeningStamp {
                    stream_generation: config.generation,
                    sequence: row.sequence,
                    received_at_ns: row.received,
                    owner_requests_analysis: false,
                },
                redaction: None,
            },
            &mut decode,
            &mut geometry,
            &mut foreground,
            &mut health,
            &mut inference,
            &mut downstream,
        )?;
        // These are current receipts only. A pending stage cannot reveal stale predecessor outputs.
        output::current(&mut out, &pipeline)?;
        match progress {
            JpegHogProgress::Complete(c) => {
                writeln!(
                    out,
                    "{{\"kind\":\"frame_complete\",\"image\":\"{}\",\"scan\":\"{}\",\"tracking\":\"{}\",\"zones\":\"{}\"}}",
                    output::hex(c.image),
                    output::hex(c.scan),
                    output::hex(c.tracking),
                    output::hex(c.zones)
                )?;
                completed += 1;
            }
            JpegHogProgress::Pending {
                image,
                stage,
                error,
            } => {
                writeln!(
                    out,
                    "{{\"kind\":\"pending\",\"image\":\"{}\",\"stage\":\"{stage:?}\",\"reason\":\"{error:?}\",\"source_consumed\":true,\"durable_checkpoint\":false}}",
                    output::hex(image)
                )?;
                out.flush()?;
                return Err("accepted source has unfinished work; replay with a sufficient explicit session budget".into());
            }
        }
        out.flush()?;
    }
    writeln!(
        out,
        "{{\"kind\":\"complete\",\"frames\":{},\"decode_units\":{},\"geometry_units\":{},\"foreground_units\":{},\"health_units\":{},\"inference_units\":{},\"downstream_units\":{},\"semantic_analyses_acknowledged\":0,\"durable_publication\":false}}",
        completed,
        decode.used(),
        geometry.used(),
        foreground.used(),
        health.used(),
        inference.used(),
        downstream.used()
    )?;
    out.flush()?;
    Ok(())
}
fn run() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let manifest =
        PathBuf::from(args.next().ok_or("usage: jpeg_people_shadow MANIFEST")?).canonicalize()?;
    if args.next().is_some() {
        return Err("expected exactly one manifest".into());
    }
    let text = String::from_utf8(input::read(&manifest, 65_536)?)?;
    let stdout = std::io::stdout();
    let mut writer = std::io::BufWriter::new(stdout.lock());
    execute(
        &text,
        manifest.parent().ok_or("manifest has no parent")?,
        &mut writer,
    )
}
fn main() {
    if let Err(error) = run() {
        eprintln!("JPEG people shadow replay failed: {error}");
        std::process::exit(1);
    }
}
