#![forbid(unsafe_code)]
//! OFFLINE LABORATORY helper for the YOLOX-Nano conformance lane (fss-q4ngj).
//!
//! `inputs DIR`: writes each conformance case's exact FSS-preprocessed model input (NCHW RGB,
//! little-endian F32) and letterbox geometry so the lab oracle (onnxruntime, outside the repo)
//! evaluates the identical tensor. `bench PACKAGE SHA256 N`: loads the verified package and
//! reports wall time per scalar-reference inference. Neither mode is a runtime path.

use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use fss_codec_mjpeg::ComponentInterpretation;
use fss_codec_mjpeg::color::RgbDecodeReceipt;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId};
use fss_reference::ingest::rgb_inference::{RgbRunLimits, RgbSourceBinding};
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::preprocess::{ImageBytes, ResizeAspect, ResizeFilter, ResizeOptions};
use fss_reference::{ChannelTransform, ExecBudget, PreprocessProgram, ReplayCx, ScalarExecCx};

#[path = "../tests/yolox_support/cases.rs"]
mod cases;
#[path = "../tests/yolox_support/person.rs"]
mod person;

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

fn inputs(dir: &Path) -> Result<(), Box<dyn Error>> {
    let program = PreprocessProgram::new(416, 416, ChannelTransform::Rgb, false);
    let cx = ScalarExecCx::new();
    for name in cases::CASES {
        let image = cases::source(name)?;
        let [w, h] = image.dimensions;
        let out = program.execute_resized_bytes(
            ImageBytes {
                bytes: &image.pixels,
                height: h as usize,
                width: w as usize,
                channels: 3,
                generation: fss_core::Generation(1),
            },
            ResizeOptions {
                filter: ResizeFilter::Bilinear,
                aspect: ResizeAspect::Letterbox(114),
                budget: ExecBudget::new(1 << 40, 1 << 30),
            },
            &cx,
        )?;
        let bytes: Vec<u8> = out
            .tensor
            .to_vec::<f32>()?
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        write_new(&dir.join(format!("{name}.input.f32le")), &bytes)?;
        let g = out.geometry;
        write_new(
            &dir.join(format!("{name}.geometry.txt")),
            format!(
                "{} {} {} {} {} {}\n",
                g.source_width, g.source_height, g.image_width, g.image_height, g.left, g.top
            )
            .as_bytes(),
        )?;
        println!(
            "{name} native_jpeg={} input_sha256={} geometry={g:?}",
            image.jpeg.is_some(),
            ContentDigest::sha256(&bytes)
        );
    }
    Ok(())
}

fn bench(package: &Path, digest: &str, iterations: usize) -> Result<(), Box<dyn Error>> {
    let bytes = std::fs::read(package)?;
    let root = std::env::temp_dir();
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:yolox-lab".into(),
        operation_id: OperationId::parse("operation:yolox-lab")?,
        principal: "principal:yolox-lab".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
        privacy_scope: "privacy:lab".into(),
        retention_scope: "retention:lab".into(),
        anchor_universe: ContentDigest::sha256(b"site:yolox-lab"),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, root)?;
    let scalar = ScalarExecCx::new();
    let started = Instant::now();
    let package =
        RgbDetectorPackage::load(&bytes, ContentDigest::parse(digest)?, 1 << 40, &cx, &scalar)?;
    println!("package_load_ms={}", started.elapsed().as_millis());
    let image = cases::source("silhouette")?;
    let allowed = vec![1_u8; image.pixels.len() / 3];
    let source = RgbSourceBinding {
        encoded_sha256: [1; 32],
        exposure: [2; 32],
        camera: 1,
        clock: 1,
        capture: [0, 0],
        image_domain: [3; 32],
        calibration: [4; 32],
        permission_mask: ContentDigest::sha256(&allowed).bytes(),
    };
    let receipt = RgbDecodeReceipt {
        encoded_sha256: [1; 32],
        rgb_sha256: ContentDigest::sha256(&image.pixels).bytes(),
        decoder: [5; 32],
        interpretation: ComponentInterpretation::YCbCr,
        dimensions: image.dimensions,
        mcus: 0,
        entropy_blocks: 0,
        restarts: 0,
        metadata_segments: 0,
        metadata_bytes: 0,
    };
    let limits = RgbRunLimits {
        decode: Default::default(),
        preprocess: ExecBudget::new(1 << 40, 256 * 1024 * 1024),
        execution: ExecBudget::new(1 << 40, 256 * 1024 * 1024),
        maximum_output_bytes: 16 * 1024 * 1024,
    };
    for i in 0..iterations {
        let t = Instant::now();
        let inference = package.model().run_rgb_pixels(
            &image.pixels,
            receipt,
            source,
            &allowed,
            limits,
            &scalar,
        )?;
        println!(
            "iteration={i} wall_ms={} executed_macs={} allocated_tensor_bytes={} output_digest={}",
            t.elapsed().as_millis(),
            inference.executed_macs(),
            inference.allocated_tensor_bytes(),
            inference.output_digest()
        );
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["inputs", dir] => inputs(Path::new(dir)),
        ["bench", package, digest, n] => n
            .parse()
            .map_err(Into::into)
            .and_then(|n| bench(Path::new(package), digest, n)),
        _ => Err("usage: yolox_lab inputs DIR | bench PACKAGE SHA256 N".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("yolox_lab: {e}");
            ExitCode::FAILURE
        }
    }
}
