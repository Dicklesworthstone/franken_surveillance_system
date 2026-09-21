#![forbid(unsafe_code)]
//! Generate, natively decode-check, and write an opt-in synthetic MJPEG source.
//! Usage: cargo run -p fss-reference --example virtual_mjpeg_capture -- OUTPUT.mjpeg

use std::error::Error;
use std::io::Write;
use std::sync::atomic::AtomicBool;

use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeLimits, decode_luma};
use fss_core::{CapsuleId, SensorId, TimestampNs};
use fss_reference::VirtualClock;
use fss_reference::ingest::virtual_mjpeg::{MjpegCameraSpec, MjpegSourceBudget, generate_mjpeg_source};

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let output = arguments.next().ok_or("usage: virtual_mjpeg_capture OUTPUT.mjpeg")?;
    if arguments.next().is_some() {
        return Err("usage: virtual_mjpeg_capture OUTPUT.mjpeg".into());
    }
    let spec = MjpegCameraSpec {
        capture_id: CapsuleId::parse("capture:virtual-mjpeg:example")?,
        sensor_id: SensorId::parse("sensor:virtual-mjpeg")?,
        seed: 7,
        frame_count: 12,
        width: 128,
        height: 96,
        start_ns: 1_000_000_000,
        period_ns: 33_333_333,
        uncertainty_ns: 500_000,
        packet_bytes: 257,
        warmup_frames: 3,
    };
    let cancellation = AtomicBool::new(false);
    let mut budget = MjpegSourceBudget::new(spec.rendered_pixels(), &cancellation);
    let mut clock = VirtualClock::new(spec.seed, TimestampNs(spec.start_ns));
    let source = generate_mjpeg_source(&spec, &mut clock, &mut budget)?;
    // Complete all native decode checks before touching the requested output path.
    for (index, span) in source.frames().iter().enumerate() {
        let bytes = source.frame_bytes(index).ok_or("missing complete generated frame")?;
        decode_luma(
            &bytes,
            span.encoded_digest.bytes(),
            ComponentInterpretation::Grayscale,
            DecodeLimits::default(),
            &mut DecodeBudget::new(100_000_000),
        )?;
    }
    // Never overwrite an existing file. A write failure may leave a partial new file;
    // the caller must not interpret it as a complete capture or clean source end.
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(output)?;
    let mut bytes_written = 0;
    for packet in source.packets() {
        file.write_all(&packet.bytes)?;
        bytes_written += packet.bytes.len();
    }
    file.sync_all()?;
    println!(
        "synthetic MJPEG: {} decoded frames, {} source packets, {} bytes; no presence/effect claim",
        source.frames().len(), source.packets().len(), bytes_written,
    );
    Ok(())
}
