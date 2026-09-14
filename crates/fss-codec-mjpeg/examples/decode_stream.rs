#![forbid(unsafe_code)]
//! Explicit owner-run raw MJPEG-file harness, not a device or network adapter.
use std::io::Read;
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeLimits};
use fss_codec_mjpeg::stream::{FramingLimits, JpegStream, StreamBasis};
use fss_core::ContentDigest;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 3 { return Err("usage: decode_stream INPUT SHA256 grayscale|ycbcr".into()); }
    let color = match args[2].as_str() {
        "grayscale" => ComponentInterpretation::Grayscale,
        "ycbcr" => ComponentInterpretation::YCbCr,
        _ => return Err("explicit grayscale or ycbcr interpretation required".into()),
    };
    let text = &args[1];
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("SHA256 must be 64 lowercase hexadecimal characters".into());
    }
    let mut expected = [0; 32];
    for (i, slot) in expected.iter_mut().enumerate() { *slot = u8::from_str_radix(&text[2*i..2*i+2], 16)?; }
    let maximum = 64 * 1024 * 1024;
    let mut bytes = Vec::new();
    std::fs::File::open(&args[0])?.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > maximum { return Err("input exceeds 64 MiB harness limit".into()); }
    if expected == [0; 32] || ContentDigest::sha256(&bytes).bytes() != expected {
        return Err("source file checksum mismatch".into());
    }
    let mut stream = JpegStream::new(StreamBasis { source: expected, generation: 1 }, FramingLimits::default())?;
    let mut budget = DecodeBudget::new(2_000_000_000);
    let mut offset = 0;
    while offset < bytes.len() {
        let end = (offset + 4096).min(bytes.len());
        let step = stream.push(offset as u64, &bytes[offset..end], &mut budget)?;
        if step.consumed == 0 { return Err("framer made no progress".into()); }
        offset += step.consumed;
        if let Some(frame) = step.frame {
            if frame.ordinal() > 1024 { return Err("input exceeds 1024-frame harness limit".into()); }
            let decoded = frame.decode(color, DecodeLimits::default(), &mut budget)?;
            let receipt = decoded.receipt();
            let encoded = hex(frame.encoded_sha256()); let luma = hex(receipt.luma_sha256);
            println!("{{\"kind\":\"frame\",\"ordinal\":{},\"start\":{},\"end\":{},\"width\":{},\"height\":{},\"encoded_sha256\":\"{}\",\"luma_sha256\":\"{}\"}}",
                frame.ordinal(), frame.byte_range()[0], frame.byte_range()[1],
                decoded.dimensions()[0], decoded.dimensions()[1], encoded, luma);
        }
    }
    let end = stream.finish(&mut budget)?;
    println!("{{\"kind\":\"complete\",\"frames\":{},\"bytes\":{},\"work\":{}}}", end.frames, end.bytes, budget.used());
    Ok(())
}
fn hex(value: [u8; 32]) -> String { value.iter().map(|b| format!("{b:02x}")).collect() }
