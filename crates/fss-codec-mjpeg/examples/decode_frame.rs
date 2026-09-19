#![forbid(unsafe_code)]
//! Owner-run file harness; no camera, timestamp, custody or public fss/1 authority.
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeLimits, decode_luma};
use std::io::{Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !(3..=4).contains(&args.len()) || (args.len() == 4 && args[3] != "--raw") {
        return Err("usage: decode_frame INPUT SHA256 grayscale|ycbcr [--raw]".into());
    }
    let color = match args[2].as_str() {
        "grayscale" => ComponentInterpretation::Grayscale,
        "ycbcr" => ComponentInterpretation::YCbCr,
        _ => return Err("explicit grayscale or ycbcr interpretation required".into()),
    };
    let text = &args[1];
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("SHA256 must be 64 lowercase hexadecimal characters".into());
    }
    let mut digest = [0; 32];
    for (i, slot) in digest.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&text[2 * i..2 * i + 2], 16)?;
    }
    let limit = DecodeLimits::default();
    let mut bytes = Vec::new();
    std::fs::File::open(&args[0])?
        .take(limit.maximum_bytes as u64 + 1)
        .read_to_end(&mut bytes)?;
    let mut budget = DecodeBudget::new(1_000_000_000);
    let frame = decode_luma(&bytes, digest, color, limit, &mut budget)?;
    if args.len() == 4 {
        std::io::stdout().lock().write_all(frame.pixels())?;
    } else {
        let receipt = frame.receipt();
        let digest = receipt
            .luma_sha256
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        println!(
            "{{\"width\":{},\"height\":{},\"luma_sha256\":\"{}\",\"mcus\":{},\"blocks\":{},\"restarts\":{},\"work\":{}}}",
            frame.dimensions()[0],
            frame.dimensions()[1],
            digest,
            receipt.mcus,
            receipt.entropy_blocks,
            receipt.restarts,
            budget.used()
        );
    }
    Ok(())
}
