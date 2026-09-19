#![forbid(unsafe_code)]
//! Read-only explicit entity-file harness; HTTP transfer decoding remains upstream.
use fss_codec_mjpeg::multipart::{MultipartFrame, MultipartLimits, MultipartStream};
use fss_codec_mjpeg::stream::StreamBasis;
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeLimits};
use fss_core::ContentDigest;
use std::io::Read;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 4 {
        return Err("usage: decode_multipart INPUT SHA256 CONTENT_TYPE grayscale|ycbcr".into());
    }
    let color = match args[3].as_str() {
        "grayscale" => ComponentInterpretation::Grayscale,
        "ycbcr" => ComponentInterpretation::YCbCr,
        _ => return Err("explicit component interpretation required".into()),
    };
    if args[1].len() != 64
        || !args[1]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("expected lowercase SHA-256".into());
    }
    let mut expected = [0; 32];
    for (i, byte) in expected.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&args[1][i * 2..i * 2 + 2], 16)?;
    }
    let maximum = 64 * 1024 * 1024;
    let mut data = Vec::new();
    std::fs::File::open(&args[0])?
        .take(maximum as u64 + 1)
        .read_to_end(&mut data)?;
    if data.len() > maximum
        || expected == [0; 32]
        || ContentDigest::sha256(&data).bytes() != expected
    {
        return Err("entity size or digest mismatch".into());
    }
    let mut budget = DecodeBudget::new(2_000_000_000);
    let mut stream = MultipartStream::new(
        StreamBasis {
            source: expected,
            generation: 1,
        },
        &args[2],
        MultipartLimits::default(),
        &mut budget,
    )?;
    let mut at = 0;
    while at < data.len() {
        let stop = (at + 4096).min(data.len());
        let step = stream.push(at as u64, &data[at..stop], &mut budget)?;
        if step.consumed == 0 {
            return Err("multipart parser made no progress".into());
        }
        at += step.consumed;
        if let Some(frame) = step.frame {
            emit(&frame, color, &mut budget)?;
        }
    }
    let finish = stream.finish(&mut budget)?;
    if let Some(frame) = finish.frame {
        emit(&frame, color, &mut budget)?;
    }
    println!(
        "{{\"kind\":\"complete\",\"frames\":{},\"bytes\":{},\"preamble_bytes\":{},\"epilogue_bytes\":{}}}",
        finish.end.frames,
        finish.end.bytes,
        finish.end.preamble.bytes().len(),
        finish.end.epilogue.bytes().len()
    );
    Ok(())
}
fn emit(
    frame: &MultipartFrame,
    color: ComponentInterpretation,
    budget: &mut DecodeBudget<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let source = frame.receipt();
    if source.ordinal > 1024 {
        return Err("harness frame ceiling".into());
    }
    let decoded = frame.decode(color, DecodeLimits::default(), budget)?;
    println!(
        "{{\"kind\":\"frame\",\"ordinal\":{},\"start\":{},\"end\":{},\"width\":{},\"height\":{},\"encoded_sha256\":\"{}\",\"luma_sha256\":\"{}\"}}",
        source.ordinal,
        source.jpeg_range[0],
        source.jpeg_range[1],
        decoded.dimensions()[0],
        decoded.dimensions()[1],
        hex(source.encoded_sha256),
        hex(decoded.receipt().luma_sha256)
    );
    Ok(())
}
fn hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
