#![forbid(unsafe_code)]
//! Source-bound JPEG snapshots from native decoded video pictures.

use std::sync::atomic::AtomicBool;

use fss_codec_h264::{Decoder, DecoderLimits, Picture};
use fss_codec_jpeg_encode::{EncodeLimits, PixelFormat};
use fss_codec_mjpeg::{
    ComponentInterpretation, DecodeBudget,
    color::{RgbDecodeLimits, decode_rgb},
};
use fss_reference::unifi_direct::video_still::{self, Color, Error};

fn picture() -> Result<Picture, Box<dyn std::error::Error>> {
    let mut decoder = Decoder::new(DecoderLimits::default())?;
    let mut frames = decoder.decode_annex_b(include_bytes!(
        "../../fss-packet/tests/fixtures/avc/baseline.264"
    ))?;
    frames.extend(decoder.finish()?);
    frames
        .into_iter()
        .next()
        .ok_or_else(|| "fixture has no frame".into())
}

#[test]
fn decoded_picture_produces_full_size_source_bound_jpeg() -> Result<(), Box<dyn std::error::Error>>
{
    let picture = picture()?;
    let source = picture.i420_sha256();
    let limits = EncodeLimits::default();
    let still = video_still::from_picture(
        &picture,
        source,
        Color::Bt601Full,
        95,
        &limits,
        u64::from(picture.width()) * u64::from(picture.height()),
        limits.work_bound(PixelFormat::Rgb),
        &AtomicBool::new(false),
    )?;
    assert_eq!(still.source_i420_sha256(), source);
    assert_eq!(still.color(), Color::Bt601Full);
    let limited = video_still::from_picture(
        &picture,
        source,
        Color::Bt601Limited,
        95,
        &limits,
        u64::from(picture.width()) * u64::from(picture.height()),
        limits.work_bound(PixelFormat::Rgb),
        &AtomicBool::new(false),
    )?;
    assert_ne!(still.identity(), limited.identity());
    let receipt = still.jpeg().receipt();
    assert_eq!(receipt.dimensions, [picture.width(), picture.height()]);
    assert_eq!(receipt.format, PixelFormat::Rgb);
    let decoded = decode_rgb(
        still.jpeg().bytes(),
        receipt.encoded_sha256,
        ComponentInterpretation::YCbCr,
        RgbDecodeLimits::default(),
        &mut DecodeBudget::new(u64::MAX),
    )?;
    assert_eq!(decoded.dimensions(), [picture.width(), picture.height()]);
    assert_eq!(
        decoded.pixels().len(),
        picture.width() as usize * picture.height() as usize * 3
    );
    Ok(())
}

#[test]
#[ignore = "requires the owner-supplied private G4 high-profile MP4 on stdin"]
fn private_g4_2k_video_frame_yields_native_jpeg() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Read;
    let mut input = Vec::new();
    std::io::stdin()
        .lock()
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut input)?;
    if input.is_empty() || input.len() > 16 * 1024 * 1024 {
        return Err("private MP4 input bound".into());
    }
    let movie = fss_container::demux::AvcMp4::parse(
        &input,
        None,
        fss_container::demux::DemuxLimits::default(),
    )?;
    let annex = movie.annex_b(0, 1)?;
    let mut decoder = Decoder::new(DecoderLimits::default())?;
    let mut frames = decoder.decode_annex_b(annex.bytes())?;
    frames.extend(decoder.finish()?);
    let frame = frames
        .into_iter()
        .next()
        .ok_or("private input produced no first picture")?;
    if (frame.width(), frame.height()) != (2688, 1512) {
        return Err("private image dimensions differ".into());
    }
    let limits = EncodeLimits::default();
    let still = video_still::from_picture(
        &frame,
        frame.i420_sha256(),
        Color::Bt601Full,
        90,
        &limits,
        u64::from(frame.width()) * u64::from(frame.height()),
        limits.work_bound(PixelFormat::Rgb),
        &AtomicBool::new(false),
    )?;
    let receipt = still.jpeg().receipt();
    let decoded = decode_rgb(
        still.jpeg().bytes(),
        receipt.encoded_sha256,
        ComponentInterpretation::YCbCr,
        RgbDecodeLimits::default(),
        &mut DecodeBudget::new(u64::MAX),
    )?;
    if decoded.dimensions() != [2688, 1512] {
        return Err("native JPEG decoded dimensions differ".into());
    }
    println!(
        "private_g4_still=passed width=2688 height=1512 matrix=bt601_full_declared jpeg_bytes={} source=previously_saved_g4_clip controller=not_contacted",
        still.jpeg().bytes().len()
    );
    Ok(())
}

#[test]
fn still_refuses_wrong_source_cancel_and_work_exhaustion() -> Result<(), Box<dyn std::error::Error>>
{
    let picture = picture()?;
    let limits = EncodeLimits::default();
    let pixels = u64::from(picture.width()) * u64::from(picture.height());
    let encode = limits.work_bound(PixelFormat::Rgb);
    let call = |source, pixel_work, encode_work, stop: &AtomicBool| {
        video_still::from_picture(
            &picture,
            source,
            Color::Bt601Limited,
            90,
            &limits,
            pixel_work,
            encode_work,
            stop,
        )
    };
    assert!(matches!(
        call([1; 32], pixels, encode, &AtomicBool::new(false)),
        Err(Error::SourceMismatch)
    ));
    assert!(matches!(
        call(
            picture.i420_sha256(),
            pixels - 1,
            encode,
            &AtomicBool::new(false)
        ),
        Err(Error::WorkLimit)
    ));
    assert!(matches!(
        call(
            picture.i420_sha256(),
            pixels,
            encode,
            &AtomicBool::new(true)
        ),
        Err(Error::Cancelled)
    ));
    assert!(matches!(
        call(picture.i420_sha256(), pixels, 0, &AtomicBool::new(false)),
        Err(Error::Encode(_))
    ));
    let probes = std::sync::atomic::AtomicUsize::new(0);
    let cancel_midway = || probes.fetch_add(1, std::sync::atomic::Ordering::Relaxed) >= 4;
    assert!(matches!(
        video_still::from_picture_with_probe(
            &picture,
            picture.i420_sha256(),
            Color::Bt601Full,
            90,
            &limits,
            pixels,
            encode,
            &cancel_midway,
        ),
        Err(Error::Cancelled)
    ));
    Ok(())
}
