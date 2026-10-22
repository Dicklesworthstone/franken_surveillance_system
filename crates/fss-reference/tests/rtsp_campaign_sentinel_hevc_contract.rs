#![forbid(unsafe_code)]
//! Current native RTSP recording admission excludes CRA/RASL before campaign catalogs exist.
//! The broader HEVC decoder can skip RASL; the campaign's complete-count guard is conservative.

#[path = "hevc_recording_support/mod.rs"]
mod hevc;

use fss_codec_h265::{Decoder, DecoderLimits, annex_b_nal_units};
use fss_container::Mp4Error;
use fss_packet::hevc::{HevcConfiguration, HevcConfigurationLimits};
use fss_reference::rtsp::recording::RecordingError;
use fss_reference::rtsp::recording::hevc::prepare_hevc_recording;

#[test]
fn real_cra_rasl_source_is_refused_before_native_rtsp_catalog_admission() -> Result<(), hevc::Error>
{
    let nals = annex_b_nal_units(include_bytes!(
        "../../fss-codec-h265/tests/fixtures/decode/b_qcif_opengop.h265"
    ))
    .collect::<Vec<_>>();
    let selected = nals.get(8..13).ok_or("CRA/RASL fixture NALs")?;
    assert_eq!(
        selected
            .iter()
            .map(|nal| (nal[0] >> 1) & 63)
            .collect::<Vec<_>>(),
        [32, 33, 34, 21, 8]
    );
    let configuration = HevcConfiguration::parse(
        selected[0],
        selected[1],
        selected[2],
        HevcConfigurationLimits::default(),
    )?;

    // The unmodified fixture is valid HEVC: native decoding returns CRA and skips RASL.
    let mut decoder = Decoder::new(DecoderLimits::default())?;
    let mut pictures = Vec::new();
    for nal in selected {
        if let Some(picture) = decoder.decode_nal(nal)? {
            pictures.push(picture);
        }
        while let Some(picture) = decoder.next_output() {
            pictures.push(picture);
        }
    }
    pictures.extend(decoder.finish()?);
    assert_eq!(pictures.len(), 1);
    assert_eq!(pictures[0].nal_unit_type(), 21);

    let mut packets = selected
        .iter()
        .enumerate()
        .map(|(index, nal)| {
            hevc::packet(
                65_533 + index as u64,
                if index == 4 { 18_000 } else { 0 },
                true,
                nal,
            )
        })
        .collect::<Vec<_>>();
    // Explicit source EOS closes the second AU; truncated RTP cannot explain the refusal.
    packets.push(hevc::packet(65_538, 18_000, true, &[0x48, 1, 0x80]));
    let result = prepare_hevc_recording(
        hevc::scope()?,
        &configuration,
        90_000,
        &hevc::timings(2),
        &hevc::borrowed(&packets),
    );
    assert!(
        matches!(
            &result,
            Err(RecordingError::Media(Mp4Error::RandomAccessRequired))
        ),
        "unexpected native source admission: {result:?}"
    );
    Ok(())
}
