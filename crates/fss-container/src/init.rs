use crate::{Mp4Error, boxes::Writer, mux::InitializationSegment};
use fss_packet::avc::{AvcPps, AvcSps};
use fss_packet::extended_flv::aac::Configuration as AacConfiguration;
use std::ops::Range;

pub(crate) fn build(
    sps: &AvcSps,
    pps: &AvcPps,
    scale: u32,
    limit: usize,
) -> Result<InitializationSegment, Mp4Error> {
    Ok(build_inner(sps, pps, scale, limit, None)?.0)
}

pub(crate) fn build_av(
    sps: &AvcSps,
    pps: &AvcPps,
    scale: u32,
    limit: usize,
    audio: &AacConfiguration<'_>,
) -> Result<(InitializationSegment, Range<usize>), Mp4Error> {
    let (video, range) = build_inner(sps, pps, scale, limit, Some(audio))?;
    Ok((video, range.ok_or(Mp4Error::Layout)?))
}

fn build_inner(
    sps: &AvcSps,
    pps: &AvcPps,
    scale: u32,
    limit: usize,
    audio: Option<&AacConfiguration<'_>>,
) -> Result<(InitializationSegment, Option<Range<usize>>), Mp4Error> {
    let mut w = Writer::new(limit, 1024.min(limit))?;
    let ftyp = w.start(b"ftyp")?;
    w.put(b"iso6")?;
    w.u32(1)?;
    w.put(b"iso6avc1mp41")?;
    w.end(ftyp)?;
    let moov = w.start(b"moov")?;
    let mvhd = w.full(b"mvhd", 0)?;
    w.zeros(8)?;
    w.u32(scale)?;
    w.u32(0)?;
    w.u32(0x10000)?;
    w.u16(0x100)?;
    w.zeros(10)?;
    w.matrix()?;
    w.zeros(24)?;
    w.u32(if audio.is_some() { 3 } else { 2 })?;
    w.end(mvhd)?;
    let trak = w.start(b"trak")?;
    let tkhd = w.full(b"tkhd", 7)?;
    w.zeros(8)?;
    w.u32(1)?;
    w.zeros(16)?;
    w.zeros(8)?;
    w.matrix()?;
    let (width, height) = sps.display_dimensions();
    w.u32(width << 16)?;
    w.u32(height << 16)?;
    w.end(tkhd)?;
    let mdia = w.start(b"mdia")?;
    let mdhd = w.full(b"mdhd", 0)?;
    w.zeros(8)?;
    w.u32(scale)?;
    w.u32(0)?;
    w.u16(0x55c4)?;
    w.u16(0)?;
    w.end(mdhd)?;
    let hdlr = w.full(b"hdlr", 0)?;
    w.u32(0)?;
    w.put(b"vide")?;
    w.zeros(12)?;
    w.put(b"FSS video\0")?;
    w.end(hdlr)?;
    let minf = w.start(b"minf")?;
    let vmhd = w.full(b"vmhd", 1)?;
    w.zeros(8)?;
    w.end(vmhd)?;
    let dinf = w.start(b"dinf")?;
    let dref = w.full(b"dref", 0)?;
    w.u32(1)?;
    let url = w.full(b"url ", 1)?;
    w.end(url)?;
    w.end(dref)?;
    w.end(dinf)?;
    let stbl = w.start(b"stbl")?;
    let stsd = w.full(b"stsd", 0)?;
    w.u32(1)?;
    let avc1 = w.start(b"avc1")?;
    w.zeros(6)?;
    w.u16(1)?;
    w.zeros(16)?;
    w.u16(width as u16)?;
    w.u16(height as u16)?;
    w.u32(0x00480000)?;
    w.u32(0x00480000)?;
    w.u32(0)?;
    w.u16(1)?;
    w.zeros(32)?;
    w.u16(0x18)?;
    w.u16(0xffff)?;
    let avcc = w.start(b"avcC")?;
    w.put(&[
        1,
        sps.profile_idc(),
        sps.constraint_flags(),
        sps.level_idc(),
        0xff,
        0xe1,
    ])?;
    w.u16(sps.nal_bytes().len() as u16)?;
    let sps_start = w.data.len();
    w.put(sps.nal_bytes())?;
    let sps_range = sps_start..w.data.len();
    w.put(&[1])?;
    w.u16(pps.nal_bytes().len() as u16)?;
    let pps_start = w.data.len();
    w.put(pps.nal_bytes())?;
    let pps_range = pps_start..w.data.len();
    if sps.profile_idc() == 100 {
        w.put(&[0xfd, 0xf8, 0xf8, 0])?;
    }
    w.end(avcc)?;
    w.end(avc1)?;
    w.end(stsd)?;
    for tag in [b"stts", b"stsc", b"stsz", b"stco"] {
        let empty = w.full(tag, 0)?;
        if tag == b"stsz" {
            w.u32(0)?;
        }
        w.u32(0)?;
        w.end(empty)?;
    }
    w.end(stbl)?;
    w.end(minf)?;
    w.end(mdia)?;
    w.end(trak)?;
    let audio_range = audio
        .map(|config| audio_track(&mut w, config))
        .transpose()?;
    let mvex = w.start(b"mvex")?;
    let trex = w.full(b"trex", 0)?;
    w.u32(1)?;
    w.u32(1)?;
    w.zeros(12)?;
    w.end(trex)?;
    if audio.is_some() {
        let trex = w.full(b"trex", 0)?;
        w.u32(2)?;
        w.u32(1)?;
        w.zeros(12)?;
        w.end(trex)?;
    }
    w.end(mvex)?;
    w.end(moov)?;
    Ok((
        InitializationSegment {
            bytes: w.data,
            sps_range,
            pps_range,
        },
        audio_range,
    ))
}

fn audio_track(w: &mut Writer, config: &AacConfiguration<'_>) -> Result<Range<usize>, Mp4Error> {
    let rate = config.sample_rate();
    if rate > u16::MAX as u32 || config.frame_samples() != 1024 {
        return Err(Mp4Error::UnsupportedFormat);
    }
    let trak = w.start(b"trak")?;
    let tkhd = w.full(b"tkhd", 7)?;
    w.zeros(8)?;
    w.u32(2)?;
    w.zeros(16)?;
    w.u16(0)?;
    w.u16(0)?;
    w.u16(0x100)?;
    w.u16(0)?;
    w.matrix()?;
    w.zeros(8)?;
    w.end(tkhd)?;
    let mdia = w.start(b"mdia")?;
    let mdhd = w.full(b"mdhd", 0)?;
    w.zeros(8)?;
    w.u32(rate)?;
    w.u32(0)?;
    w.u16(0x55c4)?;
    w.u16(0)?;
    w.end(mdhd)?;
    let hdlr = w.full(b"hdlr", 0)?;
    w.u32(0)?;
    w.put(b"soun")?;
    w.zeros(12)?;
    w.put(b"FSS audio\0")?;
    w.end(hdlr)?;
    let minf = w.start(b"minf")?;
    let smhd = w.full(b"smhd", 0)?;
    w.u32(0)?;
    w.end(smhd)?;
    let dinf = w.start(b"dinf")?;
    let dref = w.full(b"dref", 0)?;
    w.u32(1)?;
    let url = w.full(b"url ", 1)?;
    w.end(url)?;
    w.end(dref)?;
    w.end(dinf)?;
    let stbl = w.start(b"stbl")?;
    let stsd = w.full(b"stsd", 0)?;
    w.u32(1)?;
    let mp4a = w.start(b"mp4a")?;
    w.zeros(6)?;
    w.u16(1)?;
    w.zeros(8)?;
    w.u16(u16::from(config.channels()))?;
    w.u16(16)?;
    w.zeros(4)?;
    w.u32(rate << 16)?;
    let esds = w.full(b"esds", 0)?;
    // ISO MPEG-4 ES descriptor, DecoderConfigDescriptor, and SLConfigDescriptor.
    let config_len = u8::try_from(config.bytes().len()).map_err(|_| Mp4Error::Layout)?;
    let decoder_len = 0x0f_u8.checked_add(config_len).ok_or(Mp4Error::Layout)?;
    let es_len = 0x17_u8.checked_add(config_len).ok_or(Mp4Error::Layout)?;
    w.put(&[0x03, es_len, 0, 2, 0, 0x04, decoder_len, 0x40, 0x15])?;
    w.zeros(11)?;
    w.put(&[0x05, config_len])?;
    let begin = w.data.len();
    w.put(config.bytes())?;
    let range = begin..w.data.len();
    w.put(&[0x06, 0x01, 0x02])?;
    w.end(esds)?;
    w.end(mp4a)?;
    w.end(stsd)?;
    for tag in [b"stts", b"stsc", b"stsz", b"stco"] {
        let empty = w.full(tag, 0)?;
        if tag == b"stsz" {
            w.u32(0)?;
        }
        w.u32(0)?;
        w.end(empty)?;
    }
    w.end(stbl)?;
    w.end(minf)?;
    w.end(mdia)?;
    w.end(trak)?;
    Ok(range)
}
