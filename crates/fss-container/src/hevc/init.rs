#![forbid(unsafe_code)]
//! HEVC initialization using the existing bounded MP4 box writer.

use super::HevcInitialization;
use crate::{Mp4Error, boxes::Writer};
use fss_packet::hevc::HevcConfiguration;

pub(super) fn build(c: &HevcConfiguration, scale: u32, limit: usize) -> Result<HevcInitialization, Mp4Error> {
    let mut w = Writer::new(limit, 1024.min(limit))?;
    let ftyp = w.start(b"ftyp")?;
    w.put(b"iso6")?; w.u32(1)?; w.put(b"iso6hev1mp41")?; w.end(ftyp)?;
    let moov = w.start(b"moov")?;
    let mvhd = w.full(b"mvhd", 0)?;
    w.zeros(8)?; w.u32(scale)?; w.u32(0)?; w.u32(0x10000)?; w.u16(0x100)?;
    w.zeros(10)?; w.matrix()?; w.zeros(24)?; w.u32(2)?; w.end(mvhd)?;
    let trak = w.start(b"trak")?;
    let tkhd = w.full(b"tkhd", 7)?;
    w.zeros(8)?; w.u32(1)?; w.zeros(16)?; w.zeros(8)?; w.matrix()?;
    let (width, height) = c.display_dimensions();
    w.u32(width << 16)?; w.u32(height << 16)?; w.end(tkhd)?;
    let mdia = w.start(b"mdia")?;
    let mdhd = w.full(b"mdhd", 0)?;
    w.zeros(8)?; w.u32(scale)?; w.u32(0)?; w.u16(0x55c4)?; w.u16(0)?; w.end(mdhd)?;
    let hdlr = w.full(b"hdlr", 0)?;
    w.u32(0)?; w.put(b"vide")?; w.zeros(12)?; w.put(b"FSS video\0")?; w.end(hdlr)?;
    let minf = w.start(b"minf")?;
    let vmhd = w.full(b"vmhd", 1)?; w.zeros(8)?; w.end(vmhd)?;
    let dinf = w.start(b"dinf")?;
    let dref = w.full(b"dref", 0)?; w.u32(1)?;
    let url = w.full(b"url ", 1)?; w.end(url)?; w.end(dref)?; w.end(dinf)?;
    let stbl = w.start(b"stbl")?;
    let stsd = w.full(b"stsd", 0)?; w.u32(1)?;
    let hev1 = w.start(b"hev1")?;
    w.zeros(6)?; w.u16(1)?; w.zeros(16)?;
    w.u16(width as u16)?; w.u16(height as u16)?;
    w.u32(0x00480000)?; w.u32(0x00480000)?; w.u32(0)?; w.u16(1)?;
    w.zeros(32)?; w.u16(0x18)?; w.u16(0xffff)?;
    let hvcc = w.start(b"hvcC")?;
    w.put(&[1])?; w.put(c.profile_tier_level())?;
    // Unknown spatial segmentation, parallelism and frame rate remain unspecified.
    // Chroma/depth/temporal fields come only from the prefix-screened configuration.
    w.u16(0xf000)?; w.put(&[0xfc, 0xfd, 0xf8 | (c.bit_depth() - 8), 0xf8 | (c.bit_depth() - 8)])?;
    w.u16(0)?;
    w.put(&[(c.temporal_layers() << 3) | (u8::from(c.temporal_nested()) << 2) | 3, 3])?;
    let mut ranges = [0..0, 0..0, 0..0];
    for (index, (kind, bytes)) in [(32, c.vps()), (33, c.sps()), (34, c.pps())].into_iter().enumerate() {
        // hev1 permits in-band parameter sets. Do not assert array_completeness.
        w.put(&[kind])?; w.u16(1)?; w.u16(bytes.len() as u16)?;
        let start = w.data.len(); w.put(bytes)?; ranges[index] = start..w.data.len();
    }
    w.end(hvcc)?; w.end(hev1)?; w.end(stsd)?;
    for tag in [b"stts", b"stsc", b"stsz", b"stco"] {
        let empty = w.full(tag, 0)?;
        if tag == b"stsz" { w.u32(0)?; }
        w.u32(0)?; w.end(empty)?;
    }
    w.end(stbl)?; w.end(minf)?; w.end(mdia)?; w.end(trak)?;
    let mvex = w.start(b"mvex")?;
    let trex = w.full(b"trex", 0)?;
    w.u32(1)?; w.u32(1)?; w.zeros(12)?; w.end(trex)?;
    w.end(mvex)?; w.end(moov)?;
    Ok(HevcInitialization { bytes: w.data, parameter_ranges: ranges })
}
