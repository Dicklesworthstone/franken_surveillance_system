#![forbid(unsafe_code)]
use crate::entropy::{Bits, Huffman, Reader};
use crate::transform::{ZIGZAG, inverse};
use crate::{ComponentInterpretation, DecodeBudget, DecodeError, DecodeLimits};

#[derive(Clone, Copy, Default)]
struct Component {
    id: u8,
    h: usize,
    v: usize,
    quantizer: usize,
}
struct Frame {
    width: usize,
    height: usize,
    count: usize,
    components: [Component; 3],
}
#[derive(Default)]
pub(crate) struct Stats {
    pub mcus: usize,
    pub blocks: usize,
    pub restarts: usize,
    pub metadata_segments: usize,
    pub metadata_bytes: usize,
}
struct Tables {
    quantizers: [Option<[u16; 64]>; 4],
    dc: [Option<Huffman>; 2],
    ac: [Option<Huffman>; 2],
}

#[derive(Clone, Copy)]
pub(crate) enum Reconstruction {
    Luma,
    Rgb { maximum_bytes: usize },
}

pub(crate) fn decode(
    bytes: &[u8],
    interpretation: ComponentInterpretation,
    limits: DecodeLimits,
    budget: &mut DecodeBudget<'_>,
) -> Result<([u32; 2], Vec<u8>, Stats), DecodeError> {
    decode_with_output(bytes, interpretation, limits, Reconstruction::Luma, budget)
}

pub(crate) fn decode_with_output(
    bytes: &[u8],
    interpretation: ComponentInterpretation,
    limits: DecodeLimits,
    output: Reconstruction,
    budget: &mut DecodeBudget<'_>,
) -> Result<([u32; 2], Vec<u8>, Stats), DecodeError> {
    let mut input = Reader { bytes, pos: 0 };
    if input.take(2)? != [255, 216] {
        return Err(DecodeError::Malformed);
    }
    let mut frame: Option<Frame> = None;
    let mut pixels = None;
    let mut tables = Tables {
        quantizers: [None; 4],
        dc: [None, None],
        ac: [None, None],
    };
    let mut restart_interval = 0;
    let mut markers = 1;
    let mut stats = Stats::default();
    loop {
        budget.charge(32)?;
        markers += 1;
        if markers > limits.maximum_markers {
            return Err(DecodeError::Limit);
        }
        let marker = input.marker()?;
        if marker == 0xd9 {
            if input.pos != bytes.len() {
                return Err(DecodeError::Malformed);
            }
            let f = frame.ok_or(DecodeError::Malformed)?;
            return Ok((
                [f.width as u32, f.height as u32],
                pixels.ok_or(DecodeError::Malformed)?,
                stats,
            ));
        }
        if marker == 0xd8 || (0xd0..=0xd7).contains(&marker) || marker == 1 {
            return Err(DecodeError::Malformed);
        }
        let segment = input.segment()?;
        budget.charge(segment.len() as u64)?;
        if (0xe0..=0xef).contains(&marker) || marker == 0xfe {
            check_metadata(marker, segment, interpretation)?;
            stats.metadata_segments += 1;
            stats.metadata_bytes += segment.len();
            continue;
        }
        if pixels.is_some() {
            return Err(DecodeError::Unsupported);
        }
        match marker {
            0xc0 => {
                if frame.is_some() {
                    return Err(DecodeError::Malformed);
                }
                frame = Some(parse_frame(segment, interpretation, limits)?);
            }
            0xdb => quantizers(segment, &mut tables)?,
            0xc4 => huffman(segment, &mut tables)?,
            0xdd => {
                if segment.len() != 2 {
                    return Err(DecodeError::Malformed);
                }
                restart_interval = usize::from(u16::from_be_bytes([segment[0], segment[1]]));
            }
            0xda => {
                let f = frame.as_ref().ok_or(DecodeError::Malformed)?;
                pixels = Some(scan(
                    &mut input,
                    f,
                    segment,
                    &tables,
                    restart_interval,
                    &mut stats,
                    output,
                    budget,
                )?);
            }
            _ => return Err(DecodeError::Unsupported),
        }
    }
}

fn parse_frame(
    data: &[u8],
    interpretation: ComponentInterpretation,
    limits: DecodeLimits,
) -> Result<Frame, DecodeError> {
    if data.len() < 6 {
        return Err(DecodeError::Malformed);
    }
    if data[0] != 8 {
        return Err(DecodeError::Unsupported);
    }
    let height = usize::from(u16::from_be_bytes([data[1], data[2]]));
    let width = usize::from(u16::from_be_bytes([data[3], data[4]]));
    let count = usize::from(data[5]);
    let expected = match interpretation {
        ComponentInterpretation::Grayscale => 1,
        ComponentInterpretation::YCbCr => 3,
    };
    if count != expected {
        return Err(DecodeError::Unsupported);
    }
    if data.len() != 6 + 3 * count {
        return Err(DecodeError::Malformed);
    }
    if height == 0 || width == 0 {
        return Err(DecodeError::Unsupported);
    }
    if height > limits.maximum_dimension as usize
        || width > limits.maximum_dimension as usize
        || width * height > limits.maximum_pixels
    {
        return Err(DecodeError::Limit);
    }
    let mut components = [Component::default(); 3];
    for i in 0..count {
        let p = &data[6 + 3 * i..9 + 3 * i];
        if p[2] > 3 {
            return Err(DecodeError::Malformed);
        }
        components[i] = Component {
            id: p[0],
            h: usize::from(p[1] >> 4),
            v: usize::from(p[1] & 15),
            quantizer: usize::from(p[2]),
        };
    }
    if count == 1 {
        if (components[0].h, components[0].v) != (1, 1) {
            return Err(DecodeError::Unsupported);
        }
    } else {
        for (i, c) in components.iter().enumerate() {
            if c.id != (i + 1) as u8 || (i > 0 && (c.h, c.v) != (1, 1)) {
                return Err(DecodeError::Unsupported);
            }
        }
        if ![(1, 1), (2, 1), (2, 2)].contains(&(components[0].h, components[0].v)) {
            return Err(DecodeError::Unsupported);
        }
    }
    Ok(Frame {
        width,
        height,
        count,
        components,
    })
}

fn quantizers(data: &[u8], tables: &mut Tables) -> Result<(), DecodeError> {
    if data.is_empty() {
        return Err(DecodeError::Malformed);
    }
    let mut input = Reader {
        bytes: data,
        pos: 0,
    };
    while input.pos < data.len() {
        let descriptor = input.byte()?;
        if descriptor >> 4 != 0 {
            return Err(DecodeError::Unsupported);
        }
        let id = usize::from(descriptor & 15);
        if id > 3 {
            return Err(DecodeError::Malformed);
        }
        let values = input.take(64)?;
        let mut table = [0; 64];
        for (i, &value) in values.iter().enumerate() {
            if value == 0 {
                return Err(DecodeError::Malformed);
            }
            table[ZIGZAG[i]] = u16::from(value);
        }
        tables.quantizers[id] = Some(table);
    }
    Ok(())
}
fn huffman(data: &[u8], tables: &mut Tables) -> Result<(), DecodeError> {
    if data.is_empty() {
        return Err(DecodeError::Malformed);
    }
    let mut input = Reader {
        bytes: data,
        pos: 0,
    };
    while input.pos < data.len() {
        let descriptor = input.byte()?;
        let (class, id) = (descriptor >> 4, usize::from(descriptor & 15));
        if class > 1 || id > 1 {
            return Err(DecodeError::Unsupported);
        }
        let counts: [u8; 16] = input
            .take(16)?
            .try_into()
            .map_err(|_| DecodeError::Malformed)?;
        let total = counts.iter().map(|v| usize::from(*v)).sum::<usize>();
        if total > 256 {
            return Err(DecodeError::Malformed);
        }
        let table = Huffman::new(counts, input.take(total)?, class == 1)?;
        if class == 1 {
            tables.ac[id] = Some(table);
        } else {
            tables.dc[id] = Some(table);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn scan(
    input: &mut Reader<'_>,
    frame: &Frame,
    data: &[u8],
    tables: &Tables,
    restart_interval: usize,
    stats: &mut Stats,
    output: Reconstruction,
    budget: &mut DecodeBudget<'_>,
) -> Result<Vec<u8>, DecodeError> {
    if data.is_empty() {
        return Err(DecodeError::Malformed);
    }
    if usize::from(data[0]) != frame.count {
        return Err(DecodeError::Unsupported);
    }
    if data.len() != 4 + 2 * frame.count {
        return Err(DecodeError::Malformed);
    }
    if data[data.len() - 3..] != [0, 63, 0] {
        return Err(DecodeError::Unsupported);
    }
    let mut order = [(0, 0, 0); 3];
    let mut seen = [false; 3];
    for (i, slot) in order.iter_mut().enumerate().take(frame.count) {
        let id = data[1 + 2 * i];
        let selector = data[2 + 2 * i];
        let index = frame.components[..frame.count]
            .iter()
            .position(|c| c.id == id)
            .ok_or(DecodeError::Malformed)?;
        let (dc, ac) = (usize::from(selector >> 4), usize::from(selector & 15));
        if seen[index] {
            return Err(DecodeError::Malformed);
        }
        if dc > 1 || ac > 1 {
            return Err(DecodeError::Unsupported);
        }
        if tables.dc[dc].is_none()
            || tables.ac[ac].is_none()
            || tables.quantizers[frame.components[index].quantizer].is_none()
        {
            return Err(DecodeError::Unsupported);
        }
        seen[index] = true;
        *slot = (index, dc, ac);
    }
    let (h, v) = (frame.components[0].h, frame.components[0].v);
    let columns = frame.width.div_ceil(8 * h);
    let rows = frame.height.div_ceil(8 * v);
    let mcus = columns * rows;
    let rgb = matches!(output, Reconstruction::Rgb { .. });
    let length = frame
        .width
        .checked_mul(frame.height)
        .and_then(|n| n.checked_mul(if rgb { 3 } else { 1 }))
        .ok_or(DecodeError::Limit)?;
    if let Reconstruction::Rgb { maximum_bytes } = output
        && length > maximum_bytes
    {
        return Err(DecodeError::Limit);
    }
    budget.charge(length as u64)?;
    let mut pixels = Vec::new();
    pixels
        .try_reserve_exact(length)
        .map_err(|_| DecodeError::Limit)?;
    pixels.resize(length, 0);
    let mut bits = Bits::new(input);
    let mut predictors = [0_i32; 3];
    let mut restart = 0;
    for mcu in 0..mcus {
        budget.charge(1)?;
        if mcu > 0 && restart_interval != 0 && mcu % restart_interval == 0 {
            bits.restart(restart)?;
            restart = (restart + 1) % 8;
            predictors = [0; 3];
            stats.restarts += 1;
        }
        // Only one MCU of chroma is retained. Component order in SOS need not be Y first.
        let mut tiles = if rgb {
            budget.charge(3 * 256)?;
            Some([[0_u8; 256]; 3])
        } else {
            None
        };
        for &(index, dc, ac) in order.iter().take(frame.count) {
            let component = frame.components[index];
            let dc = tables.dc[dc].as_ref().ok_or(DecodeError::Malformed)?;
            let ac = tables.ac[ac].as_ref().ok_or(DecodeError::Malformed)?;
            let quantizer = tables.quantizers[component.quantizer]
                .as_ref()
                .ok_or(DecodeError::Malformed)?;
            for by in 0..component.v {
                for bx in 0..component.h {
                    budget.charge(4096)?;
                    let coeff = block(&mut bits, dc, ac, quantizer, &mut predictors[index])?;
                    stats.blocks += 1;
                    if index != 0 && !rgb {
                        continue;
                    }
                    // The luma lane retains its original numeric schedule and charges.
                    if index != 0 {
                        budget.charge(4096)?;
                    }
                    let samples = inverse(&coeff);
                    if let Some(tiles) = tiles.as_mut() {
                        budget.charge(64)?;
                        for y in 0..8 {
                            let start = (by * 8 + y) * component.h * 8 + bx * 8;
                            tiles[index][start..start + 8]
                                .copy_from_slice(&samples[y * 8..y * 8 + 8]);
                        }
                        continue;
                    }
                    let ox = (mcu % columns) * h * 8 + bx * 8;
                    let oy = (mcu / columns) * v * 8 + by * 8;
                    for y in 0..8 {
                        for x in 0..8 {
                            if oy + y < frame.height && ox + x < frame.width {
                                pixels[(oy + y) * frame.width + ox + x] = samples[y * 8 + x];
                            }
                        }
                    }
                }
            }
        }
        if let Some(tiles) = tiles {
            budget.charge((h * v * 64 * 24) as u64)?;
            let ox = (mcu % columns) * h * 8;
            let oy = (mcu / columns) * v * 8;
            for y in 0..v * 8 {
                for x in 0..h * 8 {
                    if ox + x >= frame.width || oy + y >= frame.height {
                        continue;
                    }
                    let luma = tiles[0][y * h * 8 + x];
                    let color = if frame.count == 1 {
                        [luma; 3]
                    } else {
                        // Explicit nearest-cell chroma reconstruction, not fancy upsampling.
                        let chroma = (y / v) * 8 + x / h;
                        crate::color::ycbcr_to_rgb(luma, tiles[1][chroma], tiles[2][chroma])
                    };
                    let to = ((oy + y) * frame.width + ox + x) * 3;
                    pixels[to..to + 3].copy_from_slice(&color);
                }
            }
        }
    }
    bits.align()?;
    stats.mcus = mcus;
    Ok(pixels)
}
fn block(
    bits: &mut Bits<'_, '_>,
    dc: &Huffman,
    ac: &Huffman,
    quantizer: &[u16; 64],
    predictor: &mut i32,
) -> Result<[i32; 64], DecodeError> {
    let size = dc.symbol(bits)?;
    let value = predictor
        .checked_add(bits.signed(size)?)
        .ok_or(DecodeError::Limit)?;
    // This deliberately wider-than-normal 8-bit DC bound keeps every Q14 sum in i64.
    if !(-2048..=2047).contains(&value) {
        return Err(DecodeError::Limit);
    }
    *predictor = value;
    let mut coefficients = [0_i32; 64];
    coefficients[0] = value * i32::from(quantizer[0]);
    let mut k = 1;
    while k < 64 {
        let symbol = ac.symbol(bits)?;
        let (run, size) = (usize::from(symbol >> 4), symbol & 15);
        if size == 0 {
            if run == 0 {
                break;
            }
            if run != 15 || k + 16 > 64 {
                return Err(DecodeError::Malformed);
            }
            k += 16;
            continue;
        }
        k += run;
        if k >= 64 {
            return Err(DecodeError::Malformed);
        }
        let index = ZIGZAG[k];
        coefficients[index] = bits.signed(size)? * i32::from(quantizer[index]);
        k += 1;
    }
    Ok(coefficients)
}

fn check_metadata(
    marker: u8,
    data: &[u8],
    interpretation: ComponentInterpretation,
) -> Result<(), DecodeError> {
    if marker == 0xe0
        && data.starts_with(b"JFIF\0")
        && (data.len() < 14
            || data[5] != 1
            || data[7] > 2
            || data.len() != 14 + 3 * usize::from(data[12]) * usize::from(data[13]))
    {
        return Err(DecodeError::Malformed);
    }
    if marker == 0xee && data.starts_with(b"Adobe") {
        if data.len() != 12 {
            return Err(DecodeError::Malformed);
        }
        let expected = match interpretation {
            ComponentInterpretation::Grayscale => 0,
            ComponentInterpretation::YCbCr => 1,
        };
        if data[11] != expected {
            return Err(DecodeError::Unsupported);
        }
    }
    Ok(())
}
