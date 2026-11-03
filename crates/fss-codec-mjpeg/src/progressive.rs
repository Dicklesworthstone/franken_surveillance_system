#![forbid(unsafe_code)]
//! Eight-bit Huffman progressive DCT (T.81, Annex G). No speculative pixels are published.
//!
//! Coefficients remain quantized until every scan and the exact EOI have validated. The baseline
//! parser, entropy decoder, numeric transform, and charge schedule are separate and unchanged.

use crate::color::{DecodedRgb, MAX_RGB_BYTES, RgbDecodeLimits, RgbDecodeReceipt, ycbcr_to_rgb};
use crate::entropy::{Bits, Reader};
use crate::image::{Reconstruction, Stats};
use crate::transform::{ZIGZAG, inverse};
use crate::{
    ComponentInterpretation, DecodeBudget, DecodeError, DecodeLimits, DecodeReceipt, DecodedLuma,
};
use fss_core::ContentDigest;

pub(crate) const MAX_SCANS: usize = 256;
const MAX_COEFFICIENT_BYTES: usize = 32 * 1024 * 1024;

pub(crate) fn profile_bytes() -> usize {
    include_bytes!("progressive.rs").len()
        + include_bytes!("entropy.rs").len()
        + include_bytes!("transform.rs").len()
        + include_bytes!("lib.rs").len()
        + include_bytes!("color.rs").len()
}

pub(crate) fn identity(rgb: bool) -> [u8; 32] {
    let label = if rgb {
        b"fss/jpeg-progressive/rgb/1;nearest-chroma;q16-half-up;rgb-hwc".as_slice()
    } else {
        b"fss/jpeg-progressive/luma/1;quantized-i16;fixed-q14-idct".as_slice()
    };
    let mut preimage = [0; 192];
    preimage[..32].copy_from_slice(&ContentDigest::sha256(label).bytes());
    for (i, source) in [
        include_bytes!("progressive.rs").as_slice(),
        include_bytes!("entropy.rs").as_slice(),
        include_bytes!("transform.rs").as_slice(),
        include_bytes!("lib.rs").as_slice(),
        include_bytes!("color.rs").as_slice(),
    ]
    .into_iter()
    .enumerate()
    {
        preimage[(i + 1) * 32..(i + 2) * 32]
            .copy_from_slice(&ContentDigest::sha256(source).bytes());
    }
    ContentDigest::sha256(&preimage).bytes()
}

/// The prefix probe is bounded even before caller limits/source verification. Its work fits the
/// input-length charge made by either decoder. Never search marker-looking bytes inside APP data.
pub(crate) fn is_progressive(bytes: &[u8]) -> bool {
    if bytes.len() > 16 * 1024 * 1024 {
        return false;
    }
    let mut r = Reader { bytes, pos: 0 };
    if r.take(2) != Ok([255, 216].as_slice()) {
        return false;
    }
    for _ in 1..4096 {
        let Ok(marker) = r.marker() else {
            return false;
        };
        if marker == 0xc2 {
            return true;
        }
        if marker == 0xda
            || marker == 0xd9
            || marker == 0xd8
            || marker == 1
            || (0xd0..=0xd7).contains(&marker)
            || (0xc0..=0xcf).contains(&marker) && ![0xc4, 0xc8, 0xcc].contains(&marker)
        {
            return false;
        }
        if r.segment().is_err() {
            return false;
        }
    }
    false
}

fn validate(
    bytes: &[u8],
    expected: [u8; 32],
    limits: DecodeLimits,
    budget: &mut DecodeBudget<'_>,
) -> Result<(), DecodeError> {
    budget.charge(0)?;
    if limits.maximum_bytes == 0
        || limits.maximum_bytes > 16 * 1024 * 1024
        || limits.maximum_dimension == 0
        || limits.maximum_dimension > 4096
        || limits.maximum_pixels == 0
        || limits.maximum_pixels > 4_194_304
        || limits.maximum_markers == 0
        || limits.maximum_markers > 4096
        || bytes.len() > limits.maximum_bytes
    {
        return Err(DecodeError::Limit);
    }
    budget.charge(bytes.len() as u64)?;
    if expected == [0; 32] || ContentDigest::sha256(bytes).bytes() != expected {
        return Err(DecodeError::SourceMismatch);
    }
    Ok(())
}

pub(crate) fn decode_luma(
    bytes: &[u8],
    expected: [u8; 32],
    interpretation: ComponentInterpretation,
    limits: DecodeLimits,
    budget: &mut DecodeBudget<'_>,
) -> Result<DecodedLuma, DecodeError> {
    validate(bytes, expected, limits, budget)?;
    let (dimensions, pixels, stats) =
        decode(bytes, interpretation, limits, Reconstruction::Luma, budget)?;
    budget.charge(pixels.len() as u64 + profile_bytes() as u64 + 2048)?;
    let receipt = DecodeReceipt {
        encoded_sha256: expected,
        luma_sha256: ContentDigest::sha256(&pixels).bytes(),
        decoder: identity(false),
        interpretation,
        mcus: stats.mcus,
        entropy_blocks: stats.blocks,
        restarts: stats.restarts,
        metadata_segments: stats.metadata_segments,
        metadata_bytes: stats.metadata_bytes,
    };
    budget.charge(0)?;
    Ok(DecodedLuma {
        dimensions,
        pixels,
        receipt,
    })
}

pub(crate) fn decode_rgb(
    bytes: &[u8],
    expected: [u8; 32],
    interpretation: ComponentInterpretation,
    limits: RgbDecodeLimits,
    budget: &mut DecodeBudget<'_>,
) -> Result<DecodedRgb, DecodeError> {
    budget.charge(0)?;
    if limits.maximum_output_bytes == 0 || limits.maximum_output_bytes > MAX_RGB_BYTES {
        return Err(DecodeError::Limit);
    }
    validate(bytes, expected, limits.frame, budget)?;
    let (dimensions, pixels, stats) = decode(
        bytes,
        interpretation,
        limits.frame,
        Reconstruction::Rgb {
            maximum_bytes: limits.maximum_output_bytes,
        },
        budget,
    )?;
    budget.charge(pixels.len() as u64 + profile_bytes() as u64 + 2048)?;
    let receipt = RgbDecodeReceipt {
        encoded_sha256: expected,
        rgb_sha256: ContentDigest::sha256(&pixels).bytes(),
        decoder: identity(true),
        interpretation,
        dimensions,
        mcus: stats.mcus,
        entropy_blocks: stats.blocks,
        restarts: stats.restarts,
        metadata_segments: stats.metadata_segments,
        metadata_bytes: stats.metadata_bytes,
    };
    budget.charge(0)?;
    Ok(DecodedRgb { pixels, receipt })
}

struct Component {
    id: u8,
    h: usize,
    v: usize,
    quantizer_id: usize,
    quantizer: Option<[u16; 64]>,
    columns: usize,
    actual_columns: usize,
    actual_rows: usize,
    coefficients: Vec<[i16; 64]>,
    // None means this spectral position has not been transmitted. Otherwise the value is Al.
    approximation: [Option<u8>; 64],
}

impl Default for Component {
    fn default() -> Self {
        Self {
            id: 0,
            h: 0,
            v: 0,
            quantizer_id: 0,
            quantizer: None,
            columns: 0,
            actual_columns: 0,
            actual_rows: 0,
            coefficients: Vec::new(),
            approximation: [None; 64],
        }
    }
}

struct Frame {
    width: usize,
    height: usize,
    h: usize,
    v: usize,
    columns: usize,
    rows: usize,
    count: usize,
    components: [Component; 3],
}

impl Frame {
    fn parse(
        data: &[u8],
        interpretation: ComponentInterpretation,
        limits: DecodeLimits,
        output: Reconstruction,
        budget: &mut DecodeBudget<'_>,
    ) -> Result<Self, DecodeError> {
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
        if width == 0 || height == 0 {
            return Err(DecodeError::Unsupported);
        }
        if width > limits.maximum_dimension as usize
            || height > limits.maximum_dimension as usize
            || width * height > limits.maximum_pixels
        {
            return Err(DecodeError::Limit);
        }
        if let Reconstruction::Rgb { maximum_bytes } = output
            && width * height * 3 > maximum_bytes
        {
            return Err(DecodeError::Limit);
        }
        let mut components: [Component; 3] = std::array::from_fn(|_| Component::default());
        for (i, c) in components.iter_mut().enumerate().take(count) {
            let p = &data[6 + i * 3..9 + i * 3];
            if p[2] > 3 {
                return Err(DecodeError::Malformed);
            }
            c.id = p[0];
            c.h = usize::from(p[1] >> 4);
            c.v = usize::from(p[1] & 15);
            c.quantizer_id = usize::from(p[2]);
            if count == 1 {
                if (c.h, c.v) != (1, 1) {
                    return Err(DecodeError::Unsupported);
                }
            } else if c.id != (i + 1) as u8
                || (i == 0 && ![(1, 1), (2, 1), (2, 2)].contains(&(c.h, c.v)))
                || (i > 0 && (c.h, c.v) != (1, 1))
            {
                return Err(DecodeError::Unsupported);
            }
        }
        let (h, v) = (components[0].h, components[0].v);
        let (columns, rows) = (width.div_ceil(8 * h), height.div_ceil(8 * v));
        let mut allocation = 0_usize;
        for c in &mut components[..count] {
            c.columns = columns * c.h;
            c.actual_columns = (width * c.h).div_ceil(8 * h);
            c.actual_rows = (height * c.v).div_ceil(8 * v);
            let blocks = c.columns * rows * c.v;
            allocation = allocation
                .checked_add(blocks * 128)
                .ok_or(DecodeError::Limit)?;
            if allocation > MAX_COEFFICIENT_BYTES {
                return Err(DecodeError::Limit);
            }
            budget.charge((blocks * 128) as u64)?;
            c.coefficients
                .try_reserve_exact(blocks)
                .map_err(|_| DecodeError::Limit)?;
            c.coefficients.resize(blocks, [0; 64]);
        }
        Ok(Self {
            width,
            height,
            h,
            v,
            columns,
            rows,
            count,
            components,
        })
    }
}

// Progressive AC tables permit EOB-run symbols 0x10 through 0xe0. Keeping this table distinct
// preserves the stricter v1 baseline table grammar (and its retained refusal classifications).
struct ScanTable {
    counts: [u8; 16],
    first: [u32; 16],
    offsets: [usize; 16],
    values: [u8; 256],
}

impl ScanTable {
    fn new(counts: [u8; 16], values: &[u8], ac: bool) -> Result<Self, DecodeError> {
        let total = counts.iter().map(|&n| usize::from(n)).sum::<usize>();
        if total == 0 || total > 256 || total != values.len() {
            return Err(DecodeError::Malformed);
        }
        let mut seen = [false; 256];
        for &value in values {
            if seen[usize::from(value)] || if ac { value & 15 > 10 } else { value > 11 } {
                return Err(DecodeError::Malformed);
            }
            seen[usize::from(value)] = true;
        }
        let mut table = Self {
            counts,
            first: [0; 16],
            offsets: [0; 16],
            values: [0; 256],
        };
        let mut next = 0;
        let mut offset = 0;
        for (depth, &count) in counts.iter().enumerate() {
            if next + u32::from(count) >= 1 << (depth + 1) {
                return Err(DecodeError::Malformed);
            }
            table.first[depth] = next;
            table.offsets[depth] = offset;
            offset += usize::from(count);
            next = (next + u32::from(count)) << 1;
        }
        table.values[..values.len()].copy_from_slice(values);
        Ok(table)
    }

    fn symbol(&self, bits: &mut Bits<'_, '_>) -> Result<u8, DecodeError> {
        let mut code = 0;
        for depth in 0..16 {
            code = (code << 1) | bits.read(1)?;
            if let Some(index) = code.checked_sub(self.first[depth])
                && index < u32::from(self.counts[depth])
            {
                return Ok(self.values[self.offsets[depth] + index as usize]);
            }
        }
        Err(DecodeError::Malformed)
    }
}

struct Tables {
    quantizers: [Option<[u16; 64]>; 4],
    dc: [Option<ScanTable>; 4],
    ac: [Option<ScanTable>; 4],
}

impl Tables {
    fn new() -> Self {
        Self {
            quantizers: [None; 4],
            dc: std::array::from_fn(|_| None),
            ac: std::array::from_fn(|_| None),
        }
    }

    fn quantizers(&mut self, data: &[u8], frame: Option<&Frame>) -> Result<(), DecodeError> {
        if data.is_empty() {
            return Err(DecodeError::Malformed);
        }
        let mut r = Reader {
            bytes: data,
            pos: 0,
        };
        while r.pos < data.len() {
            let descriptor = r.byte()?;
            if descriptor >> 4 != 0 {
                return Err(DecodeError::Unsupported);
            }
            let id = usize::from(descriptor & 15);
            if id > 3 {
                return Err(DecodeError::Malformed);
            }
            let mut quantizer = [0; 64];
            for (i, &value) in r.take(64)?.iter().enumerate() {
                if value == 0 {
                    return Err(DecodeError::Malformed);
                }
                quantizer[ZIGZAG[i]] = u16::from(value);
            }
            // Once used, a destination stays frozen for this image. Identical retransmission is
            // harmless; changing a quantizer under already accumulated coefficients is refused.
            if frame.is_some_and(|f| {
                f.components[..f.count]
                    .iter()
                    .any(|c| c.quantizer_id == id && c.quantizer.is_some_and(|q| q != quantizer))
            }) {
                return Err(DecodeError::Malformed);
            }
            self.quantizers[id] = Some(quantizer);
        }
        Ok(())
    }

    fn huffman(&mut self, data: &[u8]) -> Result<(), DecodeError> {
        if data.is_empty() {
            return Err(DecodeError::Malformed);
        }
        let mut r = Reader {
            bytes: data,
            pos: 0,
        };
        while r.pos < data.len() {
            let descriptor = r.byte()?;
            let id = usize::from(descriptor & 15);
            let class = descriptor >> 4;
            if id > 3 || class > 1 {
                return Err(DecodeError::Unsupported);
            }
            let counts: [u8; 16] = r.take(16)?.try_into().map_err(|_| DecodeError::Malformed)?;
            let total = counts.iter().map(|&n| usize::from(n)).sum::<usize>();
            if total > 256 {
                return Err(DecodeError::Malformed);
            }
            let table = ScanTable::new(counts, r.take(total)?, class == 1)?;
            if class == 0 {
                self.dc[id] = Some(table);
            } else {
                self.ac[id] = Some(table);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Scan {
    count: usize,
    components: [(usize, usize, usize); 3],
    start: usize,
    end: usize,
    high: u8,
    low: u8,
}

impl Scan {
    fn parse(data: &[u8], frame: &mut Frame, tables: &Tables) -> Result<Self, DecodeError> {
        let count = usize::from(*data.first().ok_or(DecodeError::Malformed)?);
        if count == 0 || count > frame.count || data.len() != 4 + 2 * count {
            return Err(DecodeError::Malformed);
        }
        let start = usize::from(data[1 + 2 * count]);
        let end = usize::from(data[2 + 2 * count]);
        let high = data[3 + 2 * count] >> 4;
        let low = data[3 + 2 * count] & 15;
        if start > end
            || end > 63
            || (start == 0 && end != 0)
            || (start != 0 && count != 1)
            || high > 13
            || low > 13
            || (high != 0 && high != low + 1)
        {
            return Err(DecodeError::Malformed);
        }
        let mut selected = [false; 3];
        let mut components = [(0, 0, 0); 3];
        for (i, slot) in components.iter_mut().enumerate().take(count) {
            let id = data[1 + 2 * i];
            let selector = data[2 + 2 * i];
            let dc = usize::from(selector >> 4);
            let ac = usize::from(selector & 15);
            let index = frame.components[..frame.count]
                .iter()
                .position(|c| c.id == id)
                .ok_or(DecodeError::Malformed)?;
            if selected[index] || dc > 3 || ac > 3 {
                return Err(DecodeError::Malformed);
            }
            selected[index] = true;
            if (start == 0 && high == 0 && tables.dc[dc].is_none())
                || (start != 0 && tables.ac[ac].is_none())
            {
                return Err(DecodeError::Unsupported);
            }
            let c = &mut frame.components[index];
            if start != 0 && c.approximation[0].is_none() {
                return Err(DecodeError::Malformed);
            }
            for state in &c.approximation[start..=end] {
                if *state != if high == 0 { None } else { Some(high) } {
                    return Err(DecodeError::Malformed);
                }
            }
            let quantizer = tables.quantizers[c.quantizer_id].ok_or(DecodeError::Unsupported)?;
            if c.quantizer.is_some_and(|old| old != quantizer) {
                return Err(DecodeError::Malformed);
            }
            c.quantizer = Some(quantizer);
            *slot = (index, dc, ac);
        }
        Ok(Self {
            count,
            components,
            start,
            end,
            high,
            low,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn decode_scan(
    input: &mut Reader<'_>,
    frame: &mut Frame,
    scan: Scan,
    tables: &Tables,
    restart_interval: usize,
    stats: &mut Stats,
    budget: &mut DecodeBudget<'_>,
) -> Result<(), DecodeError> {
    let interleaved = scan.count > 1;
    let first = &frame.components[scan.components[0].0];
    let (columns, rows) = if interleaved {
        (frame.columns, frame.rows)
    } else {
        (first.actual_columns, first.actual_rows)
    };
    let mut bits = Bits::new(input);
    let mut predictors = [0_i32; 3];
    let mut eob_run = 0_usize;
    let mut restart = 0;
    for mcu in 0..columns * rows {
        budget.charge(1)?;
        if mcu != 0 && restart_interval != 0 && mcu % restart_interval == 0 {
            if eob_run != 0 {
                return Err(DecodeError::Malformed);
            }
            bits.restart(restart)?;
            restart = (restart + 1) % 8;
            predictors = [0; 3];
            stats.restarts += 1;
        }
        for &(index, dc, ac) in &scan.components[..scan.count] {
            let component = &mut frame.components[index];
            let (h, v) = if interleaved {
                (component.h, component.v)
            } else {
                (1, 1)
            };
            for by in 0..v {
                for bx in 0..h {
                    budget.charge(4096)?;
                    let x = mcu % columns * h + bx;
                    let y = mcu / columns * v + by;
                    let block = component
                        .coefficients
                        .get_mut(y * component.columns + x)
                        .ok_or(DecodeError::Malformed)?;
                    if scan.start == 0 {
                        if scan.high == 0 {
                            let table = tables.dc[dc].as_ref().ok_or(DecodeError::Malformed)?;
                            let size = table.symbol(&mut bits)?;
                            let difference = bits.signed(size)?;
                            predictors[index] = predictors[index]
                                .checked_add(difference)
                                .ok_or(DecodeError::Limit)?;
                            let value = predictors[index]
                                .checked_mul(1_i32 << scan.low)
                                .ok_or(DecodeError::Limit)?;
                            // A negative 8-bit DC at Al=13 can temporarily be -8192 because its
                            // point transform is arithmetic shift, unlike AC magnitude truncation.
                            block[0] = checked_dc(value, scan.low)?;
                        } else {
                            // T.81 A.4/G.1.2.1: append a two's-complement bit, including negative DC.
                            block[0] |= (bits.read(1)? as i16) << scan.low;
                            block[0] = checked_dc(i32::from(block[0]), scan.low)?;
                        }
                    } else {
                        let table = tables.ac[ac].as_ref().ok_or(DecodeError::Malformed)?;
                        if scan.high == 0 {
                            ac_first(&mut bits, table, block, scan, &mut eob_run)?;
                        } else {
                            ac_refine(&mut bits, table, block, scan, &mut eob_run)?;
                        }
                    }
                    stats.blocks += 1;
                }
            }
        }
        stats.mcus += 1;
    }
    if eob_run != 0 {
        return Err(DecodeError::Malformed);
    }
    bits.align()?;
    for &(index, _, _) in &scan.components[..scan.count] {
        frame.components[index].approximation[scan.start..=scan.end].fill(Some(scan.low));
    }
    Ok(())
}

fn checked_dc(value: i32, low: u8) -> Result<i16, DecodeError> {
    // Preserve the baseline's deliberately wider 8-bit final bound. Coarse negative DC uses
    // arithmetic shift, so its current approximation can lie below -2048 until refined.
    let minimum = (-2048_i32 >> low) << low;
    let maximum = (2047_i32 >> low) << low;
    if !(minimum..=maximum).contains(&value) {
        return Err(DecodeError::Limit);
    }
    Ok(value as i16)
}

fn ac_first(
    bits: &mut Bits<'_, '_>,
    table: &ScanTable,
    block: &mut [i16; 64],
    scan: Scan,
    eob_run: &mut usize,
) -> Result<(), DecodeError> {
    if *eob_run != 0 {
        *eob_run -= 1;
        return Ok(());
    }
    let mut k = scan.start;
    while k <= scan.end {
        let symbol = table.symbol(bits)?;
        let run = usize::from(symbol >> 4);
        let size = symbol & 15;
        if size == 0 {
            if run == 15 {
                k += 16;
                if k > scan.end + 1 {
                    return Err(DecodeError::Malformed);
                }
            } else {
                *eob_run = (1 << run) + bits.read(run as u8)? as usize - 1;
                break;
            }
        } else {
            k += run;
            if k > scan.end {
                return Err(DecodeError::Malformed);
            }
            let value = bits.signed(size)? * (1_i32 << scan.low);
            if !(-1023..=1023).contains(&value) {
                return Err(DecodeError::Limit);
            }
            block[ZIGZAG[k]] = value as i16;
            k += 1;
        }
    }
    Ok(())
}

fn refine_nonzero(bits: &mut Bits<'_, '_>, value: &mut i16, low: u8) -> Result<(), DecodeError> {
    if bits.read(1)? != 0 {
        let delta = 1_i16 << low;
        if value.unsigned_abs() & delta as u16 != 0 {
            return Err(DecodeError::Malformed);
        }
        *value = value
            .checked_add(if *value < 0 { -delta } else { delta })
            .ok_or(DecodeError::Limit)?;
        if !(-1023..=1023).contains(value) {
            return Err(DecodeError::Limit);
        }
    }
    Ok(())
}

fn ac_refine(
    bits: &mut Bits<'_, '_>,
    table: &ScanTable,
    block: &mut [i16; 64],
    scan: Scan,
    eob_run: &mut usize,
) -> Result<(), DecodeError> {
    let mut k = scan.start;
    if *eob_run == 0 {
        while k <= scan.end {
            let symbol = table.symbol(bits)?;
            let run = usize::from(symbol >> 4);
            let size = symbol & 15;
            if size == 0 && run < 15 {
                *eob_run = (1 << run) + bits.read(run as u8)? as usize;
                break;
            }
            if size > 1 {
                return Err(DecodeError::Malformed);
            }
            let new_value = if size == 1 {
                Some(if bits.read(1)? == 0 {
                    -(1_i16 << scan.low)
                } else {
                    1_i16 << scan.low
                })
            } else {
                None
            };
            let mut zeros = if new_value.is_some() { run } else { 16 };
            while k <= scan.end {
                let value = &mut block[ZIGZAG[k]];
                if *value != 0 {
                    refine_nonzero(bits, value, scan.low)?;
                } else if zeros == 0 {
                    break;
                } else {
                    zeros -= 1;
                    if zeros == 0 && new_value.is_none() {
                        k += 1;
                        break;
                    }
                }
                k += 1;
            }
            if zeros != 0 {
                return Err(DecodeError::Malformed);
            }
            if let Some(value) = new_value {
                if k > scan.end {
                    return Err(DecodeError::Malformed);
                }
                if !(-1023..=1023).contains(&value) {
                    return Err(DecodeError::Limit);
                }
                block[ZIGZAG[k]] = value;
                k += 1;
            }
        }
    }
    if *eob_run != 0 {
        for &index in &ZIGZAG[k..=scan.end] {
            if block[index] != 0 {
                refine_nonzero(bits, &mut block[index], scan.low)?;
            }
        }
        *eob_run -= 1;
    }
    Ok(())
}

fn metadata(
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
        let transform = match interpretation {
            ComponentInterpretation::Grayscale => 0,
            ComponentInterpretation::YCbCr => 1,
        };
        if data[11] != transform {
            return Err(DecodeError::Unsupported);
        }
    }
    Ok(())
}

fn decode(
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
    let mut tables = Tables::new();
    let mut stats = Stats::default();
    let mut markers = 1;
    let mut scans = 0;
    let mut restart_interval = 0;
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
            let frame = frame.ok_or(DecodeError::Malformed)?;
            if scans == 0
                || frame.components[..frame.count]
                    .iter()
                    .any(|c| c.approximation[0].is_none())
            {
                return Err(DecodeError::Malformed);
            }
            let pixels = reconstruct(&frame, output, budget)?;
            return Ok(([frame.width as u32, frame.height as u32], pixels, stats));
        }
        if marker == 0xd8 || marker == 1 || (0xd0..=0xd7).contains(&marker) {
            return Err(DecodeError::Malformed);
        }
        let segment = input.segment()?;
        budget.charge(segment.len() as u64)?;
        match marker {
            0xc2 => {
                if frame.is_some() {
                    return Err(DecodeError::Malformed);
                }
                frame = Some(Frame::parse(
                    segment,
                    interpretation,
                    limits,
                    output,
                    budget,
                )?);
            }
            0xdb => tables.quantizers(segment, frame.as_ref())?,
            0xc4 => tables.huffman(segment)?,
            0xdd => {
                if segment.len() != 2 {
                    return Err(DecodeError::Malformed);
                }
                restart_interval = usize::from(u16::from_be_bytes([segment[0], segment[1]]));
            }
            0xda => {
                scans += 1;
                if scans > MAX_SCANS {
                    return Err(DecodeError::Limit);
                }
                let frame = frame.as_mut().ok_or(DecodeError::Malformed)?;
                let scan = Scan::parse(segment, frame, &tables)?;
                decode_scan(
                    &mut input,
                    frame,
                    scan,
                    &tables,
                    restart_interval,
                    &mut stats,
                    budget,
                )?;
            }
            0xe0..=0xef | 0xfe => {
                metadata(marker, segment, interpretation)?;
                stats.metadata_segments += 1;
                stats.metadata_bytes += segment.len();
            }
            _ => return Err(DecodeError::Unsupported),
        }
    }
}

fn reconstruct(
    frame: &Frame,
    output: Reconstruction,
    budget: &mut DecodeBudget<'_>,
) -> Result<Vec<u8>, DecodeError> {
    let rgb = matches!(output, Reconstruction::Rgb { .. });
    let length = frame.width * frame.height * if rgb { 3 } else { 1 };
    budget.charge(length as u64)?;
    let mut pixels = Vec::new();
    pixels
        .try_reserve_exact(length)
        .map_err(|_| DecodeError::Limit)?;
    pixels.resize(length, 0);
    for mcu in 0..frame.columns * frame.rows {
        budget.charge(1)?;
        let mut tiles = [[0; 256]; 3];
        if rgb {
            budget.charge(3 * 256)?;
        }
        for (index, component) in frame.components[..if rgb { frame.count } else { 1 }]
            .iter()
            .enumerate()
        {
            let quantizer = component.quantizer.as_ref().ok_or(DecodeError::Malformed)?;
            for by in 0..component.v {
                for bx in 0..component.h {
                    budget.charge(4096 + 64)?;
                    let x = mcu % frame.columns * component.h + bx;
                    let y = mcu / frame.columns * component.v + by;
                    let quantized = &component.coefficients[y * component.columns + x];
                    let mut dequantized = [0_i32; 64];
                    for i in 0..64 {
                        dequantized[i] = i32::from(quantized[i]) * i32::from(quantizer[i]);
                    }
                    // |DC| <= 8192 and |AC| <= 1023, Q <= 255. Even the conservative bound
                    // 64 * 8192 * 255 * 16384^2 is below 2^56, safely inside the shared i64 IDCT.
                    let samples = inverse(&dequantized);
                    if rgb {
                        budget.charge(64)?;
                        for sy in 0..8 {
                            let start = (by * 8 + sy) * component.h * 8 + bx * 8;
                            tiles[index][start..start + 8]
                                .copy_from_slice(&samples[sy * 8..sy * 8 + 8]);
                        }
                    } else {
                        for sy in 0..8 {
                            for sx in 0..8 {
                                if y * 8 + sy < frame.height && x * 8 + sx < frame.width {
                                    pixels[(y * 8 + sy) * frame.width + x * 8 + sx] =
                                        samples[sy * 8 + sx];
                                }
                            }
                        }
                    }
                }
            }
        }
        if rgb {
            budget.charge((frame.h * frame.v * 64 * 24) as u64)?;
            let ox = mcu % frame.columns * frame.h * 8;
            let oy = mcu / frame.columns * frame.v * 8;
            for y in 0..frame.v * 8 {
                for x in 0..frame.h * 8 {
                    if ox + x >= frame.width || oy + y >= frame.height {
                        continue;
                    }
                    let luma = tiles[0][y * frame.h * 8 + x];
                    let color = if frame.count == 1 {
                        [luma; 3]
                    } else {
                        let chroma = y / frame.v * 8 + x / frame.h;
                        ycbcr_to_rgb(luma, tiles[1][chroma], tiles[2][chroma])
                    };
                    let to = ((oy + y) * frame.width + ox + x) * 3;
                    pixels[to..to + 3].copy_from_slice(&color);
                }
            }
        }
    }
    Ok(pixels)
}
