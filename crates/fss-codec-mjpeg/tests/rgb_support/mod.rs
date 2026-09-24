#![forbid(unsafe_code)]
//! Test-only baseline JPEG encoder for exact DC-only component fixtures.
#![allow(dead_code)]

fn segment(bytes: &mut Vec<u8>, marker: u8, data: &[u8]) {
    bytes.extend_from_slice(&[255, marker]);
    bytes.extend_from_slice(&((data.len() + 2) as u16).to_be_bytes());
    bytes.extend_from_slice(data);
}
fn bits(output: &mut Vec<bool>, value: u32, count: u32) {
    for bit in (0..count).rev() { output.push(value & (1 << bit) != 0); }
}
fn flush(output: &mut Vec<u8>, pending: &mut Vec<bool>) {
    while !pending.len().is_multiple_of(8) { pending.push(true); }
    for chunk in pending.as_chunks::<8>().0 {
        let byte = chunk.iter().fold(0_u8, |value, bit| (value << 1) | u8::from(*bit));
        output.push(byte); if byte == 255 { output.push(0); }
    }
    pending.clear();
}
/// Constant Y/Cb/Cr per MCU, or grayscale; all padding blocks are actually encoded.
/// Chosen samples repeat over MCUs. Reversed SOS order and restart markers are optional.
pub fn jpeg(width: u16, height: u16, sampling: [usize; 2], grayscale: bool,
    restart: bool, reversed: bool, samples: &[[u8; 3]]) -> Vec<u8> {
    let [h, v] = if grayscale { [1, 1] } else { sampling };
    let count = if grayscale { 1 } else { 3 };
    let mut result = vec![255, 216];
    // Q=8 makes quantized DC equal to the desired sample minus the 128 level shift.
    let mut quantizer = vec![8; 65]; quantizer[0] = 0;
    segment(&mut result, 0xdb, &quantizer);
    let mut dc = vec![0; 17]; dc[4] = 9; dc.extend(0_u8..9);
    let mut ac = vec![0; 17]; ac[0] = 16; ac[1] = 1; ac.push(0);
    dc.extend(ac); segment(&mut result, 0xc4, &dc);
    let mut frame = vec![8]; frame.extend_from_slice(&height.to_be_bytes());
    frame.extend_from_slice(&width.to_be_bytes()); frame.push(count as u8);
    for component in 0..count { frame.extend_from_slice(&[component as u8 + 1,
        if component == 0 { (h * 16 + v) as u8 } else { 17 }, 0]); }
    segment(&mut result, 0xc0, &frame);
    if restart { segment(&mut result, 0xdd, &[0, 1]); }
    let mut order: Vec<usize> = (0..count).collect();
    if reversed { order.reverse(); }
    let mut scan = vec![count as u8];
    for &component in &order { scan.extend_from_slice(&[component as u8 + 1, 0]); }
    scan.extend_from_slice(&[0, 63, 0]); segment(&mut result, 0xda, &scan);
    let mcus = usize::from(width).div_ceil(h * 8) * usize::from(height).div_ceil(v * 8);
    let mut predictors = [0_i32; 3]; let mut pending = Vec::new();
    for mcu in 0..mcus {
        if restart && mcu > 0 {
            flush(&mut result, &mut pending); result.extend_from_slice(&[255, 0xd0 + ((mcu - 1) % 8) as u8]);
            predictors = [0; 3];
        }
        for &component in &order {
            for _ in 0..if component == 0 { h * v } else { 1 } {
                let dc = i32::from(samples[mcu % samples.len()][component]) - 128;
                let difference = dc - predictors[component]; predictors[component] = dc;
                let magnitude = difference.unsigned_abs();
                let size = 32 - magnitude.leading_zeros();
                bits(&mut pending, size, 4);
                let encoded = if difference < 0 { (difference + (1_i32 << size) - 1) as u32 }
                    else { magnitude };
                bits(&mut pending, encoded, size); bits(&mut pending, 0, 1); // AC EOB
            }
        }
    }
    flush(&mut result, &mut pending); result.extend_from_slice(&[255, 217]); result
}
