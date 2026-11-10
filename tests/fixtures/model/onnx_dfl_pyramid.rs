#![forbid(unsafe_code)]
//! Untrained three-scale RGB DFL fixture shared by native import and package tests.
//! The oracle uses direct image coordinates and binary64 softmax, independently
//! of the production reshape, transpose, pooling and DFL lowering.

pub const TARGET: [usize; 2] = [8, 8];
pub const INPUT: &str = "image";
pub const OUTPUT: &str = "detections";
pub const BINS: usize = 4;
pub const SCORE_FIELDS: usize = 2;
pub const FIELDS: usize = 4 * BINS + SCORE_FIELDS;
pub const ROWS: usize = 21;
pub const LEVEL_OUTPUTS: [&str; 3] = ["coarse", "fine", "global"];
pub const LEVEL_STRIDES: [usize; 3] = [4, 2, 8];
pub const LEVEL_NCHW: [bool; 3] = [true, false, true];

fn varint(mut value: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        bytes.push(byte | if value == 0 { 0 } else { 128 });
        if value == 0 {
            return bytes;
        }
    }
}
fn integer(tag: u64, value: i64) -> Vec<u8> {
    [varint(tag * 8), varint(value as u64)].concat()
}
fn bytes(tag: u64, value: &[u8]) -> Vec<u8> {
    [
        varint(tag * 8 + 2),
        varint(value.len() as u64),
        value.to_vec(),
    ]
    .concat()
}
fn info(name: &str, dimensions: &[usize]) -> Vec<u8> {
    let shape: Vec<_> = dimensions
        .iter()
        .flat_map(|&n| bytes(1, &integer(1, n as i64)))
        .collect();
    let tensor = [integer(1, 1), bytes(2, &shape)].concat();
    [bytes(1, name.as_bytes()), bytes(2, &bytes(1, &tensor))].concat()
}
fn weight(name: &str, dimensions: &[usize], values: &[f32]) -> Vec<u8> {
    let raw: Vec<_> = values.iter().flat_map(|v| v.to_le_bytes()).collect();
    bytes(
        5,
        &[
            dimensions
                .iter()
                .flat_map(|&n| integer(1, n as i64))
                .collect(),
            integer(2, 1),
            bytes(8, name.as_bytes()),
            bytes(9, &raw),
        ]
        .concat(),
    )
}
fn ints(name: &str, values: &[i64]) -> Vec<u8> {
    bytes(
        5,
        &[
            bytes(1, name.as_bytes()),
            integer(20, 7),
            values.iter().flat_map(|&n| integer(8, n)).collect(),
        ]
        .concat(),
    )
}
fn node(op: &str, inputs: &[&str], outputs: &[&str], attrs: &[u8]) -> Vec<u8> {
    bytes(
        1,
        &[
            inputs.iter().flat_map(|s| bytes(1, s.as_bytes())).collect(),
            outputs
                .iter()
                .flat_map(|s| bytes(2, s.as_bytes()))
                .collect(),
            bytes(4, op.as_bytes()),
            attrs.to_vec(),
        ]
        .concat(),
    )
}
fn coefficient(field: usize, channel: usize) -> f32 {
    if field == 4 * BINS {
        return if channel == 0 { 0.125 } else { 0.0 };
    }
    if field == 4 * BINS + 1 {
        return if channel == 1 { 0.125 } else { 0.0 };
    }
    match channel {
        0 => ((field % BINS) + 1) as f32 / 32.0,
        1 => ((field / BINS) + 1) as f32 / 64.0,
        _ => -(((field % 3) + 1) as f32) / 128.0,
    }
}
fn bias(field: usize) -> f32 {
    if field == 4 * BINS {
        0.625
    } else if field == 4 * BINS + 1 {
        0.25
    } else {
        ((field % BINS) as f32 - 1.5) * 0.25 + (field / BINS) as f32 * 0.125
    }
}

/// Exact declared feature-map shape for a fixture level.
pub fn level_shape(level: usize) -> [usize; 4] {
    let h = TARGET[0] / LEVEL_STRIDES[level];
    let w = TARGET[1] / LEVEL_STRIDES[level];
    if LEVEL_NCHW[level] {
        [1, FIELDS, h, w]
    } else {
        [1, h, w, FIELDS]
    }
}

/// Static opset-13 Conv and AveragePool graph, with source output order deliberately
/// different from the explicit decoding order. The extra embedding must survive.
pub fn model() -> Vec<u8> {
    let kernel: Vec<_> = (0..FIELDS)
        .flat_map(|field| (0..3).map(move |channel| coefficient(field, channel)))
        .collect();
    let biases: Vec<_> = (0..FIELDS).map(bias).collect();
    let mut graph = node("Conv", &[INPUT, "kernel", "bias"], &["features"], &[]);
    for (index, &stride) in LEVEL_STRIDES.iter().enumerate() {
        let output = if LEVEL_NCHW[index] {
            LEVEL_OUTPUTS[index]
        } else {
            "fine_nchw"
        };
        graph.extend(node(
            "AveragePool",
            &["features"],
            &[output],
            &[
                ints("kernel_shape", &[stride as i64, stride as i64]),
                ints("strides", &[stride as i64, stride as i64]),
            ]
            .concat(),
        ));
    }
    graph.extend(node(
        "Transpose",
        &["fine_nchw"],
        &["fine"],
        &ints("perm", &[0, 2, 3, 1]),
    ));
    graph.extend(node("Identity", &["global"], &["embedding"], &[]));
    graph.extend(weight("kernel", &[FIELDS, 3, 1, 1], &kernel));
    graph.extend(weight("bias", &[FIELDS], &biases));
    graph.extend(bytes(11, &info(INPUT, &[1, 3, TARGET[0], TARGET[1]])));
    for index in [1, 2, 0] {
        graph.extend(bytes(12, &info(LEVEL_OUTPUTS[index], &level_shape(index))));
    }
    graph.extend(bytes(12, &info("embedding", &level_shape(2))));
    [integer(1, 8), bytes(8, &integer(2, 13)), bytes(7, &graph)].concat()
}

/// Interleaved byte-exact RGB gradient suitable for the actual package preprocessor.
pub fn sample_rgb() -> Vec<u8> {
    (0..TARGET[0])
        .flat_map(|y| {
            (0..TARGET[1]).flat_map(move |x| {
                (0..3).map(move |channel| ((17 * x + 13 * y + 71 * channel) % 256) as u8)
            })
        })
        .collect()
}

/// The same gradient after unit RGB scaling, in the model's NCHW order.
pub fn sample_input() -> Vec<f32> {
    let rgb = sample_rgb();
    (0..3)
        .flat_map(|channel| {
            let rgb = &rgb;
            (0..TARGET[0] * TARGET[1])
                .map(move |pixel| f32::from(rgb[3 * pixel + channel]) * (1.0_f32 / 255.0_f32))
        })
        .collect()
}

/// Independent expected decoded rows: coarse, fine, global; then y and x.
/// Coordinates use binary64 expected-bin arithmetic and are returned as F32 for
/// numerical comparison with the native F32 profile, not a bit-identical claim.
pub fn oracle(input_nchw: &[f32]) -> Vec<f32> {
    assert_eq!(input_nchw.len(), 3 * TARGET[0] * TARGET[1]);
    let mut output = Vec::with_capacity(ROWS * (4 + SCORE_FIELDS));
    for stride in LEVEL_STRIDES {
        for y in 0..TARGET[0] / stride {
            for x in 0..TARGET[1] / stride {
                let mut mean = [0.0_f64; 3];
                for channel in 0..3 {
                    for dy in 0..stride {
                        for dx in 0..stride {
                            let index = (channel * TARGET[0] + y * stride + dy) * TARGET[1]
                                + x * stride
                                + dx;
                            mean[channel] +=
                                f64::from(input_nchw[index]) / (stride * stride) as f64;
                        }
                    }
                }
                let fields: Vec<_> = (0..FIELDS)
                    .map(|field| {
                        mean.iter()
                            .enumerate()
                            .fold(f64::from(bias(field)), |sum, (c, value)| {
                                sum + value * f64::from(coefficient(field, c))
                            })
                    })
                    .collect();
                let mut distance = [0.0_f64; 4];
                for side in 0..4 {
                    let logits = &fields[side * BINS..(side + 1) * BINS];
                    let maximum = logits.iter().copied().fold(f64::NEG_INFINITY, f64::max);
                    let probabilities: Vec<_> =
                        logits.iter().map(|v| (v - maximum).exp()).collect();
                    let total: f64 = probabilities.iter().sum();
                    distance[side] = probabilities
                        .iter()
                        .enumerate()
                        .map(|(bin, p)| bin as f64 * p / total)
                        .sum::<f64>()
                        * stride as f64;
                }
                let cx = (x as f64 + 0.5) * stride as f64;
                let cy = (y as f64 + 0.5) * stride as f64;
                output.extend([
                    (cx - distance[0]) as f32,
                    (cy - distance[1]) as f32,
                    (cx + distance[2]) as f32,
                    (cy + distance[3]) as f32,
                    fields[4 * BINS] as f32,
                    fields[4 * BINS + 1] as f32,
                ]);
            }
        }
    }
    output
}
