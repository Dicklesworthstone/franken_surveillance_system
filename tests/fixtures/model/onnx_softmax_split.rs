#![forbid(unsafe_code)]
//! Untrained RGB-dependent split boxes/class-logits fixture shared by native and
//! package tests. Class one is deliberately omitted AFTER full-axis Softmax.
//! The first row must remain below 0.5 despite a foreground-only Softmax exceeding
//! 0.5; the second row provides one visible foreground detection.

pub const TARGET: [usize; 2] = [2, 2];
pub const INPUT: &str = "image";
pub const BOXES: &str = "boxes";
pub const SCORES: &str = "logits";
pub const OUTPUT: &str = "detections";
pub const ROWS: usize = 2;
pub const SCORE_FIELDS: usize = 3;
pub const CLASS_INDICES: [usize; 2] = [2, 0];
pub const BOX_VALUES: [f32; 8] = [0.0, 0.0, 1.0, 1.0, 1.0, 1.0, 2.0, 2.0];
pub const SCORE_SHAPE: [usize; 3] = [1, 3, 2];
pub const BOX_SHAPE: [usize; 3] = [1, 2, 4];
const BIAS: [f32; 6] = [0.5, 8.0, 1.5, -1.0, -2.0, 4.0];

fn varint(mut value: u64) -> Vec<u8> {
    let mut output = Vec::new();
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        output.push(byte | if value == 0 { 0 } else { 128 });
        if value == 0 {
            return output;
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
fn info(name: &str, dims: &[usize]) -> Vec<u8> {
    let shape: Vec<_> = dims
        .iter()
        .flat_map(|&n| bytes(1, &integer(1, n as i64)))
        .collect();
    let tensor = [integer(1, 1), bytes(2, &shape)].concat();
    [bytes(1, name.as_bytes()), bytes(2, &bytes(1, &tensor))].concat()
}
fn tensor(name: &str, dims: &[usize], dtype: i64, raw: &[u8]) -> Vec<u8> {
    bytes(
        5,
        &[
            dims.iter().flat_map(|&n| integer(1, n as i64)).collect(),
            integer(2, dtype),
            bytes(8, name.as_bytes()),
            bytes(9, raw),
        ]
        .concat(),
    )
}
fn weight(name: &str, dims: &[usize], values: &[f32]) -> Vec<u8> {
    tensor(
        name,
        dims,
        1,
        &values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect::<Vec<_>>(),
    )
}
fn attribute(name: &str, kind: i64, payload: &[u8]) -> Vec<u8> {
    bytes(
        5,
        &[
            bytes(1, name.as_bytes()),
            integer(20, kind),
            payload.to_vec(),
        ]
        .concat(),
    )
}
fn node(op: &str, inputs: &[&str], outputs: &[&str], attrs: &[u8]) -> Vec<u8> {
    bytes(
        1,
        &[
            inputs
                .iter()
                .flat_map(|name| bytes(1, name.as_bytes()))
                .collect(),
            outputs
                .iter()
                .flat_map(|name| bytes(2, name.as_bytes()))
                .collect(),
            bytes(4, op.as_bytes()),
            attrs.to_vec(),
        ]
        .concat(),
    )
}
fn coefficient(input: usize, field: usize) -> f32 {
    match (input / 4, field) {
        (0, 0) | (2, 2) | (1, 3) | (2, 4) => 0.0625,
        (1, 1) | (0, 5) => 0.125,
        _ => 0.0,
    }
}

/// Static opset-13 image-dependent score branches, constant pixel boxes, and an
/// auxiliary Sqrt output exercising preservation of the existing native IR v2.
pub fn model() -> Vec<u8> {
    let weights: Vec<_> = (0..12)
        .flat_map(|input| (0..6).map(move |field| coefficient(input, field)))
        .collect();
    let shape: Vec<_> = [1_i64, 2, 3]
        .into_iter()
        .flat_map(i64::to_le_bytes)
        .collect();
    let graph = [
        node(
            "Flatten",
            &[INPUT],
            &["features"],
            &attribute("axis", 2, &integer(3, 1)),
        ),
        node(
            "MatMul",
            &["features", "score_weights"],
            &["score_linear"],
            &[],
        ),
        node("Add", &["score_linear", "score_bias"], &["score_flat"], &[]),
        node(
            "Reshape",
            &["score_flat", "score_shape"],
            &["score_rows"],
            &[],
        ),
        node(
            "Transpose",
            &["score_rows"],
            &[SCORES],
            &attribute(
                "perm",
                7,
                &[integer(8, 0), integer(8, 2), integer(8, 1)].concat(),
            ),
        ),
        node("Identity", &["box_values"], &[BOXES], &[]),
        node("Sqrt", &["features"], &["embedding"], &[]),
        weight("score_weights", &[12, 6], &weights),
        weight("score_bias", &[6], &BIAS),
        weight("box_values", &BOX_SHAPE, &BOX_VALUES),
        tensor("score_shape", &[3], 7, &shape),
        bytes(11, &info(INPUT, &[1, 3, 2, 2])),
        bytes(12, &info(SCORES, &SCORE_SHAPE)),
        bytes(12, &info("embedding", &[1, 12])),
        bytes(12, &info(BOXES, &BOX_SHAPE)),
    ]
    .concat();
    [integer(1, 8), bytes(8, &integer(2, 13)), bytes(7, &graph)].concat()
}

pub fn sample_rgb() -> Vec<u8> {
    vec![16, 80, 144, 224, 32, 64, 48, 192, 96, 128, 160, 240]
}

pub fn sample_input() -> Vec<f32> {
    let rgb = sample_rgb();
    (0..3)
        .flat_map(|channel| {
            let rgb = &rgb;
            (0..4).map(move |pixel| f32::from(rgb[3 * pixel + channel]) * (1.0_f32 / 255.0_f32))
        })
        .collect()
}

/// Independent image-coordinate dot products and binary64 full-class Softmax.
/// Returns [box4, class2_probability, class0_probability] for each source row.
pub fn oracle(input_nchw: &[f32]) -> Vec<f32> {
    assert_eq!(input_nchw.len(), 12);
    let logits: Vec<_> = (0..6)
        .map(|field| {
            input_nchw
                .iter()
                .enumerate()
                .fold(f64::from(BIAS[field]), |sum, (index, &value)| {
                    sum + f64::from(value) * f64::from(coefficient(index, field))
                })
        })
        .collect();
    let mut output = Vec::new();
    for row in 0..ROWS {
        let values = &logits[row * SCORE_FIELDS..(row + 1) * SCORE_FIELDS];
        let maximum = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let exp: Vec<_> = values.iter().map(|value| (value - maximum).exp()).collect();
        let sum: f64 = exp.iter().sum();
        output.extend_from_slice(&BOX_VALUES[row * 4..(row + 1) * 4]);
        output.extend(CLASS_INDICES.map(|index| (exp[index] / sum) as f32));
    }
    output
}
