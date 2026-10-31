#![forbid(unsafe_code)]
//! Original ONNX protobufs -> explicit native DFL conversion -> artifact reload ->
//! actual scalar execution. The independent oracle uses F64 exp/expectations and
//! authored pixel grids, never the production Softmax, MatMul or DFL helpers.
//! This target does not qualify the asynchronous reference runtime or a trained model.

use std::cell::Cell;
use std::collections::BTreeMap;

use fss_core::{ContentDigest, Generation};
use fss_model_ir::{
    ImportedOnnx, OnnxArtifacts, OnnxDflHeadDecode, OnnxError, OnnxExportLimits, OnnxHeadLayout,
    OnnxLimits, decode_canonical_model_ir, decode_onnx_dfl_head, encode_canonical_model_ir,
    export_onnx_artifacts, import_onnx,
};
use fss_tensor::{Shape, Tensor};

#[path = "../../fss-reference/src/ingest/model_import/safetensors.rs"]
mod safetensors;
#[path = "../../fss-reference/src/scalar_executor.rs"]
pub mod scalar_executor;
use scalar_executor::{ExecBudget, ExecError, ExecOutcome, ScalarExecCx, ScalarExecutor};

// Data-only vocabulary required by the unchanged production Safetensors parser.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ImportError {
    Limit,
    MalformedWeights,
    DuplicateKey,
    UnsupportedDType,
    NonFinite,
}
impl std::fmt::Display for ImportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}
impl std::error::Error for ImportError {}
struct ImportLimits {
    maximum_header_bytes: usize,
    maximum_tensors: usize,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum WeightFloatPolicy {
    F32Only,
    ExpandFloat16,
}

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const GENERATION: Generation = Generation(47);
const INPUT: &str = "head_logits";
const RAW: &str = "raw_head";
const DECODED: &str = "decoded_corners";

fn varint(mut value: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let low = (value & 127) as u8;
        value >>= 7;
        bytes.push(low | if value == 0 { 0 } else { 128 });
        if value == 0 {
            return bytes;
        }
    }
}
fn integer(tag: u64, value: u64) -> Vec<u8> {
    [varint(tag * 8), varint(value)].concat()
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
        .flat_map(|&n| bytes(1, &integer(1, n as u64)))
        .collect();
    let tensor = [integer(1, 1), bytes(2, &shape)].concat();
    [bytes(1, name.as_bytes()), bytes(2, &bytes(1, &tensor))].concat()
}
fn identity(input: &str, output: &str) -> Vec<u8> {
    bytes(
        1,
        &[
            bytes(1, input.as_bytes()),
            bytes(2, output.as_bytes()),
            bytes(4, b"Identity"),
        ]
        .concat(),
    )
}
fn source(dims: &[usize]) -> Vec<u8> {
    let sentinel: Vec<_> = [-0.0_f32, 3.25]
        .into_iter()
        .flat_map(f32::to_le_bytes)
        .collect();
    let initializer = bytes(
        5,
        &[
            integer(1, 2),
            integer(2, 1),
            bytes(8, b"sentinel_weights"),
            bytes(9, &sentinel),
        ]
        .concat(),
    );
    let graph = [
        bytes(2, b"original synthetic raw distance head"),
        identity(INPUT, "internal_head"),
        identity("internal_head", RAW),
        identity("sentinel_weights", "sentinel"),
        initializer,
        bytes(11, &info(INPUT, dims)),
        bytes(12, &info(RAW, dims)),
        bytes(12, &info("sentinel", &[2])),
    ]
    .concat();
    [integer(1, 8), bytes(8, &integer(2, 13)), bytes(7, &graph)].concat()
}
fn rows(target: [usize; 2], strides: &[usize]) -> usize {
    strides
        .iter()
        .map(|s| (target[0] / s) * (target[1] / s))
        .sum()
}
fn shape(layout: OnnxHeadLayout, rows: usize, fields: usize) -> Vec<usize> {
    match layout {
        OnnxHeadLayout::Rows => vec![1, rows, fields],
        OnnxHeadLayout::Channels => vec![1, fields, rows],
    }
}
fn packed(values: &[f32], rows: usize, fields: usize, layout: OnnxHeadLayout) -> Vec<f32> {
    match layout {
        OnnxHeadLayout::Rows => values.to_vec(),
        OnnxHeadLayout::Channels => (0..fields)
            .flat_map(|field| (0..rows).map(move |row| values[row * fields + field]))
            .collect(),
    }
}
fn policy(layout: OnnxHeadLayout, bins: usize, strides: &[usize]) -> OnnxDflHeadDecode {
    OnnxDflHeadDecode {
        raw_output: RAW.into(),
        raw_layout: layout,
        bins,
        strides: strides.to_vec(),
    }
}
fn import(source: &[u8]) -> Test<ImportedOnnx<'_>> {
    Ok(import_onnx(
        source,
        ContentDigest::sha256(source),
        GENERATION,
        OnnxLimits::default(),
        &|| false,
    )?)
}
fn adapted<'a>(
    source: &'a [u8],
    policy: &OnnxDflHeadDecode,
    target: [usize; 2],
    scores: usize,
) -> Test<ImportedOnnx<'a>> {
    Ok(decode_onnx_dfl_head(
        import(source)?,
        policy,
        DECODED,
        target,
        scores,
        OnnxLimits::default(),
        &|| false,
    )?)
}
fn bindings(imported: &ImportedOnnx<'_>, values: &[f32]) -> Test<Vec<(String, Tensor)>> {
    let mut inputs: Vec<_> = imported
        .parameters()
        .iter()
        .map(|(name, tensor)| (name.clone(), tensor.clone()))
        .collect();
    inputs.push((
        INPUT.into(),
        Tensor::from_values(
            imported
                .graph()
                .find_input(INPUT)
                .ok_or("missing raw runtime input")?
                .shape()
                .clone(),
            values,
            GENERATION,
        )?,
    ));
    Ok(inputs)
}
fn execute(imported: &ImportedOnnx<'_>, values: &[f32]) -> Test<ExecOutcome> {
    Ok(ScalarExecutor::run(
        imported.graph(),
        &bindings(imported, values)?,
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
    )?)
}
fn output(outcome: &ExecOutcome, name: &str) -> Test<Vec<f32>> {
    Ok(outcome
        .get_output(name)
        .ok_or("missing requested native output")?
        .to_vec::<f32>()?)
}
fn bits(values: &[f32]) -> Vec<u32> {
    values.iter().map(|x| x.to_bits()).collect()
}
fn parameters(artifacts: &OnnxArtifacts<'_>) -> Test<BTreeMap<String, Tensor>> {
    let parsed = safetensors::Weights::parse(
        artifacts.weights_bytes(),
        &ImportLimits {
            maximum_header_bytes: 256 * 1024,
            maximum_tensors: 256,
        },
    )?;
    let mut result = BTreeMap::new();
    for (name, entry) in &parsed.entries {
        let values = parsed.data[entry.start..entry.end]
            .chunks_exact(entry.width())
            .map(|bytes| safetensors::value(entry.dtype, bytes, WeightFloatPolicy::F32Only))
            .collect::<Result<Vec<_>, _>>()?;
        result.insert(
            name.clone(),
            Tensor::from_values(Shape::new(entry.shape.clone())?, &values, GENERATION)?,
        );
    }
    Ok(result)
}

fn values(rows: usize, bins: usize, scores: usize, patterned: bool) -> Vec<f32> {
    let fields = 4 * bins + scores;
    (0..rows * fields)
        .map(|index| {
            let row = index / fields;
            let field = index % fields;
            if field < 4 * bins {
                if patterned {
                    let side = field / bins;
                    let bin = field % bins;
                    ((row * 17 + side * 7 + bin * 11) % 23) as f32 * 0.25 - 2.75
                        + (bin * bin) as f32 * 0.03125
                } else {
                    0.0
                }
            } else {
                match (field - 4 * bins) % 4 {
                    0 => -0.0,
                    1 => -3.25 - row as f32 * 0.125,
                    2 => 7.5 + row as f32 * 0.25,
                    _ => 0.6,
                }
            }
        })
        .collect()
}

/// F64 mathematical oracle with explicit level/y/x enumeration and side/bin grouping.
fn oracle(
    values: &[f32],
    target: [usize; 2],
    strides: &[usize],
    bins: usize,
    scores: usize,
) -> Vec<f64> {
    let fields = 4 * bins + scores;
    let mut row = 0;
    let mut result = Vec::new();
    for &stride in strides {
        for y in 0..target[0] / stride {
            for x in 0..target[1] / stride {
                let mut distances = [0.0_f64; 4];
                for (side, distance) in distances.iter_mut().enumerate() {
                    let logits =
                        &values[row * fields + side * bins..row * fields + (side + 1) * bins];
                    let maximum = logits
                        .iter()
                        .map(|v| f64::from(*v))
                        .fold(f64::NEG_INFINITY, f64::max);
                    let mut weighted = 0.0;
                    let mut total = 0.0;
                    for (bin, logit) in logits.iter().enumerate() {
                        let probability = (f64::from(*logit) - maximum).exp();
                        weighted += bin as f64 * probability;
                        total += probability;
                    }
                    *distance = weighted / total * stride as f64;
                }
                let center = [
                    (x as f64 + 0.5) * stride as f64,
                    (y as f64 + 0.5) * stride as f64,
                ];
                result.extend([
                    center[0] - distances[0],
                    center[1] - distances[1],
                    center[0] + distances[2],
                    center[1] + distances[3],
                ]);
                result.extend(
                    values[row * fields + 4 * bins..(row + 1) * fields]
                        .iter()
                        .map(|v| f64::from(*v)),
                );
                row += 1;
            }
        }
    }
    result
}
fn matches_oracle(
    actual: &[f32],
    raw_rows: &[f32],
    target: [usize; 2],
    strides: &[usize],
    bins: usize,
    scores: usize,
) {
    let expected = oracle(raw_rows, target, strides, bins, scores);
    assert_eq!(actual.len(), expected.len());
    for (index, (&actual, &expected)) in actual.iter().zip(&expected).enumerate() {
        assert!(actual.is_finite());
        assert!(
            (f64::from(actual) - expected).abs() <= 3e-5 + 2e-6 * expected.abs(),
            "field {index}: actual {actual}, independent {expected}"
        );
    }
    for (decoded, original) in actual
        .chunks_exact(4 + scores)
        .zip(raw_rows.chunks_exact(4 * bins + scores))
    {
        assert_eq!(bits(&decoded[4..]), bits(&original[4 * bins..]));
    }
}

#[test]
fn equal_bin_logits_have_correct_half_pixel_centers_and_preserve_score_bits_in_both_layouts() -> Test
{
    for bins in [2, 3, 4, 7, 16, 31, 32] {
        for layout in [OnnxHeadLayout::Rows, OnnxHeadLayout::Channels] {
            let target = [8, 16];
            let strides = [8];
            let scores = 3;
            let count = rows(target, &strides);
            let raw = values(count, bins, scores, false);
            let source = source(&shape(layout, count, 4 * bins + scores));
            let model = adapted(&source, &policy(layout, bins, &strides), target, scores)?;
            let inputs = packed(&raw, count, 4 * bins + scores, layout);
            let result = execute(&model, &inputs)?;
            assert_eq!(
                result
                    .get_output(DECODED)
                    .ok_or("missing decoded head")?
                    .shape()
                    .dims(),
                [1, count, 4 + scores]
            );
            matches_oracle(
                &output(&result, DECODED)?,
                &raw,
                target,
                &strides,
                bins,
                scores,
            );
            assert_eq!(bits(&output(&result, RAW)?), bits(&inputs));
        }
    }
    Ok(())
}

#[test]
fn peaked_extreme_logits_decode_four_distinct_sides_without_exp_overflow() -> Test {
    let bins = 8;
    let scores = 2;
    let target = [8, 16];
    let strides = [8];
    let count = rows(target, &strides);
    for layout in [OnnxHeadLayout::Rows, OnnxHeadLayout::Channels] {
        let mut raw = values(count, bins, scores, false);
        for row in 0..count {
            for (side, peak) in [0, 2, 5, 7].into_iter().enumerate() {
                for bin in 0..bins {
                    raw[row * (4 * bins + scores) + side * bins + bin] =
                        if bin == peak { 1000.0 } else { -1000.0 };
                }
            }
        }
        let source = source(&shape(layout, count, 4 * bins + scores));
        let model = adapted(&source, &policy(layout, bins, &strides), target, scores)?;
        let result = execute(&model, &packed(&raw, count, 4 * bins + scores, layout))?;
        let decoded = output(&result, DECODED)?;
        matches_oracle(&decoded, &raw, target, &strides, bins, scores);
        assert_eq!(&decoded[..4], &[4.0, -12.0, 44.0, 60.0]);
        assert_eq!(&decoded[4 + scores..8 + scores], &[12.0, -12.0, 52.0, 60.0]);
    }
    Ok(())
}

#[test]
fn asymmetric_logits_match_independent_f64_oracle_on_rectangular_multilevel_grids() -> Test {
    let target = [16, 24];
    let strides = [4, 8];
    let bins = 7;
    let scores = 4;
    let count = rows(target, &strides);
    assert_eq!(count, 30);
    let raw = values(count, bins, scores, true);
    let mut decoded = Vec::new();
    for layout in [OnnxHeadLayout::Rows, OnnxHeadLayout::Channels] {
        let source = source(&shape(layout, count, 4 * bins + scores));
        let model = adapted(&source, &policy(layout, bins, &strides), target, scores)?;
        let result = execute(&model, &packed(&raw, count, 4 * bins + scores, layout))?;
        let output = output(&result, DECODED)?;
        matches_oracle(&output, &raw, target, &strides, bins, scores);
        decoded.push(output);
    }
    assert_eq!(bits(&decoded[0]), bits(&decoded[1]));
    Ok(())
}

#[test]
fn declared_stride_order_is_preserved_instead_of_sorted_or_width_height_swapped() -> Test {
    let target = [8, 16];
    let scores = 1;
    let bins = 2;
    let strides = [8, 4];
    let count = rows(target, &strides);
    let raw = values(count, bins, scores, false);
    let source = source(&shape(OnnxHeadLayout::Rows, count, 4 * bins + scores));
    let model = adapted(
        &source,
        &policy(OnnxHeadLayout::Rows, bins, &strides),
        target,
        scores,
    )?;
    let result = output(&execute(&model, &raw)?, DECODED)?;
    matches_oracle(&result, &raw, target, &strides, bins, scores);
    let expected = [
        [0., 0., 8., 8.],
        [8., 0., 16., 8.],
        [0., 0., 4., 4.],
        [4., 0., 8., 4.],
        [8., 0., 12., 4.],
        [12., 0., 16., 4.],
        [0., 4., 4., 8.],
        [4., 4., 8., 8.],
        [8., 4., 12., 8.],
        [12., 4., 16., 8.],
    ];
    for (row, expected) in result.as_chunks::<5>().0.iter().zip(expected) {
        assert_eq!(&row[..4], expected);
    }
    let reordered = adapted(
        &source,
        &policy(OnnxHeadLayout::Rows, bins, &[4, 8]),
        target,
        scores,
    )?;
    // Level ordering is represented by generated center/stride parameters.
    // Equal shapes retain the same graph, while the executable artifact changes.
    let first = export_onnx_artifacts(&model, OnnxExportLimits::default(), &|| false)?;
    let second = export_onnx_artifacts(&reordered, OnnxExportLimits::default(), &|| false)?;
    assert_ne!(first.weights_digest(), second.weights_digest());
    assert_ne!(
        bits(&result),
        bits(&output(&execute(&reordered, &raw)?, DECODED)?)
    );
    Ok(())
}

#[test]
fn maximum_score_tail_is_copied_without_sigmoid_softmax_clipping_or_signed_zero_loss() -> Test {
    let bins = 2;
    let scores = 257;
    let target = [4, 4];
    let strides = [4];
    let mut raw = values(1, bins, scores, true);
    raw[4 * bins + 1] = 1e30;
    raw[4 * bins + 2] = -1e30;
    let source = source(&shape(OnnxHeadLayout::Channels, 1, 4 * bins + scores));
    let model = adapted(
        &source,
        &policy(OnnxHeadLayout::Channels, bins, &strides),
        target,
        scores,
    )?;
    let result = output(&execute(&model, &raw)?, DECODED)?;
    assert_eq!(result.len(), 4 + scores);
    matches_oracle(&result, &raw, target, &strides, bins, scores);
    assert_eq!(result[4].to_bits(), (-0.0_f32).to_bits());
    assert_eq!(bits(&result[4..]), bits(&raw[4 * bins..]));
    Ok(())
}

#[test]
fn native_artifact_reload_preserves_source_raw_outputs_parameters_and_deterministic_bytes() -> Test
{
    let target = [8, 16];
    let strides = [4, 8];
    let bins = 4;
    let scores = 3;
    let count = rows(target, &strides);
    let raw = values(count, bins, scores, true);
    for layout in [OnnxHeadLayout::Rows, OnnxHeadLayout::Channels] {
        let source = source(&shape(layout, count, 4 * bins + scores));
        let original = import(&source)?;
        let model = adapted(&source, &policy(layout, bins, &strides), target, scores)?;
        let packed = packed(&raw, count, 4 * bins + scores, layout);
        let before = execute(&original, &packed)?;
        let actual = execute(&model, &packed)?;
        assert_eq!(model.source(), source);
        assert!(std::ptr::eq(model.source().as_ptr(), source.as_ptr()));
        assert_eq!(model.source_digest(), ContentDigest::sha256(&source));
        assert_eq!(model.runtime_inputs(), [INPUT]);
        for port in original.graph().outputs() {
            assert_eq!(
                bits(&output(&before, port.name())?),
                bits(&output(&actual, port.name())?)
            );
        }
        for (name, tensor) in original.parameters() {
            assert_eq!(
                bits(&model.parameters()[name].to_vec::<f32>()?),
                bits(&tensor.to_vec::<f32>()?)
            );
        }
        let first = export_onnx_artifacts(&model, OnnxExportLimits::default(), &|| false)?;
        let second = export_onnx_artifacts(&model, OnnxExportLimits::default(), &|| false)?;
        assert_eq!(first.graph_bytes(), second.graph_bytes());
        assert_eq!(first.weights_bytes(), second.weights_bytes());
        assert_eq!(first.source(), source);
        assert_eq!(first.source_digest(), ContentDigest::sha256(&source));
        let graph = decode_canonical_model_ir(first.graph_bytes(), first.graph_digest())?;
        let mut loaded = parameters(&first)?;
        for (name, tensor) in model.parameters() {
            assert_eq!(
                bits(&loaded[name].to_vec::<f32>()?),
                bits(&tensor.to_vec::<f32>()?)
            );
        }
        loaded.insert(
            INPUT.into(),
            Tensor::from_values(
                Shape::new(shape(layout, count, 4 * bins + scores))?,
                &packed,
                GENERATION,
            )?,
        );
        let reloaded = ScalarExecutor::run(
            &graph,
            &loaded.into_iter().collect::<Vec<_>>(),
            ExecBudget::unlimited(),
            &ScalarExecCx::new(),
        )?;
        assert_eq!(
            bits(&output(&reloaded, DECODED)?),
            bits(&output(&actual, DECODED)?)
        );
        assert_eq!(bits(&output(&reloaded, RAW)?), bits(&packed));
        matches_oracle(
            &output(&reloaded, DECODED)?,
            &raw,
            target,
            &strides,
            bins,
            scores,
        );
    }
    Ok(())
}

#[test]
fn only_exact_selected_raw_output_shapes_are_decoded() -> Test {
    let target = [8, 16];
    let strides = [8];
    let bins = 4;
    let scores = 2;
    let decode = policy(OnnxHeadLayout::Rows, bins, &strides);
    for dims in [
        vec![2, 18],
        vec![2, 2, 18],
        vec![1, 3, 18],
        vec![1, 2, 17],
        vec![1, 2, 19],
        vec![1, 18, 2],
    ] {
        let source = source(&dims);
        assert!(
            decode_onnx_dfl_head(
                import(&source)?,
                &decode,
                DECODED,
                target,
                scores,
                OnnxLimits::default(),
                &|| false
            )
            .is_err(),
            "accepted raw shape {dims:?}"
        );
    }
    let source = source(&[1, 2, 18]);
    for name in ["missing", INPUT, "internal_head", "sentinel_weights"] {
        let mut decode = decode.clone();
        decode.raw_output = name.into();
        assert_eq!(
            decode_onnx_dfl_head(
                import(&source)?,
                &decode,
                DECODED,
                target,
                scores,
                OnnxLimits::default(),
                &|| false
            )
            .err(),
            Some(OnnxError::Graph)
        );
    }
    Ok(())
}

#[test]
fn invalid_bins_scores_targets_stride_profiles_and_row_ceiling_refuse_before_expansion() -> Test {
    let source = source(&[1, 2, 18]);
    let base = policy(OnnxHeadLayout::Rows, 4, &[8]);
    for bins in [0, 1, 33, usize::MAX] {
        let mut decode = base.clone();
        decode.bins = bins;
        assert_eq!(
            decode_onnx_dfl_head(
                import(&source)?,
                &decode,
                DECODED,
                [8, 16],
                2,
                OnnxLimits::default(),
                &|| false
            )
            .err(),
            Some(OnnxError::Unsupported)
        );
    }
    for strides in [
        vec![],
        vec![0],
        vec![4097],
        vec![4, 4],
        vec![3],
        vec![16],
        vec![1, 2, 4, 8, 16, 32, 64, 128, 256],
    ] {
        let mut decode = base.clone();
        decode.strides = strides;
        assert_eq!(
            decode_onnx_dfl_head(
                import(&source)?,
                &decode,
                DECODED,
                [8, 16],
                2,
                OnnxLimits::default(),
                &|| false
            )
            .err(),
            Some(OnnxError::Unsupported)
        );
    }
    for target in [[0, 16], [8, 0], [4097, 16], [4096, 4096]] {
        assert_eq!(
            decode_onnx_dfl_head(
                import(&source)?,
                &base,
                DECODED,
                target,
                2,
                OnnxLimits::default(),
                &|| false
            )
            .err(),
            Some(OnnxError::Unsupported)
        );
    }
    for scores in [0, 258, usize::MAX] {
        assert_eq!(
            decode_onnx_dfl_head(
                import(&source)?,
                &base,
                DECODED,
                [8, 16],
                scores,
                OnnxLimits::default(),
                &|| false
            )
            .err(),
            Some(OnnxError::Unsupported)
        );
    }
    let large = self::source(&[1, 65536, 9]);
    assert_eq!(
        decode_onnx_dfl_head(
            import(&large)?,
            &policy(OnnxHeadLayout::Rows, 2, &[1]),
            DECODED,
            [256, 256],
            1,
            OnnxLimits::default(),
            &|| false
        )
        .err(),
        Some(OnnxError::Limit)
    );
    Ok(())
}

#[test]
fn output_name_collisions_refuse_and_repeated_explicit_decodes_do_not_rename_source() -> Test {
    let target = [8, 16];
    let bins = 4;
    let scores = 2;
    let decode = policy(OnnxHeadLayout::Rows, bins, &[8]);
    let source = source(&[1, 2, 18]);
    for name in [
        "",
        INPUT,
        RAW,
        "internal_head",
        "sentinel_weights",
        "sentinel",
    ] {
        assert!(
            decode_onnx_dfl_head(
                import(&source)?,
                &decode,
                name,
                target,
                scores,
                OnnxLimits::default(),
                &|| false
            )
            .is_err(),
            "accepted colliding output {name}"
        );
    }
    let first = adapted(&source, &decode, target, scores)?;
    let twice = decode_onnx_dfl_head(
        first,
        &decode,
        "decoded_second",
        target,
        scores,
        OnnxLimits::default(),
        &|| false,
    )?;
    let raw = values(2, bins, scores, true);
    let result = execute(&twice, &raw)?;
    assert_eq!(
        bits(&output(&result, DECODED)?),
        bits(&output(&result, "decoded_second")?)
    );
    assert_eq!(bits(&output(&result, RAW)?), bits(&raw));
    assert_eq!(bits(&output(&result, "sentinel")?), bits(&[-0.0, 3.25]));
    assert_eq!(twice.source_digest(), ContentDigest::sha256(&source));
    Ok(())
}

#[test]
fn generated_nodes_parameters_tensors_and_work_use_cumulative_import_limits() -> Test {
    let target = [8, 16];
    let bins = 4;
    let scores = 2;
    let source = source(&[1, 2, 18]);
    let decode = policy(OnnxHeadLayout::Rows, bins, &[8]);
    let original = import(&source)?;
    let full = adapted(&source, &decode, target, scores)?;
    let parameter_bytes = full.parameters().values().try_fold(
        0_usize,
        |sum, tensor| -> Result<usize, fss_tensor::TensorError> {
            Ok(sum + tensor.shape().size_bytes(tensor.dtype())?)
        },
    )?;
    let exact = OnnxLimits {
        source_bytes: source.len(),
        nodes: full.graph().nodes().len(),
        parameter_bytes,
        work_units: full.work_units(),
        ..OnnxLimits::default()
    };
    let replay = decode_onnx_dfl_head(
        import(&source)?,
        &decode,
        DECODED,
        target,
        scores,
        exact,
        &|| false,
    )?;
    assert_eq!(
        encode_canonical_model_ir(full.graph())?,
        encode_canonical_model_ir(replay.graph())?
    );
    assert!(full.work_units() > original.work_units());
    assert!(full.graph().nodes().len() > original.graph().nodes().len());
    for limits in [
        OnnxLimits {
            source_bytes: source.len() - 1,
            ..exact
        },
        OnnxLimits {
            nodes: exact.nodes - 1,
            ..exact
        },
        OnnxLimits {
            parameter_bytes: parameter_bytes - 1,
            ..exact
        },
        OnnxLimits {
            tensor_bytes: 2 * 18 * 4 - 1,
            ..exact
        },
        OnnxLimits {
            tensors: original.graph().inputs().len() + original.graph().nodes().len(),
            ..exact
        },
    ] {
        assert_eq!(
            decode_onnx_dfl_head(
                import(&source)?,
                &decode,
                DECODED,
                target,
                scores,
                limits,
                &|| false
            )
            .err(),
            Some(OnnxError::Limit)
        );
    }
    assert_eq!(
        decode_onnx_dfl_head(
            import(&source)?,
            &decode,
            DECODED,
            target,
            scores,
            OnnxLimits {
                work_units: full.work_units() - 1,
                ..exact
            },
            &|| false
        )
        .err(),
        Some(OnnxError::WorkBudget)
    );
    Ok(())
}

#[test]
fn transform_cancellation_at_early_middle_and_final_checkpoints_returns_no_partial_graph() -> Test {
    let source = source(&[1, 30, 30]);
    let decode = policy(OnnxHeadLayout::Rows, 7, &[4, 8]);
    let calls = Cell::new(0_usize);
    let full = decode_onnx_dfl_head(
        import(&source)?,
        &decode,
        DECODED,
        [16, 24],
        2,
        OnnxLimits::default(),
        &|| {
            calls.set(calls.get() + 1);
            false
        },
    )?;
    assert!(calls.get() > 10);
    for deadline in [1, calls.get() / 2, calls.get()] {
        let count = Cell::new(0_usize);
        assert_eq!(
            decode_onnx_dfl_head(
                import(&source)?,
                &decode,
                DECODED,
                [16, 24],
                2,
                OnnxLimits::default(),
                &|| {
                    count.set(count.get() + 1);
                    count.get() >= deadline
                }
            )
            .err(),
            Some(OnnxError::Cancelled)
        );
    }
    let repeated = adapted(&source, &decode, [16, 24], 2)?;
    assert_eq!(
        encode_canonical_model_ir(full.graph())?,
        encode_canonical_model_ir(repeated.graph())?
    );
    assert_eq!(full.source(), source);
    Ok(())
}

#[test]
fn native_execution_accounts_decode_helpers_and_preserves_quota_cancel_and_generation_refusals()
-> Test {
    let source = source(&[1, 2, 18]);
    let model = adapted(&source, &policy(OnnxHeadLayout::Rows, 4, &[8]), [8, 16], 2)?;
    let raw = values(2, 4, 2, true);
    let inputs = bindings(&model, &raw)?;
    let full = execute(&model, &raw)?;
    assert_eq!(
        full.node_output_digests().len(),
        model.graph().nodes().len()
    );
    assert!(full.executed_macs() > 0);
    assert!(full.allocated_bytes() > 0);
    let exact = ExecBudget::new(full.executed_macs(), full.allocated_bytes());
    assert!(ScalarExecutor::run(model.graph(), &inputs, exact, &ScalarExecCx::new()).is_ok());
    for budget in [
        ExecBudget::new(exact.max_macs - 1, exact.max_bytes),
        ExecBudget::new(exact.max_macs, exact.max_bytes - 1),
    ] {
        assert!(matches!(
            ScalarExecutor::run(model.graph(), &inputs, budget, &ScalarExecCx::new()),
            Err(ExecError::BudgetExceeded { .. })
        ));
    }
    let cx = ScalarExecCx::new();
    cx.request_cancellation();
    assert!(matches!(
        ScalarExecutor::run(model.graph(), &inputs, exact, &cx),
        Err(ExecError::CancellationRequested { .. })
    ));
    assert!(cx.is_drain_completed());
    let mut wrong = inputs;
    let supplied = wrong
        .iter_mut()
        .find(|(name, _)| name == INPUT)
        .ok_or("raw input missing")?;
    supplied.1 = Tensor::from_values(
        Shape::new(vec![1, 2, 18])?,
        &raw,
        Generation(GENERATION.0 + 1),
    )?;
    assert!(ScalarExecutor::run(model.graph(), &wrong, exact, &ScalarExecCx::new()).is_err());
    Ok(())
}
