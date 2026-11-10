#![forbid(unsafe_code)]
//! Strict recipe-v5 binding for separately exported static detector feature levels.

use fss_reference::ingest::onnx_package::{
    OnnxDflPyramidDecode, OnnxDflPyramidLayout, OnnxDflPyramidLevel,
};

use super::{Object, Value, field, integer, object, string};

fn positive(value: &Value, maximum: usize) -> Result<usize, String> {
    if !matches!(value, Value::Number(_)) {
        return Err("DFL pyramid counts and strides require JSON integers".into());
    }
    value
        .integer()
        .and_then(|n| usize::try_from(n).ok())
        .filter(|n| (1..=maximum).contains(n))
        .ok_or_else(|| "DFL pyramid count or stride exceeds its bound".into())
}

pub(super) fn decode(
    root: &Object,
    head: &Object,
    target: [usize; 2],
) -> Result<OnnxDflPyramidDecode, String> {
    let profile = object(field(root, "head_decode")?, &["kind", "bins", "levels"])?;
    if string(profile, "kind")? != "anchor-free-dfl-pyramid" {
        return Err("head_decode.kind requires anchor-free-dfl-pyramid".into());
    }
    let bins = positive(field(profile, "bins")?, 32)?;
    if bins < 2 {
        return Err("DFL pyramid requires 2..=32 bins".into());
    }
    let values = field(profile, "levels")?
        .array()
        .filter(|values| (1..=8).contains(&values.len()))
        .ok_or("DFL pyramid requires 1..=8 explicitly ordered levels")?;
    if target
        .iter()
        .any(|dimension| !(1..=4096).contains(dimension))
        || target[0] * target[1] > 4_194_304
    {
        return Err("DFL pyramid image dimensions exceed the admitted grid bound".into());
    }
    if string(head, "layout")? != "rows" || string(head, "boxes")? != "pixel-corners" {
        return Err("DFL pyramid decoded head requires rows and pixel-corners".into());
    }
    let decoded_output = string(head, "output_port")?;
    let mut rows = 0_usize;
    let mut levels = Vec::new();
    for value in values {
        let level = object(value, &["output", "stride", "layout"])?;
        let stride = positive(field(level, "stride")?, 4096)?;
        if target
            .iter()
            .any(|dimension| !dimension.is_multiple_of(stride))
        {
            return Err("DFL pyramid image dimensions must be divisible by every stride".into());
        }
        rows = rows
            .checked_add((target[0] / stride) * (target[1] / stride))
            .ok_or("DFL pyramid grid row count overflow")?;
        let output = string(level, "output")?;
        if output == decoded_output {
            return Err("DFL pyramid levels must differ from the decoded output".into());
        }
        levels.push(OnnxDflPyramidLevel {
            output,
            stride,
            layout: match string(level, "layout")?.as_str() {
                "nchw" => OnnxDflPyramidLayout::Nchw,
                "nhwc" => OnnxDflPyramidLayout::Nhwc,
                _ => return Err("DFL pyramid level layout requires nchw or nhwc".into()),
            },
        });
    }
    if rows > 32_768 || rows > integer::<usize>(head, "maximum_rows")? {
        return Err("DFL pyramid grid exceeds the declared detection row allowance".into());
    }
    let decode = OnnxDflPyramidDecode { bins, levels };
    decode
        .validate()
        .map_err(|_| "DFL pyramid requires bounded distinct output names and unique strides")?;
    Ok(decode)
}
