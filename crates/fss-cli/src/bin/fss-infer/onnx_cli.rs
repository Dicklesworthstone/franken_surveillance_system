#![forbid(unsafe_code)]
//! Explicit local ONNX -> verified, source-preserving RGB detector FMPK provisioning.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fss_cli::json_input::{self, Value};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, ContentDigest, Generation, ModelGeneration, OperationId, PrincipalId,
};
use fss_object::ModelId;
use fss_reference::ingest::onnx_package::{
    MAX_ATTRIBUTION_BYTES, OnnxPackageLimits, OnnxPackageRecipe, OnnxPackageRequest,
    import_onnx_package,
};
use fss_reference::ingest::rgb_detections::{HeadBoxes, HeadClasses, HeadLayout, HeadScore};
use fss_reference::ingest::rgb_package::PackageHeadSpec;
use fss_reference::preprocess::ResizeFilter;
use fss_reference::{ReplayCx, ScalarExecCx};

use super::{RunResult, Values, digest, number, text, value};

const HELP: &str = "fss-infer import-onnx [options]\n\
  --source FILE --source-digest sha256:HEX\n\
  --recipe FILE --recipe-digest sha256:HEX\n\
  --license FILE --license-digest sha256:HEX\n\
  --notice FILE --notice-digest sha256:HEX --output NEW.fmpk\n\
  [--principal ID] [--import-work-units N] [--export-work-units N]\n\
  [--verification-work-units N] [--max-package-bytes N]\n\
  Converts the admitted static F32 ONNX IR 7..9 / default-domain opset 13 profile to\n\
  the existing RGB detector package format. All inputs are local regular files with\n\
  independently supplied SHA-256 pins. Nothing is downloaded or activated.\n\
  Recipe JSON explicitly supplies model/tensor generations, RGB preprocessing,\n\
  decoded detection-head semantics, ordered labels and license-use approval.\n\
  See docs/ONNX_PACKAGE_IMPORT.md for the complete strict recipe and supported profile.\n\
  The original ONNX, exact LICENSE and NOTICE remain inside the package. The package\n\
  must pass the same license, graph, parameter and CPU-backend verifier used by\n\
  package-detect before a new output file is opened. Existing paths are never overwritten.\n\
  Defaults: import work 134217728, total import/export work 268435456, verifier work\n\
  4294967296, package bytes 33554432. These are distinct deterministic allowances.\n\
  Prints exact source, package, manifest, model and contract identities as JSON.\n\
  Output is uncalibrated detector provisioning, not activation or a quality certificate.\n";

#[derive(Debug)]
struct Options {
    source: PathBuf,
    source_digest: ContentDigest,
    recipe: PathBuf,
    recipe_digest: ContentDigest,
    license: PathBuf,
    license_digest: ContentDigest,
    notice: PathBuf,
    notice_digest: ContentDigest,
    output: PathBuf,
    principal: String,
    limits: OnnxPackageLimits,
}

fn parse(args: &[OsString]) -> Result<Option<Options>, String> {
    if args.is_empty() {
        return Ok(None);
    }
    if matches!(args[0].to_str(), Some("help" | "--help" | "-h")) {
        return if args.len() == 1 {
            Ok(None)
        } else {
            Err("help takes no other arguments".into())
        };
    }
    let allowed = [
        "--source",
        "--source-digest",
        "--recipe",
        "--recipe-digest",
        "--license",
        "--license-digest",
        "--notice",
        "--notice-digest",
        "--output",
        "--principal",
        "--import-work-units",
        "--export-work-units",
        "--verification-work-units",
        "--max-package-bytes",
    ];
    let mut values = Values::new();
    for pair in args.chunks(2) {
        let key = pair[0].to_str().ok_or("option names require UTF-8")?;
        if !allowed.contains(&key) {
            return Err(format!("unknown import-onnx option {key}"));
        }
        let v = pair
            .get(1)
            .ok_or_else(|| format!("missing value for {key}"))?;
        if v.is_empty() || v.to_str().is_some_and(|s| s.starts_with("--")) {
            return Err(format!("missing value for {key}"));
        }
        if values.insert(key.to_owned(), v.clone()).is_some() {
            return Err(format!("duplicate {key}"));
        }
    }
    let principal = if values.contains_key("--principal") {
        text(&values, "--principal")?.to_owned()
    } else {
        "principal:local-operator".to_owned()
    };
    PrincipalId::parse(&principal).map_err(|_| "invalid principal ID")?;
    let mut limits = OnnxPackageLimits::default();
    limits.import.work_units = number(
        &values,
        "--import-work-units",
        Some(limits.import.work_units),
    )?;
    limits.export.work_units = number(
        &values,
        "--export-work-units",
        Some(limits.export.work_units),
    )?;
    limits.verification_work = number(
        &values,
        "--verification-work-units",
        Some(limits.verification_work),
    )?;
    limits.package_bytes = number(&values, "--max-package-bytes", Some(limits.package_bytes))?;
    if limits.package_bytes == 0
        || limits.package_bytes > fss_reference::ingest::rgb_package::MAX_RGB_PACKAGE_BYTES
    {
        return Err("package ceiling must be 1..33554432 bytes".into());
    }
    Ok(Some(Options {
        source: PathBuf::from(value(&values, "--source")?),
        source_digest: digest(&values, "--source-digest")?,
        recipe: PathBuf::from(value(&values, "--recipe")?),
        recipe_digest: digest(&values, "--recipe-digest")?,
        license: PathBuf::from(value(&values, "--license")?),
        license_digest: digest(&values, "--license-digest")?,
        notice: PathBuf::from(value(&values, "--notice")?),
        notice_digest: digest(&values, "--notice-digest")?,
        output: PathBuf::from(value(&values, "--output")?),
        principal,
        limits,
    }))
}

type Object = BTreeMap<String, Value>;
fn object<'a>(v: &'a Value, keys: &[&str]) -> Result<&'a Object, String> {
    let o = v.object().ok_or("recipe field requires an object")?;
    if o.len() != keys.len() || o.keys().any(|k| !keys.contains(&k.as_str())) {
        return Err("recipe has missing or unknown fields".into());
    }
    Ok(o)
}
fn field<'a>(o: &'a Object, key: &str) -> Result<&'a Value, String> {
    o.get(key)
        .ok_or_else(|| format!("missing recipe field {key}"))
}
fn string(o: &Object, key: &str) -> Result<String, String> {
    field(o, key)?
        .text()
        .map(str::to_owned)
        .ok_or_else(|| format!("{key} must be text"))
}
fn integer<T: TryFrom<i128>>(o: &Object, key: &str) -> Result<T, String> {
    field(o, key)?
        .integer()
        .and_then(|n| T::try_from(n).ok())
        .ok_or_else(|| format!("{key} must be an in-range integer"))
}
fn boolean(o: &Object, key: &str) -> Result<bool, String> {
    field(o, key)?
        .boolean()
        .ok_or_else(|| format!("{key} must be a boolean"))
}
fn strings(o: &Object, key: &str) -> Result<Vec<String>, String> {
    field(o, key)?
        .array()
        .ok_or_else(|| format!("{key} must be an array"))?
        .iter()
        .map(|v| {
            v.text()
                .map(str::to_owned)
                .ok_or_else(|| format!("{key} requires text entries"))
        })
        .collect()
}
fn score(value: &str) -> Result<HeadScore, String> {
    match value {
        "probability" => Ok(HeadScore::Probability),
        "logit" => Ok(HeadScore::Logit),
        _ => Err("score rule requires probability or logit".into()),
    }
}

fn recipe(bytes: &[u8]) -> Result<OnnxPackageRecipe, String> {
    let json = json_input::parse(std::str::from_utf8(bytes).map_err(|_| "recipe requires UTF-8")?)
        .map_err(|e| e.to_string())?;
    let root = object(
        &json,
        &[
            "format",
            "model_id",
            "model_generation",
            "tensor_generation",
            "preprocess",
            "head",
            "labels",
            "source",
            "license",
        ],
    )?;
    if string(root, "format")? != "fss.onnx_rgb_package_recipe.v1" {
        return Err("unsupported recipe format".into());
    }
    let p = object(
        field(root, "preprocess")?,
        &[
            "image_input",
            "height",
            "width",
            "resize",
            "letterbox_pad",
            "masked_rgb",
            "scale_to_unit",
        ],
    )?;
    let h = object(
        field(root, "head")?,
        &[
            "output_port",
            "layout",
            "boxes",
            "class_score",
            "objectness",
            "classes",
            "minimum_score_ppm",
            "nms_iou_ppm",
            "maximum_rows",
            "maximum_candidates",
            "maximum_detections",
        ],
    )?;
    let s = object(
        field(root, "source")?,
        &["upstream", "revision", "producer"],
    )?;
    let l = object(
        field(root, "license")?,
        &["id", "use_approved", "restrictions"],
    )?;
    let mask = field(p, "masked_rgb")?
        .array()
        .ok_or("masked_rgb requires three bytes")?;
    let [r, g, b] = mask else {
        return Err("masked_rgb requires exactly three bytes".into());
    };
    let byte = |v: &Value| {
        v.integer()
            .and_then(|n| u8::try_from(n).ok())
            .ok_or("masked_rgb entries must be bytes")
    };
    let objectness = string(h, "objectness")?;
    Ok(OnnxPackageRecipe {
        model_id: ModelId::parse(string(root, "model_id")?).map_err(|e| e.to_string())?,
        model_generation: ModelGeneration::parse(string(root, "model_generation")?)
            .map_err(|e| e.to_string())?,
        tensor_generation: Generation(integer(root, "tensor_generation")?),
        image_input: string(p, "image_input")?,
        target: [integer(p, "height")?, integer(p, "width")?],
        filter: match string(p, "resize")?.as_str() {
            "nearest" => ResizeFilter::Nearest,
            "bilinear" => ResizeFilter::Bilinear,
            _ => return Err("resize requires nearest or bilinear".into()),
        },
        letterbox_pad: integer(p, "letterbox_pad")?,
        masked_rgb: [byte(r)?, byte(g)?, byte(b)?],
        scale_to_unit: boolean(p, "scale_to_unit")?,
        head: PackageHeadSpec {
            output_port: string(h, "output_port")?,
            layout: match string(h, "layout")?.as_str() {
                "rows" => HeadLayout::Rows,
                "channels" => HeadLayout::Channels,
                _ => return Err("head layout requires rows or channels".into()),
            },
            boxes: match string(h, "boxes")?.as_str() {
                "pixel-corners" => HeadBoxes::PixelCorners,
                "pixel-center-size" => HeadBoxes::PixelCenterSize,
                "normalized-corners" => HeadBoxes::NormalizedCorners,
                "normalized-center-size" => HeadBoxes::NormalizedCenterSize,
                _ => return Err("unknown box representation".into()),
            },
            class_score: score(&string(h, "class_score")?)?,
            objectness: if objectness == "none" {
                None
            } else {
                Some(score(&objectness)?)
            },
            classes: match string(h, "classes")?.as_str() {
                "best" => HeadClasses::Best,
                "multi-label" => HeadClasses::MultiLabel,
                _ => return Err("classes requires best or multi-label".into()),
            },
            minimum_score_ppm: integer(h, "minimum_score_ppm")?,
            nms_iou_ppm: integer(h, "nms_iou_ppm")?,
            maximum_rows: integer(h, "maximum_rows")?,
            maximum_candidates: integer(h, "maximum_candidates")?,
            maximum_detections: integer(h, "maximum_detections")?,
        },
        labels: strings(root, "labels")?,
        upstream: string(s, "upstream")?,
        revision: string(s, "revision")?,
        producer: string(s, "producer")?,
        license_id: string(l, "id")?,
        use_approved: boolean(l, "use_approved")?,
        restrictions: strings(l, "restrictions")?,
    })
}

fn read(path: &Path, expected: ContentDigest, maximum: usize, cx: &ReplayCx) -> RunResult<Vec<u8>> {
    cx.checkpoint("onnx_cli:read")?;
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err("input must be a non-symlink regular file".into());
    }
    let file = fs::File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err("opened input must be a regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    cx.checkpoint("onnx_cli:read_complete")?;
    if bytes.len() > maximum {
        return Err("input exceeds its byte ceiling".into());
    }
    if ContentDigest::sha256(&bytes) != expected {
        return Err("input digest mismatch".into());
    }
    Ok(bytes)
}

fn run(options: Options, out: &mut impl Write) -> RunResult<()> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:onnx-package-import".into(),
        operation_id: OperationId::parse("operation:onnx-package-import")?,
        principal: options.principal,
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(256 * 1024 * 1024).build()?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:offline-model-provisioning".into(),
        anchor_universe: options.source_digest,
        generation: 1,
    })?;
    authority.validate()?;
    let parent = options
        .output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let cx = ReplayCx::from_context_authority(&authority, parent.to_path_buf())?;
    let scalar = ScalarExecCx::new();
    let result = (|| -> RunResult<()> {
        let source = read(
            &options.source,
            options.source_digest,
            options.limits.import.source_bytes,
            &cx,
        )?;
        let recipe_bytes = read(
            &options.recipe,
            options.recipe_digest,
            json_input::MAX_INPUT_BYTES,
            &cx,
        )?;
        let recipe = recipe(&recipe_bytes).map_err(io::Error::other)?;
        let license = read(
            &options.license,
            options.license_digest,
            MAX_ATTRIBUTION_BYTES,
            &cx,
        )?;
        let notice = read(
            &options.notice,
            options.notice_digest,
            MAX_ATTRIBUTION_BYTES,
            &cx,
        )?;
        let imported = import_onnx_package(
            &OnnxPackageRequest {
                source: &source,
                source_digest: options.source_digest,
                license: &license,
                license_digest: options.license_digest,
                notice: &notice,
                notice_digest: options.notice_digest,
                recipe: &recipe,
            },
            options.limits,
            &cx,
            &scalar,
        )?;
        // Verification completes before any output is opened. create_new also refuses a symlink.
        cx.checkpoint("onnx_cli:export")?;
        let mut open = OpenOptions::new();
        open.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open.mode(0o600);
        }
        let mut output = open.open(&options.output)?;
        output.write_all(imported.archive())?;
        output.sync_all()?;
        cx.checkpoint_post_commit("onnx_cli:export_complete");
        let p = imported.package();
        writeln!(
            out,
            "{{\"format\":\"fss.onnx_rgb_package_import.v1\",\"source\":\"{}\",\"recipe\":\"{}\",\"package\":\"{}\",\"manifest\":\"{}\",\"model\":\"{}\",\"contract\":\"{}\",\"importer\":\"{}\",\"bytes\":{},\"conversion_work\":{},\"activated\":false,\"calibrated\":false}}",
            options.source_digest,
            options.recipe_digest,
            p.archive_digest(),
            p.manifest_digest(),
            p.model().digest(),
            p.contract().digest(),
            p.spec().importer,
            imported.archive().len(),
            imported.conversion_work()
        )?;
        Ok(())
    })();
    scalar.drain_and_finalize();
    cx.drain_and_finalize();
    result
}

pub(super) fn dispatch(args: &[OsString], out: &mut impl Write) -> Option<ExitCode> {
    if args.first().and_then(|s| s.to_str()) != Some("import-onnx") {
        return None;
    }
    Some(match parse(&args[1..]) {
        Ok(None) => {
            if out.write_all(HELP.as_bytes()).is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Ok(Some(options)) => match run(options, out) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!(
                    "{}: {e}; an output write failure may leave a partial new file",
                    fss_cli::ERR_CLI_RUNTIME_FAILURE
                );
                ExitCode::from(fss_cli::ExitIdentity::RUNTIME_FAILURE.code)
            }
        },
        Err(e) => {
            eprintln!(
                "{}: {e}; use fss-infer import-onnx --help",
                fss_cli::ERR_CLI_MALFORMED_VALUE
            );
            ExitCode::from(fss_cli::ExitIdentity::MALFORMED_VALUE.code)
        }
    })
}

#[cfg(test)]
#[path = "onnx_cli_tests.rs"]
mod tests;
