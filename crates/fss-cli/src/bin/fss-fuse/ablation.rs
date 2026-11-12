#![forbid(unsafe_code)]
//! Explicit read-only source-loss explanation over a caller-declared query.
//! The outer receipt preserves raw calibration inputs and baseline transit context that
//! normalization into the pure fusion query would otherwise omit.

use fss_cli::fusion_json::{MAX_ABLATION_REPORT_BYTES, fusion_ablation_json};

use super::*;

const SCHEMA: &str = "fss.fusion_ablation_report.v1";
const DOMAIN: &str = "fss.fusion.cli_ablation.v1";

pub(super) fn run(
    query: &FusionQuery,
    targets: &[AblationTarget],
    calibrations: &Calibrations,
    bindings: &CalibrationBindings,
    transit: Option<&TransitPlan>,
) -> Result<String> {
    let explanation = fss_fusion::ablate(query, targets)
        .map_err(|error| fail(error.stable_id(), error.to_string()))?;
    let numerical_json = fusion_ablation_json(&explanation).ok_or_else(|| {
        fail(
            "fusion.cli.ablation_output_limit",
            "complete ablation output or replay query exceeds its byte bound",
        )
    })?;
    let baseline_binding = bindings.digest(explanation.baseline().query_digest)?;
    let counterfactual_binding = bindings.digest(explanation.outcome().query_digest)?;
    let transit_json = transit.map(super::transit_json);
    let transit_digest = transit_json
        .as_ref()
        .map(|json| ContentDigest::sha256(json.as_bytes()));

    let mut encoder = CanonicalEncoder::new();
    encoder.text(DOMAIN);
    encoder.digest(explanation.digest());
    encoder.digest(baseline_binding);
    encoder.digest(counterfactual_binding);
    encoder.u32(calibrations.len() as u32);
    for calibration in calibrations.values() {
        CalibrationIdentity::of(calibration).encode(&mut encoder);
    }
    encoder.bool(transit_digest.is_some());
    if let Some(digest) = transit_digest {
        encoder.digest(digest);
    }
    let report_digest = ContentDigest::sha256(&encoder.finish_checked().map_err(|_| {
        fail(
            "fusion.cli.binding_encoding",
            "ablation provenance exceeds canonical encoding bounds",
        )
    })?);
    let json = object(&[
        ("schema", text(SCHEMA)),
        ("source_scope", text("caller_declared_query")),
        ("ablation", numerical_json),
        (
            "calibration_provenance",
            object(&[
                (
                    "score_calibrations",
                    array(
                        calibrations
                            .values()
                            .map(|calibration| CalibrationIdentity::of(calibration).to_json()),
                    ),
                ),
                (
                    "prior_calibration",
                    bindings
                        .prior
                        .as_ref()
                        .map_or_else(|| "null".to_owned(), CalibrationIdentity::to_json),
                ),
                ("score_calibration_bindings", bindings.scores_json()),
                (
                    "baseline_input_binding_digest",
                    text(&baseline_binding.to_text()),
                ),
                (
                    "counterfactual_input_binding_digest",
                    text(&counterfactual_binding.to_text()),
                ),
            ]),
        ),
        (
            "baseline_transit",
            transit_json.unwrap_or_else(|| "null".to_owned()),
        ),
        (
            "baseline_transit_digest",
            transit_digest.map_or_else(|| "null".to_owned(), |digest| text(&digest.to_text())),
        ),
        ("report_digest", text(&report_digest.to_text())),
        ("native_source_verified", "false".to_owned()),
        ("effect_authority", "false".to_owned()),
    ]);
    // Include the final newline that main writes. The response is released only as a whole.
    if json.len().saturating_add(1) > MAX_ABLATION_REPORT_BYTES {
        return Err(fail(
            "fusion.cli.ablation_output_limit",
            "complete ablation output exceeds sixteen MiB",
        ));
    }
    Ok(json)
}
