#![forbid(unsafe_code)]
//! Admission for the retired, unbound corroboration score-calibration interface.
//!
//! A Wilson-bin digest alone does not bind a score to a detector package, model, head, class,
//! analysis, deployment prior, or observable coverage. The former interface could calibrate a
//! geometric association score or an owner-supplied camera score, mistake shared-model outputs
//! for independent evidence, and report absence from candidate-selected frames. It also ran
//! after native publication and was silently ignored by whole-recording scans.
//!
//! Reject these options during parsing, before opening a deployment or any input/output path.
//! No corresponding fields remain in `CorroborateAction`, so a typed action cannot bypass this
//! refusal. Calibrated class advice uses the existing, pinned `EventFusionReport` path for both
//! short and whole-recording analysis; it keeps unknown coverage and separate native approvals.

/// Explain migration even for an incomplete or `--option=value` legacy invocation.
pub(super) fn reject_legacy_option(key: &str) -> Result<(), String> {
    let name = key.split_once('=').map_or(key, |(name, _)| name);
    if matches!(name, "--score-calibration" | "--fusion-policy") {
        return Err(format!(
            "{name} is unsupported for corroborate: legacy calibration does not bind scores to an exact detector class/model or establish observable absence; use --fusion-profile PATH --fusion-digest sha256:HEX with --detector-package PATH --detector-digest sha256:HEX --detector-max-inferences N for read-only calibrated class advice (for whole-recording profiles, use fss-fusion-profile)"
        ));
    }
    Ok(())
}
