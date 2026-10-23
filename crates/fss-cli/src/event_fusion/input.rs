#![forbid(unsafe_code)]
//! Digest-before-parse, bounded owner profile; saved derived calibration values are rechecked.

use super::*;
use crate::json_input::{Value, parse};
use fss_core::DigestAlgorithm;

mod authoring;

/// Maximum complete profile bytes, including all sensor calibration tables.
pub const MAX_PROFILE_BYTES: usize = 256 * 1024;
const SCHEMA: &str = "fss.event_class_fusion_profile.v1";
const LONG_WATCH_SCHEMA: &str = "fss.event_class_fusion_profile.v2";
const LONG_CORROBORATION_SCHEMA: &str = "fss.event_class_fusion_profile.v3";
const LONG_DWELL_SCHEMA: &str = "fss.event_class_fusion_profile.v4";
type Object = BTreeMap<String, Value>;

impl EventFusionProfile {
    /// Verify exact bytes before any JSON/count parsing. This neither reads a file nor activates
    /// calibration. Unknown fields, duplicate keys and mismatched derived values fail closed.
    pub fn from_json(bytes: &[u8], expected: ContentDigest) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_PROFILE_BYTES {
            return Err(EventFusionError::Limit);
        }
        if expected.algorithm() != DigestAlgorithm::Sha256
            || ContentDigest::sha256(bytes) != expected
        {
            return Err(EventFusionError::Profile);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| EventFusionError::Profile)?;
        let document = parse(text).map_err(|_| EventFusionError::Profile)?;
        let root = object(
            &document,
            &[
                "schema",
                "plan_digest",
                "cascade_digest",
                "coverage_digests",
                "class_index",
                "prior",
                "policy",
                "severity",
                "looks",
                "now_ns",
                "calibrations",
                "long_watch_analysis_root",
                "long_corroboration_analysis_roots",
                "long_dwell_analysis_root",
            ],
        )?;
        let whole_recording = match text_field(root, "schema")? {
            SCHEMA
                if !root.contains_key("long_watch_analysis_root")
                    && !root.contains_key("long_corroboration_analysis_roots")
                    && !root.contains_key("long_dwell_analysis_root") =>
            {
                None
            }
            LONG_WATCH_SCHEMA
                if !root.contains_key("long_corroboration_analysis_roots")
                    && !root.contains_key("long_dwell_analysis_root") =>
            {
                Some(WholeRecordingScope::Watch(sha(field(
                    root,
                    "long_watch_analysis_root",
                )?)?))
            }
            LONG_CORROBORATION_SCHEMA
                if !root.contains_key("long_watch_analysis_root")
                    && !root.contains_key("long_dwell_analysis_root") =>
            {
                let roots = array(field(root, "long_corroboration_analysis_roots")?, 2)?;
                let [first, second] = roots else {
                    return Err(EventFusionError::Profile);
                };
                Some(WholeRecordingScope::Corroboration([
                    sha(first)?,
                    sha(second)?,
                ]))
            }
            LONG_DWELL_SCHEMA
                if !root.contains_key("long_watch_analysis_root")
                    && !root.contains_key("long_corroboration_analysis_roots") =>
            {
                Some(WholeRecordingScope::Dwell(sha(field(
                    root,
                    "long_dwell_analysis_root",
                )?)?))
            }
            _ => return Err(EventFusionError::Profile),
        };
        let p = object(
            field(root, "policy")?,
            &[
                "generation",
                "alert_threshold",
                "retain_threshold",
                "reject_threshold",
                "min_independent_support",
                "urgent_single_domain_threshold",
                "max_wait_ns",
                "look_penalty_per_doubling",
                "operator_confirmation_available",
            ],
        )?;
        let s = object(
            field(root, "severity")?,
            &[
                "expected_harm",
                "false_alert_cost",
                "delay_cost_per_second",
                "reversible",
            ],
        )?;
        let bindings = array(field(root, "calibrations")?, 8)?;
        let mut calibrations = Vec::with_capacity(bindings.len());
        for binding in bindings {
            let b = object(binding, &["sensor", "failure_domains", "calibration"])?;
            let mut failure_domains = BTreeSet::new();
            for domain in array(field(b, "failure_domains")?, 8)? {
                let domain = domain.text().ok_or(EventFusionError::Profile)?;
                if !failure_domains.insert(domain.to_owned()) {
                    return Err(EventFusionError::Profile);
                }
            }
            calibrations.push(SensorCalibration {
                sensor: text_field(b, "sensor")?.to_owned(),
                calibration: calibration(field(b, "calibration")?)?,
                failure_domains,
            });
        }
        let mut coverage_digests = BTreeSet::new();
        for value in array(field(root, "coverage_digests")?, 8)? {
            if !coverage_digests.insert(sha(value)?) {
                return Err(EventFusionError::Profile);
            }
        }
        let spec = ClassFusionSpec {
            plan_digest: sha(field(root, "plan_digest")?)?,
            cascade_digest: sha(field(root, "cascade_digest")?)?,
            coverage_digests,
            class_index: number(field(root, "class_index")?)?,
            prior: interval(field(root, "prior")?)?,
            policy: FusionPolicy {
                generation: text_field(p, "generation")?.to_owned(),
                alert_threshold: number(field(p, "alert_threshold")?)?,
                retain_threshold: number(field(p, "retain_threshold")?)?,
                reject_threshold: number(field(p, "reject_threshold")?)?,
                min_independent_support: number(field(p, "min_independent_support")?)?,
                urgent_single_domain_threshold: match field(p, "urgent_single_domain_threshold")? {
                    Value::Null => None,
                    value => Some(number(value)?),
                },
                max_wait_ns: number(field(p, "max_wait_ns")?)?,
                look_penalty_per_doubling: number(field(p, "look_penalty_per_doubling")?)?,
                operator_confirmation_available: boolean(field(
                    p,
                    "operator_confirmation_available",
                )?)?,
            },
            severity: Severity {
                expected_harm: number(field(s, "expected_harm")?)?,
                false_alert_cost: number(field(s, "false_alert_cost")?)?,
                delay_cost_per_second: number(field(s, "delay_cost_per_second")?)?,
                reversible: boolean(field(s, "reversible")?)?,
            },
            looks: number(field(root, "looks")?)?,
            now_ns: number(field(root, "now_ns")?)?,
            calibrations,
        };
        match whole_recording {
            Some(WholeRecordingScope::Watch(root)) => Self::for_long_watch(spec, root),
            Some(WholeRecordingScope::Corroboration(roots)) => {
                Self::for_long_corroboration(spec, roots)
            }
            Some(WholeRecordingScope::Dwell(root)) => Self::for_long_dwell(spec, root),
            None => Self::new(spec),
        }
    }
}
fn object<'a>(value: &'a Value, keys: &[&str]) -> Result<&'a Object> {
    let value = value.object().ok_or(EventFusionError::Profile)?;
    if value.keys().any(|key| !keys.contains(&key.as_str())) {
        return Err(EventFusionError::Profile);
    }
    Ok(value)
}
fn field<'a>(value: &'a Object, key: &str) -> Result<&'a Value> {
    value.get(key).ok_or(EventFusionError::Profile)
}
fn text_field<'a>(value: &'a Object, key: &str) -> Result<&'a str> {
    field(value, key)?.text().ok_or(EventFusionError::Profile)
}
fn array(value: &Value, maximum: usize) -> Result<&[Value]> {
    value
        .array()
        .filter(|items| items.len() <= maximum)
        .ok_or(EventFusionError::Profile)
}
fn number<T: TryFrom<i128>>(value: &Value) -> Result<T> {
    value
        .integer()
        .and_then(|n| T::try_from(n).ok())
        .ok_or(EventFusionError::Profile)
}
fn boolean(value: &Value) -> Result<bool> {
    value.boolean().ok_or(EventFusionError::Profile)
}
fn sha(value: &Value) -> Result<ContentDigest> {
    ContentDigest::parse(value.text().ok_or(EventFusionError::Profile)?)
        .ok()
        .filter(|d| d.algorithm() == DigestAlgorithm::Sha256)
        .ok_or(EventFusionError::Profile)
}
fn interval(value: &Value) -> Result<LlrInterval> {
    let pair = array(value, 2)?;
    if pair.len() != 2 {
        return Err(EventFusionError::Profile);
    }
    LlrInterval::new(number(&pair[0])?, number(&pair[1])?).map_err(|_| EventFusionError::Profile)
}
pub(crate) fn calibration(value: &Value) -> Result<ScoreCalibration> {
    // Accept the score_calibration OBJECT emitted by fss-evaluate, not an arbitrary evaluation
    // report. Counts are authoritative for reconstruction; all supplied derived fields agree.
    let c = object(
        value,
        &[
            "schema",
            "generation",
            "digest",
            "bins",
            "true_positives",
            "false_positives",
            "prior_log_odds_millibans",
            "interval",
        ],
    )?;
    if text_field(c, "schema")? != "fss.score_calibration.v1" {
        return Err(EventFusionError::Profile);
    }
    let generation = text_field(c, "generation")?;
    let bins = array(field(c, "bins")?, fss_fusion::calibration::MAX_BINS)?;
    let mut edges = Vec::with_capacity(bins.len());
    let mut counts = Vec::with_capacity(bins.len());
    for bin in bins {
        let b = object(
            bin,
            &[
                "lo_ppm",
                "hi_ppm",
                "true_positives",
                "false_positives",
                "llr_millibans",
            ],
        )?;
        edges.push(number(field(b, "lo_ppm")?)?);
        counts.push((
            number(field(b, "true_positives")?)?,
            number(field(b, "false_positives")?)?,
        ));
    }
    let rebuilt = ScoreCalibration::from_counts(generation, &edges, &counts)
        .map_err(|_| EventFusionError::Profile)?;
    if sha(field(c, "digest")?)? != rebuilt.digest {
        return Err(EventFusionError::Profile);
    }
    for (name, expected) in [
        ("true_positives", rebuilt.positives),
        ("false_positives", rebuilt.negatives),
    ] {
        if let Some(value) = c.get(name)
            && number::<u64>(value)? != expected
        {
            return Err(EventFusionError::Profile);
        }
    }
    if let Some(value) = c.get("prior_log_odds_millibans")
        && interval(value)? != rebuilt.prior
    {
        return Err(EventFusionError::Profile);
    }
    if let Some(value) = c.get("interval")
        && value.text() != Some("wilson_z2_per_bin_not_simultaneous")
    {
        return Err(EventFusionError::Profile);
    }
    for (bin, actual) in bins.iter().zip(&rebuilt.bins) {
        let b = bin.object().ok_or(EventFusionError::Profile)?;
        if let Some(value) = b.get("hi_ppm")
            && number::<u32>(value)? != actual.hi_ppm
        {
            return Err(EventFusionError::Profile);
        }
        if let Some(value) = b.get("llr_millibans")
            && interval(value)? != actual.llr
        {
            return Err(EventFusionError::Profile);
        }
    }
    Ok(rebuilt)
}
