#![forbid(unsafe_code)]
//! Inert profile authoring from explicit owner choices and labelled counts.
//! No supplied likelihood, probability, calibration digest or analysis scope is trusted.

use super::*;
use super::super::render;

const COUNTS_SCHEMA: &str = "fss.event_class_fusion_counts.v1";
const TABLE_SCHEMA: &str = "fss.score_calibration_counts.v1";

impl EventFusionProfile {
    /// Build an inert profile from a digest-pinned count request and a separately selected
    /// native scope. The request supplies schema, class_index, prior, policy, severity,
    /// looks, now_ns and calibrations. Each calibration supplies sensor, failure_domains,
    /// and a table with schema `fss.score_calibration_counts.v1`, generation and bins
    /// (`lo_ppm`, `true_positives`, `false_positives`). Every choice is explicit.
    ///
    /// Native counts produce the semantic calibration digests and all Wilson intervals.
    /// The ordinary profile decoder remains the final validation owner. The request cannot
    /// override the supplied plan, cascade or coverage set. Neither these pins nor the
    /// generated profile establish deployment calibration or grant effect authority.
    pub fn from_counts_json(
        bytes: &[u8],
        expected: ContentDigest,
        plan: ContentDigest,
        cascade: ContentDigest,
        coverage: &BTreeSet<ContentDigest>,
    ) -> Result<Self> {
        Self::from_counts_scoped(bytes, expected, plan, cascade, coverage, None)
    }

    /// Author a version-two, analysis-root-bound whole-recording watch profile. The supplied
    /// identities must be taken from the complete native report, never invented coverage.
    /// Counts remain an explicit owner applicability assertion, not active calibration policy.
    pub fn from_long_watch_counts_json(
        bytes: &[u8],
        expected: ContentDigest,
        analysis: ContentDigest,
        detector_recipe: ContentDigest,
        analysis_root: ContentDigest,
    ) -> Result<Self> {
        Self::from_counts_scoped(
            bytes, expected, analysis, detector_recipe, &BTreeSet::new(), Some(WholeRecordingScope::Watch(analysis_root)),
        )
    }

    /// Author a version-three profile pinned to both complete camera analyses in native order.
    /// Supplied scope comes from the actual paired report, never from fields in the count request.
    pub fn from_long_corroboration_counts_json(
        bytes: &[u8],
        expected: ContentDigest,
        analysis: ContentDigest,
        detector_recipe: ContentDigest,
        analysis_roots: [ContentDigest; 2],
    ) -> Result<Self> {
        Self::from_counts_scoped(
            bytes, expected, analysis, detector_recipe, &BTreeSet::new(),
            Some(WholeRecordingScope::Corroboration(analysis_roots)),
        )
    }

    fn from_counts_scoped(
        bytes: &[u8],
        expected: ContentDigest,
        plan: ContentDigest,
        cascade: ContentDigest,
        coverage: &BTreeSet<ContentDigest>,
        whole_recording: Option<WholeRecordingScope>,
    ) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_PROFILE_BYTES {
            return Err(EventFusionError::Limit);
        }
        if expected.algorithm() != DigestAlgorithm::Sha256
            || ContentDigest::sha256(bytes) != expected
        {
            return Err(EventFusionError::Profile);
        }
        if (whole_recording.is_none() && (coverage.is_empty() || coverage.len() > 8))
            || (whole_recording.is_some() && !coverage.is_empty())
        {
            return Err(EventFusionError::Profile);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| EventFusionError::Profile)?;
        let document = parse(text).map_err(|_| EventFusionError::Profile)?;
        let request = object(
            &document,
            &[
                "schema", "class_index", "prior", "policy", "severity", "looks",
                "now_ns", "calibrations",
            ],
        )?;
        if text_field(request, "schema")? != COUNTS_SCHEMA {
            return Err(EventFusionError::Profile);
        }
        let bindings = array(field(request, "calibrations")?, 8)?;
        let mut tables = Vec::with_capacity(bindings.len());
        for binding in bindings {
            let binding = object(binding, &["sensor", "failure_domains", "calibration"])?;
            let mut output = binding.clone();
            let table = counts(field(binding, "calibration")?)?;
            output.insert("calibration".to_owned(), calibration_value(&table)?);
            tables.push(Value::Object(output));
        }
        let mut profile = request.clone();
        profile.insert("schema".to_owned(), text_value(SCHEMA));
        profile.insert("plan_digest".to_owned(), text_value(plan));
        profile.insert("cascade_digest".to_owned(), text_value(cascade));
        profile.insert(
            "coverage_digests".to_owned(),
            Value::Array(coverage.iter().map(text_value).collect()),
        );
        profile.insert("calibrations".to_owned(), Value::Array(tables));
        encode_scope(&mut profile, whole_recording);
        let json = encode(&Value::Object(profile))?;
        Self::from_json(json.as_bytes(), ContentDigest::sha256(json.as_bytes()))
    }

    /// Complete deterministic input JSON, without a trailing newline. This is an operator
    /// control document, not canonical evidence. Hash the exact emitted bytes separately
    /// for `--fusion-digest`; `digest()` remains the profile's semantic identity.
    pub fn to_json(&self) -> Result<String> {
        let spec = self.spec();
        let policy = &spec.policy;
        let severity = spec.severity;
        let mut calibrations = Vec::with_capacity(spec.calibrations.len());
        for binding in &spec.calibrations {
            calibrations.push(fields([
                ("sensor", text_value(&binding.sensor)),
                (
                    "failure_domains",
                    Value::Array(binding.failure_domains.iter().map(text_value).collect()),
                ),
                ("calibration", calibration_value(&binding.calibration)?),
            ]));
        }
        let mut document = fields([
            ("schema", text_value(SCHEMA)),
            ("plan_digest", text_value(spec.plan_digest)),
            ("cascade_digest", text_value(spec.cascade_digest)),
            (
                "coverage_digests",
                Value::Array(spec.coverage_digests.iter().map(text_value).collect()),
            ),
            ("class_index", numeric(spec.class_index)),
            ("prior", pair(spec.prior)),
            ("looks", numeric(spec.looks)),
            ("now_ns", numeric(spec.now_ns)),
            (
                "policy",
                fields([
                    ("generation", text_value(&policy.generation)),
                    ("alert_threshold", numeric(policy.alert_threshold)),
                    ("retain_threshold", numeric(policy.retain_threshold)),
                    ("reject_threshold", numeric(policy.reject_threshold)),
                    ("min_independent_support", numeric(policy.min_independent_support)),
                    (
                        "urgent_single_domain_threshold",
                        policy.urgent_single_domain_threshold.map_or(Value::Null, numeric),
                    ),
                    ("max_wait_ns", numeric(policy.max_wait_ns)),
                    ("look_penalty_per_doubling", numeric(policy.look_penalty_per_doubling)),
                    (
                        "operator_confirmation_available",
                        Value::Bool(policy.operator_confirmation_available),
                    ),
                ]),
            ),
            (
                "severity",
                fields([
                    ("expected_harm", numeric(severity.expected_harm)),
                    ("false_alert_cost", numeric(severity.false_alert_cost)),
                    ("delay_cost_per_second", numeric(severity.delay_cost_per_second)),
                    ("reversible", Value::Bool(severity.reversible)),
                ]),
            ),
            ("calibrations", Value::Array(calibrations)),
        ]);
        let Value::Object(fields) = &mut document else {
            return Err(EventFusionError::Profile);
        };
        encode_scope(fields, self.whole_recording);
        encode(&document)
    }
}

fn encode_scope(fields: &mut Object, scope: Option<WholeRecordingScope>) {
    match scope {
        Some(WholeRecordingScope::Watch(root)) => {
            fields.insert("schema".to_owned(), text_value(LONG_WATCH_SCHEMA));
            fields.insert("long_watch_analysis_root".to_owned(), text_value(root));
        }
        Some(WholeRecordingScope::Corroboration(roots)) => {
            fields.insert("schema".to_owned(), text_value(LONG_CORROBORATION_SCHEMA));
            fields.insert("long_corroboration_analysis_roots".to_owned(),
                Value::Array(roots.iter().map(text_value).collect()));
        }
        None => {}
    }
}

fn counts(value: &Value) -> Result<ScoreCalibration> {
    let table = object(value, &["schema", "generation", "bins"])?;
    if text_field(table, "schema")? != TABLE_SCHEMA {
        return Err(EventFusionError::Profile);
    }
    let bins = array(field(table, "bins")?, fss_fusion::calibration::MAX_BINS)?;
    let mut edges = Vec::with_capacity(bins.len());
    let mut counts = Vec::with_capacity(bins.len());
    for bin in bins {
        let bin = object(bin, &["lo_ppm", "true_positives", "false_positives"])?;
        edges.push(number(field(bin, "lo_ppm")?)?);
        counts.push((
            number(field(bin, "true_positives")?)?,
            number(field(bin, "false_positives")?)?,
        ));
    }
    ScoreCalibration::from_counts(text_field(table, "generation")?, &edges, &counts)
        .map_err(|_| EventFusionError::Profile)
}

fn calibration_value(table: &ScoreCalibration) -> Result<Value> {
    // Use the established renderer, not a second implementation of calibration arithmetic.
    parse(&render::count_calibration(table)).map_err(|_| EventFusionError::Profile)
}

fn fields<const N: usize>(rows: [(&str, Value); N]) -> Value {
    Value::Object(rows.into_iter().map(|(key, value)| (key.to_owned(), value)).collect())
}
fn text_value(value: impl ToString) -> Value {
    Value::Text(value.to_string())
}
fn numeric(value: impl ToString) -> Value {
    Value::Number(value.to_string())
}
fn pair(value: LlrInterval) -> Value {
    Value::Array(vec![numeric(value.lo()), numeric(value.hi())])
}

/// Bounded input-document encoding. Values originate only from strict parsed JSON or the
/// typed profile above; arbitrary caller-created Number strings never reach this function.
fn encode(value: &Value) -> Result<String> {
    fn append(out: &mut String, text: &str) -> Result<()> {
        if out.len().checked_add(text.len()).is_none_or(|n| n > MAX_PROFILE_BYTES) {
            return Err(EventFusionError::Limit);
        }
        out.push_str(text);
        Ok(())
    }
    fn write(out: &mut String, value: &Value) -> Result<()> {
        match value {
            Value::Null => append(out, "null"),
            Value::Bool(value) => append(out, if *value { "true" } else { "false" }),
            Value::Number(value) => append(out, value),
            Value::Text(value) => append(out, &render::text(value)),
            Value::Array(values) => {
                append(out, "[")?;
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        append(out, ",")?;
                    }
                    write(out, value)?;
                }
                append(out, "]")
            }
            Value::Object(values) => {
                append(out, "{")?;
                for (index, (key, value)) in values.iter().enumerate() {
                    if index > 0 {
                        append(out, ",")?;
                    }
                    append(out, &render::text(key))?;
                    append(out, ":")?;
                    write(out, value)?;
                }
                append(out, "}")
            }
        }
    }
    let mut output = String::new();
    write(&mut output, value)?;
    Ok(output)
}

#[cfg(test)]
mod tests;
