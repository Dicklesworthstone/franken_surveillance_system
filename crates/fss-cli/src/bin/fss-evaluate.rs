#![forbid(unsafe_code)]
//! Offline, read-only adapter for the reference event-level evaluator.
//!
//! This command scores caller-declared labels and candidates. It does not run a detector,
//! certify coverage, activate thresholds, publish authority, or send alerts.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fss_cli::escape_json_str;
use fss_reference::evaluation::{
    CandidateDisposition, CandidateSet, ClosedIntervalNs, EvaluationError, EvaluationIdentity,
    EvaluationPolicy, EvaluationReport, EventCandidate, FalseAlertBudget, LabelSet, LabeledClip,
    MAX_EVALUATION_CANDIDATES, MAX_EVALUATION_CLIPS, MAX_EVALUATION_NOT_OBSERVABLE_INTERVALS,
    MAX_EVALUATION_TRUTH_EVENTS, NotObservableInterval, NotObservableReason, OperatingPoint,
    PpmMetric, PrPoint, Ratio, TimeToDetectSummary, TruthDisposition, TruthEvent, UndefinedReason,
    evaluate,
};

const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ROW_BYTES: usize = 1024;
const HELP: &str = "fss-evaluate --labels LABELS.tsv --candidates CANDIDATES.tsv \
--pipeline-generation ID --model-generation ID --policy-generation ID \
--max-false-alerts N --per-observed-ns N \
[--early-tolerance-ns N] [--late-tolerance-ns N]\n\n\
Read-only event evaluation; emits JSON to stdout. No threshold is activated.\n\
Labels header: fss-evaluation-labels.v1\n\
Rows (TAB separated):\n\
  clip  CLIP_ID  DURATION_NS\n\
  truth  EVENT_ID  CLIP_ID  CLASS  ZONE_OR_-  START_NS  END_NS\n\
  gap  CLIP_ID  START_NS  END_NS  REASON\n\
Candidates header: fss-evaluation-candidates.v1\n\
  candidate  CANDIDATE_ID  CLIP_ID  CLASS  ZONE_OR_-  DETECT_NS  SCORE_PPM\n\n\
Intervals are closed; clips span [0,duration). Scores are integers 0..1000000.\n\
Gap reasons: sensor_down, occluded, uncalibrated, other. Blank lines and # comments\n\
after the header are allowed. Files are limited to 16 MiB; rows to 1024 bytes.\n\
Coverage and generations are caller declarations, not independently verified evidence.\n";

#[derive(Debug)]
struct Failure {
    code: &'static str,
    line: Option<usize>,
}

type Result<T> = std::result::Result<T, Failure>;

impl Failure {
    const fn new(code: &'static str) -> Self {
        Self { code, line: None }
    }

    fn at(mut self, line: usize) -> Self {
        self.line = Some(line);
        self
    }
}

impl From<EvaluationError> for Failure {
    fn from(error: EvaluationError) -> Self {
        Self::new(error.code())
    }
}

struct Options {
    labels: PathBuf,
    candidates: PathBuf,
    identity: EvaluationIdentity,
    policy: EvaluationPolicy,
}

fn integer(value: &str) -> Result<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Failure::new("evaluation.cli.invalid_integer"));
    }
    value.parse().map_err(|_| Failure::new("evaluation.cli.invalid_integer"))
}

fn required<'a>(options: &'a BTreeMap<String, OsString>, key: &str) -> Result<&'a OsStr> {
    options.get(key).map(OsString::as_os_str)
        .ok_or_else(|| Failure::new("evaluation.cli.missing_option"))
}

fn unicode(value: &OsStr) -> Result<&str> {
    value.to_str().ok_or_else(|| Failure::new("evaluation.cli.invalid_unicode"))
}

fn parse_options(args: impl IntoIterator<Item = OsString>) -> Result<Option<Options>> {
    let mut bounded = Vec::new();
    for arg in args {
        if bounded.len() == 18 {
            return Err(Failure::new("evaluation.cli.arguments_limit"));
        }
        bounded.push(arg);
    }
    if bounded.len() == 1 && bounded[0] == OsStr::new("--help") {
        return Ok(None);
    }
    let mut args = bounded.into_iter();
    let mut values = BTreeMap::new();
    while let Some(flag) = args.next() {
        let flag = unicode(&flag)?;
        if !matches!(flag, "--labels" | "--candidates" | "--pipeline-generation"
            | "--model-generation" | "--policy-generation" | "--max-false-alerts"
            | "--per-observed-ns" | "--early-tolerance-ns" | "--late-tolerance-ns") {
            return Err(Failure::new("evaluation.cli.unknown_option"));
        }
        let value = args.next().ok_or_else(|| Failure::new("evaluation.cli.missing_value"))?;
        if value.to_str().is_some_and(|text| text.starts_with("--")) {
            return Err(Failure::new("evaluation.cli.missing_value"));
        }
        if values.insert(flag.to_owned(), value).is_some() {
            return Err(Failure::new("evaluation.cli.duplicate_option"));
        }
    }
    let identity = EvaluationIdentity {
        pipeline_generation: unicode(required(&values, "--pipeline-generation")?)?.to_owned(),
        model_generation: unicode(required(&values, "--model-generation")?)?.to_owned(),
        policy_generation: unicode(required(&values, "--policy-generation")?)?.to_owned(),
    };
    let optional_number = |key| -> Result<u64> {
        values.get(key).map_or(Ok(0), |value| integer(unicode(value)?))
    };
    let policy = EvaluationPolicy {
        early_tolerance_ns: optional_number("--early-tolerance-ns")?,
        late_tolerance_ns: optional_number("--late-tolerance-ns")?,
        false_alert_budget: FalseAlertBudget {
            max_false_alerts: integer(unicode(required(&values, "--max-false-alerts")?)?)?,
            per_observed_ns: integer(unicode(required(&values, "--per-observed-ns")?)?)?,
        },
    };
    if policy.false_alert_budget.per_observed_ns == 0 {
        return Err(Failure::new("evaluation.invalid_budget"));
    }
    Ok(Some(Options {
        labels: PathBuf::from(required(&values, "--labels")?),
        candidates: PathBuf::from(required(&values, "--candidates")?),
        identity,
        policy,
    }))
}

fn read_input(path: &Path) -> Result<String> {
    let io_error = |_| Failure::new("evaluation.cli.input_io");
    let metadata = std::fs::metadata(path).map_err(io_error)?;
    if !metadata.is_file() {
        return Err(Failure::new("evaluation.cli.not_regular_file"));
    }
    if metadata.len() > MAX_INPUT_BYTES {
        return Err(Failure::new("evaluation.cli.input_limit"));
    }
    let file = File::open(path).map_err(io_error)?;
    if !file.metadata().map_err(io_error)?.is_file() {
        return Err(Failure::new("evaluation.cli.not_regular_file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_INPUT_BYTES + 1).read_to_end(&mut bytes).map_err(io_error)?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(Failure::new("evaluation.cli.input_limit"));
    }
    String::from_utf8(bytes).map_err(|_| Failure::new("evaluation.cli.invalid_unicode"))
}

fn rows<'a>(input: &'a str, header: &str) -> Result<Vec<(usize, Vec<&'a str>)>> {
    if input.len() as u64 > MAX_INPUT_BYTES {
        return Err(Failure::new("evaluation.cli.input_limit"));
    }
    let mut lines = input.lines();
    if lines.next() != Some(header) {
        return Err(Failure::new("evaluation.cli.schema").at(1));
    }
    let mut result = Vec::new();
    for (offset, line) in lines.enumerate() {
        let number = offset + 2;
        if line.len() > MAX_ROW_BYTES {
            return Err(Failure::new("evaluation.cli.row_limit").at(number));
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Reject excessive fields before collecting: malformed rows cannot inflate allocations.
        if line.bytes().filter(|byte| *byte == b'\t').count() > 6 {
            return Err(Failure::new("evaluation.cli.invalid_row").at(number));
        }
        if result.len() == MAX_EVALUATION_CANDIDATES {
            return Err(Failure::new("evaluation.cli.rows_limit").at(number));
        }
        result.push((number, line.split('\t').collect()));
    }
    Ok(result)
}

fn zone(value: &str) -> Option<String> {
    (value != "-").then(|| value.to_owned())
}

fn limit(current: usize, maximum: usize) -> Result<()> {
    if current >= maximum {
        Err(Failure::new("evaluation.limit_exceeded"))
    } else {
        Ok(())
    }
}

fn parse_labels(input: &str) -> Result<LabelSet> {
    let mut clips: BTreeMap<String, LabeledClip> = BTreeMap::new();
    let mut events = Vec::new();
    let mut gaps = Vec::new();
    for (line, fields) in rows(input, "fss-evaluation-labels.v1")? {
        let parsed = (|| -> Result<()> {
            match fields.as_slice() {
                ["clip", id, duration] => {
                    limit(clips.len(), MAX_EVALUATION_CLIPS)?;
                    let clip = LabeledClip {
                        clip_id: (*id).to_owned(), duration_ns: integer(duration)?,
                        not_observable: Vec::new(),
                    };
                    if clips.insert((*id).to_owned(), clip).is_some() {
                        return Err(Failure::new("evaluation.duplicate_id"));
                    }
                }
                ["truth", id, clip, class, area, start, end] => {
                    limit(events.len(), MAX_EVALUATION_TRUTH_EVENTS)?;
                    events.push(TruthEvent {
                        event_id: (*id).to_owned(), clip_id: (*clip).to_owned(),
                        class: (*class).to_owned(), zone: zone(area),
                        interval: ClosedIntervalNs::new(integer(start)?, integer(end)?),
                    });
                }
                ["gap", clip, start, end, reason] => {
                    limit(gaps.len(), MAX_EVALUATION_NOT_OBSERVABLE_INTERVALS)?;
                    let reason = NotObservableReason::parse(reason)
                        .ok_or_else(|| Failure::new("evaluation.cli.gap_reason"))?;
                    gaps.push(((*clip).to_owned(), NotObservableInterval {
                        interval: ClosedIntervalNs::new(integer(start)?, integer(end)?), reason,
                    }, line));
                }
                _ => return Err(Failure::new("evaluation.cli.invalid_row")),
            }
            Ok(())
        })();
        parsed.map_err(|error| error.at(line))?;
    }
    for (clip, gap, line) in gaps {
        clips.get_mut(&clip).ok_or_else(|| Failure::new("evaluation.unknown_clip").at(line))?
            .not_observable.push(gap);
    }
    Ok(LabelSet { clips: clips.into_values().collect(), events })
}

fn parse_candidates(input: &str) -> Result<CandidateSet> {
    let mut candidates = Vec::new();
    for (line, fields) in rows(input, "fss-evaluation-candidates.v1")? {
        let parsed = (|| -> Result<EventCandidate> {
            match fields.as_slice() {
                ["candidate", id, clip, class, area, at, score] => Ok(EventCandidate {
                    candidate_id: (*id).to_owned(), clip_id: (*clip).to_owned(),
                    class: (*class).to_owned(), zone: zone(area), detect_ns: integer(at)?,
                    score_ppm: u32::try_from(integer(score)?)
                        .map_err(|_| Failure::new("evaluation.score_out_of_range"))?,
                }),
                _ => Err(Failure::new("evaluation.cli.invalid_row")),
            }
        })();
        candidates.push(parsed.map_err(|error| error.at(line))?);
    }
    Ok(CandidateSet { candidates })
}

fn text(value: &str) -> String {
    format!("\"{}\"", escape_json_str(value))
}

fn object(fields: &[(&str, String)]) -> String {
    format!("{{{}}}", fields.iter().map(|(key, value)| format!("{}:{value}", text(key)))
        .collect::<Vec<_>>().join(","))
}

fn array(values: impl IntoIterator<Item = String>) -> String {
    format!("[{}]", values.into_iter().collect::<Vec<_>>().join(","))
}

fn undefined(reason: UndefinedReason) -> String {
    let reason = match reason {
        UndefinedReason::NoObservableTruthEvents => "no_observable_truth_events",
        UndefinedReason::NoScoredCandidates => "no_scored_candidates",
        UndefinedReason::NoObservedTime => "no_observed_time",
    };
    object(&[("state", text("undefined")), ("reason", text(reason))])
}

fn ratio(value: Ratio) -> String {
    match value {
        Ratio::Defined { numerator, denominator } => object(&[
            ("state", text("defined")), ("numerator", numerator.to_string()),
            ("denominator", denominator.to_string()),
        ]),
        Ratio::Undefined(reason) => undefined(reason),
    }
}

fn ppm(value: PpmMetric) -> String {
    match value {
        PpmMetric::Defined(value) => object(&[("state", text("defined")), ("ppm", value.to_string())]),
        PpmMetric::Undefined(reason) => undefined(reason),
    }
}

fn timing(value: Option<TimeToDetectSummary>) -> String {
    match value {
        Some(value) => object(&[
            ("state", text("defined")), ("count", value.count.to_string()),
            ("min_ns", text(&value.min_ns.to_string())),
            ("median_ns", text(&value.median_ns.to_string())),
            ("max_ns", text(&value.max_ns.to_string())),
        ]),
        None => object(&[("state", text("undefined")), ("reason", text("no_detected_observable_events"))]),
    }
}

fn point(value: &PrPoint) -> String {
    object(&[
        ("threshold_ppm", value.threshold_ppm.to_string()),
        ("true_positives", value.true_positives.to_string()),
        ("false_positives", value.false_positives.to_string()),
        ("precision", ratio(value.precision)), ("recall", ratio(value.recall)),
        ("within_false_alert_budget", value.within_false_alert_budget.to_string()),
    ])
}

fn operating(value: OperatingPoint) -> String {
    match value {
        OperatingPoint::WithinBudget { point: selected, time_to_detect } => object(&[
            ("state", text("within_budget")), ("point", point(&selected)),
            ("time_to_detect", timing(time_to_detect)),
        ]),
        OperatingPoint::NoThresholdWithinBudget { false_positives_at_highest_threshold } => object(&[
            ("state", text("no_threshold_within_budget")),
            ("false_positives_at_highest_threshold", false_positives_at_highest_threshold.to_string()),
        ]),
        OperatingPoint::NoScoredCandidates => object(&[("state", text("no_scored_candidates"))]),
        OperatingPoint::NoObservedTime => object(&[("state", text("no_observed_time"))]),
    }
}

fn report_json(report: &EvaluationReport) -> String {
    let counts = &report.counts;
    let truth = report.truth_outcomes.iter().map(|outcome| {
        let disposition = match &outcome.disposition {
            TruthDisposition::Detected { candidate_id, score_ppm, time_to_detect_ns } => object(&[
                ("state", text("detected")), ("candidate_id", text(candidate_id)),
                ("score_ppm", score_ppm.to_string()), ("time_to_detect_ns", text(&time_to_detect_ns.to_string())),
            ]),
            TruthDisposition::Missed => object(&[("state", text("missed"))]),
            TruthDisposition::NotObservable { matched_candidate_id } => object(&[
                ("state", text("not_observable")),
                ("matched_candidate_id", matched_candidate_id.as_deref().map_or_else(|| "null".to_owned(), text)),
            ]),
        };
        object(&[("event_id", text(&outcome.event_id)), ("disposition", disposition)])
    });
    let candidates = report.candidate_outcomes.iter().map(|outcome| {
        let disposition = match &outcome.disposition {
            CandidateDisposition::TruePositive { event_id } => object(&[
                ("state", text("true_positive")), ("event_id", text(event_id)),
            ]),
            CandidateDisposition::FalsePositive => object(&[("state", text("false_positive"))]),
            CandidateDisposition::MatchedNotObservableTruth { event_id } => object(&[
                ("state", text("matched_not_observable_truth")), ("event_id", text(event_id)),
            ]),
            CandidateDisposition::InsideNotObservable => object(&[("state", text("inside_not_observable"))]),
        };
        object(&[("candidate_id", text(&outcome.candidate_id)), ("disposition", disposition)])
    });
    object(&[
        ("schema", text("fss.evaluation.cli.v1")),
        ("derived_only", "true".to_owned()), ("threshold_activated", "false".to_owned()),
        ("coverage_basis", text("caller_declared")),
        ("identity", object(&[
            ("pipeline_generation", text(&report.identity.pipeline_generation)),
            ("model_generation", text(&report.identity.model_generation)),
            ("policy_generation", text(&report.identity.policy_generation)),
        ])),
        ("policy", object(&[
            ("early_tolerance_ns", text(&report.policy.early_tolerance_ns.to_string())),
            ("late_tolerance_ns", text(&report.policy.late_tolerance_ns.to_string())),
            ("max_false_alerts", text(&report.policy.false_alert_budget.max_false_alerts.to_string())),
            ("per_observed_ns", text(&report.policy.false_alert_budget.per_observed_ns.to_string())),
        ])),
        ("label_set_digest", text(&report.label_set_digest.to_string())),
        ("candidate_set_digest", text(&report.candidate_set_digest.to_string())),
        ("report_digest", text(&report.digest.to_string())),
        ("counts_full_matching", object(&[
            ("truth_events", counts.truth_events.to_string()),
            ("observable_truth_events", counts.observable_truth_events.to_string()),
            ("not_observable_truth_events", counts.not_observable_truth_events.to_string()),
            ("candidates", counts.candidates.to_string()),
            ("candidates_inside_not_observable", counts.candidates_inside_not_observable.to_string()),
            ("candidates_matched_not_observable_truth", counts.candidates_matched_not_observable_truth.to_string()),
            ("true_positives", counts.true_positives.to_string()),
            ("false_positives", counts.false_positives.to_string()),
            ("false_negatives", counts.false_negatives.to_string()),
        ])),
        ("durations", object(&[
            ("total_ns", text(&report.durations.total_ns.to_string())),
            ("not_observable_ns", text(&report.durations.not_observable_ns.to_string())),
            ("observed_ns", text(&report.durations.observed_ns.to_string())),
        ])),
        ("auprc", ppm(report.auprc)), ("precision", ratio(report.precision)),
        ("recall", ratio(report.recall)), ("operating_point", operating(report.operating_point)),
        ("time_to_detect", timing(report.time_to_detect)),
        ("pr_curve", array(report.pr_curve.iter().map(point))),
        ("truth_outcomes", array(truth)), ("candidate_outcomes", array(candidates)),
    ])
}

fn run(args: impl IntoIterator<Item = OsString>) -> Result<String> {
    let Some(options) = parse_options(args)? else { return Ok(HELP.to_owned()); };
    let labels = parse_labels(&read_input(&options.labels)?)?;
    let candidates = parse_candidates(&read_input(&options.candidates)?)?;
    let report = evaluate(&options.identity, &options.policy, &labels, &candidates)?;
    Ok(report_json(&report))
}

fn main() -> ExitCode {
    match run(std::env::args_os().skip(1)) {
        Ok(output) => {
            let mut stdout = io::stdout().lock();
            if writeln!(stdout, "{output}").is_ok() { ExitCode::SUCCESS } else { ExitCode::FAILURE }
        }
        Err(error) => {
            let diagnostic = object(&[
                ("schema", text("fss.evaluation.cli_error.v1")), ("code", text(error.code)),
                ("line", error.line.map_or_else(|| "null".to_owned(), |line| line.to_string())),
                ("effect_started", "false".to_owned()),
            ]);
            let _ = writeln!(io::stderr().lock(), "{diagnostic}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LABELS: &str = "fss-evaluation-labels.v1\nclip\tc\t1000\ntruth\te\tc\tperson\t-\t100\t200\ngap\tc\t500\t599\tsensor_down\ntruth\thidden\tc\tperson\t-\t510\t550\n";
    const CANDIDATES: &str = "fss-evaluation-candidates.v1\ncandidate\td\tc\tperson\t-\t110\t900000\ncandidate\tfp\tc\tperson\t-\t300\t500000\ncandidate\tgap\tc\tperson\t-\t520\t990000\n";

    fn score(labels: &str, candidates: &str) -> Result<EvaluationReport> {
        Ok(evaluate(&EvaluationIdentity {
            pipeline_generation: "synthetic-pipeline".to_owned(),
            model_generation: "synthetic-model".to_owned(),
            policy_generation: "test-policy".to_owned(),
        }, &EvaluationPolicy {
            early_tolerance_ns: 0, late_tolerance_ns: 0,
            false_alert_budget: FalseAlertBudget { max_false_alerts: 0, per_observed_ns: 1000 },
        }, &parse_labels(labels)?, &parse_candidates(candidates)?)?)
    }

    #[test]
    fn coverage_budget_and_per_event_outcomes_survive_the_adapter() -> Result<()> {
        let report = score(LABELS, CANDIDATES)?;
        assert_eq!(report.auprc, PpmMetric::Defined(1_000_000));
        assert_eq!(report.counts.true_positives, 1);
        assert_eq!(report.counts.false_positives, 1);
        assert_eq!(report.counts.false_negatives, 0);
        assert_eq!(report.counts.not_observable_truth_events, 1);
        assert_eq!(report.counts.candidates_inside_not_observable, 1);
        assert_eq!(report.durations.observed_ns, 900);
        assert!(matches!(report.operating_point, OperatingPoint::WithinBudget { point, .. }
            if point.threshold_ppm == 900_000 && point.false_positives == 0));
        let json = report_json(&report);
        assert!(json.contains("\"threshold_activated\":false"));
        assert!(json.contains("\"state\":\"not_observable\""));
        assert!(json.contains("\"time_to_detect_ns\":\"10\""));
        Ok(())
    }

    #[test]
    fn reordered_rows_produce_identical_report_bytes() -> Result<()> {
        fn reversed(input: &str) -> String {
            let mut lines = input.lines();
            let header = lines.next().unwrap_or_default();
            let mut body: Vec<_> = lines.collect();
            body.reverse();
            format!("{header}\n{}\n", body.join("\n"))
        }
        assert_eq!(report_json(&score(LABELS, CANDIDATES)?),
            report_json(&score(&reversed(LABELS), &reversed(CANDIDATES))?));
        Ok(())
    }

    #[test]
    fn empty_truth_is_undefined_not_perfect() -> Result<()> {
        let report = score("fss-evaluation-labels.v1\nclip\tc\t100\n",
            "fss-evaluation-candidates.v1\n")?;
        assert_eq!(report.auprc, PpmMetric::Undefined(UndefinedReason::NoObservableTruthEvents));
        assert!(report_json(&report).contains("no_observable_truth_events"));
        Ok(())
    }

    #[test]
    fn malformed_and_dangling_rows_are_refused() {
        for labels in ["", "fss-evaluation-labels.v2\n", "fss-evaluation-labels.v1\nclip\tc\t1\textra\n",
            "fss-evaluation-labels.v1\ngap\tmissing\t0\t1\tother\n",
            "fss-evaluation-labels.v1\nclip\tc\t1\nclip\tc\t2\n",
            "fss-evaluation-labels.v1\nclip\tc\t-1\n"] {
            assert!(parse_labels(labels).is_err());
        }
        assert!(parse_candidates("fss-evaluation-candidates.v1\ncandidate\tx\tc\tp\t-\t0\t4294967296\n").is_err());
        assert!(score(LABELS, &CANDIDATES.replace("900000", "1000001")).is_err());
        assert!(score(LABELS, &CANDIDATES.replace("110", "1000")).is_err());
    }

    #[test]
    fn command_line_is_strict() {
        assert!(parse_options([OsString::from("--help")]).is_ok());
        assert!(parse_options([OsString::from("--unknown")]).is_err());
        assert!(parse_options(["--labels", "a", "--labels", "b"].map(OsString::from)).is_err());
        assert!(parse_options(["--labels", "--candidates"].map(OsString::from)).is_err());
        assert!(integer("+1").is_err());
        assert!(integer("18446744073709551616").is_err());
        assert!(integer("1.0").is_err());
    }

    #[test]
    fn json_strings_are_escaped_and_times_are_lossless() {
        assert_eq!(text("a\"\\b"), "\"a\\\"\\\\b\"");
        let summary = timing(Some(TimeToDetectSummary {
            count: 1, min_ns: u64::MAX, median_ns: u64::MAX, max_ns: u64::MAX,
        }));
        assert!(summary.contains("\"18446744073709551615\""));
    }

    #[test]
    fn crlf_comments_and_row_limits_are_explicit() -> Result<()> {
        let labels = parse_labels("fss-evaluation-labels.v1\r\n# example\r\n\r\nclip\tc\t2\r\n")?;
        assert_eq!(labels.clips.len(), 1);
        let oversized = format!("fss-evaluation-labels.v1\n#{}\n", "x".repeat(MAX_ROW_BYTES));
        assert!(parse_labels(&oversized).is_err());
        Ok(())
    }
}
