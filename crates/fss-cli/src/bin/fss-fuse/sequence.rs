#![forbid(unsafe_code)]
//! Bounded offline continuation of the exact source-once fusion owner.
//!
//! The checkpoint pins derived caller-declared state, not source custody or an authenticated
//! history. A separate raw-input inventory prevents calibration binning from concealing source
//! reinterpretation. A complete invocation is admitted before any new checkpoint is written.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use fss_cli::fusion_json::unique_source_step_json;
use fss_core::{CanonicalDecoder, ContractError, DigestAlgorithm};
use fss_fusion::{
    EProcessConfig, MAX_UNIQUE_SOURCES, RegimeResetReason, SourceDisposition, UniqueSourceEProcess,
    UniqueSourceStepOutcome,
};

use super::*;

const REQUEST_SCHEMA: &str = "fss.fusion_sequence.v1";
const REPORT_SCHEMA: &str = "fss.fusion_sequence_report.v1";
const CHECKPOINT_DOMAIN: &str = "fss.fusion.cli_sequence_checkpoint.v1";
const RAW_DOMAIN: &str = "fss.fusion.cli_sequence_raw.v1";
const TRANSCRIPT_DOMAIN: &str = "fss.fusion.cli_sequence_transcript.v1";
const MAX_STEPS: usize = 64;
const MAX_CHECKPOINT_BYTES: usize = 16 * 1024 * 1024;
const MAX_REPORT_BYTES: usize = 16 * 1024 * 1024;
const MAX_RESET_TEXT: usize = 256;

const HELP: &str = "fss-fuse --sequence STEPS.json|- --checkpoint-out NEW_FILE [--calibration FILE]...\n\
  [--checkpoint-in PRIOR_FILE --checkpoint-digest sha256:HEX]\n\n\
Explicit offline source-once continuation. Each run processes at most 64 ordered transitions.\n\
Every invocation supplies schema fss.fusion_sequence.v1, hypothesis, source_limit (1..4096),\n\
config {alert_threshold_mban, floor_mban, ceiling_mban, min_independent_clusters}, and steps.\n\
The hypothesis, numerical config and lifetime source allowance must exactly match a resumed\n\
checkpoint. Observation time never moves backwards; equal-time retries are permitted.\n\n\
Observation: {kind: \"observe\", query: <ordinary fss.fusion_query.v1 or v2>,\n\
  sources: {\"evidence-alias\": \"sha256:HEX\", \"missing-alias\": null}}.\n\
Supply exactly one source binding for every original evidence alias. Observed calibrated rows\n\
require a key. Raw scores retain exact score, calibration digest and generation commitments,\n\
so changing a reused source within one calibration bin also refuses. Repeated source aliases\n\
add no likelihood. Signed and zero observations consume lifetime capacity; nothing is evicted.\n\n\
Reset: {kind: \"reset\", reason: {kind: \"operator_reset\", reason: \"...\"}};\n\
other reasons: {kind: \"sensor_health_degraded\", sensor: \"...\", reason: \"...\"}, or\n\
{kind: \"clock_continuity_broken\", sensor: \"...\", gap_ns: N}. Reset text is 1..256 bytes.\n\
Resets clear numerical evidence but retain consumed sources, raw commitments and ancestry.\n\n\
The input document is bounded to 1 MiB. Checkpoints and complete reports are each <=16 MiB.\n\
The checkpoint is handwritten canonical binary, never JSON state or an editable score.\n\
Resume requires an independently retained SHA-256 from the previous successful report.\n\
Checkpoint bytes, format, bounds, canonical inventory and configuration are verified before use.\n\
The new file must not exist. The complete batch and output size are checked before writing;\n\
input refusal publishes no accepted prefix. A filesystem failure may leave an incomplete new\n\
file; verify it before retrying. The old checkpoint is never replaced.\n\n\
The report includes every effective fusion decision and source receipt, raw-input and sequence\n\
transcript commitments, the source inventory and new checkpoint digest. Replaying the same\n\
steps uninterrupted or across checkpoints gives the same final checkpoint and transcript.\n\
Checkpoints are derived cognition. Digest pinning is integrity, not authentication, current\n\
freshness or rollback protection: the caller owns the latest accepted head. Source identities\n\
remain declarations; no custody, independent errors, anytime validity or effect authority is\n\
created. No sensor, model, event, policy, notification or deployment is activated or changed.\n";

pub(super) fn selected(args: &[OsString]) -> bool {
    args.iter().any(|arg| {
        matches!(
            arg.to_str(),
            Some(
                "--sequence"
                    | "--sequence-help"
                    | "--checkpoint-in"
                    | "--checkpoint-digest"
                    | "--checkpoint-out"
            )
        )
    })
}

fn refusal(detail: impl Into<String>) -> Failure {
    fail("fusion.cli.sequence_invalid", detail)
}

fn exact_keys(map: &BTreeMap<String, Value>, keys: &[&str]) -> Result<()> {
    if map.len() != keys.len() || keys.iter().any(|key| !map.contains_key(*key)) {
        return Err(refusal("unknown or missing sequence fields"));
    }
    Ok(())
}

fn sha(value: &str) -> Result<ContentDigest> {
    let digest = ContentDigest::parse(value).map_err(|_| refusal("invalid SHA-256 identity"))?;
    if digest.algorithm() != DigestAlgorithm::Sha256 || digest.to_text() != value {
        return Err(refusal("expected canonical SHA-256 identity"));
    }
    Ok(digest)
}

fn reset_text(value: &Value, name: &str) -> Result<String> {
    let value = as_text(value, name)?;
    if value.is_empty() || value.len() > MAX_RESET_TEXT || value.chars().any(char::is_control) {
        return Err(refusal(
            "reset text must be bounded and contain no controls",
        ));
    }
    Ok(value)
}

fn reset(value: &Value) -> Result<RegimeResetReason> {
    let map = as_object(value, "reset reason")?;
    match field(map, "kind")?.text() {
        Some("operator_reset") => {
            exact_keys(map, &["kind", "reason"])?;
            Ok(RegimeResetReason::OperatorReset {
                reason: reset_text(field(map, "reason")?, "reason")?,
            })
        }
        Some("sensor_health_degraded") => {
            exact_keys(map, &["kind", "sensor", "reason"])?;
            Ok(RegimeResetReason::SensorHealthDegraded {
                sensor: reset_text(field(map, "sensor")?, "sensor")?,
                reason: reset_text(field(map, "reason")?, "reason")?,
            })
        }
        Some("clock_continuity_broken") => {
            exact_keys(map, &["kind", "sensor", "gap_ns"])?;
            Ok(RegimeResetReason::ClockContinuityBroken {
                sensor: reset_text(field(map, "sensor")?, "sensor")?,
                gap_ns: as_integer(field(map, "gap_ns")?, "gap_ns")?,
            })
        }
        _ => Err(refusal("unknown reset reason")),
    }
}

fn source_bindings(value: &Value) -> Result<BTreeMap<String, Option<ContentDigest>>> {
    as_object(value, "sources")?
        .iter()
        .map(|(id, value)| {
            let source = match value {
                Value::Null => None,
                Value::Text(raw) => {
                    let source = ContentDigest::parse(raw)
                        .map_err(|_| refusal("invalid declared source identity"))?;
                    if source.to_text() != *raw {
                        return Err(refusal("noncanonical declared source identity"));
                    }
                    Some(ContentDigest::new(source.algorithm(), source.bytes()))
                }
                _ => return Err(refusal("source binding must be a digest or explicit null")),
            };
            Ok((id.clone(), source))
        })
        .collect()
}

fn finish(encoder: CanonicalEncoder) -> Result<Vec<u8>> {
    encoder
        .finish_checked()
        .map_err(|_| refusal("sequence canonical encoding bound"))
}

fn optional_digest(encoder: &mut CanonicalEncoder, value: Option<ContentDigest>) {
    encoder.bool(value.is_some());
    if let Some(value) = value {
        encoder.digest(value);
    }
}

fn raw_item(
    query: &FusionQuery,
    item: &EvidenceItem,
    bindings: &CalibrationBindings,
) -> Result<ContentDigest> {
    let mut e = CanonicalEncoder::new();
    e.text(RAW_DOMAIN);
    e.tag(0);
    e.text(&query.kind);
    e.text(&item.sensor);
    if let Some(raw) = bindings
        .scores
        .iter()
        .find(|raw| raw.evidence_id == item.id)
    {
        e.tag(0);
        e.u32(raw.score_ppm);
        raw.calibration.encode(&mut e);
    } else {
        e.tag(1);
        match &item.calibration {
            Calibration::Calibrated { generation, llr } => {
                e.text(generation);
                e.i128(i128::from(llr.lo()));
                e.i128(i128::from(llr.hi()));
            }
            Calibration::Uncalibrated { .. } => return Err(refusal("nonnumeric raw source")),
        }
    }
    Ok(ContentDigest::sha256(&finish(e)?))
}

#[derive(Clone)]
struct State {
    process: UniqueSourceEProcess,
    raw_seen: BTreeMap<ContentDigest, ContentDigest>,
    head: Option<ContentDigest>,
    last_observation_ns: Option<u64>,
}

impl State {
    fn raw_digest(&self) -> Result<ContentDigest> {
        let mut e = CanonicalEncoder::new();
        e.text(RAW_DOMAIN);
        e.tag(1);
        e.u32(self.process.source_limit() as u32);
        e.u32(self.raw_seen.len() as u32);
        for (source, raw) in &self.raw_seen {
            e.digest(*source);
            e.digest(*raw);
        }
        Ok(ContentDigest::sha256(&finish(e)?))
    }

    fn seal(
        &mut self,
        receipt: &UniqueSourceStepOutcome,
        input: Option<ContentDigest>,
    ) -> Result<ContentDigest> {
        let mut e = CanonicalEncoder::new();
        e.text(TRANSCRIPT_DOMAIN);
        optional_digest(&mut e, self.head);
        optional_digest(&mut e, input);
        e.digest(receipt.digest());
        e.digest(self.raw_digest()?);
        e.bool(self.last_observation_ns.is_some());
        if let Some(now) = self.last_observation_ns {
            e.u64(now);
        }
        let head = ContentDigest::sha256(&finish(e)?);
        self.head = Some(head);
        Ok(head)
    }

    fn checkpoint(&self) -> Result<Vec<u8>> {
        if self.raw_seen.len() != self.process.sources_seen()
            || self
                .process
                .admitted_sources()
                .any(|(source, _, _)| !self.raw_seen.contains_key(&source))
        {
            return Err(refusal("incomplete raw source inventory"));
        }
        let core = self
            .process
            .checkpoint()
            .map_err(|error| fail("fusion.cli.checkpoint_invalid", error.to_string()))?;
        let mut e = CanonicalEncoder::new();
        e.text(CHECKPOINT_DOMAIN);
        e.u32(1);
        e.digest(core.digest());
        e.bytes(core.bytes());
        optional_digest(&mut e, self.head);
        e.bool(self.last_observation_ns.is_some());
        if let Some(now) = self.last_observation_ns {
            e.u64(now);
        }
        e.u32(self.raw_seen.len() as u32);
        for (source, raw) in &self.raw_seen {
            e.digest(*source);
            e.digest(*raw);
        }
        let bytes = finish(e)?;
        if bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(fail(
                "fusion.cli.checkpoint_limit",
                "complete checkpoint exceeds 16 MiB",
            ));
        }
        Ok(bytes)
    }

    fn restore(bytes: &[u8], expected: ContentDigest) -> Result<Self> {
        if bytes.len() > MAX_CHECKPOINT_BYTES
            || expected.algorithm() != DigestAlgorithm::Sha256
            || ContentDigest::sha256(bytes) != expected
        {
            return Err(fail(
                "fusion.cli.checkpoint_identity",
                "checkpoint bound or expected digest differs",
            ));
        }
        let decode = |result: std::result::Result<_, ContractError>| {
            result.map_err(|_| refusal("malformed checkpoint"))
        };
        let mut d = CanonicalDecoder::new(bytes);
        if decode(d.text())? != CHECKPOINT_DOMAIN
            || d.u32().map_err(|_| refusal("checkpoint version"))? != 1
        {
            return Err(refusal("unsupported checkpoint profile"));
        }
        let core_digest = d
            .digest()
            .map_err(|_| refusal("checkpoint core identity"))?;
        let core = d.bytes().map_err(|_| refusal("checkpoint core bytes"))?;
        let process = UniqueSourceEProcess::from_checkpoint(core, core_digest)
            .map_err(|error| fail("fusion.cli.checkpoint_invalid", error.to_string()))?;
        let head = if d.bool().map_err(|_| refusal("checkpoint head"))? {
            Some(
                d.digest()
                    .map_err(|_| refusal("checkpoint head identity"))?,
            )
        } else {
            None
        };
        let last_observation_ns = if d
            .bool()
            .map_err(|_| refusal("checkpoint observation time"))?
        {
            Some(
                d.u64()
                    .map_err(|_| refusal("checkpoint observation time"))?,
            )
        } else {
            None
        };
        let count = d.u32().map_err(|_| refusal("checkpoint inventory count"))? as usize;
        if count != process.sources_seen()
            || count > MAX_UNIQUE_SOURCES
            || head.is_some() != (process.accumulator().step_index() != 0)
            || head.is_some_and(|head| head.algorithm() != DigestAlgorithm::Sha256)
            || (last_observation_ns.is_some() && head.is_none())
            || (count > 0 && last_observation_ns.is_none())
        {
            return Err(refusal("inconsistent checkpoint inventories"));
        }
        let mut raw_seen = BTreeMap::new();
        let mut previous = None;
        for _ in 0..count {
            let source = d
                .digest()
                .map_err(|_| refusal("checkpoint source identity"))?;
            let raw = d.digest().map_err(|_| refusal("checkpoint raw identity"))?;
            if previous.is_some_and(|previous| previous >= source)
                || raw.algorithm() != DigestAlgorithm::Sha256
            {
                return Err(refusal("noncanonical checkpoint inventory"));
            }
            previous = Some(source);
            raw_seen.insert(source, raw);
        }
        d.ensure_finished()
            .map_err(|_| refusal("trailing checkpoint bytes"))?;
        if process
            .admitted_sources()
            .any(|(source, _, _)| !raw_seen.contains_key(&source))
        {
            return Err(refusal("checkpoint source inventories disagree"));
        }
        let state = Self {
            process,
            raw_seen,
            head,
            last_observation_ns,
        };
        if state.checkpoint()? != bytes {
            return Err(refusal("checkpoint does not reproduce canonical bytes"));
        }
        Ok(state)
    }
}

fn config(document: &BTreeMap<String, Value>) -> Result<(String, EProcessConfig, usize)> {
    exact_keys(
        document,
        &["schema", "hypothesis", "config", "source_limit", "steps"],
    )?;
    if field(document, "schema")?.text() != Some(REQUEST_SCHEMA) {
        return Err(refusal("expected fss.fusion_sequence.v1"));
    }
    let c = as_object(field(document, "config")?, "config")?;
    exact_keys(
        c,
        &[
            "alert_threshold_mban",
            "floor_mban",
            "ceiling_mban",
            "min_independent_clusters",
        ],
    )?;
    let config = EProcessConfig {
        alert_threshold_mban: as_integer(
            field(c, "alert_threshold_mban")?,
            "alert_threshold_mban",
        )?,
        floor_mban: as_integer(field(c, "floor_mban")?, "floor_mban")?,
        ceiling_mban: as_integer(field(c, "ceiling_mban")?, "ceiling_mban")?,
        min_independent_clusters: as_integer(
            field(c, "min_independent_clusters")?,
            "min_independent_clusters",
        )?,
    };
    config
        .validate()
        .map_err(|error| fail(error.stable_id(), error.to_string()))?;
    let limit: usize = as_integer(field(document, "source_limit")?, "source_limit")?;
    if !(1..=MAX_UNIQUE_SOURCES).contains(&limit) {
        return Err(refusal("source_limit must be in 1..4096"));
    }
    Ok((
        as_text(field(document, "hypothesis")?, "hypothesis")?,
        config,
        limit,
    ))
}

fn execute(
    document: &Value,
    calibrations: &Calibrations,
    prior: Option<State>,
    previous: Option<ContentDigest>,
) -> Result<(String, Vec<u8>)> {
    let document = as_object(document, "sequence")?;
    let (hypothesis, config, limit) = config(document)?;
    let mut state = match prior {
        Some(state)
            if state.process.accumulator().hypothesis_id() == hypothesis
                && *state.process.accumulator().config() == config
                && state.process.source_limit() == limit =>
        {
            state
        }
        Some(_) => {
            return Err(fail(
                "fusion.cli.checkpoint_configuration",
                "hypothesis, numerical config or source limit changed",
            ));
        }
        None => State {
            process: UniqueSourceEProcess::new(&hypothesis, config, limit)
                .map_err(|error| fail(error.stable_id(), error.to_string()))?,
            raw_seen: BTreeMap::new(),
            head: None,
            last_observation_ns: None,
        },
    };
    let steps = field(document, "steps")?
        .array()
        .ok_or_else(|| refusal("steps must be an array"))?;
    if steps.len() > MAX_STEPS {
        return Err(refusal("at most 64 transitions per invocation"));
    }
    let initial_step = state.process.accumulator().step_index();
    let mut rendered = Vec::new();
    let mut rendered_bytes = 0_usize;
    for step in steps {
        let step = as_object(step, "step")?;
        let (receipt, input_binding, decision) = match field(step, "kind")?.text() {
            Some("observe") => {
                exact_keys(step, &["kind", "query", "sources"])?;
                let (query, transit, bindings) = parse_query(field(step, "query")?, calibrations)?;
                // The core validates the complete original query transactionally before
                // admission. Bound adapter provenance work before traversing its rows.
                if query.evidence.len() > fss_fusion::MAX_EVIDENCE {
                    return Err(refusal("too many evidence rows in one observation"));
                }
                if state
                    .last_observation_ns
                    .is_some_and(|last| query.now_ns < last)
                {
                    return Err(refusal("observation time moved backwards"));
                }
                let sources = source_bindings(field(step, "sources")?)?;
                let mut additions = BTreeMap::new();
                for item in &query.evidence {
                    if matches!(item.calibration, Calibration::Calibrated { .. })
                        && item.observability == Observability::Observed
                    {
                        let source = sources
                            .get(&item.id)
                            .copied()
                            .flatten()
                            .ok_or_else(|| refusal("numeric observation needs a source key"))?;
                        let raw = raw_item(&query, item, &bindings)?;
                        if state
                            .raw_seen
                            .get(&source)
                            .or_else(|| additions.get(&source))
                            .is_some_and(|prior| *prior != raw)
                        {
                            return Err(fail(
                                "ERR-FUSION-SOURCE-CONFLICT-001",
                                "reused source changed its exact raw calibration input",
                            ));
                        }
                        additions.insert(source, raw);
                    }
                }
                let input_binding = bindings.digest(query.digest())?;
                let (outcome, receipt) = state
                    .process
                    .observe_step(&query, &sources)
                    .map_err(|error| fail(error.stable_id(), error.to_string()))?;
                for admission in receipt
                    .admissions()
                    .iter()
                    .filter(|admission| admission.disposition() == SourceDisposition::Admitted)
                {
                    let source = admission
                        .source_digest()
                        .ok_or_else(|| refusal("missing admitted source"))?;
                    let raw = additions
                        .get(&source)
                        .copied()
                        .ok_or_else(|| refusal("missing raw source commitment"))?;
                    state.raw_seen.insert(source, raw);
                }
                state.last_observation_ns = Some(query.now_ns);
                // Replayed numeric rows are absent from the effective query. Its provenance must
                // not claim they were calibrated into that decision; the original full raw
                // input remains bound separately above and in the source receipt.
                let effective_aliases: BTreeSet<_> = receipt
                    .admissions()
                    .iter()
                    .filter(|admission| {
                        admission.disposition() != SourceDisposition::AlreadyAdmitted
                    })
                    .map(|admission| admission.evidence_id())
                    .collect();
                let effective_bindings = CalibrationBindings {
                    prior: bindings.prior.clone(),
                    scores: bindings
                        .scores
                        .iter()
                        .filter(|score| effective_aliases.contains(score.evidence_id.as_str()))
                        .cloned()
                        .collect(),
                };
                let effective_binding = effective_bindings.digest(outcome.query_digest)?;
                let decision = outcome_json(
                    &outcome,
                    calibrations,
                    &effective_bindings,
                    effective_binding,
                    transit.as_ref(),
                );
                (receipt, Some(input_binding), decision)
            }
            Some("reset") => {
                exact_keys(step, &["kind", "reason"])?;
                let receipt = state.process.reset_regime(reset(field(step, "reason")?)?);
                (receipt, None, "null".to_owned())
            }
            _ => return Err(refusal("expected observe or reset transition")),
        };
        let head = state.seal(&receipt, input_binding)?;
        let numerical = receipt.step();
        let row = object(&[
            ("step_index", text(&numerical.step_index.to_string())),
            ("regime_epoch", numerical.regime_epoch.to_string()),
            (
                "input_binding_digest",
                input_binding.map_or_else(|| "null".to_owned(), |digest| text(&digest.to_text())),
            ),
            ("source_receipt", unique_source_step_json(&receipt)),
            ("step_delta_millibans", pair(numerical.step_delta_llr)),
            ("accumulated_millibans", pair(numerical.accumulated_llr)),
            (
                "independent_supporting_clusters",
                numerical.independent_supporting_clusters.to_string(),
            ),
            (
                "crossed_alert_threshold",
                numerical.crossed_alert_threshold.to_string(),
            ),
            ("effective_fusion", decision),
            ("sequence_transcript_digest", text(&head.to_text())),
        ]);
        rendered_bytes = rendered_bytes
            .checked_add(row.len())
            .ok_or_else(|| refusal("report size overflow"))?;
        if rendered_bytes > MAX_REPORT_BYTES {
            return Err(fail(
                "fusion.cli.sequence_output_limit",
                "complete report exceeds 16 MiB",
            ));
        }
        rendered.push(row);
    }
    let checkpoint = state.checkpoint()?;
    let checkpoint_digest = ContentDigest::sha256(&checkpoint);
    let output = object(&[
        ("schema", text(REPORT_SCHEMA)),
        ("source_identity_basis", text("caller_declared_unverified")),
        ("hypothesis", text(&hypothesis)),
        ("initial_step_index", text(&initial_step.to_string())),
        (
            "final_step_index",
            text(&state.process.accumulator().step_index().to_string()),
        ),
        ("source_limit", limit.to_string()),
        ("sources_seen", state.process.sources_seen().to_string()),
        (
            "source_inventory_digest",
            text(&state.process.inventory_digest().to_text()),
        ),
        (
            "raw_source_inventory_digest",
            text(&state.raw_digest()?.to_text()),
        ),
        (
            "sequence_transcript_digest",
            state
                .head
                .map_or_else(|| "null".to_owned(), |digest| text(&digest.to_text())),
        ),
        (
            "previous_checkpoint_digest",
            previous.map_or_else(|| "null".to_owned(), |digest| text(&digest.to_text())),
        ),
        ("checkpoint_digest", text(&checkpoint_digest.to_text())),
        ("checkpoint_bytes", checkpoint.len().to_string()),
        (
            "accumulated_millibans",
            pair(state.process.accumulator().accumulated_llr()),
        ),
        ("steps", array(rendered)),
        ("effect_authority", "false".to_owned()),
        ("statistical_validity", text("not_established")),
    ]);
    if output.len() > MAX_REPORT_BYTES {
        return Err(fail(
            "fusion.cli.sequence_output_limit",
            "complete report exceeds 16 MiB",
        ));
    }
    Ok((output, checkpoint))
}

fn read_checkpoint(path: &Path, expected: ContentDigest) -> Result<State> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        fail(
            "fusion.cli.checkpoint_unreadable",
            "checkpoint metadata unavailable",
        )
    })?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_CHECKPOINT_BYTES as u64 {
        return Err(fail(
            "fusion.cli.checkpoint_unreadable",
            "checkpoint must be a bounded regular file",
        ));
    }
    let file = File::open(path).map_err(|_| {
        fail(
            "fusion.cli.checkpoint_unreadable",
            "checkpoint open refused",
        )
    })?;
    if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
        return Err(fail(
            "fusion.cli.checkpoint_unreadable",
            "checkpoint is not a regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_CHECKPOINT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| fail("fusion.cli.checkpoint_unreadable", "checkpoint read failed"))?;
    State::restore(&bytes, expected)
}

fn publish_checkpoint(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| {
        fail(
            "fusion.cli.checkpoint_publication",
            "new checkpoint path unavailable; existing files are never replaced",
        )
    })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| {
            fail(
                "fusion.cli.checkpoint_publication",
                "checkpoint publication unconfirmed; verify any new file before retrying",
            )
        })?;
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        File::open(parent).and_then(|directory| directory.sync_all())
            .map_err(|_| fail("fusion.cli.checkpoint_publication", "checkpoint directory synchronization unconfirmed; verify the new file before retrying"))?;
    }
    Ok(())
}

pub(super) fn run(args: Vec<OsString>) -> Result<String> {
    if args.len() == 1 && args[0] == "--sequence-help" {
        return Ok(HELP.to_owned());
    }
    if args.len() > 2 * (MAX_CALIBRATIONS + 4) {
        return Err(refusal("too many sequence arguments"));
    }
    let mut options = BTreeMap::new();
    let mut calibration_paths = Vec::new();
    let mut iter = args.into_iter();
    while let Some(flag) = iter.next() {
        let flag = flag
            .into_string()
            .map_err(|_| refusal("option name must be UTF-8"))?;
        if !matches!(
            flag.as_str(),
            "--sequence"
                | "--checkpoint-in"
                | "--checkpoint-digest"
                | "--checkpoint-out"
                | "--calibration"
        ) {
            return Err(refusal("unknown or incompatible sequence option"));
        }
        let value = iter.next().ok_or_else(|| refusal("missing option value"))?;
        if value.is_empty() || value.to_str().is_some_and(|value| value.starts_with("--")) {
            return Err(refusal("missing option value"));
        }
        if flag == "--calibration" {
            calibration_paths.push(
                value
                    .into_string()
                    .map_err(|_| refusal("calibration path must be UTF-8"))?,
            );
        } else if options.insert(flag, value).is_some() {
            return Err(refusal("duplicate sequence option"));
        }
    }
    if calibration_paths.len() > MAX_CALIBRATIONS {
        return Err(refusal("at most sixteen calibration artifacts"));
    }
    let sequence = options
        .get("--sequence")
        .and_then(|value| value.to_str())
        .ok_or_else(|| refusal("--sequence requires a UTF-8 path or -"))?;
    let output = PathBuf::from(
        options
            .get("--checkpoint-out")
            .ok_or_else(|| refusal("--checkpoint-out is required"))?,
    );
    if output.as_os_str() == "-" {
        return Err(refusal("checkpoint output requires a new file"));
    }
    let expected = match (
        options.get("--checkpoint-in"),
        options.get("--checkpoint-digest"),
    ) {
        (Some(input), Some(digest)) if input != "-" => Some((
            PathBuf::from(input),
            sha(digest
                .to_str()
                .ok_or_else(|| refusal("checkpoint digest must be UTF-8"))?)?,
        )),
        (None, None) => None,
        _ => {
            return Err(refusal(
                "resume requires both --checkpoint-in FILE and --checkpoint-digest sha256:HEX",
            ));
        }
    };
    if usize::from(sequence == "-")
        + calibration_paths
            .iter()
            .filter(|path| path.as_str() == "-")
            .count()
        > 1
    {
        return Err(refusal("only one input may use stdin"));
    }
    if fs::symlink_metadata(&output).is_ok() {
        return Err(fail(
            "fusion.cli.checkpoint_publication",
            "checkpoint output already exists",
        ));
    }
    let mut calibrations = Calibrations::new();
    let mut generations = BTreeSet::new();
    for path in calibration_paths {
        let calibration = load_calibration(&path)?;
        if !generations.insert(calibration.generation.clone())
            || calibrations
                .insert(calibration.digest.to_text(), calibration)
                .is_some()
        {
            return Err(refusal("duplicate or conflicting calibration identity"));
        }
    }
    let document = read_document(sequence)
        .map_err(|_| fail("fusion.cli.sequence_unreadable", "sequence input refused"))?;
    config(as_object(&document, "sequence")?)?;
    let prior = expected
        .as_ref()
        .map(|(path, digest)| read_checkpoint(path, *digest))
        .transpose()?;
    let (report, checkpoint) = execute(
        &document,
        &calibrations,
        prior,
        expected.map(|(_, digest)| digest),
    )?;
    publish_checkpoint(&output, &checkpoint)?;
    Ok(report)
}

#[cfg(test)]
#[path = "sequence_tests.rs"]
mod tests;
