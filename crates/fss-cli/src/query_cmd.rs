#![forbid(unsafe_code)]
//! AOP-005 CLI projection of the bounded, verified event-record query engine.
//!
//! The reference engine owns selection, plans, receipts and continuation validation. This
//! module only parses explicit predicates and renders the registered envelopes. It never
//! certifies physical absence, executes an affordance or changes a deployment.

use std::path::PathBuf;

use fss_core::{
    AgentCognitiveEnvelope, AgentView, BudgetVector, CanonicalEncode, CognitiveAnswerClass,
    Completeness, EnvelopeBudget, EnvelopeContinuity, EnvelopeProposition, EventId, EventKind,
    EventState, KnowledgeState, ResponseOutcome, ResponseSafeRetry,
};
use fss_reference::agent_follow::{AnchorToken, snapshot_anchor_token};
use fss_reference::agent_orient::{
    DeploymentOrientation, DeploymentSnapshot, OrientLimits, OrientRequest, orient_deployment,
};
use fss_reference::agent_query::{
    CAPABILITY_QUERY, DEFAULT_QUERY_ENTRIES, DeploymentQuery, EventQueryFilter, EventQueryRequest,
    MAX_QUERY_ENTRIES, QueryError, query_deployment,
};

use crate::agent_json;
use crate::error::{CliError, ExitIdentity};
use crate::orient_cmd::history::{self, HistoricalScope};
use crate::orient_cmd::{
    ERR_AGENT_CONTEXT_INCOMPLETE, RenderError, ResponseParts, build_response, collect_options,
    contexts, internal_failure, principal, read_only_boundary, rendered, request_identity,
    required_root, take,
};
use crate::token::ArgToken;

/// Maximum complete response size, including context and JSON escaping. This is a byte
/// ceiling, not token metering. An oversized response is refused, never truncated.
pub const MAX_QUERY_OUTPUT_BYTES: usize = 256 * 1024;

/// Options for an exact bounded metadata read; the principal is an audit label.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryArgs {
    /// Existing deployment root; read-only.
    pub root: PathBuf,
    /// Explicit historical metadata prefix, distinct from a current-head precondition.
    pub at: Option<AnchorToken>,
    /// Native query request, including any exact anchor and continuation preconditions.
    pub request: EventQueryRequest,
    /// Optional typed operational target, probe, or intent dispatch.
    pub ops: Option<ops_targets::OpsDispatch>,
}

fn malformed(option: &str, value: &str, reason: &str, index: usize) -> CliError {
    CliError::MalformedValue {
        option: option.to_owned(),
        value: value.to_owned(),
        reason: reason.to_owned(),
        command: Some("query".to_owned()),
        index,
    }
}

fn number<T: std::str::FromStr + ToString>(
    option: &str,
    value: &str,
    index: usize,
) -> Result<T, CliError> {
    let parsed = value
        .parse::<T>()
        .map_err(|_| malformed(option, value, "expected an integer in range", index))?;
    if parsed.to_string() != value {
        return Err(malformed(
            option,
            value,
            "expected canonical decimal spelling",
            index,
        ));
    }
    Ok(parsed)
}

/// Parses exact conjunctive filters. No natural language, raw offsets, mutation flags or
/// unimplemented query mode is accepted. Time endpoints are independently optional.
pub fn parse_query_args(tokens: &[ArgToken]) -> Result<QueryArgs, CliError> {
    if let Some(target) = detect_ops_query_target(tokens) {
        return parse_ops_query_args(target, tokens);
    }
    let values = collect_options(
        "query",
        tokens,
        &[
            "--target",
            "--root",
            "--principal",
            "--event-id",
            "--kind",
            "--zone",
            "--state",
            "--from-ns",
            "--through-ns",
            "--max-entries",
            "--anchor",
            "--at",
            "--continuation",
        ],
    )?;
    if let Some((_, target, index)) = take(&values, "--target")
        && target != "events"
    {
        return Err(malformed(
            "--target",
            target,
            "expected events for an event-record query",
            *index,
        ));
    }
    let event_id = take(&values, "--event-id")
        .map(|(_, value, index)| {
            EventId::parse(value.clone())
                .map_err(|_| malformed("--event-id", value, "invalid event identity", *index))
        })
        .transpose()?;
    let kind = take(&values, "--kind")
        .map(|(_, value, index)| {
            EventKind::parse(value)
                .map_err(|_| malformed("--kind", value, "unknown event kind", *index))
        })
        .transpose()?;
    let state = take(&values, "--state")
        .map(|(_, value, index)| {
            EventState::parse(value)
                .map_err(|_| malformed("--state", value, "unknown lifecycle state", *index))
        })
        .transpose()?;
    let from_ns = take(&values, "--from-ns")
        .map(|(_, value, index)| number::<i128>("--from-ns", value, *index))
        .transpose()?;
    let through_ns = take(&values, "--through-ns")
        .map(|(_, value, index)| number::<i128>("--through-ns", value, *index))
        .transpose()?;
    let max_entries = take(&values, "--max-entries")
        .map(|(_, value, index)| number::<u32>("--max-entries", value, *index))
        .transpose()?
        .unwrap_or(DEFAULT_QUERY_ENTRIES);
    if !(1..=MAX_QUERY_ENTRIES).contains(&max_entries) {
        return Err(malformed(
            "--max-entries",
            &max_entries.to_string(),
            "expected 1..32",
            0,
        ));
    }
    let expected_anchor = take(&values, "--anchor")
        .map(|(_, value, index)| {
            AnchorToken::parse(value).ok_or_else(|| {
                malformed("--anchor", value, "expected an exact anchor token", *index)
            })
        })
        .transpose()?;
    let at = history::parse("query", &values)?;
    if at.is_some() && expected_anchor.is_some() {
        return Err(malformed(
            "--at",
            "[redacted]",
            "historical --at cannot be combined with the current-head --anchor precondition",
            take(&values, "--at").map_or(0, |(_, _, index)| *index),
        ));
    }
    let request = EventQueryRequest {
        filter: EventQueryFilter {
            event_id,
            kind,
            state,
            zone: take(&values, "--zone").map(|(_, value, _)| value.clone()),
            from_ns,
            through_ns,
        },
        principal: principal("query", &values)?,
        max_entries,
        expected_anchor,
        continuation: take(&values, "--continuation").map(|(_, value, _)| value.clone()),
    };
    request
        .validate()
        .map_err(|error| malformed("query", "[redacted]", &error.to_string(), 0))?;
    Ok(QueryArgs {
        root: required_root("query", &values)?,
        at,
        request,
        ops: None,
    })
}

fn detect_ops_query_target(tokens: &[ArgToken]) -> Option<&'static str> {
    let mut iter = tokens.iter().enumerate();
    while let Some((_, tok)) = iter.next() {
        let raw = tok.as_str();
        let val = if let Some(rest) = raw.strip_prefix("--target=") {
            Some(rest)
        } else if raw == "--target" {
            iter.next().map(|(_, next)| next.as_str())
        } else {
            None
        };
        if let Some(v) = val {
            return match v {
                "cameras" => Some("cameras"),
                "graph" => Some("graph"),
                "fusion" => Some("fusion"),
                "holds" => Some("holds"),
                "privacy-masks" => Some("privacy-masks"),
                _ => None,
            };
        }
    }
    None
}

fn parse_ops_query_args(target: &'static str, tokens: &[ArgToken]) -> Result<QueryArgs, CliError> {
    use std::collections::BTreeSet;
    let mut root: Option<PathBuf> = None;
    let mut principal_raw: Option<String> = None;
    let mut session_raw: Option<String> = None;
    let mut camera_id: Option<String> = None;
    let mut site_id: Option<String> = None;
    let mut projection_raw: Option<String> = None;
    let mut algorithm_raw: Option<String> = None;
    let mut root_node: Option<String> = None;
    let mut event_id_raw: Option<String> = None;
    let mut sensor_raw: Option<String> = None;
    let mut coverage_state = "complete".to_owned();
    let mut prior = (-500_i64, -400_i64);
    let mut alert_threshold = 1000_i64;
    let mut retain_threshold = 0_i64;
    let mut reject_threshold = -1000_i64;
    let mut min_independent_support = 2_u32;
    let mut attested_earliest: Option<i128> = None;
    let mut attested_latest: Option<i128> = None;
    let mut without_sensors: Vec<String> = Vec::new();
    let mut without_domains: Vec<String> = Vec::new();
    let mut granted_capabilities: BTreeSet<String> = BTreeSet::new();
    let mut saw_json = false;

    let mut i = 1_usize; // skip "query"
    while i < tokens.len() {
        let tok = &tokens[i];
        if tok.as_str() == "--json" {
            saw_json = true;
            i += 1;
            continue;
        }
        let (flag, val, idx) = if let Some((k, v)) = tok.as_str().split_once('=') {
            (k, v.to_owned(), tok.index)
        } else {
            let next = tokens.get(i + 1).ok_or_else(|| CliError::MissingValue {
                option: tok.raw.clone(),
                command: Some("query".to_owned()),
                expected: "option value".to_owned(),
            })?;
            i += 1;
            (tok.as_str(), next.raw.clone(), next.index)
        };
        i += 1;
        match flag {
            "--target" => {
                if val != target {
                    return Err(malformed(
                        "--target",
                        &val,
                        "duplicate conflicting --target",
                        idx,
                    ));
                }
            }
            "--root" => {
                if root.is_some() {
                    return Err(malformed("--root", &val, "duplicate --root", idx));
                }
                root = Some(PathBuf::from(val));
            }
            "--principal" => principal_raw = Some(val),
            "--session" => session_raw = Some(val),
            "--capability" => {
                granted_capabilities.insert(val);
            }
            "--camera-id" if target == "cameras" => camera_id = Some(val),
            "--site-id" if target == "cameras" => site_id = Some(val),
            "--projection" if target == "graph" => projection_raw = Some(val),
            "--algorithm" if target == "graph" => algorithm_raw = Some(val),
            "--root-node" if target == "graph" => root_node = Some(val),
            "--event-id" if target == "fusion" => event_id_raw = Some(val),
            "--without-sensor" if target == "fusion" => without_sensors.push(val),
            "--without-domain" if target == "fusion" => without_domains.push(val),
            "--coverage" if target == "fusion" => coverage_state = val,
            "--prior-lo" if target == "fusion" => prior.0 = number::<i64>("--prior-lo", &val, idx)?,
            "--prior-hi" if target == "fusion" => prior.1 = number::<i64>("--prior-hi", &val, idx)?,
            "--alert-threshold" if target == "fusion" => {
                alert_threshold = number::<i64>("--alert-threshold", &val, idx)?;
            }
            "--retain-threshold" if target == "fusion" => {
                retain_threshold = number::<i64>("--retain-threshold", &val, idx)?;
            }
            "--reject-threshold" if target == "fusion" => {
                reject_threshold = number::<i64>("--reject-threshold", &val, idx)?;
            }
            "--min-independent-support" if target == "fusion" => {
                min_independent_support = number::<u32>("--min-independent-support", &val, idx)?;
            }
            "--sensor" if matches!(target, "holds" | "privacy-masks") => sensor_raw = Some(val),
            "--attested-earliest-ns" if target == "holds" => {
                attested_earliest = Some(number::<i128>("--attested-earliest-ns", &val, idx)?);
            }
            "--attested-latest-ns" if target == "holds" => {
                attested_latest = Some(number::<i128>("--attested-latest-ns", &val, idx)?);
            }
            _ => {
                return Err(CliError::UnknownOption {
                    option: flag.to_owned(),
                    command: Some("query".to_owned()),
                    index: idx,
                });
            }
        }
    }
    if !saw_json {
        return Err(CliError::MissingValue {
            option: "--json".to_owned(),
            command: Some("query".to_owned()),
            expected: "agent operational queries require --json".to_owned(),
        });
    }
    let root = root.ok_or_else(|| CliError::MissingValue {
        option: "--root".to_owned(),
        command: Some("query".to_owned()),
        expected: "existing deployment directory path".to_owned(),
    })?;
    let principal_id = fss_core::PrincipalId::parse(
        principal_raw.unwrap_or_else(|| "principal:local-operator".to_owned()),
    )
    .map_err(|_| malformed("--principal", "[redacted]", "invalid principal identity", 0))?;
    let session_id = session_raw
        .map(|s| {
            fss_core::SessionId::parse(s)
                .map_err(|_| malformed("--session", "[redacted]", "invalid session identity", 0))
        })
        .transpose()?;
    let dispatch = match target {
        "cameras" => ops_targets::OpsDispatch::Cameras(ops_targets::cameras::CamerasQueryRequest {
            root: root.clone(),
            principal: principal_id.clone(),
            session_id,
            camera_id,
            site_id,
            granted_capabilities,
        }),
        "graph" => ops_targets::OpsDispatch::Graph(ops_targets::graph::GraphQueryRequest {
            root: root.clone(),
            principal: principal_id.clone(),
            session_id,
            projection: ops_targets::graph::GraphProjectionKind::parse(
                projection_raw.as_deref().unwrap_or("SensorCoverageGraph"),
            )
            .map_err(|e| malformed("--projection", "[redacted]", &e.to_string(), 0))?,
            algorithm: ops_targets::graph::GraphAlgorithmKind::parse(
                algorithm_raw.as_deref().unwrap_or("ALG-BRIDGE-001"),
            )
            .map_err(|e| malformed("--algorithm", "[redacted]", &e.to_string(), 0))?,
            root_node,
            granted_capabilities,
        }),
        "fusion" => ops_targets::OpsDispatch::Fusion(ops_targets::fusion::FusionQueryRequest {
            root: root.clone(),
            principal: principal_id.clone(),
            session_id,
            event_id: event_id_raw
                .map(|v| {
                    EventId::parse(v)
                        .map_err(|_| malformed("--event-id", "[redacted]", "invalid event id", 0))
                })
                .transpose()?,
            evidence: Vec::new(),
            prior,
            coverage_state,
            alert_threshold,
            retain_threshold,
            reject_threshold,
            min_independent_support,
            without_sensors,
            without_domains,
            granted_capabilities,
        }),
        "holds" => ops_targets::OpsDispatch::Holds(ops_targets::holds_masks::HoldsQueryRequest {
            root: root.clone(),
            principal: principal_id.clone(),
            session_id,
            sensor: sensor_raw
                .map(|s| {
                    fss_core::SensorId::parse(s)
                        .map_err(|_| malformed("--sensor", "[redacted]", "invalid sensor id", 0))
                })
                .transpose()?,
            attested_now_ns: match (attested_earliest, attested_latest) {
                (Some(a), Some(b)) => Some((a, b)),
                (None, None) => None,
                _ => {
                    return Err(malformed(
                        "--attested-earliest-ns",
                        "[redacted]",
                        "supply both --attested-earliest-ns and --attested-latest-ns",
                        0,
                    ));
                }
            },
            granted_capabilities,
        }),
        "privacy-masks" => ops_targets::OpsDispatch::PrivacyMasks(
            ops_targets::holds_masks::PrivacyMasksQueryRequest {
                root: root.clone(),
                principal: principal_id.clone(),
                session_id,
                sensor: sensor_raw
                    .map(|s| {
                        fss_core::SensorId::parse(s).map_err(|_| {
                            malformed("--sensor", "[redacted]", "invalid sensor id", 0)
                        })
                    })
                    .transpose()?,
                granted_capabilities,
            },
        ),
        _ => {
            return Err(malformed(
                "--target",
                target,
                "unsupported operational target",
                0,
            ));
        }
    };
    Ok(QueryArgs {
        root,
        at: None,
        request: EventQueryRequest {
            filter: EventQueryFilter {
                event_id: None,
                kind: None,
                state: None,
                zone: None,
                from_ns: None,
                through_ns: None,
            },
            principal: principal_id,
            max_entries: DEFAULT_QUERY_ENTRIES,
            expected_anchor: None,
            continuation: None,
        },
        ops: Some(dispatch),
    })
}

fn query_response(
    args: &QueryArgs,
    query: &DeploymentQuery,
    orientation: &DeploymentOrientation,
    historical: Option<&HistoricalScope>,
) -> Result<String, Box<dyn std::error::Error>> {
    let request_digest = historical.map_or(query.request_digest, |scope| {
        request_identity("fss.cli.query.historical_request.v1", |encoder| {
            encoder.digest(query.request_digest);
            scope.encode_request(encoder);
        })
    });
    let text = request_digest.to_text();
    let hex = text.strip_prefix("sha256:").unwrap_or(&text);
    let capsule = orientation.capsule();
    let next = query
        .page
        .next_cursor
        .as_ref()
        .map(|cursor| cursor.token().to_owned());
    let mut epistemic = query.epistemic();
    if let Some(scope) = historical {
        epistemic.propositions.insert(0, scope.proposition());
    }
    epistemic.propositions.push(EnvelopeProposition {
        id: "claim:query:anchor".to_owned(),
        statement: format!(
            "Exact authority/effect-history token: {}",
            query.anchor_token
        ),
        state: KnowledgeState::Known,
        provenance: "derived".to_owned(),
        evidence: vec![query.selection_witness.to_text()],
    });
    // Filtering a catalogue must not remove unrelated critical deployment context. Use the
    // existing bounded orientation, including coverage, tamper, contradictions and effects.
    epistemic
        .propositions
        .extend(capsule.frame.knowledge_cells.iter().map(|cell| {
            EnvelopeProposition {
                id: cell.claim_id().to_owned(),
                statement: cell.disclosable_statement().to_owned(),
                state: cell.knowledge_state(),
                provenance: cell.provenance().as_str().to_owned(),
                evidence: cell
                    .evidence_digests()
                    .iter()
                    .map(|digest| digest.to_text())
                    .collect(),
            }
        }));
    let handles: Vec<_> = query
        .events
        .iter()
        .map(|row| agent_json::EvidenceHandle {
            handle_id: format!("fss://proof/{}", row.event_root),
            object_digest: row.event_root,
            kind: "event_manifest".to_owned(),
            hydration: "H0",
            allowed_hydration: vec!["H0"],
            privacy_class: "private:property".to_owned(),
            availability: "available",
            estimated_cost: BudgetVector::default(),
            required_capability: Some(CAPABILITY_QUERY.to_owned()),
        })
        .collect();
    let (_, affordance_context) = contexts(orientation);
    // Context-refresh actions plus explicit per-hit explanations fit the schema's 64-action
    // ceiling (32 hits + 3 context reads). Do not execute or synthesize affordances.
    let action_ids: Vec<String> = capsule
        .affordances
        .iter()
        .filter(|action| {
            matches!(
                action.affordance_id.as_str(),
                "affordance:orient:reorient"
                    | "affordance:orient:doctor"
                    | "affordance:orient:follow"
            ) || query.events.iter().any(|row| {
                action.affordance_id
                    == format!("affordance:explain:{}", row.event.event_id.as_str())
            })
        })
        .map(|action| action.affordance_id.clone())
        .collect();
    let action_objects =
        agent_json::affordance_objects(&action_ids, &capsule.affordances, &affordance_context)
            .ok_or(RenderError("query affordance objects"))?;
    let frame_digest = capsule.frame.frame_digest()?;
    let decision = request_identity("fss.cli.query.context_decision.v1", |encoder| {
        encoder.digest(query.decision_digest);
        encoder.digest(frame_digest);
        if let Some(scope) = historical {
            scope.encode_request(encoder);
        }
    });
    let cognitive = AgentCognitiveEnvelope::new(
        capsule.contract_basis.clone(),
        format!("request:query:{hex}"),
        format!("response:query:{hex}"),
        format!("trace:query:{hex}"),
        "query",
        "query",
        AgentView::Case.id(),
        CognitiveAnswerClass::BoundedSummary,
        capsule.anchor.clone(),
        epistemic,
        query.coverage(),
        EnvelopeBudget {
            requested_json: agent_json::budget(&orientation.requested),
            consumed_json: agent_json::budget(&orientation.consumed),
            remaining_json: agent_json::remaining(&orientation.requested, &orientation.consumed),
            degraded_dimensions: vec!["query-cpu-and-output-tokens-not-metered".to_owned()],
            marginal_work_declined: Vec::new(),
        },
        handles
            .iter()
            .map(|handle| handle.handle_id.clone())
            .collect(),
        action_ids.clone(),
        EnvelopeContinuity {
            cursor: next.clone(),
            reanchor_triggers: vec!["Any authority or effect-journal advance.".to_owned()],
            session_capsule_digest: None,
            unresolved_obligations: capsule
                .obligations
                .iter()
                .map(|id| id.as_str().to_owned())
                .collect(),
        },
        decision.to_text(),
    )?;
    let payload = agent_json::cognitive_envelope(&cognitive, &handles, &action_objects)
        .ok_or(RenderError("query cognitive envelope"))?;
    // Keep verified warnings even when this page matches no events. Current deletion
    // denials and custody limits apply to historical metadata too.
    let mut warnings = orientation.warnings.clone();
    warnings
        .push("Metadata-only query; no certified physical absence or effect authority.".to_owned());
    if let Some(scope) = historical {
        warnings.push(scope.warning());
    }
    build_response(ResponseParts {
        operation: "query",
        request_digest,
        principal: args.request.principal.clone(),
        session_id: Some(query.session_id.as_str().to_owned()),
        mission_id: Some(query.mission_id.as_str().to_owned()),
        anchor: capsule.anchor.clone(),
        view: AgentView::Case,
        capability: CAPABILITY_QUERY,
        outcome: if next.is_some() { ResponseOutcome::Partial } else { ResponseOutcome::Ok },
        error_id: None,
        payload_schema: AgentCognitiveEnvelope::SCHEMA,
        payload_json: payload,
        epistemic_state: KnowledgeState::Unknown,
        completeness: Completeness::Bounded,
        warnings,
        contradictions: orientation.contradictions.clone(),
        degradation: vec!["Query CPU, output tokens and elapsed latency are not metered. The native latency allowance is not a measurement or enforced deadline.".to_owned()],
        budgets_json: agent_json::budget_summary(&orientation.requested, &orientation.consumed),
        proof_pointers: vec![query.plan.plan_digest().to_text(), query.admission.receipt_digest().to_text(),
            query.selection_witness.to_text(), query.page.page_digest.to_text(), frame_digest.to_text()],
        affordances: action_ids,
        affordance_objects: action_objects,
        decision_fingerprint: decision,
        compression_receipt_id: None,
        continuation: next,
        recovery_class: "safe_read_retry",
        safe_retry: ResponseSafeRetry::YesSameRequest,
        boundary: read_only_boundary("Compiled exact filters and read one event-record page with protected deployment context.".to_owned()),
        created_at_ns: capsule.created_at.0,
        workspace_revision: None,
        idempotency_key: None,
    })
}

fn refusal(
    args: &QueryArgs,
    snapshot: &DeploymentSnapshot,
    reason: &str,
    rebase: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let digest = request_identity("fss.cli.query.refusal.v1", |encoder| {
        encoder.text(&args.request.filter.description());
        encoder.text(args.request.principal.as_str());
        encoder.u32(args.request.max_entries);
        encoder.text(
            args.request
                .expected_anchor
                .as_ref()
                .map_or("", AnchorToken::as_str),
        );
        encoder.text(args.request.continuation.as_deref().unwrap_or(""));
        if let Some(at) = &args.at {
            encoder.text("historical_at");
            encoder.text(at.as_str());
        }
        encoder.text(&snapshot_anchor_token(snapshot));
        encoder.text(reason);
    });
    build_response(ResponseParts {
        operation: "query", request_digest: digest, principal: args.request.principal.clone(),
        session_id: None, mission_id: None, anchor: snapshot.anchor.clone(), view: AgentView::Case,
        capability: CAPABILITY_QUERY, outcome: ResponseOutcome::Refused,
        error_id: Some(ERR_AGENT_CONTEXT_INCOMPLETE), payload_schema: AgentCognitiveEnvelope::SCHEMA,
        payload_json: "null".to_owned(), epistemic_state: KnowledgeState::Unknown,
        completeness: Completeness::Partial, warnings: vec![reason.to_owned()], contradictions: Vec::new(),
        degradation: vec!["No query result was delivered; refusal is not an empty match set. Resource use for this refused read is not metered.".to_owned()],
        budgets_json: agent_json::budget_summary(&BudgetVector::default(), &BudgetVector::default()),
        proof_pointers: Vec::new(), affordances: Vec::new(), affordance_objects: Vec::new(),
        decision_fingerprint: digest, compression_receipt_id: None, continuation: None,
        recovery_class: if rebase { "rebase_required" } else { "operator_action_required" },
        safe_retry: ResponseSafeRetry::No,
        boundary: read_only_boundary("Read refused; refresh the anchor or narrow the admitted bound.".to_owned()),
        created_at_ns: snapshot.latest_evidence_time.0, workspace_revision: None, idempotency_key: None,
    })
}

/// Reads one verified snapshot, invokes the native query engine, and renders one complete
/// registered answer. Neither a smaller page nor an empty match set bypasses a scan failure.
#[must_use]
pub fn execute_query(args: &QueryArgs) -> (String, ExitIdentity) {
    execute_query_with_control(args, &crate::RequestControl::uncancelled())
}

/// Retain one request owner's cancellation through history, projection and delivery.
pub(crate) fn execute_query_with_control(
    args: &QueryArgs,
    control: &crate::RequestControl<'_>,
) -> (String, ExitIdentity) {
    if control.is_cancelled() {
        return crate::request_control::cancelled_read("query", &args.root);
    }
    if let Some(ops) = &args.ops {
        return ops_targets::execute_with_control(ops, control);
    }
    // Public library callers can construct QueryArgs directly. Preserve the same exclusion
    // before opening the deployment rather than reinterpreting a current-head precondition.
    if args.at.is_some() && args.request.expected_anchor.is_some() {
        return (
            crate::orient_cmd::execution_diagnostic(
                "query",
                &args.root,
                crate::error::ERR_CLI_MALFORMED_VALUE,
                ExitIdentity::MALFORMED_VALUE,
            ),
            ExitIdentity::MALFORMED_VALUE,
        );
    }
    let limits = OrientLimits::default();
    let (snapshot, historical) =
        match history::read_with_control("query", &args.root, &limits, args.at.as_ref(), control) {
            Ok(read) => read,
            Err(refusal) => return refusal,
        };
    let deliver = |response: (String, ExitIdentity)| {
        if control.is_cancelled() {
            cancelled_query(args, &snapshot)
        } else {
            response
        }
    };
    if control.is_cancelled() {
        return cancelled_query(args, &snapshot);
    }
    let query_result = query_deployment(&snapshot, &args.request);
    if control.is_cancelled() {
        return cancelled_query(args, &snapshot);
    }
    let query = match query_result {
        Ok(query) => query,
        Err(error) => {
            return deliver(rendered(
                refusal(
                    args,
                    &snapshot,
                    &error.to_string(),
                    matches!(
                        error,
                        QueryError::Continuation(_) | QueryError::AnchorChanged
                    ),
                ),
                ExitIdentity::AGENT_REFUSED,
                "query",
                &args.root,
            ));
        }
    };
    let orient_request = OrientRequest {
        view: AgentView::Brief,
        principal: args.request.principal.clone(),
        budget_tokens: None,
    };
    let orientation_result = orient_deployment(&snapshot, &orient_request, &limits);
    if control.is_cancelled() {
        return cancelled_query(args, &snapshot);
    }
    let orientation = match orientation_result {
        Ok(orientation) => orientation,
        Err(error) => {
            return deliver(rendered(
                refusal(args, &snapshot, &error.to_string(), false),
                ExitIdentity::AGENT_REFUSED,
                "query",
                &args.root,
            ));
        }
    };
    let response = query_response(args, &query, &orientation, historical.as_ref());
    if control.is_cancelled() {
        return cancelled_query(args, &snapshot);
    }
    deliver(match response {
        Ok(output) if output.len() <= MAX_QUERY_OUTPUT_BYTES => (output, ExitIdentity::SUCCESS),
        Ok(_) => rendered(
            refusal(
                args,
                &snapshot,
                "Complete query response exceeds 256 KiB; reduce --max-entries. Nothing was truncated.",
                false,
            ),
            ExitIdentity::AGENT_REFUSED,
            "query",
            &args.root,
        ),
        Err(_) => internal_failure("query", &args.root),
    })
}

fn cancelled_query(args: &QueryArgs, snapshot: &DeploymentSnapshot) -> (String, ExitIdentity) {
    let digest = request_identity("fss.cli.query.cancelled.v1", |encoder| {
        encoder.text(&snapshot_anchor_token(snapshot));
        args.request.principal.encode_canonical(encoder);
        args.request.filter.encode_canonical(encoder);
        encoder.u64(u64::from(args.request.max_entries));
        for token in [
            args.request
                .expected_anchor
                .as_ref()
                .map(AnchorToken::as_str),
            args.request.continuation.as_deref(),
            args.at.as_ref().map(AnchorToken::as_str),
        ] {
            encoder.bool(token.is_some());
            if let Some(token) = token {
                encoder.text(token);
            }
        }
    });
    crate::request_control::cancelled_snapshot_read(
        crate::request_control::CancelledRead {
            command: "query",
            operation: "query",
            root: &args.root,
            request_digest: digest,
            principal: &args.request.principal,
            view: AgentView::Case,
            capability: CAPABILITY_QUERY,
            payload_schema: AgentCognitiveEnvelope::SCHEMA,
        },
        snapshot,
    )
}

/// Privacy-masked H2 (analytic) and H3 (visual keyframe/crop) hydration.
pub mod hydration;

/// Typed operational targets (`cameras`, `graph`, `fusion`, `holds`, `privacy-masks`),
/// cognition-only probes (`probe-detect`, `probe-corroborate`), and approval-gated intents.
pub mod ops_targets;

#[cfg(test)]
mod tests;
