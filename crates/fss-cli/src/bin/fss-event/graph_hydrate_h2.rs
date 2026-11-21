#![forbid(unsafe_code)]
//! `fss-event graph hydrate-h2`: read-only H2 graph-neighborhood decision-artifact hydration
//! over one exact committed event revision (`build_event_h2_graph_neighborhood`).
//!
//! Never reads raw media, never writes deployment state, and never grants effect authority.
//! Preserves v1 `fss query --target evidence-hydration` H0/H1 bounds untouched.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use fss_cli::agent_json::{evidence_anchor, object, string, strings};
use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::hydration::{DecisionArtifactKind, H2_SCHEMA};
use fss_core::{AgentView, ContentDigest, DigestAlgorithm, EventId, PrincipalId, TimestampNs};
use fss_reference::agent_event_hydration::build_event_h2_graph_neighborhood;
use fss_reference::agent_orient::{OrientLimits, OrientRequest, orient_deployment, read_deployment};

type Run<T> = Result<T, Box<dyn Error>>;

const DEFAULT_RETENTION_HORIZON_NS: i128 = 3_600_000_000_000;

const HELP: &str = "fss-event graph hydrate-h2 --root EXISTING_DIR --site SITE\n\
  --event-id ID --revision-digest sha256:HEX --grant GRANT_ID\n\
  [--retention-until-ns N] [--principal ID]\n\
Builds and round-trip verifies an authorized, privacy-redacted H2 GraphNeighborhood\n\
decision artifact for one exact committed event revision. Never reads raw media,\n\
mutates deployment authority, or grants effect authority.\n";

const OPTIONS: &[&str] = &[
    "--root",
    "--site",
    "--principal",
    "--event-id",
    "--revision-digest",
    "--grant",
    "--retention-until-ns",
];

#[derive(Debug, Eq, PartialEq)]
struct HydrateH2Options {
    root: PathBuf,
    site: String,
    principal: PrincipalId,
    event_id: EventId,
    revision_digest: ContentDigest,
    grant_id: String,
    retention_until_ns: Option<i128>,
}

fn req_text<'a>(values: &'a BTreeMap<String, OsString>, key: &str) -> Result<&'a str, String> {
    values
        .get(key)
        .ok_or_else(|| format!("required option {key}"))?
        .to_str()
        .ok_or_else(|| format!("{key} requires UTF-8"))
}

fn parse(args: &[OsString]) -> Result<HydrateH2Options, String> {
    if args.len() > 17 || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096) {
        return Err("argument bounds exceeded".into());
    }
    if args.first().and_then(|arg| arg.to_str()) != Some("hydrate-h2") {
        return Err("expected graph hydrate-h2".into());
    }
    let mut values = BTreeMap::new();
    for pair in args[1..].chunks(2) {
        let key = pair[0].to_str().ok_or("option names require UTF-8")?;
        if !OPTIONS.contains(&key) {
            return Err(format!("unknown option {key}"));
        }
        let value = pair
            .get(1)
            .filter(|v| !v.is_empty() && !v.to_str().is_some_and(|s| s.starts_with("--")))
            .ok_or_else(|| format!("missing value for {key}"))?;
        if values.insert(key.to_owned(), value.clone()).is_some() {
            return Err(format!("duplicate {key}"));
        }
    }
    let root = PathBuf::from(values.get("--root").ok_or("required option --root")?);
    let site = req_text(&values, "--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site)
        .map_err(|_| "invalid site lineage")?;
    let principal_raw = values
        .get("--principal")
        .map_or(Ok("principal:local-operator"), |v| {
            v.to_str().ok_or("--principal requires UTF-8")
        })?;
    let principal = PrincipalId::parse(principal_raw).map_err(|_| "invalid principal ID")?;
    let event_id = EventId::parse(req_text(&values, "--event-id")?)
        .map_err(|_| "invalid --event-id")?;
    let revision_digest = ContentDigest::parse(req_text(&values, "--revision-digest")?)
        .map_err(|_| "invalid --revision-digest")?;
    if revision_digest.algorithm() != DigestAlgorithm::Sha256 || revision_digest.bytes() == [0; 32]
    {
        return Err("--revision-digest requires nonzero SHA-256".into());
    }
    let grant_id = req_text(&values, "--grant")?.trim().to_owned();
    if grant_id.is_empty() || grant_id.len() > 256 {
        return Err("--grant must be 1..=256 non-blank UTF-8 bytes".into());
    }
    let retention_until_ns = if values.contains_key("--retention-until-ns") {
        let raw = req_text(&values, "--retention-until-ns")?;
        let parsed = raw
            .parse::<i128>()
            .map_err(|_| "--retention-until-ns must be a canonical integer")?;
        Some(parsed)
    } else {
        None
    };

    Ok(HydrateH2Options {
        root,
        site,
        principal,
        event_id,
        revision_digest,
        grant_id,
        retention_until_ns,
    })
}

fn run(options: HydrateH2Options) -> Run<String> {
    let limits = OrientLimits::default();
    let snapshot = read_deployment(&options.root, &limits)?;
    if snapshot.anchor.site_lineage != options.site {
        return Err("deployment site lineage mismatch".into());
    }
    let orientation = orient_deployment(
        &snapshot,
        &OrientRequest {
            view: AgentView::Brief,
            principal: options.principal,
            budget_tokens: None,
        },
        &limits,
    )?;
    let retention_until = match options.retention_until_ns {
        Some(ns) => TimestampNs(ns),
        None => TimestampNs(
            snapshot
                .latest_evidence_time
                .0
                .saturating_add(DEFAULT_RETENTION_HORIZON_NS),
        ),
    };
    let artifact = build_event_h2_graph_neighborhood(
        &snapshot,
        &orientation,
        &options.event_id,
        options.revision_digest,
        &options.grant_id,
        retention_until,
    )?;
    let DecisionArtifactKind::GraphNeighborhood(neighborhood) = artifact.artifact_kind() else {
        return Err("unexpected H2 artifact kind".into());
    };
    let proof_roots: Vec<String> = artifact
        .proof_roots()
        .iter()
        .copied()
        .map(ContentDigest::to_text)
        .collect();
    let masked: Vec<String> = neighborhood.masked_attributes().iter().cloned().collect();
    let json = object(&[
        ("schema", string(H2_SCHEMA)),
        ("level", string(artifact.level_id())),
        ("content_type", string(artifact.content_type())),
        ("handle_id", string(artifact.handle_id())),
        ("subject_id", string(artifact.subject_id())),
        ("subject_digest", string(&artifact.subject_digest().to_text())),
        (
            "artifact_digest",
            string(&artifact.artifact_digest().to_text()),
        ),
        (
            "payload_digest",
            string(&artifact.payload_digest().to_text()),
        ),
        ("payload_bytes", artifact.payload().len().to_string()),
        (
            "authorization_grant_id",
            string(artifact.authorization_grant_id()),
        ),
        ("privacy_class", string(artifact.privacy_class())),
        (
            "applied_redaction_transform",
            string(artifact.applied_redaction_transform()),
        ),
        (
            "authorized_and_redacted",
            artifact.is_authorized_and_redacted().to_string(),
        ),
        ("anchor", evidence_anchor(artifact.anchor())),
        (
            "center_entity_id",
            string(neighborhood.center_entity_id()),
        ),
        ("radius_hops", neighborhood.radius_hops().to_string()),
        ("node_count", neighborhood.node_count().to_string()),
        ("edge_count", neighborhood.edge_count().to_string()),
        (
            "subgraph_digest",
            string(&neighborhood.subgraph_digest().to_text()),
        ),
        ("masked_attributes", strings(&masked)),
        ("proof_roots", strings(&proof_roots)),
        ("raw_media_disclosed", "false".into()),
        ("effect_authority", "false".into()),
    ]);
    Ok(format!("{json}\n"))
}

pub(super) fn main(args: &[OsString]) -> ExitCode {
    if args.len() == 2 && ["help", "--help", "-h"].iter().any(|arg| args[1] == *arg) {
        return match io::stdout().lock().write_all(HELP.as_bytes()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        };
    }
    let options = match parse(args) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{ERR_CLI_MALFORMED_VALUE}: {error}; use fss-event graph hydrate-h2 --help");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    match run(options).and_then(|output| {
        io::stdout().lock().write_all(output.as_bytes())?;
        Ok(())
    }) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {error}");
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_core::region::{ContextAuthority, RootAuthoritySpec};
    use fss_core::{
        BudgetVector, CaptureInterval, DecisionPath, EventEvidence, EventHypothesis, EventKind,
        EventState, EvidenceClass, EvidenceEdgeRelation, OperationId, ProbabilityInterval,
    };
    use fss_reference::{
        ADP_REPLAY_ROW_ID, ReferenceDeployment, ReferencePolicyAction, ReferencePolicyDecision,
        ReplayCx, ReplayIoAuthority,
    };
    use std::fs;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Run<Self> {
            for attempt in 0..100_u32 {
                let path = std::env::temp_dir().join(format!(
                    "fss-graph-hydrate-h2-{tag}-{}-{attempt}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Ok(Self(path)),
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e.into()),
                }
            }
            Err(io::Error::other("temp dir capacity").into())
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn hydrate_h2_emits_verified_redacted_graph_neighborhood_and_refuses_wrong_revision()
    -> Run<()> {
        let dir = TempDir::new("e2e")?;
        let root = dir.0.join("deployment");
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:h2-cli".into(),
            operation_id: OperationId::parse("operation:h2-cli")?,
            principal: "operator:h2-cli".into(),
            capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::default(),
            privacy_scope: "privacy:internal".into(),
            retention_scope: "retention:ephemeral".into(),
            anchor_universe: ContentDigest::sha256(b"site:h2-cli"),
            generation: 1,
        })?;
        let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
            &authority,
            dir.0.join("cx"),
        )?);
        let mut deployment = ReferenceDeployment::open(&root, "site:h2-cli", &cx)?;
        let evidence_bytes = b"synthetic h2 cli support assertion";
        deployment.stage_payload(evidence_bytes)?;
        let event = EventHypothesis {
            schema: EventHypothesis::SCHEMA.to_owned(),
            event_id: EventId::parse("event:h2-cli-1")?,
            revision: 1,
            supersedes: None,
            state: EventState::Indeterminate,
            kind: EventKind::UnknownPresence,
            interval: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
            uncertainty_reason: Some("single sensor only".to_owned()),
            zone_ids: vec!["entry".to_owned()],
            track_ids: Vec::new(),
            probability: ProbabilityInterval::new(0.0, 1.0)?,
            evidence: vec![EventEvidence {
                digest: ContentDigest::sha256(evidence_bytes),
                class: EvidenceClass::Assertion,
                failure_domain: "cam:front".to_owned(),
                supports: true,
                relation: EvidenceEdgeRelation::Supports,
                capsule_digest: None,
                identity_digest: None,
            }],
            model_receipts: Vec::new(),
            decision_path: DecisionPath {
                policy_generation: ContentDigest::sha256(b"h2-policy"),
                fingerprint: ContentDigest::sha256(b"h2-fp"),
                abstained: true,
                abstention_reason: Some("single sensor".to_owned()),
            },
        };
        let rev_digest = event.revision_digest();
        event.verify()?;
        deployment.publish_event(
            &ReferencePolicyDecision {
                event,
                action: ReferencePolicyAction::Hold,
            },
            &cx,
        )?;
        drop(deployment);
        cx.drain_and_finalize();

        let argv: Vec<OsString> = vec![
            "hydrate-h2".into(),
            "--root".into(),
            root.as_os_str().to_owned(),
            "--site".into(),
            "site:h2-cli".into(),
            "--event-id".into(),
            "event:h2-cli-1".into(),
            "--revision-digest".into(),
            rev_digest.to_text().into(),
            "--grant".into(),
            "grant:operator-h2-review".into(),
        ];
        let options = parse(&argv).map_err(|e| format!("parse failed: {e}"))?;
        let json = run(options)?;
        assert!(json.contains("\"schema\":\"fss.h2_decision_artifact.v1\""), "{json}");
        assert!(json.contains("\"level\":\"H2\""), "{json}");
        assert!(json.contains("\"authorized_and_redacted\":true"), "{json}");
        assert!(json.contains("\"raw_media_disclosed\":false"), "{json}");
        assert!(json.contains("\"effect_authority\":false"), "{json}");
        assert!(json.contains("\"center_entity_id\":\"event:h2-cli-1\""), "{json}");

        let wrong_rev: Vec<OsString> = vec![
            "hydrate-h2".into(),
            "--root".into(),
            root.as_os_str().to_owned(),
            "--site".into(),
            "site:h2-cli".into(),
            "--event-id".into(),
            "event:h2-cli-1".into(),
            "--revision-digest".into(),
            ContentDigest::sha256(b"wrong-rev").to_text().into(),
            "--grant".into(),
            "grant:operator-h2-review".into(),
        ];
        let wrong_opts = parse(&wrong_rev).map_err(|e| format!("parse failed: {e}"))?;
        assert!(run(wrong_opts).is_err());

        let blank_grant: Vec<OsString> = vec![
            "hydrate-h2".into(),
            "--root".into(),
            root.as_os_str().to_owned(),
            "--site".into(),
            "site:h2-cli".into(),
            "--event-id".into(),
            "event:h2-cli-1".into(),
            "--revision-digest".into(),
            rev_digest.to_text().into(),
            "--grant".into(),
            "   ".into(),
        ];
        assert!(parse(&blank_grant).is_err());
        Ok(())
    }
}
