#![forbid(unsafe_code)]
//! The existing work-claim and immutable-finding intent families of AOP-006 investigate.
//!
//! This module only constructs public, typed CLI commands. The native journal and publication
//! owners enforce session authority, mission visibility, lease fences, exact claim revisions,
//! finding identity and one-successor semantics. Input decoding performs no I/O.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::PathBuf;

use fss_cli::FssCommand;
use fss_cli::claim_cmd::ClaimArgs;
use fss_cli::finding_cmd::FindingArgs;
use fss_core::{ContentDigest, KnowledgeState, PrincipalId, SessionId};
use fss_reference::deployment_session::claims::{
    ClaimAction, ClaimChange, ClaimRecovery, ClaimRequest, ClaimWork, DEFAULT_LEASE_MS,
    MAX_CLAIM_DEPENDENCIES,
};
use fss_reference::deployment_session::findings::{
    FindingAction, FindingDraft, FindingRequest, MAX_FINDING_CLAIM_BYTES, MAX_FINDING_EVIDENCE,
    MAX_FINDING_LINKS,
};

use super::investigate::{Refusal, digest, identity, only, text};
use super::json::Value;

const INVALID: Refusal = (-32602, "Invalid or unsupported coordination arguments");
// The native claim CLI and work-claim engine admit at most five minutes per lease.
const MAX_LEASE_MS: u64 = 300_000;

/// Routes the native intent families without adding another tool or transport vocabulary.
pub(super) fn selects(transition: &str) -> bool {
    transition == "claim"
        || transition.starts_with("claim-")
        || transition == "finding"
        || transition.starts_with("finding-")
}

fn lease_ms(args: &BTreeMap<String, Value>) -> Result<u64, Refusal> {
    match args.get("lease_ms") {
        None => Ok(DEFAULT_LEASE_MS),
        Some(Value::Number(value)) => value
            .parse::<u64>()
            .ok()
            .filter(|lease| (1..=MAX_LEASE_MS).contains(lease))
            .ok_or(INVALID),
        _ => Err(INVALID),
    }
}

fn work(args: &BTreeMap<String, Value>) -> Result<ClaimWork, Refusal> {
    let value = text(args, "work", 270)?;
    let item = |id: &str| {
        (!id.is_empty() && id.len() <= 256)
            .then(|| id.to_owned())
            .ok_or(INVALID)
    };
    match value.split_once(':') {
        None if value == "case" => Ok(ClaimWork::Case),
        Some(("hypothesis", id)) => item(id).map(ClaimWork::Hypothesis),
        Some(("discriminator", id)) => item(id).map(ClaimWork::Discriminator),
        Some(("probe", id)) => item(id).map(ClaimWork::Probe),
        _ => Err(INVALID),
    }
}

fn optional_identity(args: &BTreeMap<String, Value>, key: &str) -> Result<Option<String>, Refusal> {
    args.contains_key(key)
        .then(|| identity(args, key))
        .transpose()
}

/// Arrays are arrays, never comma-separated text. Every element is admitted, never dropped.
/// Reject duplicates before native set construction so no wire item silently disappears.
fn identities(
    args: &BTreeMap<String, Value>,
    key: &str,
    maximum: usize,
) -> Result<Vec<String>, Refusal> {
    let Some(value) = args.get(key) else {
        return Ok(Vec::new());
    };
    let Value::Array(values) = value else {
        return Err(INVALID);
    };
    if values.len() > maximum {
        return Err(INVALID);
    }
    let mut seen = BTreeSet::new();
    let mut admitted = Vec::with_capacity(values.len());
    for value in values {
        let value = value.text().ok_or(INVALID)?;
        fss_core::validate_id(value).map_err(|_| INVALID)?;
        if !seen.insert(value) {
            return Err(INVALID);
        }
        admitted.push(value.to_owned());
    }
    Ok(admitted)
}

fn evidence(
    args: &BTreeMap<String, Value>,
    key: &str,
    required: bool,
) -> Result<Vec<String>, Refusal> {
    let Some(value) = args.get(key) else {
        return if required {
            Err(INVALID)
        } else {
            Ok(Vec::new())
        };
    };
    let Value::Array(values) = value else {
        return Err(INVALID);
    };
    if values.len() > MAX_FINDING_EVIDENCE || (required && values.is_empty()) {
        return Err(INVALID);
    }
    let mut seen = BTreeSet::new();
    let mut admitted = Vec::with_capacity(values.len());
    for value in values {
        let digest = ContentDigest::parse(value.text().ok_or(INVALID)?)
            .map_err(|_| INVALID)?
            .to_text();
        if !seen.insert(digest.clone()) {
            return Err(INVALID);
        }
        admitted.push(digest);
    }
    Ok(admitted)
}

fn claim_action(args: &BTreeMap<String, Value>, transition: &str) -> Result<ClaimAction, Refusal> {
    match transition {
        "claim" => {
            only(args, &["case", "work", "lease_ms", "depends"])?;
            Ok(ClaimAction::Acquire {
                case_id: identity(args, "case")?,
                work: work(args)?,
                lease_ms: lease_ms(args)?,
                dependencies: identities(args, "depends", MAX_CLAIM_DEPENDENCIES)?
                    .into_iter()
                    .collect(),
            })
        }
        "claim-inspect" => {
            only(args, &["claim"])?;
            Ok(ClaimAction::Inspect {
                claim_id: identity(args, "claim")?,
            })
        }
        "claim-list" => {
            only(args, &[])?;
            Ok(ClaimAction::List)
        }
        "claim-expire" | "claim-transfer" | "claim-reclaim" => {
            let recovery = match transition {
                "claim-expire" => {
                    only(args, &["claim", "expected"])?;
                    ClaimRecovery::Expire
                }
                "claim-transfer" => {
                    only(args, &["claim", "expected", "recipient"])?;
                    ClaimRecovery::Transfer(
                        SessionId::parse(identity(args, "recipient")?).map_err(|_| INVALID)?,
                    )
                }
                _ => {
                    only(args, &["claim", "expected", "lease_ms"])?;
                    ClaimRecovery::Reclaim {
                        lease_ms: lease_ms(args)?,
                    }
                }
            };
            Ok(ClaimAction::Recover {
                claim_id: identity(args, "claim")?,
                expected: digest(args, "expected")?,
                recovery,
            })
        }
        _ => {
            let change = match transition {
                "claim-activate" => {
                    only(args, &["claim", "expected"])?;
                    ClaimChange::Activate
                }
                "claim-progress" | "claim-block" => {
                    only(args, &["claim", "expected", "artifact"])?;
                    let artifact = digest(args, "artifact")?;
                    if transition == "claim-progress" {
                        ClaimChange::Progress(artifact)
                    } else {
                        ClaimChange::Block(artifact)
                    }
                }
                "claim-complete" => {
                    only(args, &["claim", "expected", "result"])?;
                    ClaimChange::Complete(digest(args, "result")?)
                }
                "claim-release" => {
                    only(args, &["claim", "expected"])?;
                    ClaimChange::Release
                }
                "claim-renew" => {
                    only(args, &["claim", "expected", "lease_ms"])?;
                    ClaimChange::Renew {
                        lease_ms: lease_ms(args)?,
                    }
                }
                _ => return Err(INVALID),
            };
            Ok(ClaimAction::Change {
                claim_id: identity(args, "claim")?,
                expected: digest(args, "expected")?,
                change,
            })
        }
    }
}

fn finding_action(
    args: &BTreeMap<String, Value>,
    transition: &str,
) -> Result<FindingAction, Refusal> {
    match transition {
        "finding" => {
            only(
                args,
                &[
                    "case",
                    "claim",
                    "state",
                    "supporting",
                    "contradicting",
                    "hypothesis",
                    "follow_up",
                    "disagrees_with",
                    "supersedes",
                ],
            )?;
            Ok(FindingAction::Publish(FindingDraft {
                case_id: identity(args, "case")?,
                hypothesis_id: optional_identity(args, "hypothesis")?,
                claim: text(args, "claim", MAX_FINDING_CLAIM_BYTES)?.to_owned(),
                epistemic_state: text(args, "state", 32)?
                    .parse::<KnowledgeState>()
                    .map_err(|_| INVALID)?,
                supporting: evidence(args, "supporting", true)?,
                contradicting: evidence(args, "contradicting", false)?,
                follow_up: identities(args, "follow_up", MAX_FINDING_LINKS)?,
                disagrees_with: identities(args, "disagrees_with", MAX_FINDING_LINKS)?,
                supersedes: optional_identity(args, "supersedes")?,
            }))
        }
        "finding-withdraw" => {
            only(args, &["finding", "claim", "supporting"])?;
            Ok(FindingAction::Withdraw {
                finding_id: identity(args, "finding")?,
                claim: text(args, "claim", MAX_FINDING_CLAIM_BYTES)?.to_owned(),
                supporting: evidence(args, "supporting", true)?,
            })
        }
        "finding-list" => {
            only(args, &["case"])?;
            Ok(FindingAction::List {
                case_id: optional_identity(args, "case")?,
            })
        }
        _ => Err(INVALID),
    }
}

/// Root and principal are immutable launcher inputs, never decoded from a tool request.
pub(super) fn command(
    root: &OsStr,
    principal: &str,
    args: &BTreeMap<String, Value>,
) -> Result<FssCommand, Refusal> {
    let session_id = SessionId::parse(text(args, "session", 128)?).map_err(|_| INVALID)?;
    let principal = PrincipalId::parse(principal).map_err(|_| INVALID)?;
    let transition = text(args, "transition", 32)?;
    if transition == "claim" || transition.starts_with("claim-") {
        Ok(FssCommand::Claim(Box::new(ClaimArgs {
            root: PathBuf::from(root),
            request: ClaimRequest {
                session_id,
                principal,
                action: claim_action(args, transition)?,
            },
        })))
    } else {
        Ok(FssCommand::Finding(Box::new(FindingArgs {
            root: PathBuf::from(root),
            request: FindingRequest {
                session_id,
                principal,
                action: finding_action(args, transition)?,
            },
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn decode(arguments: &str) -> Result<FssCommand, Refusal> {
        let value = super::super::json::parse(arguments).map_err(|_| INVALID)?;
        let args = value.object().ok_or(INVALID)?;
        command(OsStr::new("/operator/root"), "principal:owner", args)
    }

    #[test]
    fn coordination_keeps_exact_native_identity_membership_and_literal_text() -> Result<(), Refusal>
    {
        let claim = decode(
            r#"{"session":"session:one","transition":"claim","case":"case:one","work":"probe:probe:hallway","lease_ms":300000,"depends":["claim:b","claim:a"]}"#,
        )?;
        let FssCommand::Claim(claim) = claim else {
            return Err(INVALID);
        };
        assert_eq!(claim.root, PathBuf::from("/operator/root"));
        assert_eq!(claim.request.principal.as_str(), "principal:owner");
        assert_eq!(
            claim.request.action,
            ClaimAction::Acquire {
                case_id: "case:one".to_owned(),
                work: ClaimWork::Probe("probe:hallway".to_owned()),
                lease_ms: 300_000,
                dependencies: ["claim:a".to_owned(), "claim:b".to_owned()]
                    .into_iter()
                    .collect(),
            }
        );
        let finding = decode(&format!(
            r#"{{"session":"session:one","transition":"finding","case":"case:one","claim":"/private/note\n--root=/elsewhere","state":"conflicted","supporting":["{DIGEST}"],"contradicting":[],"follow_up":["probe:z","probe:a"],"disagrees_with":["finding:other"]}}"#
        ))?;
        let FssCommand::Finding(finding) = finding else {
            return Err(INVALID);
        };
        let FindingAction::Publish(draft) = finding.request.action else {
            return Err(INVALID);
        };
        assert_eq!(finding.root, PathBuf::from("/operator/root"));
        assert_eq!(draft.claim, "/private/note\n--root=/elsewhere");
        assert_eq!(draft.epistemic_state, KnowledgeState::Conflicted);
        assert_eq!(draft.supporting, vec![DIGEST]);
        assert_eq!(draft.follow_up, vec!["probe:z", "probe:a"]);
        assert_eq!(draft.disagrees_with, vec!["finding:other"]);
        Ok(())
    }

    #[test]
    fn coordination_refuses_ambiguous_arrays_numbers_and_scope_overrides() {
        let acquire =
            r#""session":"session:one","transition":"claim","case":"case:one","work":"case""#;
        for suffix in [
            r#""lease_ms":"60000""#,
            r#""lease_ms":6e4"#,
            r#""lease_ms":60000.0"#,
            r#""lease_ms":0"#,
            r#""lease_ms":300001"#,
            r#""lease_ms":true"#,
            r#""depends":"claim:a,claim:b""#,
            r#""depends":["claim:a,claim:b"]"#,
            r#""depends":["claim:a",true]"#,
            r#""depends":["claim:a","claim:a"]"#,
            r#""depends":null"#,
            r#""root":"/another""#,
            r#""principal":"principal:other""#,
            r#""case_file":"/private""#,
            r#""expected":"sha256:bad""#,
        ] {
            assert!(decode(&format!("{{{acquire},{suffix}}}")).is_err());
        }
        let finding = format!(
            r#""session":"session:one","transition":"finding","case":"case:one","claim":"Observation","state":"unknown","supporting":["{DIGEST}"]"#
        );
        for suffix in [
            r#""contradicting":true"#.to_owned(),
            r#""disagrees_with":["finding:a,finding:b"]"#.to_owned(),
            r#""follow_up":["probe:a","probe:a"]"#.to_owned(),
            r#""supersedes":null"#.to_owned(),
            r#""expected":"sha256:bad""#.to_owned(),
            format!(r#""contradicting":["{DIGEST}","{DIGEST}"]"#),
        ] {
            assert!(decode(&format!("{{{finding},{suffix}}}")).is_err());
        }
        let oversized = (0..=MAX_CLAIM_DEPENDENCIES)
            .map(|index| format!("\"claim:{index}\""))
            .collect::<Vec<_>>()
            .join(",");
        assert!(decode(&format!("{{{acquire},\"depends\":[{oversized}]}}")).is_err());
        for arguments in [
            r#"{"session":"session:one","transition":"claim-activate","claim":"claim:one"}"#,
            r#"{"session":"session:one","transition":"claim-inspect","claim":"../private"}"#,
            r#"{"session":"session:one","transition":"claim-execute"}"#,
            r#"{"session":"session:one","transition":"finding-withdraw","finding":"finding:a","claim":"Withdraw","supporting":[]}"#,
        ] {
            assert!(decode(arguments).is_err(), "accepted {arguments}");
        }
    }
}
