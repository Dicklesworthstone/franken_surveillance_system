#![forbid(unsafe_code)]
//! Automated deterministic ergonomics linter for the unified `fss` CLI grammar.
//!
//! Semantic plane: `"support"` (pure static contract verifier; zero I/O or mutation).

use std::collections::BTreeSet;

use fss_core::json_input::{Value, parse as parse_json};

use crate::json_output::{array, object, string};
use crate::token::ArgToken;

use super::domains::{UNIFIED_DOMAINS, UnifiedBackend};
use super::help::{
    TOP_LEVEL_HELP_SPECS, render_domain_help, render_top_level_help, render_verb_help,
};
use super::normalize::{
    CanonicalIdKind, decode_hold_id_from_storage, encode_hold_id_for_storage,
    normalize_preview_json, translate_companion_args, validate_canonical_id,
};

/// Single ergonomics violation detected by [`lint_unified_cli_surface`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LintFinding {
    /// Stable diagnostic lint rule code (for example `"LINT-CLI-HELP-001"`).
    pub code: &'static str,
    /// Domain, verb, or contract subject where the finding occurred.
    pub target: String,
    /// Actionable human explanation of the violation.
    pub message: String,
}

/// Complete deterministic report emitted by [`lint_unified_cli_surface`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LintReport {
    /// Number of unified domains audited.
    pub checked_domains: usize,
    /// Number of unified `(domain, verb)` entries audited.
    pub checked_verbs: usize,
    /// Number of top-level `fss/1` command help specs audited.
    pub checked_fss1_commands: usize,
    /// All ergonomics findings (empty when clean).
    pub findings: Vec<LintFinding>,
}

impl LintReport {
    /// Returns `true` when zero ergonomics violations were detected.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// Renders this report as a deterministic JSON object.
    #[must_use]
    pub fn to_json(&self) -> String {
        let rows: Vec<String> = self
            .findings
            .iter()
            .map(|f| {
                object(&[
                    ("code", string(f.code)),
                    ("target", string(&f.target)),
                    ("message", string(&f.message)),
                ])
            })
            .collect();
        object(&[
            ("schema", string("fss.cli_ergonomics_lint.v1")),
            ("clean", self.is_clean().to_string()),
            ("checked_domains", self.checked_domains.to_string()),
            ("checked_verbs", self.checked_verbs.to_string()),
            (
                "checked_fss1_commands",
                self.checked_fss1_commands.to_string(),
            ),
            ("finding_count", self.findings.len().to_string()),
            ("findings", array(&rows)),
        ])
    }
}

/// Runs the complete deterministic CLI ergonomics audit across every registered unified domain,
/// verb, top-level `fss/1` subcommand, preview normalization shape, and canonical ID validator.
#[must_use]
pub fn lint_unified_cli_surface() -> LintReport {
    let mut findings = Vec::new();
    let mut seen_domains = BTreeSet::new();
    let mut checked_verbs = 0_usize;

    let fss1_reserved: BTreeSet<&str> = TOP_LEVEL_HELP_SPECS
        .iter()
        .filter(|s| s.subverb.is_none())
        .map(|s| s.command)
        .collect();

    for domain in UNIFIED_DOMAINS {
        if !seen_domains.insert(domain.name) {
            findings.push(LintFinding {
                code: "LINT-CLI-DUPLICATE-DOMAIN-001",
                target: domain.name.to_owned(),
                message: "duplicate domain registration in UNIFIED_DOMAINS".to_owned(),
            });
        }
        if fss1_reserved.contains(domain.name) {
            findings.push(LintFinding {
                code: "LINT-CLI-DOMAIN-COLLISION-001",
                target: domain.name.to_owned(),
                message: "unified domain collides with a reserved fss/1 top-level verb".to_owned(),
            });
        }
        if domain.verbs.is_empty() {
            findings.push(LintFinding {
                code: "LINT-CLI-EMPTY-DOMAIN-001",
                target: domain.name.to_owned(),
                message: "domain must register at least one verb".to_owned(),
            });
        }
        let domain_help = render_domain_help(domain);
        if domain_help.trim().is_empty()
            || !domain_help.contains("--help")
            || !domain_help.contains("--json")
        {
            findings.push(LintFinding {
                code: "LINT-CLI-HELP-001",
                target: domain.name.to_owned(),
                message: "domain help must be non-empty and document `--help` and `--json`"
                    .to_owned(),
            });
        }

        let mut seen_verbs = BTreeSet::new();
        for verb in domain.verbs {
            checked_verbs += 1;
            let verb_key = format!("{} {}", domain.name, verb.verb);
            if verb.domain != domain.name {
                findings.push(LintFinding {
                    code: "LINT-CLI-DOMAIN-MISMATCH-001",
                    target: verb_key.clone(),
                    message: format!(
                        "verb declares domain `{}` inside `{}`",
                        verb.domain, domain.name
                    ),
                });
            }
            if !seen_verbs.insert(verb.verb) {
                findings.push(LintFinding {
                    code: "LINT-CLI-DUPLICATE-VERB-001",
                    target: verb_key.clone(),
                    message: "duplicate verb name within domain".to_owned(),
                });
            }
            let verb_help = render_verb_help(verb);
            if verb_help.trim().is_empty()
                || !verb_help.contains("--help")
                || !verb_help.contains("--json")
                || !verb_help.contains("USAGE:")
            {
                findings.push(LintFinding {
                    code: "LINT-CLI-VERB-HELP-001",
                    target: verb_key.clone(),
                    message:
                        "verb help must be non-empty and document USAGE, `--help`, and `--json`"
                            .to_owned(),
                });
            }

            let mut seen_flags = BTreeSet::new();
            for flag in verb.flags {
                if !seen_flags.insert(flag.name) {
                    findings.push(LintFinding {
                        code: "LINT-CLI-DUPLICATE-FLAG-001",
                        target: format!("{verb_key} {}", flag.name),
                        message: "duplicate flag definition on verb".to_owned(),
                    });
                }
                if flag.name == "--root" && !verb.accepts_root {
                    findings.push(LintFinding {
                        code: "LINT-CLI-FLAG-SEMANTICS-001",
                        target: verb_key.clone(),
                        message:
                            "`--root` documented on a verb that does not accept deployment roots"
                                .to_owned(),
                    });
                }
                if flag.name == "--root" && flag.value_hint.is_some_and(|h| h.contains("archive")) {
                    findings.push(LintFinding {
                        code: "LINT-CLI-ROOT-ARCHIVE-ALIAS-001",
                        target: verb_key.clone(),
                        message: "`--root` must never be aliased to a capture archive directory"
                            .to_owned(),
                    });
                }
            }

            if verb.accepts_archive
                && !verb.accepts_root
                && matches!(verb.backend, UnifiedBackend::Companion { .. })
            {
                let bad_tokens = [
                    ArgToken {
                        raw: "--root".to_owned(),
                        index: 2,
                    },
                    ArgToken {
                        raw: "/tmp/archive".to_owned(),
                        index: 3,
                    },
                ];
                if translate_companion_args(verb, &bad_tokens).is_ok() {
                    findings.push(LintFinding {
                        code: "LINT-CLI-ROOT-ARCHIVE-GUARD-001",
                        target: verb_key.clone(),
                        message: "archive-only verb must refuse `--root` at flag translation"
                            .to_owned(),
                    });
                }
            }
        }
    }

    for spec in TOP_LEVEL_HELP_SPECS {
        let label = match spec.subverb {
            Some(sub) => format!("{} {}", spec.command, sub),
            None => spec.command.to_owned(),
        };
        let rendered = render_top_level_help(spec.command, spec.subverb);
        if rendered
            .as_deref()
            .is_none_or(|t| t.trim().is_empty() || !t.contains("USAGE:"))
        {
            findings.push(LintFinding {
                code: "LINT-CLI-FSS1-HELP-001",
                target: label,
                message: "top-level fss/1 command help must be non-empty and include USAGE"
                    .to_owned(),
            });
        }
    }

    lint_preview_normalization(&mut findings);
    lint_canonical_id_rules(&mut findings);

    LintReport {
        checked_domains: UNIFIED_DOMAINS.len(),
        checked_verbs,
        checked_fss1_commands: TOP_LEVEL_HELP_SPECS.len(),
        findings,
    }
}

fn lint_preview_normalization(findings: &mut Vec<LintFinding>) {
    let cases = [
        (
            "legacy_approval_field",
            r#"{"format":"legacy.preview.v1","approval":"sha256:1111111111111111111111111111111111111111111111111111111111111111"}"#,
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "approval",
        ),
        (
            "direct_approval_digest",
            r#"{"format":"direct.preview.v1","approval_digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222"}"#,
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "approval_digest",
        ),
        (
            "nested_result_approval_digest",
            r#"{"format":"fss.evidence_hold_cli.v1","result":{"status":"proposed","approval_digest":"sha256:3333333333333333333333333333333333333333333333333333333333333333"}}"#,
            "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            "result",
        ),
    ];

    for (label, raw, expected_digest, preserved_key) in cases {
        let normalized = normalize_preview_json(raw, Some("fss hold place --root /d"));
        match parse_json(&normalized) {
            Ok(Value::Object(obj)) => {
                let top_digest = obj.get("approval_digest").and_then(Value::text);
                let top_cmd = obj.get("approve_command").and_then(Value::text);
                if top_digest != Some(expected_digest) {
                    findings.push(LintFinding {
                        code: "LINT-CLI-PREVIEW-DIGEST-001",
                        target: label.to_owned(),
                        message: "normalized preview missing exact top-level `approval_digest`"
                            .to_owned(),
                    });
                }
                if top_cmd.is_none_or(|c| !c.contains(expected_digest)) {
                    findings.push(LintFinding {
                        code: "LINT-CLI-PREVIEW-CMD-001",
                        target: label.to_owned(),
                        message: "normalized preview missing top-level `approve_command` containing digest"
                            .to_owned(),
                    });
                }
                if !obj.contains_key(preserved_key) {
                    findings.push(LintFinding {
                        code: "LINT-CLI-PREVIEW-PRESERVE-001",
                        target: label.to_owned(),
                        message: format!("normalization dropped legacy key `{preserved_key}`"),
                    });
                }
            }
            _ => findings.push(LintFinding {
                code: "LINT-CLI-PREVIEW-JSON-001",
                target: label.to_owned(),
                message: "normalized preview output is not a valid JSON object".to_owned(),
            }),
        }
    }
}

fn lint_canonical_id_rules(findings: &mut Vec<LintFinding>) {
    let valid_cases = [
        (CanonicalIdKind::Hold, "hold:front-door-001"),
        (CanonicalIdKind::Hold, "hold_legacy_001"),
        (CanonicalIdKind::Sensor, "sensor:front-door"),
        (CanonicalIdKind::Event, "event:watch:001"),
        (CanonicalIdKind::Site, "site:home-main"),
    ];
    for (kind, sample) in valid_cases {
        if let Err(reason) = validate_canonical_id(kind, sample) {
            findings.push(LintFinding {
                code: "LINT-CLI-ID-ACCEPT-001",
                target: sample.to_owned(),
                message: format!("valid canonical ID rejected: {reason}"),
            });
        }
    }

    let invalid_cases = [
        (CanonicalIdKind::Hold, "../escape"),
        (CanonicalIdKind::Hold, "hold:../escape"),
        (CanonicalIdKind::Hold, "hold:a/b"),
        (CanonicalIdKind::Hold, "hold:bad\nid"),
        (CanonicalIdKind::Hold, "hold:"),
        (CanonicalIdKind::Hold, ":missing"),
        (CanonicalIdKind::Hold, "hold:a:b"),
        (CanonicalIdKind::Sensor, "../sensor"),
        (CanonicalIdKind::Event, "event:bad\x07id"),
        (CanonicalIdKind::Site, "site:has space"),
    ];
    for (kind, sample) in invalid_cases {
        if validate_canonical_id(kind, sample).is_ok() {
            findings.push(LintFinding {
                code: "LINT-CLI-ID-REJECT-001",
                target: sample.to_owned(),
                message: "unsafe identifier was accepted by canonical ID validator".to_owned(),
            });
        }
    }

    for hold_id in ["hold:front-door-001", "hold_legacy_001"] {
        match encode_hold_id_for_storage(hold_id) {
            Ok(encoded) => {
                if decode_hold_id_from_storage(&encoded) != hold_id {
                    findings.push(LintFinding {
                        code: "LINT-CLI-HOLD-CODEC-001",
                        target: hold_id.to_owned(),
                        message: "hold ID storage codec failed round-trip invariant".to_owned(),
                    });
                }
            }
            Err(err) => findings.push(LintFinding {
                code: "LINT-CLI-HOLD-CODEC-001",
                target: hold_id.to_owned(),
                message: format!("hold ID storage codec refused valid ID: {err}"),
            }),
        }
    }
}
