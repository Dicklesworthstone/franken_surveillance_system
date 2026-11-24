#![forbid(unsafe_code)]
//! Deterministic, structured `--help` / `-h` rendering for every `fss/1` top-level command,
//! nested `session`/`site` verb, and unified `fss <domain> <verb>` command.
//!
//! Semantic plane: `"support"` (read-only static help formatter; zero I/O or mutation).

use std::fmt::Write as _;

use crate::token::ArgToken;

use super::domains::{DomainSpec, VerbSpec, find_domain, find_verb};

/// Static help entry for a top-level `fss/1` verb or registered sub-verb.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TopLevelHelpSpec {
    /// Primary top-level command token (for example `"session"` or `"query"`).
    pub command: &'static str,
    /// Optional nested sub-verb (for example `Some("open")` for `fss session open`).
    pub subverb: Option<&'static str>,
    /// Canonical usage line.
    pub usage: &'static str,
    /// Concise summary of semantics and plane guarantees.
    pub summary: &'static str,
    /// Key flags and behavior notes.
    pub details: &'static str,
}

/// Complete help catalog for all canonical `fss/1` verbs and built-in `fss` commands.
pub const TOP_LEVEL_HELP_SPECS: &[TopLevelHelpSpec] = &[
    TopLevelHelpSpec {
        command: "session",
        subverb: None,
        usage: "fss session <open|resume|orient|follow|handoff> [options] [--help]",
        summary: "Durable mission-scoped agent sessions (AOP-001..004, AOP-012); agent-plane writes only",
        details: "SUBCOMMANDS:\n  open     Open a mission-scoped session and initial workspace revision (AOP-001)\n  resume   Accept a HandoffCapsule and rebase onto current head (AOP-002)\n  orient   Read-only SituationCapsule orientation at current head (AOP-003)\n  follow   Read-only or durable MeaningfulDelta stream since anchor (AOP-004)\n  handoff  Seal and publish a root-last HandoffCapsule (AOP-012)\n\nOPTIONS:\n  --root <deployment-dir>  Existing deployment root\n  --json                   Required machine-readable AgentResponseEnvelope output\n  --help, -h               Print this help and exit 0",
    },
    TopLevelHelpSpec {
        command: "session",
        subverb: Some("open"),
        usage: "fss session open --json --root <deployment-dir> (--mission <text-or-file> | --mission-text <literal>) --objective <text> [--principal <id>] [--view pulse|brief|epistemic_map] [--budget-tokens <n>] [--help]",
        summary: "AOP-001 session.open: create a durable mission-scoped session at the current orient anchor",
        details: "OPTIONS:\n  --root <deployment-dir>  Existing deployment root (writes agent/ only)\n  --mission <text|file>    Mission statement text or path to a regular UTF-8 file\n  --mission-text <literal> Literal mission text (never interpreted as a file path)\n  --objective <text>       Concrete mission objective statement\n  --principal <id>         Audit principal identity (default principal:local-operator)\n  --view <view>            pulse, brief (default), or epistemic_map\n  --budget-tokens <n>      Cumulative session token budget\n  --json                   Required AgentResponseEnvelope JSON output\n  --help, -h               Print this help and exit 0",
    },
    TopLevelHelpSpec {
        command: "session",
        subverb: Some("resume"),
        usage: "fss session resume --json --root <deployment-dir> --handoff <handoff-id> [--principal <id>] [--help]",
        summary: "AOP-002 session.resume: accept a published HandoffCapsule and rebase onto current head",
        details: "OPTIONS:\n  --root <deployment-dir>  Existing deployment root\n  --handoff <id>           Published HandoffCapsule identifier\n  --principal <id>         Resuming principal identity\n  --json                   Required AgentResponseEnvelope JSON output\n  --help, -h               Print this help and exit 0",
    },
    TopLevelHelpSpec {
        command: "session",
        subverb: Some("orient"),
        usage: "fss session orient --json --root <deployment-dir> [--session <id>] [--view pulse|brief|epistemic_map] [--principal <id>] [--budget-tokens <n>] [--help]",
        summary: "AOP-003 session.orient: read-only anchor-pinned SituationCapsule listing valid affordances",
        details: "OPTIONS:\n  --root <deployment-dir>  Existing deployment root (strictly read-only)\n  --session <id>           Optional owned session to inspect without rebasing\n  --view <view>            pulse, brief (default), or epistemic_map\n  --principal <id>         Audit principal identity\n  --budget-tokens <n>      Bounded output token budget\n  --json                   Required AgentResponseEnvelope JSON output\n  --help, -h               Print this help and exit 0",
    },
    TopLevelHelpSpec {
        command: "session",
        subverb: Some("follow"),
        usage: "fss session follow --json --root <deployment-dir> --since <anchor> [--view pulse|brief] [--max-entries <n>] [--continuation <token> | --wait-ms <1..10000>] [--help]",
        summary: "AOP-004 session.follow: exact MeaningfulDelta pages since an earlier committed anchor",
        details: "OPTIONS:\n  --root <deployment-dir>  Existing deployment root\n  --since <anchor>         Exact prior anchor token\n  --view <view>            pulse (default) or brief\n  --max-entries <n>        Maximum delta entries per page\n  --continuation <token>   Exact pagination continuation cursor\n  --wait-ms <1..10000>     Bounded read-only long-poll wait\n  --json                   Required AgentResponseEnvelope JSON output\n  --help, -h               Print this help and exit 0",
    },
    TopLevelHelpSpec {
        command: "session",
        subverb: Some("handoff"),
        usage: "fss session handoff --json --root <deployment-dir> --session <id> [--principal <id>] [--note <text>] [--help]",
        summary: "AOP-012 handoff: publish a root-last HandoffCapsule sealed as of the session anchor",
        details: "OPTIONS:\n  --root <deployment-dir>  Existing deployment root\n  --session <id>           Active session identifier to hand off\n  --principal <id>         Owning principal identity\n  --note <text>            Optional operator handoff note\n  --json                   Required AgentResponseEnvelope JSON output\n  --help, -h               Print this help and exit 0",
    },
    TopLevelHelpSpec {
        command: "orient",
        subverb: None,
        usage: "fss orient --json --root <deployment-dir> [--session <id>] [--view pulse|brief|epistemic_map] [--principal <id>] [--budget-tokens <n>] [--help]",
        summary: "Alias for `fss session orient` (AOP-003): read-only SituationCapsule orientation",
        details: "OPTIONS:\n  --root <deployment-dir>  Existing deployment root (read-only)\n  --json                   Required AgentResponseEnvelope JSON output\n  --help, -h               Print this help and exit 0",
    },
    TopLevelHelpSpec {
        command: "follow",
        subverb: None,
        usage: "fss follow --json --root <deployment-dir> --since <anchor> [--view pulse|brief] [--max-entries <n>] [--json] [--help]",
        summary: "Alias for `fss session follow` (AOP-004): exact MeaningfulDelta pages since anchor",
        details: "OPTIONS:\n  --root <deployment-dir>  Existing deployment root\n  --since <anchor>         Exact prior anchor token\n  --json                   Required AgentResponseEnvelope JSON output\n  --help, -h               Print this help and exit 0",
    },
    TopLevelHelpSpec {
        command: "handoff",
        subverb: None,
        usage: "fss handoff --json --root <deployment-dir> --session <id> [--principal <id>] [--note <text>] [--help]",
        summary: "Registered spelling for AOP-012 handoff: publish a root-last HandoffCapsule",
        details: "OPTIONS:\n  --root <deployment-dir>  Existing deployment root\n  --session <id>           Active session identifier\n  --json                   Required AgentResponseEnvelope JSON output\n  --help, -h               Print this help and exit 0",
    },
    TopLevelHelpSpec {
        command: "query",
        subverb: None,
        usage: "fss query --json --root <deployment-dir> [--target events|footage|recordings|reports|sources|tracks|qsr|onvif|localizations|evidence-hydration|cameras|graph|fusion|holds|privacy-masks] [filters...] [--help]",
        summary: "AOP-005 query: read-only exact, bounded query over committed history and operational targets",
        details: "OPTIONS:\n  --root <deployment-dir>  Existing deployment root (strictly read-only)\n  --target <target>        events (default), footage, recordings, reports, sources, tracks,\n                           qsr, onvif, localizations, evidence-hydration, cameras, graph,\n                           fusion, holds, or privacy-masks\n  --event-id <id>          Exact event filter (for --target events)\n  --max-entries <1..32>    Bounded page size\n  --anchor <token>         Current-head precondition\n  --at <historical-token>  Exact historical prefix (mutually exclusive with --anchor)\n  --json                   Required AgentResponseEnvelope JSON output\n  --help, -h               Print this help and exit 0",
    },
    TopLevelHelpSpec {
        command: "explain",
        subverb: None,
        usage: "fss explain --json --root <deployment-dir> (--event-id <id> [--question what_changed|what_if] | --session <id> --learning-root <sha256>) [--view decision_diff|forensic] [--help]",
        summary: "AOP-011 explain: read-only evidence-linked event, diff, counterfactual, or learning explanation",
        details: "OPTIONS:\n  --root <deployment-dir>  Existing deployment root (strictly read-only)\n  --event-id <id>          Published event identifier to explain\n  --question <kind>        Optional what_changed or what_if counterfactual query\n  --view <view>            decision_diff (default) or forensic\n  --custody yes|no         Check retained support byte custody\n  --json                   Required AgentResponseEnvelope JSON output\n  --help, -h               Print this help and exit 0",
    },
    TopLevelHelpSpec {
        command: "investigate",
        subverb: None,
        usage: "fss investigate --json --root <deployment-dir> --session <id> --transition <open|inspect|list|activate|cite|assess|set-state|conclude|rebase|readmit|expand|claim*|finding*|probe*> [options] [--help]",
        summary: "AOP-006 investigate: durable investigation cases, hypotheses, work claims, findings, and retained probes",
        details: "OPTIONS:\n  --root <deployment-dir>  Existing deployment root (writes agent/ only)\n  --session <id>           Owning session identifier\n  --transition <verb>      Case, claim, finding, or retained probe transition\n  --json                   Required AgentResponseEnvelope JSON output\n  --help, -h               Print this help and exit 0",
    },
    TopLevelHelpSpec {
        command: "plan",
        subverb: None,
        usage: "fss plan --json --root <deployment-dir> --session <id> (--intent alert ... [--approve <sha256>] | --close <plan-id> | --mission-contract ...) [--help]",
        summary: "AOP-007 plan: publish witnessed ControlPlans, prepare approved effects, or close terminal episodes",
        details: "OPTIONS:\n  --root <deployment-dir>  Existing deployment root\n  --session <id>           Owning session identifier\n  --intent <kind>          alert (or operational intent)\n  --approve <sha256>       Exact plan approval digest (omit to preview only)\n  --close <plan-id>        Record immutable ExecutionEpisode for a terminal plan\n  --json                   Required AgentResponseEnvelope JSON output\n  --help, -h               Print this help and exit 0",
    },
    TopLevelHelpSpec {
        command: "commit",
        subverb: None,
        usage: "fss commit --json --root <deployment-dir> (--plan <plan-id> --approve <sha256> | --reconcile delivered|not_delivered --operation <id> --evidence <sha256> --statement <text> [--approve <sha256>]) [--help]",
        summary: "AOP-008 commit: revalidate and commit an approved effect plan or owner-attested reconciliation",
        details: "OPTIONS:\n  --root <deployment-dir>  Existing deployment root\n  --plan <plan-id>         Prepared plan identifier to commit\n  --approve <sha256>       Exact dispatch or reconciliation approval digest\n  --reconcile <outcome>    delivered or not_delivered (owner-attested reconciliation)\n  --json                   Required AgentResponseEnvelope JSON output\n  --help, -h               Print this help and exit 0",
    },
    TopLevelHelpSpec {
        command: "wait",
        subverb: None,
        usage: "fss wait --json --root <deployment-dir> --operation <id> --deadline-ms <n> [--principal <id>] [--help]",
        summary: "AOP-009 wait: bounded read until an operation leaves its current state",
        details: "OPTIONS:\n  --root <deployment-dir>  Existing deployment root\n  --operation <id>         Effect operation identifier\n  --deadline-ms <n>        Bounded wait deadline in milliseconds\n  --json                   Required AgentResponseEnvelope JSON output\n  --help, -h               Print this help and exit 0",
    },
    TopLevelHelpSpec {
        command: "cancel",
        subverb: None,
        usage: "fss cancel --json --root <deployment-dir> (--operation <id> | --session <id>) [--approve <sha256>] [--principal <id>] [--help]",
        summary: "AOP-010 cancel: preview or cancel a prepared operation or revoke future session authority",
        details: "OPTIONS:\n  --root <deployment-dir>  Existing deployment root\n  --operation <id>         Prepared operation identifier to cancel\n  --session <id>           Session identifier to revoke\n  --approve <sha256>       Exact cancellation approval digest (omit to preview)\n  --json                   Required AgentResponseEnvelope JSON output\n  --help, -h               Print this help and exit 0",
    },
    TopLevelHelpSpec {
        command: "feedback",
        subverb: None,
        usage: "fss feedback --json --root <deployment-dir> --session <id> --target <event|case|operation|plan>:<id> --kind <kind> --statement <text> [--help]",
        summary: "AOP-013 feedback: publish an advisory, evidence-linked learning proposal (never mutates policy)",
        details: "OPTIONS:\n  --root <deployment-dir>  Existing deployment root\n  --session <id>           Owning session identifier\n  --target <kind:id>       Existing event, case, operation, or plan target\n  --kind <kind>            Registered feedback classification\n  --statement <text>       Non-secret evidence-linked feedback statement\n  --json                   Required AgentResponseEnvelope JSON output\n  --help, -h               Print this help and exit 0",
    },
    TopLevelHelpSpec {
        command: "doctor",
        subverb: None,
        usage: "fss doctor --json [--root <deployment-dir>] [--help]",
        summary: "Read-only diagnostic health inspection of a deployment root (never writes, locks, or repairs)",
        details: "OPTIONS:\n  --root <deployment-dir>  Optional deployment root to inspect read-only\n  --json                   Required machine-readable diagnostic JSON output\n  --help, -h               Print this help and exit 0",
    },
    TopLevelHelpSpec {
        command: "status",
        subverb: None,
        usage: "fss status --json [--root <deployment-dir>] [--max-journal-bytes <n>] [--help]",
        summary: "Read-only retained inventory summary (SCHEMA-STATUS-001; never claims live readiness)",
        details: "OPTIONS:\n  --root <deployment-dir>  Optional deployment root to inspect read-only\n  --max-journal-bytes <n>  Optional journal read byte ceiling (requires --root)\n  --json                   Required machine-readable status JSON output\n  --help, -h               Print this help and exit 0",
    },
    TopLevelHelpSpec {
        command: "capabilities",
        subverb: None,
        usage: "fss capabilities --json [--help]",
        summary: "Report disjoint implemented, partial, and unimplemented capabilities as JSON",
        details: "OPTIONS:\n  --json                   Required machine-readable capabilities JSON output\n  --help, -h               Print this help and exit 0",
    },
    TopLevelHelpSpec {
        command: "version",
        subverb: None,
        usage: "fss version [--help]",
        summary: "Print the compiled `fss` binary version",
        details: "OPTIONS:\n  --help, -h               Print this help and exit 0",
    },
    TopLevelHelpSpec {
        command: "help",
        subverb: None,
        usage: "fss help",
        summary: "Print top-level usage for the `fss` binary",
        details: "Use `fss <command> --help` or `fss <domain> <verb> --help` for command-specific options.",
    },
    TopLevelHelpSpec {
        command: "negative-evidence",
        subverb: None,
        usage: "fss negative-evidence <init|list|verify|append> [--path <file>] [--json] [--help]",
        summary: "Manage the append-only negative evidence ledger",
        details: "OPTIONS:\n  --path <file>            Path to the negative evidence ledger file\n  --json                   Emit machine-readable JSON output\n  --help, -h               Print this help and exit 0",
    },
];

/// Free-text value flags whose immediately following argument must not be interpreted as `--help`.
const FREE_TEXT_VALUE_FLAGS: &[&str] = &[
    "--mission",
    "--mission-text",
    "--objective",
    "--note",
    "--statement",
    "--reason",
    "--claim",
    "--purpose",
    "--counterfactual",
    "--zone-policy",
    "--sources",
    "--sessions",
    "--zone-roles",
    "--lane-stages",
    "--continuation",
];

/// Returns `true` if `tokens` contains a standalone `--help` or `-h` flag not consumed as the
/// value of a free-text flag.
#[must_use]
pub fn has_standalone_help_flag(tokens: &[ArgToken]) -> bool {
    let mut idx = 0;
    while idx < tokens.len() {
        let raw = tokens[idx].as_str();
        if FREE_TEXT_VALUE_FLAGS.contains(&raw) {
            idx += 2;
            continue;
        }
        if matches!(raw, "--help" | "-h") {
            return true;
        }
        idx += 1;
    }
    false
}

/// Renders structured help for a unified operational domain (`fss <domain> --help`).
#[must_use]
pub fn render_domain_help(domain: &DomainSpec) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "fss {} — {}", domain.name, domain.summary);
    let _ = writeln!(out);
    let _ = writeln!(out, "USAGE:");
    if domain.name == "migrate" {
        let _ = writeln!(
            out,
            "  fss migrate --from <v1-root> --to <new-v2-root> [--json] [--progress-jsonl] [--help]"
        );
    } else {
        let _ = writeln!(out, "  fss {} <verb> [options]", domain.name);
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "VERBS:");
    for verb in domain.verbs {
        let _ = writeln!(out, "  {:<16} {}", verb.verb, verb.summary);
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "STANDARD FLAGS:");
    let _ = writeln!(
        out,
        "  --root <deployment-dir>  Deployment root directory (never aliased to capture archives)"
    );
    let _ = writeln!(
        out,
        "  --archive <archive-dir>  Capture archive directory (distinct from deployment --root)"
    );
    let _ = writeln!(
        out,
        "  --site <site-id>         Site lineage identifier (auto-resolved from existing --root when omitted)"
    );
    let _ = writeln!(
        out,
        "  --approve <sha256>       Exact SHA-256 approval digest from a prior preview"
    );
    let _ = writeln!(
        out,
        "  --json                   Emit deterministic machine-readable JSON output"
    );
    let _ = writeln!(
        out,
        "  --help, -h               Print help for this domain or any verb and exit 0"
    );
    out
}

/// Renders structured help for a single unified verb (`fss <domain> <verb> --help`).
#[must_use]
pub fn render_verb_help(verb: &VerbSpec) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "fss {} {} — {}", verb.domain, verb.verb, verb.summary);
    let _ = writeln!(out);
    let _ = writeln!(out, "USAGE:");
    let _ = writeln!(out, "  {}", verb.usage);
    let _ = writeln!(out);
    let _ = writeln!(out, "OPTIONS:");
    for flag in verb.flags {
        let label = match flag.value_hint {
            Some(hint) => format!("{} {}", flag.name, hint),
            None => flag.name.to_owned(),
        };
        let req = if flag.required { " (required)" } else { "" };
        let _ = writeln!(out, "  {label:<28} {}{req}", flag.description);
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "AUTHORITY & OUTPUT:");
    if verb.mutating {
        let _ = writeln!(
            out,
            "  Mutating/approval-gated verb: previews write nothing and emit top-level"
        );
        let _ = writeln!(
            out,
            "  `approval_digest` + `approve_command` JSON keys; rerun with `--approve <sha256>` to commit."
        );
    } else {
        let _ = writeln!(
            out,
            "  Read-only verb: never mutates deployment authority or grants effect capability."
        );
    }
    let _ = writeln!(
        out,
        "  Use `--json` for structured output and `--help` / `-h` for this usage summary."
    );
    out
}

/// Renders crisp help for a top-level `fss/1` command, `site` verb, or `migrate`.
#[must_use]
pub fn render_top_level_help(command: &str, subverb: Option<&str>) -> Option<String> {
    let canonical_cmd = match command {
        "neg" | "negative" => "negative-evidence",
        other => other,
    };
    if matches!(canonical_cmd, "site" | "migrate") {
        if let Some(sub) = subverb {
            return find_verb(canonical_cmd, sub).map(render_verb_help);
        }
        return find_domain(canonical_cmd).map(render_domain_help);
    }
    if canonical_cmd == "negative-evidence"
        && let Some(sub) = subverb
        && matches!(sub, "init" | "list" | "verify" | "append")
    {
        return Some(format!(
            "fss negative-evidence {sub} — Negative evidence ledger `{sub}` action\n\n\
             USAGE:\n  fss negative-evidence {sub} [--path <file>] [--json] [--help]\n\n\
             OPTIONS:\n  --path <file>  Path to ledger file\n  --json         Emit JSON output\n  --help, -h     Print this help and exit 0\n"
        ));
    }
    TOP_LEVEL_HELP_SPECS
        .iter()
        .find(|spec| spec.command == canonical_cmd && spec.subverb == subverb)
        .map(|spec| {
            format!(
                "fss {}{} — {}\n\nUSAGE:\n  {}\n\n{}\n",
                spec.command,
                spec.subverb.map_or_else(String::new, |s| format!(" {s}")),
                spec.summary,
                spec.usage,
                spec.details
            )
        })
}

/// Detects `--help` / `-h` on any top-level `fss/1`, `site`, `migrate`, or `negative-evidence`
/// invocation and returns its structured help text without interfering with normal argument errors.
#[must_use]
pub fn detect_subcommand_help(tokens: &[ArgToken]) -> Option<String> {
    let first = tokens.first()?.as_str();
    if tokens.len() < 2 {
        return None;
    }
    if matches!(first, "help" | "--help" | "-h") {
        return None;
    }
    if matches!(first, "version" | "--version" | "-V") {
        return (tokens.len() == 2 && matches!(tokens[1].as_str(), "--help" | "-h"))
            .then(|| render_top_level_help("version", None))
            .flatten();
    }
    if matches!(
        first,
        "session" | "site" | "negative-evidence" | "neg" | "negative"
    ) {
        if tokens.len() == 2 && matches!(tokens[1].as_str(), "--help" | "-h") {
            return render_top_level_help(first, None);
        }
        let second = tokens[1].as_str();
        if !second.starts_with('-')
            && let Some(text) = render_top_level_help(first, Some(second))
            && has_standalone_help_flag(&tokens[2..])
        {
            return Some(text);
        }
        return None;
    }
    if matches!(
        first,
        "capabilities"
            | "doctor"
            | "status"
            | "orient"
            | "explain"
            | "follow"
            | "query"
            | "investigate"
            | "plan"
            | "commit"
            | "wait"
            | "cancel"
            | "feedback"
            | "handoff"
            | "migrate"
    ) && has_standalone_help_flag(&tokens[1..])
    {
        return render_top_level_help(first, None);
    }
    None
}
