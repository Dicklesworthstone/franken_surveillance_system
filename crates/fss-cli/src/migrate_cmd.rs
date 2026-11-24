#![forbid(unsafe_code)]
//! `fss migrate --from <v1-root> --to <new-v2-root> [--json] [--progress-jsonl]` CLI command.
//!
//! Executes the non-destructive out-of-place v1-to-v2 deployment upgrader, emitting the canonical
//! `fss.migration_receipt.v1` JSON on stdout when `--json` is passed and optional single-line
//! `fss.migration_progress.v1` JSONL events on stderr when `--progress-jsonl` is requested.

use std::io::{self, Write};
use std::path::PathBuf;

use fss_reference::migration::{MigrationError, MigrationRequest, migrate_v1_to_v2_with_progress};

use crate::agent_json::{object, string};
use crate::error::{CliError, ExitIdentity};
use crate::redact::redact_value_or_digest;
use crate::token::ArgToken;

/// Parsed options for `fss migrate`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrateArgs {
    /// Existing v1 deployment root to read strictly read-only.
    pub from: PathBuf,
    /// Fresh non-existent destination path for the new v2 deployment.
    pub to: PathBuf,
    /// Emit canonical `fss.migration_receipt.v1` JSON on stdout (or diagnostic JSON on error).
    pub json: bool,
    /// Emit single-line `fss.migration_progress.v1` JSONL progress records on stderr.
    pub progress_jsonl: bool,
}

/// Parses `fss migrate --from <v1-root> --to <new-v2-root> [--json] [--progress-jsonl]` with
/// exact option validation and total grammar exhaustion.
pub fn parse_migrate_args(tokens: &[ArgToken]) -> Result<MigrateArgs, CliError> {
    let mut from: Option<PathBuf> = None;
    let mut to: Option<PathBuf> = None;
    let mut json = false;
    let mut progress_jsonl = false;
    let mut idx = 1;

    while idx < tokens.len() {
        let arg = &tokens[idx];
        match arg.as_str() {
            "--from" => {
                if from.is_some() {
                    return Err(CliError::DuplicateOption {
                        option: "--from".to_owned(),
                        command: Some("migrate".to_owned()),
                        index: arg.index,
                    });
                }
                idx += 1;
                if idx >= tokens.len() {
                    return Err(CliError::MissingValue {
                        option: "--from".to_owned(),
                        command: Some("migrate".to_owned()),
                        expected: "v1 deployment root path for `--from`".to_owned(),
                    });
                }
                let raw = tokens[idx].as_str();
                if raw.is_empty() {
                    return Err(CliError::MissingValue {
                        option: "--from".to_owned(),
                        command: Some("migrate".to_owned()),
                        expected: "non-empty v1 deployment root path for `--from`".to_owned(),
                    });
                }
                from = Some(PathBuf::from(raw));
                idx += 1;
            }
            s if s.starts_with("--from=") => {
                if from.is_some() {
                    return Err(CliError::DuplicateOption {
                        option: "--from".to_owned(),
                        command: Some("migrate".to_owned()),
                        index: arg.index,
                    });
                }
                let val = &s["--from=".len()..];
                if val.is_empty() {
                    return Err(CliError::MissingValue {
                        option: "--from".to_owned(),
                        command: Some("migrate".to_owned()),
                        expected: "non-empty v1 deployment root path for `--from`".to_owned(),
                    });
                }
                from = Some(PathBuf::from(val));
                idx += 1;
            }
            "--to" => {
                if to.is_some() {
                    return Err(CliError::DuplicateOption {
                        option: "--to".to_owned(),
                        command: Some("migrate".to_owned()),
                        index: arg.index,
                    });
                }
                idx += 1;
                if idx >= tokens.len() {
                    return Err(CliError::MissingValue {
                        option: "--to".to_owned(),
                        command: Some("migrate".to_owned()),
                        expected: "fresh v2 destination path for `--to`".to_owned(),
                    });
                }
                let raw = tokens[idx].as_str();
                if raw.is_empty() {
                    return Err(CliError::MissingValue {
                        option: "--to".to_owned(),
                        command: Some("migrate".to_owned()),
                        expected: "non-empty v2 destination path for `--to`".to_owned(),
                    });
                }
                to = Some(PathBuf::from(raw));
                idx += 1;
            }
            s if s.starts_with("--to=") => {
                if to.is_some() {
                    return Err(CliError::DuplicateOption {
                        option: "--to".to_owned(),
                        command: Some("migrate".to_owned()),
                        index: arg.index,
                    });
                }
                let val = &s["--to=".len()..];
                if val.is_empty() {
                    return Err(CliError::MissingValue {
                        option: "--to".to_owned(),
                        command: Some("migrate".to_owned()),
                        expected: "non-empty v2 destination path for `--to`".to_owned(),
                    });
                }
                to = Some(PathBuf::from(val));
                idx += 1;
            }
            "--json" => {
                if json {
                    return Err(CliError::DuplicateOption {
                        option: "--json".to_owned(),
                        command: Some("migrate".to_owned()),
                        index: arg.index,
                    });
                }
                json = true;
                idx += 1;
            }
            "--progress-jsonl" => {
                if progress_jsonl {
                    return Err(CliError::DuplicateOption {
                        option: "--progress-jsonl".to_owned(),
                        command: Some("migrate".to_owned()),
                        index: arg.index,
                    });
                }
                progress_jsonl = true;
                idx += 1;
            }
            opt if opt.starts_with('-') => {
                return Err(CliError::UnknownOption {
                    option: opt.to_owned(),
                    command: Some("migrate".to_owned()),
                    index: arg.index,
                });
            }
            trailing => {
                return Err(CliError::TrailingArgument {
                    argument: trailing.to_owned(),
                    index: arg.index,
                    command: Some("migrate".to_owned()),
                });
            }
        }
    }

    let from = from.ok_or_else(|| CliError::MissingValue {
        option: "--from".to_owned(),
        command: Some("migrate".to_owned()),
        expected: "required source v1 deployment root path (`--from <v1-root>`)".to_owned(),
    })?;
    let to = to.ok_or_else(|| CliError::MissingValue {
        option: "--to".to_owned(),
        command: Some("migrate".to_owned()),
        expected: "required fresh v2 destination path (`--to <new-v2-root>`)".to_owned(),
    })?;

    Ok(MigrateArgs {
        from,
        to,
        json,
        progress_jsonl,
    })
}

/// Executes `fss migrate` with an uncancelled control handle.
#[must_use]
pub fn execute_migrate(args: &MigrateArgs) -> (String, ExitIdentity) {
    execute_migrate_with_control(args, &crate::RequestControl::uncancelled())
}

/// Executes `fss migrate` under an explicit cooperative cancellation handle.
#[must_use]
pub(crate) fn execute_migrate_with_control(
    args: &MigrateArgs,
    control: &crate::RequestControl<'_>,
) -> (String, ExitIdentity) {
    let request = MigrationRequest::new(&args.from, &args.to);
    let mut progress_sink = |event: fss_reference::migration::MigrationProgressEvent| {
        if args.progress_jsonl {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(stderr, "{}", event.to_jsonl());
        }
    };

    match migrate_v1_to_v2_with_progress(&request, &|| control.is_cancelled(), &mut progress_sink) {
        Ok(receipt) => {
            if args.json {
                (receipt.to_json(), ExitIdentity::SUCCESS)
            } else {
                let human = format!(
                    "Migrated v1 deployment '{}' -> v2 deployment '{}'\n  site_lineage: {}\n  batches_migrated: {}\n  objects_migrated: {}\n  roots_migrated: {}\n  events_migrated: {}\n  holds_migrated: {}\n  masks_migrated: {}\n  tombstones_migrated: {}\n  source_unreferenced_orphans: {}\n  effects_verified: {}\n  semantic_equivalence_verified: {}\n  receipt_digest: {}",
                    args.from.display(),
                    args.to.display(),
                    receipt.site_lineage,
                    receipt.batches_migrated,
                    receipt.objects_migrated,
                    receipt.roots_migrated,
                    receipt.events_migrated,
                    receipt.holds_migrated,
                    receipt.masks_migrated,
                    receipt.tombstones_migrated,
                    receipt.source_unreferenced_orphans.len(),
                    receipt.effects_verified,
                    receipt.semantic_equivalence_verified,
                    receipt.receipt_digest.to_text(),
                );
                (human, ExitIdentity::SUCCESS)
            }
        }
        Err(error) => render_migration_failure(args, &error),
    }
}

fn render_migration_failure(args: &MigrateArgs, error: &MigrationError) -> (String, ExitIdentity) {
    let exit_id = match error {
        MigrationError::NotADeployment { .. } => ExitIdentity::DOCTOR_NOT_A_DEPLOYMENT,
        _ => ExitIdentity::RUNTIME_FAILURE,
    };
    let error_id = error.stable_id();
    let repair = migration_repair_guidance(error);
    if args.json {
        let input = redact_value_or_digest(&args.from.to_string_lossy());
        let json = object(&[
            ("schema", string("fss.cli_diagnostic.v1")),
            ("phase", string("execution")),
            ("binary", string("fss")),
            ("command", string("migrate")),
            ("argument_index", "null".to_owned()),
            ("redacted_input", string(&input)),
            ("error_id", string(error_id)),
            ("exit_id", string(exit_id.identifier)),
            ("exit_code", exit_id.code.to_string()),
            ("reason", string(&error.to_string())),
            ("repair", string(repair)),
            ("contract_basis", string("fss/1")),
            ("effect_started", "false".to_owned()),
            ("retryable", "false".to_owned()),
            ("recovery_class", string("operator_action_required")),
        ]);
        (json, exit_id)
    } else {
        let human = format!(
            "fss: error[{error_id}]: {error}\n  exit identity: {} (code {})\n  repair: {repair}",
            exit_id.identifier, exit_id.code
        );
        (human, exit_id)
    }
}

const fn migration_repair_guidance(error: &MigrationError) -> &'static str {
    match error {
        MigrationError::DestinationExists { .. } => {
            "choose a brand-new, non-existent `--to <new-v2-root>` path; existing directories are never overwritten"
        }
        MigrationError::SourceNotClean { .. } => {
            "inspect the v1 root with `fss doctor --json --root <v1-root>` and complete any required recovery before migrating"
        }
        MigrationError::SourceAlreadyV2 { .. } => {
            "source directory is already in v2 format; no migration is required"
        }
        MigrationError::IncompleteMigration { .. } => {
            "remove the incomplete destination directory and re-run `fss migrate` to a fresh destination"
        }
        MigrationError::Cancelled { .. } => {
            "migration stopped before completion; discard the incomplete destination directory and re-run to a fresh path"
        }
        MigrationError::NotADeployment { .. } => {
            "verify `--from` points to an existing v1 deployment root containing a canonical LAYOUT file"
        }
        _ => "inspect the reported error and verify filesystem permissions and source integrity",
    }
}
