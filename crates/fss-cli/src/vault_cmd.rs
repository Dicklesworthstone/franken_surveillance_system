#![forbid(unsafe_code)]
//! `fss vault <init|set|list|revoke|doctor>` — operator CLI over `fss-vault` (`LocalEncryptedVault`,
//! macOS Keychain, and Linux Secret Service) with strict zero-argv-secret and `0600`/`0700` file guards.
//!
//! Semantic plane: `"authority"`.
//!
//! # Security Invariants
//! - Raw secret values and passphrases are NEVER accepted on CLI argv (`--secret`, `--password`,
//!   `--passphrase`, `--token` are refused fail-closed with `ERR-SECRET-INVALID-INPUT-001`).
//! - Secret and passphrase files (`--secret-file`, `--passphrase-file`) MUST be regular non-symlink
//!   files with owner-only `0600` permissions (no group/other bits on Unix).
//! - Secret material lives exclusively in `fss_vault::SecretBytes` (`Zeroizing<Vec<u8>>`) and NEVER
//!   appears in stdout, stderr, JSON receipts, or error messages.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use fss_core::{BudgetVector, ContextAuthority, OperationId, RootAuthoritySpec, TimestampNs};
use fss_vault::{
    AdapterFamily, CAP_SECRET_READ_001, CAP_SECRET_ROTATE_001, CAP_SECRET_WRITE_001,
    ERR_SECRET_INVALID_INPUT_001, ERR_SECRET_PERMISSION_DENIED_001, LocalEncryptedVault,
    MAX_SECRET_BYTES, SecretAccessCx, SecretBytes, SecretHandle, SecretId, SecretScope,
    SecretStore, VAULT_DIR_MODE, VAULT_FILE_MODE, VAULT_FILENAME, VAULT_FORMAT_VERSION,
    VAULT_HEADER_LEN, VAULT_MAGIC,
};

use crate::agent_json::{array, object, string};
use crate::error::ExitIdentity;
use crate::token::ArgToken;

/// Canonical JSON response schema for `fss vault` operations.
pub const VAULT_CLI_RESPONSE_SCHEMA: &str = "fss.vault_response.v1";

const FORBIDDEN_ARGV_SECRET_FLAGS: &[&str] = &[
    "--secret",
    "--password",
    "--passphrase",
    "--token",
    "--api-key",
    "--apikey",
    "--key",
    "--value",
];

/// Executes an in-process `fss vault <verb>` command (`init`, `set`, `list`, `revoke`, `doctor`).
#[must_use]
pub fn execute_vault_command(
    verb: &str,
    args: &[ArgToken],
    control: &crate::RequestControl<'_>,
) -> (String, ExitIdentity) {
    if control.is_cancelled() {
        return err_json(
            "ERR-CLI-READ-CANCELLED-001",
            "vault operation cancelled before dispatch",
            ExitIdentity::RUNTIME_FAILURE,
        );
    }
    for tok in args {
        let s = tok.as_str();
        let flag_name = s.split_once('=').map_or(s, |(k, _)| k);
        if FORBIDDEN_ARGV_SECRET_FLAGS.contains(&flag_name) {
            return err_json(
                ERR_SECRET_INVALID_INPUT_001,
                "plaintext secrets and passphrases are forbidden on CLI argv; use --secret-file/--passphrase-file (0600) or --secret-stdin/--passphrase-stdin",
                ExitIdentity::MALFORMED_VALUE,
            );
        }
    }
    match verb {
        "init" => exec_init(args),
        "set" => exec_set(args),
        "list" => exec_list(args),
        "revoke" => exec_revoke(args),
        "doctor" => exec_doctor(args),
        other => err_json(
            "ERR-CLI-UNKNOWN-COMMAND-001",
            &format!("unknown vault verb `{other}` (expected init, set, list, revoke, doctor)"),
            ExitIdentity::UNKNOWN_COMMAND,
        ),
    }
}

struct VaultOpts {
    vault_dir: PathBuf,
    passphrase_file: Option<PathBuf>,
    passphrase_stdin: bool,
    secret_file: Option<PathBuf>,
    secret_stdin: bool,
    secret_id: Option<String>,
    family: Option<String>,
    target: Option<String>,
    endpoint: Option<String>,
    rotate: bool,
    raw_bytes: bool,
    principal: String,
}

fn parse_vault_opts(verb: &str, tokens: &[ArgToken]) -> Result<VaultOpts, (String, ExitIdentity)> {
    let mut vault_dir: Option<PathBuf> = None;
    let mut passphrase_file: Option<PathBuf> = None;
    let mut passphrase_stdin = false;
    let mut secret_file: Option<PathBuf> = None;
    let mut secret_stdin = false;
    let mut secret_id: Option<String> = None;
    let mut family: Option<String> = None;
    let mut target: Option<String> = None;
    let mut endpoint: Option<String> = None;
    let mut rotate = false;
    let mut raw_bytes = false;
    let mut principal = "principal:local-operator".to_owned();

    let mut i = 0_usize;
    while i < tokens.len() {
        let raw = tokens[i].as_str();
        let (flag, inline) = match raw.split_once('=') {
            Some((k, v)) => (k, Some(v)),
            None => (raw, None),
        };
        let next_val = |idx: &mut usize, name: &str| -> Result<String, (String, ExitIdentity)> {
            if let Some(v) = inline {
                if v.is_empty() {
                    return Err(err_json(
                        ERR_SECRET_INVALID_INPUT_001,
                        &format!("empty value for `{name}`"),
                        ExitIdentity::MALFORMED_VALUE,
                    ));
                }
                return Ok(v.to_owned());
            }
            *idx += 1;
            let Some(tok) = tokens.get(*idx) else {
                return Err(err_json(
                    ERR_SECRET_INVALID_INPUT_001,
                    &format!("missing value for `{name}` in `fss vault {verb}`"),
                    ExitIdentity::MISSING_VALUE,
                ));
            };
            Ok(tok.as_str().to_owned())
        };
        match flag {
            "--vault-dir" => vault_dir = Some(PathBuf::from(next_val(&mut i, "--vault-dir")?)),
            "--passphrase-file" => {
                passphrase_file = Some(PathBuf::from(next_val(&mut i, "--passphrase-file")?));
            }
            "--passphrase-stdin" => passphrase_stdin = true,
            "--secret-file" => {
                secret_file = Some(PathBuf::from(next_val(&mut i, "--secret-file")?));
            }
            "--secret-stdin" => secret_stdin = true,
            "--secret-id" => secret_id = Some(next_val(&mut i, "--secret-id")?),
            "--family" => family = Some(next_val(&mut i, "--family")?),
            "--target" => target = Some(next_val(&mut i, "--target")?),
            "--endpoint" => endpoint = Some(next_val(&mut i, "--endpoint")?),
            "--principal" => principal = next_val(&mut i, "--principal")?,
            "--rotate" => rotate = true,
            "--raw" | "--raw-bytes" => raw_bytes = true,
            "--json" => {}
            other => {
                return Err(err_json(
                    "ERR-CLI-UNKNOWN-OPTION-001",
                    &format!("unknown option `{other}` for `fss vault {verb}`"),
                    ExitIdentity::UNKNOWN_OPTION,
                ));
            }
        }
        i += 1;
    }

    let Some(vault_dir) = vault_dir else {
        return Err(err_json(
            ERR_SECRET_INVALID_INPUT_001,
            &format!("`fss vault {verb}` requires `--vault-dir <dir>`"),
            ExitIdentity::MISSING_VALUE,
        ));
    };
    if passphrase_stdin && secret_stdin {
        return Err(err_json(
            ERR_SECRET_INVALID_INPUT_001,
            "`--passphrase-stdin` and `--secret-stdin` cannot both read from stdin simultaneously",
            ExitIdentity::MALFORMED_VALUE,
        ));
    }

    Ok(VaultOpts {
        vault_dir,
        passphrase_file,
        passphrase_stdin,
        secret_file,
        secret_stdin,
        secret_id,
        family,
        target,
        endpoint,
        rotate,
        raw_bytes,
        principal,
    })
}

fn exec_init(args: &[ArgToken]) -> (String, ExitIdentity) {
    let opts = match parse_vault_opts("init", args) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let passphrase = match read_passphrase(&opts) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let mut vault = LocalEncryptedVault::open(&opts.vault_dir);
    if let Err(err) = vault.initialize(&passphrase) {
        return err_json(
            err.error_id(),
            &err.to_string(),
            ExitIdentity::RUNTIME_FAILURE,
        );
    }
    let vault_path = vault.vault_path().display().to_string();
    let backend = vault.backend_kind().as_str().to_owned();
    vault.lock();
    (
        object(&[
            ("schema", string(VAULT_CLI_RESPONSE_SCHEMA)),
            ("action", string("init")),
            ("status", string("initialized")),
            ("vault_path", string(&vault_path)),
            ("backend", string(&backend)),
            ("plaintext_on_disk", "false".to_owned()),
        ]),
        ExitIdentity::SUCCESS,
    )
}

fn exec_set(args: &[ArgToken]) -> (String, ExitIdentity) {
    let opts = match parse_vault_opts("set", args) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let secret_id = match parse_required_secret_id(&opts) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let scope = match parse_required_scope(&opts) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let passphrase = match read_passphrase(&opts) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let secret_bytes = match read_secret_payload(&opts) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let cap = if opts.rotate {
        CAP_SECRET_ROTATE_001
    } else {
        CAP_SECRET_WRITE_001
    };
    let cx = match build_secret_cx(&opts.principal, "op:vault:set", &[cap], scope) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let mut vault = LocalEncryptedVault::open(&opts.vault_dir);
    if let Err(err) = vault.unlock(&passphrase) {
        return err_json(
            err.error_id(),
            &err.to_string(),
            ExitIdentity::RUNTIME_FAILURE,
        );
    }
    let res = if opts.rotate {
        vault.rotate(&cx, &secret_id, secret_bytes)
    } else {
        vault.store(&cx, &secret_id, secret_bytes)
    };
    vault.lock();
    match res {
        Ok(handle) => (
            object(&[
                ("schema", string(VAULT_CLI_RESPONSE_SCHEMA)),
                ("action", string(if opts.rotate { "rotate" } else { "set" })),
                ("status", string("stored")),
                ("handle", render_handle_json(&handle)),
            ]),
            ExitIdentity::SUCCESS,
        ),
        Err(err) => err_json(
            err.error_id(),
            &err.to_string(),
            ExitIdentity::RUNTIME_FAILURE,
        ),
    }
}

fn exec_list(args: &[ArgToken]) -> (String, ExitIdentity) {
    let opts = match parse_vault_opts("list", args) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let scope = match parse_required_scope(&opts) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let passphrase = match read_passphrase(&opts) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let cx = match build_secret_cx(
        &opts.principal,
        "op:vault:list",
        &[CAP_SECRET_READ_001],
        scope,
    ) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let mut vault = LocalEncryptedVault::open(&opts.vault_dir);
    if let Err(err) = vault.unlock(&passphrase) {
        return err_json(
            err.error_id(),
            &err.to_string(),
            ExitIdentity::RUNTIME_FAILURE,
        );
    }
    let res = vault.list_handles(&cx);
    vault.lock();
    match res {
        Ok(handles) => {
            let rows: Vec<String> = handles.iter().map(render_handle_json).collect();
            (
                object(&[
                    ("schema", string(VAULT_CLI_RESPONSE_SCHEMA)),
                    ("action", string("list")),
                    ("count", rows.len().to_string()),
                    ("handles", array(&rows)),
                ]),
                ExitIdentity::SUCCESS,
            )
        }
        Err(err) => err_json(
            err.error_id(),
            &err.to_string(),
            ExitIdentity::RUNTIME_FAILURE,
        ),
    }
}

fn exec_revoke(args: &[ArgToken]) -> (String, ExitIdentity) {
    let opts = match parse_vault_opts("revoke", args) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let secret_id = match parse_required_secret_id(&opts) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let scope = match parse_required_scope(&opts) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let passphrase = match read_passphrase(&opts) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let cx = match build_secret_cx(
        &opts.principal,
        "op:vault:revoke",
        &[CAP_SECRET_ROTATE_001, CAP_SECRET_WRITE_001],
        scope,
    ) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let mut vault = LocalEncryptedVault::open(&opts.vault_dir);
    if let Err(err) = vault.unlock(&passphrase) {
        return err_json(
            err.error_id(),
            &err.to_string(),
            ExitIdentity::RUNTIME_FAILURE,
        );
    }
    let res = vault.revoke(&cx, &secret_id);
    vault.lock();
    match res {
        Ok(handle) => (
            object(&[
                ("schema", string(VAULT_CLI_RESPONSE_SCHEMA)),
                ("action", string("revoke")),
                ("status", string("revoked")),
                ("revoked", "true".to_owned()),
                ("handle", render_handle_json(&handle)),
            ]),
            ExitIdentity::SUCCESS,
        ),
        Err(err) => err_json(
            err.error_id(),
            &err.to_string(),
            ExitIdentity::RUNTIME_FAILURE,
        ),
    }
}

fn exec_doctor(args: &[ArgToken]) -> (String, ExitIdentity) {
    let opts = match parse_vault_opts("doctor", args) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let vault_path = opts.vault_dir.join(VAULT_FILENAME);
    let mut findings: Vec<String> = Vec::new();
    let dir_ok = match fs::symlink_metadata(&opts.vault_dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                findings.push(string("vault_dir_not_regular_directory"));
                false
            } else if !mode_is_owner_only(&meta, VAULT_DIR_MODE) {
                findings.push(string("vault_dir_permissions_too_permissive"));
                false
            } else {
                true
            }
        }
        Err(_) => {
            findings.push(string("vault_dir_missing"));
            false
        }
    };
    let mut header_valid = false;
    let file_ok = match fs::symlink_metadata(&vault_path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_file() {
                findings.push(string("vault_file_not_regular_file"));
                false
            } else if !mode_is_owner_only(&meta, VAULT_FILE_MODE) {
                findings.push(string("vault_file_permissions_too_permissive"));
                false
            } else {
                match read_bounded_header(&vault_path) {
                    Ok(hdr) if hdr.len() >= 6 && hdr[0..4] == VAULT_MAGIC => {
                        let ver = u16::from_be_bytes([hdr[4], hdr[5]]);
                        if ver == VAULT_FORMAT_VERSION {
                            header_valid = true;
                        } else {
                            findings.push(string("vault_unsupported_format_version"));
                        }
                    }
                    _ => findings.push(string("vault_header_corrupt_or_truncated")),
                }
                true
            }
        }
        Err(_) => {
            findings.push(string("vault_file_missing"));
            false
        }
    };
    let healthy = dir_ok && file_ok && header_valid && findings.is_empty();
    let os_backend = if cfg!(target_os = "macos") {
        "macos_keychain"
    } else if cfg!(target_os = "linux") {
        "linux_secret_service"
    } else {
        "local_encrypted_vault_only"
    };
    (
        object(&[
            ("schema", string(VAULT_CLI_RESPONSE_SCHEMA)),
            ("action", string("doctor")),
            (
                "verdict",
                string(if healthy {
                    "healthy"
                } else {
                    "attention_required"
                }),
            ),
            ("vault_dir", string(&opts.vault_dir.display().to_string())),
            ("vault_file_present", file_ok.to_string()),
            ("header_valid", header_valid.to_string()),
            ("platform_os_backend", string(os_backend)),
            ("findings", array(&findings)),
        ]),
        if healthy {
            ExitIdentity::SUCCESS
        } else {
            ExitIdentity::DOCTOR_ATTENTION_REQUIRED
        },
    )
}

fn parse_required_secret_id(opts: &VaultOpts) -> Result<SecretId, (String, ExitIdentity)> {
    let raw = opts.secret_id.as_deref().ok_or_else(|| {
        err_json(
            ERR_SECRET_INVALID_INPUT_001,
            "`--secret-id <id>` is required",
            ExitIdentity::MISSING_VALUE,
        )
    })?;
    SecretId::parse(raw).map_err(|err| {
        err_json(
            err.error_id(),
            &err.to_string(),
            ExitIdentity::MALFORMED_VALUE,
        )
    })
}

fn parse_required_scope(opts: &VaultOpts) -> Result<SecretScope, (String, ExitIdentity)> {
    let fam_raw = opts.family.as_deref().ok_or_else(|| {
        err_json(
            ERR_SECRET_INVALID_INPUT_001,
            "`--family <rtsp|tutk|onvif|unifi_protect|alert_webhook|alert_relay|storage_kek|archive_s3|operator_session>` is required",
            ExitIdentity::MISSING_VALUE,
        )
    })?;
    let family = AdapterFamily::from_str(fam_raw).map_err(|err| {
        err_json(
            err.error_id(),
            &err.to_string(),
            ExitIdentity::MALFORMED_VALUE,
        )
    })?;
    let target = opts.target.as_deref().ok_or_else(|| {
        err_json(
            ERR_SECRET_INVALID_INPUT_001,
            "`--target <sensor-or-target-id>` is required",
            ExitIdentity::MISSING_VALUE,
        )
    })?;
    let endpoint = opts.endpoint.as_deref().ok_or_else(|| {
        err_json(
            ERR_SECRET_INVALID_INPUT_001,
            "`--endpoint <scope>` is required",
            ExitIdentity::MISSING_VALUE,
        )
    })?;
    SecretScope::new(family, target, endpoint).map_err(|err| {
        err_json(
            err.error_id(),
            &err.to_string(),
            ExitIdentity::MALFORMED_VALUE,
        )
    })
}

fn read_passphrase(opts: &VaultOpts) -> Result<SecretBytes, (String, ExitIdentity)> {
    if let Some(path) = &opts.passphrase_file {
        read_secret_file_0600(path, opts.raw_bytes)
    } else if opts.passphrase_stdin {
        read_secret_stdin(opts.raw_bytes)
    } else {
        Err(err_json(
            ERR_SECRET_INVALID_INPUT_001,
            "supply `--passphrase-file <0600-file>` or `--passphrase-stdin` (never pass passphrases on argv)",
            ExitIdentity::MISSING_VALUE,
        ))
    }
}

fn read_secret_payload(opts: &VaultOpts) -> Result<SecretBytes, (String, ExitIdentity)> {
    if let Some(path) = &opts.secret_file {
        read_secret_file_0600(path, opts.raw_bytes)
    } else if opts.secret_stdin {
        read_secret_stdin(opts.raw_bytes)
    } else {
        Err(err_json(
            ERR_SECRET_INVALID_INPUT_001,
            "supply `--secret-file <0600-file>` or `--secret-stdin` (never pass secrets on argv)",
            ExitIdentity::MISSING_VALUE,
        ))
    }
}

/// Reads secret or passphrase bytes from a regular non-symlink `0600` file into [`SecretBytes`].
pub(crate) fn read_secret_file_0600(
    path: &Path,
    raw_bytes: bool,
) -> Result<SecretBytes, (String, ExitIdentity)> {
    let meta = fs::symlink_metadata(path).map_err(|err| {
        err_json(
            ERR_SECRET_INVALID_INPUT_001,
            &format!("cannot stat secret file: {err}"),
            ExitIdentity::RUNTIME_FAILURE,
        )
    })?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err(err_json(
            ERR_SECRET_PERMISSION_DENIED_001,
            "secret/passphrase file must be a regular non-symlink file",
            ExitIdentity::RUNTIME_FAILURE,
        ));
    }
    if !mode_is_owner_only(&meta, VAULT_FILE_MODE) {
        return Err(err_json(
            ERR_SECRET_PERMISSION_DENIED_001,
            "secret/passphrase file must have owner-only 0600 permissions (chmod 0600)",
            ExitIdentity::RUNTIME_FAILURE,
        ));
    }
    if meta.len() > MAX_SECRET_BYTES as u64 {
        return Err(err_json(
            ERR_SECRET_INVALID_INPUT_001,
            "secret file exceeds maximum allowed secret size",
            ExitIdentity::MALFORMED_VALUE,
        ));
    }
    let file = File::open(path).map_err(|err| {
        err_json(
            ERR_SECRET_INVALID_INPUT_001,
            &format!("cannot open secret file: {err}"),
            ExitIdentity::RUNTIME_FAILURE,
        )
    })?;
    let mut buf = Vec::new();
    file.take((MAX_SECRET_BYTES as u64).saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|err| {
            err_json(
                ERR_SECRET_INVALID_INPUT_001,
                &format!("cannot read secret file: {err}"),
                ExitIdentity::RUNTIME_FAILURE,
            )
        })?;
    finalize_secret_bytes(buf, raw_bytes)
}

fn read_secret_stdin(raw_bytes: bool) -> Result<SecretBytes, (String, ExitIdentity)> {
    let mut buf = Vec::new();
    io::stdin()
        .take((MAX_SECRET_BYTES as u64).saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|err| {
            err_json(
                ERR_SECRET_INVALID_INPUT_001,
                &format!("failed reading secret from stdin: {err}"),
                ExitIdentity::RUNTIME_FAILURE,
            )
        })?;
    finalize_secret_bytes(buf, raw_bytes)
}

fn finalize_secret_bytes(
    mut buf: Vec<u8>,
    raw_bytes: bool,
) -> Result<SecretBytes, (String, ExitIdentity)> {
    if !raw_bytes {
        if buf.ends_with(b"\r\n") {
            buf.truncate(buf.len().saturating_sub(2));
        } else if buf.ends_with(b"\n") {
            buf.truncate(buf.len().saturating_sub(1));
        }
    }
    if buf.is_empty() || buf.len() > MAX_SECRET_BYTES {
        buf.fill(0);
    }
    SecretBytes::new(buf).map_err(|err| {
        err_json(
            err.error_id(),
            &err.to_string(),
            ExitIdentity::MALFORMED_VALUE,
        )
    })
}

pub(crate) fn build_secret_cx(
    principal: &str,
    op_id_str: &str,
    caps: &[&str],
    scope: SecretScope,
) -> Result<SecretAccessCx, (String, ExitIdentity)> {
    let op_id = OperationId::parse(op_id_str).map_err(|_| {
        err_json(
            ERR_SECRET_INVALID_INPUT_001,
            "invalid operation id for secret context",
            ExitIdentity::RUNTIME_FAILURE,
        )
    })?;
    let budgets = BudgetVector::builder().bytes(65_536).build().map_err(|_| {
        err_json(
            ERR_SECRET_INVALID_INPUT_001,
            "failed building secret access budget",
            ExitIdentity::RUNTIME_FAILURE,
        )
    })?;
    let auth = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: format!("trace:cli:{op_id_str}"),
        operation_id: op_id,
        principal: principal.to_owned(),
        capabilities: caps.iter().map(|s| (*s).to_owned()).collect(),
        deadline: None,
        priority: 1,
        budgets,
        privacy_scope: "privacy:operator-vault".to_owned(),
        retention_scope: "retention:operator-vault".to_owned(),
        anchor_universe: scope.scope_digest(),
        generation: 1,
    })
    .map_err(|err| {
        err_json(
            ERR_SECRET_INVALID_INPUT_001,
            &format!("failed building ContextAuthority: {err}"),
            ExitIdentity::RUNTIME_FAILURE,
        )
    })?;
    SecretAccessCx::new(auth, scope, current_timestamp_ns()).map_err(|err| {
        err_json(
            err.error_id(),
            &err.to_string(),
            ExitIdentity::RUNTIME_FAILURE,
        )
    })
}

fn render_handle_json(h: &SecretHandle) -> String {
    object(&[
        ("secret_id", string(h.secret_id.as_str())),
        ("adapter_family", string(h.scope.adapter_family().as_str())),
        ("target_id", string(h.scope.sensor_or_target_id())),
        ("endpoint_scope", string(h.scope.endpoint_scope())),
        ("generation", h.generation.to_string()),
        ("scope_digest", string(&h.scope_digest.to_text())),
        ("revoked", h.revoked.to_string()),
        ("backend", string(h.backend_kind.as_str())),
    ])
}

fn read_bounded_header(path: &Path) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut buf = Vec::with_capacity(VAULT_HEADER_LEN);
    file.take(VAULT_HEADER_LEN as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

#[cfg(unix)]
fn mode_is_owner_only(meta: &fs::Metadata, _expected: u32) -> bool {
    use std::os::unix::fs::PermissionsExt;
    (meta.permissions().mode() & 0o077) == 0
}

#[cfg(not(unix))]
fn mode_is_owner_only(_meta: &fs::Metadata, _expected: u32) -> bool {
    true
}

pub(crate) fn current_timestamp_ns() -> TimestampNs {
    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1_700_000_000_000_000_000, |d| {
            i128::try_from(d.as_nanos()).unwrap_or(1_700_000_000_000_000_000)
        });
    TimestampNs(ns)
}

fn err_json(code: &str, message: &str, exit: ExitIdentity) -> (String, ExitIdentity) {
    (
        object(&[
            ("schema", string("fss.vault_error.v1")),
            ("error_id", string(code)),
            ("message", string(message)),
        ]),
        exit,
    )
}
