#![forbid(unsafe_code)]
//! `fss notify <preview|dispatch>` — production pure-Rust RFC 8446 TLS 1.3 webhook & multi-channel
//! relay (`https-webhook`, `ntfy`, `pushover`, `smtps`, `smtp-starttls`) CLI wired to
//! `fss_reference::notify`, `fss_vault`, and `DurableEffectJournal`.
//!
//! Semantic plane: `"effect"`.
//!
//! # Safety & Security Invariants
//! - Two-step approval required: `fss notify preview` computes exact `route_digest` and
//!   `approval_digest` (`fss.notify.cli_approval.v1`) with ZERO network I/O and ZERO secret reads;
//!   `fss notify dispatch` requires `--approve <sha256>` matching that exact preview digest.
//! - Plaintext `http://` targets fail closed with `ERR-NOTIFY-PLAINTEXT-REFUSED-001`.
//! - Secrets are loaded exclusively from `fss-vault` under exact `SecretAccessCx` scoping.
//! - Effects execute through `DurableEffectJournal` (when `--effects-journal` or `--root` is set)
//!   so `Indeterminate` operations can NEVER be silently resent (`ERR-NOTIFY-INDETERMINATE-001`).

use std::fs::{self, File};
use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use fss_core::{
    CanonicalEncoder, ContentDigest, EffectJournal, EventId, IdempotencyKey, ObligationId,
    OperationId,
};
use fss_reference::DurableEffectJournal;
use fss_reference::notify::escalation::{
    NotificationChannelTarget, dispatch_prepared_notification, prepare_notification_effect,
};
use fss_reference::notify::relays::{NtfyTarget, PushoverTarget};
use fss_reference::notify::smtp::{SmtpSecurityMode, SmtpTlsTarget};
use fss_reference::notify::webhook::HttpsWebhookTarget;
use fss_reference::notify::x509::{MAX_PEM_BUNDLE_BYTES, TlsTrustPolicy};
use fss_reference::notify::{
    DisclosureProfile, DnsResolver, NotifyDeadlineCx, NotifyEventMetadata, NotifyLimits,
    NotifyPayload, PinnedDnsResolver, SystemDnsResolver,
};
use fss_vault::{CAP_SECRET_READ_001, LocalEncryptedVault, OsEntropy, SecretId};

use crate::agent_json::{object, string};
use crate::error::ExitIdentity;
use crate::token::ArgToken;
use crate::vault_cmd::{build_secret_cx, current_timestamp_ns, read_secret_file_0600};

/// Canonical JSON response schema for `fss notify preview|dispatch`.
pub const NOTIFY_CLI_RESPONSE_SCHEMA: &str = "fss.notify_response.v1";
/// Canonical digest domain for `fss notify` two-step CLI preview/dispatch approvals.
pub const NOTIFY_CLI_APPROVAL_DOMAIN: &str = "fss.notify.cli_approval.v1";

const FORBIDDEN_SECRET_FLAGS: &[&str] = &[
    "--secret",
    "--password",
    "--passphrase",
    "--token",
    "--hmac-key",
    "--bearer",
    "--api-key",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChannelKind {
    HttpsWebhook,
    Ntfy,
    Pushover,
    Smtps,
    SmtpStartTls,
}

impl ChannelKind {
    fn parse(s: &str) -> Result<Self, &'static str> {
        match s {
            "https-webhook" => Ok(Self::HttpsWebhook),
            "ntfy" => Ok(Self::Ntfy),
            "pushover" => Ok(Self::Pushover),
            "smtps" => Ok(Self::Smtps),
            "smtp-starttls" => Ok(Self::SmtpStartTls),
            _ => Err(
                "unknown --channel (expected https-webhook, ntfy, pushover, smtps, or smtp-starttls)",
            ),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::HttpsWebhook => "https-webhook",
            Self::Ntfy => "ntfy",
            Self::Pushover => "pushover",
            Self::Smtps => "smtps",
            Self::SmtpStartTls => "smtp-starttls",
        }
    }
}

struct NotifyOpts {
    channel: ChannelKind,
    target_id: String,
    url: Option<String>,
    topic: Option<String>,
    smtp_host: Option<String>,
    smtp_port: Option<u16>,
    smtp_from: Option<String>,
    smtp_to: Vec<String>,
    smtp_ehlo: String,
    secret_id: SecretId,
    secondary_secret_id: Option<SecretId>,
    disclosure: DisclosureProfile,
    metadata_approval: Option<ContentDigest>,
    event_id: Option<EventId>,
    event_root: ContentDigest,
    event_revision_digest: ContentDigest,
    event_summary: String,
    operation_id: OperationId,
    idempotency_key: IdempotencyKey,
    ca_pem: Option<PathBuf>,
    pin_spki: Option<ContentDigest>,
    approve: Option<ContentDigest>,
    vault_dir: Option<PathBuf>,
    passphrase_file: Option<PathBuf>,
    effects_journal: Option<PathBuf>,
    root: Option<PathBuf>,
    resolve_entries: Vec<(String, SocketAddr)>,
    timeout_ms: u64,
    principal: String,
    priority: u8,
}

/// Executes an in-process `fss notify <preview|dispatch>` command.
#[must_use]
pub fn execute_notify_command(
    verb: &str,
    args: &[ArgToken],
    control: &crate::RequestControl<'_>,
) -> (String, ExitIdentity) {
    if control.is_cancelled() {
        return err_json(
            "ERR-CLI-READ-CANCELLED-001",
            "notify operation cancelled before dispatch",
            ExitIdentity::RUNTIME_FAILURE,
        );
    }
    for tok in args {
        let s = tok.as_str();
        let flag = s.split_once('=').map_or(s, |(k, _)| k);
        if FORBIDDEN_SECRET_FLAGS.contains(&flag) {
            return err_json(
                "ERR-NOTIFY-VAULT-001",
                "plaintext secrets are forbidden on CLI argv; store secrets in fss-vault and pass --secret-id",
                ExitIdentity::MALFORMED_VALUE,
            );
        }
    }
    match verb {
        "preview" => exec_preview(args),
        "dispatch" => exec_dispatch(args),
        other => err_json(
            "ERR-CLI-UNKNOWN-COMMAND-001",
            &format!("unknown notify verb `{other}` (expected preview or dispatch)"),
            ExitIdentity::UNKNOWN_COMMAND,
        ),
    }
}

fn parse_notify_opts(
    verb: &str,
    tokens: &[ArgToken],
) -> Result<NotifyOpts, (String, ExitIdentity)> {
    let mut channel_raw: Option<String> = None;
    let mut target_id: Option<String> = None;
    let mut url: Option<String> = None;
    let mut topic: Option<String> = None;
    let mut smtp_host: Option<String> = None;
    let mut smtp_port: Option<u16> = None;
    let mut smtp_from: Option<String> = None;
    let mut smtp_to: Vec<String> = Vec::new();
    let mut smtp_ehlo = "fss.local".to_owned();
    let mut secret_id_raw: Option<String> = None;
    let mut secondary_secret_raw: Option<String> = None;
    let mut disclosure_raw = "references-v1".to_owned();
    let mut metadata_approval_raw: Option<String> = None;
    let mut event_id_raw: Option<String> = None;
    let mut event_root_raw: Option<String> = None;
    let mut event_rev_raw: Option<String> = None;
    let mut event_summary = "Corroborated surveillance event".to_owned();
    let mut op_id_raw: Option<String> = None;
    let mut idem_raw: Option<String> = None;
    let mut ca_pem: Option<PathBuf> = None;
    let mut pin_spki_raw: Option<String> = None;
    let mut approve_raw: Option<String> = None;
    let mut vault_dir: Option<PathBuf> = None;
    let mut passphrase_file: Option<PathBuf> = None;
    let mut effects_journal: Option<PathBuf> = None;
    let mut root: Option<PathBuf> = None;
    let mut resolve_entries: Vec<(String, SocketAddr)> = Vec::new();
    let mut timeout_ms = 10_000_u64;
    let mut principal = "principal:local-operator".to_owned();
    let mut priority = 4_u8;

    let mut i = 0_usize;
    while i < tokens.len() {
        let raw = tokens[i].as_str();
        let (flag, inline) = match raw.split_once('=') {
            Some((k, v)) => (k, Some(v)),
            None => (raw, None),
        };
        let next_val = |idx: &mut usize, name: &str| -> Result<String, (String, ExitIdentity)> {
            if let Some(v) = inline {
                return Ok(v.to_owned());
            }
            *idx += 1;
            let Some(tok) = tokens.get(*idx) else {
                return Err(err_json(
                    "ERR-CLI-MISSING-VALUE-001",
                    &format!("missing value for `{name}` in `fss notify {verb}`"),
                    ExitIdentity::MISSING_VALUE,
                ));
            };
            Ok(tok.as_str().to_owned())
        };
        match flag {
            "--channel" => channel_raw = Some(next_val(&mut i, "--channel")?),
            "--target-id" => target_id = Some(next_val(&mut i, "--target-id")?),
            "--url" => url = Some(next_val(&mut i, "--url")?),
            "--topic" => topic = Some(next_val(&mut i, "--topic")?),
            "--smtp-host" => smtp_host = Some(next_val(&mut i, "--smtp-host")?),
            "--smtp-port" => {
                let s = next_val(&mut i, "--smtp-port")?;
                smtp_port = Some(s.parse::<u16>().map_err(|_| {
                    err_json(
                        "ERR-CLI-MALFORMED-VALUE-001",
                        "invalid --smtp-port",
                        ExitIdentity::MALFORMED_VALUE,
                    )
                })?);
            }
            "--smtp-from" => smtp_from = Some(next_val(&mut i, "--smtp-from")?),
            "--smtp-to" => smtp_to.push(next_val(&mut i, "--smtp-to")?),
            "--smtp-ehlo" => smtp_ehlo = next_val(&mut i, "--smtp-ehlo")?,
            "--secret-id" => secret_id_raw = Some(next_val(&mut i, "--secret-id")?),
            "--secondary-secret-id" => {
                secondary_secret_raw = Some(next_val(&mut i, "--secondary-secret-id")?);
            }
            "--disclosure" => disclosure_raw = next_val(&mut i, "--disclosure")?,
            "--metadata-approval" => {
                metadata_approval_raw = Some(next_val(&mut i, "--metadata-approval")?);
            }
            "--event-id" => event_id_raw = Some(next_val(&mut i, "--event-id")?),
            "--event-root" => event_root_raw = Some(next_val(&mut i, "--event-root")?),
            "--event-revision" => event_rev_raw = Some(next_val(&mut i, "--event-revision")?),
            "--summary" => event_summary = next_val(&mut i, "--summary")?,
            "--operation-id" => op_id_raw = Some(next_val(&mut i, "--operation-id")?),
            "--idempotency-key" => idem_raw = Some(next_val(&mut i, "--idempotency-key")?),
            "--ca-pem" => ca_pem = Some(PathBuf::from(next_val(&mut i, "--ca-pem")?)),
            "--pin-spki" => pin_spki_raw = Some(next_val(&mut i, "--pin-spki")?),
            "--approve" => approve_raw = Some(next_val(&mut i, "--approve")?),
            "--vault-dir" => vault_dir = Some(PathBuf::from(next_val(&mut i, "--vault-dir")?)),
            "--passphrase-file" => {
                passphrase_file = Some(PathBuf::from(next_val(&mut i, "--passphrase-file")?));
            }
            "--effects-journal" => {
                effects_journal = Some(PathBuf::from(next_val(&mut i, "--effects-journal")?));
            }
            "--root" => root = Some(PathBuf::from(next_val(&mut i, "--root")?)),
            "--resolve" => {
                let entry = next_val(&mut i, "--resolve")?;
                let Some((host, addr_str)) = entry.split_once('=') else {
                    return Err(err_json(
                        "ERR-CLI-MALFORMED-VALUE-001",
                        "--resolve must be `host=ip:port`",
                        ExitIdentity::MALFORMED_VALUE,
                    ));
                };
                let addr: SocketAddr = addr_str.parse().map_err(|_| {
                    err_json(
                        "ERR-CLI-MALFORMED-VALUE-001",
                        "invalid socket address in --resolve",
                        ExitIdentity::MALFORMED_VALUE,
                    )
                })?;
                resolve_entries.push((host.to_ascii_lowercase(), addr));
            }
            "--timeout-ms" => {
                let s = next_val(&mut i, "--timeout-ms")?;
                timeout_ms = s.parse::<u64>().map_err(|_| {
                    err_json(
                        "ERR-CLI-MALFORMED-VALUE-001",
                        "invalid --timeout-ms integer",
                        ExitIdentity::MALFORMED_VALUE,
                    )
                })?;
            }
            "--priority" => {
                let s = next_val(&mut i, "--priority")?;
                priority = s.parse::<u8>().map_err(|_| {
                    err_json(
                        "ERR-CLI-MALFORMED-VALUE-001",
                        "invalid --priority integer",
                        ExitIdentity::MALFORMED_VALUE,
                    )
                })?;
            }
            "--principal" => principal = next_val(&mut i, "--principal")?,
            "--json" => {}
            other => {
                return Err(err_json(
                    "ERR-CLI-UNKNOWN-OPTION-001",
                    &format!("unknown option `{other}` for `fss notify {verb}`"),
                    ExitIdentity::UNKNOWN_OPTION,
                ));
            }
        }
        i += 1;
    }

    let channel = ChannelKind::parse(channel_raw.as_deref().unwrap_or("")).map_err(|m| {
        err_json(
            "ERR-CLI-MALFORMED-VALUE-001",
            m,
            ExitIdentity::MALFORMED_VALUE,
        )
    })?;
    let target_id = target_id.ok_or_else(|| {
        err_json(
            "ERR-CLI-MISSING-VALUE-001",
            "`--target-id <id>` is required",
            ExitIdentity::MISSING_VALUE,
        )
    })?;
    let secret_id = SecretId::parse(secret_id_raw.as_deref().ok_or_else(|| {
        err_json(
            "ERR-CLI-MISSING-VALUE-001",
            "`--secret-id <vault-secret-id>` is required",
            ExitIdentity::MISSING_VALUE,
        )
    })?)
    .map_err(|e| err_json(e.error_id(), &e.to_string(), ExitIdentity::MALFORMED_VALUE))?;
    let secondary_secret_id =
        match secondary_secret_raw {
            Some(raw) => Some(SecretId::parse(&raw).map_err(|e| {
                err_json(e.error_id(), &e.to_string(), ExitIdentity::MALFORMED_VALUE)
            })?),
            None => None,
        };
    let disclosure = DisclosureProfile::parse(&disclosure_raw)
        .map_err(|e| err_json(e.code, &e.to_string(), ExitIdentity::MALFORMED_VALUE))?;
    let metadata_approval = parse_opt_digest("--metadata-approval", metadata_approval_raw)?;
    let pin_spki = parse_opt_digest("--pin-spki", pin_spki_raw)?;
    let approve = parse_opt_digest("--approve", approve_raw)?;
    let event_id = match event_id_raw {
        Some(raw) => Some(EventId::parse(raw).map_err(|_| {
            err_json(
                "ERR-CLI-MALFORMED-VALUE-001",
                "invalid --event-id",
                ExitIdentity::MALFORMED_VALUE,
            )
        })?),
        None => None,
    };
    let event_root = parse_opt_digest("--event-root", event_root_raw)?
        .unwrap_or_else(|| ContentDigest::sha256(target_id.as_bytes()));
    let event_revision_digest =
        parse_opt_digest("--event-revision", event_rev_raw)?.unwrap_or(event_root);
    let operation_id = OperationId::parse(op_id_raw.as_deref().ok_or_else(|| {
        err_json(
            "ERR-CLI-MISSING-VALUE-001",
            "`--operation-id <id>` is required",
            ExitIdentity::MISSING_VALUE,
        )
    })?)
    .map_err(|_| {
        err_json(
            "ERR-CLI-MALFORMED-VALUE-001",
            "invalid --operation-id",
            ExitIdentity::MALFORMED_VALUE,
        )
    })?;
    let idempotency_key = IdempotencyKey::parse(idem_raw.as_deref().ok_or_else(|| {
        err_json(
            "ERR-CLI-MISSING-VALUE-001",
            "`--idempotency-key <key>` is required",
            ExitIdentity::MISSING_VALUE,
        )
    })?)
    .map_err(|_| {
        err_json(
            "ERR-CLI-MALFORMED-VALUE-001",
            "invalid --idempotency-key",
            ExitIdentity::MALFORMED_VALUE,
        )
    })?;

    Ok(NotifyOpts {
        channel,
        target_id,
        url,
        topic,
        smtp_host,
        smtp_port,
        smtp_from,
        smtp_to,
        smtp_ehlo,
        secret_id,
        secondary_secret_id,
        disclosure,
        metadata_approval,
        event_id,
        event_root,
        event_revision_digest,
        event_summary,
        operation_id,
        idempotency_key,
        ca_pem,
        pin_spki,
        approve,
        vault_dir,
        passphrase_file,
        effects_journal,
        root,
        resolve_entries,
        timeout_ms,
        principal,
        priority,
    })
}

enum BuiltTarget {
    HttpsWebhook(HttpsWebhookTarget),
    Ntfy(NtfyTarget),
    Pushover(PushoverTarget),
    SmtpTls(SmtpTlsTarget),
}

impl BuiltTarget {
    fn route_digest(&self) -> ContentDigest {
        match self {
            Self::HttpsWebhook(t) => t.route_digest,
            Self::Ntfy(t) => t.route_digest,
            Self::Pushover(t) => t.route_digest,
            Self::SmtpTls(t) => t.route_digest,
        }
    }

    fn secret_scope(&self) -> &fss_vault::SecretScope {
        match self {
            Self::HttpsWebhook(t) => &t.secret_scope,
            Self::Ntfy(t) => &t.secret_scope,
            Self::Pushover(t) => &t.secret_scope,
            Self::SmtpTls(t) => &t.secret_scope,
        }
    }

    fn as_channel_target(&self) -> NotificationChannelTarget<'_> {
        match self {
            Self::HttpsWebhook(t) => NotificationChannelTarget::HttpsWebhook(t),
            Self::Ntfy(t) => NotificationChannelTarget::Ntfy(t),
            Self::Pushover(t) => NotificationChannelTarget::Pushover(t),
            Self::SmtpTls(t) => NotificationChannelTarget::SmtpTls(t),
        }
    }
}

fn load_trust_policy(opts: &NotifyOpts) -> Result<TlsTrustPolicy, (String, ExitIdentity)> {
    let mut policy = if let Some(pem_path) = &opts.ca_pem {
        let meta = fs::symlink_metadata(pem_path).map_err(|err| {
            err_json(
                "ERR-NOTIFY-TLS-CERT-001",
                &format!("cannot stat --ca-pem: {err}"),
                ExitIdentity::RUNTIME_FAILURE,
            )
        })?;
        if meta.file_type().is_symlink()
            || !meta.is_file()
            || meta.len() > MAX_PEM_BUNDLE_BYTES as u64
        {
            return Err(err_json(
                "ERR-NOTIFY-TLS-CERT-001",
                "--ca-pem must be a regular non-symlink file <= 256 KiB",
                ExitIdentity::MALFORMED_VALUE,
            ));
        }
        let file = File::open(pem_path).map_err(|err| {
            err_json(
                "ERR-NOTIFY-TLS-CERT-001",
                &format!("cannot open --ca-pem: {err}"),
                ExitIdentity::RUNTIME_FAILURE,
            )
        })?;
        let opened_meta = file.metadata().map_err(|err| {
            err_json(
                "ERR-NOTIFY-TLS-CERT-001",
                &format!("cannot stat --ca-pem: {err}"),
                ExitIdentity::RUNTIME_FAILURE,
            )
        })?;
        if !opened_meta.file_type().is_file() {
            return Err(err_json(
                "ERR-NOTIFY-TLS-CERT-001",
                "--ca-pem must be a regular non-symlink file <= 256 KiB",
                ExitIdentity::MALFORMED_VALUE,
            ));
        }
        let mut pem_bytes = Vec::new();
        file.take((MAX_PEM_BUNDLE_BYTES as u64).saturating_add(1))
            .read_to_end(&mut pem_bytes)
            .map_err(|err| {
                err_json(
                    "ERR-NOTIFY-TLS-CERT-001",
                    &format!("cannot read --ca-pem: {err}"),
                    ExitIdentity::RUNTIME_FAILURE,
                )
            })?;
        if pem_bytes.len() > MAX_PEM_BUNDLE_BYTES {
            return Err(err_json(
                "ERR-NOTIFY-TLS-CERT-001",
                "--ca-pem exceeds 256 KiB bound",
                ExitIdentity::MALFORMED_VALUE,
            ));
        }
        let pem = String::from_utf8(pem_bytes).map_err(|_| {
            err_json(
                "ERR-NOTIFY-TLS-CERT-001",
                "--ca-pem must be valid UTF-8 PEM text",
                ExitIdentity::MALFORMED_VALUE,
            )
        })?;
        TlsTrustPolicy::from_pem_bundle(&pem).map_err(|err| {
            err_json(
                err.error_code(),
                &err.to_string(),
                ExitIdentity::MALFORMED_VALUE,
            )
        })?
    } else if let Some(pin) = opts.pin_spki {
        TlsTrustPolicy::from_pinned_leaf_spki(pin)
    } else {
        return Err(err_json(
            "ERR-NOTIFY-TLS-CERT-001",
            "explicit TLS 1.3 trust anchor required: supply `--ca-pem <file>` or `--pin-spki <sha256>`",
            ExitIdentity::MISSING_VALUE,
        ));
    };
    if let Some(pin) = opts.pin_spki
        && opts.ca_pem.is_some()
    {
        policy = policy.with_pinned_leaf_spki(pin);
    }
    Ok(policy)
}

fn build_target(
    opts: &NotifyOpts,
    trust: TlsTrustPolicy,
) -> Result<BuiltTarget, (String, ExitIdentity)> {
    match opts.channel {
        ChannelKind::HttpsWebhook => {
            let url = opts.url.as_deref().ok_or_else(|| {
                err_json(
                    "ERR-CLI-MISSING-VALUE-001",
                    "https-webhook requires `--url https://...`",
                    ExitIdentity::MISSING_VALUE,
                )
            })?;
            HttpsWebhookTarget::new(
                &opts.target_id,
                url,
                opts.secret_id.clone(),
                trust,
                opts.disclosure,
                opts.metadata_approval,
                None,
            )
            .map(BuiltTarget::HttpsWebhook)
            .map_err(|e| err_json(e.code, &e.to_string(), ExitIdentity::MALFORMED_VALUE))
        }
        ChannelKind::Ntfy => {
            let url = opts.url.as_deref().ok_or_else(|| {
                err_json(
                    "ERR-CLI-MISSING-VALUE-001",
                    "ntfy requires `--url https://...`",
                    ExitIdentity::MISSING_VALUE,
                )
            })?;
            let topic = opts.topic.as_deref().ok_or_else(|| {
                err_json(
                    "ERR-CLI-MISSING-VALUE-001",
                    "ntfy requires `--topic <topic>`",
                    ExitIdentity::MISSING_VALUE,
                )
            })?;
            NtfyTarget::new(
                &opts.target_id,
                url,
                topic,
                opts.secret_id.clone(),
                trust,
                opts.disclosure,
                opts.metadata_approval,
                None,
                opts.priority,
                Vec::new(),
            )
            .map(BuiltTarget::Ntfy)
            .map_err(|e| err_json(e.code, &e.to_string(), ExitIdentity::MALFORMED_VALUE))
        }
        ChannelKind::Pushover => {
            let url = opts
                .url
                .as_deref()
                .unwrap_or("https://api.pushover.net/1/messages.json");
            let user_secret_id = opts.secondary_secret_id.clone().ok_or_else(|| {
                err_json(
                    "ERR-CLI-MISSING-VALUE-001",
                    "pushover requires `--secondary-secret-id <user-key-secret-id>`",
                    ExitIdentity::MISSING_VALUE,
                )
            })?;
            PushoverTarget::new(
                &opts.target_id,
                url,
                opts.secret_id.clone(),
                user_secret_id,
                trust,
                opts.disclosure,
                opts.metadata_approval,
                None,
                0,
            )
            .map(BuiltTarget::Pushover)
            .map_err(|e| err_json(e.code, &e.to_string(), ExitIdentity::MALFORMED_VALUE))
        }
        ChannelKind::Smtps | ChannelKind::SmtpStartTls => {
            let host = opts.smtp_host.as_deref().ok_or_else(|| {
                err_json(
                    "ERR-CLI-MISSING-VALUE-001",
                    "smtp requires `--smtp-host <host>`",
                    ExitIdentity::MISSING_VALUE,
                )
            })?;
            let default_port = if opts.channel == ChannelKind::Smtps {
                465
            } else {
                587
            };
            let port = opts.smtp_port.unwrap_or(default_port);
            let from = opts.smtp_from.as_deref().ok_or_else(|| {
                err_json(
                    "ERR-CLI-MISSING-VALUE-001",
                    "smtp requires `--smtp-from <email>`",
                    ExitIdentity::MISSING_VALUE,
                )
            })?;
            let pass_secret = opts.secondary_secret_id.clone().ok_or_else(|| {
                err_json(
                    "ERR-CLI-MISSING-VALUE-001",
                    "smtp requires `--secondary-secret-id <password-secret-id>`",
                    ExitIdentity::MISSING_VALUE,
                )
            })?;
            let mode = if opts.channel == ChannelKind::Smtps {
                SmtpSecurityMode::ImplicitTls
            } else {
                SmtpSecurityMode::StartTls
            };
            SmtpTlsTarget::new(
                &opts.target_id,
                host,
                port,
                mode,
                &opts.smtp_ehlo,
                from,
                opts.smtp_to.clone(),
                opts.secret_id.clone(),
                pass_secret,
                trust,
                opts.disclosure,
                opts.metadata_approval,
                None,
            )
            .map(BuiltTarget::SmtpTls)
            .map_err(|e| err_json(e.code, &e.to_string(), ExitIdentity::MALFORMED_VALUE))
        }
    }
}

fn build_payload(opts: &NotifyOpts) -> Result<NotifyPayload, (String, ExitIdentity)> {
    let event_metadata = match opts.disclosure {
        DisclosureProfile::ReferencesV1 => None,
        DisclosureProfile::EventMetadataV1 | DisclosureProfile::EventMetadataVisualV1 => {
            let event_id = opts.event_id.clone().ok_or_else(|| {
                err_json(
                    "ERR-NOTIFY-DISCLOSURE-001",
                    "event-metadata disclosure requires `--event-id <id>`",
                    ExitIdentity::MISSING_VALUE,
                )
            })?;
            Some(NotifyEventMetadata {
                event_id,
                revision: 1,
                kind: "unknown_presence".to_owned(),
                lifecycle: "corroborated".to_owned(),
                zone_ids: Vec::new(),
                summary: opts.event_summary.clone(),
            })
        }
    };
    let payload = NotifyPayload {
        operation_id: opts.operation_id.clone(),
        idempotency_key: opts.idempotency_key.clone(),
        event_root: opts.event_root,
        event_revision_digest: opts.event_revision_digest,
        channel: opts.channel.as_str().to_owned(),
        event_metadata,
        visual_attachment: None,
    };
    payload
        .validate_for_profile(opts.disclosure)
        .map_err(|e| err_json(e.code, &e.to_string(), ExitIdentity::MALFORMED_VALUE))?;
    Ok(payload)
}

fn compute_cli_approval(opts: &NotifyOpts, route_digest: ContentDigest) -> ContentDigest {
    let mut enc = CanonicalEncoder::new();
    enc.text("fss.canonical.v1");
    enc.text(NOTIFY_CLI_APPROVAL_DOMAIN);
    enc.text(opts.channel.as_str());
    enc.text(&opts.target_id);
    enc.digest(route_digest);
    enc.text(opts.operation_id.as_str());
    enc.text(opts.idempotency_key.as_str());
    enc.digest(opts.event_root);
    enc.digest(opts.event_revision_digest);
    enc.text(opts.disclosure.as_str());
    ContentDigest::sha256(&enc.finish())
}

fn exec_preview(args: &[ArgToken]) -> (String, ExitIdentity) {
    let opts = match parse_notify_opts("preview", args) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let trust = match load_trust_policy(&opts) {
        Ok(t) => t,
        Err(e) => return e,
    };
    let target = match build_target(&opts, trust) {
        Ok(t) => t,
        Err(e) => return e,
    };
    let _payload = match build_payload(&opts) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let route_digest = target.route_digest();
    let approval_digest = compute_cli_approval(&opts, route_digest);
    let approve_cmd = format!(
        "fss notify dispatch --channel {} --target-id {} --secret-id {} --operation-id {} --idempotency-key {} --approve {} --vault-dir <vault-dir> --passphrase-file <0600-file> --json",
        opts.channel.as_str(),
        opts.target_id,
        opts.secret_id.as_str(),
        opts.operation_id.as_str(),
        opts.idempotency_key.as_str(),
        approval_digest.to_text(),
    );
    (
        object(&[
            ("schema", string(NOTIFY_CLI_RESPONSE_SCHEMA)),
            ("action", string("preview")),
            ("network_io_executed", "false".to_owned()),
            ("channel", string(opts.channel.as_str())),
            ("target_id", string(&opts.target_id)),
            ("disclosure_profile", string(opts.disclosure.as_str())),
            ("route_digest", string(&route_digest.to_text())),
            ("approval_digest", string(&approval_digest.to_text())),
            ("approve_command", string(&approve_cmd)),
        ]),
        ExitIdentity::SUCCESS,
    )
}

fn exec_dispatch(args: &[ArgToken]) -> (String, ExitIdentity) {
    let opts = match parse_notify_opts("dispatch", args) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let trust = match load_trust_policy(&opts) {
        Ok(t) => t,
        Err(e) => return e,
    };
    let target = match build_target(&opts, trust) {
        Ok(t) => t,
        Err(e) => return e,
    };
    let payload = match build_payload(&opts) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let route_digest = target.route_digest();
    let expected_approval = compute_cli_approval(&opts, route_digest);
    let Some(supplied_approval) = opts.approve else {
        return err_json(
            "ERR-NOTIFY-APPROVAL-REQUIRED-001",
            &format!(
                "missing `--approve {}`; run `fss notify preview` first",
                expected_approval.to_text()
            ),
            ExitIdentity::AGENT_REFUSED,
        );
    };
    if supplied_approval != expected_approval {
        return err_json(
            "ERR-NOTIFY-APPROVAL-MISMATCH-001",
            &format!(
                "`--approve` digest does not match canonical preview approval {}",
                expected_approval.to_text()
            ),
            ExitIdentity::AGENT_REFUSED,
        );
    }

    let Some(vault_dir) = &opts.vault_dir else {
        return err_json(
            "ERR-NOTIFY-VAULT-001",
            "`--vault-dir <dir>` is required to fetch scoped relay credentials",
            ExitIdentity::MISSING_VALUE,
        );
    };
    let Some(pass_file) = &opts.passphrase_file else {
        return err_json(
            "ERR-NOTIFY-VAULT-001",
            "`--passphrase-file <0600-file>` is required to unlock the vault",
            ExitIdentity::MISSING_VALUE,
        );
    };
    let passphrase = match read_secret_file_0600(pass_file, false) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let mut vault = LocalEncryptedVault::open(vault_dir);
    if let Err(err) = vault.unlock(&passphrase) {
        return err_json(
            err.error_id(),
            &err.to_string(),
            ExitIdentity::RUNTIME_FAILURE,
        );
    }
    let secret_cx = match build_secret_cx(
        &opts.principal,
        opts.operation_id.as_str(),
        &[CAP_SECRET_READ_001],
        target.secret_scope().clone(),
    ) {
        Ok(cx) => cx,
        Err(e) => {
            vault.lock();
            return e;
        }
    };

    let now = current_timestamp_ns();
    let deadline = match NotifyDeadlineCx::new(now, Duration::from_millis(opts.timeout_ms.max(1))) {
        Ok(d) => d,
        Err(err) => {
            vault.lock();
            return err_json(err.code, &err.to_string(), ExitIdentity::MALFORMED_VALUE);
        }
    };
    let mut pinned_dns = PinnedDnsResolver::new();
    for (host, addr) in &opts.resolve_entries {
        pinned_dns = pinned_dns.with_entry(host.clone(), *addr);
    }
    let dns: &dyn DnsResolver = if opts.resolve_entries.is_empty() {
        &SystemDnsResolver
    } else {
        &pinned_dns
    };
    let mut entropy = OsEntropy::new();
    let limits = NotifyLimits::default();
    let ob_id = match ObligationId::parse(format!(
        "ob:notify:{}",
        opts.operation_id.as_str().replace(':', "-")
    ))
    .or_else(|_| ObligationId::parse("ob:notify:dispatch"))
    {
        Ok(id) => id,
        Err(_) => {
            vault.lock();
            return err_json(
                "ERR-CLI-MALFORMED-VALUE-001",
                "failed to derive canonical notification obligation identifier",
                ExitIdentity::MALFORMED_VALUE,
            );
        }
    };

    let journal_path = opts
        .effects_journal
        .clone()
        .or_else(|| opts.root.as_ref().map(|r| r.join("effects/journal.fssj")));

    let outcome = if let Some(jpath) = journal_path {
        let mut journal =
            match DurableEffectJournal::open(&jpath, fss_ledger::IncompleteTailPolicy::Reject) {
                Ok(j) => j,
                Err(err) => {
                    vault.lock();
                    return err_json(
                        "ERR-NOTIFY-TRANSPORT-001",
                        &format!("failed opening durable effect journal: {err}"),
                        ExitIdentity::RUNTIME_FAILURE,
                    );
                }
            };
        if journal.operation(&opts.operation_id).is_none()
            && let Err(err) = prepare_notification_effect(
                &mut journal,
                &payload,
                route_digest,
                expected_approval,
                ob_id,
                now,
            )
        {
            vault.lock();
            return err_json(err.code, &err.to_string(), ExitIdentity::RUNTIME_FAILURE);
        }
        let res = dispatch_prepared_notification(
            &mut journal,
            target.as_channel_target(),
            &payload,
            &vault,
            &secret_cx,
            dns,
            &deadline,
            limits,
            &mut entropy,
        );
        (res, true)
    } else {
        let mut journal = EffectJournal::new();
        if let Err(err) = prepare_notification_effect(
            &mut journal,
            &payload,
            route_digest,
            expected_approval,
            ob_id,
            now,
        ) {
            vault.lock();
            return err_json(err.code, &err.to_string(), ExitIdentity::RUNTIME_FAILURE);
        }
        let res = dispatch_prepared_notification(
            &mut journal,
            target.as_channel_target(),
            &payload,
            &vault,
            &secret_cx,
            dns,
            &deadline,
            limits,
            &mut entropy,
        );
        (res, false)
    };
    vault.lock();

    match outcome.0 {
        Ok(dispatched) => (
            object(&[
                ("schema", string(NOTIFY_CLI_RESPONSE_SCHEMA)),
                ("action", string("dispatch")),
                ("durable_journal", outcome.1.to_string()),
                ("channel", string(opts.channel.as_str())),
                ("target_id", string(&opts.target_id)),
                ("operation_id", string(opts.operation_id.as_str())),
                (
                    "effect_state",
                    string(dispatched.operation_receipt.state.as_str()),
                ),
                ("route_digest", string(&route_digest.to_text())),
                (
                    "delivery_receipt_digest",
                    string(
                        &dispatched
                            .delivery_receipt
                            .observation
                            .observation_digest
                            .to_text(),
                    ),
                ),
                (
                    "response_status_code",
                    dispatched
                        .delivery_receipt
                        .observation
                        .protocol_status
                        .to_string(),
                ),
                (
                    "peer_spki_sha256",
                    string(
                        &dispatched
                            .delivery_receipt
                            .observation
                            .tls_peer_spki_sha256
                            .to_text(),
                    ),
                ),
            ]),
            ExitIdentity::SUCCESS,
        ),
        Err(err) => err_json(err.code, &err.to_string(), ExitIdentity::RUNTIME_FAILURE),
    }
}

fn parse_opt_digest(
    flag: &str,
    raw: Option<String>,
) -> Result<Option<ContentDigest>, (String, ExitIdentity)> {
    match raw {
        None => Ok(None),
        Some(s) => ContentDigest::parse(&s).map(Some).map_err(|_| {
            err_json(
                "ERR-CLI-MALFORMED-VALUE-001",
                &format!("{flag} must be a canonical `sha256:<hex>` digest"),
                ExitIdentity::MALFORMED_VALUE,
            )
        }),
    }
}

fn err_json(code: &str, message: &str, exit: ExitIdentity) -> (String, ExitIdentity) {
    (
        object(&[
            ("schema", string("fss.notify_error.v1")),
            ("error_id", string(code)),
            ("message", string(message)),
        ]),
        exit,
    )
}
