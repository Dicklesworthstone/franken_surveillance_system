#![forbid(unsafe_code)]
//! `fss archive <seal|verify|upload|restore|crypto-erase>` — ChaCha20-Poly1305 AEAD sealed
//! packfile encryption, S3/R2/B2 cold-tier archival & restore, and cryptographic DEK erasure
//! (`PRIV-010`), wired directly to `fss-pack` and `fss-vault`.
//!
//! Semantic plane: `"authority"`.
//!
//! # Safety & Security Invariants
//! - Never accepts raw secret/KEK/passphrase/S3-key flags on CLI argv
//!   (`ERR-SECRET-INVALID-INPUT-001`).
//! - All KEK (`AdapterFamily::StorageKek`) and S3 (`AdapterFamily::ArchiveS3`) material is fetched
//!   strictly from `fss-vault` under exact `SecretAccessCx` scopes and zeroized on exit.
//! - Cold upload (`upload`) and irreversible DEK destruction (`crypto-erase`) enforce two-step
//!   preview -> `--approve <sha256>` (`fss.pack_archive.cli_approval.v1`).
//! - `verify` on plaintext sealed packs is strictly read-only and lock-free.

use std::fs::{self, File};
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm};
use fss_pack::{
    ColdArchivePolicy, ColdPackArchiveManifest, ColdProviderKind, ColdS3Credentials,
    ColdS3Endpoint, ColdS3Limits, ColdStorageTier, ColdUploadMode, DEFAULT_ENCRYPTION_CHUNK_BYTES,
    DekId, DurabilityMode, ERR_CRYPTO_AUTH_FAILED_001, ERR_CRYPTO_KEY_ERASED_001,
    EncryptedStreamKind, KeyEncryptionKey, KeyEnvelopeCatalog, KeyEpoch,
    MAX_COLD_MANIFEST_DOWNLOAD_BYTES, PackConfig, PackError, PackId, PackStore,
    S3CompatiblePackTransport, SCHEMA_EPOCH_PACKFILE, archive_sealed_pack_with_pin,
    decrypt_and_verify_pack_bytes,
    fetch_cold_pack_manifest, restore_cold_pack_to_dir, verify_sealed_pack,
};
use fss_pack::crypto::pack_io::{decrypt_and_verify_sealed_pack_file, encrypt_pack_file_with_pin};
use fss_pack::packfile::{verify_sealed_pack_bytes, verify_sealed_pack_with_digest};
use fss_vault::{
    AdapterFamily, CAP_SECRET_READ_001, ERR_SECRET_INVALID_INPUT_001, LocalEncryptedVault,
    OsEntropy, SecretId, SecretScope,
};

use crate::agent_json::{array, object, optional_string, string};
use crate::error::ExitIdentity;
use crate::token::ArgToken;
use crate::vault_cmd::{build_secret_cx, current_timestamp_ns, read_secret_file_0600};

/// Canonical JSON response schema for `fss archive <seal|verify|upload|restore|crypto-erase>`.
pub const PACK_ARCHIVE_CLI_SCHEMA: &str = "fss.pack_archive_response.v1";
/// Canonical digest domain for two-step `fss archive upload|crypto-erase` CLI approvals.
pub const PACK_ARCHIVE_CLI_APPROVAL_DOMAIN: &str = "fss.pack_archive.cli_approval.v1";

const FORBIDDEN_SECRET_FLAGS: &[&str] = &[
    "--secret",
    "--password",
    "--passphrase",
    "--kek",
    "--s3-secret",
    "--secret-access-key",
    "--token",
];

struct ArchiveOpts {
    root: Option<PathBuf>,
    packs_dir: Option<PathBuf>,
    pack_id: Option<PackId>,
    out_file: Option<PathBuf>,
    enc_file: Option<PathBuf>,
    manifest_file: Option<PathBuf>,
    manifest_object_key: Option<String>,
    expected_manifest: Option<ContentDigest>,
    local_manifest_dir: Option<PathBuf>,
    key_catalog: Option<PathBuf>,
    vault_dir: Option<PathBuf>,
    passphrase_file: Option<PathBuf>,
    kek_secret_id: Option<SecretId>,
    kek_epoch: u32,
    kek_endpoint: Option<String>,
    site_id: String,
    s3_peer: Option<SocketAddr>,
    s3_host: Option<String>,
    s3_region: String,
    s3_bucket: Option<String>,
    s3_provider: ColdProviderKind,
    s3_tier: ColdStorageTier,
    s3_access_key_id: Option<String>,
    s3_secret_id: Option<SecretId>,
    s3_target_id: Option<String>,
    s3_endpoint_scope: Option<String>,
    endpoint_approval: Option<ContentDigest>,
    min_pack_bytes: Option<u64>,
    multipart_threshold_bytes: Option<u64>,
    multipart_part_bytes: Option<usize>,
    key_prefix: Option<String>,
    dek_id: Option<DekId>,
    reason: Option<String>,
    principal: String,
    approve: Option<ContentDigest>,
}

/// Executes an in-process `fss archive <seal|verify|upload|restore|crypto-erase>` command.
#[must_use]
pub fn execute_pack_archive_command(
    verb: &str,
    args: &[ArgToken],
    control: &crate::RequestControl<'_>,
) -> (String, ExitIdentity) {
    if control.is_cancelled() {
        return err_json(
            "ERR-CLI-READ-CANCELLED-001",
            "archive operation cancelled before dispatch",
            ExitIdentity::RUNTIME_FAILURE,
        );
    }
    for tok in args {
        let s = tok.as_str();
        let flag = s.split_once('=').map_or(s, |(k, _)| k);
        if FORBIDDEN_SECRET_FLAGS.contains(&flag) {
            return err_json(
                ERR_SECRET_INVALID_INPUT_001,
                "plaintext secrets, passphrases, and keys are forbidden on CLI argv; use fss-vault",
                ExitIdentity::MALFORMED_VALUE,
            );
        }
    }
    match verb {
        "seal" => exec_seal(args),
        "verify" => exec_verify(args),
        "upload" => exec_upload(args),
        "restore" => exec_restore(args, control),
        "crypto-erase" => exec_crypto_erase(args),
        other => err_json(
            "ERR-CLI-UNKNOWN-COMMAND-001",
            &format!(
                "unknown archive verb `{other}` (expected seal, verify, upload, restore, or crypto-erase)"
            ),
            ExitIdentity::UNKNOWN_COMMAND,
        ),
    }
}

fn parse_archive_opts(
    verb: &str,
    tokens: &[ArgToken],
) -> Result<ArchiveOpts, (String, ExitIdentity)> {
    let mut opts = ArchiveOpts {
        root: None,
        packs_dir: None,
        pack_id: None,
        out_file: None,
        enc_file: None,
        manifest_file: None,
        manifest_object_key: None,
        expected_manifest: None,
        local_manifest_dir: None,
        key_catalog: None,
        vault_dir: None,
        passphrase_file: None,
        kek_secret_id: None,
        kek_epoch: 1,
        kek_endpoint: None,
        site_id: "site:default".to_owned(),
        s3_peer: None,
        s3_host: None,
        s3_region: "us-east-1".to_owned(),
        s3_bucket: None,
        s3_provider: ColdProviderKind::LocalS3Compatible,
        s3_tier: ColdStorageTier::Standard,
        s3_access_key_id: None,
        s3_secret_id: None,
        s3_target_id: None,
        s3_endpoint_scope: None,
        endpoint_approval: None,
        min_pack_bytes: None,
        multipart_threshold_bytes: None,
        multipart_part_bytes: None,
        key_prefix: None,
        dek_id: None,
        reason: None,
        principal: "principal:local-operator".to_owned(),
        approve: None,
    };

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
                    &format!("missing value for `{name}` in `fss archive {verb}`"),
                    ExitIdentity::MISSING_VALUE,
                ));
            };
            Ok(tok.as_str().to_owned())
        };

        match flag {
            "--root" => opts.root = Some(PathBuf::from(next_val(&mut i, "--root")?)),
            "--packs-dir" => opts.packs_dir = Some(PathBuf::from(next_val(&mut i, "--packs-dir")?)),
            "--pack-id" => opts.pack_id = Some(parse_pack_id(&next_val(&mut i, "--pack-id")?)?),
            "--out" => opts.out_file = Some(PathBuf::from(next_val(&mut i, "--out")?)),
            "--enc-file" => opts.enc_file = Some(PathBuf::from(next_val(&mut i, "--enc-file")?)),
            "--manifest-file" => {
                if opts.manifest_file.is_some() {
                    return Err(err_json(
                        "ERR-CLI-MALFORMED-VALUE-001",
                        "--manifest-file must be supplied once",
                        ExitIdentity::MALFORMED_VALUE,
                    ));
                }
                opts.manifest_file = Some(PathBuf::from(next_val(&mut i, "--manifest-file")?));
            }
            "--manifest-object-key" if verb == "restore" => {
                if opts.manifest_object_key.is_some() {
                    return Err(err_json(
                        "ERR-CLI-MALFORMED-VALUE-001",
                        "--manifest-object-key must be supplied once",
                        ExitIdentity::MALFORMED_VALUE,
                    ));
                }
                let key = next_val(&mut i, "--manifest-object-key")?;
                if key.is_empty() || key.len() > 1024 || key.chars().any(char::is_control) {
                    return Err(err_json(
                        "ERR-CLI-MALFORMED-VALUE-001",
                        "--manifest-object-key must be a bounded nonempty object key",
                        ExitIdentity::MALFORMED_VALUE,
                    ));
                }
                opts.manifest_object_key = Some(key);
            }
            "--expected-manifest" if verb == "restore" => {
                if opts.expected_manifest.is_some() {
                    return Err(err_json(
                        "ERR-CLI-MALFORMED-VALUE-001",
                        "--expected-manifest must be supplied once",
                        ExitIdentity::MALFORMED_VALUE,
                    ));
                }
                let digest = parse_digest(
                    "--expected-manifest",
                    &next_val(&mut i, "--expected-manifest")?,
                )?;
                if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
                    return Err(err_json(
                        "ERR-CLI-MALFORMED-VALUE-001",
                        "--expected-manifest requires a nonzero SHA-256 manifest digest",
                        ExitIdentity::MALFORMED_VALUE,
                    ));
                }
                opts.expected_manifest = Some(digest);
            }
            "--local-manifest-dir" => {
                opts.local_manifest_dir =
                    Some(PathBuf::from(next_val(&mut i, "--local-manifest-dir")?));
            }
            "--key-catalog" => {
                opts.key_catalog = Some(PathBuf::from(next_val(&mut i, "--key-catalog")?));
            }
            "--vault-dir" => opts.vault_dir = Some(PathBuf::from(next_val(&mut i, "--vault-dir")?)),
            "--passphrase-file" => {
                opts.passphrase_file = Some(PathBuf::from(next_val(&mut i, "--passphrase-file")?));
            }
            "--kek-secret-id" => {
                let s = next_val(&mut i, "--kek-secret-id")?;
                opts.kek_secret_id = Some(SecretId::parse(&s).map_err(|e| {
                    err_json(e.error_id(), &e.to_string(), ExitIdentity::MALFORMED_VALUE)
                })?);
            }
            "--kek-epoch" => {
                let s = next_val(&mut i, "--kek-epoch")?;
                opts.kek_epoch = s.parse::<u32>().map_err(|_| {
                    err_json(
                        "ERR-CLI-MALFORMED-VALUE-001",
                        "invalid --kek-epoch (expected integer >= 1)",
                        ExitIdentity::MALFORMED_VALUE,
                    )
                })?;
            }
            "--kek-endpoint" => opts.kek_endpoint = Some(next_val(&mut i, "--kek-endpoint")?),
            "--site" | "--site-id" => opts.site_id = next_val(&mut i, "--site")?,
            "--peer" => {
                let s = next_val(&mut i, "--peer")?;
                opts.s3_peer = Some(s.parse::<SocketAddr>().map_err(|_| {
                    err_json(
                        "ERR-CLI-MALFORMED-VALUE-001",
                        "invalid --peer socket address (expected ip:port)",
                        ExitIdentity::MALFORMED_VALUE,
                    )
                })?);
            }
            "--host" => opts.s3_host = Some(next_val(&mut i, "--host")?),
            "--region" => opts.s3_region = next_val(&mut i, "--region")?,
            "--bucket" => opts.s3_bucket = Some(next_val(&mut i, "--bucket")?),
            "--provider" => {
                let s = next_val(&mut i, "--provider")?;
                opts.s3_provider = match s.as_str() {
                    "aws-s3" | "aws_s3" => ColdProviderKind::AwsS3,
                    "cloudflare-r2" | "cloudflare_r2" | "r2" => ColdProviderKind::CloudflareR2,
                    "backblaze-b2" | "backblaze_b2" | "b2" => ColdProviderKind::BackblazeB2,
                    "local" | "local-s3" | "local_s3_compatible" => {
                        ColdProviderKind::LocalS3Compatible
                    }
                    _ => {
                        return Err(err_json(
                            "ERR-CLI-MALFORMED-VALUE-001",
                            "unknown --provider (expected local-s3, aws-s3, cloudflare-r2, or backblaze-b2)",
                            ExitIdentity::MALFORMED_VALUE,
                        ));
                    }
                };
            }
            "--tier" => {
                let s = next_val(&mut i, "--tier")?;
                opts.s3_tier = match s.as_str() {
                    "standard" => ColdStorageTier::Standard,
                    "infrequent-access" | "infrequent_access" => ColdStorageTier::InfrequentAccess,
                    "cold-archive" | "cold_archive" => ColdStorageTier::ColdArchive,
                    "cloudflare-r2" | "cloudflare_r2" | "r2" => ColdStorageTier::CloudflareR2,
                    "backblaze-b2" | "backblaze_b2" | "b2" => ColdStorageTier::BackblazeB2,
                    _ => {
                        return Err(err_json(
                            "ERR-CLI-MALFORMED-VALUE-001",
                            "unknown --tier (expected standard, infrequent-access, cold-archive, cloudflare-r2, or backblaze-b2)",
                            ExitIdentity::MALFORMED_VALUE,
                        ));
                    }
                };
            }
            "--access-key-id" => opts.s3_access_key_id = Some(next_val(&mut i, "--access-key-id")?),
            "--s3-secret-id" => {
                let s = next_val(&mut i, "--s3-secret-id")?;
                opts.s3_secret_id = Some(SecretId::parse(&s).map_err(|e| {
                    err_json(e.error_id(), &e.to_string(), ExitIdentity::MALFORMED_VALUE)
                })?);
            }
            "--s3-target" => opts.s3_target_id = Some(next_val(&mut i, "--s3-target")?),
            "--s3-endpoint-scope" => {
                opts.s3_endpoint_scope = Some(next_val(&mut i, "--s3-endpoint-scope")?);
            }
            "--endpoint-approval" => {
                opts.endpoint_approval = Some(parse_digest(
                    "--endpoint-approval",
                    &next_val(&mut i, "--endpoint-approval")?,
                )?);
            }
            "--min-pack-bytes" => {
                opts.min_pack_bytes = Some(
                    next_val(&mut i, "--min-pack-bytes")?
                        .parse::<u64>()
                        .map_err(|_| {
                            err_json(
                                "ERR-CLI-MALFORMED-VALUE-001",
                                "invalid --min-pack-bytes",
                                ExitIdentity::MALFORMED_VALUE,
                            )
                        })?,
                );
            }
            "--multipart-threshold-bytes" => {
                opts.multipart_threshold_bytes = Some(
                    next_val(&mut i, "--multipart-threshold-bytes")?
                        .parse::<u64>()
                        .map_err(|_| {
                            err_json(
                                "ERR-CLI-MALFORMED-VALUE-001",
                                "invalid --multipart-threshold-bytes",
                                ExitIdentity::MALFORMED_VALUE,
                            )
                        })?,
                );
            }
            "--multipart-part-bytes" => {
                opts.multipart_part_bytes = Some(
                    next_val(&mut i, "--multipart-part-bytes")?
                        .parse::<usize>()
                        .map_err(|_| {
                            err_json(
                                "ERR-CLI-MALFORMED-VALUE-001",
                                "invalid --multipart-part-bytes",
                                ExitIdentity::MALFORMED_VALUE,
                            )
                        })?,
                );
            }
            "--key-prefix" => opts.key_prefix = Some(next_val(&mut i, "--key-prefix")?),
            "--dek-id" => {
                let s = next_val(&mut i, "--dek-id")?;
                opts.dek_id = Some(DekId::from_hex(&s).map_err(pack_err_to_json)?);
            }
            "--reason" => opts.reason = Some(next_val(&mut i, "--reason")?),
            "--principal" => opts.principal = next_val(&mut i, "--principal")?,
            "--approve" => {
                opts.approve = Some(parse_digest("--approve", &next_val(&mut i, "--approve")?)?);
            }
            "--json" => {}
            other => {
                return Err(err_json(
                    "ERR-CLI-UNKNOWN-OPTION-001",
                    &format!("unknown option `{other}` for `fss archive {verb}`"),
                    ExitIdentity::UNKNOWN_OPTION,
                ));
            }
        }
        i += 1;
    }

    if verb == "restore" {
        match (
            &opts.manifest_file,
            &opts.manifest_object_key,
            opts.expected_manifest,
        ) {
            (Some(_), None, None) | (None, Some(_), Some(_)) => {}
            (None, None, None) => {
                return Err(err_json(
                    "ERR-CLI-MISSING-VALUE-001",
                    "restore requires --manifest-file or both --manifest-object-key and --expected-manifest",
                    ExitIdentity::MISSING_VALUE,
                ));
            }
            _ => {
                return Err(err_json(
                    "ERR-CLI-MALFORMED-VALUE-001",
                    "restore requires either --manifest-file or both --manifest-object-key and --expected-manifest",
                    ExitIdentity::MALFORMED_VALUE,
                ));
            }
        }
    }
    Ok(opts)
}

fn exec_seal(args: &[ArgToken]) -> (String, ExitIdentity) {
    let opts = match parse_archive_opts("seal", args) {
        Ok(o) => o,
        Err(e) => return e,
    };

    // Mode B: encrypt a sealed `.fssp` packfile into an authenticated `.fsep` file.
    if let Some(out_path) = &opts.out_file {
        let packs_dir = match resolve_packs_dir(&opts) {
            Ok(d) => d,
            Err(e) => return e,
        };
        let Some(pack_id) = opts.pack_id else {
            return err_json(
                "ERR-CLI-MISSING-VALUE-001",
                "encrypting a sealed pack requires `--pack-id <epoch:seq>`",
                ExitIdentity::MISSING_VALUE,
            );
        };
        let (_, source_digest) = match verify_sealed_pack_with_digest(&packs_dir, pack_id) {
            Ok(verified) => verified,
            Err(err) => return pack_err_to_json(err),
        };
        let Some(catalog_path) = &opts.key_catalog else {
            return err_json(
                "ERR-CLI-MISSING-VALUE-001",
                "encrypting a sealed pack requires `--key-catalog <file.fskc>`",
                ExitIdentity::MISSING_VALUE,
            );
        };
        let (mut vault, kek, kek_scope) = match load_kek_from_vault(&opts, "op:archive:seal") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let now = current_timestamp_ns();
        let mut entropy = OsEntropy::new();
        let mut catalog = match KeyEnvelopeCatalog::open_or_create(
            catalog_path,
            kek.epoch(),
            &kek_scope,
            DurabilityMode::Fsync,
        ) {
            Ok(c) => c,
            Err(err) => {
                vault.lock();
                return pack_err_to_json(err);
            }
        };
        let (dek, env) = match catalog.create_and_wrap_dek(&kek, &mut entropy, &[pack_id], now) {
            Ok(pair) => pair,
            Err(err) => {
                vault.lock();
                return pack_err_to_json(err);
            }
        };
        let src_pack = packs_dir.join(pack_id.file_name());
        let receipt = match encrypt_pack_file_with_pin(
            &src_pack,
            out_path,
            pack_id,
            SCHEMA_EPOCH_PACKFILE,
            dek,
            env.origin_key_epoch,
            DEFAULT_ENCRYPTION_CHUNK_BYTES,
            &mut entropy,
            DurabilityMode::Fsync,
            Some(source_digest),
        ) {
            Ok(r) => r,
            Err(err) => {
                vault.lock();
                return pack_err_to_json(err);
            }
        };
        vault.lock();
        return (
            object(&[
                ("schema", string(PACK_ARCHIVE_CLI_SCHEMA)),
                ("action", string("seal_encrypt")),
                ("pack_id", string(&pack_id.to_string())),
                ("dek_id", string(&receipt.dek_id.to_hex())),
                ("origin_key_epoch", receipt.origin_key_epoch.0.to_string()),
                ("frame_count", receipt.frame_count.to_string()),
                ("plaintext_bytes", receipt.plaintext_bytes.to_string()),
                (
                    "plaintext_sha256",
                    string(&receipt.plaintext_sha256.to_text()),
                ),
                ("ciphertext_bytes", receipt.ciphertext_bytes.to_string()),
                (
                    "ciphertext_sha256",
                    string(&receipt.ciphertext_sha256.to_text()),
                ),
                ("output_file", string(&out_path.display().to_string())),
            ]),
            ExitIdentity::SUCCESS,
        );
    }

    // Mode A: seal active open packfile inside a quiescent deployment root.
    let Some(root) = &opts.root else {
        return err_json(
            "ERR-CLI-MISSING-VALUE-001",
            "`--root <deployment-dir>` is required to seal the active packfile",
            ExitIdentity::MISSING_VALUE,
        );
    };
    let store = match PackStore::open(root, PackConfig::default()) {
        Ok(s) => s,
        Err(err) => return pack_err_to_json(err),
    };
    match store.seal_active_pack() {
        Ok(Some(receipt)) => (
            object(&[
                ("schema", string(PACK_ARCHIVE_CLI_SCHEMA)),
                ("action", string("seal")),
                ("sealed", "true".to_owned()),
                ("pack_id", string(&receipt.pack_id.to_string())),
                ("pack_file", string(&receipt.pack_id.file_name())),
                ("object_count", receipt.entry_count.to_string()),
                ("footer_offset", receipt.footer_offset.to_string()),
                ("total_bytes", receipt.total_bytes.to_string()),
                (
                    "whole_pack_sha256",
                    string(&receipt.whole_pack_digest.to_text()),
                ),
            ]),
            ExitIdentity::SUCCESS,
        ),
        Ok(None) => (
            object(&[
                ("schema", string(PACK_ARCHIVE_CLI_SCHEMA)),
                ("action", string("seal")),
                ("sealed", "false".to_owned()),
                ("reason", string("no_nonempty_active_pack")),
            ]),
            ExitIdentity::SUCCESS,
        ),
        Err(err) => pack_err_to_json(err),
    }
}

fn exec_verify(args: &[ArgToken]) -> (String, ExitIdentity) {
    let opts = match parse_archive_opts("verify", args) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let Some(pack_id) = opts.pack_id else {
        return err_json(
            "ERR-CLI-MISSING-VALUE-001",
            "`--pack-id <epoch:seq>` is required",
            ExitIdentity::MISSING_VALUE,
        );
    };

    // Encrypted `.fsep` verification (and optional atomic decryption to `--out`).
    if let Some(enc_path) = &opts.enc_file {
        let Some(catalog_path) = &opts.key_catalog else {
            return err_json(
                "ERR-CLI-MISSING-VALUE-001",
                "verifying an encrypted .fsep file requires `--key-catalog <file.fskc>`",
                ExitIdentity::MISSING_VALUE,
            );
        };
        let (mut vault, kek, _) = match load_kek_from_vault(&opts, "op:archive:verify") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let catalog = match KeyEnvelopeCatalog::open_existing(catalog_path, DurabilityMode::Fsync) {
            Ok(c) => c,
            Err(err) => {
                vault.lock();
                return pack_err_to_json(err);
            }
        };
        let dec = if let Some(out_path) = &opts.out_file {
            decrypt_and_verify_sealed_pack_file(
                enc_path,
                out_path,
                pack_id,
                SCHEMA_EPOCH_PACKFILE,
                &catalog,
                &kek,
                DurabilityMode::Fsync,
            )
        } else {
            match read_bounded_regular_file(enc_path, 256 * 1024 * 1024, "encrypted pack") {
                Ok(bytes) => decrypt_and_verify_pack_bytes(
                    &bytes,
                    pack_id,
                    EncryptedStreamKind::SealedPackChunks,
                    SCHEMA_EPOCH_PACKFILE,
                    &catalog,
                    &kek,
                )
                .and_then(|(plaintext, receipt)| {
                    verify_sealed_pack_bytes(pack_id, &plaintext)?;
                    Ok(receipt)
                }),
                Err(err) => {
                    vault.lock();
                    return err;
                }
            }
        };
        vault.lock();
        return match dec {
            Ok(receipt) => (
                object(&[
                    ("schema", string(PACK_ARCHIVE_CLI_SCHEMA)),
                    ("action", string("verify_encrypted")),
                    ("verified", "true".to_owned()),
                    ("pack_id", string(&receipt.pack_id.to_string())),
                    ("dek_id", string(&receipt.dek_id.to_hex())),
                    ("frame_count", receipt.frame_count.to_string()),
                    ("plaintext_bytes", receipt.plaintext_bytes.to_string()),
                    (
                        "plaintext_sha256",
                        string(&receipt.plaintext_sha256.to_text()),
                    ),
                    (
                        "ciphertext_sha256",
                        string(&receipt.ciphertext_sha256.to_text()),
                    ),
                    (
                        "decrypted_output_file",
                        optional_string(
                            opts.out_file
                                .as_ref()
                                .map(|p| p.display().to_string())
                                .as_deref(),
                        ),
                    ),
                ]),
                ExitIdentity::SUCCESS,
            ),
            Err(err) => pack_err_to_json(err),
        };
    }

    // Plaintext sealed `.fssp` verification — strictly read-only, lock-free!
    let packs_dir = match resolve_packs_dir(&opts) {
        Ok(d) => d,
        Err(e) => return e,
    };
    match verify_sealed_pack(&packs_dir, pack_id) {
        Ok(footer) => (
            object(&[
                ("schema", string(PACK_ARCHIVE_CLI_SCHEMA)),
                ("action", string("verify")),
                ("verified", "true".to_owned()),
                ("pack_id", string(&pack_id.to_string())),
                ("object_count", footer.entries.len().to_string()),
                ("footer_offset", footer.footer_offset.to_string()),
                (
                    "whole_pack_sha256",
                    string(
                        &ContentDigest::new(DigestAlgorithm::Sha256, footer.whole_pack_sha256)
                            .to_text(),
                    ),
                ),
            ]),
            ExitIdentity::SUCCESS,
        ),
        Err(err) => pack_err_to_json(err),
    }
}

fn exec_upload(args: &[ArgToken]) -> (String, ExitIdentity) {
    let opts = match parse_archive_opts("upload", args) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let packs_dir = match resolve_packs_dir(&opts) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let Some(pack_id) = opts.pack_id else {
        return err_json(
            "ERR-CLI-MISSING-VALUE-001",
            "`--pack-id <epoch:seq>` is required",
            ExitIdentity::MISSING_VALUE,
        );
    };
    let footer = match verify_sealed_pack(&packs_dir, pack_id) {
        Ok(f) => f,
        Err(err) => return pack_err_to_json(err),
    };
    let whole_sha = ContentDigest::new(DigestAlgorithm::Sha256, footer.whole_pack_sha256);
    let endpoint = match build_s3_endpoint(&opts) {
        Ok(e) => e,
        Err(e) => return e,
    };
    let policy = match build_archive_policy(&opts) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let expected_approval =
        compute_upload_approval(pack_id, whole_sha, endpoint.endpoint_digest(), &policy);

    let Some(supplied) = opts.approve else {
        let approve_cmd = format!(
            "fss archive upload --packs-dir {} --pack-id {} --peer {} --host {} --bucket {} --region {} --approve {} --key-catalog <file.fskc> --vault-dir <vault-dir> --passphrase-file <0600-file> --kek-secret-id <id> --s3-secret-id <id> --access-key-id <id> --json",
            packs_dir.display(),
            pack_id,
            endpoint.peer(),
            endpoint.host(),
            endpoint.bucket(),
            endpoint.region(),
            expected_approval.to_text(),
        );
        return (
            object(&[
                ("schema", string(PACK_ARCHIVE_CLI_SCHEMA)),
                ("action", string("upload_preview")),
                ("network_io_executed", "false".to_owned()),
                ("pack_id", string(&pack_id.to_string())),
                ("whole_pack_sha256", string(&whole_sha.to_text())),
                (
                    "endpoint_digest",
                    string(&endpoint.endpoint_digest().to_text()),
                ),
                ("storage_tier", string(policy.storage_tier.as_str())),
                ("approval_digest", string(&expected_approval.to_text())),
                ("approve_command", string(&approve_cmd)),
            ]),
            ExitIdentity::SUCCESS,
        );
    };
    if supplied != expected_approval {
        return err_json(
            "ERR-ARCHIVE-APPROVAL-MISMATCH-001",
            &format!(
                "`--approve` digest does not match expected upload approval {}",
                expected_approval.to_text()
            ),
            ExitIdentity::AGENT_REFUSED,
        );
    }

    let Some(catalog_path) = &opts.key_catalog else {
        return err_json(
            "ERR-CLI-MISSING-VALUE-001",
            "`--key-catalog <file.fskc>` is required for cold archive upload",
            ExitIdentity::MISSING_VALUE,
        );
    };
    let (mut vault, kek, kek_scope, s3_creds) =
        match load_kek_and_s3_from_vault(&opts, &endpoint, "op:archive:upload") {
            Ok(v) => v,
            Err(e) => return e,
        };
    let mut catalog = match KeyEnvelopeCatalog::open_or_create(
        catalog_path,
        kek.epoch(),
        &kek_scope,
        DurabilityMode::Fsync,
    ) {
        Ok(c) => c,
        Err(err) => {
            vault.lock();
            return pack_err_to_json(err);
        }
    };
    let mut transport =
        match S3CompatiblePackTransport::new(endpoint, s3_creds, ColdS3Limits::default()) {
            Ok(t) => t,
            Err(err) => {
                vault.lock();
                return pack_err_to_json(err);
            }
        };
    let mut entropy = OsEntropy::new();
    let now = current_timestamp_ns();
    let res = archive_sealed_pack_with_pin(
        &packs_dir,
        pack_id,
        Some(whole_sha),
        &policy,
        &mut catalog,
        &kek,
        &mut transport,
        &mut entropy,
        opts.local_manifest_dir.as_deref(),
        DurabilityMode::Fsync,
        now,
    );
    vault.lock();
    match res {
        Ok(receipt) => {
            let mode_str = match receipt.upload_mode {
                ColdUploadMode::SinglePut => "single_put".to_owned(),
                ColdUploadMode::Multipart { part_count } => format!("multipart:{part_count}"),
            };
            (
                object(&[
                    ("schema", string(PACK_ARCHIVE_CLI_SCHEMA)),
                    ("action", string("upload")),
                    ("pack_id", string(&receipt.manifest.pack_id.to_string())),
                    ("dek_id", string(&receipt.manifest.dek_id.to_hex())),
                    ("upload_mode", string(&mode_str)),
                    ("pack_object_key", string(&receipt.manifest.object_key)),
                    ("manifest_object_key", string(&receipt.manifest_object_key)),
                    ("manifest_etag", string(&receipt.manifest_etag)),
                    (
                        "manifest_digest",
                        string(&receipt.manifest.manifest_digest.to_text()),
                    ),
                    (
                        "plaintext_pack_sha256",
                        string(&receipt.manifest.plaintext_pack_sha256.to_text()),
                    ),
                    (
                        "ciphertext_sha256",
                        string(&receipt.manifest.ciphertext_sha256.to_text()),
                    ),
                    (
                        "ciphertext_bytes",
                        receipt.manifest.ciphertext_bytes.to_string(),
                    ),
                    (
                        "encryption_frame_count",
                        receipt.encryption_frame_count.to_string(),
                    ),
                ]),
                ExitIdentity::SUCCESS,
            )
        }
        Err(err) => pack_err_to_json(err),
    }
}

fn exec_restore(args: &[ArgToken], control: &crate::RequestControl<'_>) -> (String, ExitIdentity) {
    let opts = match parse_archive_opts("restore", args) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let packs_dir = match resolve_packs_dir(&opts) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let Some(catalog_path) = &opts.key_catalog else {
        return err_json(
            "ERR-CLI-MISSING-VALUE-001",
            "`--key-catalog <file.fskc>` is required",
            ExitIdentity::MISSING_VALUE,
        );
    };
    let local_manifest = match &opts.manifest_file {
        Some(path) => {
            let bytes = match read_bounded_regular_file(path, 1024 * 1024, "cold archive manifest")
            {
                Ok(bytes) => bytes,
                Err(err) => return err,
            };
            match ColdPackArchiveManifest::from_canonical_bytes(&bytes) {
                Ok(manifest) => Some(manifest),
                Err(err) => return pack_err_to_json(err),
            }
        }
        None => None,
    };
    let endpoint = match build_s3_endpoint(&opts) {
        Ok(e) => e,
        Err(e) => return e,
    };
    let (mut vault, kek, _kek_scope, s3_creds) =
        match load_kek_and_s3_from_vault(&opts, &endpoint, "op:archive:restore") {
            Ok(v) => v,
            Err(e) => return e,
        };
    let catalog = match KeyEnvelopeCatalog::open_existing(catalog_path, DurabilityMode::Fsync) {
        Ok(c) => c,
        Err(err) => {
            vault.lock();
            return pack_err_to_json(err);
        }
    };
    let mut transport =
        match S3CompatiblePackTransport::new(endpoint, s3_creds, ColdS3Limits::default()) {
            Ok(t) => t,
            Err(err) => {
                vault.lock();
                return pack_err_to_json(err);
            }
        };
    if control.is_cancelled() {
        vault.lock();
        return err_json(
            "ERR-CLI-READ-CANCELLED-001",
            "archive restore cancelled before download",
            ExitIdentity::RUNTIME_FAILURE,
        );
    }
    let now = current_timestamp_ns();
    let manifest = match local_manifest {
        Some(manifest) => manifest,
        None => {
            // The parser admits this branch only with one remote key and an independent pin.
            let (Some(key), Some(pin)) = (&opts.manifest_object_key, opts.expected_manifest) else {
                vault.lock();
                return err_json(
                    "ERR-CLI-MISSING-VALUE-001",
                    "remote manifest recovery requires its object key and independent digest",
                    ExitIdentity::MISSING_VALUE,
                );
            };
            match fetch_cold_pack_manifest(&mut transport, key, pin, now) {
                Ok(manifest) => manifest,
                Err(err) => {
                    vault.lock();
                    return pack_err_to_json(err);
                }
            }
        }
    };
    if control.is_cancelled() {
        vault.lock();
        return err_json(
            "ERR-CLI-READ-CANCELLED-001",
            "archive restore cancelled before ciphertext download",
            ExitIdentity::RUNTIME_FAILURE,
        );
    }
    let res = restore_cold_pack_to_dir(
        &mut transport,
        &manifest,
        &catalog,
        &kek,
        &packs_dir,
        DurabilityMode::Fsync,
        256 * 1024 * 1024,
        now,
    );
    vault.lock();
    match res {
        Ok(digests) => {
            let restored_path = packs_dir.join(manifest.pack_id.file_name());
            (
                object(&[
                    ("schema", string(PACK_ARCHIVE_CLI_SCHEMA)),
                    ("action", string("restore")),
                    (
                        "manifest_source",
                        string(if opts.manifest_object_key.is_some() {
                            "remote_object"
                        } else {
                            "local_file"
                        }),
                    ),
                    (
                        "manifest_object_key",
                        optional_string(opts.manifest_object_key.as_deref()),
                    ),
                    (
                        "manifest_pin_verified",
                        opts.expected_manifest.is_some().to_string(),
                    ),
                    (
                        "manifest_download_limit_bytes",
                        if opts.manifest_object_key.is_some() {
                            MAX_COLD_MANIFEST_DOWNLOAD_BYTES
                        } else {
                            0
                        }
                        .to_string(),
                    ),
                    ("pack_id", string(&manifest.pack_id.to_string())),
                    (
                        "manifest_digest",
                        string(&manifest.manifest_digest.to_text()),
                    ),
                    ("restored_object_count", digests.len().to_string()),
                    (
                        "restored_pack_path",
                        string(&restored_path.display().to_string()),
                    ),
                    (
                        "plaintext_pack_sha256",
                        string(&manifest.plaintext_pack_sha256.to_text()),
                    ),
                ]),
                ExitIdentity::SUCCESS,
            )
        }
        Err(err) => pack_err_to_json(err),
    }
}

fn exec_crypto_erase(args: &[ArgToken]) -> (String, ExitIdentity) {
    let opts = match parse_archive_opts("crypto-erase", args) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let Some(catalog_path) = &opts.key_catalog else {
        return err_json(
            "ERR-CLI-MISSING-VALUE-001",
            "`--key-catalog <file.fskc>` is required",
            ExitIdentity::MISSING_VALUE,
        );
    };
    let Some(dek_id) = opts.dek_id else {
        return err_json(
            "ERR-CLI-MISSING-VALUE-001",
            "`--dek-id <32-hex>` is required",
            ExitIdentity::MISSING_VALUE,
        );
    };
    let reason = opts.reason.as_deref().unwrap_or("operator_crypto_erase");
    let mut catalog = match KeyEnvelopeCatalog::open_existing(catalog_path, DurabilityMode::Fsync) {
        Ok(c) => c,
        Err(err) => return pack_err_to_json(err),
    };
    let Some(env) = catalog.get_envelope(dek_id) else {
        if let Some(tomb) = catalog.get_tombstone(dek_id) {
            return err_json(
                ERR_CRYPTO_KEY_ERASED_001,
                &format!("DEK {} is already erased: {}", dek_id.to_hex(), tomb.reason),
                ExitIdentity::AGENT_REFUSED,
            );
        }
        return err_json(
            ERR_CRYPTO_AUTH_FAILED_001,
            &format!("DEK {} not found in key catalog", dek_id.to_hex()),
            ExitIdentity::MALFORMED_VALUE,
        );
    };
    let expected_approval = compute_erasure_approval(
        dek_id,
        env.envelope_digest(),
        catalog.scope_digest(),
        reason,
        &opts.principal,
    );
    let affected: Vec<String> = env
        .bound_pack_ids
        .iter()
        .map(|p| string(&p.to_string()))
        .collect();

    let Some(supplied) = opts.approve else {
        let approve_cmd = format!(
            "fss archive crypto-erase --key-catalog {} --dek-id {} --reason {} --approve {} --vault-dir <vault-dir> --passphrase-file <0600-file> --kek-secret-id <id> --site {} --json",
            catalog_path.display(),
            dek_id.to_hex(),
            reason,
            expected_approval.to_text(),
            opts.site_id,
        );
        return (
            object(&[
                ("schema", string(PACK_ARCHIVE_CLI_SCHEMA)),
                ("action", string("crypto_erase_preview")),
                ("irreversible", "true".to_owned()),
                ("dek_id", string(&dek_id.to_hex())),
                ("affected_pack_ids", array(&affected)),
                ("approval_digest", string(&expected_approval.to_text())),
                ("approve_command", string(&approve_cmd)),
            ]),
            ExitIdentity::SUCCESS,
        );
    };
    if supplied != expected_approval {
        return err_json(
            "ERR-ARCHIVE-APPROVAL-MISMATCH-001",
            &format!(
                "`--approve` digest does not match expected crypto-erase approval {}",
                expected_approval.to_text()
            ),
            ExitIdentity::AGENT_REFUSED,
        );
    }

    let (mut vault, kek, _) = match load_kek_from_vault(&opts, "op:archive:crypto-erase") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let now = current_timestamp_ns();
    let res = catalog.crypto_erase_dek_signed(dek_id, &kek, reason, &opts.principal, now);
    vault.lock();
    match res {
        Ok(receipt) => {
            let erased_packs: Vec<String> = receipt
                .affected_pack_ids
                .iter()
                .map(|p| string(&p.to_string()))
                .collect();
            (
                object(&[
                    ("schema", string(PACK_ARCHIVE_CLI_SCHEMA)),
                    ("action", string("crypto_erase")),
                    (
                        "cryptographic_erasure",
                        receipt.cryptographic_erasure.to_string(),
                    ),
                    ("dek_id", string(&receipt.dek_id.to_hex())),
                    ("signed_with_kek", receipt.signed_with_kek.to_string()),
                    ("affected_pack_ids", array(&erased_packs)),
                    ("receipt_digest", string(&receipt.receipt_digest.to_text())),
                ]),
                ExitIdentity::SUCCESS,
            )
        }
        Err(err) => pack_err_to_json(err),
    }
}

fn resolve_packs_dir(opts: &ArchiveOpts) -> Result<PathBuf, (String, ExitIdentity)> {
    if let Some(dir) = &opts.packs_dir {
        Ok(dir.clone())
    } else if let Some(root) = &opts.root {
        Ok(root.join("objects").join("packs"))
    } else {
        Err(err_json(
            "ERR-CLI-MISSING-VALUE-001",
            "supply `--root <deployment-dir>` or `--packs-dir <packs-dir>`",
            ExitIdentity::MISSING_VALUE,
        ))
    }
}

fn build_s3_endpoint(opts: &ArchiveOpts) -> Result<ColdS3Endpoint, (String, ExitIdentity)> {
    let peer = opts.s3_peer.ok_or_else(|| {
        err_json(
            "ERR-CLI-MISSING-VALUE-001",
            "`--peer <ip:port>` is required for S3-compatible cold transport",
            ExitIdentity::MISSING_VALUE,
        )
    })?;
    let host = opts.s3_host.as_deref().ok_or_else(|| {
        err_json(
            "ERR-CLI-MISSING-VALUE-001",
            "`--host <hostname>` is required for S3-compatible cold transport",
            ExitIdentity::MISSING_VALUE,
        )
    })?;
    let bucket = opts.s3_bucket.as_deref().ok_or_else(|| {
        err_json(
            "ERR-CLI-MISSING-VALUE-001",
            "`--bucket <bucket-name>` is required",
            ExitIdentity::MISSING_VALUE,
        )
    })?;
    let approval = opts.endpoint_approval.unwrap_or_else(|| {
        let mut enc = CanonicalEncoder::new();
        enc.text("fss.canonical.v1");
        enc.text(PACK_ARCHIVE_CLI_APPROVAL_DOMAIN);
        enc.text("endpoint");
        enc.text(&peer.to_string());
        enc.text(host);
        enc.text(&opts.s3_region);
        enc.text(bucket);
        ContentDigest::sha256(&enc.finish())
    });
    ColdS3Endpoint::new_local_approved(
        opts.s3_provider,
        peer,
        host,
        &opts.s3_region,
        bucket,
        approval,
    )
    .map_err(pack_err_to_json)
}

fn build_archive_policy(opts: &ArchiveOpts) -> Result<ColdArchivePolicy, (String, ExitIdentity)> {
    let mut policy = ColdArchivePolicy::production_default(opts.s3_tier);
    if let Some(min_b) = opts.min_pack_bytes {
        policy.min_pack_bytes = min_b;
    }
    if let Some(mp_thresh) = opts.multipart_threshold_bytes {
        policy.multipart_threshold_bytes = mp_thresh;
    }
    if let Some(mp_part) = opts.multipart_part_bytes {
        policy.multipart_part_bytes = mp_part;
    }
    if let Some(prefix) = &opts.key_prefix {
        policy.key_prefix = prefix.clone();
    }
    policy.validate().map_err(pack_err_to_json)?;
    Ok(policy)
}

fn load_kek_from_vault(
    opts: &ArchiveOpts,
    op_id: &str,
) -> Result<(LocalEncryptedVault, KeyEncryptionKey, SecretScope), (String, ExitIdentity)> {
    let vault_dir = opts.vault_dir.as_ref().ok_or_else(|| {
        err_json(
            "ERR-CLI-MISSING-VALUE-001",
            "`--vault-dir <dir>` is required",
            ExitIdentity::MISSING_VALUE,
        )
    })?;
    let pass_file = opts.passphrase_file.as_ref().ok_or_else(|| {
        err_json(
            "ERR-CLI-MISSING-VALUE-001",
            "`--passphrase-file <0600-file>` is required",
            ExitIdentity::MISSING_VALUE,
        )
    })?;
    let kek_secret_id = opts.kek_secret_id.as_ref().ok_or_else(|| {
        err_json(
            "ERR-CLI-MISSING-VALUE-001",
            "`--kek-secret-id <vault-secret-id>` is required",
            ExitIdentity::MISSING_VALUE,
        )
    })?;
    let kek_endpoint = opts
        .kek_endpoint
        .clone()
        .unwrap_or_else(|| format!("storage-kek://{}/epoch-{}", opts.site_id, opts.kek_epoch));
    let kek_scope = SecretScope::new(AdapterFamily::StorageKek, &opts.site_id, &kek_endpoint)
        .map_err(|e| err_json(e.error_id(), &e.to_string(), ExitIdentity::MALFORMED_VALUE))?;
    let passphrase = read_secret_file_0600(pass_file, false)?;
    let mut vault = LocalEncryptedVault::open(vault_dir);
    if let Err(err) = vault.unlock(&passphrase) {
        return Err(err_json(
            err.error_id(),
            &err.to_string(),
            ExitIdentity::RUNTIME_FAILURE,
        ));
    }
    let cx = match build_secret_cx(
        &opts.principal,
        op_id,
        &[CAP_SECRET_READ_001],
        kek_scope.clone(),
    ) {
        Ok(c) => c,
        Err(e) => {
            vault.lock();
            return Err(e);
        }
    };
    let epoch = KeyEpoch::new(opts.kek_epoch).map_err(|e| {
        vault.lock();
        pack_err_to_json(e)
    })?;
    let kek = match KeyEncryptionKey::from_vault(&vault, &cx, kek_secret_id, epoch) {
        Ok(k) => k,
        Err(err) => {
            vault.lock();
            return Err(pack_err_to_json(err));
        }
    };
    Ok((vault, kek, kek_scope))
}

fn load_kek_and_s3_from_vault(
    opts: &ArchiveOpts,
    endpoint: &ColdS3Endpoint,
    op_id: &str,
) -> Result<
    (
        LocalEncryptedVault,
        KeyEncryptionKey,
        SecretScope,
        ColdS3Credentials,
    ),
    (String, ExitIdentity),
> {
    let (mut vault, kek, kek_scope) = load_kek_from_vault(opts, op_id)?;
    let Some(access_key_id) = opts.s3_access_key_id.as_deref() else {
        vault.lock();
        return Err(err_json(
            "ERR-CLI-MISSING-VALUE-001",
            "`--access-key-id <id>` is required",
            ExitIdentity::MISSING_VALUE,
        ));
    };
    let Some(s3_secret_id) = opts.s3_secret_id.as_ref() else {
        vault.lock();
        return Err(err_json(
            "ERR-CLI-MISSING-VALUE-001",
            "`--s3-secret-id <vault-secret-id>` is required",
            ExitIdentity::MISSING_VALUE,
        ));
    };
    let s3_target = opts
        .s3_target_id
        .as_deref()
        .unwrap_or_else(|| endpoint.bucket());
    let s3_endpoint_scope = opts
        .s3_endpoint_scope
        .clone()
        .unwrap_or_else(|| format!("s3://{}/{}", endpoint.host(), endpoint.bucket()));
    let s3_scope = match SecretScope::new(AdapterFamily::ArchiveS3, s3_target, &s3_endpoint_scope) {
        Ok(s) => s,
        Err(e) => {
            vault.lock();
            return Err(err_json(
                e.error_id(),
                &e.to_string(),
                ExitIdentity::MALFORMED_VALUE,
            ));
        }
    };
    let s3_cx = match build_secret_cx(
        &opts.principal,
        &format!("{op_id}:s3"),
        &[CAP_SECRET_READ_001],
        s3_scope,
    ) {
        Ok(c) => c,
        Err(e) => {
            vault.lock();
            return Err(e);
        }
    };
    let creds =
        match ColdS3Credentials::from_vault(&vault, &s3_cx, access_key_id, s3_secret_id, None) {
            Ok(c) => c,
            Err(err) => {
                vault.lock();
                return Err(pack_err_to_json(err));
            }
        };
    Ok((vault, kek, kek_scope, creds))
}

fn compute_upload_approval(
    pack_id: PackId,
    whole_pack_sha256: ContentDigest,
    endpoint_digest: ContentDigest,
    policy: &ColdArchivePolicy,
) -> ContentDigest {
    let mut enc = CanonicalEncoder::new();
    enc.text("fss.canonical.v1");
    enc.text(PACK_ARCHIVE_CLI_APPROVAL_DOMAIN);
    enc.text("upload");
    enc.u32(pack_id.epoch);
    enc.u64(pack_id.seq);
    enc.digest(whole_pack_sha256);
    enc.digest(endpoint_digest);
    enc.text(policy.storage_tier.as_str());
    enc.text(&policy.key_prefix);
    ContentDigest::sha256(&enc.finish())
}

fn compute_erasure_approval(
    dek_id: DekId,
    envelope_digest: ContentDigest,
    catalog_scope_digest: ContentDigest,
    reason: &str,
    principal: &str,
) -> ContentDigest {
    let mut enc = CanonicalEncoder::new();
    enc.text("fss.canonical.v1");
    enc.text(PACK_ARCHIVE_CLI_APPROVAL_DOMAIN);
    enc.text("crypto_erase");
    enc.text(&dek_id.to_hex());
    enc.digest(envelope_digest);
    enc.digest(catalog_scope_digest);
    enc.text(reason);
    enc.text(principal);
    ContentDigest::sha256(&enc.finish())
}

fn parse_pack_id(raw: &str) -> Result<PackId, (String, ExitIdentity)> {
    if let Some(rest) = raw.strip_prefix("pack-") {
        let trimmed = rest.strip_suffix(".fssp").unwrap_or(rest);
        if let Some((ep_hex, seq_hex)) = trimmed.split_once('-')
            && let (Ok(epoch), Ok(seq)) = (
                u32::from_str_radix(ep_hex, 16),
                u64::from_str_radix(seq_hex, 16),
            )
        {
            return Ok(PackId::new(epoch, seq));
        }
        return Err(err_json(
            "ERR-CLI-MALFORMED-VALUE-001",
            "--pack-id must be `pack-<epoch_hex>-<seq_hex>` or `<epoch>:<seq>` (e.g. `1:1`)",
            ExitIdentity::MALFORMED_VALUE,
        ));
    }
    let Some((ep_str, seq_str)) = raw.split_once(':').or_else(|| raw.split_once('-')) else {
        return Err(err_json(
            "ERR-CLI-MALFORMED-VALUE-001",
            "--pack-id must be `pack-<epoch_hex>-<seq_hex>` or `<epoch>:<seq>` (e.g. `1:1`)",
            ExitIdentity::MALFORMED_VALUE,
        ));
    };
    let epoch = ep_str.parse::<u32>().map_err(|_| {
        err_json(
            "ERR-CLI-MALFORMED-VALUE-001",
            "invalid epoch in --pack-id",
            ExitIdentity::MALFORMED_VALUE,
        )
    })?;
    let seq = seq_str.parse::<u64>().map_err(|_| {
        err_json(
            "ERR-CLI-MALFORMED-VALUE-001",
            "invalid seq in --pack-id",
            ExitIdentity::MALFORMED_VALUE,
        )
    })?;
    Ok(PackId::new(epoch, seq))
}

fn parse_digest(flag: &str, raw: &str) -> Result<ContentDigest, (String, ExitIdentity)> {
    ContentDigest::parse(raw).map_err(|_| {
        err_json(
            "ERR-CLI-MALFORMED-VALUE-001",
            &format!("{flag} must be a canonical `sha256:<hex>` digest"),
            ExitIdentity::MALFORMED_VALUE,
        )
    })
}

fn pack_err_to_json(err: PackError) -> (String, ExitIdentity) {
    let code = match &err {
        PackError::CryptoKeyErased { .. } => ERR_CRYPTO_KEY_ERASED_001,
        PackError::CryptoAuthFailed { .. }
        | PackError::CryptoAuthority { .. }
        | PackError::CryptoKeyNotFound { .. } => ERR_CRYPTO_AUTH_FAILED_001,
        PackError::StoreLocked => "ERR-PACK-STORE-LOCKED-001",
        PackError::InvalidConfig { .. } => "ERR-CLI-MALFORMED-VALUE-001",
        _ => "ERR-PACK-ARCHIVE-001",
    };
    err_json(code, &err.to_string(), ExitIdentity::RUNTIME_FAILURE)
}

fn read_bounded_regular_file(
    path: &Path,
    max_bytes: u64,
    label: &str,
) -> Result<Vec<u8>, (String, ExitIdentity)> {
    let meta = fs::symlink_metadata(path).map_err(|err| {
        err_json(
            "ERR-CLI-RUNTIME-FAILURE-001",
            &format!("failed stating {label}: {err}"),
            ExitIdentity::RUNTIME_FAILURE,
        )
    })?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err(err_json(
            "ERR-CLI-MALFORMED-VALUE-001",
            &format!("{label} must be a regular non-symlink file"),
            ExitIdentity::MALFORMED_VALUE,
        ));
    }
    if meta.len() > max_bytes {
        return Err(err_json(
            "ERR-CLI-MALFORMED-VALUE-001",
            &format!("{label} exceeds maximum read bound of {max_bytes} bytes"),
            ExitIdentity::MALFORMED_VALUE,
        ));
    }
    let file = File::open(path).map_err(|err| {
        err_json(
            "ERR-CLI-RUNTIME-FAILURE-001",
            &format!("failed opening {label}: {err}"),
            ExitIdentity::RUNTIME_FAILURE,
        )
    })?;
    let mut buf = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|err| {
            err_json(
                "ERR-CLI-RUNTIME-FAILURE-001",
                &format!("failed reading {label}: {err}"),
                ExitIdentity::RUNTIME_FAILURE,
            )
        })?;
    if u64::try_from(buf.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(err_json(
            "ERR-CLI-MALFORMED-VALUE-001",
            &format!("{label} grew past maximum read bound of {max_bytes} bytes"),
            ExitIdentity::MALFORMED_VALUE,
        ));
    }
    Ok(buf)
}

fn err_json(code: &str, message: &str, exit: ExitIdentity) -> (String, ExitIdentity) {
    (
        object(&[
            ("schema", string("fss.pack_archive_error.v1")),
            ("error_id", string(code)),
            ("message", string(message)),
        ]),
        exit,
    )
}
