#![forbid(unsafe_code)]
//! Core local-vault security contract, scope isolation, tamper, permission, and canary leak tests.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, OperationId, RegionId, RegionKind,
    RootAuthoritySpec, TimestampNs, validate_error_id,
};
use fss_runtime::authority::AuthorityCx;
use fss_vault::{
    ALL_VAULT_ERROR_IDS, AdapterFamily, CAP_SECRET_READ_001, CAP_SECRET_ROTATE_001,
    CAP_SECRET_WRITE_001, CanaryLeakScanner, ERR_SECRET_AUTH_FAILED_001, ERR_SECRET_CANCELLED_001,
    ERR_SECRET_PERMISSION_DENIED_001, ERR_SECRET_REVOKED_001, ERR_SECRET_SCOPE_MISMATCH_001,
    ERR_SECRET_TAMPERED_001, ERR_SECRET_UNAUTHORIZED_001, ERR_SECRET_VAULT_LOCKED_001, KdfParams,
    LabEntropy, LeakEncoding, LocalEncryptedVault, REDACTED_SECRET_DISPLAY, SecretAccessCx,
    SecretBackendKind, SecretBytes, SecretError, SecretId, SecretScope, SecretStore,
    VAULT_HEADER_LEN, open_secret_entry, seal_secret_entry,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

static TEST_DIR_SEQ: AtomicU64 = AtomicU64::new(1);

struct TempVaultDir {
    path: PathBuf,
}

impl TempVaultDir {
    fn new(prefix: &str) -> Result<Self, std::io::Error> {
        let seq = TEST_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("fss-vault-{prefix}-{}-{seq}", std::process::id()));
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempVaultDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn make_authority(
    caps: &[&str],
    deadline: Option<TimestampNs>,
) -> Result<ContextAuthority, Box<dyn std::error::Error>> {
    let spec = RootAuthoritySpec {
        trace_id: "trace:vault:test".to_string(),
        operation_id: OperationId::parse("op:vault:test")?,
        principal: "principal:operator:alice".to_string(),
        capabilities: caps.iter().map(|c| (*c).to_string()).collect(),
        deadline,
        priority: 1,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:owner".to_string(),
        retention_scope: "retention:standard".to_string(),
        anchor_universe: ContentDigest::sha256(b"fss-vault-test-anchor"),
        generation: 1,
    };
    Ok(ContextAuthority::new_root(spec)?)
}

fn make_cx(
    caps: &[&str],
    scope: SecretScope,
    now_ns: i128,
) -> Result<SecretAccessCx, Box<dyn std::error::Error>> {
    let authority = make_authority(caps, None)?;
    Ok(SecretAccessCx::new(authority, scope, TimestampNs(now_ns))?)
}

fn full_caps() -> &'static [&'static str] {
    &[
        CAP_SECRET_READ_001,
        CAP_SECRET_WRITE_001,
        CAP_SECRET_ROTATE_001,
    ]
}

#[test]
fn lifecycle_persistence_rotation_and_revocation() -> TestResult {
    let dir = TempVaultDir::new("lifecycle")?;
    let passphrase = SecretBytes::from_slice(b"operator-vault-passphrase-2026!")?;
    let scope = SecretScope::new(
        AdapterFamily::Rtsp,
        "sensor:cam-front-01",
        "rtsp://192.168.10.21:554/stream1",
    )?;
    let secret_id = SecretId::parse("secret:rtsp:cam-front-01")?;
    let val_v1 = SecretBytes::from_slice(b"rtsp-pass-gen1-alpha-9981")?;
    let val_v2 = SecretBytes::from_slice(b"rtsp-pass-gen2-beta-7742")?;

    let mut vault = LocalEncryptedVault::open_with_entropy(
        dir.path(),
        KdfParams::for_testing(64)?,
        LabEntropy::from_seed([0x11; 32]),
    );
    vault.initialize(&passphrase)?;
    assert!(vault.is_unlocked());

    let cx1 = make_cx(full_caps(), scope.clone(), 1_000)?;
    let h1 = vault.store(&cx1, &secret_id, val_v1.clone())?;
    assert_eq!(h1.generation, 1);
    assert!(!h1.revoked);
    assert_eq!(h1.backend_kind, SecretBackendKind::LocalEncryptedVault);

    let fetched1 = vault.fetch(&cx1, &secret_id)?;
    assert_eq!(fetched1.handle(), &h1);
    assert_eq!(fetched1.secret(), &val_v1);

    let cx2 = make_cx(full_caps(), scope.clone(), 2_000)?;
    let h2 = vault.rotate(&cx2, &secret_id, val_v2.clone())?;
    assert_eq!(h2.generation, 2);
    assert_eq!(h2.created_at_ns, TimestampNs(1_000));
    assert_eq!(h2.rotated_at_ns, TimestampNs(2_000));

    // Old generation fetch fails closed.
    assert!(vault.fetch_generation(&cx2, &secret_id, 1).is_err());
    let fetched2 = vault.fetch_generation(&cx2, &secret_id, 2)?;
    assert_eq!(fetched2.secret(), &val_v2);

    // Reopen from disk and verify persistence.
    vault.lock();
    assert!(!vault.is_unlocked());
    let mut reopened = LocalEncryptedVault::open_with_entropy(
        dir.path(),
        KdfParams::for_testing(64)?,
        LabEntropy::from_seed([0x22; 32]),
    );
    reopened.unlock(&passphrase)?;
    let handles = reopened.list_handles(&cx2)?;
    assert_eq!(handles.len(), 1);
    assert_eq!(handles[0], h2);
    assert_eq!(reopened.fetch(&cx2, &secret_id)?.secret(), &val_v2);

    // Revoke tombstones the handle and permanently refuses fetch/rotate/re-store.
    let cx3 = make_cx(full_caps(), scope, 3_000)?;
    let revoked_handle = reopened.revoke(&cx3, &secret_id)?;
    assert!(revoked_handle.revoked);
    assert_eq!(revoked_handle.generation, 2);

    assert_eq!(
        reopened.fetch(&cx3, &secret_id).err().map(|e| e.error_id()),
        Some(ERR_SECRET_REVOKED_001)
    );
    assert_eq!(
        reopened
            .rotate(&cx3, &secret_id, val_v1.clone())
            .err()
            .map(|e| e.error_id()),
        Some(ERR_SECRET_REVOKED_001)
    );
    assert_eq!(
        reopened
            .store(&cx3, &secret_id, val_v1)
            .err()
            .map(|e| e.error_id()),
        Some(ERR_SECRET_REVOKED_001)
    );
    Ok(())
}

#[test]
fn cross_adapter_scope_isolation_and_per_record_aad_enforcement() -> TestResult {
    let dir = TempVaultDir::new("scope-iso")?;
    let passphrase = SecretBytes::from_slice(b"scope-passphrase-2026!")?;
    let rtsp_scope = SecretScope::new(
        AdapterFamily::Rtsp,
        "sensor:cam-01",
        "rtsp://10.0.0.10:554/main",
    )?;
    let unifi_scope = SecretScope::new(
        AdapterFamily::UniFiProtect,
        "sensor:cam-01",
        "rtsp://10.0.0.10:554/main",
    )?;
    let other_sensor_scope = SecretScope::new(
        AdapterFamily::Rtsp,
        "sensor:cam-02",
        "rtsp://10.0.0.10:554/main",
    )?;
    let other_endpoint_scope = SecretScope::new(
        AdapterFamily::Rtsp,
        "sensor:cam-01",
        "rtsp://10.0.0.11:554/main",
    )?;

    let mut vault = LocalEncryptedVault::open_with_entropy(
        dir.path(),
        KdfParams::for_testing(32)?,
        LabEntropy::from_seed([0x33; 32]),
    );
    vault.initialize(&passphrase)?;
    let id = SecretId::parse("secret:rtsp:cam-01")?;
    let cx_rtsp = make_cx(full_caps(), rtsp_scope.clone(), 100)?;
    vault.store(&cx_rtsp, &id, SecretBytes::from_slice(b"rtsp-only-secret")?)?;

    for mismatched_scope in [
        unifi_scope.clone(),
        other_sensor_scope,
        other_endpoint_scope,
    ] {
        let bad_cx = make_cx(full_caps(), mismatched_scope, 200)?;
        assert_eq!(
            vault.fetch(&bad_cx, &id).err().map(|e| e.error_id()),
            Some(ERR_SECRET_SCOPE_MISMATCH_001)
        );
        assert!(vault.list_handles(&bad_cx)?.is_empty());
    }

    // Direct per-record AEAD binding: decrypting under tampered scope or generation fails closed.
    let kek = [0x42_u8; 32];
    let mut entropy = LabEntropy::from_seed([0x44; 32]);
    let (nonce, ct) = seal_secret_entry(
        &kek,
        &id,
        1,
        rtsp_scope.scope_digest(),
        &SecretBytes::from_slice(b"bound-payload")?,
        &mut entropy,
    )?;
    assert_eq!(
        open_secret_entry(&kek, &id, 1, unifi_scope.scope_digest(), &nonce, &ct)
            .err()
            .map(|e| e.error_id()),
        Some(ERR_SECRET_TAMPERED_001)
    );
    assert_eq!(
        open_secret_entry(&kek, &id, 2, rtsp_scope.scope_digest(), &nonce, &ct)
            .err()
            .map(|e| e.error_id()),
        Some(ERR_SECRET_TAMPERED_001)
    );
    Ok(())
}

#[test]
fn capability_and_cancellation_checks_fail_closed() -> TestResult {
    let dir = TempVaultDir::new("auth-cancel")?;
    let passphrase = SecretBytes::from_slice(b"auth-passphrase-2026!")?;
    let scope = SecretScope::new(AdapterFamily::Onvif, "cam-ptz-1", "http://10.0.1.5/onvif")?;
    let id = SecretId::parse("secret:onvif:cam-ptz-1")?;

    let mut vault = LocalEncryptedVault::open_with_entropy(
        dir.path(),
        KdfParams::for_testing(32)?,
        LabEntropy::from_seed([0x55; 32]),
    );
    vault.initialize(&passphrase)?;

    let read_only = make_cx(&[CAP_SECRET_READ_001], scope.clone(), 100)?;
    assert_eq!(
        vault
            .store(&read_only, &id, SecretBytes::from_slice(b"onvif-pw")?)
            .err()
            .map(|e| e.error_id()),
        Some(ERR_SECRET_UNAUTHORIZED_001)
    );

    let write_only = make_cx(&[CAP_SECRET_WRITE_001], scope.clone(), 100)?;
    vault.store(&write_only, &id, SecretBytes::from_slice(b"onvif-pw")?)?;

    assert_eq!(
        vault.fetch(&write_only, &id).err().map(|e| e.error_id()),
        Some(ERR_SECRET_UNAUTHORIZED_001)
    );
    assert_eq!(
        vault
            .rotate(&write_only, &id, SecretBytes::from_slice(b"new-pw")?)
            .err()
            .map(|e| e.error_id()),
        Some(ERR_SECRET_UNAUTHORIZED_001)
    );

    let cancelled = read_only.clone().with_cancelled("operator abort");
    assert_eq!(
        vault.fetch(&cancelled, &id).err().map(|e| e.error_id()),
        Some(ERR_SECRET_CANCELLED_001)
    );

    let expired_auth = make_authority(&[CAP_SECRET_READ_001], Some(TimestampNs(500)))?;
    let expired_cx = SecretAccessCx::new(expired_auth, scope.clone(), TimestampNs(600))?;
    assert_eq!(
        vault.fetch(&expired_cx, &id).err().map(|e| e.error_id()),
        Some(ERR_SECRET_CANCELLED_001)
    );

    // Live fss_runtime AuthorityCx + RegionTree cancellation propagation
    let runtime_spec = RootAuthoritySpec {
        trace_id: "trace:runtime:cancel".to_string(),
        operation_id: OperationId::parse("op:runtime:cancel")?,
        principal: "principal:runtime:worker".to_string(),
        capabilities: vec!["CAP-ADAPTER-AUTH-001".to_string()],
        deadline: None,
        priority: 1,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:owner".to_string(),
        retention_scope: "retention:standard".to_string(),
        anchor_universe: ContentDigest::sha256(b"runtime-anchor"),
        generation: 1,
    };
    let (auth_cx, mut tree) = AuthorityCx::root(
        runtime_spec,
        RegionId::new("region:process:vault")?,
        RegionKind::Process,
        BudgetVector::default(),
        TimestampNs(10),
    )?;
    auth_cx.request_cancellation(&mut tree, TimestampNs(20))?;
    let runtime_secret_cx = SecretAccessCx::from_runtime_region(
        &auth_cx,
        &tree,
        &[CAP_SECRET_READ_001],
        scope,
        TimestampNs(30),
    )?;
    assert_eq!(
        vault
            .fetch(&runtime_secret_cx, &id)
            .err()
            .map(|e| e.error_id()),
        Some(ERR_SECRET_CANCELLED_001)
    );
    Ok(())
}

#[test]
fn locked_wrong_passphrase_tamper_and_default_kdf_checks() -> TestResult {
    let dir = TempVaultDir::new("tamper")?;
    let passphrase = SecretBytes::from_slice(b"correct-passphrase-2026!")?;
    let wrong_passphrase = SecretBytes::from_slice(b"wrong-passphrase-2026!")?;
    let scope = SecretScope::new(
        AdapterFamily::ArchiveS3,
        "bucket-primary",
        "s3://fss-arch/v1",
    )?;
    let id = SecretId::parse("secret:s3:archive-primary")?;
    let cx = make_cx(full_caps(), scope, 1_000)?;

    let mut vault = LocalEncryptedVault::open_with_entropy(
        dir.path(),
        KdfParams::for_testing(32)?,
        LabEntropy::from_seed([0x66; 32]),
    );
    assert_eq!(
        vault.fetch(&cx, &id).err().map(|e| e.error_id()),
        Some(ERR_SECRET_VAULT_LOCKED_001)
    );

    vault.initialize(&passphrase)?;
    vault.store(
        &cx,
        &id,
        SecretBytes::from_slice(b"s3-secret-access-key-01")?,
    )?;
    vault.lock();
    assert_eq!(
        vault.fetch(&cx, &id).err().map(|e| e.error_id()),
        Some(ERR_SECRET_VAULT_LOCKED_001)
    );

    assert_eq!(
        vault.unlock(&wrong_passphrase).err().map(|e| e.error_id()),
        Some(ERR_SECRET_AUTH_FAILED_001)
    );

    let original_bytes = fs::read(vault.vault_path())?;
    assert!(original_bytes.len() > VAULT_HEADER_LEN + 16);

    for &flip_offset in &[
        0_usize,
        5,
        8,
        20,
        50,
        80,
        VAULT_HEADER_LEN - 1,
        VAULT_HEADER_LEN + 3,
    ] {
        let mut mutated = original_bytes.clone();
        mutated[flip_offset] ^= 0x01;
        fs::write(vault.vault_path(), &mutated)?;
        assert_eq!(
            vault.unlock(&passphrase).err().map(|e| e.error_id()),
            Some(ERR_SECRET_TAMPERED_001),
            "expected tamper refusal at offset {flip_offset}"
        );
    }

    fs::write(vault.vault_path(), &original_bytes)?;
    vault.unlock(&passphrase)?;
    assert_eq!(
        vault.fetch(&cx, &id)?.secret().as_slice(),
        b"s3-secret-access-key-01"
    );

    // Production 100_000-round PBKDF2 default + OsEntropy round-trip
    let prod_dir = TempVaultDir::new("prod-kdf")?;
    let mut prod_vault = LocalEncryptedVault::open(prod_dir.path());
    prod_vault.initialize(&passphrase)?;
    prod_vault.lock();
    prod_vault.unlock(&passphrase)?;
    assert!(prod_vault.is_unlocked());
    Ok(())
}

#[cfg(unix)]
#[test]
fn permission_and_symlink_hardening_is_enforced() -> TestResult {
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    let dir = TempVaultDir::new("perms")?;
    let passphrase = SecretBytes::from_slice(b"perm-passphrase-2026!")?;
    let mut vault = LocalEncryptedVault::open_with_entropy(
        dir.path(),
        KdfParams::for_testing(16)?,
        LabEntropy::from_seed([0x77; 32]),
    );
    vault.initialize(&passphrase)?;
    vault.lock();

    assert_eq!(fs::symlink_metadata(dir.path())?.mode() & 0o777, 0o700);
    assert_eq!(
        fs::symlink_metadata(vault.vault_path())?.mode() & 0o777,
        0o600
    );

    fs::set_permissions(vault.vault_path(), fs::Permissions::from_mode(0o644))?;
    assert_eq!(
        vault.unlock(&passphrase).err().map(|e| e.error_id()),
        Some(ERR_SECRET_PERMISSION_DENIED_001)
    );
    fs::set_permissions(vault.vault_path(), fs::Permissions::from_mode(0o600))?;

    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755))?;
    assert_eq!(
        vault.unlock(&passphrase).err().map(|e| e.error_id()),
        Some(ERR_SECRET_PERMISSION_DENIED_001)
    );
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;

    let hardlink_path = dir.path().join("vault-hardlink.fssv");
    fs::hard_link(vault.vault_path(), &hardlink_path)?;
    assert_eq!(
        vault.unlock(&passphrase).err().map(|e| e.error_id()),
        Some(ERR_SECRET_PERMISSION_DENIED_001)
    );
    fs::remove_file(&hardlink_path)?;

    let symlink_dir = TempVaultDir::new("symlink-file")?;
    fs::create_dir(symlink_dir.path())?;
    fs::set_permissions(symlink_dir.path(), fs::Permissions::from_mode(0o700))?;
    symlink(vault.vault_path(), symlink_dir.path().join("vault.fssv"))?;
    let mut symlink_vault = LocalEncryptedVault::open_with_entropy(
        symlink_dir.path(),
        KdfParams::for_testing(16)?,
        LabEntropy::from_seed([0x78; 32]),
    );
    assert_eq!(
        symlink_vault
            .unlock(&passphrase)
            .err()
            .map(|e| e.error_id()),
        Some(ERR_SECRET_PERMISSION_DENIED_001)
    );

    let symlink_dir_alias = TempVaultDir::new("symlink-dir")?;
    symlink(dir.path(), symlink_dir_alias.path())?;
    let mut alias_vault = LocalEncryptedVault::open_with_entropy(
        symlink_dir_alias.path(),
        KdfParams::for_testing(16)?,
        LabEntropy::from_seed([0x79; 32]),
    );
    assert_eq!(
        alias_vault.unlock(&passphrase).err().map(|e| e.error_id()),
        Some(ERR_SECRET_PERMISSION_DENIED_001)
    );
    Ok(())
}

#[test]
fn redaction_and_canary_leak_scanner_across_all_surfaces() -> TestResult {
    let dir = TempVaultDir::new("canary")?;
    let passphrase = SecretBytes::from_slice(b"CANARY-PASS-9f8e7d6c5b4a!")?;
    let canary_rtsp = SecretBytes::from_slice(b"CANARY-RTSP-SECRET-X91K7Q!")?;
    let canary_webhook = SecretBytes::from_slice(b"CANARY-WEBHOOK-HMAC-Z44P2M!")?;

    let mut scanner = CanaryLeakScanner::new();
    scanner.register_secret("passphrase", &passphrase)?;
    scanner.register_secret("rtsp", &canary_rtsp)?;
    scanner.register_secret("webhook", &canary_webhook)?;

    let mut vault = LocalEncryptedVault::open_with_entropy(
        dir.path(),
        KdfParams::for_testing(32)?,
        LabEntropy::from_seed([0x88; 32]),
    );
    vault.initialize(&passphrase)?;

    let scope_rtsp = SecretScope::new(AdapterFamily::Rtsp, "cam-canary", "rtsp://10.1.1.2/s1")?;
    let scope_hook = SecretScope::new(
        AdapterFamily::AlertWebhook,
        "hook-pager",
        "https://alerts.example.invalid/v1/hook",
    )?;
    let cx_rtsp = make_cx(full_caps(), scope_rtsp, 1_000)?;
    let cx_hook = make_cx(full_caps(), scope_hook, 2_000)?;

    let h_rtsp = vault.store(
        &cx_rtsp,
        &SecretId::parse("secret:rtsp:cam-canary")?,
        canary_rtsp.clone(),
    )?;
    let h_hook = vault.store(
        &cx_hook,
        &SecretId::parse("secret:webhook:pager")?,
        canary_webhook.clone(),
    )?;
    let fetched = vault.fetch(&cx_rtsp, &h_rtsp.secret_id)?;

    assert_eq!(format!("{canary_rtsp:?}"), REDACTED_SECRET_DISPLAY);
    assert_eq!(format!("{canary_rtsp}"), REDACTED_SECRET_DISPLAY);

    let debug_dump = format!(
        "secret={canary_rtsp:?} fetched={fetched:?} vault={vault:?} h1={h_rtsp:?} h2={h_hook} cx={cx_rtsp:?} scanner={scanner:?}"
    );
    let simulated_capsule_json = format!(
        "{{\"handles\":[\"{h_rtsp}\",\"{h_hook}\"],\"backend\":\"{}\",\"status\":\"ok\"}}",
        vault.backend_kind()
    );
    let on_disk_bytes = fs::read(vault.vault_path())?;

    scanner.assert_clean("vault.fssv", &on_disk_bytes)?;
    scanner.assert_clean("debug_and_display", debug_dump.as_bytes())?;
    scanner.assert_clean("situation_capsule_json", simulated_capsule_json.as_bytes())?;

    let leak_err = scanner.assert_clean(
        "bad_log",
        b"leaked token=CANARY-RTSP-SECRET-X91K7Q! in trace",
    );
    let report = match leak_err {
        Err(report) => report,
        Ok(()) => return Err("expected canary leak to be detected".into()),
    };
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.encoding == LeakEncoding::Raw)
    );
    assert!(!report.to_string().contains("CANARY-RTSP-SECRET"));

    for &err_id in ALL_VAULT_ERROR_IDS {
        validate_error_id(err_id)?;
    }
    let op_err = SecretError::VaultLocked.to_operation_error()?;
    assert_eq!(op_err.error_id.as_str(), ERR_SECRET_VAULT_LOCKED_001);
    Ok(())
}
