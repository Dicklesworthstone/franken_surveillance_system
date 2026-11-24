#![forbid(unsafe_code)]
//! Mocked macOS Keychain, Linux Secret-Service, argv-leak, and `VaultManager` contract tests.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec, TimestampNs,
};
use fss_vault::{
    AdapterFamily, CAP_SECRET_READ_001, CAP_SECRET_ROTATE_001, CAP_SECRET_WRITE_001,
    CanaryLeakScanner, CommandInvocation, CommandOutput, ERR_SECRET_BACKEND_UNAVAILABLE_001,
    ERR_SECRET_REVOKED_001, ERR_SECRET_SCOPE_MISMATCH_001, ERR_SECRET_TAMPERED_001, KdfParams,
    KeychainTransport, KeyringTransport, LabEntropy, LinuxKeyringBackend, MacOsKeychainBackend,
    OsEntropy, OsKekCustodian, SecretAccessCx, SecretBackendKind, SecretBytes, SecretError,
    SecretId, SecretScope, SecretStore, VaultManager,
};
use zeroize::Zeroizing;

type TestResult = Result<(), Box<dyn std::error::Error>>;

static OS_TEST_DIR_SEQ: AtomicU64 = AtomicU64::new(1);

struct TempVaultDir {
    path: PathBuf,
}

impl TempVaultDir {
    fn new(prefix: &str) -> Result<Self, std::io::Error> {
        let seq = OS_TEST_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fss-vault-os-{prefix}-{}-{seq}",
            std::process::id()
        ));
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

fn make_cx(scope: SecretScope, now_ns: i128) -> Result<SecretAccessCx, Box<dyn std::error::Error>> {
    let spec = RootAuthoritySpec {
        trace_id: "trace:vault:os-test".to_string(),
        operation_id: OperationId::parse("op:vault:os-test")?,
        principal: "principal:operator:bob".to_string(),
        capabilities: vec![
            CAP_SECRET_READ_001.to_string(),
            CAP_SECRET_WRITE_001.to_string(),
            CAP_SECRET_ROTATE_001.to_string(),
        ],
        deadline: None,
        priority: 1,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:owner".to_string(),
        retention_scope: "retention:standard".to_string(),
        anchor_universe: ContentDigest::sha256(b"fss-vault-os-anchor"),
        generation: 1,
    };
    let authority = ContextAuthority::new_root(spec)?;
    Ok(SecretAccessCx::new(authority, scope, TimestampNs(now_ns))?)
}

#[derive(Default)]
struct MockKeychainTransport {
    store: Mutex<BTreeMap<(String, String), Vec<u8>>>,
    captured_args: Mutex<Vec<Vec<String>>>,
}

impl MockKeychainTransport {
    fn captured_args(&self) -> Vec<Vec<String>> {
        self.captured_args
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    fn corrupt_entry(&self, service: &str, account: &str) {
        if let Ok(mut map) = self.store.lock()
            && let Some(val) = map.get_mut(&(service.to_string(), account.to_string()))
            && let Some(last) = val.last_mut()
        {
            *last = if *last == b'0' { b'1' } else { b'0' };
        }
    }
}

impl KeychainTransport for MockKeychainTransport {
    fn execute(&self, invocation: CommandInvocation) -> Result<CommandOutput, SecretError> {
        if let Ok(mut guard) = self.captured_args.lock() {
            guard.push(invocation.args.clone());
        }
        let script = invocation
            .stdin
            .as_ref()
            .map(|s| String::from_utf8_lossy(s.as_slice()).into_owned())
            .unwrap_or_default();
        let tokens: Vec<&str> = script.split_whitespace().collect();
        let cmd = tokens.first().copied().unwrap_or("");
        let mut account = String::new();
        let mut service = String::new();
        let mut hex_payload = String::new();
        let mut idx = 1;
        while idx < tokens.len() {
            match tokens[idx] {
                "-a" if idx + 1 < tokens.len() => {
                    account = tokens[idx + 1].to_string();
                    idx += 2;
                }
                "-s" if idx + 1 < tokens.len() => {
                    service = tokens[idx + 1].to_string();
                    idx += 2;
                }
                "-X" if idx + 1 < tokens.len() => {
                    hex_payload = tokens[idx + 1].to_string();
                    idx += 2;
                }
                _ => idx += 1,
            }
        }
        let mut map = self
            .store
            .lock()
            .map_err(|_| SecretError::BackendUnavailable {
                backend: "mock_keychain",
                detail: "poisoned lock".to_string(),
            })?;
        match cmd {
            "add-generic-password" => {
                map.insert((service, account), hex_payload.into_bytes());
                Ok(CommandOutput {
                    success: true,
                    exit_code: Some(0),
                    stdout: Zeroizing::new(Vec::new()),
                    stderr: String::new(),
                })
            }
            "find-generic-password" => match map.get(&(service, account)) {
                Some(bytes) => Ok(CommandOutput {
                    success: true,
                    exit_code: Some(0),
                    stdout: Zeroizing::new(bytes.clone()),
                    stderr: String::new(),
                }),
                None => Ok(CommandOutput {
                    success: false,
                    exit_code: Some(44),
                    stdout: Zeroizing::new(Vec::new()),
                    stderr: "not found".to_string(),
                }),
            },
            "delete-generic-password" => {
                let removed = map.remove(&(service, account)).is_some();
                Ok(CommandOutput {
                    success: removed,
                    exit_code: Some(if removed { 0 } else { 44 }),
                    stdout: Zeroizing::new(Vec::new()),
                    stderr: String::new(),
                })
            }
            _ => Err(SecretError::BackendUnavailable {
                backend: "mock_keychain",
                detail: "unexpected command".to_string(),
            }),
        }
    }
}

#[derive(Default)]
struct MockKeyringTransport {
    store: Mutex<BTreeMap<(String, String), Vec<u8>>>,
    captured_args: Mutex<Vec<Vec<String>>>,
}

impl MockKeyringTransport {
    fn captured_args(&self) -> Vec<Vec<String>> {
        self.captured_args
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }
}

impl KeyringTransport for MockKeyringTransport {
    fn execute(&self, invocation: CommandInvocation) -> Result<CommandOutput, SecretError> {
        if let Ok(mut guard) = self.captured_args.lock() {
            guard.push(invocation.args.clone());
        }
        let cmd = invocation.args.first().map(String::as_str).unwrap_or("");
        let mut service = String::new();
        let mut account = String::new();
        let mut idx = 1;
        while idx < invocation.args.len() {
            match invocation.args[idx].as_str() {
                "service" if idx + 1 < invocation.args.len() => {
                    service = invocation.args[idx + 1].clone();
                    idx += 2;
                }
                "account" if idx + 1 < invocation.args.len() => {
                    account = invocation.args[idx + 1].clone();
                    idx += 2;
                }
                _ => idx += 1,
            }
        }
        let mut map = self
            .store
            .lock()
            .map_err(|_| SecretError::BackendUnavailable {
                backend: "mock_keyring",
                detail: "poisoned lock".to_string(),
            })?;
        match cmd {
            "store" => {
                let payload = invocation
                    .stdin
                    .as_ref()
                    .map(|s| s.as_slice().to_vec())
                    .unwrap_or_default();
                map.insert((service, account), payload);
                Ok(CommandOutput {
                    success: true,
                    exit_code: Some(0),
                    stdout: Zeroizing::new(Vec::new()),
                    stderr: String::new(),
                })
            }
            "lookup" => match map.get(&(service, account)) {
                Some(bytes) => Ok(CommandOutput {
                    success: true,
                    exit_code: Some(0),
                    stdout: Zeroizing::new(bytes.clone()),
                    stderr: String::new(),
                }),
                None => Ok(CommandOutput {
                    success: false,
                    exit_code: Some(1),
                    stdout: Zeroizing::new(Vec::new()),
                    stderr: String::new(),
                }),
            },
            "clear" => {
                let removed = map.remove(&(service, account)).is_some();
                Ok(CommandOutput {
                    success: removed,
                    exit_code: Some(if removed { 0 } else { 1 }),
                    stdout: Zeroizing::new(Vec::new()),
                    stderr: String::new(),
                })
            }
            _ => Err(SecretError::BackendUnavailable {
                backend: "mock_keyring",
                detail: "unexpected secret-tool subcommand".to_string(),
            }),
        }
    }
}

struct UnavailableOsCustodian;

impl OsKekCustodian for UnavailableOsCustodian {
    fn os_backend_kind(&self) -> SecretBackendKind {
        SecretBackendKind::MacOsKeychain
    }

    fn store_kek(&self, _vault_id: &str, _kek: &[u8; 32]) -> Result<(), SecretError> {
        Err(SecretError::BackendUnavailable {
            backend: "unavailable_os",
            detail: "headless environment".to_string(),
        })
    }

    fn load_kek(&self, _vault_id: &str) -> Result<Option<Zeroizing<[u8; 32]>>, SecretError> {
        Err(SecretError::BackendUnavailable {
            backend: "unavailable_os",
            detail: "headless environment".to_string(),
        })
    }

    fn delete_kek(&self, _vault_id: &str) -> Result<(), SecretError> {
        Err(SecretError::BackendUnavailable {
            backend: "unavailable_os",
            detail: "headless environment".to_string(),
        })
    }
}

#[test]
fn os_keychain_and_keyring_never_leak_secrets_in_argv() -> TestResult {
    let secret_canary = SecretBytes::from_slice(b"CANARY-OS-BACKEND-KEY-778899!")?;
    let rotated_canary = SecretBytes::from_slice(b"CANARY-OS-ROTATED-KEY-445566!")?;
    let mut scanner = CanaryLeakScanner::new();
    scanner.register_secret("os-secret", &secret_canary)?;
    scanner.register_secret("os-rotated", &rotated_canary)?;

    let scope = SecretScope::new(
        AdapterFamily::UniFiProtect,
        "nvr-home-01",
        "https://192.168.1.1:443/proxy/protect",
    )?;
    let other_scope =
        SecretScope::new(AdapterFamily::Rtsp, "nvr-home-01", "rtsp://192.168.1.1/s1")?;
    let id = SecretId::parse("secret:unifi:nvr-home-01")?;
    let cx = make_cx(scope, 5_000)?;
    let bad_cx = make_cx(other_scope, 5_000)?;

    // 1. macOS Keychain backend with mocked transport
    let mut mac_backend = MacOsKeychainBackend::new(
        "com.fss.vault.test",
        Zeroizing::new([0xA5; 32]),
        MockKeychainTransport::default(),
        LabEntropy::from_seed([0x91; 32]),
    )?;
    let h1 = mac_backend.store(&cx, &id, secret_canary.clone())?;
    assert_eq!(h1.backend_kind, SecretBackendKind::MacOsKeychain);
    assert_eq!(mac_backend.fetch(&cx, &id)?.secret(), &secret_canary);
    assert_eq!(
        mac_backend.fetch(&bad_cx, &id).err().map(|e| e.error_id()),
        Some(ERR_SECRET_SCOPE_MISMATCH_001)
    );
    let h2 = mac_backend.rotate(&cx, &id, rotated_canary.clone())?;
    assert_eq!(h2.generation, 2);
    assert_eq!(mac_backend.fetch(&cx, &id)?.secret(), &rotated_canary);
    assert_eq!(mac_backend.list_handles(&cx)?.len(), 1);

    // Tampered keychain ciphertext fails closed with ERR-SECRET-TAMPERED-001
    mac_backend
        .transport()
        .corrupt_entry("com.fss.vault.test", id.as_str());
    assert_eq!(
        mac_backend.fetch(&cx, &id).err().map(|e| e.error_id()),
        Some(ERR_SECRET_TAMPERED_001)
    );

    let _ = mac_backend.revoke(&cx, &id)?;
    assert_eq!(
        mac_backend.fetch(&cx, &id).err().map(|e| e.error_id()),
        Some(ERR_SECRET_REVOKED_001)
    );
    for argv in mac_backend.transport().captured_args() {
        assert_eq!(argv, vec!["-i".to_string()]);
        scanner.assert_clean("macos_argv", argv.join(" ").as_bytes())?;
    }

    // 2. Linux Secret-Service backend with mocked transport
    let mut linux_backend = LinuxKeyringBackend::new(
        "com.fss.vault.test",
        Zeroizing::new([0x5A; 32]),
        MockKeyringTransport::default(),
        LabEntropy::from_seed([0x92; 32]),
    )?;
    let lh1 = linux_backend.store(&cx, &id, secret_canary.clone())?;
    assert_eq!(lh1.backend_kind, SecretBackendKind::LinuxSecretService);
    assert_eq!(linux_backend.fetch(&cx, &id)?.secret(), &secret_canary);
    let _ = linux_backend.rotate(&cx, &id, rotated_canary.clone())?;
    assert_eq!(linux_backend.fetch(&cx, &id)?.secret(), &rotated_canary);
    let _ = linux_backend.revoke(&cx, &id)?;
    for argv in linux_backend.transport().captured_args() {
        scanner.assert_clean("linux_argv", argv.join(" ").as_bytes())?;
    }
    Ok(())
}

#[test]
fn vault_manager_composes_os_kek_and_falls_back_cleanly() -> TestResult {
    let secret_canary = SecretBytes::from_slice(b"CANARY-MANAGER-SECRET-112233!")?;
    let fallback_canary = SecretBytes::from_slice(b"CANARY-FALLBACK-SECRET-445566!")?;
    let scope = SecretScope::new(
        AdapterFamily::AlertRelay,
        "relay-eu-01",
        "https://relay.example.invalid/events",
    )?;
    let id = SecretId::parse("secret:relay:eu-01")?;
    let cx = make_cx(scope, 9_000)?;

    let mac_custodian = MacOsKeychainBackend::new(
        "com.fss.vault.manager",
        Zeroizing::new([0xB4; 32]),
        MockKeychainTransport::default(),
        LabEntropy::from_seed([0x93; 32]),
    )?;

    let composed_dir = TempVaultDir::new("manager-os")?;
    let mut manager = VaultManager::open_with_os_kek_or_fallback(
        composed_dir.path(),
        "property-main",
        &mac_custodian,
        None,
        KdfParams::for_testing(16)?,
        LabEntropy::from_seed([0x94; 32]),
    )?;
    assert!(manager.used_os_kek());
    assert_eq!(
        manager.backend_kind(),
        SecretBackendKind::ComposedOsKekLocalVault
    );
    manager.store(&cx, &id, secret_canary.clone())?;
    manager.lock();
    assert!(!manager.is_unlocked());

    let reopened_manager = VaultManager::open_with_os_kek_or_fallback(
        composed_dir.path(),
        "property-main",
        &mac_custodian,
        None,
        KdfParams::for_testing(16)?,
        LabEntropy::from_seed([0x95; 32]),
    )?;
    assert!(reopened_manager.used_os_kek());
    assert_eq!(reopened_manager.fetch(&cx, &id)?.secret(), &secret_canary);

    // Fallback when OS backend is unavailable
    let fallback_dir = TempVaultDir::new("manager-fallback")?;
    let fallback_pass = SecretBytes::from_slice(b"fallback-operator-pass-2026!")?;
    let unavailable = UnavailableOsCustodian;
    assert_eq!(
        VaultManager::open_with_os_kek_or_fallback(
            fallback_dir.path(),
            "property-headless",
            &unavailable,
            None,
            KdfParams::for_testing(16)?,
            OsEntropy::new(),
        )
        .err()
        .map(|e| e.error_id()),
        Some(ERR_SECRET_BACKEND_UNAVAILABLE_001)
    );
    let mut fallback_manager = VaultManager::open_with_os_kek_or_fallback(
        fallback_dir.path(),
        "property-headless",
        &unavailable,
        Some(&fallback_pass),
        KdfParams::for_testing(16)?,
        LabEntropy::from_seed([0x96; 32]),
    )?;
    assert!(!fallback_manager.used_os_kek());
    assert_eq!(
        fallback_manager.backend_kind(),
        SecretBackendKind::LocalEncryptedVault
    );
    fallback_manager.store(&cx, &id, fallback_canary.clone())?;
    assert_eq!(fallback_manager.fetch(&cx, &id)?.secret(), &fallback_canary);
    Ok(())
}
