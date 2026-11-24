#![forbid(unsafe_code)]
//! Safe stdin-only subprocess transports, sealed OS envelopes, and [`OsKekCustodian`].
//!
//! Sensitive payloads are NEVER placed in `argv` or environment variables; all
//! secret material flows strictly over piped `stdin` and zeroizing `stdout`.

use core::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{
    AEAD_KEY_LEN, AEAD_NONCE_LEN, AEAD_TAG_LEN, EntropySource, VAULT_OS_ENVELOPE_AAD_DOMAIN,
    aead_decrypt_zeroizing, aead_encrypt, derive_record_key,
};
use crate::error::SecretError;
use crate::scope::{SecretBackendKind, SecretHandle};
use crate::secret::{REDACTED_SECRET_DISPLAY, SecretBytes, SecretId};

/// Sealed OS-backend envelope binary prefix (`b"FSSO"`).
pub const OS_ENVELOPE_MAGIC: [u8; 4] = *b"FSSO";

/// Sealed OS-backend envelope format version.
pub const OS_ENVELOPE_VERSION: u16 = 1;

/// Subprocess command invocation enforcing zero secrets in `args`.
#[derive(Clone, Eq, PartialEq)]
pub struct CommandInvocation {
    /// Executable program path or name.
    pub program: &'static str,
    /// Non-secret command-line arguments (NEVER carries secret bytes).
    pub args: Vec<String>,
    /// Optional sensitive payload written strictly to piped `stdin`.
    pub stdin: Option<SecretBytes>,
}

impl fmt::Debug for CommandInvocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommandInvocation")
            .field("program", &self.program)
            .field("args", &self.args)
            .field(
                "stdin",
                &self.stdin.as_ref().map(|_| REDACTED_SECRET_DISPLAY),
            )
            .finish()
    }
}

/// Captured subprocess output with zeroizing `stdout`.
pub struct CommandOutput {
    /// Whether the subprocess exited with status 0.
    pub success: bool,
    /// Optional OS exit code.
    pub exit_code: Option<i32>,
    /// Standard output bytes, zeroized on drop.
    pub stdout: Zeroizing<Vec<u8>>,
    /// Non-secret standard error diagnostic text.
    pub stderr: String,
}

impl fmt::Debug for CommandOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommandOutput")
            .field("success", &self.success)
            .field("exit_code", &self.exit_code)
            .field("stdout", &REDACTED_SECRET_DISPLAY)
            .field("stderr_len", &self.stderr.len())
            .finish()
    }
}

/// Pluggable transport for macOS Keychain operations.
pub trait KeychainTransport {
    /// Executes a safe stdin-piped keychain command invocation.
    fn execute(&self, invocation: CommandInvocation) -> Result<CommandOutput, SecretError>;
}

/// Pluggable transport for Linux Secret-Service (`secret-tool`) operations.
pub trait KeyringTransport {
    /// Executes a safe stdin-piped keyring command invocation.
    fn execute(&self, invocation: CommandInvocation) -> Result<CommandOutput, SecretError>;
}

/// Custodian trait for storing and loading a 256-bit local-vault KEK in an OS keychain/keyring.
pub trait OsKekCustodian {
    /// Reports the underlying OS backend kind.
    fn os_backend_kind(&self) -> SecretBackendKind;

    /// Stores a 32-byte master KEK under `vault_id` via stdin-only IPC.
    fn store_kek(&self, vault_id: &str, kek: &[u8; AEAD_KEY_LEN]) -> Result<(), SecretError>;

    /// Loads an existing 32-byte master KEK for `vault_id`, or `Ok(None)` if absent.
    fn load_kek(
        &self,
        vault_id: &str,
    ) -> Result<Option<Zeroizing<[u8; AEAD_KEY_LEN]>>, SecretError>;

    /// Deletes a stored KEK for `vault_id`.
    fn delete_kek(&self, vault_id: &str) -> Result<(), SecretError>;
}

/// Production macOS Keychain transport invoking `/usr/bin/security -i` with cleared env
/// and stdin-only command dispatch.
#[derive(Clone, Copy, Debug, Default)]
pub struct SecurityCliKeychainTransport;

impl KeychainTransport for SecurityCliKeychainTransport {
    #[cfg(target_os = "macos")]
    fn execute(&self, invocation: CommandInvocation) -> Result<CommandOutput, SecretError> {
        run_piped_command("macos_keychain", invocation, &[])
    }

    #[cfg(not(target_os = "macos"))]
    fn execute(&self, _invocation: CommandInvocation) -> Result<CommandOutput, SecretError> {
        Err(SecretError::BackendUnavailable {
            backend: "macos_keychain",
            detail: "macOS Keychain is only available on target_os = \"macos\"".to_string(),
        })
    }
}

/// Production Linux Secret-Service transport invoking `secret-tool` with stdin-only secret transfer.
#[derive(Clone, Copy, Debug, Default)]
pub struct SecretToolKeyringTransport;

impl KeyringTransport for SecretToolKeyringTransport {
    #[cfg(target_os = "linux")]
    fn execute(&self, invocation: CommandInvocation) -> Result<CommandOutput, SecretError> {
        run_piped_command(
            "linux_secret_service",
            invocation,
            &["DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"],
        )
    }

    #[cfg(not(target_os = "linux"))]
    fn execute(&self, _invocation: CommandInvocation) -> Result<CommandOutput, SecretError> {
        Err(SecretError::BackendUnavailable {
            backend: "linux_secret_service",
            detail: "Linux Secret-Service is only available on target_os = \"linux\"".to_string(),
        })
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn run_piped_command(
    backend: &'static str,
    invocation: CommandInvocation,
    preserved_env_keys: &[&str],
) -> Result<CommandOutput, SecretError> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut cmd = Command::new(invocation.program);
    cmd.args(&invocation.args)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    for &key in preserved_env_keys {
        if let Ok(val) = std::env::var(key) {
            cmd.env(key, val);
        }
    }

    let mut child = cmd.spawn().map_err(|err| SecretError::BackendUnavailable {
        backend,
        detail: format!("failed to spawn '{}': {:?}", invocation.program, err.kind()),
    })?;

    if let Some(stdin_payload) = invocation.stdin
        && let Some(mut child_stdin) = child.stdin.take()
    {
        child_stdin
            .write_all(stdin_payload.as_slice())
            .map_err(|err| SecretError::BackendUnavailable {
                backend,
                detail: format!(
                    "failed writing stdin to '{}': {:?}",
                    invocation.program,
                    err.kind()
                ),
            })?;
    }

    let output = child
        .wait_with_output()
        .map_err(|err| SecretError::BackendUnavailable {
            backend,
            detail: format!(
                "failed waiting on '{}': {:?}",
                invocation.program,
                err.kind()
            ),
        })?;
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    Ok(CommandOutput {
        success: output.status.success(),
        exit_code: output.status.code(),
        stdout: Zeroizing::new(output.stdout),
        stderr,
    })
}

fn build_os_envelope_aad(
    secret_id: &SecretId,
    generation: u64,
    scope_digest: ContentDigest,
    backend_kind: SecretBackendKind,
) -> Vec<u8> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(VAULT_OS_ENVELOPE_AAD_DOMAIN);
    secret_id.encode_canonical(&mut encoder);
    encoder.u64(generation);
    encoder.digest(scope_digest);
    backend_kind.encode_canonical(&mut encoder);
    encoder.finish()
}

pub(crate) fn seal_os_envelope(
    wrapping_key: &[u8; AEAD_KEY_LEN],
    handle: &SecretHandle,
    secret: &SecretBytes,
    entropy: &mut dyn EntropySource,
) -> Result<Vec<u8>, SecretError> {
    let mut nonce = [0_u8; AEAD_NONCE_LEN];
    entropy.fill_bytes(&mut nonce)?;
    let key = derive_record_key(
        wrapping_key,
        &handle.secret_id,
        handle.generation,
        handle.scope_digest,
    );
    let aad = build_os_envelope_aad(
        &handle.secret_id,
        handle.generation,
        handle.scope_digest,
        handle.backend_kind,
    );
    let ciphertext = aead_encrypt(&key, &nonce, &aad, secret.as_slice())?;
    let mut encoder = CanonicalEncoder::new();
    encoder.bytes(&OS_ENVELOPE_MAGIC);
    encoder.u32(u32::from(OS_ENVELOPE_VERSION));
    handle.encode_canonical(&mut encoder);
    encoder.bytes(&nonce);
    encoder.bytes(&ciphertext);
    encoder.finish_checked().map_err(|_| SecretError::Tampered {
        detail: "failed to encode OS sealed envelope",
    })
}

pub(crate) fn open_os_envelope(
    wrapping_key: &[u8; AEAD_KEY_LEN],
    expected_handle: &SecretHandle,
    raw: &[u8],
) -> Result<SecretBytes, SecretError> {
    let mut decoder = CanonicalDecoder::new(raw);
    let magic = decoder.bytes().map_err(|_| SecretError::Tampered {
        detail: "invalid OS envelope magic",
    })?;
    if magic != OS_ENVELOPE_MAGIC {
        return Err(SecretError::Tampered {
            detail: "OS envelope magic mismatch",
        });
    }
    let version = decoder.u32().map_err(|_| SecretError::Tampered {
        detail: "invalid OS envelope version",
    })?;
    if version != u32::from(OS_ENVELOPE_VERSION) {
        return Err(SecretError::Tampered {
            detail: "unsupported OS envelope version",
        });
    }
    let stored_handle =
        SecretHandle::decode_canonical(&mut decoder).map_err(|_| SecretError::Tampered {
            detail: "invalid handle in OS envelope",
        })?;
    if stored_handle.secret_id != expected_handle.secret_id
        || stored_handle.generation != expected_handle.generation
        || stored_handle.scope_digest != expected_handle.scope_digest
        || stored_handle.backend_kind != expected_handle.backend_kind
    {
        return Err(SecretError::Tampered {
            detail: "OS envelope metadata does not match expected handle",
        });
    }
    let nonce_slice = decoder.bytes().map_err(|_| SecretError::Tampered {
        detail: "invalid nonce in OS envelope",
    })?;
    let nonce: [u8; AEAD_NONCE_LEN] =
        nonce_slice.try_into().map_err(|_| SecretError::Tampered {
            detail: "OS envelope nonce length mismatch",
        })?;
    let ciphertext = decoder.bytes().map_err(|_| SecretError::Tampered {
        detail: "invalid ciphertext in OS envelope",
    })?;
    if ciphertext.len() < AEAD_TAG_LEN {
        return Err(SecretError::Tampered {
            detail: "OS envelope ciphertext truncated",
        });
    }
    decoder
        .ensure_finished()
        .map_err(|_| SecretError::Tampered {
            detail: "trailing bytes in OS envelope",
        })?;

    let key = derive_record_key(
        wrapping_key,
        &expected_handle.secret_id,
        expected_handle.generation,
        expected_handle.scope_digest,
    );
    let aad = build_os_envelope_aad(
        &expected_handle.secret_id,
        expected_handle.generation,
        expected_handle.scope_digest,
        expected_handle.backend_kind,
    );
    let mut plain = aead_decrypt_zeroizing(
        &key,
        &nonce,
        &aad,
        ciphertext,
        "OS envelope AEAD authentication failed",
    )?;
    let bytes = core::mem::take(&mut *plain);
    let result = SecretBytes::new(bytes);
    plain.zeroize();
    result
}

pub(crate) fn validate_os_label(field: &str, value: &str) -> Result<(), SecretError> {
    if value.is_empty()
        || value.len() > 160
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
    {
        return Err(SecretError::InvalidInput {
            detail: format!(
                "{field} must be 1..=160 ASCII characters in [A-Za-z0-9._:-] with no whitespace"
            ),
        });
    }
    Ok(())
}

pub(crate) fn trim_ascii_whitespace(mut bytes: &[u8]) -> &[u8] {
    while let Some(&first) = bytes.first() {
        if first.is_ascii_whitespace() {
            bytes = &bytes[1..];
        } else {
            break;
        }
    }
    while let Some(&last) = bytes.last() {
        if last.is_ascii_whitespace() {
            bytes = &bytes[..bytes.len() - 1];
        } else {
            break;
        }
    }
    bytes
}

pub(crate) fn encode_hex_zeroizing(bytes: &[u8]) -> Zeroizing<String> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    Zeroizing::new(out)
}

pub(crate) fn decode_hex_zeroizing(hex: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    if !hex.len().is_multiple_of(2) {
        return Err(SecretError::Tampered {
            detail: "OS backend returned odd-length hex payload",
        });
    }
    let mut out = Zeroizing::new(Vec::with_capacity(hex.len() / 2));
    let (pairs, remainder) = hex.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(SecretError::Tampered {
            detail: "OS backend returned odd-length hex payload",
        });
    }
    for &[hi_byte, lo_byte] in pairs {
        let hi = decode_nibble(hi_byte).ok_or(SecretError::Tampered {
            detail: "OS backend returned non-hex byte",
        })?;
        let lo = decode_nibble(lo_byte).ok_or(SecretError::Tampered {
            detail: "OS backend returned non-hex byte",
        })?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn bytes_to_kek(bytes: &[u8]) -> Result<Zeroizing<[u8; AEAD_KEY_LEN]>, SecretError> {
    let arr: [u8; AEAD_KEY_LEN] = bytes.try_into().map_err(|_| SecretError::Tampered {
        detail: "OS backend returned malformed KEK length",
    })?;
    Ok(Zeroizing::new(arr))
}
