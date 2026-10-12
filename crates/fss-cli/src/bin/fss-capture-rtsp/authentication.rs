#![forbid(unsafe_code)]
//! The operator's exact private-file credential lease and Linux entropy boundary.
//! Parsing an AuthPlan performs no I/O. Credential values never enter the plan,
//! debug output, progress, archive, or command line. Allocation clearing below
//! is best effort, not a certified zeroization or protected-memory primitive.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use fss_cli::agent_json::{object, string};
use fss_core::ContentDigest;
use fss_reference::rtsp::authentication::{DigestCredentials, DigestPolicy};

pub(super) const MAX_CREDENTIAL_BYTES: usize = 256 + 1 + 1024 + 1;
pub(super) const MAX_SECRET_IO_CALLS: usize = 16;

#[derive(Debug)]
pub(super) struct AuthPlan {
    pub(super) credential_file: PathBuf,
    pub(super) realm: String,
    pub(super) policy: DigestPolicy,
}

impl AuthPlan {
    pub(super) fn parse(
        values: &BTreeMap<&str, &str>,
        path: fn(&str) -> Result<PathBuf, &'static str>,
    ) -> Result<Option<Self>, &'static str> {
        if ![
            "--credential-file",
            "--auth-realm",
            "--legacy-md5",
            "--legacy-no-qop",
        ]
        .iter()
        .any(|key| values.contains_key(key))
        {
            return Ok(None);
        }
        let credential_file = path(
            values
                .get("--credential-file")
                .ok_or("Digest requires a private credential-file reference")?,
        )?;
        let realm = *values
            .get("--auth-realm")
            .ok_or("Digest requires an exact realm")?;
        if realm.is_empty() || realm.len() > 512 || !realm.bytes().all(|b| (32..127).contains(&b)) {
            return Err("bounded printable ASCII Digest realm required");
        }
        let flag = |key| match values.get(key).copied() {
            None | Some("no") => Ok(false),
            Some("yes") => Ok(true),
            _ => Err("Digest legacy policy requires yes or no"),
        };
        let policy = DigestPolicy {
            allow_legacy_md5: flag("--legacy-md5")?,
            allow_legacy_no_qop: flag("--legacy-no-qop")?,
        };
        if policy.allow_legacy_no_qop && !policy.allow_legacy_md5 {
            return Err("legacy no-qop requires explicit legacy MD5 approval");
        }
        Ok(Some(Self {
            credential_file,
            realm: realm.to_owned(),
            policy,
        }))
    }

    pub(super) fn preview(&self) -> String {
        object(&[
            (
                "credential_file",
                string(self.credential_file.to_str().unwrap_or("")),
            ),
            (
                "realm_digest",
                string(&ContentDigest::sha256(self.realm.as_bytes()).to_text()),
            ),
            ("allow_legacy_md5", self.policy.allow_legacy_md5.to_string()),
            (
                "allow_legacy_no_qop",
                self.policy.allow_legacy_no_qop.to_string(),
            ),
            ("credential_backend", string("linux_private_regular_file")),
            ("entropy_backend", string("linux_urandom")),
            ("credentials_read", "false".into()),
            ("server_identity_verified", "false".into()),
            ("transport_encrypted", "false".into()),
        ])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SecretError {
    Credentials,
    Revoked,
    Entropy,
    Authority,
    Deadline,
}
impl std::fmt::Display for SecretError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "RTSP private credential/entropy boundary refused: {self:?}"
        )
    }
}
impl std::error::Error for SecretError {}

struct SecretBytes(Vec<u8>);
impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

fn credential_ranges(bytes: &[u8]) -> Result<(usize, usize), SecretError> {
    if bytes.len() > MAX_CREDENTIAL_BYTES || bytes.last() != Some(&b'\n') {
        return Err(SecretError::Credentials);
    }
    let user_end = bytes
        .iter()
        .position(|b| *b == b'\n')
        .ok_or(SecretError::Credentials)?;
    let password_end = bytes.len() - 1;
    if user_end >= password_end {
        return Err(SecretError::Credentials);
    }
    let username = std::str::from_utf8(&bytes[..user_end]).map_err(|_| SecretError::Credentials)?;
    let password = std::str::from_utf8(&bytes[user_end + 1..password_end])
        .map_err(|_| SecretError::Credentials)?;
    DigestCredentials::new(username, password).map_err(|_| SecretError::Credentials)?;
    Ok((user_end, password_end))
}

#[cfg(target_os = "linux")]
mod native {
    use super::*;
    use std::fs::{File, Metadata, OpenOptions};
    use std::io::{self, Read};
    use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};

    // Linux UAPI O_NONBLOCK | O_NOFOLLOW. Safe std opens refuse final symlinks;
    // even a concurrent replacement by a FIFO cannot create a blocking open.
    const OPEN_FLAGS: i32 = 0o4000 | 0o400000;

    #[derive(Clone, Copy, Eq, PartialEq)]
    struct Fingerprint {
        device: u64,
        inode: u64,
        owner: u32,
        group: u32,
        mode: u32,
        links: u64,
        bytes: u64,
        modified: (i64, i64),
        changed: (i64, i64),
    }
    impl Fingerprint {
        fn private_file(meta: Metadata) -> Result<Self, SecretError> {
            if !meta.is_file()
                || meta.mode() & 0o077 != 0
                || meta.mode() & 0o400 == 0
                || meta.nlink() != 1
                || meta.len() == 0
                || meta.len() > MAX_CREDENTIAL_BYTES as u64
            {
                return Err(SecretError::Credentials);
            }
            Ok(Self {
                device: meta.dev(),
                inode: meta.ino(),
                owner: meta.uid(),
                group: meta.gid(),
                mode: meta.mode(),
                links: meta.nlink(),
                bytes: meta.len(),
                modified: (meta.mtime(), meta.mtime_nsec()),
                changed: (meta.ctime(), meta.ctime_nsec()),
            })
        }
    }

    pub(crate) struct CredentialLease {
        path: PathBuf,
        file: File,
        identity: Fingerprint,
        secret: SecretBytes,
        user_end: usize,
        password_end: usize,
    }
    impl CredentialLease {
        pub(crate) fn load(
            path: &Path,
            check: &impl Fn() -> Result<(), SecretError>,
        ) -> Result<Self, SecretError> {
            check()?;
            let identity = Fingerprint::private_file(
                std::fs::symlink_metadata(path).map_err(|_| SecretError::Credentials)?,
            )?;
            check()?;
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(OPEN_FLAGS)
                .open(path)
                .map_err(|_| SecretError::Credentials)?;
            check()?;
            if Fingerprint::private_file(file.metadata().map_err(|_| SecretError::Credentials)?)?
                != identity
            {
                return Err(SecretError::Revoked);
            }
            check()?;
            let mut secret = SecretBytes(Vec::new());
            secret
                .0
                .try_reserve_exact(MAX_CREDENTIAL_BYTES + 1)
                .map_err(|_| SecretError::Credentials)?;
            secret.0.resize(MAX_CREDENTIAL_BYTES + 1, 0);
            let mut length = 0;
            let mut ended = false;
            for _ in 0..MAX_SECRET_IO_CALLS {
                check()?;
                let read = file.read(&mut secret.0[length..]);
                check()?;
                match read {
                    Ok(0) => {
                        ended = true;
                        break;
                    }
                    Ok(n) => {
                        length += n;
                        if length > MAX_CREDENTIAL_BYTES {
                            return Err(SecretError::Credentials);
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => return Err(SecretError::Credentials),
                }
            }
            if !ended || length as u64 != identity.bytes {
                return Err(SecretError::Credentials);
            }
            // Never truncate away nonzero secret bytes: the unused reservation is already zero.
            secret.0.truncate(length);
            let (user_end, password_end) = credential_ranges(&secret.0)?;
            let lease = Self {
                path: path.to_owned(),
                file,
                identity,
                secret,
                user_end,
                password_end,
            };
            lease.revalidate(check)?;
            Ok(lease)
        }

        /// Check before and after every socket operation. Rotation is revocation:
        /// a new run needs a newly resolved lease, never a silent credential refresh.
        pub(crate) fn revalidate(
            &self,
            check: &impl Fn() -> Result<(), SecretError>,
        ) -> Result<(), SecretError> {
            check()?;
            let current =
                std::fs::symlink_metadata(&self.path).map_err(|_| SecretError::Revoked)?;
            check()?;
            let held = self.file.metadata().map_err(|_| SecretError::Revoked)?;
            check()?;
            if Fingerprint::private_file(current).ok() != Some(self.identity)
                || Fingerprint::private_file(held).ok() != Some(self.identity)
            {
                return Err(SecretError::Revoked);
            }
            Ok(())
        }

        pub(crate) fn credentials(&self) -> Result<DigestCredentials<'_>, SecretError> {
            let username = std::str::from_utf8(&self.secret.0[..self.user_end])
                .map_err(|_| SecretError::Credentials)?;
            let password =
                std::str::from_utf8(&self.secret.0[self.user_end + 1..self.password_end])
                    .map_err(|_| SecretError::Credentials)?;
            DigestCredentials::new(username, password).map_err(|_| SecretError::Credentials)
        }
    }

    pub(crate) struct Entropy(File);
    impl Entropy {
        pub(crate) fn open(
            check: &impl Fn() -> Result<(), SecretError>,
        ) -> Result<Self, SecretError> {
            check()?;
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(OPEN_FLAGS)
                .open("/dev/urandom")
                .map_err(|_| SecretError::Entropy)?;
            check()?;
            let metadata = file.metadata().map_err(|_| SecretError::Entropy)?;
            check()?;
            // Linux's random character device is major 1, minor 9. A regular file
            // or another device at this path must not supply predictable cnonces.
            if !metadata.file_type().is_char_device() || metadata.rdev() != 0x109 {
                return Err(SecretError::Entropy);
            }
            Ok(Self(file))
        }
        pub(crate) fn next(
            &mut self,
            check: &impl Fn() -> Result<(), SecretError>,
        ) -> Result<[u8; 16], SecretError> {
            let mut value = [0; 16];
            let mut offset = 0;
            for _ in 0..MAX_SECRET_IO_CALLS {
                check()?;
                let read = self.0.read(&mut value[offset..]);
                check()?;
                match read {
                    Ok(0) => return Err(SecretError::Entropy),
                    Ok(n) => {
                        offset += n;
                        if offset == value.len() {
                            return Ok(value);
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => return Err(SecretError::Entropy),
                }
            }
            Err(SecretError::Entropy)
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod native {
    use super::*;
    pub(crate) struct CredentialLease;
    impl CredentialLease {
        pub(crate) fn load(
            _: &Path,
            check: &impl Fn() -> Result<(), SecretError>,
        ) -> Result<Self, SecretError> {
            check()?;
            Err(SecretError::Credentials)
        }
        pub(crate) fn revalidate(
            &self,
            _: &impl Fn() -> Result<(), SecretError>,
        ) -> Result<(), SecretError> {
            Err(SecretError::Revoked)
        }
        pub(crate) fn credentials(&self) -> Result<DigestCredentials<'_>, SecretError> {
            Err(SecretError::Credentials)
        }
    }
    pub(crate) struct Entropy;
    impl Entropy {
        pub(crate) fn open(
            check: &impl Fn() -> Result<(), SecretError>,
        ) -> Result<Self, SecretError> {
            check()?;
            Err(SecretError::Entropy)
        }
        pub(crate) fn next(
            &mut self,
            _: &impl Fn() -> Result<(), SecretError>,
        ) -> Result<[u8; 16], SecretError> {
            Err(SecretError::Entropy)
        }
    }
}

pub(crate) use native::{CredentialLease, Entropy};

#[cfg(test)]
#[path = "authentication_tests.rs"]
mod tests;
