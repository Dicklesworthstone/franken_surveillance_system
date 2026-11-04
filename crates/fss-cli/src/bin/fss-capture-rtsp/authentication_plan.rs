#![forbid(unsafe_code)]
//! Pure credential-reference planning shared by native capture and site compilation.
//!
//! This module validates only the supplied reference and policy. It cannot read a
//! credential file, acquire entropy, or contact a camera.

use std::collections::BTreeMap;
use std::path::PathBuf;

use fss_cli::agent_json::{object, string};
use fss_core::ContentDigest;
use fss_reference::rtsp::authentication::DigestPolicy;

pub(crate) const MAX_CREDENTIAL_BYTES: usize = 256 + 1 + 1024 + 1;
pub(crate) const MAX_SECRET_IO_CALLS: usize = 16;

#[derive(Debug)]
pub(crate) struct AuthPlan {
    pub(crate) credential_file: PathBuf,
    pub(crate) realm: String,
    pub(crate) policy: DigestPolicy,
}

impl AuthPlan {
    pub(crate) fn parse(
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

    pub(crate) fn preview(&self) -> String {
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
