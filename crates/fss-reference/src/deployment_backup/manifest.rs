#![forbid(unsafe_code)]
//! Canonical, strictly bounded inventory and irreversible restore provenance.

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    DigestAlgorithm, LedgerAnchor,
};
use fss_publication::SlotName;

use super::{
    AGENT_BACKUP_MANIFEST_DOMAIN, AGENT_BACKUP_PROFILE, AgentBackupSummary, BACKUP_MANIFEST_DOMAIN,
    BACKUP_PROFILE, BackupError, BackupLimits, DeploymentLimits, RESTORE_FENCE_DOMAIN, Result,
};

const VERSION: u32 = 1;
const FENCE_POLICY: &str = "all-alert-preparation-and-dispatch-disabled:no-unfence:v1";
const AGENT_FENCE_POLICY: &str =
    "all-alert-preparation-and-dispatch-disabled:agent-state-historical-read-only:no-unfence:v1";

/// One exact, whitelisted core-deployment file. Locks and transient staging files are excluded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupFile {
    pub(super) path: String,
    pub(super) bytes: u64,
    pub(super) digest: ContentDigest,
}
impl BackupFile {
    /// Safe relative path determined by the current-format profile, never arbitrary archive input.
    pub fn relative_path(&self) -> &str {
        &self.path
    }
    /// Exact raw file length; a spool file includes its envelope.
    pub const fn byte_len(&self) -> u64 {
        self.bytes
    }
    /// Digest of all raw file bytes, in addition to an object's native payload digest.
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }
}

pub(super) fn named_digest(name: &str) -> Result<ContentDigest> {
    if name.len() != 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(BackupError::Unsupported("object_filename"));
    }
    ContentDigest::parse(format!("sha256:{name}")).map_err(BackupError::from)
}

/// Whitelist maps untrusted names into already-owned file roles before any filesystem access.
pub(super) fn valid_path(path: &str) -> Result<()> {
    if let Some(relative) = path.strip_prefix("agent/publications/") {
        return valid_path(&format!("objects/{relative}"));
    }
    if matches!(path, "agent/sessions/journal.fssj" | "agent/sessions/ROOT") {
        return Ok(());
    }
    if matches!(
        path,
        "LAYOUT" | "ledger/journal.fssj" | "effects/journal.fssj"
    ) {
        return Ok(());
    }
    for prefix in ["objects/spool/objects/", "objects/spool/verified/"] {
        if let Some(name) = path.strip_prefix(prefix) {
            named_digest(name)?;
            return Ok(());
        }
    }
    if let Some(name) = path
        .strip_prefix("objects/roots/")
        .and_then(|name| name.strip_suffix(".root"))
    {
        SlotName::parse(name).map_err(|_| BackupError::Unsupported("root_filename"))?;
        return Ok(());
    }
    if let Some(name) = path
        .strip_prefix("objects/tombstones/")
        .and_then(|name| name.strip_suffix(".tomb"))
    {
        // The publication owner uses an algorithm-qualified stem here, whereas the spool
        // object and verification directories use bare SHA-256 hex names.
        named_digest(
            name.strip_prefix("sha256-")
                .ok_or(BackupError::Unsupported("tombstone_filename"))?,
        )?;
        return Ok(());
    }
    Err(BackupError::Unsupported("file_role"))
}

pub(super) fn encode_limits(e: &mut CanonicalEncoder, limits: &DeploymentLimits) {
    e.u64(limits.spool_object_max_bytes);
    e.u64(limits.spool_total_max_bytes);
    e.u64(limits.manifest_children_max as u64);
    e.u64(limits.batch_entries_max as u64);
    e.u32(limits.journal_record_max_bytes);
    e.u64(limits.max_roots as u64);
    e.u64(limits.max_tombstones as u64);
    e.u64(limits.spool_max_objects as u64);
    e.u64(limits.scan_max_objects as u64);
}
fn size(n: u64) -> Result<usize> {
    usize::try_from(n).map_err(|_| BackupError::Limit("integer_size"))
}
fn decode_limits(d: &mut CanonicalDecoder<'_>) -> Result<DeploymentLimits> {
    Ok(DeploymentLimits {
        spool_object_max_bytes: d.u64()?,
        spool_total_max_bytes: d.u64()?,
        manifest_children_max: size(d.u64()?)?,
        batch_entries_max: size(d.u64()?)?,
        journal_record_max_bytes: d.u32()?,
        max_roots: size(d.u64()?)?,
        max_tombstones: size(d.u64()?)?,
        spool_max_objects: size(d.u64()?)?,
        scan_max_objects: size(d.u64()?)?,
    })
}
pub(super) fn validate_deployment_limits(
    limits: &DeploymentLimits,
    ceilings: BackupLimits,
) -> Result<()> {
    if limits.spool_object_max_bytes > 256 * 1024 * 1024
        || limits.spool_total_max_bytes > 4 * 1024 * 1024 * 1024
        || limits.spool_max_objects > 65_536
        || limits.scan_max_objects > 262_144
        || limits.max_roots > 65_536
        || limits.max_tombstones > 65_536
        || limits.manifest_children_max > 16_384
        || limits.batch_entries_max > 16_384
        || limits.journal_record_max_bytes as usize > fss_ledger::MAX_RECORD_PAYLOAD_BYTES
        || limits.spool_object_max_bytes.checked_add(52).is_none()
    {
        return Err(BackupError::Unsupported("deployment_limits"));
    }
    // Capacity policy is retained exactly. Caller ceilings limit observed bytes, not the
    // deployment's unused capacity, so a small bundle from a larger capacity remains inspectable.
    limits
        .to_publication_limits()
        .validate()
        .map_err(|_| BackupError::Unsupported("deployment_limits"))?;
    ceilings.validate()
}

/// Exact complete snapshot of the supported core-deployment files.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupManifest {
    pub(super) site: String,
    pub(super) deployment_limits: DeploymentLimits,
    pub(super) source_anchor: LedgerAnchor,
    pub(super) ledger_root: ContentDigest,
    pub(super) ledger_bytes: u64,
    pub(super) effects_root: ContentDigest,
    pub(super) effects_bytes: u64,
    pub(super) agent: Option<AgentBackupSummary>,
    pub(super) total_bytes: u64,
    pub(super) files: Vec<BackupFile>,
}
impl BackupManifest {
    /// Exact current-format recovery profile.
    pub const fn profile(&self) -> &'static str {
        if self.agent.is_some() {
            AGENT_BACKUP_PROFILE
        } else {
            BACKUP_PROFILE
        }
    }
    /// Exact native agent recovery metadata, absent for the unchanged core-only profile.
    pub const fn agent_state(&self) -> Option<&AgentBackupSummary> {
        self.agent.as_ref()
    }
    /// Original site lineage; restoration does not rename historical authority.
    pub fn site(&self) -> &str {
        &self.site
    }
    /// All capacity values, independently bound to the original LAYOUT digest.
    pub const fn deployment_limits(&self) -> &DeploymentLimits {
        &self.deployment_limits
    }
    /// Committed source authority anchor before restoration appends a fence.
    pub fn source_anchor(&self) -> &LedgerAnchor {
        &self.source_anchor
    }
    /// Exact committed authority-journal root.
    pub const fn ledger_root(&self) -> ContentDigest {
        self.ledger_root
    }
    /// Exact committed effect-journal root; no replay or reconciliation has changed it.
    pub const fn effects_root(&self) -> ContentDigest {
        self.effects_root
    }
    /// Source authority journal length, used to prove prefix preservation after the fence.
    pub const fn ledger_bytes(&self) -> u64 {
        self.ledger_bytes
    }
    /// Source effect journal length, preserved exactly at restoration.
    pub const fn effects_bytes(&self) -> u64 {
        self.effects_bytes
    }
    /// Complete count including verification markers and metadata.
    pub fn file_count(&self) -> usize {
        self.files.len()
    }
    /// Total copied file bytes, excluding bundle manifest and fresh lock files.
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
    /// Canonically ordered complete inventory.
    pub fn files(&self) -> &[BackupFile] {
        &self.files
    }
    /// Independent checksum to retain before a bundle is used to restore.
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.to_bytes())
    }
    /// Hand-audited canonical format, independent of JSON or filesystem metadata.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        if self.agent.is_some() {
            e.text(AGENT_BACKUP_MANIFEST_DOMAIN);
            e.u32(2);
        } else {
            e.text(BACKUP_MANIFEST_DOMAIN);
            e.u32(VERSION);
        }
        e.text(self.profile());
        e.text(&self.site);
        encode_limits(&mut e, &self.deployment_limits);
        self.source_anchor.encode_canonical(&mut e);
        e.digest(self.ledger_root);
        e.u64(self.ledger_bytes);
        e.digest(self.effects_root);
        e.u64(self.effects_bytes);
        if let Some(agent) = &self.agent {
            agent.encode(&mut e);
        }
        e.u64(self.total_bytes);
        e.u64(self.files.len() as u64);
        for file in &self.files {
            e.text(&file.path);
            e.u64(file.bytes);
            e.digest(file.digest);
        }
        e.finish()
    }
    /// Decode only an independently pinned current-format manifest under caller ceilings.
    pub fn from_bytes(bytes: &[u8], expected: ContentDigest, limits: BackupLimits) -> Result<Self> {
        limits.validate()?;
        if bytes.len() > limits.max_manifest_bytes {
            return Err(BackupError::Limit("manifest_bytes"));
        }
        if ContentDigest::sha256(bytes) != expected {
            return Err(BackupError::Changed);
        }
        let mut d = CanonicalDecoder::new(bytes);
        let with_agent = match (d.text()?, d.u32()?, d.text()?) {
            (BACKUP_MANIFEST_DOMAIN, VERSION, BACKUP_PROFILE) => false,
            (AGENT_BACKUP_MANIFEST_DOMAIN, 2, AGENT_BACKUP_PROFILE) => true,
            _ => return Err(BackupError::Unsupported("manifest_version")),
        };
        let site = d.text()?;
        if site.len() > 256 {
            return Err(BackupError::Limit("site_bytes"));
        }
        crate::reference_deployment::validate_site_lineage(site)
            .map_err(|_| BackupError::Corrupt("site_lineage"))?;
        let site = site.to_owned();
        let deployment_limits = decode_limits(&mut d)?;
        validate_deployment_limits(&deployment_limits, limits)?;
        let source_anchor = LedgerAnchor::decode_canonical(&mut d)?;
        if source_anchor.site_lineage != site {
            return Err(BackupError::Corrupt("anchor_lineage"));
        }
        let ledger_root = d.digest()?;
        let ledger_bytes = d.u64()?;
        let effects_root = d.digest()?;
        let effects_bytes = d.u64()?;
        if ledger_bytes > limits.max_journal_bytes as u64
            || effects_bytes > limits.max_journal_bytes as u64
        {
            return Err(BackupError::Limit("journal_bytes"));
        }
        let agent = if with_agent {
            Some(AgentBackupSummary::decode(&mut d, limits)?)
        } else {
            None
        };
        let total_bytes = d.u64()?;
        if total_bytes > limits.max_total_bytes {
            return Err(BackupError::Limit("inventory_bytes"));
        }
        let count = size(d.u64()?)?;
        if count > limits.max_files {
            return Err(BackupError::Limit("inventory_files"));
        }
        let mut files: Vec<BackupFile> = Vec::with_capacity(count);
        let mut total = 0_u64;
        for _ in 0..count {
            let path = d.text()?;
            valid_path(path)?;
            if !with_agent && path.starts_with("agent/") {
                return Err(BackupError::Unsupported("profile_file_role"));
            }
            if files.last().is_some_and(|last| last.path.as_str() >= path) {
                return Err(BackupError::Corrupt("inventory_order"));
            }
            let bytes = d.u64()?;
            if bytes > limits.max_file_bytes {
                return Err(BackupError::Limit("file_bytes"));
            }
            if (path.starts_with("objects/spool/verified/")
                || path.starts_with("agent/publications/spool/verified/"))
                && bytes != 0
            {
                return Err(BackupError::Corrupt("verification_marker"));
            }
            let digest = d.digest()?;
            if digest.algorithm() != DigestAlgorithm::Sha256 {
                return Err(BackupError::Corrupt("digest_algorithm"));
            }
            total = total
                .checked_add(bytes)
                .ok_or(BackupError::Limit("inventory_bytes"))?;
            files.push(BackupFile {
                path: path.to_owned(),
                bytes,
                digest,
            });
        }
        d.ensure_finished()?;
        if total != total_bytes {
            return Err(BackupError::Corrupt("inventory_total"));
        }
        for (required, size) in [
            ("LAYOUT", None),
            ("ledger/journal.fssj", Some(ledger_bytes)),
            ("effects/journal.fssj", Some(effects_bytes)),
        ] {
            let file = files
                .iter()
                .find(|file| file.path == required)
                .ok_or(BackupError::Corrupt("required_file"))?;
            if size.is_some_and(|size| file.bytes != size) {
                return Err(BackupError::Corrupt("journal_length"));
            }
        }
        if let Some(agent) = &agent {
            for (path, expected) in [
                ("agent/sessions/journal.fssj", Some(agent.journal_bytes)),
                ("agent/sessions/ROOT", None),
            ] {
                let file = files
                    .iter()
                    .find(|file| file.path == path)
                    .ok_or(BackupError::Corrupt("agent_required_file"))?;
                if expected.is_some_and(|bytes| file.bytes != bytes) {
                    return Err(BackupError::Corrupt("agent_journal_length"));
                }
            }
        }
        let manifest = Self {
            site,
            deployment_limits,
            source_anchor,
            ledger_root,
            ledger_bytes,
            effects_root,
            effects_bytes,
            agent,
            total_bytes,
            files,
        };
        if manifest.to_bytes() != bytes {
            return Err(BackupError::Corrupt("noncanonical_manifest"));
        }
        Ok(manifest)
    }
}

/// Irreversible authority record: all alert preparation and dispatch are disabled on restore.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreFence {
    with_agent: bool,
    source_manifest: ContentDigest,
    source_anchor: LedgerAnchor,
    source_ledger_root: ContentDigest,
    source_effects_root: ContentDigest,
}
impl RestoreFence {
    pub(super) fn new(manifest: &BackupManifest) -> Self {
        Self {
            with_agent: manifest.agent.is_some(),
            source_manifest: manifest.digest(),
            source_anchor: manifest.source_anchor.clone(),
            source_ledger_root: manifest.ledger_root,
            source_effects_root: manifest.effects_root,
        }
    }
    /// Whether this profile copied historical agent authority that may never be resumed.
    pub const fn agent_state_read_only(&self) -> bool {
        self.with_agent
    }
    /// Pinned snapshot whose historical authority prefix was copied.
    pub const fn source_manifest(&self) -> ContentDigest {
        self.source_manifest
    }
    /// Exact historical source head; this record grants no old capability a new lifetime.
    pub fn source_anchor(&self) -> &LedgerAnchor {
        &self.source_anchor
    }
    /// Historical authority-journal root before the destination fence append.
    pub const fn source_ledger_root(&self) -> ContentDigest {
        self.source_ledger_root
    }
    /// Historical effect-journal root, preserved without dispatch or guessed reconciliation.
    pub const fn source_effects_root(&self) -> ContentDigest {
        self.source_effects_root
    }
    /// Canonical retained fence encoding and fixed no-unfence policy.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        e.text(RESTORE_FENCE_DOMAIN);
        e.text(if self.with_agent {
            AGENT_BACKUP_PROFILE
        } else {
            BACKUP_PROFILE
        });
        e.digest(self.source_manifest);
        self.source_anchor.encode_canonical(&mut e);
        e.digest(self.source_ledger_root);
        e.digest(self.source_effects_root);
        e.text(if self.with_agent {
            AGENT_FENCE_POLICY
        } else {
            FENCE_POLICY
        });
        e.finish()
    }
    /// Exact content identity of the fence record.
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.to_bytes())
    }
    /// Verify the exact retained fence. Unknown policy or encoding is an error.
    pub fn from_bytes(bytes: &[u8], expected: ContentDigest) -> Result<Self> {
        if bytes.len() > 4096 || ContentDigest::sha256(bytes) != expected {
            return Err(BackupError::Corrupt("restore_fence"));
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.text()? != RESTORE_FENCE_DOMAIN {
            return Err(BackupError::Unsupported("restore_fence_version"));
        }
        let with_agent = match d.text()? {
            BACKUP_PROFILE => false,
            AGENT_BACKUP_PROFILE => true,
            _ => return Err(BackupError::Unsupported("restore_fence_version")),
        };
        let value = Self {
            with_agent,
            source_manifest: d.digest()?,
            source_anchor: LedgerAnchor::decode_canonical(&mut d)?,
            source_ledger_root: d.digest()?,
            source_effects_root: d.digest()?,
        };
        let policy = if with_agent {
            AGENT_FENCE_POLICY
        } else {
            FENCE_POLICY
        };
        if value.source_anchor.site_lineage.len() > 256 || d.text()? != policy {
            return Err(BackupError::Corrupt("restore_fence_policy"));
        }
        d.ensure_finished()?;
        if value.to_bytes() != bytes {
            return Err(BackupError::Corrupt("restore_fence_canonical"));
        }
        Ok(value)
    }
}
