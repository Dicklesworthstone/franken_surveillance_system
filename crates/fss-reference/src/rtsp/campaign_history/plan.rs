#![forbid(unsafe_code)]
//! Frozen finite campaign scope, destinations, and independently selected resource ceilings.

use std::collections::BTreeSet;
use std::path::{Component, Path};

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, PrincipalId};

use super::{CampaignHistoryError as Error, Result, sha};

/// Maximum number of independently approved native attempts in one campaign.
pub const MAX_CAMPAIGN_ATTEMPTS: usize = 16;
/// Start and finish for every attempt, followed by one distinct terminal observation.
pub const MAX_CAMPAIGN_RECORDS: u32 = 33;
pub(super) const MAX_PATH: usize = 2048;
pub(super) const MAX_PLAN_BYTES: usize = 128 * 1024;

/// Exact original-datagram destination, when original retention was approved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CampaignSourceBinding {
    /// Absolute local destination; this metadata grants no access to it.
    pub path: String,
    /// Native `DatagramScope` canonical identity.
    pub scope: ContentDigest,
}

/// One predeclared attempt. Reconnect never silently reuses a generation or destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CampaignAttempt {
    /// One-based ordinal, including attempts that produce no usable pictures.
    pub ordinal: u32,
    /// Exact approval expected by the native acquisition owner.
    pub child_approval: ContentDigest,
    /// Native recording generation; no cross-attempt continuity is asserted.
    pub generation: u64,
    /// Native recording archive namespace.
    pub archive_namespace: ContentDigest,
    /// Independent native archive-pin journal identity.
    pub journal_id: ContentDigest,
    /// Host receive-clock identity, not camera capture time.
    pub receive_clock: ContentDigest,
    /// Explicit native decode-clock identity.
    pub decode_clock: ContentDigest,
    /// Absolute recording archive destination.
    pub archive_path: String,
    /// Absolute native archive-pin journal destination.
    pub pins_path: String,
    /// Optional separately approved original-datagram retention.
    pub source: Option<CampaignSourceBinding>,
    /// Exact picture count, or ceiling under explicit duration approval.
    pub picture_ceiling: u64,
}

/// Approved finite scope. No URI, credential, camera payload, or inferred capture clock is stored.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CampaignPlan {
    /// Outer approval, binding native plans and the history destination/ceilings at the caller.
    pub approval: ContentDigest,
    /// Principal bound to both the live owner and every subsequent metadata disclosure.
    pub principal: String,
    /// Absolute destination of this history's immutable object graph.
    pub history_path: String,
    /// Whether every planned independent session must settle successfully.
    pub continue_after_success: bool,
    /// Whether the owner approved retry after a sealed partial read interruption.
    pub retry_interrupted: bool,
    /// Whether progress-stall retry was explicitly configured.
    pub progress_supervised: bool,
    /// Whether a positive prefix below the picture ceiling satisfies the native stop rule.
    pub duration_limited: bool,
    /// Every attempt frozen before the first camera operation.
    pub attempts: Vec<CampaignAttempt>,
}

pub(super) fn path_valid(text: &str) -> bool {
    let path = Path::new(text);
    !text.is_empty()
        && text.len() <= MAX_PATH
        && !text.chars().any(char::is_control)
        && path.is_absolute()
        && path.components().all(|part| {
            matches!(
                part,
                Component::RootDir | Component::Prefix(_) | Component::Normal(_)
            )
        })
        && path.parent().is_some()
}

impl CampaignPlan {
    /// Validate exact identity, finite ordinals and disjoint local ownership domains.
    pub fn validate(&self) -> Result<()> {
        if !sha(self.approval)
            || self.principal.len() > 256
            || PrincipalId::parse(&self.principal).is_err()
            || !path_valid(&self.history_path)
            || !(1..=MAX_CAMPAIGN_ATTEMPTS).contains(&self.attempts.len())
        {
            return Err(Error::Configuration);
        }
        let mut paths = vec![self.history_path.as_str()];
        let (mut approvals, mut archives, mut journals, mut sources) = (
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
        );
        let mut generation = None;
        for (index, attempt) in self.attempts.iter().enumerate() {
            if attempt.ordinal != index as u32 + 1
                || attempt.picture_ceiling == 0
                || !sha(attempt.child_approval)
                || !sha(attempt.archive_namespace)
                || !sha(attempt.journal_id)
                || !sha(attempt.receive_clock)
                || !sha(attempt.decode_clock)
                || !path_valid(&attempt.archive_path)
                || !path_valid(&attempt.pins_path)
                || generation.is_some_and(|prior| attempt.generation <= prior)
                || !approvals.insert(attempt.child_approval)
                || !archives.insert(attempt.archive_namespace)
                || !journals.insert(attempt.journal_id)
            {
                return Err(Error::Configuration);
            }
            generation = Some(attempt.generation);
            paths.extend([attempt.archive_path.as_str(), attempt.pins_path.as_str()]);
            if let Some(source) = &attempt.source {
                if !path_valid(&source.path) || !sha(source.scope) || !sources.insert(source.scope)
                {
                    return Err(Error::Configuration);
                }
                paths.push(&source.path);
            }
        }
        for (index, left) in paths.iter().enumerate() {
            for right in &paths[index + 1..] {
                if Path::new(left).starts_with(right) || Path::new(right).starts_with(left) {
                    return Err(Error::Configuration);
                }
            }
        }
        Ok(())
    }

    /// Canonical v1 bytes, independent of Rust layout and JSON presentation.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut e = CanonicalEncoder::new();
        e.bytes(b"FSSRTCP1");
        e.u32(1);
        e.text("fss.rtsp_campaign_plan.v1");
        e.digest(self.approval);
        e.text(&self.principal);
        e.text(&self.history_path);
        e.bool(self.continue_after_success);
        e.bool(self.retry_interrupted);
        e.bool(self.progress_supervised);
        e.bool(self.duration_limited);
        e.u32(self.attempts.len() as u32);
        for attempt in &self.attempts {
            e.u32(attempt.ordinal);
            e.digest(attempt.child_approval);
            e.u64(attempt.generation);
            e.digest(attempt.archive_namespace);
            e.digest(attempt.journal_id);
            e.digest(attempt.receive_clock);
            e.digest(attempt.decode_clock);
            e.text(&attempt.archive_path);
            e.text(&attempt.pins_path);
            e.bool(attempt.source.is_some());
            if let Some(source) = &attempt.source {
                e.text(&source.path);
                e.digest(source.scope);
            }
            e.u64(attempt.picture_ceiling);
        }
        let bytes = e.finish_checked()?;
        if bytes.len() > MAX_PLAN_BYTES {
            return Err(Error::Limit);
        }
        Ok(bytes)
    }

    /// Exact immutable plan identity, also carried in every independently retained pin.
    pub fn digest(&self) -> Result<ContentDigest> {
        Ok(ContentDigest::sha256(&self.canonical_bytes()?))
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_PLAN_BYTES {
            return Err(Error::Limit);
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.bytes()? != b"FSSRTCP1" || d.u32()? != 1 || d.text()? != "fss.rtsp_campaign_plan.v1" {
            return Err(Error::Metadata);
        }
        let approval = d.digest()?;
        let principal = text(&mut d, 256)?;
        let history_path = text(&mut d, MAX_PATH)?;
        let continue_after_success = d.bool()?;
        let retry_interrupted = d.bool()?;
        let progress_supervised = d.bool()?;
        let duration_limited = d.bool()?;
        let count = d.u32()? as usize;
        if !(1..=MAX_CAMPAIGN_ATTEMPTS).contains(&count) {
            return Err(Error::Limit);
        }
        let mut attempts = Vec::with_capacity(count);
        for _ in 0..count {
            attempts.push(CampaignAttempt {
                ordinal: d.u32()?,
                child_approval: d.digest()?,
                generation: d.u64()?,
                archive_namespace: d.digest()?,
                journal_id: d.digest()?,
                receive_clock: d.digest()?,
                decode_clock: d.digest()?,
                archive_path: text(&mut d, MAX_PATH)?,
                pins_path: text(&mut d, MAX_PATH)?,
                source: if d.bool()? {
                    Some(CampaignSourceBinding {
                        path: text(&mut d, MAX_PATH)?,
                        scope: d.digest()?,
                    })
                } else {
                    None
                },
                picture_ceiling: d.u64()?,
            });
        }
        d.ensure_finished()?;
        let plan = Self {
            approval,
            principal,
            history_path,
            continue_after_success,
            retry_interrupted,
            progress_supervised,
            duration_limited,
            attempts,
        };
        if plan.canonical_bytes()? != bytes {
            return Err(Error::Metadata);
        }
        Ok(plan)
    }
}

pub(super) fn text(d: &mut CanonicalDecoder<'_>, maximum: usize) -> Result<String> {
    let text = d.text()?;
    if text.len() > maximum {
        return Err(Error::Limit);
    }
    Ok(text.to_owned())
}

/// Independent input, allocation, scan and aggregate metadata bounds. No stored bytes widen them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CampaignHistoryLimits {
    /// Maximum selected transition records, at most 33.
    pub maximum_records: u32,
    /// Largest allocating read admitted from the publisher, 4 KiB through 1 MiB.
    pub maximum_spool_object_bytes: usize,
    /// Maximum entries admitted by any directory scan, at most 65536.
    pub maximum_scan_roots: usize,
    /// Cumulative selected canonical metadata and manifest bytes, at most 256 MiB.
    pub maximum_metadata_bytes: u64,
}
impl Default for CampaignHistoryLimits {
    fn default() -> Self {
        Self {
            maximum_records: MAX_CAMPAIGN_RECORDS,
            maximum_spool_object_bytes: 256 * 1024,
            maximum_scan_roots: 4096,
            maximum_metadata_bytes: 16 * 1024 * 1024,
        }
    }
}
impl CampaignHistoryLimits {
    /// Reject invalid or unbounded resource reservations before any I/O.
    pub fn validate(self) -> Result<()> {
        if !(1..=MAX_CAMPAIGN_RECORDS).contains(&self.maximum_records)
            || !(4096..=1024 * 1024).contains(&self.maximum_spool_object_bytes)
            || !(1..=65536).contains(&self.maximum_scan_roots)
            || !(4096..=256 * 1024 * 1024).contains(&self.maximum_metadata_bytes)
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }

    /// Explicit canonical resource reservation, suitable for the caller's outer approval.
    pub fn canonical_bytes(self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut e = CanonicalEncoder::new();
        e.text("fss.rtsp_campaign_limits.v1");
        self.encode(&mut e);
        Ok(e.finish_checked()?)
    }

    /// Exact identity of the approved resource ceilings.
    pub fn digest(self) -> Result<ContentDigest> {
        Ok(ContentDigest::sha256(&self.canonical_bytes()?))
    }

    pub(super) fn encode(self, e: &mut CanonicalEncoder) {
        e.u32(self.maximum_records);
        e.u64(self.maximum_spool_object_bytes as u64);
        e.u64(self.maximum_scan_roots as u64);
        e.u64(self.maximum_metadata_bytes);
    }
    pub(super) fn decode(d: &mut CanonicalDecoder<'_>) -> Result<Self> {
        let limits = Self {
            maximum_records: d.u32()?,
            maximum_spool_object_bytes: usize::try_from(d.u64()?).map_err(|_| Error::Limit)?,
            maximum_scan_roots: usize::try_from(d.u64()?).map_err(|_| Error::Limit)?,
            maximum_metadata_bytes: d.u64()?,
        };
        limits.validate()?;
        Ok(limits)
    }
}
