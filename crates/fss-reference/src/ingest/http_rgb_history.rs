#![forbid(unsafe_code)]
//! Ordered, restart-discoverable perception history in the existing root-last/ledger store.
//!
//! Each bounded prefix retains complete temporal configuration and every exact HTTP/RGB pin.
//! This is derived replay metadata, not a second authority journal or an episode checkpoint.
//! A stored history is not executed inference; native replay must still match all four stages.
//! New prefixes come only from held, ledgered native recording results. Prefixes and actual
//! source completion are distinct. No socket EOF, availability, event or alert is inferred.

use std::collections::BTreeSet;
use std::error::Error;
use crate::ingest::http_archive::HttpWirePin;
use crate::ingest::http_replay::completion::HttpCompletionPin;
use crate::ingest::http_rgb_evidence::{HttpRgbEvidencePin, HttpRgbEvidenceRecording};
use crate::ingest::rgb_archive::RgbArchivePin;
use crate::ReplayCx;
use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, DigestAlgorithm};
use fss_geometry::WorkBudget;
use fss_object::ObjectManifest;
use fss_publication::SlotName;

mod config;
mod storage;
pub use config::{HttpRgbHistoryConfig, HttpRgbHistorySpec, CONFIG_DOMAIN, MAX_CONFIG_BYTES};
pub use storage::{HistoryAccess, HistoryAuthority, HistoryLimits, HistoryOperation, HistoryRecovery, read_latest_history};

/// Immutable derived history-prefix schema.
pub const HISTORY_DOMAIN: &str = "fss.http_rgb_history.v1";
/// Bounded reference segment length; longer operation requires an explicitly new episode.
pub const MAX_HISTORY_FRAMES: usize = 64;
/// Complete prefix record limit. No frame pins or safety fields are truncated to fit.
pub const MAX_HISTORY_BYTES: usize = 64 * 1024;
const KIND: &str = "http-rgb-history-v1";

/// Typed refusal. No refused operation yields a partial successful history or replay.
#[derive(Debug)]
pub enum HistoryError {
    /// Complete input, allocation, scan, step or session-length bound.
    Limit,
    /// Inconsistent canonical bytes, configuration, source, sequence or native stage.
    Mismatch,
    /// Another immutable prefix owns this slot, or the proposed predecessor is stale.
    Conflict,
    /// Required native computation, publication or terminal source boundary is absent.
    NotReady,
    /// Current history read/write authority or owner cancellation refused.
    Denied,
    /// A required prefix was deleted or is not durably ledgered.
    Unavailable,
    /// Native storage, canonical, media, model or temporal engine refusal.
    Backend(Box<dyn Error>),
}
impl HistoryError {
    /// Stable registered boundary identities; nested native errors retain their source.
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::Limit => "ERR-HTTP-RGB-HISTORY-LIMIT-001",
            Self::Mismatch => "ERR-HTTP-RGB-HISTORY-MISMATCH-001",
            Self::Conflict => "ERR-HTTP-RGB-HISTORY-CONFLICT-001",
            Self::NotReady => "ERR-HTTP-RGB-HISTORY-NOT-READY-001",
            Self::Denied => "ERR-HTTP-RGB-HISTORY-DENIED-001",
            Self::Unavailable => "ERR-HTTP-RGB-HISTORY-UNAVAILABLE-001",
            Self::Backend(_) => "ERR-HTTP-RGB-HISTORY-001",
        }
    }
}
impl std::fmt::Display for HistoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(self.stable_id()) }
}
impl Error for HistoryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self { Self::Backend(error) => Some(error.as_ref()), _ => None }
    }
}
/// Complete operation result.
pub type Result<T> = std::result::Result<T, HistoryError>;
fn backend<E: Error + 'static>(e: E) -> HistoryError { HistoryError::Backend(Box::new(e)) }
fn sha(bytes: [u8; 32]) -> ContentDigest { ContentDigest::new(DigestAlgorithm::Sha256, bytes) }
fn digest(d: ContentDigest) -> bool { d.algorithm() == DigestAlgorithm::Sha256 && d.bytes() != [0; 32] }
fn raw(d: &mut CanonicalDecoder<'_>) -> Result<[u8; 32]> {
    let value = d.digest().map_err(backend)?;
    if !digest(value) { return Err(HistoryError::Mismatch); }
    Ok(value.bytes())
}
fn count(d: &mut CanonicalDecoder<'_>, maximum: usize) -> Result<usize> {
    let n = usize::try_from(d.u64().map_err(backend)?).map_err(|_| HistoryError::Limit)?;
    if n > maximum { return Err(HistoryError::Limit); }
    Ok(n)
}
fn checkpoint(cx: &ReplayCx) -> Result<()> {
    cx.checkpoint("http-rgb-history:work").map_err(|_| HistoryError::Denied)
}

/// Independent pre-publication expectation. Possession is neither a grant nor a custody proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpRgbHistoryTip {
    /// Frozen configuration identity; sufficient to discover the latest canonical prefix.
    pub session: ContentDigest,
    /// Exact immutable prefix root.
    pub root: ContentDigest,
    /// Zero for configuration, then one per frame, then one optional source-completion revision.
    pub revision: u64,
}

/// Immutable bounded replay recipe. Only `publish` establishes durable canonical reachability;
/// `read_latest_history` returns stored expectations, not verified numerical results.
#[derive(Clone, Debug)]
pub struct HttpRgbHistory {
    config: HttpRgbHistoryConfig,
    frames: Vec<HttpRgbEvidencePin>,
    complete: Option<HttpCompletionPin>,
}
impl HttpRgbHistory {
    /// The empty initial prefix stores the configuration before acquisition starts.
    pub fn new(config: HttpRgbHistoryConfig) -> Self { Self { config, frames: Vec::new(), complete: None } }
    /// Entire retained configuration, including the original episode and zone polygons.
    pub fn config(&self) -> &HttpRgbHistoryConfig { &self.config }
    /// Exact source/detector/temporal expectations in original HTTP part order.
    pub fn frames(&self) -> &[HttpRgbEvidencePin] { &self.frames }
    /// Actual source completion selected by the native recording, not a guessed prefix end.
    pub fn source_completion(&self) -> Option<HttpCompletionPin> { self.complete }
    /// A history prefix is incomplete until its native source completion is separately recorded.
    pub fn is_complete(&self) -> bool { self.complete.is_some() }
    /// Exact prospective root known before any storage write.
    pub fn tip(&self) -> Result<HttpRgbHistoryTip> {
        Ok(HttpRgbHistoryTip { session: self.config.identity(), root: self.manifest()?.root(),
            revision: self.frames.len() as u64 + u64::from(self.complete.is_some()) })
    }
    /// Prepare the next prefix from the still-held, ledgered native result. No I/O or transfer.
    /// Both predecessor chains, the native zone configuration, selected class and model must
    /// agree. A skipped frame, wrong episode or silently changed policy cannot join this history.
    pub fn appended(&self, recording: &HttpRgbEvidenceRecording<'_, '_>, work: &mut WorkBudget<'_>, cx: &ReplayCx) -> Result<Self> {
        checkpoint(cx)?;
        let pin = recording.published().ok_or(HistoryError::NotReady)?;
        if self.complete.is_some() { return Err(HistoryError::Conflict); }
        if recording.recording().scope() != self.config.spec().source { return Err(HistoryError::Mismatch); }
        let done = recording.recording().capture().completed().ok_or(HistoryError::NotReady)?;
        let temporal = done.temporal();
        let spec = self.config.spec();
        if done.detection_run().report().contract_digest() != spec.head
            || done.detection_run().inference().model_digest() != spec.model
            || temporal.selected_class() != spec.class_index
            || temporal.zone_config_digest() != self.config.zone_config()
            || temporal.tracking_digest() != pin.stages[2] || temporal.zone_digest() != pin.stages[3]
        { return Err(HistoryError::Mismatch); }
        if self.frames.last() == Some(&pin) { return Ok(self.clone()); }
        if self.frames.len() >= MAX_HISTORY_FRAMES { return Err(HistoryError::Limit); }
        let prior = self.frames.last().map_or(self.config.initial_stages(), |p| [p.stages[2], p.stages[3]]);
        if [temporal.tracking_prior(), temporal.zone_prior()] != prior { return Err(HistoryError::Mismatch); }
        work.charge(MAX_HISTORY_BYTES as u64).map_err(backend)?;
        let mut next = self.clone();
        next.frames.push(pin);
        next.validate()?;
        Ok(next)
    }
    /// Prepare a terminal revision only from the recording's successful native completion.
    /// All results must already be delivered AND present in this exact contiguous history.
    pub fn completed(&self, recording: &HttpRgbEvidenceRecording<'_, '_>, cx: &ReplayCx) -> Result<Self> {
        checkpoint(cx)?;
        let original = recording.recording();
        let complete = original.completion().ok_or(HistoryError::NotReady)?;
        if original.scope() != self.config.spec().source || recording.prepared().is_some()
            || original.work().transferred != self.frames.len() as u64
            || self.frames.last().copied() != recording.last_delivered()
        { return Err(HistoryError::Mismatch); }
        if self.complete.is_some_and(|p| p != complete) { return Err(HistoryError::Conflict); }
        let mut next = self.clone(); next.complete = Some(complete); next.validate()?; Ok(next)
    }
    fn validate(&self) -> Result<()> {
        if self.frames.len() > MAX_HISTORY_FRAMES || self.frames.len() > self.config.spec().tracking.maximum_exposures { return Err(HistoryError::Limit); }
        let scope = self.config.spec().source.digest().map_err(backend)?;
        let mut exposures = BTreeSet::new();
        for (index, pin) in self.frames.iter().enumerate() {
            validate_pin(*pin)?;
            if pin.ordinal != index as u64 + 1 || pin.wire.scope != scope
                || pin.archive.retention != self.config.spec().retention || !exposures.insert(pin.exposure)
                || i128::from(pin.archive.capture[0]) < self.config.spec().validity.earliest.0
                || i128::from(pin.archive.capture[1]) > self.config.spec().validity.latest.0
            { return Err(HistoryError::Mismatch); }
            if index > 0 {
                let prior = self.frames[index - 1];
                if pin.archive.capture[0] <= prior.archive.capture[1]
                    || pin.wire.reads < prior.wire.reads || pin.wire.bytes < prior.wire.bytes
                    || ((pin.wire.reads == prior.wire.reads) != (pin.wire == prior.wire))
                    || pin.mask_policy != prior.mask_policy || pin.mask_generation != prior.mask_generation
                { return Err(HistoryError::Mismatch); }
            }
        }
        if let Some(complete) = self.complete {
            if !digest(complete.root) || complete.wire.scope != scope || !valid_wire(complete.wire)
                || self.frames.last().is_some_and(|last| last.wire.reads > complete.wire.reads || last.wire.bytes > complete.wire.bytes
                    || (last.wire.reads == complete.wire.reads && last.wire != complete.wire))
            { return Err(HistoryError::Mismatch); }
        }
        Ok(())
    }
    fn record(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut e = CanonicalEncoder::new();
        e.text(HISTORY_DOMAIN); e.digest(self.config.identity()); e.u64(self.frames.len() as u64);
        for pin in &self.frames { encode_pin(&mut e, *pin); }
        e.bool(self.complete.is_some());
        if let Some(complete) = self.complete { e.digest(complete.root); encode_wire(&mut e, complete.wire); }
        let bytes = e.finish_checked().map_err(backend)?;
        if bytes.len() > MAX_HISTORY_BYTES { return Err(HistoryError::Limit); }
        Ok(bytes)
    }
    fn decode(bytes: &[u8], config: HttpRgbHistoryConfig) -> Result<Self> {
        if bytes.len() > MAX_HISTORY_BYTES { return Err(HistoryError::Limit); }
        let mut d = CanonicalDecoder::new(bytes);
        if d.text().map_err(backend)? != HISTORY_DOMAIN || d.digest().map_err(backend)? != config.identity() { return Err(HistoryError::Mismatch); }
        let n = count(&mut d, MAX_HISTORY_FRAMES)?;
        let mut frames = Vec::with_capacity(n);
        for _ in 0..n { frames.push(decode_pin(&mut d)?); }
        let complete = if d.bool().map_err(backend)? { Some(HttpCompletionPin { root: d.digest().map_err(backend)?, wire: decode_wire(&mut d)? }) } else { None };
        d.ensure_finished().map_err(backend)?;
        let history = Self { config, frames, complete };
        if history.record()? != bytes { return Err(HistoryError::Mismatch); }
        Ok(history)
    }
    fn manifest(&self) -> Result<ObjectManifest> {
        let mut children = BTreeSet::from([self.config.identity()]);
        children.extend(self.frames.iter().map(|p| p.archive.root));
        ObjectManifest::new(KIND, children, Some(ContentDigest::sha256(&self.record()?))).map_err(backend)
    }
    fn at_revision(&self, revision: usize) -> Result<Self> {
        if revision > self.frames.len() + usize::from(self.complete.is_some()) { return Err(HistoryError::Mismatch); }
        Ok(Self { config: self.config.clone(), frames: self.frames[..revision.min(self.frames.len())].to_vec(),
            complete: if revision > self.frames.len() { self.complete } else { None } })
    }
}
fn prefix(session: ContentDigest) -> Result<String> {
    if !digest(session) { return Err(HistoryError::Mismatch); }
    let hex: String = session.bytes().iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("rgbh1-{hex}-"))
}
fn slot(session: ContentDigest, revision: usize) -> Result<SlotName> {
    if revision > MAX_HISTORY_FRAMES + 1 { return Err(HistoryError::Limit); }
    SlotName::parse(&format!("{}{:04x}", prefix(session)?, revision)).map_err(backend)
}
fn valid_wire(pin: HttpWirePin) -> bool { digest(pin.scope) && digest(pin.head) && pin.reads > 0 && pin.bytes > 0 }
fn validate_pin(pin: HttpRgbEvidencePin) -> Result<()> {
    if ![pin.archive.root, pin.archive.evidence, pin.archive.retention].into_iter().all(digest)
        || !valid_wire(pin.wire) || pin.ordinal == 0 || pin.archive.capture[0] > pin.archive.capture[1]
        || [pin.exposure, pin.encoded].into_iter().chain(pin.stages).any(|v| v == [0; 32])
        || pin.mask_policy.is_some() != pin.mask_generation.is_some()
        || pin.mask_policy.is_some_and(|v| !digest(v)) || pin.mask_generation == Some(0)
    { return Err(HistoryError::Mismatch); }
    Ok(())
}
fn encode_wire(e: &mut CanonicalEncoder, p: HttpWirePin) { e.digest(p.scope); e.digest(p.head); e.u64(p.reads); e.u64(p.bytes); }
fn decode_wire(d: &mut CanonicalDecoder<'_>) -> Result<HttpWirePin> {
    Ok(HttpWirePin { scope: d.digest().map_err(backend)?, head: d.digest().map_err(backend)?, reads: d.u64().map_err(backend)?, bytes: d.u64().map_err(backend)? })
}
fn encode_pin(e: &mut CanonicalEncoder, p: HttpRgbEvidencePin) {
    for value in [p.archive.root, p.archive.evidence, p.archive.retention] { e.digest(value); }
    for n in p.archive.capture { e.u64(n); }
    encode_wire(e, p.wire); e.digest(sha(p.exposure)); e.u64(p.ordinal); e.digest(sha(p.encoded));
    for value in p.stages { e.digest(sha(value)); }
    e.bool(p.mask_policy.is_some());
    if let (Some(policy), Some(generation)) = (p.mask_policy, p.mask_generation) { e.digest(policy); e.u64(generation); }
}
fn decode_pin(d: &mut CanonicalDecoder<'_>) -> Result<HttpRgbEvidencePin> {
    let archive = RgbArchivePin { root: d.digest().map_err(backend)?, evidence: d.digest().map_err(backend)?, retention: d.digest().map_err(backend)?,
        capture: [d.u64().map_err(backend)?, d.u64().map_err(backend)?] };
    let wire = decode_wire(d)?;
    let exposure = raw(d)?; let ordinal = d.u64().map_err(backend)?; let encoded = raw(d)?;
    let stages = [raw(d)?, raw(d)?, raw(d)?, raw(d)?];
    let (mask_policy, mask_generation) = if d.bool().map_err(backend)? { (Some(d.digest().map_err(backend)?), Some(d.u64().map_err(backend)?)) } else { (None, None) };
    Ok(HttpRgbEvidencePin { archive, wire, exposure, ordinal, encoded, stages, mask_policy, mask_generation })
}

#[cfg(test)]
mod tests;
