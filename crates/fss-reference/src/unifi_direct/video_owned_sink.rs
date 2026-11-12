#![forbid(unsafe_code)]
//! Owned unknown-time video publication without an audio configuration.
//!
//! This synchronous owner starts no task. A caller must provide a supervised,
//! authorized execution boundary and drain it on cancellation. No source is
//! discarded on a refusal and a possibly published candidate is never changed.

use fss_container::{Mp4Error, Mp4Limits, flv_avc};
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_packet::extended_flv::stream::SourceRecord;
use fss_publication::RootLedgerReceipt;

use super::{archive, evidence, recording};
use crate::{ReferenceDeployment, ReplayCx};

/// Inputs returned unchanged when video initialization is refused.
pub struct Inputs {
    /// Exact original AVC configuration record.
    pub configuration: SourceRecord,
    /// Caller-bound connection and generation; not camera authentication.
    pub source: flv_avc::SourceKey,
    /// Select the fixed-configuration `avc3` profile when true.
    pub inband: bool,
    /// Identity of the separately authorized original-byte retention decision.
    pub retention: ContentDigest,
    /// Bounds on media initialization.
    pub media_limits: Mp4Limits,
    /// Bounds on video evidence preparation.
    pub evidence_limits: evidence::Limits,
}

/// Initialization refusal with all caller-owned inputs.
#[must_use]
pub struct ConstructionRefusal {
    /// Payload-free media refusal.
    pub reason: Mp4Error,
    /// Original inputs, including the source record.
    pub inputs: Inputs,
}

/// Reason an offered segment was not consumed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfferError {
    /// A segment or uncertain publication is already retained.
    Busy,
    /// Source, configuration, or initialization does not match this owner.
    Binding,
    /// Sequence, timing, or bounded arithmetic is invalid.
    Continuity,
}

/// Refused segment remains wholly owned by the caller.
#[must_use]
pub struct OfferRefusal {
    /// Payload-free reason.
    pub reason: OfferError,
    /// Unconsumed original segment.
    pub segment: recording::Segment,
}

/// A failed flush retains the segment and, after preparation, its exact pin.
#[derive(Debug)]
pub enum FlushError {
    /// There was no segment to publish.
    Empty,
    /// Original-source verification or bounded preparation refused.
    Preparation(evidence::Error),
    /// A prior pin did not match the current segment.
    Candidate,
    /// The publication may require exact-root reconciliation.
    Publication(archive::UnknownTimePublishError),
}

/// Publication receipt and original segment returned to the caller.
#[must_use]
pub struct Published {
    /// Exact candidate used for intent and confirmation.
    pub pin: archive::UnknownTimePin,
    /// Root-ledger outcome; not a physical capture-time claim.
    pub receipt: RootLedgerReceipt,
    /// Original segment, still requiring caller-managed custody.
    pub segment: recording::Segment,
    still_seal: StillSeal,
}

struct StillSeal {
    pin: archive::UnknownTimePin,
    source: flv_avc::SourceKey,
    configuration: SourceRecord,
    inband: bool,
    media_limits: Mp4Limits,
    evidence_limits: evidence::Limits,
}

/// An exact confirmed publication retained for a concurrent still operation.
/// This is publication-linked source, not an independent archive readback.
#[must_use = "return the original publication after still work drains"]
pub struct PublishedStillSource {
    published: Published,
}

pub(super) enum StillSourceError {
    Mismatch,
    Limit,
    Cancelled,
}

impl Published {
    /// Transfer one publication to a still worker without copying its fragment.
    /// The worker revalidates the private publication seal before decoding.
    pub fn into_still_source(self) -> PublishedStillSource {
        PublishedStillSource { published: self }
    }
}

impl PublishedStillSource {
    /// The confirmed root and retention as recorded at publication.
    pub const fn pin(&self) -> archive::UnknownTimePin {
        self.published.still_seal.pin
    }
    /// Connection and generation claims recorded with the publication.
    pub const fn claimed_source(&self) -> flv_avc::SourceKey {
        self.published.still_seal.source
    }
    pub(super) fn samples(&self) -> usize {
        self.published.segment.fragment().samples().len()
    }
    /// Return the original publication and all segment source custody.
    pub fn into_publication(self) -> Published {
        self.published
    }

    pub(super) fn checked_media(
        &self,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<Vec<u8>, StillSourceError> {
        let published = &self.published;
        let seal = &published.still_seal;
        let fragment = published.segment.fragment();
        if cancelled() {
            return Err(StillSourceError::Cancelled);
        }
        if published.pin != seal.pin
            || published.receipt.root != seal.pin.root
            || fragment.key() != seal.source
        {
            return Err(StillSourceError::Mismatch);
        }
        let constructor = if seal.inband {
            flv_avc::Muxer::new_inband
        } else {
            flv_avc::Muxer::new
        };
        let muxer = constructor(seal.source, &seal.configuration, seal.media_limits)
            .map_err(|_| StillSourceError::Mismatch)?;
        let initialization = muxer.initialization();
        let plan = evidence::Prepared::new(
            &published.segment,
            &seal.configuration,
            initialization,
            seal.pin.retention,
            seal.evidence_limits,
        )
        .map_err(|_| StillSourceError::Mismatch)?;
        if archive::UnknownTimePin::from_plan(&plan) != Some(seal.pin) {
            return Err(StillSourceError::Mismatch);
        }
        if cancelled() {
            return Err(StillSourceError::Cancelled);
        }
        let bytes = initialization
            .bytes()
            .len()
            .checked_add(fragment.bytes().len())
            .ok_or(StillSourceError::Limit)?;
        if bytes > 128 * 1024 * 1024 {
            return Err(StillSourceError::Limit);
        }
        let mut media = Vec::new();
        media
            .try_reserve_exact(bytes)
            .map_err(|_| StillSourceError::Limit)?;
        media.extend_from_slice(initialization.bytes());
        for chunk in fragment.bytes().chunks(16 * 1024) {
            if cancelled() {
                return Err(StillSourceError::Cancelled);
            }
            media.extend_from_slice(chunk);
        }
        Ok(media)
    }
}

/// All original source and unresolved state returned at shutdown.
#[must_use]
pub struct Retirement {
    /// Original configuration and policy inputs.
    pub inputs: Inputs,
    /// Segment not yet successfully published, if any.
    pub pending: Option<recording::Segment>,
    /// Exact candidate requiring reconciliation, if preparation completed.
    pub pending_pin: Option<archive::UnknownTimePin>,
    /// Next accepted fragment sequence; absent after exhaustion.
    pub next_sequence: Option<u32>,
    /// Previous successfully published media-clock end, not wall time.
    pub last_end_ms: Option<u64>,
}

/// One source-bound video-only owner. It does not authorize storage or retry.
#[must_use = "retain or retire the original configuration and any pending segment"]
pub struct Sink {
    inputs: Inputs,
    video: flv_avc::Muxer,
    pending: Option<recording::Segment>,
    pending_pin: Option<archive::UnknownTimePin>,
    next_sequence: Option<u32>,
    last_end_ms: Option<u64>,
}

impl Sink {
    /// Caller-bound source identity used for segment binding.
    pub fn source_key(&self) -> flv_avc::SourceKey {
        self.inputs.source
    }

    /// Caller-supplied retention decision identity; this is not authority.
    pub fn retention(&self) -> ContentDigest {
        self.inputs.retention
    }

    /// Validate video initialization without doing I/O or consuming a refusal.
    pub fn new(inputs: Inputs) -> Result<Self, ConstructionRefusal> {
        let constructor = if inputs.inband {
            flv_avc::Muxer::new_inband
        } else {
            flv_avc::Muxer::new
        };
        let video = match constructor(inputs.source, &inputs.configuration, inputs.media_limits) {
            Ok(video) => video,
            Err(reason) => return Err(ConstructionRefusal { reason, inputs }),
        };
        Ok(Self {
            inputs,
            video,
            pending: None,
            pending_pin: None,
            next_sequence: Some(1),
            last_end_ms: None,
        })
    }

    /// Whether an original segment or an unresolved candidate is retained.
    pub fn has_pending(&self) -> bool {
        self.pending.is_some() || self.pending_pin.is_some()
    }

    /// Exact candidate requiring reconciliation after a publication attempt.
    pub fn pending_pin(&self) -> Option<archive::UnknownTimePin> {
        self.pending_pin
    }

    /// Bounded preparation input size, including retained source witnesses.
    /// `None` means no segment or an arithmetic overflow.
    pub fn pending_work_bytes(&self) -> Option<u64> {
        let segment = self.pending.as_ref()?;
        let mut bytes = self
            .inputs
            .configuration
            .bytes()
            .len()
            .checked_add(self.video.initialization().bytes().len())?
            .checked_add(segment.fragment().bytes().len())?;
        for record in segment.source().iter().chain(segment.lookahead_copies()) {
            bytes = bytes.checked_add(record.bytes().len())?;
        }
        u64::try_from(bytes).ok()
    }

    /// Admit the next exact source segment without starting publication.
    pub fn offer(&mut self, segment: recording::Segment) -> Result<(), OfferRefusal> {
        let binding = segment.configuration();
        let fragment = segment.fragment();
        let configuration = &self.inputs.configuration;
        let reason = if self.pending.is_some() || self.pending_pin.is_some() {
            Some(OfferError::Busy)
        } else if fragment.key() != self.inputs.source
            || binding.inband != self.inputs.inband
            || binding.source_offset != configuration.offset()
            || binding.source_bytes != configuration.bytes().len()
            || binding.source_digest != ContentDigest::sha256(configuration.bytes())
            || binding.initialization_digest
                != ContentDigest::sha256(self.video.initialization().bytes())
            || fragment.configuration_sources() != *self.video.configuration_sources()
        {
            Some(OfferError::Binding)
        } else if self.next_sequence != Some(fragment.sequence())
            || fragment.samples().first().is_none()
            || fragment
                .samples()
                .last()
                .and_then(|sample| {
                    sample
                        .decode_time_ms
                        .checked_add(u64::from(sample.duration_ms))
                })
                .is_none()
            || self.last_end_ms.is_some_and(|end| {
                fragment.timeline_gap().is_some()
                    || fragment
                        .samples()
                        .first()
                        .is_none_or(|sample| sample.decode_time_ms != end)
            })
        {
            Some(OfferError::Continuity)
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(OfferRefusal { reason, segment });
        }
        self.pending = Some(segment);
        Ok(())
    }

    /// Publish or explicitly retry the same retained candidate. The caller
    /// must keep the same deployment, journal and keeper across reconciliation.
    pub fn flush(
        &mut self,
        deployment: &mut ReferenceDeployment,
        authority: &dyn archive::RetainAuthority,
        limits: archive::Limits,
        work: &mut WorkBudget<'_>,
        cx: &ReplayCx,
        journal: &mut archive::journal::UnknownTimeJournal,
        keeper: &mut archive::journal::UnknownTimeAnchorKeeper,
    ) -> Result<Published, FlushError> {
        let segment = self.pending.as_ref().ok_or(FlushError::Empty)?;
        let last_end_ms = segment
            .fragment()
            .samples()
            .last()
            .and_then(|last| last.decode_time_ms.checked_add(u64::from(last.duration_ms)))
            .ok_or(FlushError::Candidate)?;
        let next_sequence = segment.fragment().sequence().checked_add(1);
        // Duplicate the small source configuration before publication, so a
        // failure cannot hide a completed ledger or anchor operation.
        let still_configuration = self
            .inputs
            .configuration
            .try_duplicate()
            .map_err(|_| FlushError::Preparation(evidence::Error::Limit))?;
        let still_source = segment.fragment().key();
        let plan = evidence::Prepared::new(
            segment,
            &self.inputs.configuration,
            self.video.initialization(),
            self.inputs.retention,
            self.inputs.evidence_limits,
        )
        .map_err(FlushError::Preparation)?;
        let pin = archive::UnknownTimePin::from_plan(&plan).ok_or(FlushError::Candidate)?;
        if self.pending_pin.is_some_and(|prior| prior != pin) {
            return Err(FlushError::Candidate);
        }
        self.pending_pin = Some(pin);
        let receipt = archive::publish_unknown_time_video_anchored(
            &plan, deployment, authority, limits, work, cx, journal, keeper,
        )
        .map_err(FlushError::Publication)?;
        let segment = self.pending.take().ok_or(FlushError::Empty)?;
        self.last_end_ms = Some(last_end_ms);
        self.next_sequence = next_sequence;
        self.pending_pin = None;
        Ok(Published {
            pin,
            receipt,
            segment,
            still_seal: StillSeal {
                pin,
                source: still_source,
                configuration: still_configuration,
                inband: self.inputs.inband,
                media_limits: self.inputs.media_limits,
                evidence_limits: self.inputs.evidence_limits,
            },
        })
    }

    /// Recover the original configuration, pending segment and exact pin.
    pub fn retire(self) -> Retirement {
        Retirement {
            inputs: self.inputs,
            pending: self.pending,
            pending_pin: self.pending_pin,
            next_sequence: self.next_sequence,
            last_end_ms: self.last_end_ms,
        }
    }
}
