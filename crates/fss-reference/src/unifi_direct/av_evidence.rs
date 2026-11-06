#![forbid(unsafe_code)]
//! Source-linked A/V evidence preparation. This is not a durable receipt.
//!
//! The caller must establish that the audio configuration, video epoch,
//! and records belong to the same connection. Source boundaries remain
//! heuristic; identity, capture time, coverage, A/V synchronization, decoding,
//! permission and durable publication are separate obligations.

use std::{collections::BTreeSet, fmt};

use fss_container::flv_av;
use fss_core::{CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest};
use fss_object::ObjectManifest;
use fss_packet::extended_flv::{self, aac, aac_adts, aac_track};

use super::evidence::{self, Prepared};

pub(super) const DOMAIN: &str = "fss.unifi-direct.flv-av-evidence.v1";
pub(super) const KIND: &str = "unifi-direct-flv-av-v1";

/// Whether audio configuration bytes were found in an original FLV record.
/// Neither variant authenticates the camera or proves a shared source epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AudioConfigurationOrigin {
    /// The exact source record is included, with its claimed track epoch.
    InBand,
    /// The caller supplied codec bytes without an original FLV record.
    SuppliedUnverified,
}

#[derive(Clone, Copy)]
enum AudioConfiguration<'a> {
    InBand(&'a aac_track::BoundConfiguration<'a>),
    Supplied(&'a aac::Configuration<'a>),
}
impl<'a> AudioConfiguration<'a> {
    fn configuration(self) -> &'a aac::Configuration<'a> {
        match self {
            Self::InBand(bound) => bound.configuration(),
            Self::Supplied(configuration) => configuration,
        }
    }
    fn record(self) -> Option<&'a fss_packet::extended_flv::stream::SourceRecord> {
        match self {
            Self::InBand(bound) => Some(bound.record()),
            Self::Supplied(_) => None,
        }
    }
    fn origin(self) -> AudioConfigurationOrigin {
        match self {
            Self::InBand(_) => AudioConfigurationOrigin::InBand,
            Self::Supplied(_) => AudioConfigurationOrigin::SuppliedUnverified,
        }
    }
}

/// A payload-free refusal to construct a bounded A/V evidence graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A limit or allocation failed.
    Limit,
    /// The source, initialization or derivative mappings do not agree.
    Mismatch,
    /// Canonical graph encoding failed.
    Encoding,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi A/V evidence preparation refused: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Candidate graph with exact original video and audio records and derivatives.
/// The video candidate remains borrowed, as do the A/V fragment and source record.
pub struct PreparedAv<'a> {
    video: &'a Prepared<'a>,
    audio_configuration: AudioConfiguration<'a>,
    initialization: &'a flv_av::Initialization,
    fragment: &'a flv_av::Fragment<'a>,
    video_manifest: Vec<u8>,
    metadata: Vec<u8>,
    manifest: ObjectManifest,
}
impl fmt::Debug for PreparedAv<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedAv")
            .field("root", &self.manifest.root())
            .finish_non_exhaustive()
    }
}
impl<'a> PreparedAv<'a> {
    /// Prepare only when the audio configuration is bound to an original,
    /// non-provisional preceding record and every copied media body matches.
    /// The caller's connection and epoch claim is not independently verified.
    pub fn new(
        video: &'a Prepared<'a>,
        audio_configuration: &'a aac_track::BoundConfiguration<'a>,
        initialization: &'a flv_av::Initialization,
        fragment: &'a flv_av::Fragment<'a>,
        limits: evidence::Limits,
    ) -> Result<Self, Error> {
        Self::prepare(
            video,
            AudioConfiguration::InBand(audio_configuration),
            initialization,
            fragment,
            limits,
        )
    }

    /// Prepare with explicitly supplied codec bytes whose original source and
    /// connection epoch are unknown. The graph retains the exact supplied
    /// bytes and encodes this uncertainty; it does not claim an in-band record.
    pub fn new_with_unverified_audio_configuration(
        video: &'a Prepared<'a>,
        audio_configuration: &'a aac::Configuration<'a>,
        initialization: &'a flv_av::Initialization,
        fragment: &'a flv_av::Fragment<'a>,
        limits: evidence::Limits,
    ) -> Result<Self, Error> {
        Self::prepare(
            video,
            AudioConfiguration::Supplied(audio_configuration),
            initialization,
            fragment,
            limits,
        )
    }

    fn prepare(
        video: &'a Prepared<'a>,
        audio_configuration: AudioConfiguration<'a>,
        initialization: &'a flv_av::Initialization,
        fragment: &'a flv_av::Fragment<'a>,
        limits: evidence::Limits,
    ) -> Result<Self, Error> {
        let segment = video.segment();
        let record = audio_configuration.record();
        if matches!(audio_configuration, AudioConfiguration::InBand(bound) if bound.provisional())
            || !std::ptr::eq(fragment.video(), segment.fragment())
            || initialization.source_key() != fragment.video().key()
            || initialization.video_configuration_sources()
                != fragment.video().configuration_sources()
            || record.is_some_and(|record| {
                record
                    .offset()
                    .checked_add(record.bytes().len() as u64)
                    .is_none_or(|end| end > segment.source()[0].offset())
            })
            || initialization
                .bytes()
                .get(initialization.audio_configuration_range())
                != Some(audio_configuration.configuration().bytes())
        {
            return Err(Error::Mismatch);
        }
        for (a, b) in [
            (
                initialization.sps_range(),
                video.initialization().sps_range(),
            ),
            (
                initialization.pps_range(),
                video.initialization().pps_range(),
            ),
        ] {
            if initialization.bytes().get(a) != video.initialization().bytes().get(b) {
                return Err(Error::Mismatch);
            }
        }
        let video_manifest = video.manifest().canonical_bytes();
        let total = video
            .payloads()
            .try_fold(0usize, |n, bytes| n.checked_add(bytes.len()))
            .and_then(|n| n.checked_add(video_manifest.len()))
            .and_then(|n| n.checked_add(record.map_or(0, |record| record.bytes().len())))
            .and_then(|n| n.checked_add(audio_configuration.configuration().bytes().len()))
            .and_then(|n| n.checked_add(initialization.bytes().len()))
            .and_then(|n| n.checked_add(fragment.bytes().len()))
            .ok_or(Error::Limit)?;
        if !(1..=256 * 1024 * 1024).contains(&limits.max_bytes)
            || total > limits.max_bytes
            || fragment.audio().is_empty()
            || fragment.audio().len() > limits.max_records
            || !(1..=8192).contains(&limits.max_records)
            || segment
                .source()
                .len()
                .checked_add(segment.lookahead_copies().len())
                .and_then(|n| n.checked_add(usize::from(record.is_some())))
                .is_none_or(|n| n > limits.max_records)
            || !(1..=65_536).contains(&limits.max_nals)
            || fragment.video().nals().len() > limits.max_nals
        {
            return Err(Error::Limit);
        }
        let mut count = 0usize;
        for source in segment.source() {
            if let Some(frame) = aac_adts::source_frame(
                audio_configuration.configuration(),
                source,
                extended_flv::Limits::default(),
                aac::Limits::default(),
            )
            .map_err(|_| Error::Mismatch)?
            {
                let map = fragment.audio().get(count).ok_or(Error::Mismatch)?;
                if frame.provisional()
                    || frame.body_range() != map.source
                    || map.duration_ticks == 0
                    || fragment.bytes().get(map.target.clone()) != Some(frame.body())
                {
                    return Err(Error::Mismatch);
                }
                count = count.checked_add(1).ok_or(Error::Limit)?;
            }
        }
        if count != fragment.audio().len() {
            return Err(Error::Mismatch);
        }
        for nal in fragment.video().nals() {
            let start = nal
                .target
                .start
                .checked_add(fragment.video_target_shift())
                .ok_or(Error::Limit)?;
            let end = nal
                .target
                .end
                .checked_add(fragment.video_target_shift())
                .ok_or(Error::Limit)?;
            if fragment.video().bytes().get(nal.target.clone()) != fragment.bytes().get(start..end)
                || fragment.bytes().get(start..end).is_none()
            {
                return Err(Error::Mismatch);
            }
        }
        let mut e = CanonicalEncoder::new();
        e.text(DOMAIN);
        e.digest(video.retention());
        match video.capture() {
            Some(capture) => {
                e.bool(true);
                e.i128(capture.earliest.0);
                e.i128(capture.latest.0);
            }
            None => e.bool(false),
        }
        e.digest(video.manifest().root());
        match audio_configuration {
            AudioConfiguration::InBand(bound) => {
                e.u8(0);
                e.u64(bound.epoch());
                evidence::encode_record(&mut e, bound.record());
                let source = bound.source();
                e.u64(source.start);
                e.u64(source.end);
            }
            AudioConfiguration::Supplied(_) => e.u8(1),
        }
        e.digest(ContentDigest::sha256(
            audio_configuration.configuration().bytes(),
        ));
        e.digest(ContentDigest::sha256(initialization.bytes()));
        e.u64(initialization.bytes().len() as u64);
        e.digest(ContentDigest::sha256(fragment.bytes()));
        e.u64(fragment.bytes().len() as u64);
        e.u64(fragment.video_target_shift() as u64);
        e.u64(count as u64);
        for map in fragment.audio() {
            e.u64(map.source.start);
            e.u64(map.source.end);
            e.u64(map.target.start as u64);
            e.u64(map.target.end as u64);
            e.u64(map.decode_ticks);
            e.u32(u32::from(map.duration_ticks));
        }
        let metadata = e.finish_checked().map_err(|_| Error::Encoding)?;
        if total
            .checked_add(metadata.len())
            .is_none_or(|n| n > limits.max_bytes)
        {
            return Err(Error::Limit);
        }
        let metadata_digest = ContentDigest::sha256(&metadata);
        let mut children: BTreeSet<_> = video.manifest().children().iter().copied().collect();
        children.insert(video.manifest().root());
        if let Some(record) = record {
            children.insert(ContentDigest::sha256(record.bytes()));
        }
        children.insert(ContentDigest::sha256(
            audio_configuration.configuration().bytes(),
        ));
        children.insert(ContentDigest::sha256(initialization.bytes()));
        children.insert(ContentDigest::sha256(fragment.bytes()));
        children.remove(&metadata_digest);
        let manifest = ObjectManifest::new(KIND, children, Some(metadata_digest))
            .map_err(|_| Error::Encoding)?;
        Ok(Self {
            video,
            audio_configuration,
            initialization,
            fragment,
            video_manifest,
            metadata,
            manifest,
        })
    }
    /// Immutable graph identity, not permission or a durable receipt.
    pub fn manifest(&self) -> &ObjectManifest {
        &self.manifest
    }
    /// Canonical evidence metadata, including audio source-to-derivative mappings.
    pub fn metadata(&self) -> &[u8] {
        &self.metadata
    }
    /// Source class of the AAC configuration; neither class proves its epoch.
    pub fn audio_configuration_origin(&self) -> AudioConfigurationOrigin {
        self.audio_configuration.origin()
    }
    pub(super) fn retention(&self) -> ContentDigest {
        self.video.retention()
    }
    pub(super) fn capture(&self) -> Option<CaptureInterval> {
        self.video.capture()
    }
    pub(super) fn payloads(&self) -> impl Iterator<Item = &[u8]> {
        self.video
            .payloads()
            .chain(
                self.audio_configuration
                    .record()
                    .map(|record| record.bytes()),
            )
            .chain([
                self.audio_configuration.configuration().bytes(),
                self.video_manifest.as_slice(),
                self.initialization.bytes(),
                self.fragment.bytes(),
                self.metadata.as_slice(),
            ])
    }
    /// Visit candidate objects without retaining, authorizing or disclosing them.
    pub fn visit_objects(&self, mut visitor: impl FnMut(ContentDigest, &[u8])) {
        for bytes in self.payloads() {
            visitor(ContentDigest::sha256(bytes), bytes);
        }
    }
}
