#![forbid(unsafe_code)]
//! Parameter-ID-aware AVC/HEVC sample admission. The original bytes remain authoritative;
//! this module indexes their references and picture prefixes, never reconstructs pixels.

use super::reader::Reader;
use super::tables::{Configuration, hevc_nal_kind, nal_kind, nals, sample_entry_configuration};
use super::{AvcSample, DemuxError, DemuxLimits, VideoCodec};
use fss_packet::avc::{self, AvcPps, AvcSliceIdentity, AvcSps, AvcSyntaxLimits};
use fss_packet::hevc::{self, HevcConfiguration, HevcConfigurationLimits, HevcSlicePrefix};
use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::Arc;

const PARAMETER_BYTES: usize = 65_535;
const MAX_NAL_BYTES: usize = 16 * 1024 * 1024;

/// A separately retained original `avc3`/`hev1` sample-entry box. This is the bounded metadata
/// needed to bootstrap a later random-access sample without reading earlier video samples.
pub struct InbandSampleEntry<'a> {
    source: &'a [u8],
    configuration: Configuration,
    limits: DemuxLimits,
    work: [usize; 3],
}
impl std::fmt::Debug for InbandSampleEntry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InbandSampleEntry")
            .field("codec", &self.configuration.codec)
            .field("length_bytes", &self.configuration.length)
            .field("parameter_count", &self.configuration.parameters.len())
            .finish_non_exhaustive()
    }
}

/// A checked random-access configuration borrowing exact bytes from the retained entry and
/// selected sample. These NALs may precede the sample during decode; no bytes are synthesized.
pub struct InbandBootstrap<'a> {
    parameters: Vec<&'a [u8]>,
    configuration: SampleConfiguration,
}
impl std::fmt::Debug for InbandBootstrap<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InbandBootstrap")
            .field("configuration", &self.configuration)
            .finish_non_exhaustive()
    }
}
impl<'a> InbandBootstrap<'a> {
    /// Exact referenced SPS/PPS or VPS/SPS/PPS bytes, in decoder dependency order.
    pub fn parameter_sets(&self) -> &[&'a [u8]] {
        &self.parameters
    }
    /// Prefix metadata and source spans. Here `sample=None` addresses the separately retained
    /// sample-entry bytes, and `sample=Some(0)` addresses the selected sample bytes. Generation
    /// is local to this bootstrap; it does not claim knowledge of earlier media.
    pub const fn configuration(&self) -> &SampleConfiguration {
        &self.configuration
    }
}
impl<'a> InbandSampleEntry<'a> {
    /// Parse exactly one original sample-entry box. No enclosing `moov` or original file is
    /// needed, and the entry type is read from retained bytes rather than trusted caller text.
    pub fn parse(source: &'a [u8], limits: DemuxLimits) -> Result<Self, DemuxError> {
        Self::parse_with_checkpoint(source, limits, &mut || Ok(()))
    }
    /// Same operation with explicit cancellation checkpoints.
    pub fn parse_with_checkpoint(
        source: &'a [u8],
        limits: DemuxLimits,
        check: &mut dyn FnMut() -> Result<(), DemuxError>,
    ) -> Result<Self, DemuxError> {
        limits.validate()?;
        if source.len() > limits.maximum_input_bytes || source.len() > limits.maximum_metadata_bytes
        {
            return Err(DemuxError::Limit);
        }
        let mut r = Reader::new(source, limits, check);
        let entries = r.children(0..source.len(), false)?;
        if entries.len() != 1 || !matches!(&entries[0].kind, b"avc3" | b"hev1") {
            return Err(DemuxError::Unsupported);
        }
        let configuration = sample_entry_configuration(&mut r, &entries[0], true)?;
        let work = [r.boxes, r.entries, r.nals];
        r.checkpoint()?;
        Ok(Self {
            source,
            configuration,
            limits,
            work,
        })
    }
    /// The original sample entry's codec, including no decoder-support claim.
    pub const fn codec(&self) -> VideoCodec {
        self.configuration.codec
    }
    /// Exact original sample NAL-length field width.
    pub const fn nal_length_bytes(&self) -> usize {
        self.configuration.length
    }
    /// Bind a selected sample's IDR/IRAP to its actual parameter closure. A missing required
    /// in-band definition cannot be supplied from an earlier GOP or guessed from dimensions.
    pub fn bootstrap<'s>(&'s self, sample: &'s [u8]) -> Result<InbandBootstrap<'s>, DemuxError> {
        self.bootstrap_with_checkpoint(sample, &mut || Ok(()))
    }
    /// Budgeted/cancellable bootstrap. Metadata and sample syntax visits share the caller's
    /// aggregate NAL/table limits; no original parameter bytes are copied into the result.
    pub fn bootstrap_with_checkpoint<'s>(
        &'s self,
        sample: &'s [u8],
        check: &mut dyn FnMut() -> Result<(), DemuxError>,
    ) -> Result<InbandBootstrap<'s>, DemuxError> {
        if self
            .source
            .len()
            .checked_add(sample.len())
            .is_none_or(|bytes| bytes > self.limits.maximum_input_bytes)
        {
            return Err(DemuxError::Limit);
        }
        let mut state = State::new(self.configuration.codec, self.configuration.complete);
        let mut r = Reader::new(sample, self.limits, check);
        [r.boxes, r.entries, r.nals] = self.work;
        for parameter in &self.configuration.parameters {
            r.checkpoint()?;
            state.parameter(&self.source[parameter.clone()], parameter.clone(), None)?;
        }
        let input = AvcSample {
            index: 0,
            source: 0..sample.len(),
            decode_time: 0,
            duration: 1,
            composition_offset: 0,
            sync_sample: true,
            contains_idr: false,
        };
        let configuration =
            sample_configuration(&mut r, &mut state, self.configuration.length, &input)?;
        if !configuration.random_access {
            return Err(DemuxError::RandomAccessRequired);
        }
        r.entries(configuration.parameters.len())?;
        let parameters = configuration
            .parameters
            .iter()
            .map(|origin| {
                (if origin.sample.is_none() {
                    self.source
                } else {
                    sample
                })
                .get(origin.source.clone())
                .ok_or(DemuxError::Nal)
            })
            .collect::<Result<Vec<_>, _>>()?;
        r.checkpoint()?;
        Ok(InbandBootstrap {
            parameters,
            configuration,
        })
    }

    /// Own the bounded original parameter definitions for a contiguous selected range.
    /// Subsequent samples may reference other IDs from this entry without repeating them.
    /// `first_sample` is the original decode-order index used in returned source spans.
    pub fn stream(&self, first_sample: usize) -> Result<InbandConfiguration, DemuxError> {
        self.stream_with_checkpoint(first_sample, &mut || Ok(()))
    }

    /// Same operation with cancellation during parameter admission.
    pub fn stream_with_checkpoint(
        &self,
        first_sample: usize,
        check: &mut dyn FnMut() -> Result<(), DemuxError>,
    ) -> Result<InbandConfiguration, DemuxError> {
        if first_sample >= super::MAX_MP4_SAMPLES {
            return Err(DemuxError::Limit);
        }
        let mut state = State::new(self.configuration.codec, self.configuration.complete);
        for source in &self.configuration.parameters {
            check()?;
            state.parameter(&self.source[source.clone()], source.clone(), None)?;
        }
        check()?;
        Ok(InbandConfiguration {
            state,
            length: self.configuration.length,
            limits: self.limits,
            work: self.work,
            input_bytes: self.source.len(),
            next: first_sample,
            count: 0,
            revisions: None,
            generation: 0,
            failure: None,
        })
    }
}

/// Bounded parameter state for retained sequential samples. Raw definitions are exact copies
/// of source NALs; unchanged retransmissions share their allocation. Only referenced tuples
/// are supplied to the decoder, so stale unrelated entry definitions cannot widen its limits.
pub struct InbandConfiguration {
    state: State,
    length: usize,
    limits: DemuxLimits,
    work: [usize; 3],
    input_bytes: usize,
    next: usize,
    count: usize,
    revisions: Option<Vec<u32>>,
    generation: u32,
    failure: Option<DemuxError>,
}
impl std::fmt::Debug for InbandConfiguration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InbandConfiguration")
            .field("codec", &self.state.codec)
            .field("next_sample", &self.next)
            .field("generation", &self.generation)
            .field("failed", &self.failure.is_some())
            .finish_non_exhaustive()
    }
}

/// One validated sample's referenced configuration and any exact tuple needed before its
/// original NALs. Keeping this result alive keeps its bounded prefix bytes alive.
pub struct InbandSampleParameters {
    prefix: Vec<Arc<[u8]>>,
    configuration: SampleConfiguration,
}
impl std::fmt::Debug for InbandSampleParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InbandSampleParameters")
            .field("configuration", &self.configuration)
            .field("prefix_nals", &self.prefix.len())
            .finish_non_exhaustive()
    }
}
impl InbandSampleParameters {
    /// Dependency-ordered original parameter bytes to feed before this sample. Empty when
    /// the previously supplied tuple is still current; raw sample NALs must always follow.
    pub fn decoder_prefix(&self) -> impl ExactSizeIterator<Item = &[u8]> {
        self.prefix.iter().map(|bytes| bytes.as_ref())
    }
    /// Actual referenced tuple; ranges with `sample=Some(index)` address that original
    /// sample's local payload, and `None` addresses the retained sample entry.
    pub const fn configuration(&self) -> &SampleConfiguration {
        &self.configuration
    }
}
impl InbandConfiguration {
    /// Admit the next original sample. The first must be self-contained random access.
    /// Refusal is terminal: partial parameter updates cannot be reused on a later call.
    pub fn sample(&mut self, bytes: &[u8]) -> Result<InbandSampleParameters, DemuxError> {
        self.sample_with_checkpoint(bytes, &mut || Ok(()))
    }

    /// Same operation with cumulative entry/NAL bounds and explicit cancellation.
    pub fn sample_with_checkpoint(
        &mut self,
        bytes: &[u8],
        check: &mut dyn FnMut() -> Result<(), DemuxError>,
    ) -> Result<InbandSampleParameters, DemuxError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        let result = self.sample_inner(bytes, check);
        if let Err(error) = &result {
            self.failure = Some(*error);
        }
        result
    }

    fn sample_inner(
        &mut self,
        bytes: &[u8],
        check: &mut dyn FnMut() -> Result<(), DemuxError>,
    ) -> Result<InbandSampleParameters, DemuxError> {
        let input_bytes = self
            .input_bytes
            .checked_add(bytes.len())
            .ok_or(DemuxError::Limit)?;
        if input_bytes > self.limits.maximum_input_bytes
            || self.count == self.limits.maximum_samples
            || self.next >= super::MAX_MP4_SAMPLES
        {
            return Err(DemuxError::Limit);
        }
        let mut r = Reader::new(bytes, self.limits, check);
        [r.boxes, r.entries, r.nals] = self.work;
        r.checkpoint()?;
        let input = AvcSample {
            index: self.next,
            source: 0..bytes.len(),
            decode_time: 0,
            duration: 1,
            composition_offset: 0,
            sync_sample: self.count == 0,
            contains_idr: false,
        };
        let mut configuration = sample_configuration(&mut r, &mut self.state, self.length, &input)?;
        if self.count == 0 && !configuration.random_access {
            return Err(DemuxError::RandomAccessRequired);
        }
        r.entries(configuration.parameters.len())?;
        let mut revisions = Vec::with_capacity(3);
        let mut prefix = Vec::with_capacity(3);
        for source in &configuration.parameters {
            let parameter = self
                .state
                .parameters
                .get(&(source.nal_type, source.id))
                .ok_or(DemuxError::Nal)?;
            revisions.push(parameter.revision);
            prefix.push(Arc::clone(&parameter.bytes));
        }
        if let Some(previous) = &self.revisions {
            if *previous == revisions {
                prefix.clear();
            } else {
                self.generation = self.generation.checked_add(1).ok_or(DemuxError::Limit)?;
            }
        }
        configuration.generation = self.generation;
        r.checkpoint()?;
        self.work = [r.boxes, r.entries, r.nals];
        self.input_bytes = input_bytes;
        self.revisions = Some(revisions);
        self.count += 1;
        self.next += 1;
        Ok(InbandSampleParameters {
            prefix,
            configuration,
        })
    }
}

/// One exact parameter NAL and the original sample, if any, that carried it. Bitstream IDs
/// are local names: replacing the bytes under an ID changes the configuration generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParameterSetSource {
    /// Original NAL type (AVC 7/8 or HEVC 32/33/34).
    pub nal_type: u8,
    /// SPS/PPS/VPS bitstream-local identifier.
    pub id: u16,
    /// `None` for the sample entry, otherwise the original decode-order sample index.
    pub sample: Option<usize>,
    /// Complete original NAL, excluding the length field and including its NAL header.
    pub source: Range<usize>,
}

/// The parameter closure referenced by one checked primary-picture prefix. This is an index,
/// not a decoded-picture certificate: entropy data and reference availability remain opaque.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SampleConfiguration {
    parameters: Vec<ParameterSetSource>,
    generation: u32,
    coded: [u32; 2],
    display: [u32; 2],
    bit_depth: u8,
    random_access: bool,
}
impl SampleConfiguration {
    /// Original parameter NALs in dependency order: SPS/PPS or VPS/SPS/PPS.
    pub fn parameter_sets(&self) -> &[ParameterSetSource] {
        &self.parameters
    }
    /// Zero-based generation, advancing when referenced parameter bytes change. Repeated
    /// identical parameter NALs at a new source location do not invent a configuration change.
    pub const fn generation(&self) -> u32 {
        self.generation
    }
    /// Coded dimensions from the bounded SPS metadata parser, before cropping.
    pub const fn coded_dimensions(&self) -> [u32; 2] {
        self.coded
    }
    /// SPS display dimensions; the container matrix and edit list are not applied.
    pub const fn display_dimensions(&self) -> [u32; 2] {
        self.display
    }
    /// Equal component bit depth admitted by the metadata parser, not decoder availability.
    pub const fn bit_depth(&self) -> u8 {
        self.bit_depth
    }
    /// Observed IDR/IRAP prefix with all referenced parameter bytes available from the sample
    /// entry or this sample. The container sync flag is checked separately during extraction.
    pub const fn is_random_access(&self) -> bool {
        self.random_access
    }
}

#[derive(Clone)]
struct Parameter {
    origin: ParameterSetSource,
    parent: Option<u16>,
    bytes: Arc<[u8]>,
    revision: u32,
}
struct AvcCache {
    revisions: Vec<u32>,
    sps: AvcSps,
    pps: AvcPps,
}
struct HevcCache {
    revisions: Vec<u32>,
    configuration: HevcConfiguration,
}
struct State {
    codec: VideoCodec,
    parameters: BTreeMap<(u8, u16), Parameter>,
    initial: BTreeMap<(u8, u16), Parameter>,
    complete: [bool; 3],
    next_revision: u32,
    random_access_start: Option<usize>,
    // Caches have at most one entry per bounded PPS ID. Replacing an SPS invalidates the
    // dependent cache by exact source identity; the old parsed allocation is then dropped.
    avc: BTreeMap<u16, AvcCache>,
    hevc: BTreeMap<u16, HevcCache>,
}

fn avc_error(error: avc::AvcError) -> DemuxError {
    match error {
        avc::AvcError::Limit | avc::AvcError::Allocation => DemuxError::Limit,
        avc::AvcError::UnsupportedProfile
        | avc::AvcError::UnsupportedSampleFormat
        | avc::AvcError::UnsupportedSliceGroups
        | avc::AvcError::UnsupportedPicture => DemuxError::Unsupported,
        _ => DemuxError::Nal,
    }
}
fn hevc_error(error: hevc::HevcConfigurationError) -> DemuxError {
    match error {
        hevc::HevcConfigurationError::Limit | hevc::HevcConfigurationError::Allocation => {
            DemuxError::Limit
        }
        hevc::HevcConfigurationError::Unsupported => DemuxError::Unsupported,
        _ => DemuxError::Nal,
    }
}
impl State {
    fn new(codec: VideoCodec, complete: [bool; 3]) -> Self {
        Self {
            codec,
            parameters: BTreeMap::new(),
            initial: BTreeMap::new(),
            complete,
            next_revision: 0,
            random_access_start: None,
            avc: BTreeMap::new(),
            hevc: BTreeMap::new(),
        }
    }
    fn parameter(
        &mut self,
        bytes: &[u8],
        source: Range<usize>,
        sample: Option<usize>,
    ) -> Result<(), DemuxError> {
        let (kind, id, parent) = parameter_ids(self.codec, bytes)?;
        if sample.is_some()
            && self.codec == VideoCodec::Hevc
            && self.complete[usize::from(kind - 32)]
        {
            return Err(DemuxError::Nal);
        }
        let (revision, owned) = if let Some(previous) = self
            .parameters
            .get(&(kind, id))
            .filter(|p| p.bytes.as_ref() == bytes)
        {
            (previous.revision, Arc::clone(&previous.bytes))
        } else {
            self.next_revision = self.next_revision.checked_add(1).ok_or(DemuxError::Limit)?;
            let mut owned = Vec::new();
            owned
                .try_reserve_exact(bytes.len())
                .map_err(|_| DemuxError::Limit)?;
            owned.extend_from_slice(bytes);
            (self.next_revision, Arc::<[u8]>::from(owned))
        };
        let parameter = Parameter {
            origin: ParameterSetSource {
                nal_type: kind,
                id,
                sample,
                source,
            },
            parent,
            bytes: owned,
            revision,
        };
        if sample.is_none() {
            if self
                .initial
                .get(&(kind, id))
                .is_some_and(|old| old.bytes.as_ref() != bytes)
            {
                return Err(DemuxError::Nal);
            }
            self.initial.insert((kind, id), parameter.clone());
        }
        self.parameters.insert((kind, id), parameter);
        Ok(())
    }
    fn closure(&self, pps_id: u16) -> Result<Vec<Parameter>, DemuxError> {
        let (pps_kind, sps_kind) = if self.codec == VideoCodec::Avc {
            (8, 7)
        } else {
            (34, 33)
        };
        let pps = self
            .parameters
            .get(&(pps_kind, pps_id))
            .ok_or(DemuxError::Nal)?;
        let sps = self
            .parameters
            .get(&(sps_kind, pps.parent.ok_or(DemuxError::Nal)?))
            .ok_or(DemuxError::Nal)?;
        let mut parameters = Vec::with_capacity(3);
        if self.codec == VideoCodec::Hevc {
            let vps = self
                .parameters
                .get(&(32, sps.parent.ok_or(DemuxError::Nal)?))
                .ok_or(DemuxError::Nal)?;
            parameters.push(vps.clone());
        }
        parameters.push(sps.clone());
        parameters.push(pps.clone());
        Ok(parameters)
    }
    fn avc_slice(
        &mut self,
        bytes: &[u8],
    ) -> Result<(AvcSliceIdentity, SampleConfiguration), DemuxError> {
        let mut bits = PrefixBits::new(bytes.get(1..).ok_or(DemuxError::Nal)?);
        bits.ue(1_048_575)?;
        bits.ue(9)?;
        let id = bits.ue(255)? as u16;
        let parameters = self.closure(id)?;
        let sources: Vec<_> = parameters.iter().map(|p| p.origin.clone()).collect();
        let revisions: Vec<_> = parameters.iter().map(|p| p.revision).collect();
        if self
            .avc
            .get(&id)
            .is_none_or(|cached| cached.revisions != revisions)
        {
            let limits = AvcSyntaxLimits::default();
            let sps = avc::parse_sps(&parameters[0].bytes, limits).map_err(avc_error)?;
            let pps = avc::parse_pps(&parameters[1].bytes, &sps, limits).map_err(avc_error)?;
            self.avc.insert(
                id,
                AvcCache {
                    revisions,
                    sps,
                    pps,
                },
            );
        }
        let cached = self.avc.get(&id).ok_or(DemuxError::Nal)?;
        let identity =
            avc::parse_slice_identity(bytes, &cached.sps, &cached.pps, AvcSyntaxLimits::default())
                .map_err(avc_error)?;
        let (width, height) = cached.sps.coded_dimensions();
        let (display_width, display_height) = cached.sps.display_dimensions();
        Ok((
            identity,
            SampleConfiguration {
                parameters: sources,
                generation: 0,
                coded: [width, height],
                display: [display_width, display_height],
                bit_depth: 8,
                random_access: identity.idr_pic_id().is_some(),
            },
        ))
    }
    fn hevc_slice(
        &mut self,
        bytes: &[u8],
    ) -> Result<(HevcSlicePrefix, SampleConfiguration), DemuxError> {
        let prefix =
            hevc::parse_slice_prefix(bytes, MAX_NAL_BYTES).map_err(|error| match error {
                hevc::HevcPrefixError::Limit => DemuxError::Limit,
                _ => DemuxError::Nal,
            })?;
        let id = u16::from(prefix.pps_id);
        let parameters = self.closure(id)?;
        let sources: Vec<_> = parameters.iter().map(|p| p.origin.clone()).collect();
        let revisions: Vec<_> = parameters.iter().map(|p| p.revision).collect();
        if self
            .hevc
            .get(&id)
            .is_none_or(|cached| cached.revisions != revisions)
        {
            let configuration = HevcConfiguration::parse(
                &parameters[0].bytes,
                &parameters[1].bytes,
                &parameters[2].bytes,
                HevcConfigurationLimits::default(),
            )
            .map_err(hevc_error)?;
            self.hevc.insert(
                id,
                HevcCache {
                    revisions,
                    configuration,
                },
            );
        }
        let configuration = &self.hevc.get(&id).ok_or(DemuxError::Nal)?.configuration;
        let (width, height) = configuration.coded_dimensions();
        let (display_width, display_height) = configuration.display_dimensions();
        Ok((
            prefix,
            SampleConfiguration {
                parameters: sources,
                generation: 0,
                coded: [width, height],
                display: [display_width, display_height],
                bit_depth: configuration.bit_depth(),
                random_access: (16..=21).contains(&prefix.nal_type),
            },
        ))
    }
    fn random_access(
        &mut self,
        configuration: &mut SampleConfiguration,
        sample: usize,
    ) -> Result<(), DemuxError> {
        if configuration.random_access {
            self.random_access_start = Some(sample);
        }
        let first = self.random_access_start.unwrap_or(0);
        for origin in &mut configuration.parameters {
            if origin.sample.is_none() || origin.sample.is_some_and(|index| index >= first) {
                continue;
            }
            let key = (origin.nal_type, origin.id);
            let active = self.parameters.get(&key).ok_or(DemuxError::Nal)?;
            let initial = self
                .initial
                .get(&key)
                .filter(|p| p.bytes == active.bytes)
                .ok_or(DemuxError::RandomAccessRequired)?;
            // A byte-identical retransmission before the latest RAP does not make any picture
            // of its selected range depend on that earlier media sample: the entry suffices.
            *origin = initial.origin.clone();
        }
        Ok(())
    }
}

pub(super) fn index(
    r: &mut Reader<'_, '_>,
    codec: VideoCodec,
    length: usize,
    initial: &[Range<usize>],
    samples: &[AvcSample],
    complete: [bool; 3],
) -> Result<Vec<SampleConfiguration>, DemuxError> {
    let source = r.bytes;
    let mut state = State::new(codec, complete);
    for parameter in initial {
        r.checkpoint()?;
        state.parameter(&source[parameter.clone()], parameter.clone(), None)?;
    }
    let mut configurations: Vec<SampleConfiguration> = Vec::new();
    configurations
        .try_reserve_exact(samples.len())
        .map_err(|_| DemuxError::Limit)?;
    let mut generation = 0_u32;
    let mut previous_revisions: Option<Vec<u32>> = None;
    for sample in samples {
        r.checkpoint()?;
        let mut configuration = sample_configuration(r, &mut state, length, sample)?;
        let revisions = configuration
            .parameters
            .iter()
            .map(|p| {
                state
                    .parameters
                    .get(&(p.nal_type, p.id))
                    .map(|p| p.revision)
                    .ok_or(DemuxError::Nal)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if previous_revisions
            .as_ref()
            .is_some_and(|previous| *previous != revisions)
        {
            generation = generation.checked_add(1).ok_or(DemuxError::Limit)?;
        }
        previous_revisions = Some(revisions);
        configuration.generation = generation;
        r.entries(configuration.parameters.len())?;
        configurations.push(configuration);
    }
    Ok(configurations)
}

fn sample_configuration(
    r: &mut Reader<'_, '_>,
    state: &mut State,
    length: usize,
    sample: &AvcSample,
) -> Result<SampleConfiguration, DemuxError> {
    let source = r.bytes;
    let mut configuration = None;
    let mut avc_identity = None;
    let mut last_mb = None;
    let mut hevc_prefix: Option<HevcSlicePrefix> = None;
    nals(source, sample.source.clone(), length, &mut |range| {
        r.checkpoint()?;
        r.nals = r
            .nals
            .checked_add(1)
            .filter(|n| *n <= r.limits.maximum_nals)
            .ok_or(DemuxError::Limit)?;
        let bytes = &source[range.clone()];
        if bytes.len() > MAX_NAL_BYTES {
            return Err(DemuxError::Limit);
        }
        let kind = if state.codec == VideoCodec::Avc {
            nal_kind(bytes)?
        } else {
            hevc_nal_kind(bytes)?
        };
        let parameter = match state.codec {
            VideoCodec::Avc => matches!(kind, 7 | 8 | 13),
            VideoCodec::Hevc => matches!(kind, 32..=34),
        };
        if parameter {
            if configuration.is_some() {
                return Err(DemuxError::Nal);
            }
            return state.parameter(bytes, range, Some(sample.index));
        }
        match state.codec {
            VideoCodec::Avc if matches!(kind, 1 | 5) => {
                let (identity, current) = state.avc_slice(bytes)?;
                if avc_identity.is_some_and(|previous| identity.starts_new_picture(previous)) {
                    return Err(DemuxError::Nal);
                }
                if identity.redundant_pic_cnt() == 0 {
                    let first_mb = identity.first_mb_in_slice();
                    if last_mb.map_or(first_mb != 0, |previous| first_mb <= previous) {
                        return Err(DemuxError::Nal);
                    }
                    last_mb = Some(first_mb);
                    avc_identity = Some(identity);
                    configuration = Some(current);
                } else if avc_identity.is_none() {
                    return Err(DemuxError::Nal);
                }
            }
            VideoCodec::Hevc if matches!(kind, 0..=9 | 16..=21) => {
                let (prefix, current) = state.hevc_slice(bytes)?;
                if let Some(previous) = hevc_prefix {
                    if prefix.first_slice
                        || prefix.pps_id != previous.pps_id
                        || prefix.nal_type != previous.nal_type
                        || prefix.temporal_id_plus_one != previous.temporal_id_plus_one
                        || prefix.no_output_of_prior_pics != previous.no_output_of_prior_pics
                    {
                        return Err(DemuxError::Nal);
                    }
                } else if !prefix.first_slice {
                    return Err(DemuxError::Nal);
                }
                hevc_prefix = Some(prefix);
                configuration = Some(current);
            }
            _ => {}
        }
        Ok(())
    })?;
    let mut configuration = configuration.ok_or(DemuxError::Nal)?;
    state.random_access(&mut configuration, sample.index)?;
    Ok(configuration)
}

/// Parameter-prefix identity only. Full AVC parameter syntax and bounded HEVC configuration
/// metadata are screened when the tuple is referenced by a picture, using fss-packet.
fn parameter_ids(codec: VideoCodec, bytes: &[u8]) -> Result<(u8, u16, Option<u16>), DemuxError> {
    if bytes.len() > PARAMETER_BYTES {
        return Err(DemuxError::Limit);
    }
    let header = if codec == VideoCodec::Avc { 1 } else { 2 };
    let kind = if codec == VideoCodec::Avc {
        nal_kind(bytes)?
    } else {
        hevc_nal_kind(bytes)?
    };
    let mut bits = PrefixBits::new(bytes.get(header..).ok_or(DemuxError::Nal)?);
    let (id, parent) = match (codec, kind) {
        (VideoCodec::Avc, 7) => {
            bits.uint(24)?;
            (bits.ue(31)?, None)
        }
        (VideoCodec::Avc, 8) => (bits.ue(255)?, Some(bits.ue(31)?)),
        (VideoCodec::Hevc, 32) => (bits.uint(4)?, None),
        (VideoCodec::Hevc, 33) => {
            let vps = bits.uint(4)?;
            let layers = bits.uint(3)? as usize;
            if layers > 6 {
                return Err(DemuxError::Nal);
            }
            bits.uint(1)?;
            bits.skip(96)?;
            let mut flags = [(false, false); 6];
            for flag in &mut flags[..layers] {
                *flag = (bits.uint(1)? != 0, bits.uint(1)? != 0);
            }
            if layers > 0 {
                bits.skip((8 - layers) * 2)?;
            }
            for (profile, level) in flags.into_iter().take(layers) {
                if profile {
                    bits.skip(88)?;
                }
                if level {
                    bits.skip(8)?;
                }
            }
            (bits.ue(15)?, Some(vps))
        }
        (VideoCodec::Hevc, 34) => (bits.ue(63)?, Some(bits.ue(15)?)),
        _ => return Err(DemuxError::Unsupported),
    };
    Ok((kind, id as u16, parent.map(|n| n as u16)))
}

/// Nonallocating EBSP prefix reader. Only at most 1024 bits are consumed to obtain IDs; full
/// source bytes are retained, never rewritten into a synthetic parameter NAL.
struct PrefixBits<'a> {
    source: &'a [u8],
    position: usize,
    zeros: u8,
    byte: u8,
    remaining: u8,
    bits: usize,
}
impl<'a> PrefixBits<'a> {
    fn new(source: &'a [u8]) -> Self {
        Self {
            source,
            position: 0,
            zeros: 0,
            byte: 0,
            remaining: 0,
            bits: 0,
        }
    }
    fn bit(&mut self) -> Result<u32, DemuxError> {
        if self.bits == 1024 {
            return Err(DemuxError::Limit);
        }
        if self.remaining == 0 {
            let mut byte = *self.source.get(self.position).ok_or(DemuxError::Nal)?;
            self.position += 1;
            if self.zeros == 2 {
                if byte == 3 {
                    byte = *self
                        .source
                        .get(self.position)
                        .filter(|b| **b <= 3)
                        .ok_or(DemuxError::Nal)?;
                    self.position += 1;
                    self.zeros = 0;
                } else if byte < 3 {
                    return Err(DemuxError::Nal);
                }
            }
            self.zeros = if byte == 0 { self.zeros + 1 } else { 0 };
            self.byte = byte;
            self.remaining = 8;
        }
        self.bits += 1;
        self.remaining -= 1;
        Ok(u32::from((self.byte >> self.remaining) & 1))
    }
    fn uint(&mut self, bits: usize) -> Result<u32, DemuxError> {
        let mut value = 0;
        for _ in 0..bits {
            value = (value << 1) | self.bit()?;
        }
        Ok(value)
    }
    fn skip(&mut self, bits: usize) -> Result<(), DemuxError> {
        for _ in 0..bits {
            self.bit()?;
        }
        Ok(())
    }
    fn ue(&mut self, maximum: u32) -> Result<u32, DemuxError> {
        let mut zeros = 0;
        while self.bit()? == 0 {
            zeros += 1;
            if zeros > 20 {
                return Err(DemuxError::Nal);
            }
        }
        let value = (1_u32 << zeros) - 1 + self.uint(zeros)?;
        if value > maximum {
            Err(DemuxError::Nal)
        } else {
            Ok(value)
        }
    }
}
