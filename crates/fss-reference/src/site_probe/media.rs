#![forbid(unsafe_code)]
//! Native codec reconstruction and picture witnesses; never marker-only counting.

use fss_core::ContentDigest;
use fss_packet::avc::{
    AvcAssembler, AvcAssemblyError, AvcAssemblyLimits, AvcAssemblyOutput, AvcAssemblyPoll,
    AvcAssemblyStep, AvcBoundary, AvcPictureGroup, AvcPps, AvcRetirementReason, AvcSps,
    AvcSyntaxLimits, parse_pps, parse_sps,
};
use fss_packet::hevc::{
    HevcAssembler, HevcAssemblyLimits, HevcAssemblyOutput, HevcAssemblyStep, HevcBoundary,
    HevcConfiguration, HevcConfigurationLimits, HevcPictureGroup, HevcRetirementReason,
};
use fss_packet::{
    H264Depacketizer, H264Limits, H264Mode, H264Status, H265Depacketizer, H265Limits, H265Status,
    RtcpMode, RtpPacket, StreamKey,
};

use crate::rtsp::client::observed::ObservedVideoDescription;

use super::{Cadence, SiteProbeError};

pub(super) enum PreparedMedia {
    Avc {
        sps: AvcSps,
        pps: AvcPps,
        mode: H264Mode,
        payload_type: u8,
        reduced_rtcp: bool,
    },
    Hevc {
        configuration: HevcConfiguration,
        payload_type: u8,
        reduced_rtcp: bool,
    },
}

impl PreparedMedia {
    pub(super) fn new(description: ObservedVideoDescription) -> Result<Self, SiteProbeError> {
        match description {
            ObservedVideoDescription::Avc(media) => {
                if !(96..=127).contains(&media.payload_type()) {
                    return Err(SiteProbeError::Selection);
                }
                let (sps, pps) = media.parameter_sets();
                let syntax = AvcSyntaxLimits::default();
                let sps = parse_sps(sps, syntax).map_err(|_| SiteProbeError::Codec)?;
                // The packet syntax owner can identify fields and MBAFF pictures,
                // but native footage decode/remux admits frame-only AVC. Counting
                // field timestamps as frames would mint the wrong capture cadence.
                if !sps.frame_mbs_only() {
                    return Err(SiteProbeError::Codec);
                }
                let pps = parse_pps(pps, &sps, syntax).map_err(|_| SiteProbeError::Codec)?;
                let mode = match media.packetization_mode() {
                    0 => H264Mode::SingleNal,
                    1 => H264Mode::NonInterleaved,
                    _ => return Err(SiteProbeError::Codec),
                };
                Ok(Self::Avc {
                    sps,
                    pps,
                    mode,
                    payload_type: media.payload_type(),
                    reduced_rtcp: media.reduced_rtcp(),
                })
            }
            ObservedVideoDescription::Hevc(media) => {
                if !(96..=127).contains(&media.payload_type())
                    || media.vps().len() != 1
                    || media.sps().len() != 1
                    || media.pps().len() != 1
                {
                    return Err(SiteProbeError::Codec);
                }
                let configuration = HevcConfiguration::parse(
                    &media.vps()[0],
                    &media.sps()[0],
                    &media.pps()[0],
                    HevcConfigurationLimits::default(),
                )
                .map_err(|_| SiteProbeError::Codec)?;
                // Native footage capture admits eight-bit HEVC; an offline receipt
                // must not hide a sample-format requirement from that downstream plan.
                if configuration.bit_depth() != 8 {
                    return Err(SiteProbeError::Codec);
                }
                // The packet configuration owner deliberately stops before VUI.
                // The existing full SPS parser rejects field_seq_flag and other
                // unsupported sequence syntax; field timestamps must never be
                // relabeled frame cadence. This reads metadata, not pixel data.
                let (_, escaped) = fss_codec_h265::nal::NalHeader::split(configuration.sps())
                    .map_err(|_| SiteProbeError::Codec)?;
                let rbsp = fss_codec_h265::nal::rbsp_from_ebsp(escaped, 16_384)
                    .map_err(|_| SiteProbeError::Codec)?;
                let _sequence_parameters =
                    fss_codec_h265::params::parse_sps(&rbsp).map_err(|_| SiteProbeError::Codec)?;
                Ok(Self::Hevc {
                    configuration,
                    payload_type: media.payload_type(),
                    reduced_rtcp: media.reduced_rtcp(),
                })
            }
        }
    }

    pub(super) fn payload_type(&self) -> u8 {
        match self {
            Self::Avc { payload_type, .. } | Self::Hevc { payload_type, .. } => *payload_type,
        }
    }

    pub(super) fn rtcp_mode(&self) -> RtcpMode {
        let reduced = match self {
            Self::Avc { reduced_rtcp, .. } | Self::Hevc { reduced_rtcp, .. } => *reduced_rtcp,
        };
        if reduced {
            RtcpMode::ReducedSize
        } else {
            RtcpMode::Compound
        }
    }

    pub(super) fn parameter_set_digests(&self) -> Vec<ContentDigest> {
        match self {
            Self::Avc { sps, pps, .. } => [sps.nal_bytes(), pps.nal_bytes()]
                .into_iter()
                .map(ContentDigest::sha256)
                .collect(),
            Self::Hevc { configuration, .. } => [
                configuration.vps(),
                configuration.sps(),
                configuration.pps(),
            ]
            .into_iter()
            .map(ContentDigest::sha256)
            .collect(),
        }
    }

    pub(super) fn start(self, key: StreamKey) -> Result<MediaObserver, SiteProbeError> {
        match self {
            Self::Avc {
                sps,
                pps,
                mode,
                payload_type,
                ..
            } => {
                let depacketizer =
                    H264Depacketizer::new(key, payload_type, mode, H264Limits::default())
                        .map_err(|_| SiteProbeError::Codec)?;
                let assembler = AvcAssembler::new(
                    key,
                    sps,
                    pps,
                    AvcSyntaxLimits::default(),
                    AvcAssemblyLimits::default(),
                )
                .map_err(|_| SiteProbeError::Codec)?;
                Ok(MediaObserver::Avc(Box::new(AvcObserver {
                    key,
                    depacketizer,
                    assembler,
                })))
            }
            Self::Hevc {
                configuration,
                payload_type,
                ..
            } => {
                let depacketizer =
                    H265Depacketizer::new(key, payload_type, 0, H265Limits::default())
                        .map_err(|_| SiteProbeError::Codec)?;
                let assembler = HevcAssembler::new(key, HevcAssemblyLimits::default())
                    .map_err(|_| SiteProbeError::Codec)?;
                Ok(MediaObserver::Hevc(Box::new(HevcObserver {
                    key,
                    depacketizer,
                    assembler,
                    configuration,
                })))
            }
        }
    }
}

pub(super) enum MediaObserver {
    Avc(Box<AvcObserver>),
    Hevc(Box<HevcObserver>),
}

impl MediaObserver {
    pub(super) fn push(
        &mut self,
        sequence: u64,
        packet: RtpPacket<'_>,
        step: u64,
        cadence: &mut Cadence,
    ) -> Result<(), SiteProbeError> {
        match self {
            Self::Avc(observer) => observer.push(sequence, packet, step, cadence),
            Self::Hevc(observer) => observer.push(sequence, packet, step, cadence),
        }
    }

    pub(super) fn finish(
        &mut self,
        step: u64,
        cadence: &mut Cadence,
    ) -> Result<(), SiteProbeError> {
        match self {
            Self::Avc(observer) => observer.finish(step, cadence),
            Self::Hevc(observer) => observer.finish(step, cadence),
        }
    }
}

pub(super) struct AvcObserver {
    key: StreamKey,
    depacketizer: H264Depacketizer,
    assembler: AvcAssembler,
}

impl AvcObserver {
    fn push(
        &mut self,
        sequence: u64,
        packet: RtpPacket<'_>,
        step: u64,
        cadence: &mut Cadence,
    ) -> Result<(), SiteProbeError> {
        let output = self
            .depacketizer
            .push(self.key, sequence, packet, step)
            .map_err(|_| SiteProbeError::Codec)?;
        if output.gap_before
            || output.discarded.is_some()
            || output.status == H264Status::IgnoredNonIncreasing
        {
            return Err(SiteProbeError::Sequence);
        }
        for nal in output.nals {
            match self.assembler.push(nal, step) {
                AvcAssemblyStep::Accepted(output) => avc_output(output, cadence)?,
                AvcAssemblyStep::Refused(refusal) => {
                    return Err(
                        if refusal.reason == AvcAssemblyError::ConfigurationChanged {
                            SiteProbeError::ParameterChange
                        } else {
                            SiteProbeError::Codec
                        },
                    );
                }
            }
            loop {
                match self
                    .assembler
                    .poll(step)
                    .map_err(|_| SiteProbeError::Codec)?
                {
                    AvcAssemblyPoll::Picture(picture) => avc_picture(&picture, cadence)?,
                    AvcAssemblyPoll::Retired(retired)
                        if retired.reason == AvcRetirementReason::NoPrimaryPicture => {}
                    AvcAssemblyPoll::Retired(_) => return Err(SiteProbeError::IncompletePicture),
                    AvcAssemblyPoll::Pending { .. } | AvcAssemblyPoll::Ended => break,
                }
            }
        }
        Ok(())
    }

    fn finish(&mut self, step: u64, cadence: &mut Cadence) -> Result<(), SiteProbeError> {
        if self.depacketizer.finish().is_some() {
            return Err(SiteProbeError::IncompletePicture);
        }
        let output = self
            .assembler
            .finish(step)
            .map_err(|_| SiteProbeError::Codec)?;
        avc_output(output, cadence)
    }
}

fn avc_output(output: AvcAssemblyOutput, cadence: &mut Cadence) -> Result<(), SiteProbeError> {
    if output
        .retired
        .is_some_and(|retired| retired.reason != AvcRetirementReason::NoPrimaryPicture)
    {
        return Err(SiteProbeError::IncompletePicture);
    }
    if let Some(picture) = output.picture {
        avc_picture(&picture, cadence)?;
    }
    Ok(())
}

fn avc_picture(picture: &AvcPictureGroup, cadence: &mut Cadence) -> Result<(), SiteProbeError> {
    if picture.boundary() == AvcBoundary::EndOfInputUnverified {
        return Err(SiteProbeError::IncompletePicture);
    }
    if !picture.saw_first_macroblock() || picture.discontinuity_before() {
        return Err(SiteProbeError::Picture);
    }
    cadence.observe(picture.timestamp())
}

pub(super) struct HevcObserver {
    key: StreamKey,
    depacketizer: H265Depacketizer,
    assembler: HevcAssembler,
    configuration: HevcConfiguration,
}

impl HevcObserver {
    fn push(
        &mut self,
        sequence: u64,
        packet: RtpPacket<'_>,
        step: u64,
        cadence: &mut Cadence,
    ) -> Result<(), SiteProbeError> {
        let output = self
            .depacketizer
            .push(self.key, sequence, packet, step)
            .map_err(|_| SiteProbeError::Codec)?;
        if output.gap_before
            || output.discarded.is_some()
            || output.status == H265Status::IgnoredNonIncreasing
        {
            return Err(SiteProbeError::Sequence);
        }
        for nal in output.nals {
            let configured = match nal.nal_type() {
                32 => Some(self.configuration.vps()),
                33 => Some(self.configuration.sps()),
                34 => Some(self.configuration.pps()),
                _ => None,
            };
            if configured.is_some_and(|expected| expected != nal.bytes()) {
                return Err(SiteProbeError::ParameterChange);
            }
            match self.assembler.push(nal, step) {
                HevcAssemblyStep::Accepted(output) => self.output(output, cadence)?,
                HevcAssemblyStep::Refused(_) => return Err(SiteProbeError::Codec),
            }
        }
        Ok(())
    }

    fn output(
        &self,
        output: HevcAssemblyOutput,
        cadence: &mut Cadence,
    ) -> Result<(), SiteProbeError> {
        if output
            .retired
            .is_some_and(|retired| retired.reason != HevcRetirementReason::NoPicture)
        {
            return Err(SiteProbeError::IncompletePicture);
        }
        if let Some(picture) = output.picture {
            self.picture(&picture, cadence)?;
        }
        Ok(())
    }

    fn picture(
        &self,
        picture: &HevcPictureGroup,
        cadence: &mut Cadence,
    ) -> Result<(), SiteProbeError> {
        if picture.boundary() == HevcBoundary::EndOfInputUnverified {
            return Err(SiteProbeError::IncompletePicture);
        }
        if !picture.prefix().first_slice || picture.discontinuity_before() {
            return Err(SiteProbeError::Picture);
        }
        if picture.prefix().pps_id != self.configuration.pps_id()
            || picture.prefix().temporal_id_plus_one > self.configuration.temporal_layers()
        {
            return Err(SiteProbeError::ParameterChange);
        }
        cadence.observe(picture.timestamp())
    }

    fn finish(&mut self, step: u64, cadence: &mut Cadence) -> Result<(), SiteProbeError> {
        if self.depacketizer.finish().is_some() {
            return Err(SiteProbeError::IncompletePicture);
        }
        let output = self
            .assembler
            .finish(step)
            .map_err(|_| SiteProbeError::Codec)?;
        self.output(output, cadence)
    }
}
