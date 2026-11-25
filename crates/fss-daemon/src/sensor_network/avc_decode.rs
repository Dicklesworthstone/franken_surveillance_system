#![forbid(unsafe_code)]
//! Bounded AVC source/picture association. Codec output may arrive in display order; daemon
//! custody must retain access units in their original decode order. The codec's decode index
//! joins the two without assigning an earlier picture to the packet that released it.

use std::collections::BTreeMap;

use fss_codec_h264::{Decoder, DecoderLimits, Picture, annex_b_nal_units};
use fss_core::ContentDigest;
use fss_packet::avc::{
    AvcAssemblyOutput, AvcAssemblyStep, AvcPictureGroup, AvcReceivePoll, AvcRetirementReason,
};

const MAX_PENDING_PICTURES: usize = 32;
const MAX_PENDING_BYTES: usize = 128 * 1_024 * 1_024;
const MAX_ACCESS_UNIT_BYTES: usize = 32 * 1_024 * 1_024;
// Beyond half an RTP cycle, receive time cannot select a unique nearby wrap epoch.
const RTP_HALF_CYCLE_NS: i128 = ((1_i128 << 31) * 1_000_000_000 + 89_999) / 90_000;

pub(super) struct SourcePicture {
    pub(super) encoded: Vec<u8>,
    pub(super) digest: ContentDigest,
    pub(super) media_pts_ns: i128,
    pub(super) host_receive_ns: i128,
    pub(super) discontinuity_before: bool,
}

pub(super) struct DecodedSource {
    pub(super) source: SourcePicture,
    pub(super) picture: Picture,
}

pub(super) struct AvcSourceDecoder {
    decoder: Decoder,
    sources: BTreeMap<u64, SourcePicture>,
    pictures: BTreeMap<u64, Picture>,
    pending_bytes: usize,
    sent_parameter_sets: bool,
    last_receive_ns: Option<i128>,
    last_media_timestamp: Option<(u32, i128)>,
    closed: bool,
}

impl AvcSourceDecoder {
    pub(super) fn new() -> Result<Self, &'static str> {
        Ok(Self {
            decoder: Decoder::new(DecoderLimits::default())
                .map_err(|_| "failed initializing pure-Rust H.264 decoder")?,
            sources: BTreeMap::new(),
            pictures: BTreeMap::new(),
            pending_bytes: 0,
            sent_parameter_sets: false,
            last_receive_ns: None,
            last_media_timestamp: None,
            closed: false,
        })
    }

    /// A group is admitted only after native decoding proves exactly one complete picture.
    /// Any error closes this instance: the driver must report loss and reconnect into a new
    /// generation, rather than silently continuing the old prediction/continuity chain.
    pub(super) fn push(
        &mut self,
        group: &AvcPictureGroup,
        host_receive_ns: i128,
    ) -> Result<(), &'static str> {
        let result = self.push_inner(group, host_receive_ns);
        if result.is_err() {
            self.refuse();
        }
        result
    }

    fn push_inner(
        &mut self,
        group: &AvcPictureGroup,
        host_receive_ns: i128,
    ) -> Result<(), &'static str> {
        if self.closed {
            return Err("AVC source decoder is closed");
        }
        if self
            .last_receive_ns
            .is_some_and(|last| host_receive_ns < last)
        {
            return Err("AVC source receive time moved backwards");
        }
        if group.discontinuity_before() && self.decoder.pictures_decoded() != 0 {
            return Err("AVC source discontinuity requires a new decoder generation");
        }
        if self.sources.len() >= MAX_PENDING_PICTURES {
            return Err("AVC source reorder window exceeded its picture bound");
        }

        let media_ticks = self.extend_media_timestamp(group.timestamp(), host_receive_ns)?;
        let media_pts_ns = media_ticks
            .checked_mul(1_000_000_000)
            .ok_or("AVC source media time exhausted its numeric bound")?
            / 90_000;
        let idr = group.nals().iter().any(|nal| nal.nal_type() == 5);
        let include_parameters = !self.sent_parameter_sets || idr;
        let parameter_bytes = if include_parameters {
            group
                .sps()
                .nal_bytes()
                .len()
                .checked_add(group.pps().nal_bytes().len())
                .and_then(|bytes| bytes.checked_add(8))
                .ok_or("AVC parameter sets exceeded their source byte bound")?
        } else {
            0
        };
        let bytes = group
            .nals()
            .len()
            .checked_mul(4)
            .and_then(|prefixes| group.byte_len().checked_add(prefixes))
            .and_then(|total| total.checked_add(parameter_bytes))
            .filter(|total| *total <= MAX_ACCESS_UNIT_BYTES)
            .ok_or("AVC access unit exceeded its source byte bound")?;
        let next_bytes = self
            .pending_bytes
            .checked_add(bytes)
            .filter(|total| *total <= MAX_PENDING_BYTES)
            .ok_or("AVC source reorder window exceeded its byte bound")?;
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(bytes)
            .map_err(|_| "AVC source allocation refused")?;
        if include_parameters {
            append_nal(&mut encoded, group.sps().nal_bytes());
            append_nal(&mut encoded, group.pps().nal_bytes());
        }
        for nal in group.nals() {
            append_nal(&mut encoded, nal.bytes());
        }

        let index = self.decoder.pictures_decoded();
        let mut output = Vec::new();
        for nal in annex_b_nal_units(&encoded) {
            let picture = self
                .decoder
                .decode_nal(nal)
                .map_err(|_| "AVC native picture decoding refused the access unit")?;
            if self
                .decoder
                .pictures_decoded()
                .checked_sub(index)
                .is_none_or(|count| count > 1)
            {
                return Err("AVC access unit contained multiple decoded pictures");
            }
            if let Some(picture) = picture {
                output.push(picture);
            }
            while let Some(picture) = self.decoder.next_output() {
                output.push(picture);
            }
        }
        if self.decoder.pictures_decoded().checked_sub(index) != Some(1)
            || self.decoder.has_incomplete_picture()
        {
            return Err("AVC access unit did not decode exactly one complete picture");
        }

        let source = SourcePicture {
            digest: ContentDigest::sha256(&encoded),
            encoded,
            media_pts_ns,
            host_receive_ns,
            discontinuity_before: group.discontinuity_before(),
        };
        self.sources.insert(index, source);
        self.pending_bytes = next_bytes;
        self.store_pictures(output)?;
        // An IDR normally drains waiting prior pictures. Its explicit no-output flag can
        // discard them instead. Do not let their missing indexes permanently block output,
        // nor silently declare their source/picture association complete.
        if idr
            && self
                .sources
                .keys()
                .any(|key| *key < index && !self.pictures.contains_key(key))
        {
            return Err("AVC random-access reset discarded pending source pictures");
        }
        self.sent_parameter_sets = true;
        self.last_receive_ns = Some(host_receive_ns);
        self.last_media_timestamp = Some((group.timestamp(), media_ticks));
        Ok(())
    }

    /// Extend the sender's 32-bit presentation clock within this decoder generation.
    /// Signed nearby differences preserve B-picture reordering on either side of a wrap;
    /// neither a wrap nor a decode-order inversion is a physical capture-time assertion.
    fn extend_media_timestamp(
        &self,
        timestamp: u32,
        host_receive_ns: i128,
    ) -> Result<i128, &'static str> {
        let Some((previous, extended)) = self.last_media_timestamp else {
            return Ok(i128::from(timestamp));
        };
        let previous_receive_ns = self
            .last_receive_ns
            .ok_or("AVC source clock state is incomplete")?;
        let receive_delta = host_receive_ns
            .checked_sub(previous_receive_ns)
            .ok_or("AVC source receive time exhausted its numeric bound")?;
        let delta = timestamp.wrapping_sub(previous);
        if receive_delta >= RTP_HALF_CYCLE_NS || delta == 0x8000_0000 {
            return Err("AVC source timestamp epoch is ambiguous; new generation required");
        }
        extended
            .checked_add(i128::from(delta as i32))
            .ok_or("AVC source media time exhausted its numeric bound")
    }

    fn store_pictures(&mut self, output: Vec<Picture>) -> Result<(), &'static str> {
        for picture in output {
            let index = picture.decode_index();
            if !self.sources.contains_key(&index) || self.pictures.contains_key(&index) {
                return Err("AVC decoded picture has no unique retained source");
            }
            self.pending_bytes = self
                .pending_bytes
                .checked_add(picture_bytes(&picture))
                .filter(|total| *total <= MAX_PENDING_BYTES)
                .ok_or("AVC decoded reorder window exceeded its byte bound")?;
            self.pictures.insert(index, picture);
        }
        Ok(())
    }

    /// Called only once accepted protocol input has completely drained at a clean EOF.
    pub(super) fn finish(&mut self) -> Result<(), &'static str> {
        let result = self.finish_inner();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    fn finish_inner(&mut self) -> Result<(), &'static str> {
        if self.closed {
            return Err("AVC source decoder is closed");
        }
        self.closed = true;
        let output = self
            .decoder
            .finish()
            .map_err(|_| "AVC stream ended with an incomplete picture")?;
        self.store_pictures(output)?;
        if self
            .sources
            .keys()
            .any(|key| !self.pictures.contains_key(key))
        {
            return Err("AVC stream ended without every retained source picture");
        }
        Ok(())
    }

    fn refuse(&mut self) {
        self.closed = true;
        self.sources.clear();
        self.pictures.clear();
        self.pending_bytes = 0;
    }

    /// Release one original access unit and its exact decoded pixels in decode order. Keeping
    /// this single-item avoids allocating an entire burst of RGB frames when an IDR or EOF
    /// releases many codec pictures at once.
    pub(super) fn take_ready(&mut self) -> Option<DecodedSource> {
        let index = *self.sources.first_key_value()?.0;
        let picture = self.pictures.remove(&index)?;
        let source = self.sources.remove(&index)?;
        self.pending_bytes = self
            .pending_bytes
            .saturating_sub(source.encoded.len())
            .saturating_sub(picture_bytes(&picture));
        Some(DecodedSource { source, picture })
    }
}

/// Extract one group while retaining the receiver's explicit loss/refusal distinction.
/// Metadata-only retirement does not claim a lost picture. Every damaged picture or input
/// discontinuity requires driver reconnect so stale prediction state cannot conceal a gap.
pub(super) fn collect_avc_media(
    media: AvcReceivePoll,
    group: &mut Option<AvcPictureGroup>,
) -> Result<bool, &'static str> {
    match media {
        AvcReceivePoll::Picture(picture) => collect_picture(picture, group)?,
        AvcReceivePoll::Assembly(AvcAssemblyStep::Accepted(output)) => {
            collect_assembly(output, group)?;
        }
        AvcReceivePoll::Assembly(AvcAssemblyStep::Refused(_)) => {
            return Err("AVC picture assembly refused input");
        }
        AvcReceivePoll::Source {
            gap_before,
            fragment,
            picture,
            ..
        } => {
            if gap_before
                || fragment.is_some()
                || picture
                    .is_some_and(|retired| retired.reason != AvcRetirementReason::NoPrimaryPicture)
            {
                return Err("AVC source input lost continuity");
            }
        }
        AvcReceivePoll::CodecRefused { .. } => {
            return Err("AVC packet reconstruction refused input");
        }
        AvcReceivePoll::Gap { .. } | AvcReceivePoll::FragmentRetired { .. } => {
            return Err("AVC source input lost continuity");
        }
        AvcReceivePoll::PictureRetired(retired) => {
            if retired.reason != AvcRetirementReason::NoPrimaryPicture {
                return Err("AVC incomplete picture was retired");
            }
        }
        AvcReceivePoll::Ended {
            fragment,
            interrupted_picture,
            tail,
        } => {
            if fragment.is_some() || interrupted_picture.is_some() {
                return Err("AVC stream ended with interrupted source input");
            }
            if let Some(output) = tail {
                collect_assembly(output, group)?;
            }
            return Ok(true);
        }
        AvcReceivePoll::Pending { .. } => {}
    }
    Ok(false)
}

fn collect_assembly(
    output: AvcAssemblyOutput,
    group: &mut Option<AvcPictureGroup>,
) -> Result<(), &'static str> {
    if output
        .retired
        .is_some_and(|retired| retired.reason != AvcRetirementReason::NoPrimaryPicture)
    {
        return Err("AVC incomplete picture was retired");
    }
    if let Some(picture) = output.picture {
        collect_picture(picture, group)?;
    }
    Ok(())
}

fn collect_picture(
    picture: AvcPictureGroup,
    group: &mut Option<AvcPictureGroup>,
) -> Result<(), &'static str> {
    if group.is_some() {
        return Err("AVC poll exceeded its single-picture work bound");
    }
    *group = Some(picture);
    Ok(())
}

fn append_nal(encoded: &mut Vec<u8>, nal: &[u8]) {
    encoded.extend_from_slice(&[0, 0, 0, 1]);
    encoded.extend_from_slice(nal);
}

fn picture_bytes(picture: &Picture) -> usize {
    picture.luma().len() + picture.cb().len() + picture.cr().len()
}

#[cfg(test)]
mod tests;
