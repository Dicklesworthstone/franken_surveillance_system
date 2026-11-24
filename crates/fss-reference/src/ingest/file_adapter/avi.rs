#![forbid(unsafe_code)]
//! AVI framing joins the existing file-import capsule, custody and publication path.

use super::*;
use fss_container::avi::AviMjpeg;

pub(super) fn sniff(
    bytes: &[u8],
    maximum_samples: usize,
    check: &mut dyn FnMut() -> Result<(), DemuxError>,
) -> Result<(DetectedFileFormat, &'static str), FileIngestError> {
    AviMjpeg::parse_with_checkpoint(bytes, limits(maximum_samples), check).map_err(refusal)?;
    Ok((DetectedFileFormat::AviMjpeg, "avi_riff_mjpeg"))
}

fn refusal(error: DemuxError) -> FileIngestError {
    match error {
        DemuxError::Cancelled => FileIngestError::CancellationRequested { stage: STAGE_SPLIT },
        refusal => FileIngestError::AviRefused { refusal },
    }
}

impl ContainerVideo {
    pub(super) fn avi(
        bytes: &[u8],
        request: &FileIngestRequest,
        cx: &ReplayCx,
    ) -> Result<Self, FileIngestError> {
        let limits = limits(
            request
                .limits
                .max_segments
                .min(request.limits.mjpeg_limits.max_frames),
        );
        let video = AviMjpeg::parse_with_checkpoint(bytes, limits, &mut || {
            cx.checkpoint(STAGE_SPLIT)
                .map_err(|_| DemuxError::Cancelled)
        })
        .map_err(refusal)?;
        if video.samples().len() > request.limits.mjpeg_limits.max_frames {
            return Err(refusal(DemuxError::Limit));
        }
        let mut selected_bytes = 0_usize;
        for sample in video.samples() {
            selected_bytes = selected_bytes
                .checked_add(sample.source.len())
                .filter(|size| *size <= request.limits.mjpeg_limits.max_input_bytes)
                .ok_or_else(|| refusal(DemuxError::Limit))?;
            let source = &bytes[sample.source.clone()];
            let scan = split_jpeg_stream(source, &request.limits.mjpeg_limits, Some(cx))?;
            let [frame] = scan.frames.as_slice() else {
                return Err(refusal(DemuxError::Unsupported));
            };
            if frame.start_offset != 0
                || frame.end_offset != source.len()
                || frame.is_truncated
                || !frame.has_eoi
                || !scan.omissions.is_empty()
                || !scan.findings.is_empty()
            {
                return Err(refusal(DemuxError::Layout));
            }
            progressive_jpeg(source, cx)?;
            let dimensions = frame
                .sof
                .as_ref()
                .map(|sof| [u32::from(sof.width), u32::from(sof.height)]);
            if dimensions != Some(video.dimensions()) {
                return Err(refusal(DemuxError::Layout));
            }
        }
        let (scale, rate) = video.time_base();
        Ok(Self {
            family: ContainerFamily::Avi,
            parameter_prefix: AVI_STRUCTURE_REASON_PREFIX,
            nal_length_bytes: 0,
            parameter_sets: Vec::new(),
            samples: video
                .samples()
                .iter()
                .map(|sample| {
                    (
                        sample.index,
                        sample.source.clone(),
                        i128::from(sample.presentation_tick),
                    )
                })
                .collect(),
            tick_ns: (i128::from(scale) * 1_000_000_000, i128::from(rate)),
            regions: vec![(0, bytes.len(), "avi_structure".to_owned())],
            tail: bytes.len(),
        })
    }
}

// Unlike MP4, AVI spends at least one RIFF chunk per video frame and may
// interleave audio chunks. Keep the shared hard ceiling explicit for this format.
fn limits(maximum_samples: usize) -> fss_container::demux::DemuxLimits {
    fss_container::demux::DemuxLimits {
        maximum_boxes: 65_536,
        maximum_metadata_bytes: 32 * 1024 * 1024,
        ..mp4_demux_limits(maximum_samples)
    }
}

// OpenDML AVI1 APP0 field polarity distinguishes progressive pictures from
// individual fields. Inspect marker payloads, never a raw byte-pattern match
// that could mistake JPEG entropy or another application's metadata for AVI1.
fn progressive_jpeg(bytes: &[u8], cx: &ReplayCx) -> Result<(), FileIngestError> {
    let mut at = 2_usize;
    let mut checkpoint = 0;
    while at < bytes.len() {
        if at >= checkpoint {
            cx.checkpoint(STAGE_SPLIT)
                .map_err(|_| FileIngestError::CancellationRequested { stage: STAGE_SPLIT })?;
            checkpoint = at.saturating_add(4096);
        }
        if bytes[at] != 0xff {
            at += 1;
            continue;
        }
        while bytes.get(at) == Some(&0xff) {
            at += 1;
        }
        let marker = *bytes
            .get(at)
            .ok_or_else(|| refusal(DemuxError::Truncated))?;
        at += 1;
        match marker {
            0x00 | 0x01 | 0xd0..=0xd7 => continue,
            0xd9 => return Ok(()),
            0xd8 => return Err(refusal(DemuxError::Layout)),
            _ => {}
        }
        let length = bytes
            .get(at..at + 2)
            .map(|value| usize::from(u16::from_be_bytes([value[0], value[1]])))
            .filter(|value| *value >= 2)
            .ok_or_else(|| refusal(DemuxError::Layout))?;
        let end = at
            .checked_add(length)
            .ok_or_else(|| refusal(DemuxError::Limit))?;
        let payload = bytes
            .get(at + 2..end)
            .ok_or_else(|| refusal(DemuxError::Truncated))?;
        if marker == 0xe0 && payload.starts_with(b"AVI1") && payload.get(4) != Some(&0) {
            return Err(refusal(DemuxError::Unsupported));
        }
        at = end;
    }
    Err(refusal(DemuxError::Truncated))
}
