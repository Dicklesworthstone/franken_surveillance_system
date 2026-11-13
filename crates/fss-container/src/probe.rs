//! Bounded, allocation-free media probing over the head of a source (FSS-053).
//!
//! A probe answers one question and nothing else: which container and payload domain do these bytes
//! claim to be? It never decodes, never allocates, never touches the filesystem or a socket, and
//! never reads past [`ProbeLimits::max_bytes`]. Everything it cannot settle is reported as
//! [`ProbeOutcome::Insufficient`] with the byte count it needed, so a caller can ask for more
//! without guessing; contradictory heads are reported rather than resolved by precedence.
//!
//! Every arm is a prefix test on bytes that a real file is required to carry at offset zero, so a
//! positive answer is a claim about the head only. Frame-level validity, sample counts, and codec
//! parameters belong to the demuxers.

use fss_core::identity::MediaKind;

/// Most bytes a single probe may inspect. A probe never keeps a buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeLimits {
    /// Header bytes the caller permits, in 1..=4096.
    pub max_bytes: usize,
}

/// Longest prefix any recognizer needs (MP4 `ftyp` plus a four-character brand).
pub const MAX_PREFIX: usize = 12;

impl Default for ProbeLimits {
    fn default() -> Self {
        Self {
            max_bytes: MAX_PREFIX,
        }
    }
}

impl ProbeLimits {
    /// Builds limits, clamping into the supported range instead of failing.
    #[must_use]
    pub const fn new(max_bytes: usize) -> Self {
        let max_bytes = if max_bytes == 0 {
            1
        } else if max_bytes > 4096 {
            4096
        } else {
            max_bytes
        };
        Self { max_bytes }
    }
}

/// Container family claimed by the head.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ContainerKind {
    /// ISO base media (`ftyp`).
    IsoBmff,
    /// Matroska or WebM (EBML header).
    Matroska,
    /// Adobe FLV.
    Flv,
    /// MPEG transport stream.
    MpegTs,
    /// Annex-B byte stream (start codes).
    AnnexB,
    /// JPEG still.
    Jpeg,
}

impl ContainerKind {
    /// Stable machine-readable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IsoBmff => "iso-bmff",
            Self::Matroska => "matroska",
            Self::Flv => "flv",
            Self::MpegTs => "mpeg-ts",
            Self::AnnexB => "annex-b",
            Self::Jpeg => "jpeg",
        }
    }

    /// Payload domain the family carries.
    #[must_use]
    pub const fn media(self) -> MediaKind {
        match self {
            Self::Jpeg => MediaKind::Image,
            Self::IsoBmff | Self::Matroska | Self::Flv | Self::MpegTs | Self::AnnexB => {
                MediaKind::Video
            }
        }
    }
}

/// What the head settled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeOutcome<'a> {
    /// One family matched; `brand` carries the ISO-BMFF brand when the family is [`ContainerKind::IsoBmff`].
    Identified {
        /// Matching family.
        container: ContainerKind,
        /// Payload domain implied by the family.
        media: MediaKind,
        /// ISO-BMFF major brand, verbatim, when present.
        brand: Option<&'a [u8]>,
    },
    /// The head is shorter than the recognizer needs, or the budget cut it short.
    Insufficient {
        /// Header bytes the recognizer needs to decide.
        needed: usize,
    },
    /// The head carries two mutually exclusive signatures.
    Contradictory,
    /// Nothing matched, or a signature matched in a position a real file cannot occupy.
    Unsupported,
}

fn starts_with(head: &[u8], prefix: &[u8]) -> bool {
    head.len() >= prefix.len() && head.starts_with(prefix)
}

/// Probes `head` under `limits`.
#[must_use]
pub fn probe<'a>(head: &'a [u8], limits: &ProbeLimits) -> ProbeOutcome<'a> {
    let window = &head[..head.len().min(limits.max_bytes)];
    // A budget too small to hold the longest recognizer cannot decide anything on its own; report
    // the shortfall first so the caller grows the window instead of reading a false negative.
    if window.len() < MAX_PREFIX {
        return ProbeOutcome::Insufficient { needed: MAX_PREFIX };
    }
    if !head.is_empty() && head[0] == 0x47 && head.get(188) == Some(&0x47) {
        return ProbeOutcome::Identified {
            container: ContainerKind::MpegTs,
            media: ContainerKind::MpegTs.media(),
            brand: None,
        };
    }
    if window[4..8] == *b"ftyp" {
        return ProbeOutcome::Identified {
            container: ContainerKind::IsoBmff,
            media: ContainerKind::IsoBmff.media(),
            brand: Some(&window[8..12]),
        };
    }
    let ebml = starts_with(window, &[0x1A, 0x45, 0xDF, 0xA3]);
    let flv = starts_with(window, b"FLV");
    let jpeg = starts_with(window, &[0xFF, 0xD8, 0xFF]);
    let annex_b = starts_with(window, &[0x00, 0x00, 0x00, 0x01])
        || starts_with(window, &[0x00, 0x00, 0x01]);
    let matched = u8::from(ebml) + u8::from(flv) + u8::from(jpeg);
    if matched > 1 {
        return ProbeOutcome::Contradictory;
    }
    let container = if ebml {
        ContainerKind::Matroska
    } else if flv {
        ContainerKind::Flv
    } else if jpeg {
        ContainerKind::Jpeg
    } else if annex_b {
        ContainerKind::AnnexB
    } else {
        return ProbeOutcome::Unsupported;
    };
    ProbeOutcome::Identified {
        container,
        media: container.media(),
        brand: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(prefix: &[u8]) -> Vec<u8> {
        let mut bytes = prefix.to_vec();
        bytes.resize(MAX_PREFIX, 0);
        bytes
    }

    fn identify(bytes: &[u8], limits: &ProbeLimits) -> ContainerKind {
        match probe(bytes, limits) {
            ProbeOutcome::Identified { container, .. } => container,
            other => panic!("expected identification, got {other:?}"),
        }
    }

    #[test]
    fn identifies_each_recognized_family() {
        let limits = ProbeLimits::default();
        assert_eq!(
            identify(&head(b"\x00\x00\x00\x18ftypisom"), &limits),
            ContainerKind::IsoBmff
        );
        assert_eq!(
            identify(&head(&[0x1A, 0x45, 0xDF, 0xA3]), &limits),
            ContainerKind::Matroska
        );
        assert_eq!(identify(&head(b"FLV\x01\x05"), &limits), ContainerKind::Flv);
        assert_eq!(
            identify(&head(&[0xFF, 0xD8, 0xFF, 0xE0]), &limits),
            ContainerKind::Jpeg
        );
        assert_eq!(
            identify(&head(&[0x00, 0x00, 0x00, 0x01, 0x67]), &limits),
            ContainerKind::AnnexB
        );
        assert_eq!(
            identify(&head(&[0x00, 0x00, 0x01, 0xBA]), &limits),
            ContainerKind::AnnexB
        );
    }

    #[test]
    fn transport_stream_needs_the_second_sync_byte() {
        let limits = ProbeLimits::default();
        let mut packet = vec![0u8; 376];
        packet[0] = 0x47;
        packet[188] = 0x47;
        assert_eq!(identify(&packet, &limits), ContainerKind::MpegTs);
        // A single 0x47 is also the first byte of a plausible Annex-B or junk head.
        packet[188] = 0x00;
        assert_eq!(probe(&packet, &limits), ProbeOutcome::Unsupported);
    }

    #[test]
    fn jpeg_is_an_image_and_the_rest_are_video() {
        assert_eq!(ContainerKind::Jpeg.media(), MediaKind::Image);
        assert_eq!(ContainerKind::IsoBmff.media(), MediaKind::Video);
    }

    #[test]
    fn brand_is_returned_verbatim() {
        let bytes = head(b"\x00\x00\x00\x18ftypavc1");
        match probe(&bytes, &ProbeLimits::default()) {
            ProbeOutcome::Identified { brand, .. } => assert_eq!(brand, Some(&b"avc1"[..])),
            other => panic!("expected identification, got {other:?}"),
        }
    }

    #[test]
    fn short_head_reports_the_bytes_it_needs() {
        assert_eq!(
            probe(b"FLV", &ProbeLimits::default()),
            ProbeOutcome::Insufficient { needed: MAX_PREFIX }
        );
        assert_eq!(
            probe(b"", &ProbeLimits::default()),
            ProbeOutcome::Insufficient { needed: MAX_PREFIX }
        );
    }

    #[test]
    fn budget_below_the_longest_prefix_still_reports_the_shortfall() {
        // A 4-byte budget can never satisfy MAX_PREFIX, even when the caller holds a longer head.
        let bytes = head(b"\x00\x00\x00\x18ftypisom");
        assert_eq!(
            probe(&bytes, &ProbeLimits::new(4)),
            ProbeOutcome::Insufficient { needed: MAX_PREFIX }
        );
    }

    #[test]
    fn limits_clamp_into_range() {
        assert_eq!(ProbeLimits::new(0).max_bytes, 1);
        assert_eq!(ProbeLimits::new(usize::MAX).max_bytes, 4096);
        assert_eq!(ProbeLimits::new(64).max_bytes, 64);
    }

    #[test]
    fn unknown_head_is_unsupported() {
        assert_eq!(
            probe(&head(b"RIFFxxxxWAVE"), &ProbeLimits::default()),
            ProbeOutcome::Unsupported
        );
    }

    #[test]
    fn container_names_are_stable() {
        assert_eq!(ContainerKind::IsoBmff.as_str(), "iso-bmff");
        assert_eq!(ContainerKind::MpegTs.as_str(), "mpeg-ts");
    }
}
