//! Bounded, allocation-free media probing over the head of a source (FSS-053).
//!
//! A family probe answers one question: which container and payload domain do these bytes
//! claim to be? It never decodes, never allocates, never touches the filesystem or a socket, and
//! never reads past [`ProbeLimits::max_bytes`]. Everything it cannot settle is reported as
//! [`ProbeOutcome::Insufficient`] with the byte count it needed, so a caller can ask for more
//! without guessing; contradictory heads are reported rather than resolved by precedence.
//!
//! Every arm is a prefix test on bytes that a real file is required to carry at offset zero, so a
//! positive answer is a claim about the head only. Frame-level validity, sample counts, and codec
//! parameters are a separate bounded claim in [`parameters`], never decoder acceptance.

#![forbid(unsafe_code)]

pub mod parameters;

use fss_core::identity::MediaKind;

/// Most bytes a single probe may inspect. A probe never keeps a buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeLimits {
    /// Header bytes the caller permits, in 1..=4096.
    pub max_bytes: usize,
}

/// Minimum family-probe window (MP4 `ftyp` plus a four-character brand).
/// Transport streams and extended-size ISO-BMFF headers need longer windows.
pub const MAX_PREFIX: usize = 12;

/// Bytes needed to observe two MPEG-TS synchronization bytes 188 bytes apart.
pub const TRANSPORT_PREFIX: usize = 189;

/// Hard head-inspection ceiling, including directly constructed limits.
pub const MAX_PROBE_BYTES: usize = 4096;

impl Default for ProbeLimits {
    fn default() -> Self {
        Self {
            max_bytes: TRANSPORT_PREFIX,
        }
    }
}

impl ProbeLimits {
    /// Builds limits, clamping into the supported range instead of failing.
    #[must_use]
    pub const fn new(max_bytes: usize) -> Self {
        let max_bytes = if max_bytes == 0 {
            1
        } else if max_bytes > MAX_PROBE_BYTES {
            MAX_PROBE_BYTES
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
    let window = &head[..head.len().min(limits.max_bytes).min(MAX_PROBE_BYTES)];
    if window.len() < MAX_PREFIX {
        return ProbeOutcome::Insufficient { needed: MAX_PREFIX };
    }
    if window[0] == 0x47 && window.len() < TRANSPORT_PREFIX {
        return ProbeOutcome::Insufficient {
            needed: TRANSPORT_PREFIX,
        };
    }
    let transport = window[0] == 0x47 && window.get(188) == Some(&0x47);
    let bmff = window[4..8] == *b"ftyp";
    let ebml = starts_with(window, &[0x1A, 0x45, 0xDF, 0xA3]);
    let flv = starts_with(window, b"FLV");
    let jpeg = starts_with(window, &[0xFF, 0xD8, 0xFF]);
    // An extended ISO-BMFF size is exactly 00 00 00 01. Its explicit box type
    // disambiguates that shared prefix; it is not a second independent signature.
    let extended_bmff = bmff && window[..4] == [0, 0, 0, 1];
    let annex_b = !extended_bmff
        && (starts_with(window, &[0x00, 0x00, 0x00, 0x01])
            || starts_with(window, &[0x00, 0x00, 0x01]));
    let matched = u8::from(ebml)
        + u8::from(flv)
        + u8::from(jpeg)
        + u8::from(annex_b)
        + u8::from(bmff)
        + u8::from(transport);
    if matched > 1 {
        return ProbeOutcome::Contradictory;
    }
    if bmff {
        let size = u32::from_be_bytes([window[0], window[1], window[2], window[3]]);
        let brand = if size == 1 {
            if window.len() < 20 {
                return ProbeOutcome::Insufficient { needed: 20 };
            }
            let size = u64::from_be_bytes([
                window[8], window[9], window[10], window[11],
                window[12], window[13], window[14], window[15],
            ]);
            if size < 24 {
                return ProbeOutcome::Unsupported;
            }
            &window[16..20]
        } else {
            if size != 0 && size < 16 {
                return ProbeOutcome::Unsupported;
            }
            &window[8..12]
        };
        return ProbeOutcome::Identified {
            container: ContainerKind::IsoBmff,
            media: ContainerKind::IsoBmff.media(),
            brand: Some(brand),
        };
    }
    let container = if transport {
        ContainerKind::MpegTs
    } else if ebml {
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

    #[test]
    fn transport_sync_outside_the_budget_cannot_affect_the_answer() {
        let mut packet = vec![0u8; 376];
        packet[0] = 0x47;
        for budget in [12, 32, 188] {
            let limits = ProbeLimits::new(budget);
            for second in [0, 0x47] {
                packet[188] = second;
                assert_eq!(
                    probe(&packet, &limits),
                    ProbeOutcome::Insufficient { needed: 189 }
                );
                assert_eq!(probe(&packet, &limits), probe(&packet[..budget], &limits));
            }
        }
        packet[188] = 0x47;
        assert_eq!(identify(&packet, &ProbeLimits::new(189)), ContainerKind::MpegTs);
    }

    #[test]
    fn conflicting_signatures_are_not_resolved_by_precedence() {
        let mut bytes = head(&[0xff, 0xd8, 0xff, 0xe0]);
        bytes[4..8].copy_from_slice(b"ftyp");
        assert_eq!(
            probe(&bytes, &ProbeLimits::default()),
            ProbeOutcome::Contradictory
        );
        let annex_b_overlap = b"\x00\x00\x01\x67ftypisom";
        assert_eq!(
            probe(annex_b_overlap, &ProbeLimits::default()),
            ProbeOutcome::Contradictory
        );
        let mut transport = vec![0u8; TRANSPORT_PREFIX];
        transport[0] = 0x47;
        transport[188] = 0x47;
        transport[4..8].copy_from_slice(b"ftyp");
        assert_eq!(
            probe(&transport, &ProbeLimits::default()),
            ProbeOutcome::Contradictory
        );
    }

    #[test]
    fn extended_size_bmff_uses_the_actual_brand_offset() {
        let bytes = b"\x00\x00\x00\x01ftyp\x00\x00\x00\x00\x00\x00\x00\x18iso6\x00\x00\x00\x00";
        assert_eq!(
            probe(bytes, &ProbeLimits::new(19)),
            ProbeOutcome::Insufficient { needed: 20 }
        );
        match probe(bytes, &ProbeLimits::new(20)) {
            ProbeOutcome::Identified { container, brand, .. } => {
                assert_eq!(container, ContainerKind::IsoBmff);
                assert_eq!(brand, Some(&b"iso6"[..]));
            }
            other => panic!("expected extended-size brand, got {other:?}"),
        }
        let mut malformed = *bytes;
        malformed[15] = 23;
        assert_eq!(
            probe(&malformed, &ProbeLimits::default()),
            ProbeOutcome::Unsupported
        );
        assert_eq!(
            probe(b"\x00\x00\x00\x0cftypisom", &ProbeLimits::default()),
            ProbeOutcome::Unsupported
        );
    }

}
