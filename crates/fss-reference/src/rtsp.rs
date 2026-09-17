#![forbid(unsafe_code)]
//! Sans-IO RTSP/1.0 parsing and owner-driven client negotiation for FSS.
//!
//! Public wire parsing redacts credentials. Explicit authentication helpers
//! borrow owner-supplied secrets without I/O. A PLAY response is not proof of
//! frames, source custody, or continuous camera coverage.

/// Bounded opt-in Digest authentication for an explicit credential owner.
pub mod authentication;
/// RTSP framing, negotiated video, and source-linked AVC receiver composition.
pub mod avc_client;
/// Exact bounded wire frames for explicit authentication and source-custody owners.
pub mod framed;

/// Capability-scoped, owner-driven RTSP/1.0 client session reference.
pub mod client;
pub mod message;
/// Sealed source-linked recording windows and byte-provenance verification.
pub mod recording;
/// Continuous bounded IDR collection with explicit source ownership and backpressure.
pub mod recording_collector;
/// Bounded receiver-event capture with explicit timing and automatic failure fencing.
pub mod recording_capture;
/// Immutable multi-window discovery and bounded, verified decode-range retrieval.
pub mod recording_catalog;
/// Bounded local archive discovery, restart recovery, and cross-page retrieval.
pub mod recording_archive;
pub mod sdp;

pub use message::{
    AuthScheme, ContentLengthConflict, DEFAULT_MAX_BODY_BYTES, DEFAULT_MAX_HEADERS,
    DEFAULT_MAX_INTERLEAVED_BYTES, DEFAULT_MAX_LINE_BYTES, DuplicateHeader, HeaderLimitFault,
    HeaderValueFault, LengthLimit, MessageKind, NulSite, NumericFault, PoisonCause,
    REDACTED_CREDENTIAL, RtspError, RtspEvent, RtspHeader, RtspHeaders, RtspLimits, RtspMethod,
    RtspParser, RtspRequest, RtspResponse, RtspTransport, StartLineFault, TransportFault,
    UnsupportedMethod, UserinfoSite, Utf8Fault, VersionFault,
};
pub use sdp::{
    Base64Fault, MAX_BASE64_INPUT_BYTES, MAX_SDP_LINE_BYTES, MAX_SDP_LINES, SdpControlLevel,
    SdpError, SdpFault, SdpLimitFault, SdpMalformed, SdpMedia, SdpSession, decode_base64,
    parse_sdp, parse_sdp_bytes,
};
