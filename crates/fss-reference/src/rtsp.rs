#![forbid(unsafe_code)]
//! Sans-IO RTSP/1.0 parsing and owner-driven client negotiation for FSS.
//!
//! Bounded wire parsing and explicit DESCRIBE/SETUP/PLAY/keepalive/TEARDOWN
//! transitions perform no I/O and never handle credentials. A PLAY response
//! is not proof of frames, source custody, or continuous camera coverage.

/// RTSP framing, negotiated video, and source-linked AVC receiver composition.
pub mod avc_client;

/// Capability-scoped, owner-driven RTSP/1.0 client session reference.
pub mod client;
pub mod message;
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
