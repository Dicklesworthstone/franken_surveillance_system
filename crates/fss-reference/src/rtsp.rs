#![forbid(unsafe_code)]
//! Sans-IO RTSP/1.0 message and SDP parser for FSS.
//!
//! Provides bounded, incremental parsing of RTSP/1.0 requests, responses,
//! interleaved frames, and Session Description Protocol (SDP) payloads.
//! Performs zero I/O and never handles credentials. Errors carry only typed
//! reasons plus byte offsets or lengths, never input text.

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
