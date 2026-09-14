#![forbid(unsafe_code)]
//! Sans-IO RTSP/1.0 message and SDP parser for FSS.
//!
//! Provides bounded, incremental parsing of RTSP/1.0 requests, responses,
//! interleaved frames, and Session Description Protocol (SDP) payloads.
//! Performs zero I/O and never handles credentials.

pub mod message;
pub mod sdp;

pub use message::{
    DEFAULT_MAX_BODY_BYTES, DEFAULT_MAX_HEADERS, DEFAULT_MAX_INTERLEAVED_BYTES,
    DEFAULT_MAX_LINE_BYTES, RtspError, RtspEvent, RtspHeader, RtspHeaders, RtspLimits, RtspMethod,
    RtspParser, RtspRequest, RtspResponse, RtspTransport,
};
pub use sdp::{
    MAX_BASE64_INPUT_BYTES, MAX_SDP_LINES, SdpError, SdpMedia, SdpSession, decode_base64,
    parse_sdp, parse_sdp_bytes,
};
