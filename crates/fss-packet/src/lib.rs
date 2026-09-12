#![forbid(unsafe_code)]
//! Bounded, dependency-free packet truth for owner-authorized media ingestion.
//!
//! This crate parses supplied wire bytes. It performs no I/O, authenticates no
//! sender, and does not turn packet acceptance into continuity or capture truth.
//! The owning adapter retains the original datagram and its stream generation.

mod error;
mod rtcp;
mod rtp;

pub use error::{PacketError, PacketLimits};
pub use rtcp::{
    NtpTimestamp, ReceptionReport, ReportBlocks, RtcpCompound, RtcpMode, RtcpPacket,
    RtcpPackets, SenderReport,
};
pub use rtp::{HeaderExtension, RtpPacket};
