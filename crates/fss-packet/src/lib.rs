#![forbid(unsafe_code)]
//! Bounded, dependency-free packet truth for owner-authorized media ingestion.
//!
//! This crate parses supplied wire bytes. It performs no I/O, authenticates no
//! sender, and does not turn packet acceptance into continuity or capture truth.
//! The owning adapter retains the original datagram and its stream generation.

pub mod avc;

mod continuity;
mod error;
mod h264;
mod h265;
mod h265_receiver;
mod receiver;
mod reorder;
mod rtcp;
mod rtp;
mod timing;

pub use error::{PacketError, PacketLimits};
pub use rtcp::{
    NtpTimestamp, ReceptionReport, ReportBlocks, RtcpCompound, RtcpMode, RtcpPacket, RtcpPackets,
    SenderReport,
};
pub use rtp::{HeaderExtension, RtpPacket};

pub use continuity::{
    ContinuityError, SequenceClass, SequenceObservation, SequenceStats, SequenceTracker, StreamKey,
};
pub use timing::{JitterEstimator, SenderReportClock, SenderTimeEstimate, arrival_ticks};

pub use h264::{
    FragmentDiscard, H264Depacketizer, H264Error, H264Failure, H264Limits, H264Mode, H264Output,
    H264Status, NalSourceSpan, NalUnit,
};
pub use h265::{
    H265Depacketizer, H265Error, H265Failure, H265FragmentDiscard, H265Limits, H265NalUnit,
    H265Output, H265SourceSpan, H265Status,
};
pub use h265_receiver::{
    H265ReceiveAdmission, H265ReceiveCancellation, H265ReceiveError, H265ReceivePoll, H265Receiver,
};
pub use receiver::{
    H264ReceiveAdmission, H264ReceiveCancellation, H264ReceiveError, H264ReceivePoll, H264Receiver,
};
pub use reorder::{
    OrderedRtpPacket, QueueDiscard, QueueDiscardReason, ReorderAdmission, ReorderDisposition,
    ReorderError, ReorderGap, ReorderGapReason, ReorderLimits, ReorderPoll, RtpReorderBuffer,
};
