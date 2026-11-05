#![forbid(unsafe_code)]
//! A bounded, owner-driven TCP-to-extended-FLV source framing boundary.
//!
//! This composes the existing Asupersync TCP byte owner and pure FLV framer.
//! It does not create a listener, authenticate the peer, prove trailer
//! boundaries, retain evidence durably, decode media, or control a camera.

use std::fmt;

use asupersync::Cx;
use fss_core::{BudgetVector, TimestampNs};
use fss_packet::extended_flv::stream::{self, Framer, Next, SourceRecord};
use fss_packet::extended_flv::{self, avc, track};
use fss_runtime::{
    execution::TaskCx,
    tcp_ingress::{self, Receive, SourceChunk, TcpIngress},
};

/// Payload-free refusal. An owning caller may retire the attempt to recover bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The explicit runtime or canonical task checkpoint refused progress.
    CancelledOrUnauthorized,
    /// TCP source admission or reading failed.
    Source(tcp_ingress::IngressError),
    /// Incremental structural framing refused the buffered source.
    Framing(stream::Error),
    /// An internal original-stream offset overflowed.
    OffsetOverflow,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "direct UniFi source refusal: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Bounded progress from at most one socket read and one appended source prefix.
#[derive(Debug, Eq, PartialEq)]
pub enum Step {
    /// One original-byte record; its structural candidate is not a custody proof.
    Record(SourceRecord),
    /// Original bytes were buffered but no complete record was available.
    Progress {
        /// Number of original bytes appended in this step.
        appended: usize,
    },
    /// The TCP peer closed its send side; unparsed tail is returned by retirement.
    Eof,
    /// The configured per-connection input bound was reached.
    LimitReached,
}

/// A socket chunk partly copied into the framer. Prefix bytes may overlap
/// framer records or its remainder; the suffix has not been appended.
#[must_use]
#[derive(Debug)]
pub struct BufferedChunk {
    /// Exact original TCP chunk, with connection-relative start offset.
    pub source: SourceChunk,
    /// Prefix already appended to the framer; `source.bytes()[appended..]` is pending.
    pub appended: usize,
}

/// Every remaining owner-held source byte and local terminal observation.
#[must_use]
#[derive(Debug)]
pub struct Retirement {
    /// TCP owner's state, including any untransferred socket chunk.
    pub source: tcp_ingress::Retirement,
    /// Unparsed exact bytes currently in the framer.
    pub framing: stream::Remainder,
    /// Original socket chunk and its appended prefix, if any.
    pub buffered: Option<BufferedChunk>,
}

/// One camera-stream attempt, holding both source and framing state.
pub struct DirectIngress {
    source: TcpIngress,
    framer: Framer,
    buffered: Option<BufferedChunk>,
}
impl fmt::Debug for DirectIngress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectIngress")
            .field("source", &self.source)
            .field("framer", &self.framer)
            .field("buffered", &self.buffered)
            .finish()
    }
}

impl DirectIngress {
    /// Compose already-constructed owners without starting any I/O.
    /// The caller must bind both to the same connection and stream generation.
    pub fn new(source: TcpIngress, framer: Framer) -> Self {
        Self {
            source,
            framer,
            buffered: None,
        }
    }

    /// Advance at most one socket read and one buffered-chunk append.
    ///
    /// The caller supplies the executing runtime task's context and the current
    /// observation in the canonical task's clock domain. The enclosing owner
    /// must supervise idle time, CPU, custody, authorization and cancellation.
    /// A returned record transfers original bytes but is not itself durable.
    pub async fn step(
        &mut self,
        owner: &TaskCx<'_>,
        runtime_cx: &Cx,
        now: TimestampNs,
    ) -> Result<Step, Error> {
        runtime_cx
            .checkpoint()
            .map_err(|_| Error::CancelledOrUnauthorized)?;
        owner
            .checkpoint(now, &BudgetVector::ZERO)
            .map_err(|_| Error::CancelledOrUnauthorized)?;
        if let Next::Record(record) = self.framer.take().map_err(Error::Framing)? {
            return Ok(Step::Record(record));
        }
        if self.buffered.is_none() && self.source.pending_bytes().is_some() {
            self.buffered = self
                .source
                .take_chunk()
                .map_err(Error::Source)?
                .map(|source| BufferedChunk {
                    source,
                    appended: 0,
                });
        }
        if self.buffered.is_none() {
            match self
                .source
                .receive(owner, runtime_cx, now)
                .await
                .map_err(Error::Source)?
            {
                Receive::Data { .. } => {
                    self.buffered =
                        self.source
                            .take_chunk()
                            .map_err(Error::Source)?
                            .map(|source| BufferedChunk {
                                source,
                                appended: 0,
                            });
                }
                Receive::Eof => return Ok(Step::Eof),
                Receive::LimitReached => return Ok(Step::LimitReached),
            }
        }
        let buffered = self
            .buffered
            .as_mut()
            .ok_or(Error::Source(tcp_ingress::IngressError::PendingChunk))?;
        let remaining = &buffered.source.bytes()[buffered.appended..];
        let appended = remaining.len().min(self.framer.remaining_capacity());
        if appended == 0 {
            return Err(Error::Framing(stream::Error::BufferLimit));
        }
        let offset = buffered
            .source
            .offset()
            .checked_add(buffered.appended as u64)
            .ok_or(Error::OffsetOverflow)?;
        self.framer
            .append(offset, &remaining[..appended])
            .map_err(Error::Framing)?;
        buffered.appended += appended;
        if buffered.appended == buffered.source.bytes().len() {
            self.buffered = None;
        }
        match self.framer.take().map_err(Error::Framing)? {
            Next::Record(record) => Ok(Step::Record(record)),
            Next::NeedMore => Ok(Step::Progress { appended }),
        }
    }

    /// Close both local owners and return every untransferred source byte.
    /// Buffered prefixes can overlap the framing remainder and emitted records.
    pub fn retire(self) -> Retirement {
        Retirement {
            source: self.source.retire(),
            framing: self.framer.retire(),
            buffered: self.buffered,
        }
    }
}

/// One source record and its AVC interpretation. The original remains owned by
/// the caller even when the interpretation is refused.
#[must_use]
#[derive(Debug)]
pub enum TrackedStep {
    /// An exact original record and its payload-free interpretation result.
    Record {
        /// Original source bytes; not a durable custody receipt.
        source: SourceRecord,
        /// Structural interpretation or the reason this track was fenced.
        interpretation: Result<track::Observation, track::Error>,
    },
    /// Bytes were buffered but a complete record is not yet available.
    Progress {
        /// Number of original bytes appended.
        appended: usize,
    },
    /// The TCP source closed; buffered source is returned by retirement.
    Eof,
    /// The configured connection byte limit was reached.
    LimitReached,
}

/// Payload-free refusal by a tracked source owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrackedError {
    /// The underlying owned source or framer refused progress.
    Ingress(Error),
    /// An earlier returned record could not be interpreted; no more input was read.
    TrackFenced,
}
impl fmt::Display for TrackedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tracked UniFi source refusal: {self:?}")
    }
}
impl std::error::Error for TrackedError {}

/// A single connection's ingress and source-relative AVC interpretation.
/// This owner neither authenticates the peer nor stores, decodes or muxes data.
pub struct TrackedIngress {
    ingress: DirectIngress,
    track: track::Track,
    fenced: bool,
}
impl fmt::Debug for TrackedIngress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrackedIngress")
            .field("ingress", &self.ingress)
            .field("track", &self.track)
            .field("fenced", &self.fenced)
            .finish()
    }
}
impl TrackedIngress {
    /// Attach a fresh track to the beginning of one caller-owned connection.
    /// The caller must use FLV limits compatible with the supplied framer and
    /// bind the enclosing connection to its authorized stream generation.
    pub fn new(
        ingress: DirectIngress,
        flv_limits: extended_flv::Limits,
        avc_limits: avc::Limits,
    ) -> Self {
        Self {
            ingress,
            track: track::Track::new(flv_limits, avc_limits),
            fenced: false,
        }
    }

    /// Advance the underlying source once and interpret at most one record.
    /// When interpretation fails the exact record is returned with the error;
    /// all further reads are fenced until this owner is retired.
    pub async fn step(
        &mut self,
        owner: &TaskCx<'_>,
        cx: &Cx,
        now: TimestampNs,
    ) -> Result<TrackedStep, TrackedError> {
        if self.fenced {
            return Err(TrackedError::TrackFenced);
        }
        Ok(
            match self
                .ingress
                .step(owner, cx, now)
                .await
                .map_err(TrackedError::Ingress)?
            {
                Step::Record(source) => {
                    let interpretation = self.track.observe(&source);
                    self.fenced = interpretation.is_err();
                    TrackedStep::Record {
                        source,
                        interpretation,
                    }
                }
                Step::Progress { appended } => TrackedStep::Progress { appended },
                Step::Eof => TrackedStep::Eof,
                Step::LimitReached => TrackedStep::LimitReached,
            },
        )
    }

    /// Return the underlying source's pending and unparsed bytes.
    pub fn retire(self) -> Retirement {
        self.ingress.retire()
    }
}
