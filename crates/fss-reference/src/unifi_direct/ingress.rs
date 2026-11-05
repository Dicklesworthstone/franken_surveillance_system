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
