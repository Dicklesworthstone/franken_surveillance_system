#![forbid(unsafe_code)]
//! Bounded original-byte ingress from a caller-owned Asupersync TCP stream.
//!
//! A network read is admitted against the canonical task's scoped media and
//! network grants and conservatively charged before it is polled. Read bytes
//! remain in this owner until moved to the caller as a source chunk. The
//! adapter does not bind or authenticate a peer, make data durable, parse a
//! protocol, start background work, or supply an idle timer. The enclosing
//! runtime owner must supervise deadlines, cancellation, and reconciliation.

use std::{fmt, future::poll_fn, io, pin::Pin, task::Poll};

use asupersync::{
    Cx,
    io::{AsyncRead, ReadBuf},
    net::TcpStream,
};
use fss_core::{BudgetVector, RuntimeGrant, TimestampNs};

use crate::execution::{TaskBinding, TaskCx};

/// Maximum buffered original bytes per read.
pub const MAX_CHUNK_BYTES: usize = 64 * 1024;
const MAX_RESOURCE_BYTES: usize = 1024;

/// Payload-free ingress refusals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngressError {
    /// Invalid byte limits or resource name.
    Configuration,
    /// Memory could not be reserved without discarding pending source bytes.
    Allocation,
    /// The canonical owner refused an active task, grant, deadline, or budget check.
    Authority,
    /// The canonical byte allowances cannot admit even one byte.
    BudgetExhausted,
    /// The explicit Asupersync context refused its cancellation checkpoint.
    Cancelled,
    /// The caller must move the prior source chunk before another read.
    PendingChunk,
    /// The socket returned an error. No camera or media bytes are included.
    Io(io::ErrorKind),
    /// The source was retired after an I/O error.
    Stopped,
}

impl fmt::Display for IngressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TCP source ingress refusal: {self:?}")
    }
}
impl std::error::Error for IngressError {}

/// Local outcome of one admitted socket read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Receive {
    /// Original bytes are held by the owner and must be moved with `take_chunk`.
    Data {
        /// Offset from the beginning of this local connection.
        offset: u64,
        /// Number of bytes held; always nonzero.
        len: usize,
    },
    /// The TCP peer closed its send side. This is not proof of source continuity.
    Eof,
    /// The caller's finite per-connection byte limit was reached.
    LimitReached,
}

/// Original bytes moved out of the read owner, not a durable-custody receipt.
#[must_use]
#[derive(Eq, PartialEq)]
pub struct SourceChunk {
    offset: u64,
    bytes: Vec<u8>,
}
impl SourceChunk {
    /// Offset within this one TCP connection.
    pub fn offset(&self) -> u64 {
        self.offset
    }
    /// Exact unmodified bytes returned by the socket.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Move the exact original bytes to the next owner.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
impl fmt::Debug for SourceChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SourceChunk")
            .field("offset", &self.offset)
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// The fate of a source owner, without a claim about remote state or durability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndState {
    /// The owner stopped before observing a terminal socket event.
    Open,
    /// The peer closed its send side.
    Eof,
    /// The configured connection byte limit was reached.
    LimitReached,
    /// An I/O error fenced the stream.
    Io(io::ErrorKind),
}

/// Facts and any untransferred bytes returned when the source owner is retired.
#[must_use]
#[derive(Debug)]
pub struct Retirement {
    /// Terminal observation or explicit early retirement.
    pub state: EndState,
    /// Total bytes returned by the socket within this connection.
    pub received: u64,
    /// A chunk the caller had not yet moved out, if any.
    pub pending: Option<SourceChunk>,
    /// Conservatively charged read capacity outstanding at retirement.
    pub reserved_bytes: usize,
}

/// Single-connection source owner. It never interprets or logs the bytes.
pub struct TcpIngress {
    stream: TcpStream,
    buffer: Vec<u8>,
    chunk_bytes: usize,
    max_total_bytes: u64,
    resource: String,
    owner: Option<TaskBinding>,
    received: u64,
    pending: Option<(u64, usize)>,
    reserved: usize,
    state: EndState,
}

impl fmt::Debug for TcpIngress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpIngress")
            .field("received", &self.received)
            .field("pending", &self.pending)
            .field("reserved", &self.reserved)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl TcpIngress {
    /// Take ownership of an already accepted stream under explicit finite bounds.
    /// The caller remains responsible for listener authority, routing and peer identity.
    pub fn new(
        stream: TcpStream,
        resource: &str,
        chunk_bytes: usize,
        max_total_bytes: u64,
    ) -> Result<Self, IngressError> {
        if !(1..=MAX_CHUNK_BYTES).contains(&chunk_bytes)
            || max_total_bytes == 0
            || resource.is_empty()
            || resource.len() > MAX_RESOURCE_BYTES
        {
            return Err(IngressError::Configuration);
        }
        let buffer = allocate_buffer(chunk_bytes)?;
        Ok(Self {
            stream,
            buffer,
            chunk_bytes,
            max_total_bytes,
            resource: resource.to_owned(),
            owner: None,
            received: 0,
            pending: None,
            reserved: 0,
            state: EndState::Open,
        })
    }

    /// Borrow the currently owned source chunk, if any.
    pub fn pending_bytes(&self) -> Option<&[u8]> {
        self.pending.map(|(_, len)| &self.buffer[..len])
    }

    /// Move the source chunk out only after a replacement buffer is reserved.
    /// This is an ownership transfer, not proof of persisted source custody.
    pub fn take_chunk(&mut self) -> Result<Option<SourceChunk>, IngressError> {
        let Some((offset, len)) = self.pending else {
            return Ok(None);
        };
        let replacement = allocate_buffer(self.chunk_bytes)?;
        let mut bytes = std::mem::replace(&mut self.buffer, replacement);
        bytes.truncate(len);
        self.pending = None;
        Ok(Some(SourceChunk { offset, bytes }))
    }

    /// Receive one bounded chunk into this owner's buffer.
    ///
    /// `runtime_cx` must be the executing runtime task's own context. The
    /// caller must supply a clock observation in the canonical task's clock
    /// domain and supervise any idle timeout. At most one pending chunk exists.
    /// A dropped pending read retains its prepaid capacity for a retry; bytes
    /// returned by the underlying TCP poll are committed to this owner before
    /// the future yields `Ready`. A completed read does not establish custody.
    pub async fn receive(
        &mut self,
        owner: &TaskCx<'_>,
        runtime_cx: &Cx,
        now: TimestampNs,
    ) -> Result<Receive, IngressError> {
        if self.pending.is_some() {
            return Err(IngressError::PendingChunk);
        }
        match self.state {
            EndState::Eof => return Ok(Receive::Eof),
            EndState::LimitReached => return Ok(Receive::LimitReached),
            EndState::Io(_) => return Err(IngressError::Stopped),
            EndState::Open => {}
        }
        runtime_cx
            .checkpoint()
            .map_err(|_| IngressError::Cancelled)?;
        let binding = owner.binding().map_err(|_| IngressError::Authority)?;
        if self
            .owner
            .as_ref()
            .is_some_and(|current| current != &binding)
        {
            return Err(IngressError::Authority);
        }
        owner
            .checkpoint_for(
                RuntimeGrant::ReadMedia,
                &self.resource,
                now,
                &BudgetVector::ZERO,
            )
            .map_err(|_| IngressError::Authority)?;
        if self.received == self.max_total_bytes {
            self.state = EndState::LimitReached;
            return Ok(Receive::LimitReached);
        }
        let capacity = if self.reserved != 0 {
            owner
                .checkpoint_for(
                    RuntimeGrant::AdapterNet,
                    &self.resource,
                    now,
                    &BudgetVector::ZERO,
                )
                .map_err(|_| IngressError::Authority)?;
            self.reserved
        } else {
            let available = owner
                .remaining_budget()
                .map_err(|_| IngressError::Authority)?;
            let limit = (self.chunk_bytes as u64)
                .min(self.max_total_bytes - self.received)
                .min(available.bytes)
                .min(available.network_bytes);
            if limit == 0 {
                return Err(IngressError::BudgetExhausted);
            }
            let capacity = usize::try_from(limit).map_err(|_| IngressError::Configuration)?;
            let mut cost = BudgetVector::ZERO;
            cost.bytes = limit;
            cost.network_bytes = limit;
            owner
                .checkpoint_for(RuntimeGrant::AdapterNet, &self.resource, now, &cost)
                .map_err(|_| IngressError::Authority)?;
            self.reserved = capacity;
            capacity
        };
        self.owner = Some(binding);
        poll_fn(|task| {
            if runtime_cx.checkpoint().is_err() {
                return Poll::Ready(Err(IngressError::Cancelled));
            }
            let mut buffer = ReadBuf::new(&mut self.buffer[..capacity]);
            match Pin::new(&mut self.stream).poll_read(task, &mut buffer) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(error)) => {
                    self.reserved = 0;
                    self.state = EndState::Io(error.kind());
                    Poll::Ready(Err(IngressError::Io(error.kind())))
                }
                Poll::Ready(Ok(())) => {
                    let len = buffer.filled().len();
                    self.reserved = 0;
                    if len == 0 {
                        self.state = EndState::Eof;
                        Poll::Ready(Ok(Receive::Eof))
                    } else {
                        let offset = self.received;
                        self.received += len as u64;
                        self.pending = Some((offset, len));
                        Poll::Ready(Ok(Receive::Data { offset, len }))
                    }
                }
            }
        })
        .await
    }

    /// Close this local owner and return any bytes not yet transferred.
    pub fn retire(mut self) -> Retirement {
        let pending = self.pending.take().map(|(offset, len)| {
            self.buffer.truncate(len);
            SourceChunk {
                offset,
                bytes: std::mem::take(&mut self.buffer),
            }
        });
        Retirement {
            state: self.state,
            received: self.received,
            pending,
            reserved_bytes: self.reserved,
        }
    }
}

fn allocate_buffer(size: usize) -> Result<Vec<u8>, IngressError> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(size)
        .map_err(|_| IngressError::Allocation)?;
    buffer.resize(size, 0);
    Ok(buffer)
}
