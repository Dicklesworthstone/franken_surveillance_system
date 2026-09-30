#![forbid(unsafe_code)]
//! Versioned bounded metadata. Diagnostic text is uninterpreted and never drives retry policy.

use super::{HistoryError, ReconnectHistoryPin, sha};
use crate::ingest::http_archive::{HttpWirePin, HttpWireScope};
use crate::ingest::http_camera::HttpCameraTotals;
use crate::ingest::http_reconnect::{HttpReconnectOutcome, HttpReconnectStop};
use crate::ingest::http_reconnect_recording::HttpReconnectBoundary;
use fss_codec_mjpeg::stream::StreamBasis;
use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest};

pub(super) const KIND: &str = "http_reconnect_boundary_v1";
pub(super) const DOMAIN: &str = "fss.http_reconnect_boundary.v1";
pub(super) const MAX_METADATA: usize = 2048;
const MAGIC: &[u8] = b"FSSHRB01";

/// Native observation class, not a claim about physical coverage or a replay EOF capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundaryOutcome {
    /// The native source reported HTTP AND MIME completion.
    NativeComplete,
    /// Setup failed; the native connector reports whether TCP was attempted.
    ConnectFailed {
        /// Whether the native connector attempted TCP, not a successful HTTP request.
        attempted: bool,
    },
    /// An established source reported a terminal failure.
    SourceFailed,
}
impl BoundaryOutcome {
    /// Stable schema spelling, independent of Rust debug formatting.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NativeComplete => "native_complete",
            Self::ConnectFailed { .. } => "connect_failed",
            Self::SourceFailed => "source_failed",
        }
    }
}

/// Immutable observation retained by the local archive writer, constructed from a native barrier.
/// A cold load verifies storage/canonical custody, not the honesty of a foreign archive writer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchivedReconnectBoundary {
    pub(super) session: ContentDigest,
    pub(super) prior: Option<ReconnectHistoryPin>,
    pub(super) connection: u32,
    pub(super) scope: HttpWireScope,
    pub(super) prefix: HttpWirePin,
    pub(super) outcome: BoundaryOutcome,
    pub(super) diagnostic: String,
    pub(super) totals: HttpCameraTotals,
    pub(super) admitted_ns: u64,
    pub(super) next_source: Option<StreamBasis>,
    pub(super) retry_at_ns: Option<u64>,
    pub(super) stop: Option<HttpReconnectStop>,
}
impl ArchivedReconnectBoundary {
    /// Exact acquisition plan identity named by this history.
    pub fn session(&self) -> ContentDigest {
        self.session
    }
    /// Exact predecessor, absent only on the first connection.
    pub fn prior(&self) -> Option<ReconnectHistoryPin> {
        self.prior
    }
    /// One-based native connection ordinal, including refused connection submissions.
    pub fn connection(&self) -> u32 {
        self.connection
    }
    /// Original source generation, raw retention scope and receive-clock interpretation.
    pub fn scope(&self) -> HttpWireScope {
        self.scope
    }
    /// Complete original-byte prefix of this ended connection, possibly empty.
    pub fn prefix(&self) -> HttpWirePin {
        self.prefix
    }
    /// Native reported terminal class, never physical continuity or an effect grant.
    pub fn outcome(&self) -> BoundaryOutcome {
        self.outcome
    }
    /// Payload-free original error text, preserved verbatim as UNINTERPRETED diagnostic data.
    /// Consumers must not parse this string to infer retry permission or a stable error enum.
    pub fn diagnostic(&self) -> &str {
        &self.diagnostic
    }
    /// Local connection counters, including failed progress, not remote acknowledgements.
    pub fn totals(&self) -> HttpCameraTotals {
        self.totals
    }
    /// Native owner admission time, not camera capture time.
    pub fn admitted_ns(&self) -> u64 {
        self.admitted_ns
    }
    /// Reserved next source, NOT evidence that another connection actually occurred.
    pub fn next_source(&self) -> Option<StreamBasis> {
        self.next_source
    }
    /// Earliest admitted retry time within this frozen native plan.
    pub fn retry_at_ns(&self) -> Option<u64> {
        self.retry_at_ns
    }
    /// Native stop reason, absent precisely when a next source and backoff were reserved.
    pub fn stop(&self) -> Option<HttpReconnectStop> {
        self.stop
    }

    pub(super) fn from_native(
        session: ContentDigest,
        prior: Option<ReconnectHistoryPin>,
        scope: HttpWireScope,
        native: HttpReconnectBoundary,
    ) -> Result<Self, HistoryError> {
        let receipt = native.source;
        if receipt.source != scope.stream {
            return Err(HistoryError::Mismatch);
        }
        let (outcome, diagnostic) = match receipt.outcome {
            HttpReconnectOutcome::Complete => (BoundaryOutcome::NativeComplete, String::new()),
            HttpReconnectOutcome::ConnectFailed { reason, attempted } => (
                BoundaryOutcome::ConnectFailed { attempted },
                reason.to_string(),
            ),
            HttpReconnectOutcome::SourceFailed(reason) => {
                (BoundaryOutcome::SourceFailed, reason.to_string())
            }
        };
        let value = Self {
            session,
            prior,
            scope,
            connection: receipt.connection,
            prefix: native.prefix,
            outcome,
            diagnostic,
            totals: receipt.totals,
            admitted_ns: receipt.admitted_ns,
            next_source: receipt.next_source,
            retry_at_ns: receipt.retry_at_ns,
            stop: receipt.stop,
        };
        value.validate()?;
        Ok(value)
    }
    pub(super) fn validate(&self) -> Result<(), HistoryError> {
        let scope_digest = self.scope.digest()?;
        let p = self.prefix;
        if !sha(self.session)
            || !(1..=32).contains(&self.connection)
            || self.diagnostic.len() > 512
            || !self.diagnostic.is_ascii()
            || self.diagnostic.bytes().any(|b| b.is_ascii_control())
            || (self.outcome == BoundaryOutcome::NativeComplete) != self.diagnostic.is_empty()
            || p.scope != scope_digest
            || !sha(p.head)
            || p.reads > 4096
            || p.bytes > 256 * 1024 * 1024
            || p.reads > p.bytes
            || p.bytes > p.reads * 65536
            || self.totals.received_bytes != p.bytes
            || self.totals.read_calls < p.reads
            || (p.reads == 0 && (p.bytes != 0 || p.head != scope_digest))
            || (p.reads != 0 && p.head == scope_digest)
            || (self.connection == 1) != self.prior.is_none()
        {
            return Err(HistoryError::Metadata);
        }
        if let Some(prior) = self.prior {
            prior.validate()?;
            if prior.session != self.session || prior.connections + 1 != self.connection {
                return Err(HistoryError::Mismatch);
            }
        }
        if self.outcome == BoundaryOutcome::NativeComplete
            && (p.reads == 0 || self.totals.sent_bytes == 0 || self.totals.write_calls == 0)
        {
            return Err(HistoryError::Metadata);
        }
        if matches!(self.outcome, BoundaryOutcome::ConnectFailed { .. })
            && self.totals != HttpCameraTotals::default()
        {
            return Err(HistoryError::Metadata);
        }
        match (self.next_source, self.retry_at_ns, self.stop) {
            (Some(next), Some(retry), None)
                if self.connection < 32
                    && next.source == self.scope.stream.source
                    && next.generation > self.scope.stream.generation
                    && retry > self.admitted_ns => {}
            (None, None, Some(_)) => {}
            _ => return Err(HistoryError::Metadata),
        }
        if self.stop == Some(HttpReconnectStop::Complete)
            && self.outcome != BoundaryOutcome::NativeComplete
        {
            return Err(HistoryError::Metadata);
        }
        Ok(())
    }
    pub(super) fn follows(&self, prior: &Self) -> Result<(), HistoryError> {
        if self.session != prior.session
            || self.connection != prior.connection + 1
            || prior.next_source != Some(self.scope.stream)
            || prior.stop.is_some()
            || prior
                .retry_at_ns
                .is_none_or(|retry| self.admitted_ns < retry)
        {
            return Err(HistoryError::Mismatch);
        }
        Ok(())
    }
    pub(super) fn encode(&self) -> Result<Vec<u8>, HistoryError> {
        self.validate()?;
        let mut e = CanonicalEncoder::new();
        e.bytes(MAGIC);
        e.u32(1);
        e.text(DOMAIN);
        e.digest(self.session);
        e.u32(self.connection);
        match self.prior {
            None => e.u8(0),
            Some(p) => {
                e.u8(1);
                e.digest(p.root);
            }
        }
        e.digest(ContentDigest::sha256(
            b"original-source-no-coverage-no-resume-authority:v1",
        ));
        e.digest(crate_digest(self.scope.stream.source));
        e.u64(self.scope.stream.generation);
        e.digest(crate_digest(self.scope.receive_clock));
        e.digest(crate_digest(self.scope.retention_evidence));
        e.digest(self.prefix.scope);
        e.digest(self.prefix.head);
        e.u64(self.prefix.reads);
        e.u64(self.prefix.bytes);
        match self.outcome {
            BoundaryOutcome::NativeComplete => e.u8(0),
            BoundaryOutcome::ConnectFailed { attempted } => {
                e.u8(1);
                e.bool(attempted);
            }
            BoundaryOutcome::SourceFailed => e.u8(2),
        }
        e.text(&self.diagnostic);
        for n in [
            self.totals.sent_bytes,
            self.totals.received_bytes,
            self.totals.read_calls,
            self.totals.write_calls,
            self.totals.frames,
        ] {
            e.u64(n);
        }
        e.bool(self.totals.peer_eof);
        e.u64(self.admitted_ns);
        match (self.next_source, self.retry_at_ns) {
            (Some(next), Some(retry)) => {
                e.u8(1);
                e.digest(crate_digest(next.source));
                e.u64(next.generation);
                e.u64(retry);
            }
            _ => e.u8(0),
        }
        e.u8(match self.stop {
            None => 0,
            Some(HttpReconnectStop::Complete) => 1,
            Some(HttpReconnectStop::NotRetryable) => 2,
            Some(HttpReconnectStop::ConnectionsExhausted) => 3,
            Some(HttpReconnectStop::FramingWorkExhausted) => 4,
            Some(HttpReconnectStop::Deadline) => 5,
        });
        let bytes = e.finish();
        if bytes.len() > MAX_METADATA {
            return Err(HistoryError::Limit);
        }
        Ok(bytes)
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, HistoryError> {
        if bytes.len() > MAX_METADATA {
            return Err(HistoryError::Limit);
        }
        let invalid = |_| HistoryError::Metadata;
        let mut d = CanonicalDecoder::new(bytes);
        if d.bytes().map_err(invalid)? != MAGIC
            || d.u32().map_err(invalid)? != 1
            || d.text().map_err(invalid)? != DOMAIN
        {
            return Err(HistoryError::Metadata);
        }
        let session = d.digest().map_err(invalid)?;
        let connection = d.u32().map_err(invalid)?;
        let prior = match d.u8().map_err(invalid)? {
            0 => None,
            1 => Some(ReconnectHistoryPin {
                session,
                root: d.digest().map_err(invalid)?,
                connections: connection.checked_sub(1).ok_or(HistoryError::Metadata)?,
            }),
            _ => return Err(HistoryError::Metadata),
        };
        if d.digest().map_err(invalid)?
            != ContentDigest::sha256(b"original-source-no-coverage-no-resume-authority:v1")
        {
            return Err(HistoryError::Metadata);
        }
        let raw_digest = |d: &mut CanonicalDecoder<'_>| -> Result<[u8; 32], HistoryError> {
            let digest = d.digest().map_err(invalid)?;
            if !sha(digest) {
                return Err(HistoryError::Metadata);
            }
            Ok(digest.bytes())
        };
        let scope = HttpWireScope {
            stream: StreamBasis {
                source: raw_digest(&mut d)?,
                generation: d.u64().map_err(invalid)?,
            },
            receive_clock: raw_digest(&mut d)?,
            retention_evidence: raw_digest(&mut d)?,
        };
        let prefix = HttpWirePin {
            scope: d.digest().map_err(invalid)?,
            head: d.digest().map_err(invalid)?,
            reads: d.u64().map_err(invalid)?,
            bytes: d.u64().map_err(invalid)?,
        };
        let outcome = match d.u8().map_err(invalid)? {
            0 => BoundaryOutcome::NativeComplete,
            1 => BoundaryOutcome::ConnectFailed {
                attempted: d.bool().map_err(invalid)?,
            },
            2 => BoundaryOutcome::SourceFailed,
            _ => return Err(HistoryError::Metadata),
        };
        let diagnostic = d.text().map_err(invalid)?.to_owned();
        let totals = HttpCameraTotals {
            sent_bytes: d.u64().map_err(invalid)?,
            received_bytes: d.u64().map_err(invalid)?,
            read_calls: d.u64().map_err(invalid)?,
            write_calls: d.u64().map_err(invalid)?,
            frames: d.u64().map_err(invalid)?,
            peer_eof: d.bool().map_err(invalid)?,
        };
        let admitted_ns = d.u64().map_err(invalid)?;
        let (next_source, retry_at_ns) = match d.u8().map_err(invalid)? {
            0 => (None, None),
            1 => (
                Some(StreamBasis {
                    source: raw_digest(&mut d)?,
                    generation: d.u64().map_err(invalid)?,
                }),
                Some(d.u64().map_err(invalid)?),
            ),
            _ => return Err(HistoryError::Metadata),
        };
        let stop = match d.u8().map_err(invalid)? {
            0 => None,
            1 => Some(HttpReconnectStop::Complete),
            2 => Some(HttpReconnectStop::NotRetryable),
            3 => Some(HttpReconnectStop::ConnectionsExhausted),
            4 => Some(HttpReconnectStop::FramingWorkExhausted),
            5 => Some(HttpReconnectStop::Deadline),
            _ => return Err(HistoryError::Metadata),
        };
        d.ensure_finished().map_err(invalid)?;
        let value = Self {
            session,
            prior,
            connection,
            scope,
            prefix,
            outcome,
            diagnostic,
            totals,
            admitted_ns,
            next_source,
            retry_at_ns,
            stop,
        };
        value.validate()?;
        if value.encode()? != bytes {
            return Err(HistoryError::Metadata);
        }
        Ok(value)
    }
}
fn crate_digest(bytes: [u8; 32]) -> ContentDigest {
    ContentDigest::new(fss_core::DigestAlgorithm::Sha256, bytes)
}
