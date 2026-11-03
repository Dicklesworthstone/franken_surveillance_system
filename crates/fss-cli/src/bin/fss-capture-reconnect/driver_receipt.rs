#![forbid(unsafe_code)]
//! Bounded native observations for capture consumers; no transcript parsing or effect grant.

use fss_reference::http_reconnect_history::{ArchivedReconnectBoundary, ReconnectHistoryPin};
use fss_reference::ingest::http_archive::HttpWirePin;

use super::{Boundary, End, Failure, Options, Recording, Statistics};

/// An original-byte prefix acknowledged by the capture owner, possibly still unfinished.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CapturePrefix {
    pub(crate) generation: u64,
    pub(crate) pin: HttpWirePin,
    pub(crate) frames_taken: u64,
}

/// An exact native connection observation and the history root prepared for it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CaptureBoundary {
    pub(crate) observation: ArchivedReconnectBoundary,
    pub(crate) pin: ReconnectHistoryPin,
    pub(crate) released: bool,
}

/// Terminal presentation of this capture attempt, with at most one row per reserved generation.
/// A pin remains an expected custody handle; downstream native owners must reverify its graph.
#[derive(Clone, Debug)]
pub(crate) struct CaptureReceipt {
    pub(crate) request_satisfied: bool,
    pub(crate) error_code: Option<&'static str>,
    pub(crate) terminal_observed: bool,
    pub(crate) history_pin: Option<ReconnectHistoryPin>,
    pub(crate) pending_history: Option<(ReconnectHistoryPin, bool)>,
    pub(crate) pending_wire: Option<HttpWirePin>,
    pub(crate) prefixes: Vec<CapturePrefix>,
    /// Empty when durable history was not selected; native-only boundaries are not invented.
    pub(crate) boundaries: Vec<CaptureBoundary>,
    pub(crate) connections_started: u32,
    pub(crate) frames_taken: u64,
    pub(crate) received_bytes: u64,
    pub(crate) unpublished_received_bytes: u64,
    settled_history: Option<ReconnectHistoryPin>,
}

impl CaptureReceipt {
    /// The exact ended-history pin only when every started source reached a durable, released
    /// native boundary and there is no unfinished source or publication. This says nothing
    /// about physical coverage, acquisition success, or permission to consume the originals.
    /// In particular, a settled failed source can retain a history without satisfying the request.
    pub(crate) fn settled_history(&self) -> Option<ReconnectHistoryPin> {
        self.settled_history
    }

    pub(super) fn from_native(
        options: &Options,
        recording: &dyn Recording,
        stats: &Statistics,
        outcome: &Result<End, Failure>,
        terminal_observed: bool,
    ) -> Self {
        let history = recording.history();
        let native = recording.native();
        let totals = native.totals();
        let prefixes: Vec<_> = stats
            .prefixes
            .iter()
            .map(|(&generation, &pin)| CapturePrefix {
                generation,
                pin,
                frames_taken: stats.per_generation.get(&generation).copied().unwrap_or(0),
            })
            .collect();
        let durable_bytes = prefixes.iter().map(|prefix| prefix.pin.bytes).sum::<u64>();
        let mut receipt = Self {
            request_satisfied: outcome.is_ok(),
            error_code: outcome.as_ref().err().map(Failure::code),
            terminal_observed,
            history_pin: history.and_then(|history| history.history_pin()),
            pending_history: history.and_then(|history| {
                history
                    .pending_boundary()
                    .map(|pending| (pending.pin(), pending.published()))
            }),
            pending_wire: native.pending_wire_plan().map(|plan| plan.expected_pin()),
            prefixes,
            boundaries: stats
                .boundaries
                .iter()
                .filter_map(|(boundary, released)| match boundary {
                    Boundary::History(observation, pin) => Some(CaptureBoundary {
                        observation: observation.clone(),
                        pin: *pin,
                        released: *released,
                    }),
                    Boundary::Native(_) => None,
                })
                .collect(),
            connections_started: totals.slots_started,
            frames_taken: stats.frames,
            received_bytes: totals.received_bytes,
            unpublished_received_bytes: totals.received_bytes.saturating_sub(durable_bytes),
            settled_history: None,
        };
        if stats.decode_pending.is_none() && stats.boundaries.len() == receipt.boundaries.len() {
            receipt.settled_history = receipt.verify_settled(options, native.scope(), native.pin());
        }
        receipt
    }

    fn verify_settled(
        &self,
        options: &Options,
        current_scope: fss_reference::ingest::http_archive::HttpWireScope,
        current_prefix: HttpWirePin,
    ) -> Option<ReconnectHistoryPin> {
        let expected = self.history_pin?;
        let count = self.boundaries.len();
        if !self.terminal_observed
            || self.pending_history.is_some()
            || self.pending_wire.is_some()
            || self.unpublished_received_bytes != 0
            || count == 0
            || count > options.generations.len()
            || self.prefixes.len() != count
            || u32::try_from(count).ok()? != self.connections_started
            || self.connections_started != expected.connections
            || expected.session != options.approval()
        {
            return None;
        }
        let mut previous = None;
        let mut received_bytes = 0_u64;
        let mut frames_taken = 0_u64;
        for (index, (boundary, prefix)) in self.boundaries.iter().zip(&self.prefixes).enumerate() {
            let observation = &boundary.observation;
            let scope = observation.scope();
            let ordinal = u32::try_from(index).ok()?.checked_add(1)?;
            if !boundary.released
                || observation.session() != expected.session
                || observation.connection() != ordinal
                || observation.prior() != previous
                || boundary.pin.session != expected.session
                || boundary.pin.connections != ordinal
                || scope.stream.source != options.source.bytes()
                || scope.stream.generation != options.generations[index]
                || scope.receive_clock != options.receive_clock.bytes()
                || scope.retention_evidence != options.retention_evidence.bytes()
                || prefix.generation != scope.stream.generation
                || prefix.pin != observation.prefix()
                || observation.totals().received_bytes != prefix.pin.bytes
                || prefix.frames_taken > observation.totals().frames
                || (index + 1 == count) != observation.stop().is_some()
            {
                return None;
            }
            received_bytes = received_bytes.checked_add(prefix.pin.bytes)?;
            frames_taken = frames_taken.checked_add(prefix.frames_taken)?;
            previous = Some(boundary.pin);
        }
        let last = self.boundaries.last()?;
        if previous != Some(expected)
            || current_scope != last.observation.scope()
            || current_prefix != last.observation.prefix()
            || received_bytes != self.received_bytes
            || frames_taken != self.frames_taken
        {
            return None;
        }
        Some(expected)
    }
}
