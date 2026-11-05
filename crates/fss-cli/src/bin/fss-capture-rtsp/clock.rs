#![forbid(unsafe_code)]
//! Capture-owned clock observations and a root-last view over durable originals.
//!
//! The transport's pre-read coordinate is retained in every source packet. A
//! successful read has both pre- and post-I/O authority callbacks with that same
//! coordinate; the later bracket encloses its actual native admission. Polls
//! without bytes have no post callback and cannot supply a completed bracket.

use std::collections::BTreeMap;
use std::time::Duration;

use fss_cli::native_clock::{ClockIo, MAX_NETWORK_BYTES, SynchronizedClock};
use fss_core::ContentDigest;
use fss_publication::SlotName;
use fss_reference::rtsp::recording::PreparedRecording;
use fss_reference::rtsp::recording::hevc::PreparedHevcRecording;
use fss_reference::rtsp::recording_clock::{
    ClockWindow, MAX_CLOCK_BRACKETS, MAX_CLOCK_WINDOWS, ReceiveClockBracket, RecordingClockCodec,
    RecordingClockIndex,
};
use fss_reference::rtsp::tcp::TcpOperation;
use fss_reference::site::clock::HostClockSample;

use super::{Failure, Options, Owner};

pub(super) struct CaptureClockIo<'a, 'b, 'task>(pub(super) &'a Owner<'b, 'task>);
impl ClockIo for CaptureClockIo<'_, '_, '_> {
    fn now(&self) -> Result<u64, &'static str> {
        if self.0.drain_deadline.get().is_some() {
            return Err(Failure::Clock.code());
        }
        let now = self
            .0
            .clock
            .now(self.0.task, false)
            .map_err(Failure::code)?;
        if now >= self.0.live_deadline {
            return Err(Failure::Deadline.code());
        }
        Ok(now)
    }

    fn network_admit(&self) -> Result<(), &'static str> {
        self.now()?;
        self.0
            .clock
            .clock_network(self.0.task, self.0.resources)
            .map_err(Failure::code)?;
        self.now()?;
        Ok(())
    }

    fn network_bytes(&self, bytes: u64) -> Result<(), &'static str> {
        // CaptureRuntime prepaid this exact independent UDP ceiling. Preserve
        // actual accepted bytes before the post-charge authority check.
        let total = self
            .0
            .clock_network_bytes
            .get()
            .checked_add(bytes)
            .filter(|total| *total <= MAX_NETWORK_BYTES)
            .ok_or(Failure::WorkBudget.code())?;
        self.0.clock_network_bytes.set(total);
        self.network_admit()
    }

    fn wait(&self, deadline_ns: u64) -> Result<(), &'static str> {
        let now = self.now()?;
        if now >= deadline_ns {
            return Err(Failure::Deadline.code());
        }
        self.network_admit()?;
        std::thread::sleep(Duration::from_nanos((deadline_ns - now).min(1_000_000)));
        self.network_admit()
    }
}

struct ReadObservation {
    completed: HostClockSample,
    callbacks: u64,
}

pub(super) struct CaptureClock {
    clock: SynchronizedClock,
    reads: BTreeMap<u64, ReadObservation>,
    pending: Option<ClockWindow>,
    durable: Vec<ClockWindow>,
    terminal: Option<HostClockSample>,
    failed: bool,
    interrupted_network: bool,
}
impl CaptureClock {
    pub(super) fn begin(options: &Options, owner: &Owner<'_, '_>) -> Result<Self, Failure> {
        let peer = options.node_clock.ok_or(Failure::State)?.peer;
        Ok(Self {
            clock: SynchronizedClock::begin(peer, options.timeout_ns, &CaptureClockIo(owner))
                .map_err(|_| Failure::Clock)?,
            reads: BTreeMap::new(),
            pending: None,
            durable: Vec::new(),
            terminal: None,
            failed: false,
            interrupted_network: false,
        })
    }

    pub(super) fn checkpoint(
        &mut self,
        operation: TcpOperation,
        admission_ns: u64,
        owner: &Owner<'_, '_>,
    ) -> Result<(), Failure> {
        let result = self.observe(operation, admission_ns, owner);
        if result.is_err() {
            self.failed = true;
            self.interrupted_network = true;
        }
        result
    }

    fn observe(
        &mut self,
        operation: TcpOperation,
        admission_ns: u64,
        owner: &Owner<'_, '_>,
    ) -> Result<(), Failure> {
        if self.failed || self.terminal.is_some() {
            return Err(Failure::Clock);
        }
        let completed = self
            .clock
            .sample(&CaptureClockIo(owner))
            .map_err(|_| Failure::Clock)?;
        if operation != TcpOperation::Read {
            return Ok(());
        }
        if admission_ns < self.clock.exchange().received_after.monotonic_after_ns
            || admission_ns > completed.monotonic_before_ns
        {
            return Err(Failure::Clock);
        }
        if let Some(existing) = self.reads.get_mut(&admission_ns) {
            existing.callbacks = existing.callbacks.checked_add(1).ok_or(Failure::Clock)?;
            existing.completed = completed;
        } else {
            if self.reads.len() >= MAX_CLOCK_BRACKETS {
                return Err(Failure::WorkBudget);
            }
            self.reads.insert(
                admission_ns,
                ReadObservation {
                    completed,
                    callbacks: 1,
                },
            );
        }
        Ok(())
    }

    /// Closing network intake freezes this sample before storage-only drain.
    /// A clock refusal cannot prevent the existing source-custody drain.
    pub(super) fn freeze(&mut self, owner: &Owner<'_, '_>) {
        if self.failed || self.terminal.is_some() {
            return;
        }
        match self.clock.finish(&CaptureClockIo(owner)) {
            Ok(terminal) => self.terminal = Some(terminal),
            Err(_) => self.failed = true,
        }
    }

    fn accept(&mut self, window: ClockWindow) -> Result<(), Failure> {
        if self.failed {
            return Ok(());
        }
        if self.pending.is_some() || self.durable.len() >= MAX_CLOCK_WINDOWS {
            self.failed = true;
            return Err(Failure::Clock);
        }
        for admission in window.packet_admissions() {
            if self
                .reads
                .get(admission)
                .is_none_or(|read| read.callbacks < 2)
            {
                self.failed = true;
                return Err(Failure::Clock);
            }
        }
        self.pending = Some(window);
        Ok(())
    }

    pub(super) fn accept_avc(
        &mut self,
        slot: SlotName,
        recording: &PreparedRecording,
    ) -> Result<(), Failure> {
        let result = ClockWindow::from_avc(slot, recording)
            .map_err(|_| Failure::Clock)
            .and_then(|window| self.accept(window));
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub(super) fn accept_hevc(
        &mut self,
        slot: SlotName,
        recording: &PreparedHevcRecording,
    ) -> Result<(), Failure> {
        let result = ClockWindow::from_hevc(slot, recording)
            .map_err(|_| Failure::Clock)
            .and_then(|window| self.accept(window));
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub(super) fn durable(&mut self, root: ContentDigest) -> Result<(), Failure> {
        if self.failed {
            return Ok(());
        }
        let Some(window) = self.pending.take() else {
            self.failed = true;
            return Err(Failure::Clock);
        };
        if window.root() != root {
            self.failed = true;
            return Err(Failure::Clock);
        }
        self.durable.push(window);
        Ok(())
    }
    pub(super) fn failed(&self) -> bool {
        self.failed
    }
    pub(super) fn interrupted_network(&self) -> bool {
        self.interrupted_network
    }

    pub(super) fn prepare(
        &self,
        options: &Options,
        approval: ContentDigest,
    ) -> Result<RecordingClockIndex, Failure> {
        if self.failed || self.pending.is_some() || self.durable.is_empty() {
            return Err(Failure::Clock);
        }
        let brackets: Vec<_> = self
            .reads
            .iter()
            .filter(|(_, read)| read.callbacks >= 2)
            .map(|(&admission_ns, read)| ReceiveClockBracket {
                admission_ns,
                completed: read.completed,
            })
            .collect();
        RecordingClockIndex::prepare(
            options.catalog_scope().clone(),
            if options.codec() == "hevc" {
                RecordingClockCodec::Hevc
            } else {
                RecordingClockCodec::Avc
            },
            approval,
            self.clock.exchange(),
            self.terminal.ok_or(Failure::Clock)?,
            &brackets,
            &self.durable,
        )
        .map_err(|_| Failure::Clock)
    }
}
