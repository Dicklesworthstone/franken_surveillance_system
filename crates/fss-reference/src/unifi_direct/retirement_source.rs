#![forbid(unsafe_code)]
//! Transfer a retired pipeline's held bytes into ordered source records.
//!
//! This does not read the socket, publish objects, prove completeness, infer a
//! capture time, or turn an unfinished GOP into a completed video segment.

use asupersync::Cx;
use fss_container::flv_avc::SourceKey;
use fss_core::ContentDigest;
use fss_packet::extended_flv::stream::{Phase, RecordKind, SourceRecord, UnframedOrigin};
use fss_runtime::{execution::TaskCx, tcp_ingress::EndState};

use super::{
    av_worker, metered::MeteredClock, pipeline, recording::SourceDisposition, source_batch,
    source_coordinator::ArchiveAdmission, source_worker,
};

/// Why a retirement could not be safely decomposed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Source ranges overlap, overflow, or contradict the received-byte facts.
    /// The original pipeline tail also rejects internal gaps.
    Range,
    /// A held recorder record is not an eligible framed record.
    Record,
    /// A bounded allocation failed before ownership transfer.
    Allocation,
    /// Collector copies exceed the explicit record or byte cap.
    Limit,
}

/// The complete original retirement returned when planning refuses.
#[must_use]
pub struct Refusal {
    /// Payload-free refusal.
    pub reason: Error,
    /// Unchanged pipeline retirement and all its held bytes.
    pub retirement: pipeline::Retirement,
}

/// One exact held source range and its explicit retirement disposition.
#[must_use]
pub struct Item {
    /// Source bytes and untrusted connection-relative range.
    pub record: SourceRecord,
    /// Why the bytes were not included in a finished video segment.
    pub disposition: SourceDisposition,
}

/// Exact source records transferred together to one archive attempt.
#[must_use = "retain or return every original source item"]
pub struct Batch {
    items: Vec<Item>,
    bytes: usize,
}
impl Batch {
    pub(super) fn items(&self) -> &[Item] {
        &self.items
    }
    pub(super) fn bytes(&self) -> usize {
        self.bytes
    }
    /// Borrow the exact original records retained by this batch in source order.
    pub fn items_in_order(&self) -> impl ExactSizeIterator<Item = &Item> {
        self.items.iter()
    }
}

/// Ordered source custody and terminal facts, not a persistence receipt.
#[must_use = "archive or recover every held item"]
pub struct Plan {
    items: Vec<Item>,
    /// Local socket state, not a claim about unread or remote bytes.
    pub socket_state: EndState,
    /// Bytes actually received by this socket owner.
    pub received: u64,
    /// Socket read capacity still reserved at retirement.
    pub reserved_bytes: usize,
    /// Parser phase at retirement.
    pub framing_phase: Phase,
    /// Whether a selected earlier framing boundary was provisional.
    pub framing_provisional: bool,
    /// Whether the recorder had already fenced itself.
    pub recorder_fenced: bool,
    /// Audio observation still held separately, if any.
    pub pending_audio: Option<pipeline::AudioEvent>,
    /// First held byte offset, absent when no source bytes remain. The range
    /// between this and `end` can contain gaps after collector copies join it.
    pub start: Option<u64>,
    /// End offset of held bytes, absent when no source bytes remain; this is
    /// not a coverage or contiguity assertion.
    pub end: Option<u64>,
}

impl Plan {
    /// Check ordered ranges before consuming any original owner.
    pub fn new(retirement: pipeline::Retirement) -> Result<Self, Refusal> {
        let inspect = || -> Result<(Option<u64>, Option<u64>, usize), Error> {
            let mut start = None;
            let mut end = None;
            let mut count = 0usize;
            let mut add = |offset: u64, len: usize| -> Result<(), Error> {
                if len == 0 {
                    return Ok(());
                }
                let next = offset
                    .checked_add(u64::try_from(len).map_err(|_| Error::Range)?)
                    .ok_or(Error::Range)?;
                if end.is_some_and(|previous| previous != offset) {
                    return Err(Error::Range);
                }
                if start.is_none() {
                    start = Some(offset);
                }
                end = Some(next);
                count = count.checked_add(1).ok_or(Error::Range)?;
                Ok(())
            };
            let mut total = 0usize;
            for record in &retirement.recorder.pending {
                if matches!(
                    record.kind(),
                    RecordKind::Header | RecordKind::Unframed { .. }
                ) {
                    return Err(Error::Record);
                }
                total = total
                    .checked_add(record.bytes().len())
                    .ok_or(Error::Range)?;
                if record.bytes().is_empty() {
                    return Err(Error::Record);
                }
                add(record.offset(), record.bytes().len())?;
            }
            if total != retirement.recorder.source_bytes {
                return Err(Error::Range);
            }
            add(
                retirement.ingress.framing.offset,
                retirement.ingress.framing.bytes().len(),
            )?;
            if let Some(buffered) = &retirement.ingress.buffered {
                let len = buffered.source.bytes().len();
                if buffered.appended > len {
                    return Err(Error::Range);
                }
                let offset = buffered
                    .source
                    .offset()
                    .checked_add(buffered.appended as u64)
                    .ok_or(Error::Range)?;
                add(offset, len - buffered.appended)?;
            }
            if let Some(source) = &retirement.ingress.source.pending {
                add(source.offset(), source.bytes().len())?;
            }
            if end.is_some_and(|end| end != retirement.ingress.source.received) {
                return Err(Error::Range);
            }
            Ok((start, end, count))
        };
        let (start, end, count) = match inspect() {
            Ok(value) => value,
            Err(reason) => return Err(Refusal { reason, retirement }),
        };
        let mut items = Vec::new();
        if items.try_reserve_exact(count).is_err() {
            return Err(Refusal {
                reason: Error::Allocation,
                retirement,
            });
        }
        let pipeline::Retirement {
            ingress,
            recorder,
            pending_audio,
        } = retirement;
        let socket_state = ingress.source.state;
        let received = ingress.source.received;
        let reserved_bytes = ingress.source.reserved_bytes;
        let framing_phase = ingress.framing.phase;
        let framing_provisional = ingress.framing.provisional;
        let recorder_fenced = recorder.fenced;
        for record in recorder.pending {
            items.push(Item {
                record,
                disposition: SourceDisposition::Unclosed,
            });
        }
        let framing_offset = ingress.framing.offset;
        let framing = ingress.framing.into_bytes();
        if !framing.is_empty() {
            let record = SourceRecord::unframed(framing_offset, framing, UnframedOrigin::Framer)
                .unwrap_or_else(|_| unreachable!("source ranges validated"));
            items.push(Item {
                record,
                disposition: SourceDisposition::Unframed,
            });
        }
        if let Some(buffered) = ingress.buffered {
            let offset = buffered.source.offset() + buffered.appended as u64;
            let mut bytes = buffered.source.into_bytes();
            bytes.drain(..buffered.appended);
            if !bytes.is_empty() {
                let record = SourceRecord::unframed(offset, bytes, UnframedOrigin::BufferedSuffix)
                    .unwrap_or_else(|_| unreachable!("source ranges validated"));
                items.push(Item {
                    record,
                    disposition: SourceDisposition::Unframed,
                });
            }
        }
        if let Some(source) = ingress.source.pending {
            let offset = source.offset();
            let bytes = source.into_bytes();
            if !bytes.is_empty() {
                let record = SourceRecord::unframed(offset, bytes, UnframedOrigin::SocketPending)
                    .unwrap_or_else(|_| unreachable!("source ranges validated"));
                items.push(Item {
                    record,
                    disposition: SourceDisposition::Unframed,
                });
            }
        }
        items.reverse();
        Ok(Self {
            items,
            socket_state,
            received,
            reserved_bytes,
            framing_phase,
            framing_provisional,
            recorder_fenced,
            pending_audio,
            start,
            end,
        })
    }

    /// Number of remaining source ranges.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether all held ranges have been transferred.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Borrow the remaining exact ranges in source order without transferring custody.
    pub fn items_in_order(&self) -> impl ExactSizeIterator<Item = &Item> + Clone {
        self.items.iter().rev()
    }

    /// Copy collector-held originals into this retirement plan without
    /// consuming the collector. Original offsets and framing are preserved;
    /// copied lookahead witnesses and supplied AAC bytes are excluded. Gaps
    /// remain explicit and do not imply coverage. On refusal neither owner
    /// changes, and no copy has been published.
    pub fn include_collector_copies(
        &mut self,
        collector: &super::av_bootstrap::Collector,
    ) -> Result<usize, Error> {
        const MAX_COPIES: usize = 65_538;
        const MAX_COPY_BYTES: usize = 128 * 1024 * 1024;
        let count = collector.retained_source_records().count();
        if count > MAX_COPIES {
            return Err(Error::Limit);
        }
        if count == 0 {
            return Ok(0);
        }
        let total = count.checked_add(self.items.len()).ok_or(Error::Limit)?;
        if total > MAX_COPIES.saturating_mul(2).saturating_add(3) {
            return Err(Error::Limit);
        }
        let mut ranges = Vec::new();
        ranges
            .try_reserve_exact(total)
            .map_err(|_| Error::Allocation)?;
        let mut copy_bytes = 0usize;
        for record in collector.retained_source_records() {
            if record.bytes().is_empty()
                || matches!(
                    record.kind(),
                    RecordKind::Header | RecordKind::Unframed { .. }
                )
            {
                return Err(Error::Record);
            }
            copy_bytes = copy_bytes
                .checked_add(record.bytes().len())
                .ok_or(Error::Limit)?;
            if copy_bytes > MAX_COPY_BYTES {
                return Err(Error::Limit);
            }
            let end = record
                .offset()
                .checked_add(u64::try_from(record.bytes().len()).map_err(|_| Error::Range)?)
                .ok_or(Error::Range)?;
            if end > self.received {
                return Err(Error::Range);
            }
            ranges.push((record.offset(), end));
        }
        for item in &self.items {
            let end = item
                .record
                .offset()
                .checked_add(u64::try_from(item.record.bytes().len()).map_err(|_| Error::Range)?)
                .ok_or(Error::Range)?;
            ranges.push((item.record.offset(), end));
        }
        ranges.sort_unstable();
        if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
            return Err(Error::Range);
        }
        let mut copies = Vec::new();
        copies
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        for record in collector.retained_source_records() {
            copies.push(Item {
                record: record.try_duplicate().map_err(|_| Error::Allocation)?,
                disposition: SourceDisposition::BootstrapCopy,
            });
        }
        self.items
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        self.items.extend(copies);
        self.items
            .sort_unstable_by(|a, b| b.record.offset().cmp(&a.record.offset()));
        self.start = ranges.first().map(|range| range.0);
        self.end = ranges.last().map(|range| range.1);
        Ok(count)
    }

    fn take_batch(&mut self, max_records: usize, max_bytes: usize) -> Result<Option<Batch>, Error> {
        let mut count = 0usize;
        let mut bytes = 0usize;
        let mut expected = None;
        for item in self.items_in_order().take(max_records) {
            if expected.is_some_and(|offset| offset != item.record.offset()) {
                break;
            }
            let next = bytes
                .checked_add(item.record.bytes().len())
                .ok_or(Error::Range)?;
            if next > max_bytes {
                break;
            }
            expected = Some(
                item.record
                    .offset()
                    .checked_add(
                        u64::try_from(item.record.bytes().len()).map_err(|_| Error::Range)?,
                    )
                    .ok_or(Error::Range)?,
            );
            count += 1;
            bytes = next;
        }
        if count == 0 {
            return Ok(None);
        }
        let mut items = Vec::new();
        items
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        for _ in 0..count {
            match self.items.pop() {
                Some(item) => items.push(item),
                None => {
                    for item in items.into_iter().rev() {
                        self.items.push(item);
                    }
                    return Err(Error::Range);
                }
            }
        }
        Ok(Some(Batch { items, bytes }))
    }

    fn restore_batch(&mut self, batch: Batch) {
        // Removing this prefix left enough capacity in the original vector.
        for item in batch.items.into_iter().rev() {
            self.items.push(item);
        }
    }

    /// Transfer the next held source in original connection order.
    pub fn next_item(&mut self) -> Option<Item> {
        self.items.pop()
    }
}

/// All original owners retained by a tail driver.
#[must_use]
pub struct DriverParts {
    /// Dedicated source archive worker, including any pending source.
    pub worker: source_worker::Worker,
    /// All not-yet-offered ranges and terminal facts.
    pub plan: Plan,
    /// Caller-bound connection claim.
    pub key: SourceKey,
    /// Caller-bound camera claim, not independent authentication.
    pub camera_claim: ContentDigest,
    /// Whether the pending source has one authorized attempt.
    pub armed: bool,
    /// Whether new source admission was stopped.
    pub halted: bool,
    /// Optional record-count and byte limits for a single retained batch.
    pub batch_limits: Option<(usize, usize)>,
}

/// One ownership-preserving archive step for a retired source tail.
#[must_use]
pub enum DriverStep {
    /// A source record was accepted by the worker, but not yet published.
    Offered {
        /// Original connection-relative offset.
        offset: u64,
        /// Number of source bytes.
        len: usize,
        /// Explicit unfinished or unframed classification.
        disposition: SourceDisposition,
    },
    /// A bounded group of original records was accepted, but not published.
    BatchOffered {
        /// Offset of the first original record.
        offset: u64,
        /// Total original source bytes.
        len: usize,
        /// Number of original records transferred.
        records: usize,
    },
    /// An archive task was admitted.
    Started,
    /// The attempt drained; the caller owns the actual outcome and receipt.
    Completed(source_worker::Completion),
    /// Source admission refused; the same source was restored to the plan.
    OfferRefused,
    /// An attempt could not start; the pending source remains in the worker.
    StartRefused(av_worker::StartError),
    /// The exact pending source needs an explicit retry decision.
    RetryRequired,
    /// No held source or active publication remains.
    Finished,
    /// The worker is fenced or unavailable and requires reconciliation.
    Unavailable,
    /// Admission was stopped.
    Halted,
}

/// Drains one source at a time without detaching work or inventing a fragment.
#[must_use = "abort and join any active attempt before recovering both owners"]
pub struct Driver {
    parts: DriverParts,
}

impl Driver {
    /// Whether a source-tail archive attempt still requires joining.
    pub fn is_running(&self) -> bool {
        self.parts.worker.is_running()
    }

    /// Join an idle source worker to a checked retirement plan.
    pub fn begin(
        worker: source_worker::Worker,
        plan: Plan,
        key: SourceKey,
        camera_claim: ContentDigest,
    ) -> Result<Self, DriverParts> {
        let parts = DriverParts {
            worker,
            plan,
            key,
            camera_claim,
            armed: false,
            halted: false,
            batch_limits: None,
        };
        if parts.worker.status() != source_worker::Status::Idle
            || key.connection == 0
            || key.generation == 0
        {
            return Err(parts);
        }
        Ok(Self { parts })
    }

    /// Inspect terminal facts and ranges not yet offered to the source worker.
    /// A range already offered is held separately by the worker until drained.
    pub fn plan(&self) -> &Plan {
        &self.parts.plan
    }

    /// Opt in to bounded source batching before an attempt is offered.
    pub fn enable_batching(&mut self, max_records: usize, max_bytes: usize) -> bool {
        if self.parts.halted
            || self.parts.worker.status() != source_worker::Status::Idle
            || !(1..=source_batch::MAX_RECORDS).contains(&max_records)
            || !(1..=source_batch::MAX_BYTES).contains(&max_bytes)
        {
            return false;
        }
        self.parts.batch_limits = Some((max_records, max_bytes));
        true
    }

    /// Explicitly authorize one retry of the same retained source.
    pub fn authorize_retry(&mut self) -> bool {
        if !self.parts.halted
            && !self.parts.armed
            && self.parts.worker.status() == source_worker::Status::Pending
        {
            self.parts.armed = true;
            true
        } else {
            false
        }
    }

    /// Stop admission and request cancellation of any running attempt.
    pub fn abort(&mut self) {
        self.parts.halted = true;
        self.parts.armed = false;
        self.parts.worker.abort();
    }

    /// Join the exact active attempt, returning its actual outcome.
    pub async fn join(&mut self) -> Option<source_worker::Completion> {
        self.parts.worker.join().await
    }

    /// Recover both owners after any active attempt drains.
    pub fn into_parts(self) -> Result<DriverParts, Self> {
        if self.parts.worker.is_running() {
            Err(self)
        } else {
            Ok(self.parts)
        }
    }

    /// Advance one offer, task admission, or fully drained publication.
    pub async fn step<'scope, 'task>(
        &mut self,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        admission: ArchiveAdmission<'_>,
    ) -> DriverStep {
        if self.parts.halted {
            return DriverStep::Halted;
        }
        match self.parts.worker.status() {
            source_worker::Status::Running => match self.parts.worker.join().await {
                Some(completion) => DriverStep::Completed(completion),
                None => DriverStep::Unavailable,
            },
            source_worker::Status::Pending if self.parts.armed => {
                self.parts.armed = false;
                match self
                    .parts
                    .worker
                    .start(task, cx, clock, admission.resource, admission.cost)
                {
                    Ok(()) => DriverStep::Started,
                    Err(error) => DriverStep::StartRefused(error),
                }
            }
            source_worker::Status::Pending => DriverStep::RetryRequired,
            source_worker::Status::Fenced | source_worker::Status::Unavailable => {
                DriverStep::Unavailable
            }
            source_worker::Status::Idle => {
                if let Some((max_records, max_bytes)) = self.parts.batch_limits {
                    match self.parts.plan.take_batch(max_records, max_bytes) {
                        Ok(Some(batch)) => {
                            let offset = batch.items[0].record.offset();
                            let len = batch.bytes;
                            let records = batch.items.len();
                            match self.parts.worker.offer(source_worker::Input::Batch {
                                batch,
                                key: self.parts.key,
                                camera_claim: self.parts.camera_claim,
                            }) {
                                Ok(()) => {
                                    self.parts.armed = true;
                                    return DriverStep::BatchOffered {
                                        offset,
                                        len,
                                        records,
                                    };
                                }
                                Err(refusal) => {
                                    let input = match refusal {
                                        source_worker::OfferRefusal::Busy(input)
                                        | source_worker::OfferRefusal::Invalid(input)
                                        | source_worker::OfferRefusal::Fenced(input) => input,
                                    };
                                    let source_worker::Input::Batch { batch, .. } = input else {
                                        unreachable!("the driver only offered a batch")
                                    };
                                    self.parts.plan.restore_batch(batch);
                                    return DriverStep::OfferRefused;
                                }
                            }
                        }
                        Ok(None) => (), // Empty or first record exceeds the batch cap.
                        Err(_) => return DriverStep::OfferRefused,
                    }
                }
                let Some(item) = self.parts.plan.next_item() else {
                    return DriverStep::Finished;
                };
                let offset = item.record.offset();
                let len = item.record.bytes().len();
                let disposition = item.disposition;
                match self.parts.worker.offer(source_worker::Input::Original {
                    record: item.record,
                    key: self.parts.key,
                    disposition,
                    camera_claim: self.parts.camera_claim,
                }) {
                    Ok(()) => {
                        self.parts.armed = true;
                        DriverStep::Offered {
                            offset,
                            len,
                            disposition,
                        }
                    }
                    Err(refusal) => {
                        let input = match refusal {
                            source_worker::OfferRefusal::Busy(input)
                            | source_worker::OfferRefusal::Invalid(input)
                            | source_worker::OfferRefusal::Fenced(input) => input,
                        };
                        let source_worker::Input::Original {
                            record,
                            disposition,
                            ..
                        } = input
                        else {
                            unreachable!("the driver only offers original source")
                        };
                        // The item was just popped, so the reserved capacity still exists.
                        self.parts.plan.items.push(Item {
                            record,
                            disposition,
                        });
                        DriverStep::OfferRefused
                    }
                }
            }
        }
    }
}
