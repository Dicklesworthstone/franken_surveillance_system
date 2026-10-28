#![forbid(unsafe_code)]
//! Deterministic source-framed replay. Recorder time is an untrusted scheduling input only.

use std::{collections::BTreeMap, ops::Range};

use fss_packet::{
    ContinuityError, OnvifMetadataDiscard, OnvifMetadataDiscardReason, OnvifMetadataDocument,
    OnvifMetadataError, OnvifMetadataReceiveCancellation, OnvifMetadataReceiveError,
    OnvifMetadataReceivePoll, OnvifMetadataReceiver, OnvifMetadataStatus, PacketError,
    ReorderDisposition, ReorderError, ReorderGapReason, SequenceClass,
};

use super::{
    MetadataError, RtpDocumentProvenance, RtpMetadataBoundary, RtpMetadataConfig,
    RtpMetadataDocument, RtpMetadataFragment, RtpMetadataIssue, RtpMetadataRecord,
    RtpMetadataReport,
};
use crate::ingest::rtpdump::{RtpDumpFault, RtpDumpKind, RtpDumpLimits, RtpDumpReader};
use crate::onvif::{
    metadata::Interpretation,
    wire::{EventDocumentFormat, WireError},
};

pub(super) struct Replay {
    pub(super) report: RtpMetadataReport,
    pub(super) documents: Vec<RtpMetadataDocument>,
    by_sequence: BTreeMap<u64, usize>,
    projected_bytes: usize,
}
impl Replay {
    fn new(input_bytes: usize) -> Self {
        Self {
            report: RtpMetadataReport {
                input_bytes,
                records: Vec::new(),
                issues: Vec::new(),
                end_reason: "end_of_input",
                unprocessed_span: None,
                complete_documents: 0,
                usable_documents: 0,
                rejected_documents: 0,
            },
            documents: Vec::new(),
            by_sequence: BTreeMap::new(),
            projected_bytes: 0,
        }
    }
    fn note(&mut self, reason: &'static str, record: Option<usize>, source: Range<usize>) {
        self.report.issues.push(RtpMetadataIssue {
            reason,
            record,
            source,
            first_sequence: None,
            last_sequence: None,
            discarded_bytes: 0,
            discarded_fragments: 0,
        });
    }
    fn stop(&mut self, reason: &'static str, unprocessed_at: usize) {
        self.report.end_reason = reason;
        self.report.unprocessed_span = (unprocessed_at < self.report.input_bytes)
            .then_some(unprocessed_at..self.report.input_bytes);
    }
    fn sequence_source(&self, first: u64, last: u64) -> Range<usize> {
        let mut start = self.report.input_bytes;
        let mut end = 0;
        for (_, record) in self.by_sequence.range(first..=last) {
            let source = &self.report.records[*record].span;
            start = start.min(source.start);
            end = end.max(source.end);
        }
        if end == 0 { 0..0 } else { start..end }
    }
    fn discard(&mut self, discarded: OnvifMetadataDiscard) {
        self.report.issues.push(RtpMetadataIssue {
            reason: discard_reason(discarded.reason),
            record: None,
            source: self.sequence_source(discarded.boundary.sequence, discarded.last_sequence),
            first_sequence: Some(discarded.first_sequence),
            last_sequence: Some(discarded.last_sequence),
            discarded_bytes: discarded.byte_len,
            discarded_fragments: discarded.fragments,
        });
    }
    fn retirement(&mut self, retired: OnvifMetadataReceiveCancellation) {
        if retired.queue.packets != 0 {
            self.report.issues.push(RtpMetadataIssue {
                reason: "queued_packets_retired",
                record: None,
                source: match (retired.queue.first_sequence, retired.queue.last_sequence) {
                    (Some(first), Some(last)) => self.sequence_source(first, last),
                    _ => 0..0,
                },
                first_sequence: retired.queue.first_sequence,
                last_sequence: retired.queue.last_sequence,
                discarded_bytes: retired.queue.bytes,
                discarded_fragments: retired.queue.packets,
            });
        }
        if let Some(document) = retired.document {
            self.discard(document);
        }
    }

    /// Drive each due deadline at its actual replay time before the next recorded arrival.
    fn advance(
        &mut self,
        receiver: &mut OnvifMetadataReceiver,
        through_ns: u64,
        source: &[u8],
        config: RtpMetadataConfig,
        checkpoint: &mut impl FnMut() -> Result<(), MetadataError>,
    ) -> Result<Option<&'static str>, MetadataError> {
        // Each step consumes a packet/gap/discard or stops. This secondary work bound guards
        // accidental nonprogress without exposing an unbounded cancellation-free poll loop.
        let mut work = 0_usize;
        while let Some(wake) = receiver.next_wake_ns().filter(|wake| *wake <= through_ns) {
            checkpoint()?;
            work += 1;
            if work > 4 * super::MAX_RECORDS + 4 {
                return Err(MetadataError::Custody);
            }
            match receiver.poll(wake).map_err(|_| MetadataError::Custody)? {
                OnvifMetadataReceivePoll::Packet {
                    source: packet,
                    reconstruction,
                } => {
                    let index = *self
                        .by_sequence
                        .get(&packet.sequence())
                        .ok_or(MetadataError::Custody)?;
                    let original = &self.report.records[index];
                    if source.get(original.packet_span.clone()) != Some(packet.bytes())
                        || packet.received_ns() != u64::from(original.offset_ms) * 1_000_000
                    {
                        return Err(MetadataError::Custody);
                    }
                    match reconstruction {
                        Ok(output) => {
                            self.report.records[index].reconstruction = Some(match output.status {
                                OnvifMetadataStatus::SeekingBoundary => "seeking_boundary",
                                OnvifMetadataStatus::BoundaryObserved => "boundary_observed",
                                OnvifMetadataStatus::FragmentPending => "fragment_pending",
                                OnvifMetadataStatus::Complete => "complete",
                            });
                            if let Some(document) = output.document {
                                if let Some(stop) = self.document(document, source, config)? {
                                    return Ok(Some(stop));
                                }
                            }
                        }
                        Err(failure) => {
                            let reason = reconstruction_reason(failure.reason);
                            self.report.records[index].reconstruction = Some(reason);
                            self.note(reason, Some(index), self.report.records[index].span.clone());
                            if let Some(discarded) = failure.discarded {
                                self.discard(discarded);
                            }
                        }
                    }
                }
                OnvifMetadataReceivePoll::Gap { gap, discarded } => {
                    self.report.issues.push(RtpMetadataIssue {
                        reason: match gap.reason {
                            ReorderGapReason::Deadline => "sequence_gap_deadline",
                            ReorderGapReason::EndOfInput => "sequence_gap_end_of_input",
                        },
                        record: None,
                        source: 0..0,
                        first_sequence: Some(gap.first_sequence),
                        last_sequence: Some(gap.last_sequence),
                        discarded_bytes: 0,
                        discarded_fragments: 0,
                    });
                    if let Some(discarded) = discarded {
                        self.discard(discarded);
                    }
                }
                OnvifMetadataReceivePoll::DocumentDiscarded(discarded) => self.discard(discarded),
                OnvifMetadataReceivePoll::Pending { wake_at_ns } => {
                    if wake_at_ns.is_some_and(|next| next <= wake) {
                        return Err(MetadataError::Custody);
                    }
                    // A later deadline may still fall before the next arrival.
                    if wake_at_ns.is_none_or(|next| next > through_ns) {
                        break;
                    }
                }
                OnvifMetadataReceivePoll::Ended { discarded } => {
                    if let Some(discarded) = discarded {
                        self.discard(discarded);
                    }
                    break;
                }
            }
        }
        Ok(None)
    }

    fn document(
        &mut self,
        document: OnvifMetadataDocument,
        input: &[u8],
        config: RtpMetadataConfig,
    ) -> Result<Option<&'static str>, MetadataError> {
        if document.key() != config.stream {
            return Err(MetadataError::Custody);
        }
        if self.documents.len() == config.limits.max_documents {
            let last = *self
                .by_sequence
                .get(&document.last_sequence())
                .ok_or(MetadataError::Custody)?;
            self.report.issues.push(RtpMetadataIssue {
                reason: "document_count_limit",
                record: Some(last),
                source: self
                    .sequence_source(document.boundary().sequence, document.last_sequence()),
                first_sequence: Some(document.first_sequence()),
                last_sequence: Some(document.last_sequence()),
                discarded_bytes: document.bytes().len(),
                discarded_fragments: document.sources().len(),
            });
            return Ok(Some("document_count_limit"));
        }
        let boundary = document.boundary();
        let boundary_index = *self
            .by_sequence
            .get(&boundary.sequence)
            .ok_or(MetadataError::Custody)?;
        let boundary_record = &self.report.records[boundary_index];
        let mut fragments = Vec::new();
        let mut written = 0_usize;
        for fragment in document.sources() {
            let index = *self
                .by_sequence
                .get(&fragment.sequence)
                .ok_or(MetadataError::Custody)?;
            let record = &self.report.records[index];
            let payload = record
                .packet_span
                .start
                .checked_add(fragment.wire_range.start)
                .ok_or(MetadataError::Custody)?
                ..record
                    .packet_span
                    .start
                    .checked_add(fragment.wire_range.end)
                    .ok_or(MetadataError::Custody)?;
            if fragment.wire_range.start > fragment.wire_range.end
                || payload.end > record.packet_span.end
                || fragment.document_range.start != written
                || input.get(payload.clone())
                    != document.bytes().get(fragment.document_range.clone())
                || fragment.received_ns != u64::from(record.offset_ms) * 1_000_000
            {
                return Err(MetadataError::Custody);
            }
            written = fragment.document_range.end;
            fragments.push(RtpMetadataFragment {
                record: index,
                source: record.span.clone(),
                payload,
                document: fragment.document_range.clone(),
                sequence: fragment.sequence,
                timestamp: fragment.timestamp,
                replay_received_ns: fragment.received_ns,
            });
        }
        if written != document.bytes().len()
            || fragments.is_empty()
            || boundary.received_ns != u64::from(boundary_record.offset_ms) * 1_000_000
        {
            return Err(MetadataError::Custody);
        }
        let provenance = RtpDocumentProvenance {
            boundary: RtpMetadataBoundary {
                record: boundary_index,
                source: boundary_record.span.clone(),
                sequence: boundary.sequence,
                timestamp: boundary.timestamp,
                replay_received_ns: boundary.received_ns,
            },
            fragments,
            replay_started_ns: document.started_ns(),
            replay_completed_ns: document.completed_ns(),
        };
        let mut parse_error = None;
        let mut projection = None;
        let mut parsed = None;
        let mut stop = None;
        match Interpretation::AnalyticsV2.parse(document.bytes()) {
            Ok(value) if value.format == EventDocumentFormat::MetadataStream => {
                match super::super::record::projection(&value, Interpretation::AnalyticsV2) {
                    Ok(bytes)
                        if bytes.len()
                            <= super::MAX_PROJECTION_BYTES.saturating_sub(self.projected_bytes) =>
                    {
                        self.projected_bytes += bytes.len();
                        projection = Some(bytes);
                        parsed = Some(value);
                    }
                    Ok(_) => {
                        parse_error = Some("projection_byte_limit");
                        stop = Some("projection_byte_limit");
                    }
                    Err(MetadataError::Limit) => parse_error = Some("projection_document_limit"),
                    Err(error) => return Err(error),
                }
            }
            Ok(_) => parse_error = Some("unexpected_metadata_format"),
            Err(error) => parse_error = Some(wire_reason(error)),
        }
        if let Some(reason) = parse_error {
            let last = provenance.fragments.last().ok_or(MetadataError::Custody)?;
            self.note(
                reason,
                Some(last.record),
                self.sequence_source(document.first_sequence(), document.last_sequence()),
            );
            self.report.rejected_documents += 1;
        } else {
            self.report.usable_documents += 1;
        }
        self.documents.push(RtpMetadataDocument {
            index: self.documents.len(),
            bytes: document.bytes().to_vec(),
            projection,
            parsed,
            parse_error,
            provenance,
        });
        self.report.complete_documents = self.documents.len();
        Ok(stop)
    }
}

pub(super) fn analyze(
    source: &[u8],
    config: RtpMetadataConfig,
    mut checkpoint: impl FnMut() -> Result<(), MetadataError>,
) -> Result<Replay, MetadataError> {
    config.validate()?;
    if source.len() > config.limits.max_input_bytes {
        return Err(MetadataError::Limit);
    }
    checkpoint()?;
    let mut replay = Replay::new(source.len());
    let mut receiver = OnvifMetadataReceiver::new(
        config.stream,
        config.payload_type,
        config.reorder,
        config.metadata,
    )
    .map_err(|_| MetadataError::InvalidBinding)?;
    let limits = RtpDumpLimits {
        max_input_bytes: config.limits.max_input_bytes,
        max_records: config.limits.max_records,
        max_packet_bytes: 65_527,
    };
    let mut reader = match RtpDumpReader::new(source, limits) {
        Ok(reader) => reader,
        Err(error) => {
            replay.note(framing_reason(error.fault), None, error.span.clone());
            replay.stop("framing_error", 0);
            return Ok(replay);
        }
    };
    let mut now_ns = 0_u64;
    loop {
        checkpoint()?;
        let record = match reader.next_record() {
            Ok(Some(record)) => record,
            Ok(None) => {
                receiver.finish();
                if let Some(reason) =
                    replay.advance(&mut receiver, now_ns, source, config, &mut checkpoint)?
                {
                    replay.retirement(receiver.cancel());
                    replay.stop(reason, reader.consumed_bytes());
                }
                break;
            }
            Err(error) => {
                replay.note(framing_reason(error.fault), None, error.span.clone());
                let reason = match error.fault {
                    RtpDumpFault::TruncatedHeader
                    | RtpDumpFault::TruncatedRecordHeader
                    | RtpDumpFault::TruncatedRecord => OnvifMetadataDiscardReason::TruncatedSource,
                    RtpDumpFault::RecordLength => OnvifMetadataDiscardReason::InvalidPacket,
                    _ => OnvifMetadataDiscardReason::Cancelled,
                };
                replay.retirement(receiver.invalidate(reason));
                replay.stop("framing_error", error.span.start);
                break;
            }
        };
        let index = record.index();
        replay.report.records.push(RtpMetadataRecord {
            index,
            span: record.span(),
            packet_span: record.packet_span(),
            offset_ms: record.offset_ms(),
            result: "unprocessed",
            sequence_class: None,
            sequence: None,
            reconstruction: None,
        });
        let received_ns = u64::from(record.offset_ms()) * 1_000_000;
        if received_ns < now_ns {
            replay.report.records[index].result = "recorded_clock_reversed";
            replay.note("recorded_clock_reversed", Some(index), record.span());
            replay.retirement(receiver.cancel());
            replay.stop("recorded_clock_reversed", record.span().start);
            break;
        }
        if let Some(reason) =
            replay.advance(&mut receiver, received_ns, source, config, &mut checkpoint)?
        {
            replay.retirement(receiver.cancel());
            replay.stop(reason, record.span().start);
            break;
        }
        now_ns = received_ns;
        match record.kind() {
            RtpDumpKind::Rtcp => replay.report.records[index].result = "rtcp_retained",
            RtpDumpKind::CapturedPrefix => {
                replay.report.records[index].result = "captured_prefix";
                replay.note("captured_prefix", Some(index), record.span());
                replay.retirement(receiver.invalidate(OnvifMetadataDiscardReason::TruncatedSource));
                replay.stop("truncated_source", record.span().end);
                break;
            }
            RtpDumpKind::Rtp => {
                match receiver.ingest(config.stream, record.packet(), received_ns) {
                    Ok(admission) => {
                        let transport = admission.transport;
                        let outcome = &mut replay.report.records[index];
                        outcome.result = match transport.disposition {
                            ReorderDisposition::Buffered => "buffered",
                            ReorderDisposition::NotAdmitted => "not_admitted",
                            ReorderDisposition::Duplicate => "duplicate",
                            ReorderDisposition::TooLate => "too_late",
                            ReorderDisposition::RestartRequired => "restart_required",
                        };
                        outcome.sequence_class = Some(sequence_reason(transport.sequence.class));
                        outcome.sequence = transport.sequence.extended_sequence;
                        if transport.disposition == ReorderDisposition::Buffered {
                            let sequence = transport
                                .sequence
                                .extended_sequence
                                .ok_or(MetadataError::Custody)?;
                            if replay.by_sequence.insert(sequence, index).is_some() {
                                return Err(MetadataError::Custody);
                            }
                        }
                        if let Some(discarded) = admission.discarded {
                            replay.discard(discarded);
                        }
                        if matches!(
                            transport.disposition,
                            ReorderDisposition::TooLate | ReorderDisposition::RestartRequired
                        ) || transport.sequence.class == SequenceClass::DiscontinuitySuspected
                        {
                            let reason = if transport.sequence.class
                                == SequenceClass::DiscontinuitySuspected
                            {
                                "discontinuity_suspected"
                            } else {
                                replay.report.records[index].result
                            };
                            replay.note(reason, Some(index), record.span());
                        }
                        if transport.disposition == ReorderDisposition::RestartRequired {
                            if let Some(queue) = transport.discarded {
                                replay.retirement(OnvifMetadataReceiveCancellation {
                                    queue,
                                    document: None,
                                    reason: OnvifMetadataDiscardReason::RestartRequired,
                                });
                            }
                            replay.stop("restart_required", record.span().end);
                            break;
                        }
                    }
                    Err(OnvifMetadataReceiveError::Transport(error)) => {
                        let reason = transport_reason(error);
                        replay.report.records[index].result = reason;
                        replay.note(reason, Some(index), record.span());
                        if !matches!(
                            error,
                            ReorderError::Continuity(
                                ContinuityError::StreamMismatch | ContinuityError::PayloadType
                            )
                        ) {
                            replay.retirement(receiver.cancel());
                            replay.stop("receiver_refused", record.span().end);
                            break;
                        }
                    }
                    Err(OnvifMetadataReceiveError::Invalidated { cause, retired }) => {
                        let reason = transport_reason(cause);
                        replay.report.records[index].result = reason;
                        replay.note(reason, Some(index), record.span());
                        replay.retirement(retired);
                        replay.stop("receiver_invalidated", record.span().end);
                        break;
                    }
                    Err(OnvifMetadataReceiveError::Reconstruction(failure)) => {
                        let reason = reconstruction_reason(failure.reason);
                        replay.report.records[index].result = reason;
                        replay.note(reason, Some(index), record.span());
                        if let Some(discarded) = failure.discarded {
                            replay.discard(discarded);
                        }
                        replay.retirement(receiver.cancel());
                        replay.stop("receiver_refused", record.span().end);
                        break;
                    }
                }
                if let Some(reason) =
                    replay.advance(&mut receiver, now_ns, source, config, &mut checkpoint)?
                {
                    replay.retirement(receiver.cancel());
                    replay.stop(reason, record.span().end);
                    break;
                }
            }
        }
    }
    Ok(replay)
}

fn framing_reason(reason: RtpDumpFault) -> &'static str {
    match reason {
        RtpDumpFault::Configuration => "rtpdump_configuration",
        RtpDumpFault::Limit => "rtpdump_limit",
        RtpDumpFault::Header => "rtpdump_header",
        RtpDumpFault::TruncatedHeader => "rtpdump_truncated_header",
        RtpDumpFault::TruncatedRecordHeader => "rtpdump_truncated_record_header",
        RtpDumpFault::TruncatedRecord => "rtpdump_truncated_record",
        RtpDumpFault::RecordLength => "rtpdump_record_length",
        RtpDumpFault::Stopped => "rtpdump_stopped",
    }
}
fn sequence_reason(reason: SequenceClass) -> &'static str {
    match reason {
        SequenceClass::Probation => "probation",
        SequenceClass::Baseline => "baseline",
        SequenceClass::Advanced => "advanced",
        SequenceClass::Reordered => "reordered",
        SequenceClass::Duplicate => "duplicate",
        SequenceClass::BeforeBaseline => "before_baseline",
        SequenceClass::DiscontinuitySuspected => "discontinuity_suspected",
        SequenceClass::RestartRequired => "restart_required",
    }
}
fn discard_reason(reason: OnvifMetadataDiscardReason) -> &'static str {
    match reason {
        OnvifMetadataDiscardReason::Gap => "document_gap",
        OnvifMetadataDiscardReason::Deadline => "document_deadline",
        OnvifMetadataDiscardReason::ByteLimit => "document_byte_limit",
        OnvifMetadataDiscardReason::FragmentLimit => "document_fragment_limit",
        OnvifMetadataDiscardReason::Allocation => "document_allocation",
        OnvifMetadataDiscardReason::EmptyDocument => "empty_document",
        OnvifMetadataDiscardReason::EndOfInput => "incomplete_document_end_of_input",
        OnvifMetadataDiscardReason::Cancelled => "document_cancelled",
        OnvifMetadataDiscardReason::RestartRequired => "document_restart_required",
        OnvifMetadataDiscardReason::InvalidPacket => "document_invalid_packet",
        OnvifMetadataDiscardReason::ConflictingPacket => "document_conflicting_packet",
        OnvifMetadataDiscardReason::TruncatedSource => "document_truncated_source",
    }
}
fn reconstruction_reason(reason: OnvifMetadataError) -> &'static str {
    match reason {
        OnvifMetadataError::Configuration => "metadata_configuration",
        OnvifMetadataError::StreamMismatch => "metadata_stream_mismatch",
        OnvifMetadataError::Sequence => "metadata_sequence",
        OnvifMetadataError::ClockReversed => "metadata_clock_reversed",
        OnvifMetadataError::Exhausted => "metadata_exhausted",
        OnvifMetadataError::ByteLimit => "document_byte_limit",
        OnvifMetadataError::FragmentLimit => "document_fragment_limit",
        OnvifMetadataError::Allocation => "document_allocation",
        OnvifMetadataError::EmptyDocument => "empty_document",
        OnvifMetadataError::Packet(error) => packet_reason(error),
    }
}
fn transport_reason(reason: ReorderError) -> &'static str {
    match reason {
        ReorderError::Configuration => "reorder_configuration",
        ReorderError::Packet(error) => packet_reason(error),
        ReorderError::Closed => "receiver_closed",
        ReorderError::PacketCapacity => "queue_packet_limit",
        ReorderError::ByteCapacity => "queue_byte_limit",
        ReorderError::Allocation => "queue_allocation",
        ReorderError::ConflictingDuplicate => "conflicting_duplicate",
        ReorderError::Continuity(error) => match error {
            ContinuityError::Configuration => "continuity_configuration",
            ContinuityError::StreamMismatch => "stream_mismatch",
            ContinuityError::PayloadType => "payload_type_mismatch",
            ContinuityError::GenerationRequired => "generation_required",
            ContinuityError::Exhausted => "continuity_exhausted",
            ContinuityError::ClockReversed => "clock_reversed",
            ContinuityError::ClockAmbiguous => "clock_ambiguous",
            ContinuityError::NoSenderReport => "no_sender_report",
        },
    }
}
fn packet_reason(reason: PacketError) -> &'static str {
    match reason {
        PacketError::InvalidLimits => "packet_limits",
        PacketError::ByteLimit => "packet_byte_limit",
        PacketError::Truncated => "packet_truncated",
        PacketError::Version => "packet_version",
        PacketError::ExtensionLimit => "packet_extension_limit",
        PacketError::Padding => "packet_padding",
        PacketError::PacketCount => "packet_count",
        PacketError::Compound => "packet_compound",
        PacketError::Report => "packet_report",
        PacketError::SourceDescription => "packet_source_description",
        PacketError::Goodbye => "packet_goodbye",
        PacketError::Application => "packet_application",
    }
}
fn wire_reason(reason: WireError) -> &'static str {
    match reason {
        WireError::InputTooLarge => "xml_input_limit",
        WireError::MalformedXml => "malformed_xml",
        WireError::UnsupportedXml => "unsupported_xml",
        WireError::XmlLimitExceeded => "xml_resource_limit",
        WireError::UnexpectedEnvelope => "unexpected_xml_envelope",
        WireError::UnexpectedResponse => "unexpected_xml_response",
        WireError::DuplicateField => "duplicate_xml_field",
        WireError::MissingField => "missing_xml_field",
        WireError::InvalidField => "invalid_xml_field",
        WireError::ProfileLimitExceeded => "xml_profile_limit",
        WireError::ServiceLimitExceeded => "xml_service_limit",
        WireError::EventLimitExceeded => "xml_event_limit",
        WireError::ItemLimitExceeded => "xml_item_limit",
        WireError::AnalyticsLimitExceeded => "xml_analytics_limit",
        WireError::UnsupportedEventContent => "unsupported_xml_event_content",
        WireError::UnsupportedHeader => "unsupported_xml_header",
        WireError::SoapFault(_) => "xml_soap_fault",
    }
}
