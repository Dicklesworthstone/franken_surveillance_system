#![forbid(unsafe_code)]

use super::super::{
    MAX_RECORDING_BYTES, ReplayWindowProof, Result,
    storage::{self, ReceiptVisitor, VerifiedOriginal},
};
use super::*;
use crate::rtsp::recording::{RecordingError, RecordingPacket};
use fss_packet::onvif_replay::parse_replay_extension;
use fss_packet::{PacketLimits, RtpPacket};

pub(super) fn query(
    publisher: &LocalRootPublisher,
    query: &ReplayTimeQuery,
    cancel: &dyn PublishCancellation,
) -> std::result::Result<ReplayTimeReport, ReplayTimeError> {
    let mut scan = Scan {
        query,
        cancel,
        cseq: 0,
        reserved: 0,
        windows: 0,
        samples: 0,
        packets: 0,
        bytes: 0,
        outside: 0,
        results: 0,
        matches: Vec::new(),
        unknown: Vec::new(),
        source_only: Vec::new(),
        observations: Vec::new(),
    };
    // This loader invokes metadata admission before any original read, then
    // verifies each original exactly once before visiting it. Its final custody
    // and cancellation checks run after every projection callback has completed.
    let receipt = storage::load_codec_receipt_visit(
        publisher,
        query.codec,
        query.receipt_root,
        &query.scope,
        query.request,
        cancel,
        &mut scan,
    )?;
    if scan.windows != receipt.windows().len()
        || scan.samples != scan.matches.len() + scan.unknown.len() + scan.outside
    {
        return Err(ReplayTimeError::Receipt(ReplayReceiptError::WindowMismatch));
    }
    let index_digest = proof::index(query, &scan.observations)?;
    let mut report = ReplayTimeReport {
        query: query.clone(),
        receipt,
        digest: index_digest,
        index_digest,
        scanned_windows: scan.windows,
        scanned_samples: scan.samples,
        scanned_packets: scan.packets,
        source_bytes_reserved: scan.reserved,
        source_bytes: scan.bytes,
        outside_samples: scan.outside,
        matches: scan.matches,
        unknown: scan.unknown,
        source_only: scan.source_only,
    };
    report.digest = proof::report(&report)?;
    storage::cancelled(cancel)?;
    Ok(report)
}

struct Scan<'a> {
    query: &'a ReplayTimeQuery,
    cancel: &'a dyn PublishCancellation,
    cseq: u32,
    reserved: u64,
    windows: usize,
    samples: usize,
    packets: usize,
    bytes: u64,
    outside: usize,
    results: usize,
    matches: Vec<ReplaySampleTime>,
    unknown: Vec<ReplaySampleTime>,
    source_only: Vec<ReplaySourceOnlyTime>,
    observations: Vec<ContentDigest>,
}

impl ReceiptVisitor for Scan<'_> {
    fn admit_receipt(&mut self, receipt: &ReplayReceipt) -> Result<()> {
        storage::cancelled(self.cancel)?;
        let limits = self.query.limits;
        if receipt.windows().len() > limits.max_windows {
            return Err(ReplayReceiptError::Limit);
        }
        let mut samples = 0_usize;
        let mut packets = 0_usize;
        for window in receipt.windows() {
            storage::cancelled(self.cancel)?;
            samples = samples
                .checked_add(window.samples())
                .ok_or(ReplayReceiptError::Limit)?;
            packets = packets
                .checked_add(window.packets())
                .ok_or(ReplayReceiptError::Limit)?;
            if samples > limits.max_samples || packets > limits.max_packets {
                return Err(ReplayReceiptError::Limit);
            }
        }
        // Reserve a whole native verifier allowance per window. A forged small
        // receipt byte count must not turn into unbudgeted source I/O.
        self.reserved = u64::try_from(receipt.windows().len())
            .ok()
            .and_then(|count| count.checked_mul(MAX_RECORDING_BYTES as u64))
            .ok_or(ReplayReceiptError::Limit)?;
        if self.reserved > limits.max_source_bytes {
            return Err(ReplayReceiptError::Limit);
        }
        self.cseq = receipt.acceptance().cseq();
        Ok(())
    }

    fn original(
        &mut self,
        ordinal: usize,
        window: &ReplayWindowProof,
        original: VerifiedOriginal<'_>,
    ) -> Result<()> {
        storage::cancelled(self.cancel)?;
        if ordinal != self.windows {
            return Err(ReplayReceiptError::Order);
        }
        match original {
            VerifiedOriginal::Avc(recording) => {
                let packets = recording.packets()?;
                let projection = source::avc(recording, self.cancel)?;
                self.window(ordinal, window, &packets, projection)?;
            }
            VerifiedOriginal::Hevc(recording) => {
                let packets = recording.packets()?;
                let projection = source::hevc(recording, &packets, self.cancel)?;
                self.window(ordinal, window, &packets, projection)?;
            }
        }
        Ok(())
    }
}

impl Scan<'_> {
    fn window(
        &mut self,
        ordinal: usize,
        window: &ReplayWindowProof,
        originals: &[RecordingPacket<'_>],
        projection: source::Projection,
    ) -> Result<()> {
        if originals.len() != window.packets() || projection.samples.len() != window.samples() {
            return Err(ReplayReceiptError::WindowMismatch);
        }
        self.windows = self
            .windows
            .checked_add(1)
            .ok_or(ReplayReceiptError::Limit)?;
        self.samples = self
            .samples
            .checked_add(projection.samples.len())
            .ok_or(ReplayReceiptError::Limit)?;
        self.packets = self
            .packets
            .checked_add(originals.len())
            .ok_or(ReplayReceiptError::Limit)?;
        self.bytes = self
            .bytes
            .checked_add(u64::try_from(window.byte_len()).map_err(|_| ReplayReceiptError::Limit)?)
            .ok_or(ReplayReceiptError::Limit)?;
        let limits = self.query.limits;
        if self.windows > limits.max_windows
            || self.samples > limits.max_samples
            || self.packets > limits.max_packets
            || self.bytes > limits.max_source_bytes
            || self.bytes > self.reserved
        {
            return Err(ReplayReceiptError::Limit);
        }

        let packets = observed_packets(originals, self.cancel)?;
        let mut owners = super::super::bounded_vec(packets.len())?;
        owners.resize(packets.len(), 0_usize);
        for sequences in projection
            .samples
            .iter()
            .map(|sample| sample.sequences.as_slice())
            .chain(
                projection
                    .source_only
                    .iter()
                    .map(|group| group.sequences.as_slice()),
            )
        {
            storage::cancelled(self.cancel)?;
            for sequence in sequences {
                let position = position(&packets, *sequence)?;
                owners[position] = owners[position]
                    .checked_add(1)
                    .ok_or(ReplayReceiptError::Limit)?;
            }
        }
        // A verified original packet may contribute to a media sample or to the
        // explicit source-only suffix. It must not silently disappear from both.
        if owners.contains(&0) {
            return Err(RecordingError::Source.into());
        }

        for sample in projection.samples {
            storage::cancelled(self.cancel)?;
            let evidence =
                self.evidence(sample.rtp_timestamp, &sample.sequences, &packets, &owners)?;
            let mut row = ReplaySampleTime {
                window: ordinal,
                slot: window.slot().clone(),
                root: window.root(),
                sample: sample.sample,
                decode_time: sample.decode_time,
                presentation_time: sample.presentation_time,
                duration: sample.duration,
                rtp_timestamp: sample.rtp_timestamp,
                evidence,
            };
            row.evidence.proof_digest = proof::sample(self.query, &row)?;
            self.observe(row.evidence.proof_digest)?;
            if let Some(utc) = row.evidence.utc {
                if utc.latest_ns >= self.query.start_ns && utc.earliest_ns < self.query.end_ns {
                    self.result()?;
                    self.matches
                        .try_reserve(1)
                        .map_err(|_| ReplayReceiptError::Limit)?;
                    self.matches.push(row);
                } else {
                    self.outside = self
                        .outside
                        .checked_add(1)
                        .ok_or(ReplayReceiptError::Limit)?;
                }
            } else {
                self.result()?;
                self.unknown
                    .try_reserve(1)
                    .map_err(|_| ReplayReceiptError::Limit)?;
                self.unknown.push(row);
            }
        }
        for (group_ordinal, group) in projection.source_only.into_iter().enumerate() {
            storage::cancelled(self.cancel)?;
            let evidence =
                self.evidence(group.rtp_timestamp, &group.sequences, &packets, &owners)?;
            let mut row = ReplaySourceOnlyTime {
                window: ordinal,
                slot: window.slot().clone(),
                root: window.root(),
                rtp_timestamp: group.rtp_timestamp,
                evidence,
            };
            row.evidence.proof_digest = proof::source_only(self.query, group_ordinal, &row)?;
            self.observe(row.evidence.proof_digest)?;
            self.result()?;
            self.source_only
                .try_reserve(1)
                .map_err(|_| ReplayReceiptError::Limit)?;
            self.source_only.push(row);
        }
        Ok(())
    }

    fn evidence(
        &self,
        timestamp: u32,
        sequences: &[u64],
        packets: &[ObservedPacket],
        owners: &[usize],
    ) -> Result<ReplayTimeEvidence> {
        let first_sequence = *sequences.first().ok_or(RecordingError::Source)?;
        let last_sequence = *sequences.last().ok_or(RecordingError::Source)?;
        let mut positions = super::super::bounded_vec(sequences.len())?;
        let mut shared = false;
        let mut timestamp_mismatch = false;
        for sequence in sequences {
            storage::cancelled(self.cancel)?;
            let position = position(packets, *sequence)?;
            positions.push(position);
            shared |= owners[position] > 1;
            timestamp_mismatch |= packets[position].timestamp != timestamp;
        }
        let first = packets[*positions.first().ok_or(RecordingError::Source)?];
        let (header, mut unknown) = match first.header {
            ObservedHeader::Missing => (None, Some(ReplayTimeUnknown::MissingFirstExtension)),
            ObservedHeader::Foreign => (None, Some(ReplayTimeUnknown::ForeignFirstExtension)),
            ObservedHeader::Malformed(error) => {
                (None, Some(ReplayTimeUnknown::MalformedExtension(error)))
            }
            ObservedHeader::Replay(value) => (Some(value), None),
        };
        if let Some(header) = header {
            for position in positions.iter().skip(1) {
                storage::cancelled(self.cancel)?;
                match packets[*position].header {
                    ObservedHeader::Malformed(error) if unknown.is_none() => {
                        unknown = Some(ReplayTimeUnknown::MalformedExtension(error))
                    }
                    ObservedHeader::Replay(other) if other != header && unknown.is_none() => {
                        unknown = Some(ReplayTimeUnknown::ConflictingExtensions)
                    }
                    _ => {}
                }
            }
        }
        // Keep the first parsed header for diagnostics, but never assign its UTC
        // to two access units or repair a contradictory native/source association.
        if shared {
            unknown = Some(ReplayTimeUnknown::SharedPacket);
        } else if timestamp_mismatch {
            unknown = Some(ReplayTimeUnknown::RtpTimestampMismatch);
        }
        let mut utc = None;
        if unknown.is_none() {
            let header = header.ok_or(RecordingError::Source)?;
            if let Err(error) = header.correlate_play(self.cseq) {
                unknown = Some(match error {
                    ReplayExtensionError::PlayCseqMismatch => ReplayTimeUnknown::PlayCseqMismatch,
                    error => ReplayTimeUnknown::MalformedExtension(error),
                });
            } else {
                match header.utc_for_era(self.query.ntp_era) {
                    Ok(value) => utc = Some(value),
                    Err(ReplayExtensionError::UnknownTimestamp) => {
                        unknown = Some(ReplayTimeUnknown::UnknownTimestamp)
                    }
                    Err(ReplayExtensionError::UtcRange) => {
                        unknown = Some(ReplayTimeUnknown::UtcOutOfRange)
                    }
                    Err(error) => unknown = Some(ReplayTimeUnknown::MalformedExtension(error)),
                }
            }
        }
        let packet_set_digest = proof::packet_set(
            positions.len(),
            positions.iter().map(|position| {
                let packet = packets[*position];
                (packet.sequence, packet.digest)
            }),
        )?;
        Ok(ReplayTimeEvidence {
            first_sequence,
            last_sequence,
            packet_count: positions.len(),
            packet_set_digest,
            // Replaced immediately by the complete sample/source-only proof.
            proof_digest: packet_set_digest,
            header,
            utc,
            unknown,
        })
    }

    fn observe(&mut self, digest: ContentDigest) -> Result<()> {
        if self.observations.len() >= MAX_REPLAY_TIME_RESULTS {
            return Err(ReplayReceiptError::Limit);
        }
        self.observations
            .try_reserve(1)
            .map_err(|_| ReplayReceiptError::Limit)?;
        self.observations.push(digest);
        Ok(())
    }

    fn result(&mut self) -> Result<()> {
        if self.results >= self.query.limits.max_results {
            return Err(ReplayReceiptError::Limit);
        }
        self.results += 1;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum ObservedHeader {
    Missing,
    Foreign,
    Malformed(ReplayExtensionError),
    Replay(ReplayHeaderExtension),
}

#[derive(Clone, Copy)]
struct ObservedPacket {
    sequence: u64,
    timestamp: u32,
    digest: ContentDigest,
    header: ObservedHeader,
}

fn observed_packets(
    originals: &[RecordingPacket<'_>],
    cancel: &dyn PublishCancellation,
) -> Result<Vec<ObservedPacket>> {
    let mut packets = super::super::bounded_vec(originals.len())?;
    let mut previous = None;
    for original in originals {
        storage::cancelled(cancel)?;
        if previous.is_some_and(|value| original.sequence <= value) {
            return Err(RecordingError::Source.into());
        }
        previous = Some(original.sequence);
        let packet = RtpPacket::parse(original.bytes, PacketLimits::default())
            .map_err(|_| RecordingError::Source)?;
        let header = match packet.extension() {
            None => ObservedHeader::Missing,
            Some(extension) => match parse_replay_extension(extension) {
                Ok(None) => ObservedHeader::Foreign,
                Ok(Some(value)) => ObservedHeader::Replay(value),
                Err(error) => ObservedHeader::Malformed(error),
            },
        };
        packets.push(ObservedPacket {
            sequence: original.sequence,
            timestamp: packet.timestamp(),
            digest: ContentDigest::try_sha256(original.bytes)
                .map_err(|_| ReplayReceiptError::Limit)?,
            header,
        });
    }
    Ok(packets)
}

fn position(packets: &[ObservedPacket], sequence: u64) -> Result<usize> {
    packets
        .binary_search_by_key(&sequence, |packet| packet.sequence)
        .map_err(|_| RecordingError::Source.into())
}
