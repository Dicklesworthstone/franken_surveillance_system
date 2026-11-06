#![forbid(unsafe_code)]
//! Bounded reassembly for the experimentally documented UniFi BLE packet stream.
//!
//! According to the third-party protocol description, a big-endian 16-bit
//! length includes its own two bytes; BLE notifications may split or join
//! packets. See <https://github.com/zerotypic/unifi-ble-client/blob/main/doc/protocol.md#encrypted-packet>.
//! This module only preserves supplied bytes and their framing. It performs no
//! Bluetooth I/O, decryption, authentication, sequence tracking or provisioning,
//! and this description has not been qualified against the owned G4 camera.
//! The caller binds each input byte to its device, session and source evidence.

use std::fmt;

/// Feed outcome. The caller retains input after `consumed` and retries it after
/// taking the completed packet; bytes after one packet are never discarded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Feed {
    /// Number of input bytes accepted into this frame.
    pub consumed: usize,
    /// A complete frame is held until the caller takes it.
    pub complete: bool,
}

/// Reason a framing session must be retired without automatic resynchronization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureKind {
    /// Declared length cannot include its own two-byte prefix.
    InvalidLength,
    /// Declared length exceeds the caller's configured limit.
    LengthLimit,
    /// Memory reservation failed.
    Allocation,
    /// This framer has already failed and must not consume further input.
    Retired,
}

/// Failure together with the exact accepted prefix of the caller's input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeedFailure {
    /// Bytes accepted before the failure; unaccepted input remains caller-owned.
    pub consumed: usize,
    /// Why no further input may be accepted.
    pub kind: FailureKind,
}

impl fmt::Display for FeedFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi BLE framing refusal: {:?}", self.kind)
    }
}
impl std::error::Error for FeedFailure {}

/// A completed frame or the unprocessed prefix returned when retiring a session.
/// Debug output intentionally does not include packet contents.
pub struct Bytes(Vec<u8>);

impl Bytes {
    /// Original bytes, including the length prefix when present.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Transfer the original bytes to the owner.
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bytes").field("len", &self.0.len()).finish()
    }
}

/// One frame at a time, with bounded memory and explicit backpressure.
pub struct Framer {
    bytes: Vec<u8>,
    expected: Option<usize>,
    maximum: usize,
    failed: bool,
}

impl Framer {
    /// Construct with a total-frame limit, including the length prefix.
    /// Wire lengths are 16-bit; limits outside that range are refused.
    pub fn new(maximum: usize) -> Option<Self> {
        (2..=usize::from(u16::MAX))
            .contains(&maximum)
            .then(|| Self {
                bytes: Vec::new(),
                expected: None,
                maximum,
                failed: false,
            })
    }

    /// Accept a prefix of one notification. A complete pending packet applies
    /// backpressure. Malformed lengths and allocation failures are terminal;
    /// the accepted prefix remains available through [`Self::retire`].
    pub fn feed(&mut self, input: &[u8]) -> Result<Feed, FeedFailure> {
        if self.failed {
            return Err(FeedFailure {
                consumed: 0,
                kind: FailureKind::Retired,
            });
        }
        if self.expected == Some(self.bytes.len()) {
            return Ok(Feed {
                consumed: 0,
                complete: true,
            });
        }
        let mut consumed = 0;
        if self.bytes.len() < 2 {
            let n = (2 - self.bytes.len()).min(input.len());
            if self.bytes.try_reserve(n).is_err() {
                self.failed = true;
                return Err(FeedFailure {
                    consumed,
                    kind: FailureKind::Allocation,
                });
            }
            self.bytes.extend_from_slice(&input[..n]);
            consumed = n;
            if self.bytes.len() < 2 {
                return Ok(Feed {
                    consumed,
                    complete: false,
                });
            }
            let size = usize::from(u16::from_be_bytes([self.bytes[0], self.bytes[1]]));
            let failure = if size < 2 {
                Some(FailureKind::InvalidLength)
            } else if size > self.maximum {
                Some(FailureKind::LengthLimit)
            } else {
                None
            };
            if let Some(kind) = failure {
                self.failed = true;
                return Err(FeedFailure { consumed, kind });
            }
            if self.bytes.try_reserve_exact(size - 2).is_err() {
                self.failed = true;
                return Err(FeedFailure {
                    consumed,
                    kind: FailureKind::Allocation,
                });
            }
            self.expected = Some(size);
        }
        let Some(expected) = self.expected else {
            self.failed = true;
            return Err(FeedFailure {
                consumed,
                kind: FailureKind::Retired,
            });
        };
        let n = (expected - self.bytes.len()).min(input.len() - consumed);
        self.bytes.extend_from_slice(&input[consumed..consumed + n]);
        consumed += n;
        Ok(Feed {
            consumed,
            complete: self.bytes.len() == expected,
        })
    }

    /// Take exactly one complete frame, allowing the next frame to be fed.
    pub fn take(&mut self) -> Option<Bytes> {
        if self.failed || self.expected != Some(self.bytes.len()) {
            return None;
        }
        self.expected = None;
        Some(Bytes(std::mem::take(&mut self.bytes)))
    }

    /// Return all still-owned bytes on cancellation, end of stream, or failure.
    pub fn retire(self) -> Bytes {
        Bytes(self.bytes)
    }
}

/// A bounded packet write's observation, supplied by the transport owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteOutcome {
    /// The transport acknowledged the complete characteristic write.
    Acknowledged,
    /// The owner established that no bytes were submitted; retry may be prepared.
    DefinitelyNotSubmitted,
    /// Submission or acknowledgment is uncertain; the session must stop.
    Indeterminate,
}

/// Refusal to prepare or resolve a packet write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteError {
    /// The frame length or characteristic payload bound is invalid.
    Configuration,
    /// A prepared write still needs an outcome.
    Pending,
    /// There is no prepared write to resolve.
    NoPending,
    /// An uncertain result prevents further submissions.
    Indeterminate,
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi BLE write refusal: {self:?}")
    }
}
impl std::error::Error for WriteError {}

/// A prepared or interrupted write, retaining its original frame and offsets.
/// The owner must reconcile a pending write independently before any retry.
pub struct WriteRetirement<'a> {
    frame: &'a [u8],
    acknowledged: usize,
    pending_end: Option<usize>,
    indeterminate: bool,
}

impl<'a> WriteRetirement<'a> {
    /// The exact original framed ciphertext supplied by the caller.
    pub fn frame(&self) -> &'a [u8] {
        self.frame
    }

    /// Prefix acknowledged by the transport, not proof of device processing.
    pub fn acknowledged(&self) -> usize {
        self.acknowledged
    }

    /// Range submitted or prepared without a settled acknowledgment, if any.
    pub fn pending(&self) -> Option<std::ops::Range<usize>> {
        self.pending_end.map(|end| self.acknowledged..end)
    }

    /// A transport result was explicitly reported indeterminate.
    pub fn indeterminate(&self) -> bool {
        self.indeterminate
    }
}

impl fmt::Debug for WriteRetirement<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriteRetirement")
            .field("frame_len", &self.frame.len())
            .field("acknowledged", &self.acknowledged)
            .field("pending_end", &self.pending_end)
            .field("indeterminate", &self.indeterminate)
            .finish()
    }
}

/// Single-owner splitter for BLE characteristic writes with response.
/// It performs no I/O and cannot decide whether a write was submitted.
pub struct WriteCursor<'a> {
    frame: &'a [u8],
    maximum_chunk: usize,
    acknowledged: usize,
    pending_end: Option<usize>,
    indeterminate: bool,
}

impl<'a> WriteCursor<'a> {
    /// `maximum_chunk` is the already-negotiated characteristic payload size,
    /// not the ATT MTU. The frame must contain exactly its declared wire length.
    pub fn new(frame: &'a [u8], maximum_chunk: usize) -> Result<Self, WriteError> {
        if frame.len() < 2
            || frame.len() > usize::from(u16::MAX)
            || usize::from(u16::from_be_bytes([frame[0], frame[1]])) != frame.len()
            || maximum_chunk == 0
            || maximum_chunk > usize::from(u16::MAX)
        {
            return Err(WriteError::Configuration);
        }
        Ok(Self {
            frame,
            maximum_chunk,
            acknowledged: 0,
            pending_end: None,
            indeterminate: false,
        })
    }

    /// Prepare exactly one chunk. Its result must be resolved before another is
    /// prepared. Dropping a transport future does not establish non-submission.
    pub fn prepare(&mut self) -> Result<Option<&'a [u8]>, WriteError> {
        if self.indeterminate {
            return Err(WriteError::Indeterminate);
        }
        if self.pending_end.is_some() {
            return Err(WriteError::Pending);
        }
        if self.acknowledged == self.frame.len() {
            return Ok(None);
        }
        let end = self
            .acknowledged
            .saturating_add(self.maximum_chunk)
            .min(self.frame.len());
        self.pending_end = Some(end);
        Ok(Some(&self.frame[self.acknowledged..end]))
    }

    /// Transfer the transport's actual outcome to this cursor.
    pub fn resolve(&mut self, outcome: WriteOutcome) -> Result<(), WriteError> {
        if self.indeterminate {
            return Err(WriteError::Indeterminate);
        }
        let end = self.pending_end.ok_or(WriteError::NoPending)?;
        match outcome {
            WriteOutcome::Acknowledged => {
                self.acknowledged = end;
                self.pending_end = None;
            }
            WriteOutcome::DefinitelyNotSubmitted => self.pending_end = None,
            WriteOutcome::Indeterminate => self.indeterminate = true,
        }
        Ok(())
    }

    /// Retain the original packet and all unsettled write state at cancellation.
    pub fn retire(self) -> WriteRetirement<'a> {
        WriteRetirement {
            frame: self.frame,
            acknowledged: self.acknowledged,
            pending_end: self.pending_end,
            indeterminate: self.indeterminate,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type Test = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn every_fragmentation_point_preserves_bytes() -> Test {
        let wire = [0, 7, 1, 2, 3, 4, 5];
        for split in 0..=wire.len() {
            let mut decoder = Framer::new(32).ok_or("framer configuration")?;
            let first = decoder.feed(&wire[..split])?;
            assert_eq!(first.consumed, split);
            assert_eq!(first.complete, split == wire.len());
            let second = decoder.feed(&wire[split..])?;
            assert_eq!(second.consumed, wire.len() - split);
            assert!(second.complete);
            assert_eq!(decoder.take().ok_or("missing frame")?.as_bytes(), wire);
        }
        Ok(())
    }

    #[test]
    fn coalesced_frames_obey_backpressure() -> Test {
        let mut decoder = Framer::new(8).ok_or("framer configuration")?;
        let bytes = [0, 3, 42, 0, 4, 1, 2];
        assert_eq!(
            decoder.feed(&bytes)?,
            Feed {
                consumed: 3,
                complete: true
            }
        );
        assert_eq!(
            decoder.feed(&bytes[3..])?,
            Feed {
                consumed: 0,
                complete: true
            }
        );
        assert_eq!(
            decoder.take().ok_or("missing frame")?.as_bytes(),
            &bytes[..3]
        );
        assert_eq!(
            decoder.feed(&bytes[3..])?,
            Feed {
                consumed: 4,
                complete: true
            }
        );
        assert_eq!(
            decoder.take().ok_or("missing frame")?.as_bytes(),
            &bytes[3..]
        );
        Ok(())
    }

    #[test]
    fn bad_length_retires_without_losing_accepted_prefix() -> Test {
        for (prefix, expected) in [
            ([0, 1], FailureKind::InvalidLength),
            ([0, 9], FailureKind::LengthLimit),
        ] {
            let mut decoder = Framer::new(8).ok_or("framer configuration")?;
            assert_eq!(decoder.feed(&prefix[..1])?.consumed, 1);
            assert_eq!(
                decoder.feed(&prefix[1..]),
                Err(FeedFailure {
                    consumed: 1,
                    kind: expected
                })
            );
            assert_eq!(
                decoder.feed(&[1, 2]),
                Err(FeedFailure {
                    consumed: 0,
                    kind: FailureKind::Retired
                })
            );
            assert!(decoder.take().is_none());
            assert_eq!(decoder.retire().as_bytes(), prefix);
        }
        Ok(())
    }

    #[test]
    fn bounds_empty_packets_and_retirement() -> Test {
        assert!(Framer::new(1).is_none());
        assert!(Framer::new(usize::from(u16::MAX) + 1).is_none());
        let mut decoder = Framer::new(4).ok_or("framer configuration")?;
        assert_eq!(
            decoder.feed(&[])?,
            Feed {
                consumed: 0,
                complete: false
            }
        );
        assert_eq!(
            decoder.feed(&[0, 2])?,
            Feed {
                consumed: 2,
                complete: true
            }
        );
        let packet = decoder.take().ok_or("missing frame")?;
        assert_eq!(packet.as_bytes(), [0, 2]);
        assert!(!format!("{packet:?}").contains("[0, 2]"));
        assert_eq!(
            decoder.feed(&[0, 4, 9])?,
            Feed {
                consumed: 3,
                complete: false
            }
        );
        assert_eq!(decoder.retire().into_vec(), [0, 4, 9]);
        Ok(())
    }

    #[test]
    fn writes_are_chunked_only_after_acknowledgment() -> Test {
        let wire = [0, 7, 1, 2, 3, 4, 5];
        for maximum in 1..=wire.len() + 1 {
            let mut cursor = WriteCursor::new(&wire, maximum)?;
            let mut transmitted = Vec::new();
            while let Some(chunk) = cursor.prepare()? {
                assert!(chunk.len() <= maximum);
                transmitted.extend_from_slice(chunk);
                assert_eq!(cursor.prepare(), Err(WriteError::Pending));
                cursor.resolve(WriteOutcome::Acknowledged)?;
            }
            assert_eq!(transmitted, wire);
            let retired = cursor.retire();
            assert_eq!(retired.acknowledged(), wire.len());
            assert!(retired.pending().is_none());
        }
        Ok(())
    }

    #[test]
    fn uncertain_or_cancelled_writes_are_not_retried() -> Test {
        let wire = [0, 5, 8, 9, 10];
        let mut cursor = WriteCursor::new(&wire, 2)?;
        assert_eq!(
            cursor.resolve(WriteOutcome::Acknowledged),
            Err(WriteError::NoPending)
        );
        assert_eq!(cursor.prepare()?.ok_or("missing chunk")?, &wire[..2]);
        cursor.resolve(WriteOutcome::DefinitelyNotSubmitted)?;
        assert_eq!(cursor.prepare()?.ok_or("missing chunk")?, &wire[..2]);
        cursor.resolve(WriteOutcome::Acknowledged)?;
        assert_eq!(cursor.prepare()?.ok_or("missing chunk")?, &wire[2..4]);
        cursor.resolve(WriteOutcome::Indeterminate)?;
        assert_eq!(cursor.prepare(), Err(WriteError::Indeterminate));
        assert_eq!(
            cursor.resolve(WriteOutcome::Acknowledged),
            Err(WriteError::Indeterminate)
        );
        let retired = cursor.retire();
        assert_eq!(retired.acknowledged(), 2);
        assert_eq!(retired.pending(), Some(2..4));
        assert!(retired.indeterminate());
        assert!(!format!("{retired:?}").contains("[0, 5, 8, 9, 10]"));

        let mut cancelled = WriteCursor::new(&wire, 3)?;
        let _ = cancelled.prepare()?;
        let cancelled = cancelled.retire();
        assert_eq!(cancelled.acknowledged(), 0);
        assert_eq!(cancelled.pending(), Some(0..3));
        assert!(!cancelled.indeterminate());
        assert_eq!(cancelled.frame(), wire);
        assert!(matches!(
            WriteCursor::new(&wire, 0),
            Err(WriteError::Configuration)
        ));
        assert!(matches!(
            WriteCursor::new(&wire[..4], 1),
            Err(WriteError::Configuration)
        ));
        Ok(())
    }
}
