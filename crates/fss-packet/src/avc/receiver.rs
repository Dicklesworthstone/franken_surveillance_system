#![forbid(unsafe_code)]

use super::{
    AvcAssembler, AvcAssemblyError, AvcAssemblyLimits, AvcAssemblyOutput, AvcAssemblyPoll,
    AvcAssemblyRetirement, AvcAssemblyStep, AvcPictureGroup, AvcPps, AvcSps, AvcSyntaxLimits,
};
use crate::{
    FragmentDiscard, H264Limits, H264Mode, H264Output, H264ReceiveAdmission,
    H264ReceiveCancellation, H264ReceiveError, H264ReceivePoll, H264Receiver, H264Status, NalUnit,
    OrderedRtpPacket, ReorderDisposition, ReorderGap, ReorderLimits, SequenceStats, StreamKey,
};

/// Independent limits for transport, NAL reconstruction, syntax, and picture assembly.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AvcReceiveLimits {
    /// Original datagram queue, parsing, and reorder timeout.
    pub reorder: ReorderLimits,
    /// Per-NAL reconstruction byte/fragment/age bounds.
    pub reconstruction: H264Limits,
    /// Parameter and picture-prefix parsing bounds.
    pub syntax: AvcSyntaxLimits,
    /// Pending picture NAL/byte/age bounds.
    pub assembly: AvcAssemblyLimits,
}

/// Payload-free receiver construction, owner, or clock refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AvcReceiveError {
    /// RTP admission/reconstruction boundary refused the operation.
    Transport(H264ReceiveError),
    /// Picture configuration, owner, generation, or time refused the operation.
    Assembly(AvcAssemblyError),
}

impl std::fmt::Display for AvcReceiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AVC receiver refusal: {self:?}")
    }
}
impl std::error::Error for AvcReceiveError {}

/// Accounting for complete NALs retired before picture admission.
/// Original datagrams were already exposed by source events; independent source
/// custody remains the owner's responsibility before and after these events.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AvcQueuedNalRetirement {
    /// Exact owner stream epoch.
    pub key: StreamKey,
    /// Complete NALs retired without picture admission.
    pub nals: usize,
    /// Reconstructed bytes retired.
    pub bytes: usize,
    /// First contributing extended RTP sequence, if the queue was not empty.
    pub first_sequence: Option<u64>,
    /// Last contributing extended RTP sequence, if the queue was not empty.
    pub last_sequence: Option<u64>,
}

/// Admission does not imply decode, picture completeness, or retained source custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AvcReceiveAdmission {
    /// Existing packet/NAL receiver admission, including source-restart receipts.
    pub transport: H264ReceiveAdmission,
    /// Complete queued NALs retired on a confirmed restart.
    pub queued_nals: Option<AvcQueuedNalRetirement>,
    /// Pending picture retired on a confirmed restart.
    pub picture: Option<AvcAssemblyRetirement>,
}

/// Cancellation accounts for all three independently bounded derivative layers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AvcReceiveCancellation {
    /// Queued original datagrams and incomplete FU reconstruction.
    pub transport: H264ReceiveCancellation,
    /// Complete NALs not yet admitted to a picture.
    pub queued_nals: AvcQueuedNalRetirement,
    /// Pending picture grouping, if any.
    pub picture: Option<AvcAssemblyRetirement>,
}

/// One bounded, ownership-preserving step from wire admission to picture grouping.
#[derive(Debug, Eq, PartialEq)]
pub enum AvcReceivePoll {
    /// Exact original source datagram and reconstruction accounting. Complete NALs
    /// are processed on subsequent poll steps, never as an unbounded callback batch.
    Source {
        /// Owned original RTP bytes, including headers/extensions/padding.
        source: OrderedRtpPacket,
        /// Complete/pending reconstruction classification, not a frame result.
        status: H264Status,
        /// Complete NAL count queued by this datagram.
        queued_nals: usize,
        /// Whether reconstruction itself detected missing delivery positions.
        gap_before: bool,
        /// Incomplete NAL retired before this output, if any.
        fragment: Option<FragmentDiscard>,
        /// Picture grouping automatically invalidated by the gap/retirement.
        picture: Option<AvcAssemblyRetirement>,
    },
    /// A codec refusal still owns the exact original datagram. It invalidates
    /// pending picture assembly before any later NAL can be admitted.
    CodecRefused {
        /// Exact original packet whose reconstruction failed.
        source: OrderedRtpPacket,
        /// Typed reconstruction failure, including any fragment retirement.
        error: H264ReceiveError,
        /// Pending grouping retired because the input could not be reconstructed.
        picture: Option<AvcAssemblyRetirement>,
    },
    /// Missing ordered positions automatically invalidate both derivative layers.
    Gap {
        /// Exact delivery-gap receipt.
        gap: ReorderGap,
        /// Incomplete FU retirement, if present.
        fragment: Option<FragmentDiscard>,
        /// Pending picture retirement, if present.
        picture: Option<AvcAssemblyRetirement>,
    },
    /// A NAL reconstruction timed out even without another network packet.
    FragmentRetired {
        /// Exact incomplete-NAL retirement.
        fragment: FragmentDiscard,
        /// Pending picture retired before later NAL admission.
        picture: Option<AvcAssemblyRetirement>,
    },
    /// One owned NAL was admitted or returned intact with a typed refusal.
    Assembly(AvcAssemblyStep),
    /// A marked group retained by the previous bounded admission step is ready.
    Picture(AvcPictureGroup),
    /// A pending picture reached its own deadline or contained no primary picture.
    PictureRetired(AvcAssemblyRetirement),
    /// All immediate work is drained; the owner must arrange the supplied wake.
    Pending {
        /// Earliest monotonic transport/reconstruction/picture deadline.
        wake_at_ns: Option<u64>,
    },
    /// Transport and derivatives drained. A remaining picture has an explicit
    /// unverified EOF boundary; interrupted reconstruction retires it instead.
    Ended {
        /// Any incomplete NAL retired at transport EOF.
        fragment: Option<FragmentDiscard>,
        /// Any picture retired because EOF interrupted its input.
        interrupted_picture: Option<AvcAssemblyRetirement>,
        /// Final picture or metadata-only retirement. None on repeated terminal polls.
        tail: Option<AvcAssemblyOutput>,
    },
}

/// Composed owner-driven RTP → ordered NAL → exact-config picture grouping.
///
/// Every delivery gap, codec refusal, fragment timeout, restart, and cancellation
/// is propagated into picture assembly here, rather than relying on caller glue.
/// No socket, clock, thread, effect authority, decoder, or completeness claim is
/// introduced. The owner independently retains original ingress source custody.
pub struct AvcReceiver {
    key: StreamKey,
    transport: H264Receiver,
    assembler: AvcAssembler,
    pending_nals: std::vec::IntoIter<NalUnit>,
    last_now_ns: u64,
    finishing: bool,
    ended: bool,
}

impl std::fmt::Debug for AvcReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AvcReceiver")
            .field("key", &self.key)
            .field("transport", &self.transport)
            .field("assembler", &self.assembler)
            .field("queued_nals", &self.pending_nals.len())
            .field("last_now_ns", &self.last_now_ns)
            .field("finishing", &self.finishing)
            .field("ended", &self.ended)
            .finish_non_exhaustive()
    }
}

impl AvcReceiver {
    /// Open a negotiated stream with independently validated budgets and exact
    /// parsed SPS/PPS. Out-of-band parameter bytes need their own owner custody.
    pub fn new(
        key: StreamKey,
        payload_type: u8,
        mode: H264Mode,
        limits: AvcReceiveLimits,
        parameters: (AvcSps, AvcPps),
    ) -> Result<Self, AvcReceiveError> {
        let assembler = AvcAssembler::new(
            key,
            parameters.0,
            parameters.1,
            limits.syntax,
            limits.assembly,
        )
        .map_err(AvcReceiveError::Assembly)?;
        let transport = H264Receiver::new(
            key,
            payload_type,
            mode,
            limits.reorder,
            limits.reconstruction,
        )
        .map_err(AvcReceiveError::Transport)?;
        Ok(Self {
            key,
            transport,
            assembler,
            pending_nals: Vec::new().into_iter(),
            last_now_ns: 0,
            finishing: false,
            ended: false,
        })
    }

    /// Transport accounting; late recovery cannot retract prior picture retirements.
    pub fn stats(&self) -> SequenceStats {
        self.transport.stats()
    }
    /// Queued original datagrams awaiting ordered delivery.
    pub fn queued_packets(&self) -> usize {
        self.transport.queued_packets()
    }
    /// Complete NALs awaiting bounded picture-admission steps.
    pub fn queued_nals(&self) -> usize {
        self.pending_nals.len()
    }
    /// Incomplete FU bytes plus queued complete NAL bytes plus pending picture bytes.
    /// Source-spool storage and metadata overhead are separate owner costs.
    pub fn retained_nal_bytes(&self) -> usize {
        self.transport.pending_nal_bytes()
            + self
                .pending_nals
                .as_slice()
                .iter()
                .map(|n| n.bytes().len())
                .sum::<usize>()
            + self.assembler.pending_bytes()
    }
    /// Earliest useful wake. Ready NALs, marked pictures, and EOF drain request
    /// immediate polling; other wakes preserve their original monotonic deadlines.
    pub fn next_wake_ns(&self) -> Option<u64> {
        if self.ended {
            return None;
        }
        if !self.pending_nals.as_slice().is_empty() || self.finishing {
            return Some(self.last_now_ns);
        }
        let wake = match (self.transport.next_wake_ns(), self.assembler.next_wake_ns()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        wake.map(|at| at.max(self.last_now_ns))
    }

    /// Admit complete original wire bytes. Failed admission preserves all state;
    /// confirmed source restart retires all old-epoch derivatives immediately.
    pub fn ingest(
        &mut self,
        key: StreamKey,
        wire: &[u8],
        now_ns: u64,
    ) -> Result<AvcReceiveAdmission, AvcReceiveError> {
        self.check_time(now_ns)?;
        let transport = self
            .transport
            .ingest(key, wire, now_ns)
            .map_err(AvcReceiveError::Transport)?;
        self.last_now_ns = now_ns;
        let (queued_nals, picture) =
            if transport.transport.disposition == ReorderDisposition::RestartRequired {
                let picture = self
                    .assembler
                    .discontinuity(self.key, now_ns)
                    .map_err(AvcReceiveError::Assembly)?;
                let _ = self.assembler.cancel(); // discontinuity already returned the sole pending receipt.
                self.ended = true;
                (Some(self.retire_queue()), picture)
            } else {
                (None, None)
            };
        Ok(AvcReceiveAdmission {
            transport,
            queued_nals,
            picture,
        })
    }

    /// Perform at most one visible progress step. Drive until Pending/Ended after
    /// ingress and at timer wakes. Original source events precede their NAL steps.
    pub fn poll(&mut self, now_ns: u64) -> Result<AvcReceivePoll, AvcReceiveError> {
        self.check_time(now_ns)?;
        self.last_now_ns = now_ns;
        if self.ended {
            return Ok(AvcReceivePoll::Ended {
                fragment: None,
                interrupted_picture: None,
                tail: None,
            });
        }
        match self
            .assembler
            .poll(now_ns)
            .map_err(AvcReceiveError::Assembly)?
        {
            AvcAssemblyPoll::Picture(picture) => return Ok(AvcReceivePoll::Picture(picture)),
            AvcAssemblyPoll::Retired(retired) => {
                return Ok(AvcReceivePoll::PictureRetired(retired));
            }
            AvcAssemblyPoll::Pending { .. } | AvcAssemblyPoll::Ended => {}
        }
        if let Some(nal) = self.pending_nals.next() {
            let was_end_stream = nal.nal_type() == 11;
            let step = self.assembler.push(nal, now_ns);
            let fenced = matches!(&step, AvcAssemblyStep::Refused(r)
                if r.reason == AvcAssemblyError::ConfigurationChanged);
            if fenced || (was_end_stream && matches!(&step, AvcAssemblyStep::Accepted(_))) {
                self.finish();
            }
            return Ok(AvcReceivePoll::Assembly(step));
        }
        match self
            .transport
            .poll(now_ns)
            .map_err(AvcReceiveError::Transport)?
        {
            H264ReceivePoll::Packet {
                source,
                reconstruction,
            } => match reconstruction {
                Ok(H264Output {
                    status,
                    nals,
                    gap_before,
                    discarded,
                }) => {
                    let picture = if gap_before || discarded.is_some() {
                        self.assembler
                            .discontinuity(self.key, now_ns)
                            .map_err(AvcReceiveError::Assembly)?
                    } else {
                        None
                    };
                    let queued_nals = nals.len();
                    self.pending_nals = nals.into_iter();
                    Ok(AvcReceivePoll::Source {
                        source,
                        status,
                        queued_nals,
                        gap_before,
                        fragment: discarded,
                        picture,
                    })
                }
                Err(error) => {
                    let picture = self
                        .assembler
                        .discontinuity(self.key, now_ns)
                        .map_err(AvcReceiveError::Assembly)?;
                    Ok(AvcReceivePoll::CodecRefused {
                        source,
                        error,
                        picture,
                    })
                }
            },
            H264ReceivePoll::Gap { gap, discarded } => {
                let picture = self
                    .assembler
                    .discontinuity(self.key, now_ns)
                    .map_err(AvcReceiveError::Assembly)?;
                Ok(AvcReceivePoll::Gap {
                    gap,
                    fragment: discarded,
                    picture,
                })
            }
            H264ReceivePoll::FragmentDiscarded(fragment) => {
                let picture = self
                    .assembler
                    .discontinuity(self.key, now_ns)
                    .map_err(AvcReceiveError::Assembly)?;
                Ok(AvcReceivePoll::FragmentRetired { fragment, picture })
            }
            H264ReceivePoll::Pending { .. } => Ok(AvcReceivePoll::Pending {
                wake_at_ns: self.next_wake_ns(),
            }),
            H264ReceivePoll::Ended { discarded } => {
                let interrupted_picture = if discarded.is_some() {
                    self.assembler
                        .discontinuity(self.key, now_ns)
                        .map_err(AvcReceiveError::Assembly)?
                } else {
                    None
                };
                let tail = self
                    .assembler
                    .finish(now_ns)
                    .map_err(AvcReceiveError::Assembly)?;
                self.ended = true;
                Ok(AvcReceivePoll::Ended {
                    fragment: discarded,
                    interrupted_picture,
                    tail: Some(tail),
                })
            }
        }
    }

    /// Stop new transport admission, then drain every accepted packet and complete
    /// NAL through poll before picture EOF. Does not implicitly advance time.
    pub fn finish(&mut self) {
        self.finishing = true;
        self.transport.finish();
    }

    /// Cancel immediately with separate accounting for all derivative layers.
    pub fn cancel(&mut self) -> AvcReceiveCancellation {
        self.ended = true;
        AvcReceiveCancellation {
            transport: self.transport.cancel(),
            queued_nals: self.retire_queue(),
            picture: self.assembler.cancel(),
        }
    }

    /// Validate a strictly newer epoch before retiring this receiver. A refused
    /// reconfiguration changes nothing. Successful restart returns all old receipts.
    pub fn restart(
        &mut self,
        key: StreamKey,
        payload_type: u8,
        mode: H264Mode,
        limits: AvcReceiveLimits,
        parameters: (AvcSps, AvcPps),
    ) -> Result<(Self, AvcReceiveCancellation), AvcReceiveError> {
        if key.ingress != self.key.ingress {
            return Err(AvcReceiveError::Assembly(AvcAssemblyError::StreamMismatch));
        }
        if key.generation <= self.key.generation {
            return Err(AvcReceiveError::Assembly(
                AvcAssemblyError::GenerationRequired,
            ));
        }
        let next = Self::new(key, payload_type, mode, limits, parameters)?;
        Ok((next, self.cancel()))
    }

    fn check_time(&self, now_ns: u64) -> Result<(), AvcReceiveError> {
        if now_ns < self.last_now_ns {
            return Err(AvcReceiveError::Assembly(AvcAssemblyError::ClockReversed));
        }
        Ok(())
    }

    fn retire_queue(&mut self) -> AvcQueuedNalRetirement {
        let queue = self.pending_nals.as_slice();
        let receipt = AvcQueuedNalRetirement {
            key: self.key,
            nals: queue.len(),
            bytes: queue.iter().map(|n| n.bytes().len()).sum(),
            first_sequence: queue
                .first()
                .and_then(|n| n.sources().first())
                .map(|s| s.sequence),
            last_sequence: queue
                .last()
                .and_then(|n| n.sources().last())
                .map(|s| s.sequence),
        };
        self.pending_nals = Vec::new().into_iter();
        receipt
    }
}
