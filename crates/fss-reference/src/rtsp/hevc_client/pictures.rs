#![forbid(unsafe_code)]
//! Picture-aware composition of the existing authenticated RTSP HEVC client.
//!
//! Original control/RTP/RTCP ownership is preserved. All reported media gaps,
//! codec failures and incomplete-FU EOF invalidate picture assembly automatically.
//! No parallel RTSP grammar, authentication state, source spool or decoder exists.

use super::*;
use fss_packet::hevc::{
    HevcAssembler, HevcAssemblyError, HevcAssemblyLimits, HevcAssemblyOutput,
    HevcAssemblyRetirement, HevcAssemblyStep,
};
use fss_packet::{H265FragmentDiscard, H265NalUnit, H265Status, OrderedRtpPacket, ReorderGap};

/// Payload-free refusal from either existing semantic owner or this bounded composition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HevcPictureClientError {
    /// Existing RTSP/HEVC/authentication refusal, with no wire contents.
    Client(HevcClientError),
    /// Picture owner, time, or policy refusal.
    Assembly(HevcAssemblyError),
    /// Drain complete queued NALs first; no request, credentials or input was consumed.
    Backpressure,
    /// A queued-NAL deadline cannot be represented at the supplied owner time.
    DeadlineExhausted,
    /// This picture-aware connection is closed.
    Closed,
}
impl fmt::Display for HevcPictureClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RTSP HEVC picture refusal: {self:?}")
    }
}
impl std::error::Error for HevcPictureClientError {}

/// Why this composition retired retained picture work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HevcPictureWorkReason {
    /// The existing client closed or reported a source restart/fatal fault.
    ClientTerminal,
    /// Complete NALs waited past their original bounded residence deadline.
    QueueDeadline,
    /// Owner cancellation, independent of whether remote TEARDOWN was acknowledged.
    Cancelled,
    /// An admitted EOB ended this bitstream; later input needs a new connection/epoch.
    EndOfBitstream,
}

/// Accounting for complete NALs retired before picture admission.
/// Their original source datagrams were already returned to the transport owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HevcQueuedNalRetirement {
    /// Exact owner epoch of the queue.
    pub key: StreamKey,
    /// Complete NAL count retired.
    pub nals: usize,
    /// Reconstructed byte count retired.
    pub bytes: usize,
    /// First contributing sequence, absent when no complete NAL was queued.
    pub first_sequence: Option<u64>,
    /// Last contributing sequence, absent when the queue was empty.
    pub last_sequence: Option<u64>,
}

/// Picture-side retirement without duplicating the existing transport receipts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HevcPictureWorkRetirement {
    /// Cause at the composition boundary.
    pub reason: HevcPictureWorkReason,
    /// Complete NALs whose original datagrams were already transferred to the owner.
    pub queued: HevcQueuedNalRetirement,
    /// Pending picture/prefix invalidated before later admission.
    pub picture: Option<HevcAssemblyRetirement>,
}

/// Complete local shutdown, preserving the existing client's source/remote-state receipts.
#[derive(Debug)]
pub struct HevcPictureClientRetirement {
    /// TCP lookahead, challenges, RTP/FU work and remote-session uncertainty.
    pub client: HevcClientRetirement,
    /// Complete queued NALs and pending picture work.
    pub work: HevcPictureWorkRetirement,
}

/// Input/request failure. No retirement means a safe, unconsumed refusal.
#[derive(Debug)]
pub struct HevcPictureClientFailure {
    /// Typed refusal category.
    pub reason: HevcPictureClientError,
    /// Present only when this operation closed every local layer.
    pub retirement: Option<Box<HevcPictureClientRetirement>>,
}
impl fmt::Display for HevcPictureClientFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.reason, f)
    }
}
impl std::error::Error for HevcPictureClientFailure {}

/// One bounded original-source, picture, refusal or retirement step.
#[derive(Debug)]
pub enum HevcPictureClientPoll {
    /// Unchanged control/authentication/RTP-admission/RTCP event from the existing client.
    Client {
        /// Original event, including exact source frames and any transport retirement.
        event: Box<HevcClientPoll>,
        /// Present when the inner event also closed picture work, without repeating its receipts.
        work: Option<HevcPictureWorkRetirement>,
    },
    /// Original ordered RTP datagram before any of its complete NALs enter assembly.
    Source {
        /// Original datagram, including headers, extensions and padding.
        source: OrderedRtpPacket,
        /// Existing reconstruction disposition, not a picture/decoding claim.
        status: H265Status,
        /// Complete NALs queued for subsequent one-at-a-time assembly steps.
        queued_nals: usize,
        /// Reconstruction's explicit sequence gap observation.
        gap_before: bool,
        /// Any incomplete FU retired by reconstruction.
        fragment: Option<H265FragmentDiscard>,
        /// Pending picture automatically invalidated by a gap or fragment retirement.
        picture: Option<HevcAssemblyRetirement>,
    },
    /// Codec refusal still returns its exact original datagram and invalidates grouping.
    CodecRefused {
        /// Original source packet for the failed reconstruction.
        source: OrderedRtpPacket,
        /// Existing codec/packet refusal, including any incomplete-FU receipt.
        error: H265ReceiveError,
        /// Picture retired before any subsequent complete NAL is admitted.
        picture: Option<HevcAssemblyRetirement>,
    },
    /// Ordered-delivery loss immediately invalidates both derivative layers.
    Gap {
        /// Exact missing delivery range, not physical absence.
        gap: ReorderGap,
        /// Incomplete FU retired by the lower layer.
        fragment: Option<H265FragmentDiscard>,
        /// Pending grouping retired by this composition.
        picture: Option<HevcAssemblyRetirement>,
    },
    /// Fragment lifetime expired even without another network packet.
    FragmentRetired {
        /// Existing incomplete-fragment receipt.
        fragment: H265FragmentDiscard,
        /// Pending picture invalidated automatically.
        picture: Option<HevcAssemblyRetirement>,
    },
    /// One NAL entered assembly, or was returned intact with its refusal.
    Assembly {
        /// Existing ownership-preserving assembler result.
        step: HevcAssemblyStep,
        /// EOB closes all local layers; later buffered wire is retained here.
        retirement: Option<Box<HevcPictureClientRetirement>>,
    },
    /// Pending picture expired without flushing a false complete picture.
    PictureRetired(HevcAssemblyRetirement),
    /// Complete queued NALs expired before assembly; the connection may safely continue.
    QueueRetired(HevcPictureWorkRetirement),
    /// No immediate work. This wake includes picture deadlines as well as client deadlines.
    Pending {
        /// Earliest useful owner-supplied monotonic timer wake.
        wake_at_ns: Option<u64>,
    },
    /// Composition could not retain source output. The original event is transferred intact.
    Fault {
        /// Typed refusal, never payload text.
        reason: HevcPictureClientError,
        /// Complete local shutdown with remote-session uncertainty preserved.
        retirement: Box<HevcPictureClientRetirement>,
        /// Original inner event that could not be consumed, including all its NALs.
        source: Box<HevcClientPoll>,
    },
    /// Existing EOF/TEARDOWN completion plus a separately classified picture tail.
    Ended {
        /// Original terminal client event and transport receipts, absent on repeated polls.
        client: Option<Box<HevcClientPoll>>,
        /// Picture invalidated because EOF interrupted a FU; such a picture is never flushed.
        interrupted_picture: Option<HevcAssemblyRetirement>,
        /// Unverified EOF group or metadata-only retirement, absent on repeated polls.
        tail: Option<HevcAssemblyOutput>,
    },
}

/// Authenticated/plain RTSP -> ordered HEVC NALs -> source-linked picture grouping.
///
/// The ordinary RtspHevcClient remains unchanged. This type privately owns it;
/// no mutable inner session or public injection path can bypass loss propagation.
/// NAL bytes are moved, not cloned. The extra queue is bounded by one admitted
/// reconstruction output and a fixed lifetime from its original Source event.
pub struct RtspHevcPictureClient {
    inner: RtspHevcClient,
    assembler: HevcAssembler,
    key: StreamKey,
    limits: HevcAssemblyLimits,
    pending: std::vec::IntoIter<H265NalUnit>,
    pending_deadline_ns: Option<u64>,
    last_ns: u64,
    closed: bool,
}
impl fmt::Debug for RtspHevcPictureClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtspHevcPictureClient")
            .field("client", &self.inner)
            .field("assembler", &self.assembler)
            .field("queued_nals", &self.pending.len())
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}
impl RtspHevcPictureClient {
    /// Pin the same owner/source/transport bounds, plus independent picture bounds.
    pub fn new(
        config: ClientConfig,
        key: StreamKey,
        reorder: ReorderLimits,
        reconstruction: H265Limits,
        assembly: HevcAssemblyLimits,
    ) -> Result<Self, HevcPictureClientError> {
        let assembler =
            HevcAssembler::new(key, assembly).map_err(HevcPictureClientError::Assembly)?;
        let inner = RtspHevcClient::new(config, key, reorder, reconstruction)
            .map_err(HevcPictureClientError::Client)?;
        Ok(Self {
            inner,
            assembler,
            key,
            limits: assembly,
            pending: Vec::new().into_iter(),
            pending_deadline_ns: None,
            last_ns: 0,
            closed: false,
        })
    }
    /// Pin the existing Digest policy/realm before any request; credentials remain borrowed.
    pub fn with_digest(
        config: ClientConfig,
        key: StreamKey,
        reorder: ReorderLimits,
        reconstruction: H265Limits,
        assembly: HevcAssemblyLimits,
        realm: &str,
        policy: DigestPolicy,
    ) -> Result<Self, HevcPictureClientError> {
        let mut client = Self::new(config, key, reorder, reconstruction, assembly)?;
        client
            .inner
            .session
            .enable_digest(realm, policy)
            .map_err(|e| HevcPictureClientError::Client(HevcClientError::Authentication(e)))?;
        client.inner.digest_enabled = true;
        Ok(client)
    }
    /// Existing RTSP protocol state; not decoded-frame or coverage truth.
    pub fn state(&self) -> ClientState {
        self.inner.state()
    }
    /// Immutable accepted HEVC signaling; not parsed parameter-set compatibility.
    pub fn media(&self) -> Option<&HevcClientMedia> {
        self.inner.media()
    }
    /// Exact TCP bytes retained by the existing client.
    pub fn buffered_wire_bytes(&self) -> usize {
        self.inner.buffered_wire_bytes()
    }
    /// Original RTP bytes still awaiting ordered delivery.
    pub fn queued_rtp_bytes(&self) -> usize {
        self.inner.queued_rtp_bytes()
    }
    /// Complete reconstructed NALs not yet admitted to a picture.
    pub fn queued_nals(&self) -> usize {
        self.pending.len()
    }
    /// Incomplete FU, complete queued NAL and picture bytes; source storage is independent.
    pub fn retained_nal_bytes(&self) -> usize {
        self.inner.retained_nal_bytes()
            + self.assembler.pending_bytes()
            + self
                .pending
                .as_slice()
                .iter()
                .map(|n| n.bytes().len())
                .sum::<usize>()
    }
    /// Include picture and complete-NAL residence timers even during authentication waits.
    pub fn next_wake_ns(&self) -> Option<u64> {
        if self.closed {
            return None;
        }
        if self.pending.len() != 0 {
            return Some(self.last_ns);
        }
        earlier(self.inner.next_wake_ns(), self.assembler.next_wake_ns())
            .map(|at| at.max(self.last_ns))
    }
    /// Prepare one request through the existing plain client. No send occurs here.
    pub fn request(
        &mut self,
        command: ClientCommand,
        now: u64,
    ) -> Result<ClientRequest, HevcPictureClientFailure> {
        self.admit_call(now)?;
        let result = self.inner.request(command, now);
        result.map_err(|e| self.map_failure(e))
    }
    /// Borrow credentials/cnonce for the shared Digest lifecycle; no new authentication logic.
    pub fn request_digest(
        &mut self,
        command: ClientCommand,
        credentials: &DigestCredentials<'_>,
        cnonce: [u8; 16],
        now: u64,
    ) -> Result<ClientRequest, HevcPictureClientFailure> {
        self.admit_call(now)?;
        let result = self.inner.request_digest(command, credentials, cnonce, now);
        result.map_err(|e| self.map_failure(e))
    }
    /// Answer the held exact challenge through the original client, preserving both outputs.
    pub fn respond_digest(
        &mut self,
        credentials: &DigestCredentials<'_>,
        cnonce: [u8; 16],
        now: u64,
    ) -> Result<HevcChallengeResponse, HevcPictureClientFailure> {
        self.admit_call(now)?;
        let result = self.inner.respond_digest(credentials, cnonce, now);
        result.map_err(|e| self.map_failure(e))
    }
    /// Feed bounded TCP input. Drain queued NALs first; refused input remains caller-owned.
    pub fn ingest(&mut self, bytes: &[u8], now: u64) -> Result<(), HevcPictureClientFailure> {
        self.admit_call(now)?;
        let result = self.inner.ingest(bytes, now);
        result.map_err(|e| self.map_failure(e))
    }
    /// Perform one bounded progress step; every original source event precedes its NAL steps.
    pub fn poll(&mut self, now: u64) -> Result<HevcPictureClientPoll, HevcPictureClientError> {
        self.check_time(now)?;
        self.last_ns = now;
        if self.closed {
            return Ok(HevcPictureClientPoll::Ended {
                client: None,
                interrupted_picture: None,
                tail: None,
            });
        }
        // Do not let queued derivatives postpone session/wire/challenge expiry.
        // This child module uses the SAME private deadline owner as the raw pump.
        self.inner.last_ns = now;
        if !self.inner.draining
            && let Some(error) = self.inner.deadline_error(now)
        {
            let event = self.inner.fault(error, None);
            return Ok(self.client_event(event));
        }
        if self.pending_deadline_ns.is_some_and(|at| now >= at) {
            let queued = self.retire_queue();
            let picture = self.assembler.discard_gap();
            return Ok(HevcPictureClientPoll::QueueRetired(
                HevcPictureWorkRetirement {
                    reason: HevcPictureWorkReason::QueueDeadline,
                    queued,
                    picture,
                },
            ));
        }
        if let Some(retired) = self
            .assembler
            .expire(now)
            .map_err(HevcPictureClientError::Assembly)?
        {
            return Ok(HevcPictureClientPoll::PictureRetired(retired));
        }
        if let Some(nal) = self.pending.next() {
            let eob = nal.nal_type() == 37;
            if self.pending.len() == 0 {
                self.pending = Vec::new().into_iter();
                self.pending_deadline_ns = None;
            }
            let step = self.assembler.push(nal, now);
            let retirement = if eob && matches!(&step, HevcAssemblyStep::Accepted(_)) {
                Some(Box::new(
                    self.cancel_with_reason(HevcPictureWorkReason::EndOfBitstream),
                ))
            } else {
                None
            };
            return Ok(HevcPictureClientPoll::Assembly { step, retirement });
        }
        let event = self
            .inner
            .poll(now)
            .map_err(HevcPictureClientError::Client)?;
        Ok(match event {
            HevcClientPoll::Media(H265ReceivePoll::Packet {
                source,
                reconstruction,
            }) => match reconstruction {
                Ok(output) => {
                    let deadline = now.checked_add(self.limits.max_age_ns);
                    if !output.nals.is_empty() && deadline.is_none() {
                        let source = HevcClientPoll::Media(H265ReceivePoll::Packet {
                            source,
                            reconstruction: Ok(output),
                        });
                        return Ok(HevcPictureClientPoll::Fault {
                            reason: HevcPictureClientError::DeadlineExhausted,
                            retirement: Box::new(
                                self.cancel_with_reason(HevcPictureWorkReason::ClientTerminal),
                            ),
                            source: Box::new(source),
                        });
                    }
                    let picture = if output.gap_before || output.discarded.is_some() {
                        self.assembler.discard_gap()
                    } else {
                        None
                    };
                    let queued_nals = output.nals.len();
                    self.pending = output.nals.into_iter();
                    self.pending_deadline_ns = if queued_nals == 0 { None } else { deadline };
                    HevcPictureClientPoll::Source {
                        source,
                        status: output.status,
                        queued_nals,
                        gap_before: output.gap_before,
                        fragment: output.discarded,
                        picture,
                    }
                }
                Err(error) => HevcPictureClientPoll::CodecRefused {
                    source,
                    error,
                    picture: self.assembler.discard_gap(),
                },
            },
            HevcClientPoll::Media(H265ReceivePoll::Gap { gap, discarded }) => {
                HevcPictureClientPoll::Gap {
                    gap,
                    fragment: discarded,
                    picture: self.assembler.discard_gap(),
                }
            }
            HevcClientPoll::Media(H265ReceivePoll::FragmentDiscarded(fragment)) => {
                HevcPictureClientPoll::FragmentRetired {
                    fragment,
                    picture: self.assembler.discard_gap(),
                }
            }
            event @ HevcClientPoll::Ended { .. } => {
                let interrupted = matches!(
                    &event,
                    HevcClientPoll::Ended {
                        media: Some(H265ReceivePoll::Ended { discarded: Some(_) }),
                        ..
                    }
                );
                let interrupted_picture = if interrupted {
                    self.assembler.discard_gap()
                } else {
                    None
                };
                let tail = self
                    .assembler
                    .finish(now)
                    .map_err(HevcPictureClientError::Assembly)?;
                self.closed = true;
                HevcPictureClientPoll::Ended {
                    client: Some(Box::new(event)),
                    interrupted_picture,
                    tail: Some(tail),
                }
            }
            HevcClientPoll::Pending { .. } => HevcPictureClientPoll::Pending {
                wake_at_ns: self.next_wake_ns(),
            },
            event => self.client_event(event),
        })
    }
    /// Stop TCP admission and drain accepted work. Incomplete-FU EOF cannot flush a picture.
    pub fn finish(&mut self) {
        self.inner.finish();
    }
    /// Cancel every local layer. Returned bytes/receipts never assert remote TEARDOWN success.
    pub fn cancel(&mut self) -> HevcPictureClientRetirement {
        self.cancel_with_reason(HevcPictureWorkReason::Cancelled)
    }
    fn cancel_with_reason(&mut self, reason: HevcPictureWorkReason) -> HevcPictureClientRetirement {
        let client = self.inner.cancel();
        let work = self.close_work(reason);
        HevcPictureClientRetirement { client, work }
    }
    fn client_event(&mut self, mut event: HevcClientPoll) -> HevcPictureClientPoll {
        let terminal = matches!(
            &event,
            HevcClientPoll::Fault { .. }
                | HevcClientPoll::Rtp {
                    retirement: Some(_),
                    ..
                }
        );
        let work = if terminal {
            Some(self.close_work(HevcPictureWorkReason::ClientTerminal))
        } else {
            None
        };
        // A raw client wait must not hide the picture assembler's earlier timer.
        match &mut event {
            HevcClientPoll::AuthenticationRequired { wake_at_ns, .. }
            | HevcClientPoll::Backpressure { wake_at_ns } => *wake_at_ns = self.next_wake_ns(),
            _ => {}
        }
        HevcPictureClientPoll::Client {
            event: Box::new(event),
            work,
        }
    }
    fn close_work(&mut self, reason: HevcPictureWorkReason) -> HevcPictureWorkRetirement {
        self.closed = true;
        HevcPictureWorkRetirement {
            reason,
            queued: self.retire_queue(),
            picture: self.assembler.cancel(),
        }
    }
    fn retire_queue(&mut self) -> HevcQueuedNalRetirement {
        let nals = self.pending.as_slice();
        let receipt = HevcQueuedNalRetirement {
            key: self.key,
            nals: nals.len(),
            bytes: nals.iter().map(|n| n.bytes().len()).sum(),
            first_sequence: nals
                .first()
                .and_then(|n| n.sources().first())
                .map(|s| s.sequence),
            last_sequence: nals
                .last()
                .and_then(|n| n.sources().last())
                .map(|s| s.sequence),
        };
        self.pending = Vec::new().into_iter();
        self.pending_deadline_ns = None;
        receipt
    }
    fn check_time(&self, now: u64) -> Result<(), HevcPictureClientError> {
        if now < self.last_ns {
            Err(HevcPictureClientError::Client(HevcClientError::Session(
                ClientError::ClockReversed,
            )))
        } else {
            Ok(())
        }
    }
    fn admit_call(&mut self, now: u64) -> Result<(), HevcPictureClientFailure> {
        self.check_time(now).map_err(safe_picture)?;
        if self.closed {
            return Err(safe_picture(HevcPictureClientError::Closed));
        }
        if self.pending.len() != 0 {
            return Err(safe_picture(HevcPictureClientError::Backpressure));
        }
        self.last_ns = now;
        Ok(())
    }
    fn map_failure(&mut self, failure: HevcClientFailure) -> HevcPictureClientFailure {
        let retirement = failure.retirement.map(|client| {
            Box::new(HevcPictureClientRetirement {
                client: *client,
                work: self.close_work(HevcPictureWorkReason::ClientTerminal),
            })
        });
        HevcPictureClientFailure {
            reason: HevcPictureClientError::Client(failure.reason),
            retirement,
        }
    }
}

fn safe_picture(reason: HevcPictureClientError) -> HevcPictureClientFailure {
    HevcPictureClientFailure {
        reason,
        retirement: None,
    }
}
