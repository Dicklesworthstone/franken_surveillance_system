#![forbid(unsafe_code)]
//! Reconstructible local-daemon SNTP evidence for one native site observation.
//!
//! The packet bytes and bracketed host samples remain untrusted supplied
//! evidence. Reconstruction proves internal consistency and conservative interval
//! arithmetic, not server authentication, clock accuracy, camera exposure time,
//! uninterrupted clock continuity or persistence of the source bytes. The native
//! caller must bind the one-use exchange and first RTP observation to its own
//! explicitly authorized session.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use fss_core::{CanonicalEncoder, ContentDigest};
use fss_packet::ntp::{LocalExchange, SntpError, SntpLimits, SntpRequest, UnixTimeInterval};

use super::clock::{
    ClockCorrelation, ClockCorrelationError, ClockCorrelationPolicy, ClockOffsetInterval,
    HostClockSample, drift_ns, local_sample_window, validate_sample,
};
use super::{ClockWitness, MAX_CLOCK_UNCERTAINTY_NS};

/// Full, versioned evidence identity including observation and terminal samples.
pub const LOCAL_NTP_CLOCK_PROOF_DOMAIN: &str = "fss.site_local_ntp_clock_proof.v1";
/// Synchronization-source identity before binding one RTP observation bracket.
pub const LOCAL_NTP_EXCHANGE_DOMAIN: &str = "fss.site_local_ntp_exchange.v1";
/// Fixed maximum clock-read bracket in the explicitly selected native profile.
pub const LOCAL_NTP_MAX_SAMPLE_BRACKET_NS: u64 = 25_000_000;
/// Explicit native drift/slew assumption: 500 parts per million, not measured
/// synchronization precision or permission to adjust the host's clock.
pub const LOCAL_NTP_MAX_DRIFT_PPB: u64 = 500_000;
/// Maximum lifetime after the original synchronization bracket in this profile.
pub const LOCAL_NTP_MAX_AGE_NS: u64 = 60_000_000_000;
/// Native policy is exact and immutable under the versioned proof domain. A
/// different policy needs an independently defined profile, not hidden defaults.
pub const LOCAL_NTP_CLOCK_POLICY: ClockCorrelationPolicy = ClockCorrelationPolicy {
    max_sample_bracket_ns: LOCAL_NTP_MAX_SAMPLE_BRACKET_NS,
    max_drift_ppb: LOCAL_NTP_MAX_DRIFT_PPB,
    max_age_ns: LOCAL_NTP_MAX_AGE_NS,
};
/// Fixed basic-mode SNTP bounds for the local-daemon observation profile.
pub const LOCAL_NTP_LIMITS: SntpLimits = SntpLimits {
    max_exchange_ns: 1_000_000_000,
    max_offset_ns: 10_000_000_000,
    max_uncertainty_ns: 10_000_000_000,
};

/// Exact supplied exchange and host samples needed to reconstruct a site-node
/// clock witness. The peer must be an explicitly selected literal loopback
/// endpoint; its presence here grants no network authority.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct LocalNtpClockProof {
    /// Exact UDP peer, with a nonzero port and no IPv6 zone or flow identifier.
    pub peer: SocketAddr,
    /// Exact 48-byte request generated from `sent_before.wall_clock_unix_ns`.
    pub request: [u8; 48],
    /// Exact complete 48-byte server reply, before any parsing or projection.
    pub reply: [u8; 48],
    /// Host sample completed before request transmission.
    pub sent_before: HostClockSample,
    /// Host sample begun after request transmission.
    pub sent_after: HostClockSample,
    /// Host sample completed before response reception.
    pub received_before: HostClockSample,
    /// Host sample begun after response reception; the correlation's origin.
    pub received_after: HostClockSample,
    /// Monotonic admission coordinate before the native processing step which
    /// observed the first semantically confirmed picture's RTP timestamp. The
    /// step may consume previously buffered input, not a fresh socket read.
    pub observation_start_ns: u64,
    /// Monotonic coordinate after that complete native processing step. The
    /// whole bracket widens uncertainty; no kernel arrival, socket-read time or
    /// camera capture time is claimed.
    pub observation_end_ns: u64,
    /// Final sample after the observed prefix, checked for sampled discontinuity.
    pub terminal: HostClockSample,
    /// Explicit fixed profile, retained so a consumer can replay its assumptions.
    pub policy: ClockCorrelationPolicy,
}

impl fmt::Debug for LocalNtpClockProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalNtpClockProof")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

/// Payload-free native clock-proof refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockProofError {
    /// The peer is not a supported literal loopback endpoint.
    Peer,
    /// A supplied policy does not equal the versioned native profile.
    Policy,
    /// Host/exchange/observation/terminal brackets are out of order.
    ObservationOrder,
    /// The exact request differs from the canonical request for its host sample.
    RequestMismatch,
    /// Leap seconds and leap smear do not yet have an admitted native mapping.
    LeapUnsupported,
    /// Native packet evidence was refused by the SNTP owner.
    Ntp(SntpError),
    /// Correlation bounds or sampled host-clock continuity were refused.
    Correlation(ClockCorrelationError),
    /// Required interval widening or symmetric endpoints cannot be represented.
    ArithmeticOverflow,
    /// Canonical evidence encoding exceeded its declared bounds.
    Canonical,
}

impl fmt::Display for ClockProofError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Peer => formatter.write_str("site NTP peer is not a supported loopback endpoint"),
            Self::Policy => formatter.write_str("site NTP policy differs from its native profile"),
            Self::ObservationOrder => {
                formatter.write_str("site clock observation brackets are out of order")
            }
            Self::RequestMismatch => {
                formatter.write_str("site NTP request does not match its host sample")
            }
            Self::LeapUnsupported => {
                formatter.write_str("site NTP leap indication has no admitted clock mapping")
            }
            Self::Ntp(error) => error.fmt(formatter),
            Self::Correlation(error) => error.fmt(formatter),
            Self::ArithmeticOverflow => {
                formatter.write_str("site NTP witness widening is not representable")
            }
            Self::Canonical => formatter.write_str("site NTP evidence encoding failed"),
        }
    }
}

impl std::error::Error for ClockProofError {}

impl From<ClockCorrelationError> for ClockProofError {
    fn from(error: ClockCorrelationError) -> Self {
        Self::Correlation(error)
    }
}

impl From<SntpError> for ClockProofError {
    fn from(error: SntpError) -> Self {
        Self::Ntp(error)
    }
}

impl LocalNtpClockProof {
    /// Admit the synchronization exchange and return its checked correlation for
    /// live host-clock monitoring. This checks only the peer, policy, packet bytes
    /// and four exchange samples. Observation and terminal fields are checked by
    /// [`Self::reconstruct`] after the native caller has observed its prefix.
    /// No placeholder precision or authenticated-server claim is introduced.
    pub fn correlation(&self) -> Result<ClockCorrelation, ClockProofError> {
        self.validate_scope_and_samples()?;
        let request = SntpRequest::new(self.sent_before.wall_clock_unix_ns)?;
        if request.wire_bytes() != &self.request {
            return Err(ClockProofError::RequestMismatch);
        }
        let observed = request.evaluate_reply(
            &self.reply,
            LocalExchange {
                sent: UnixTimeInterval {
                    earliest_ns: self.sent_before.wall_clock_unix_ns,
                    latest_ns: self.sent_after.wall_clock_unix_ns,
                },
                received: UnixTimeInterval {
                    earliest_ns: self.received_before.wall_clock_unix_ns,
                    latest_ns: self.received_after.wall_clock_unix_ns,
                },
            },
            LOCAL_NTP_LIMITS,
        )?;
        if observed.leap_indicator != 0 {
            return Err(ClockProofError::LeapUnsupported);
        }

        // The packet owner includes its stated nominal 15 ppm allowance. Add
        // this profile's independent host drift bound over the complete exchange
        // rather than treating that nominal protocol allowance as measured
        // oscillator precision. No subtraction cancels either error source.
        let exchange_span = self
            .received_after
            .monotonic_after_ns
            .checked_sub(self.sent_before.monotonic_before_ns)
            .ok_or(ClockProofError::ObservationOrder)?;
        if exchange_span > LOCAL_NTP_LIMITS.max_exchange_ns {
            return Err(ClockProofError::Ntp(SntpError::ExchangeLimit));
        }
        let exchange_drift = i64::try_from(drift_ns(exchange_span, self.policy.max_drift_ppb)?)
            .map_err(|_| ClockProofError::ArithmeticOverflow)?;
        let offset = ClockOffsetInterval {
            lower_ns: observed
                .offset_interval_ns
                .lower_ns
                .checked_sub(exchange_drift)
                .ok_or(ClockProofError::ArithmeticOverflow)?,
            upper_ns: observed
                .offset_interval_ns
                .upper_ns
                .checked_add(exchange_drift)
                .ok_or(ClockProofError::ArithmeticOverflow)?,
        };
        Ok(ClockCorrelation::new(
            self.received_after,
            offset,
            self.exchange_digest_unchecked()?,
            self.policy,
        )?)
    }

    /// Recompute the exact unchanged v1 witness from raw protocol and clock
    /// evidence. Every field is checked on each call, including direct struct
    /// literals; successful reconstruction is not a server-authentication claim.
    pub fn reconstruct(&self) -> Result<ClockWitness, ClockProofError> {
        let mut correlation = self.correlation()?;
        validate_sample(self.terminal, self.policy)?;
        if self.observation_start_ns < self.received_after.monotonic_after_ns
            || self.observation_end_ns < self.observation_start_ns
            || self.terminal.monotonic_before_ns < self.observation_end_ns
        {
            return Err(ClockProofError::ObservationOrder);
        }
        correlation.observe_later_sample(self.terminal)?;
        let mut witness = correlation.witness_at(self.observation_start_ns)?;
        let observation_span = self.observation_end_ns - self.observation_start_ns;
        let observation_growth = observation_span
            .checked_add(drift_ns(observation_span, self.policy.max_drift_ppb)?)
            .ok_or(ClockProofError::ArithmeticOverflow)?;
        witness.ntp_uncertainty_ns = witness
            .ntp_uncertainty_ns
            .checked_add(observation_growth)
            .ok_or(ClockProofError::ArithmeticOverflow)?;
        if witness.ntp_uncertainty_ns > MAX_CLOCK_UNCERTAINTY_NS {
            return Err(ClockProofError::Correlation(
                ClockCorrelationError::UncertaintyLimit,
            ));
        }
        witness
            .wall_clock_unix_ns
            .checked_sub(witness.ntp_uncertainty_ns)
            .and_then(|_| {
                witness
                    .wall_clock_unix_ns
                    .checked_add(witness.ntp_uncertainty_ns)
            })
            .ok_or(ClockProofError::ArithmeticOverflow)?;
        witness
            .validate()
            .map_err(|_| ClockProofError::Correlation(ClockCorrelationError::UncertaintyLimit))?;
        Ok(witness)
    }

    /// Full proof identity after successful reconstruction. Even unused raw
    /// server metadata and all sampling/policy fields remain digest-bound.
    pub fn digest(&self) -> Result<ContentDigest, ClockProofError> {
        self.reconstruct()?;
        let mut encoder = CanonicalEncoder::new();
        encoder.text(LOCAL_NTP_CLOCK_PROOF_DOMAIN);
        encoder.digest(self.exchange_digest_unchecked()?);
        encoder.u64(self.observation_start_ns);
        encoder.u64(self.observation_end_ns);
        encode_sample(&mut encoder, self.terminal);
        finish_digest(encoder)
    }

    /// Exact synchronization-only source identity after admitting the exchange.
    /// Observation and terminal fields are outside this source identity. This
    /// does not make the source authenticated or durably retained.
    pub fn source_digest(&self) -> Result<ContentDigest, ClockProofError> {
        self.correlation()?;
        self.exchange_digest_unchecked()
    }

    fn validate_scope_and_samples(&self) -> Result<(), ClockProofError> {
        if !self.peer.ip().is_loopback()
            || self.peer.port() == 0
            || matches!(self.peer, SocketAddr::V6(peer) if peer.flowinfo() != 0 || peer.scope_id() != 0)
        {
            return Err(ClockProofError::Peer);
        }
        if self.policy != LOCAL_NTP_CLOCK_POLICY {
            return Err(ClockProofError::Policy);
        }
        let samples = [
            self.sent_before,
            self.sent_after,
            self.received_before,
            self.received_after,
        ];
        for sample in samples {
            validate_sample(sample, self.policy)?;
        }
        for pair in samples.windows(2) {
            if pair[0].monotonic_after_ns > pair[1].monotonic_before_ns {
                return Err(ClockProofError::ObservationOrder);
            }
            let from_previous = local_sample_window(pair[0], pair[1], self.policy.max_drift_ppb)?;
            let from_origin =
                local_sample_window(self.sent_before, pair[1], self.policy.max_drift_ppb)?;
            if !from_previous.contains(pair[1].wall_clock_unix_ns)
                || !from_origin.contains(pair[1].wall_clock_unix_ns)
            {
                return Err(ClockProofError::Correlation(
                    ClockCorrelationError::WallClockDiscontinuity,
                ));
            }
        }
        Ok(())
    }

    fn exchange_digest_unchecked(&self) -> Result<ContentDigest, ClockProofError> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(LOCAL_NTP_EXCHANGE_DOMAIN);
        match self.peer.ip() {
            IpAddr::V4(ip) => {
                encoder.tag(4);
                encoder.bytes(&ip.octets());
            }
            IpAddr::V6(ip) => {
                encoder.tag(6);
                encoder.bytes(&ip.octets());
            }
        }
        encoder.u32(u32::from(self.peer.port()));
        encoder.bytes(&self.request);
        encoder.bytes(&self.reply);
        for sample in [
            self.sent_before,
            self.sent_after,
            self.received_before,
            self.received_after,
        ] {
            encode_sample(&mut encoder, sample);
        }
        encoder.u64(self.policy.max_sample_bracket_ns);
        encoder.u64(self.policy.max_drift_ppb);
        encoder.u64(self.policy.max_age_ns);
        finish_digest(encoder)
    }
}

fn encode_sample(encoder: &mut CanonicalEncoder, sample: HostClockSample) {
    encoder.u64(sample.monotonic_before_ns);
    encoder.u64(sample.wall_clock_unix_ns);
    encoder.u64(sample.monotonic_after_ns);
}

fn finish_digest(encoder: CanonicalEncoder) -> Result<ContentDigest, ClockProofError> {
    let bytes = encoder
        .finish_checked()
        .map_err(|_| ClockProofError::Canonical)?;
    ContentDigest::try_sha256(&bytes).map_err(|_| ClockProofError::Canonical)
}
