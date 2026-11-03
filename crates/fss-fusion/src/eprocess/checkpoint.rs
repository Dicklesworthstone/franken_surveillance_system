#![forbid(unsafe_code)]
//! Numerical-owner codec used only by the bounded source-once checkpoint.
//!
//! Private fields stay owned here: the public numerical accumulator has no mutable restoration
//! escape hatch, and the source-once owner validates its lifetime source inventory alongside us.

use std::collections::BTreeSet;

use fss_core::{CanonicalDecoder, CanonicalEncoder};

use super::{EProcessConfig, RegimeResetReason, SequentialEProcess};
use crate::model::{MAX_DOMAINS_PER_ITEM, MAX_TEXT, valid_text};
use crate::unique_source::checkpoint::{
    Result, UniqueSourceCheckpointError as Error, count, decode_optional_digest,
    encode_optional_digest, require_sha256,
};
use crate::{LlrInterval, MAX_UNIQUE_SOURCES};

const MAX_RESET_TEXT: usize = 65_536;
const INTRINSIC_PREFIX: &str = "sensor:";
const DOMAINS_PER_SOURCE: usize = MAX_DOMAINS_PER_ITEM + 1;

fn valid_domain(value: &str) -> bool {
    valid_text(value) || value.strip_prefix(INTRINSIC_PREFIX).is_some_and(valid_text)
}

fn reset_bound(reason: &RegimeResetReason) -> Result<()> {
    let valid = match reason {
        RegimeResetReason::SensorHealthDegraded { sensor, reason } => {
            sensor.len() <= MAX_RESET_TEXT && reason.len() <= MAX_RESET_TEXT
        }
        RegimeResetReason::ClockContinuityBroken { sensor, .. } => sensor.len() <= MAX_RESET_TEXT,
        RegimeResetReason::OperatorReset { reason } => reason.len() <= MAX_RESET_TEXT,
    };
    if valid { Ok(()) } else { Err(Error::Limit) }
}

fn text(decoder: &mut CanonicalDecoder<'_>, maximum: usize) -> Result<String> {
    // CanonicalDecoder borrows the bytes; the specific bound precedes the owned allocation.
    let value = decoder.text()?;
    if value.len() > maximum {
        return Err(Error::Limit);
    }
    Ok(value.to_owned())
}

fn integer(decoder: &mut CanonicalDecoder<'_>) -> Result<i64> {
    i64::try_from(decoder.i128()?).map_err(|_| Error::InvalidState)
}

fn encode_reset(encoder: &mut CanonicalEncoder, reason: Option<&RegimeResetReason>) {
    match reason {
        None => encoder.tag(0),
        Some(RegimeResetReason::SensorHealthDegraded { sensor, reason }) => {
            encoder.tag(1);
            encoder.text(sensor);
            encoder.text(reason);
        }
        Some(RegimeResetReason::ClockContinuityBroken { sensor, gap_ns }) => {
            encoder.tag(2);
            encoder.text(sensor);
            encoder.u64(*gap_ns);
        }
        Some(RegimeResetReason::OperatorReset { reason }) => {
            encoder.tag(3);
            encoder.text(reason);
        }
    }
}

fn decode_reset(decoder: &mut CanonicalDecoder<'_>) -> Result<Option<RegimeResetReason>> {
    Ok(match decoder.tag()? {
        0 => None,
        1 => Some(RegimeResetReason::SensorHealthDegraded {
            sensor: text(decoder, MAX_RESET_TEXT)?,
            reason: text(decoder, MAX_RESET_TEXT)?,
        }),
        2 => Some(RegimeResetReason::ClockContinuityBroken {
            sensor: text(decoder, MAX_RESET_TEXT)?,
            gap_ns: decoder.u64()?,
        }),
        3 => Some(RegimeResetReason::OperatorReset {
            reason: text(decoder, MAX_RESET_TEXT)?,
        }),
        _ => return Err(Error::InvalidEncoding),
    })
}

impl SequentialEProcess {
    pub(crate) const fn checkpoint_regime_epoch(&self) -> u32 {
        self.regime_epoch
    }

    pub(crate) fn validate_checkpoint(&self, sources: usize) -> Result<()> {
        if sources > MAX_UNIQUE_SOURCES {
            return Err(Error::Limit);
        }
        if !valid_text(&self.hypothesis_id)
            || self.config.validate().is_err()
            || self.accumulated_llr.lo() < self.config.floor_mban
            || self.accumulated_llr.hi() > self.config.ceiling_mban
            || self.accumulated_llr.lo() > self.accumulated_llr.hi()
            || self.supremum_lo_mban < self.accumulated_llr.lo().max(0)
            || self.supremum_lo_mban > self.config.ceiling_mban
            || u64::from(self.regime_epoch) > self.step_index
            || self.last_reset.is_some() != (self.regime_epoch > 0)
            || self.last_transcript.is_some() != (self.step_index > 0)
        {
            return Err(Error::InvalidState);
        }
        if let Some(head) = self.last_transcript {
            require_sha256(head)?;
        }
        if let Some(reset) = &self.last_reset {
            reset_bound(reset)?;
        }
        if (self.step_index == 0 || sources == 0)
            && (self.accumulated_llr != LlrInterval::unchecked(0, 0)
                || self.supremum_lo_mban != 0
                || !self.supporting_domain_components.is_empty())
        {
            return Err(Error::InvalidState);
        }
        if self.supporting_domain_components.is_empty() && self.accumulated_llr.lo() > 0 {
            return Err(Error::InvalidState);
        }
        if self.supporting_domain_components.len() > sources {
            return Err(Error::Limit);
        }
        let mut domains_left = sources * DOMAINS_PER_SOURCE;
        let mut all_domains = BTreeSet::new();
        let mut previous = None;
        for component in &self.supporting_domain_components {
            if component.is_empty()
                || previous.is_some_and(|previous| previous >= component)
                || !component.iter().any(|domain| {
                    domain
                        .strip_prefix(INTRINSIC_PREFIX)
                        .is_some_and(valid_text)
                })
            {
                return Err(Error::InvalidState);
            }
            domains_left = domains_left
                .checked_sub(component.len())
                .ok_or(Error::Limit)?;
            for domain in component {
                if !valid_domain(domain) || !all_domains.insert(domain.as_str()) {
                    return Err(Error::InvalidState);
                }
            }
            previous = Some(component);
        }
        Ok(())
    }

    pub(crate) fn encode_checkpoint(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.hypothesis_id);
        encoder.i128(i128::from(self.config.alert_threshold_mban));
        encoder.i128(i128::from(self.config.floor_mban));
        encoder.i128(i128::from(self.config.ceiling_mban));
        encoder.u32(self.config.min_independent_clusters);
        encoder.u64(self.step_index);
        encoder.u32(self.regime_epoch);
        self.accumulated_llr.encode(encoder);
        encoder.i128(i128::from(self.supremum_lo_mban));
        encode_reset(encoder, self.last_reset.as_ref());
        encode_optional_digest(encoder, self.last_transcript);
        encoder.u32(self.supporting_domain_components.len() as u32);
        for component in &self.supporting_domain_components {
            encoder.u32(component.len() as u32);
            for domain in component {
                encoder.text(domain);
            }
        }
    }

    pub(crate) fn decode_checkpoint(
        decoder: &mut CanonicalDecoder<'_>,
        sources: usize,
    ) -> Result<Self> {
        let hypothesis_id = text(decoder, MAX_TEXT)?;
        let config = EProcessConfig {
            alert_threshold_mban: integer(decoder)?,
            floor_mban: integer(decoder)?,
            ceiling_mban: integer(decoder)?,
            min_independent_clusters: decoder.u32()?,
        };
        let step_index = decoder.u64()?;
        let regime_epoch = decoder.u32()?;
        let accumulated_llr = LlrInterval::unchecked(integer(decoder)?, integer(decoder)?);
        let supremum_lo_mban = integer(decoder)?;
        let last_reset = decode_reset(decoder)?;
        let last_transcript = decode_optional_digest(decoder)?;
        let components = count(decoder, sources)?;
        let mut supporting_domain_components = Vec::new();
        let mut domains_left = sources * DOMAINS_PER_SOURCE;
        for _ in 0..components {
            let domains = count(decoder, domains_left)?;
            if domains == 0 || domains > decoder.remaining() / 9 {
                return Err(Error::InvalidEncoding);
            }
            domains_left -= domains;
            let mut component = BTreeSet::<String>::new();
            for _ in 0..domains {
                let domain = text(decoder, MAX_TEXT + INTRINSIC_PREFIX.len())?;
                if !valid_domain(&domain) || component.last().is_some_and(|last| last >= &domain) {
                    return Err(Error::InvalidEncoding);
                }
                component.insert(domain);
            }
            if supporting_domain_components
                .last()
                .is_some_and(|previous| previous >= &component)
            {
                return Err(Error::InvalidEncoding);
            }
            supporting_domain_components.push(component);
        }
        let state = Self {
            hypothesis_id,
            config,
            step_index,
            regime_epoch,
            accumulated_llr,
            supremum_lo_mban,
            supporting_domain_components,
            last_reset,
            last_transcript,
        };
        state.validate_checkpoint(sources)?;
        Ok(state)
    }
}
