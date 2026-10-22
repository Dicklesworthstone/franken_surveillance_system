#![forbid(unsafe_code)]
//! Handwritten canonical transition encoding, with exact native identities and no JSON parser.

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest};
use fss_object::ObjectManifest;

use super::plan::text;
use super::{
    CampaignCatalogBinding, CampaignFinish, CampaignHistoryError as Error, CampaignHistoryLimits,
    CampaignPin, CampaignRetryReason, CampaignSourcePin, CampaignTerminal, MAX_CAMPAIGN_CATALOGS,
    MAX_CAMPAIGN_RECORDS, NativeAttemptObservation, NativeBindings, Result, sha,
};
use crate::rtsp::archive_pins::ArchivePinAnchor;

pub(super) const KIND: &str = "rtsp_campaign_transition_v1";
pub(super) const MAX_RECORD_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Transition {
    Start(u32),
    Finish(u32, CampaignFinish),
    Terminal(CampaignTerminal),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CampaignRecord {
    pub approval: ContentDigest,
    pub plan: ContentDigest,
    pub limits: CampaignHistoryLimits,
    pub sequence: u32,
    pub prior: Option<CampaignPin>,
    pub transition: Transition,
}

impl CampaignRecord {
    pub fn pin(&self, root: ContentDigest) -> CampaignPin {
        CampaignPin {
            approval: self.approval,
            plan: self.plan,
            root,
            records: self.sequence,
        }
    }
    fn validate(&self) -> Result<()> {
        self.limits.validate()?;
        if !sha(self.approval)
            || !sha(self.plan)
            || !(1..=MAX_CAMPAIGN_RECORDS).contains(&self.sequence)
            || self.sequence > self.limits.maximum_records
        {
            return Err(Error::Metadata);
        }
        match self.prior {
            None if self.sequence == 1 => {}
            Some(pin)
                if pin.approval == self.approval
                    && pin.plan == self.plan
                    && pin.records + 1 == self.sequence =>
            {
                pin.validate()?
            }
            _ => return Err(Error::Mismatch),
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut e = CanonicalEncoder::new();
        e.bytes(b"FSSRTCH1");
        e.u32(1);
        e.text("fss.rtsp_campaign_transition.v1");
        e.digest(self.approval);
        e.digest(self.plan);
        self.limits.encode(&mut e);
        e.u32(self.sequence);
        e.bool(self.prior.is_some());
        if let Some(pin) = self.prior {
            encode_pin(&mut e, pin);
        }
        match &self.transition {
            Transition::Start(ordinal) => {
                e.u8(1);
                e.u32(*ordinal);
            }
            Transition::Finish(ordinal, finish) => {
                e.u8(2);
                e.u32(*ordinal);
                e.bool(finish.native.is_some());
                if let Some(native) = &finish.native {
                    encode_native(&mut e, native)?;
                }
                option_text(&mut e, finish.controller_error.as_deref());
                e.bool(finish.settled_success);
                e.bool(finish.next_attempt_planned);
            }
            Transition::Terminal(terminal) => {
                e.u8(3);
                e.bool(terminal.complete);
                option_text(&mut e, terminal.error_id.as_deref());
            }
        }
        let bytes = e.finish_checked()?;
        if bytes.len() > MAX_RECORD_BYTES || bytes.len() > self.limits.maximum_spool_object_bytes {
            return Err(Error::Limit);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(Error::Limit);
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.bytes()? != b"FSSRTCH1"
            || d.u32()? != 1
            || d.text()? != "fss.rtsp_campaign_transition.v1"
        {
            return Err(Error::Metadata);
        }
        let approval = d.digest()?;
        let plan = d.digest()?;
        let limits = CampaignHistoryLimits::decode(&mut d)?;
        let sequence = d.u32()?;
        let prior = if d.bool()? {
            Some(decode_pin(&mut d)?)
        } else {
            None
        };
        let transition = match d.u8()? {
            1 => Transition::Start(d.u32()?),
            2 => Transition::Finish(
                d.u32()?,
                CampaignFinish {
                    native: if d.bool()? {
                        Some(decode_native(&mut d)?)
                    } else {
                        None
                    },
                    controller_error: decode_option_text(&mut d)?,
                    settled_success: d.bool()?,
                    next_attempt_planned: d.bool()?,
                },
            ),
            3 => Transition::Terminal(CampaignTerminal {
                complete: d.bool()?,
                error_id: decode_option_text(&mut d)?,
            }),
            _ => return Err(Error::Metadata),
        };
        d.ensure_finished()?;
        let record = Self {
            approval,
            plan,
            limits,
            sequence,
            prior,
            transition,
        };
        if record.encode()? != bytes {
            return Err(Error::Metadata);
        }
        Ok(record)
    }
    pub fn manifest(&self) -> Result<ObjectManifest> {
        let metadata = ContentDigest::sha256(&self.encode()?);
        ObjectManifest::new(
            KIND,
            std::iter::once(self.plan).chain(self.prior.iter().map(|pin| pin.root)),
            Some(metadata),
        )
        .map_err(|_| Error::Metadata)
    }
}

fn encode_pin(e: &mut CanonicalEncoder, pin: CampaignPin) {
    e.digest(pin.approval);
    e.digest(pin.plan);
    e.digest(pin.root);
    e.u32(pin.records);
}
fn decode_pin(d: &mut CanonicalDecoder<'_>) -> Result<CampaignPin> {
    let pin = CampaignPin {
        approval: d.digest()?,
        plan: d.digest()?,
        root: d.digest()?,
        records: d.u32()?,
    };
    pin.validate()?;
    Ok(pin)
}
fn option_text(e: &mut CanonicalEncoder, text: Option<&str>) {
    e.bool(text.is_some());
    if let Some(text) = text {
        e.text(text);
    }
}
fn decode_option_text(d: &mut CanonicalDecoder<'_>) -> Result<Option<String>> {
    if d.bool()? {
        Ok(Some(text(d, 128)?))
    } else {
        Ok(None)
    }
}
fn optional_digest(e: &mut CanonicalEncoder, digest: Option<ContentDigest>) {
    e.bool(digest.is_some());
    if let Some(digest) = digest {
        e.digest(digest);
    }
}
fn decode_optional_digest(d: &mut CanonicalDecoder<'_>) -> Result<Option<ContentDigest>> {
    if d.bool()? {
        Ok(Some(d.digest()?))
    } else {
        Ok(None)
    }
}
fn encode_native(e: &mut CanonicalEncoder, native: &NativeAttemptObservation) -> Result<()> {
    e.bool(native.complete);
    option_text(e, native.error_id.as_deref());
    e.u8(match native.retry {
        None => 0,
        Some(CampaignRetryReason::ConnectionUnavailable) => 1,
        Some(CampaignRetryReason::SourceEnded) => 2,
        Some(CampaignRetryReason::ProgressStalled) => 3,
        Some(CampaignRetryReason::ReadInterrupted) => 4,
        Some(CampaignRetryReason::SettledSuccess) => 5,
    });
    e.u64(native.durable_pictures);
    e.bool(native.recovery_required);
    let bindings = &native.bindings;
    optional_digest(e, bindings.snapshot_digest);
    e.bool(bindings.journal_anchor.is_some());
    if let Some(anchor) = bindings.journal_anchor {
        e.u64(anchor.sequence);
        e.digest(anchor.root);
    }
    if bindings.catalogs.len() > MAX_CAMPAIGN_CATALOGS {
        return Err(Error::Limit);
    }
    e.u32(bindings.catalogs.len() as u32);
    for catalog in &bindings.catalogs {
        e.text(&catalog.slot);
        e.digest(catalog.root);
    }
    e.bool(bindings.source_pin.is_some());
    if let Some(pin) = bindings.source_pin {
        e.digest(pin.scope);
        e.digest(pin.head);
        e.u64(pin.datagrams);
        e.u64(pin.bytes);
    }
    Ok(())
}
fn decode_native(d: &mut CanonicalDecoder<'_>) -> Result<NativeAttemptObservation> {
    let complete = d.bool()?;
    let error_id = decode_option_text(d)?;
    let retry = match d.u8()? {
        0 => None,
        1 => Some(CampaignRetryReason::ConnectionUnavailable),
        2 => Some(CampaignRetryReason::SourceEnded),
        3 => Some(CampaignRetryReason::ProgressStalled),
        4 => Some(CampaignRetryReason::ReadInterrupted),
        5 => Some(CampaignRetryReason::SettledSuccess),
        _ => return Err(Error::Metadata),
    };
    let durable_pictures = d.u64()?;
    let recovery_required = d.bool()?;
    let snapshot_digest = decode_optional_digest(d)?;
    let journal_anchor = if d.bool()? {
        Some(ArchivePinAnchor {
            sequence: d.u64()?,
            root: d.digest()?,
        })
    } else {
        None
    };
    let count = d.u32()? as usize;
    if count > MAX_CAMPAIGN_CATALOGS {
        return Err(Error::Limit);
    }
    let mut catalogs = Vec::with_capacity(count);
    for _ in 0..count {
        catalogs.push(CampaignCatalogBinding {
            slot: text(d, 256)?,
            root: d.digest()?,
        });
    }
    let source_pin = if d.bool()? {
        Some(CampaignSourcePin {
            scope: d.digest()?,
            head: d.digest()?,
            datagrams: d.u64()?,
            bytes: d.u64()?,
        })
    } else {
        None
    };
    Ok(NativeAttemptObservation {
        complete,
        error_id,
        retry,
        durable_pictures,
        recovery_required,
        bindings: NativeBindings {
            snapshot_digest,
            journal_anchor,
            catalogs,
            source_pin,
        },
    })
}
