#![forbid(unsafe_code)]
//! Canonical binary encoders and decoders for [`super::sessions`] records and events.

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContractError,
    TimestampNs,
};

use super::sessions::{
    CaseLifecycle, IndexedCase, IndexedSession, SessionJournalEvent, SessionLifecycle,
};

impl CanonicalEncode for IndexedSession {
    fn encode_canonical(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.session_id);
        enc.text(&self.mission_id);
        enc.text(&self.principal_id);
        enc.tag(self.lifecycle.to_tag());
        self.lease_expires_at_ns.encode_canonical(enc);
        enc.u64(self.workspace_revision);
        self.opened_at_ns.encode_canonical(enc);
        self.updated_at_ns.encode_canonical(enc);
        enc.u64(self.last_seq);
    }
}

impl CanonicalDecode for IndexedSession {
    fn decode_canonical(dec: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            session_id: dec.text()?.to_owned(),
            mission_id: dec.text()?.to_owned(),
            principal_id: dec.text()?.to_owned(),
            lifecycle: SessionLifecycle::from_tag(dec.tag()?)
                .ok_or(ContractError::InvalidIdentifier)?,
            lease_expires_at_ns: TimestampNs::decode_canonical(dec)?,
            workspace_revision: dec.u64()?,
            opened_at_ns: TimestampNs::decode_canonical(dec)?,
            updated_at_ns: TimestampNs::decode_canonical(dec)?,
            last_seq: dec.u64()?,
        })
    }
}

impl CanonicalEncode for IndexedCase {
    fn encode_canonical(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.case_id);
        enc.text(&self.session_id);
        enc.text(&self.mission_id);
        enc.tag(self.lifecycle.to_tag());
        enc.u32(self.hypothesis_count);
        self.updated_at_ns.encode_canonical(enc);
        enc.u64(self.last_seq);
    }
}

impl CanonicalDecode for IndexedCase {
    fn decode_canonical(dec: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            case_id: dec.text()?.to_owned(),
            session_id: dec.text()?.to_owned(),
            mission_id: dec.text()?.to_owned(),
            lifecycle: CaseLifecycle::from_tag(dec.tag()?)
                .ok_or(ContractError::InvalidIdentifier)?,
            hypothesis_count: dec.u32()?,
            updated_at_ns: TimestampNs::decode_canonical(dec)?,
            last_seq: dec.u64()?,
        })
    }
}

impl CanonicalEncode for SessionJournalEvent {
    fn encode_canonical(&self, enc: &mut CanonicalEncoder) {
        match self {
            Self::OpenSession(s) => {
                enc.tag(1);
                s.encode_canonical(enc);
            }
            Self::RenewLease {
                session_id,
                lease_expires_at_ns,
                workspace_revision,
                updated_at_ns,
            } => {
                enc.tag(2);
                enc.text(session_id);
                lease_expires_at_ns.encode_canonical(enc);
                enc.u64(*workspace_revision);
                updated_at_ns.encode_canonical(enc);
            }
            Self::TransitionSession {
                session_id,
                lifecycle,
                updated_at_ns,
            } => {
                enc.tag(3);
                enc.text(session_id);
                enc.tag(lifecycle.to_tag());
                updated_at_ns.encode_canonical(enc);
            }
            Self::UpsertCase(c) => {
                enc.tag(4);
                c.encode_canonical(enc);
            }
            Self::CloseCase {
                case_id,
                lifecycle,
                updated_at_ns,
            } => {
                enc.tag(5);
                enc.text(case_id);
                enc.tag(lifecycle.to_tag());
                updated_at_ns.encode_canonical(enc);
            }
        }
    }
}

impl CanonicalDecode for SessionJournalEvent {
    fn decode_canonical(dec: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match dec.tag()? {
            1 => Ok(Self::OpenSession(IndexedSession::decode_canonical(dec)?)),
            2 => Ok(Self::RenewLease {
                session_id: dec.text()?.to_owned(),
                lease_expires_at_ns: TimestampNs::decode_canonical(dec)?,
                workspace_revision: dec.u64()?,
                updated_at_ns: TimestampNs::decode_canonical(dec)?,
            }),
            3 => Ok(Self::TransitionSession {
                session_id: dec.text()?.to_owned(),
                lifecycle: SessionLifecycle::from_tag(dec.tag()?)
                    .ok_or(ContractError::InvalidIdentifier)?,
                updated_at_ns: TimestampNs::decode_canonical(dec)?,
            }),
            4 => Ok(Self::UpsertCase(IndexedCase::decode_canonical(dec)?)),
            5 => Ok(Self::CloseCase {
                case_id: dec.text()?.to_owned(),
                lifecycle: CaseLifecycle::from_tag(dec.tag()?)
                    .ok_or(ContractError::InvalidIdentifier)?,
                updated_at_ns: TimestampNs::decode_canonical(dec)?,
            }),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}
