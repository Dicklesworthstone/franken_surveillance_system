#![forbid(unsafe_code)]
//! Pure canonical plan records. Encoding retains intent and approval evidence, never effect authority.
//!
//! Reference-only routes keep the exact v1 bytes. A metadata-disclosing route uses v2 and binds
//! its profile and distinct metadata approval after the route deadline. Old v1 records always
//! mean reference-only disclosure; decoding never upgrades an old route or approval.

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, MissionId, PrincipalId, SessionId, TimestampNs,
};

use crate::webhook::WebhookDisclosureProfile;

pub(super) const MAX_PLAN_RECORD_BYTES: usize = 1024 * 1024;
const PLAN_RECORD_DOMAIN: &str = "fss.reference_agent_plan.v1";
const PLAN_RECORD_METADATA_DOMAIN: &str = "fss.reference_agent_plan.v2";
const PLAN_IDENTITY_DOMAIN: &str = "fss.reference_agent_plan_identity.v1";

/// The exact relay route an alert plan sends over.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlertRoute {
    /// Literal `IP:PORT` socket address (no DNS).
    pub relay: String,
    /// Absolute request path.
    pub path: String,
    /// Owner approval of the plaintext relay.
    pub plaintext_approval: ContentDigest,
    /// Explicit dispatch deadline in milliseconds.
    pub deadline_ms: u64,
    /// Exact versioned content the relay may receive.
    pub disclosure_profile: WebhookDisclosureProfile,
    /// Distinct approval of event-metadata disclosure, absent for reference-only routes.
    pub metadata_approval: Option<ContentDigest>,
}

impl AlertRoute {
    /// Refuses missing, inapplicable or invalid metadata-disclosure approvals.
    ///
    /// This validates a recorded choice only. The effect owner still verifies the live relay,
    /// event, policy, authority and approval before dispatch.
    pub fn validate_disclosure(&self) -> Result<(), ContractError> {
        self.disclosure_profile
            .validate(self.metadata_approval)
            .map_err(|_| ContractError::InvalidIdentifier)
    }
}

/// One published control plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanRecord {
    /// Stable plan identity (`plan:<32 hex>`).
    pub plan_id: String,
    /// Session the plan was compiled in.
    pub session_id: SessionId,
    /// The session's mission.
    pub mission_id: MissionId,
    /// The session's principal (an audit label; it approves nothing by itself).
    pub principal: PrincipalId,
    /// Anchor token of the session situation the plan was compiled against.
    pub anchor_token: String,
    /// Registered intent family (`alert`).
    pub intent: String,
    /// Event the alert is about.
    pub event_id: String,
    /// Exact event revision the plan was compiled against.
    pub event_revision: ContentDigest,
    /// Exact relay route.
    pub route: AlertRoute,
    /// Effect operation identity the plan prepares and commits.
    pub operation_id: String,
    /// Terminal-proof obligation identity.
    pub obligation_id: String,
    /// Exact operator approval digest that admits preparation.
    pub plan_approval: ContentDigest,
    /// Digest of the published `fss.agent_control_plan.v1` rendering.
    pub control_plan_digest: ContentDigest,
    /// Investigation case and exact revision the plan rests on, when one was named.
    pub case: Option<(String, ContentDigest)>,
    /// Compile time on the deployment evidence clock.
    pub created_at: TimestampNs,
}

impl PlanRecord {
    /// The plan identity of `session` at `anchor_token` for an exact plan approval.
    #[must_use]
    pub fn identity(
        session: &SessionId,
        anchor_token: &str,
        plan_approval: ContentDigest,
    ) -> String {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(PLAN_IDENTITY_DOMAIN);
        session.encode_canonical(&mut encoder);
        encoder.text(anchor_token);
        encoder.digest(plan_approval);
        let digest = ContentDigest::sha256(&encoder.finish());
        format!(
            "plan:{}",
            digest.bytes()[..16]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )
    }

    /// Canonical record bytes, retaining the exact v1 layout for reference-only routes.
    ///
    /// In v2, immediately after `deadline_ms`, a profile tag (`2` = event metadata) precedes
    /// an approval-presence Boolean and its canonical digest. Other fields retain their order.
    /// Invalid disclosure choices are represented without dropping fields and are refused by
    /// decoding and publication; serialization alone does not admit a route or grant authority.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoder = CanonicalEncoder::new();
        let legacy = self.route.disclosure_profile == WebhookDisclosureProfile::ReferencesV1
            && self.route.metadata_approval.is_none();
        encoder.text(if legacy {
            PLAN_RECORD_DOMAIN
        } else {
            PLAN_RECORD_METADATA_DOMAIN
        });
        encoder.text(&self.plan_id);
        self.session_id.encode_canonical(&mut encoder);
        self.mission_id.encode_canonical(&mut encoder);
        self.principal.encode_canonical(&mut encoder);
        encoder.text(&self.anchor_token);
        encoder.text(&self.intent);
        encoder.text(&self.event_id);
        encoder.digest(self.event_revision);
        encoder.text(&self.route.relay);
        encoder.text(&self.route.path);
        encoder.digest(self.route.plaintext_approval);
        encoder.u64(self.route.deadline_ms);
        if !legacy {
            encoder.tag(match self.route.disclosure_profile {
                WebhookDisclosureProfile::ReferencesV1 => 1,
                WebhookDisclosureProfile::EventMetadataV1 => 2,
            });
            encoder.bool(self.route.metadata_approval.is_some());
            if let Some(approval) = self.route.metadata_approval {
                encoder.digest(approval);
            }
        }
        encoder.text(&self.operation_id);
        encoder.text(&self.obligation_id);
        encoder.digest(self.plan_approval);
        encoder.digest(self.control_plan_digest);
        encoder.bool(self.case.is_some());
        if let Some((case_id, revision)) = &self.case {
            encoder.text(case_id);
            encoder.digest(*revision);
        }
        encoder.i128(self.created_at.0);
        encoder.finish()
    }

    /// Decodes exactly canonical record bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() > MAX_PLAN_RECORD_BYTES {
            return Err(ContractError::CountBoundExceeded);
        }
        let mut decoder = CanonicalDecoder::new(bytes);
        let with_disclosure = match decoder.text()? {
            PLAN_RECORD_DOMAIN => false,
            PLAN_RECORD_METADATA_DOMAIN => true,
            _ => return Err(ContractError::DigestMismatch),
        };
        let plan_id = decoder.text()?.to_owned();
        let session_id = SessionId::parse(decoder.text()?)?;
        let mission_id = MissionId::parse(decoder.text()?)?;
        let principal = PrincipalId::parse(decoder.text()?)?;
        let anchor_token = decoder.text()?.to_owned();
        let intent = decoder.text()?.to_owned();
        let event_id = decoder.text()?.to_owned();
        let event_revision = ContentDigest::decode_canonical(&mut decoder)?;
        let mut route = AlertRoute {
            relay: decoder.text()?.to_owned(),
            path: decoder.text()?.to_owned(),
            plaintext_approval: ContentDigest::decode_canonical(&mut decoder)?,
            deadline_ms: decoder.u64()?,
            disclosure_profile: WebhookDisclosureProfile::ReferencesV1,
            metadata_approval: None,
        };
        if with_disclosure {
            route.disclosure_profile = match decoder.tag()? {
                1 => WebhookDisclosureProfile::ReferencesV1,
                2 => WebhookDisclosureProfile::EventMetadataV1,
                tag => return Err(ContractError::UnknownEntryTag(tag)),
            };
            route.metadata_approval = if decoder.bool()? {
                Some(ContentDigest::decode_canonical(&mut decoder)?)
            } else {
                None
            };
            // There is exactly one encoding for a reference-only record: the retained v1.
            if route.disclosure_profile != WebhookDisclosureProfile::EventMetadataV1 {
                return Err(ContractError::InvalidIdentifier);
            }
        }
        route.validate_disclosure()?;
        let operation_id = decoder.text()?.to_owned();
        let obligation_id = decoder.text()?.to_owned();
        let plan_approval = ContentDigest::decode_canonical(&mut decoder)?;
        let control_plan_digest = ContentDigest::decode_canonical(&mut decoder)?;
        let case = if decoder.bool()? {
            Some((
                decoder.text()?.to_owned(),
                ContentDigest::decode_canonical(&mut decoder)?,
            ))
        } else {
            None
        };
        let record = Self {
            plan_id,
            session_id,
            mission_id,
            principal,
            anchor_token,
            intent,
            event_id,
            event_revision,
            route,
            operation_id,
            obligation_id,
            plan_approval,
            control_plan_digest,
            case,
            created_at: TimestampNs(decoder.i128()?),
        };
        decoder.ensure_finished()?;
        if record.to_bytes() != bytes {
            return Err(ContractError::DigestMismatch);
        }
        Ok(record)
    }
}

#[cfg(test)]
#[path = "record/tests.rs"]
mod tests;
