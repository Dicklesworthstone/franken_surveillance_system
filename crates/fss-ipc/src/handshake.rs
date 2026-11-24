#![forbid(unsafe_code)]
//! Mutually pinned canonical IPC handshake messages (zero Serde).

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, ErrorId, PrincipalId,
};

use crate::error::IpcError;
use crate::security::{MAX_HANDSHAKE_CAPABILITIES, validate_capabilities, validate_wire_text};

/// Canonical digest domain for [`HandshakeRequest`].
pub const IPC_HANDSHAKE_DIGEST_DOMAIN: &str = "fss.ipc.handshake.v1";

/// Maximum length of a deployment or daemon instance identifier on the wire.
pub const MAX_DEPLOYMENT_ID_BYTES: usize = 256;

/// Maximum length of a refusal or diagnostic string on the wire.
pub const MAX_REASON_BYTES: usize = 4096;

/// Client-initiated handshake pinning protocol, deployment, contract basis, principal, and capabilities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandshakeRequest {
    /// Wire and semantic IPC protocol version.
    pub protocol_version: u16,
    /// Stable deployment identifier expected by the client.
    pub deployment_id: String,
    /// Canonical digest of the deployment root directory.
    pub deployment_root_digest: ContentDigest,
    /// Canonical `ContractBasis::basis_digest()` pinned by the client.
    pub contract_basis_digest: ContentDigest,
    /// Authenticated local principal identifier.
    pub principal: PrincipalId,
    /// Requested opaque capability identifiers (zero raw secrets).
    pub capabilities: Vec<String>,
}

impl HandshakeRequest {
    /// Validates structural bounds and opaque capability constraints.
    pub fn validate(&self) -> Result<(), IpcError> {
        if self.deployment_id.is_empty() {
            return Err(IpcError::HandshakeMismatch {
                reason: "deployment_id must be non-empty".to_owned(),
            });
        }
        validate_wire_text(
            "deployment_id",
            &self.deployment_id,
            MAX_DEPLOYMENT_ID_BYTES,
        )?;
        validate_capabilities(&self.capabilities)?;
        Ok(())
    }

    /// Computes the canonical domain-separated digest of this handshake request.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        self.canonical_digest(IPC_HANDSHAKE_DIGEST_DOMAIN)
    }
}

impl CanonicalEncode for HandshakeRequest {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(u32::from(self.protocol_version));
        encoder.text(&self.deployment_id);
        encoder.digest(self.deployment_root_digest);
        encoder.digest(self.contract_basis_digest);
        self.principal.encode_canonical(encoder);
        encoder.u32(self.capabilities.len() as u32);
        for cap in &self.capabilities {
            encoder.text(cap);
        }
    }
}

impl CanonicalDecode for HandshakeRequest {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let protocol_version =
            u16::try_from(decoder.u32()?).map_err(|_| ContractError::InvalidIdentifier)?;
        let deployment_id = decoder.text()?.to_owned();
        if deployment_id.is_empty() || deployment_id.len() > MAX_DEPLOYMENT_ID_BYTES {
            return Err(ContractError::InvalidIdentifier);
        }
        let deployment_root_digest = decoder.digest()?;
        let contract_basis_digest = decoder.digest()?;
        let principal = PrincipalId::decode_canonical(decoder)?;
        let cap_count = decoder.u32()? as usize;
        if cap_count > MAX_HANDSHAKE_CAPABILITIES {
            return Err(ContractError::InvalidIdentifier);
        }
        let mut capabilities = Vec::with_capacity(cap_count);
        for _ in 0..cap_count {
            capabilities.push(decoder.text()?.to_owned());
        }
        Ok(Self {
            protocol_version,
            deployment_id,
            deployment_root_digest,
            contract_basis_digest,
            principal,
            capabilities,
        })
    }
}

/// Daemon acceptance payload returned when handshake pins match.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandshakeAccepted {
    /// Confirmed protocol version.
    pub protocol_version: u16,
    /// Confirmed deployment identifier.
    pub deployment_id: String,
    /// Confirmed canonical deployment root digest.
    pub deployment_root_digest: ContentDigest,
    /// Confirmed canonical `ContractBasis` digest.
    pub contract_basis_digest: ContentDigest,
    /// Stable identifier of the serving daemon instance.
    pub daemon_instance_id: String,
    /// Opaque capability identifiers granted for this session.
    pub granted_capabilities: Vec<String>,
    /// Current authoritative ledger head commit sequence.
    pub head_commit_sequence: u64,
}

impl CanonicalEncode for HandshakeAccepted {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(u32::from(self.protocol_version));
        encoder.text(&self.deployment_id);
        encoder.digest(self.deployment_root_digest);
        encoder.digest(self.contract_basis_digest);
        encoder.text(&self.daemon_instance_id);
        encoder.u32(self.granted_capabilities.len() as u32);
        for cap in &self.granted_capabilities {
            encoder.text(cap);
        }
        encoder.u64(self.head_commit_sequence);
    }
}

impl CanonicalDecode for HandshakeAccepted {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let protocol_version =
            u16::try_from(decoder.u32()?).map_err(|_| ContractError::InvalidIdentifier)?;
        let deployment_id = decoder.text()?.to_owned();
        if deployment_id.is_empty() || deployment_id.len() > MAX_DEPLOYMENT_ID_BYTES {
            return Err(ContractError::InvalidIdentifier);
        }
        let deployment_root_digest = decoder.digest()?;
        let contract_basis_digest = decoder.digest()?;
        let daemon_instance_id = decoder.text()?.to_owned();
        if daemon_instance_id.is_empty() || daemon_instance_id.len() > MAX_DEPLOYMENT_ID_BYTES {
            return Err(ContractError::InvalidIdentifier);
        }
        let cap_count = decoder.u32()? as usize;
        if cap_count > MAX_HANDSHAKE_CAPABILITIES {
            return Err(ContractError::InvalidIdentifier);
        }
        let mut granted_capabilities = Vec::with_capacity(cap_count);
        for _ in 0..cap_count {
            granted_capabilities.push(decoder.text()?.to_owned());
        }
        let head_commit_sequence = decoder.u64()?;
        Ok(Self {
            protocol_version,
            deployment_id,
            deployment_root_digest,
            contract_basis_digest,
            daemon_instance_id,
            granted_capabilities,
            head_commit_sequence,
        })
    }
}

/// Daemon rejection payload returned when handshake pinning or authorization fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandshakeRejected {
    /// Stable machine-readable error identifier.
    pub error_id: ErrorId,
    /// Non-secret explanation of the handshake refusal.
    pub reason: String,
    /// Protocol version expected by the daemon.
    pub expected_protocol_version: u16,
}

impl CanonicalEncode for HandshakeRejected {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.error_id.encode_canonical(encoder);
        encoder.text(&self.reason);
        encoder.u32(u32::from(self.expected_protocol_version));
    }
}

impl CanonicalDecode for HandshakeRejected {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let error_id = ErrorId::decode_canonical(decoder)?;
        let reason = decoder.text()?.to_owned();
        if reason.len() > MAX_REASON_BYTES {
            return Err(ContractError::InvalidIdentifier);
        }
        let expected_protocol_version =
            u16::try_from(decoder.u32()?).map_err(|_| ContractError::InvalidIdentifier)?;
        Ok(Self {
            error_id,
            reason,
            expected_protocol_version,
        })
    }
}

/// Handshake reply returned by the local daemon.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandshakeResponse {
    /// Session admitted with mutually pinned basis and granted capabilities.
    Accepted(HandshakeAccepted),
    /// Session refused; the connection closes immediately after sending this frame.
    Rejected(HandshakeRejected),
}

impl CanonicalEncode for HandshakeResponse {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        match self {
            Self::Accepted(accepted) => {
                encoder.tag(1);
                accepted.encode_canonical(encoder);
            }
            Self::Rejected(rejected) => {
                encoder.tag(2);
                rejected.encode_canonical(encoder);
            }
        }
    }
}

impl CanonicalDecode for HandshakeResponse {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.tag()? {
            1 => Ok(Self::Accepted(HandshakeAccepted::decode_canonical(
                decoder,
            )?)),
            2 => Ok(Self::Rejected(HandshakeRejected::decode_canonical(
                decoder,
            )?)),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}
