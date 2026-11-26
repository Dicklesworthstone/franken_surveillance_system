#![forbid(unsafe_code)]
//! Bounded canonical control bookkeeping; no grant or dispatch permit is decoded.

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    DigestAlgorithm, OperationId, PrincipalId,
};
use fss_ipc::BoundedControlOp;
use fss_runtime::effect_journal::EffectPersistenceError;

use super::{
    CONTROL_JOURNAL_DOMAIN, ControlHistoryEntry, ControlProgress, MAX_CONTROL_RECORD_BYTES,
    PendingControlCommand, Scope, invalid,
};

pub(super) enum Record {
    Accepted(ControlHistoryEntry),
    Progress {
        operation_id: OperationId,
        progress: ControlProgress,
    },
}

fn text_valid(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn digest_valid(value: ContentDigest) -> bool {
    value.algorithm() == DigestAlgorithm::Sha256
        && !value.is_laboratory()
        && value.bytes() != [0; 32]
}

pub(super) fn header(scope: &Scope) -> Result<Vec<u8>, EffectPersistenceError> {
    if !text_valid(&scope.deployment_id)
        || !digest_valid(scope.root_digest)
        || !digest_valid(scope.basis_digest)
    {
        return Err(invalid("invalid control journal scope"));
    }
    let mut enc = CanonicalEncoder::new();
    enc.text(CONTROL_JOURNAL_DOMAIN);
    enc.tag(0);
    enc.text(&scope.deployment_id);
    enc.digest(scope.root_digest);
    enc.digest(scope.basis_digest);
    enc.finish_checked()
        .map_err(|_| invalid("control scope encoding"))
}

pub(super) fn scope_digest(scope: &Scope) -> Result<ContentDigest, EffectPersistenceError> {
    Ok(ContentDigest::sha256(&header(scope)?))
}

pub(super) fn operation_id(
    scope: &Scope,
    op: BoundedControlOp,
    sequence: u64,
) -> Result<OperationId, EffectPersistenceError> {
    if sequence < 2 {
        return Err(invalid(
            "control acceptance requires a bootstrap predecessor",
        ));
    }
    OperationId::parse(format!(
        "op:ctrl:{}:{}:{sequence}",
        op.as_str(),
        scope_digest(scope)?.to_text()
    ))
    .map_err(|_| invalid("control operation identity"))
}

fn validate_entry(
    scope: &Scope,
    entry: &ControlHistoryEntry,
) -> Result<(), EffectPersistenceError> {
    if entry.contract_basis_digest != scope.basis_digest
        || entry.command.operation_id
            != operation_id(scope, entry.command.op, entry.accepted_sequence)?
        || !text_valid(entry.principal.as_str())
        || !digest_valid(entry.command.approval_digest)
        || entry
            .command
            .target_camera_id
            .as_deref()
            .is_some_and(|target| !text_valid(target))
        || entry.command.op.requires_camera_id() && entry.command.target_camera_id.is_none()
        || matches!(
            entry.command.op,
            BoundedControlOp::ReloadManifest | BoundedControlOp::TriggerScrub
        ) && entry.command.target_camera_id.is_some()
        || entry.granted_capabilities.len() > 64
        || entry
            .granted_capabilities
            .iter()
            .any(|value| !text_valid(value))
        || entry
            .granted_capabilities
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || entry.progress != ControlProgress::NeverStarted
    {
        return Err(invalid("invalid retained control admission"));
    }
    Ok(())
}

pub(super) fn encode(scope: &Scope, record: &Record) -> Result<Vec<u8>, EffectPersistenceError> {
    let mut enc = CanonicalEncoder::new();
    enc.text(CONTROL_JOURNAL_DOMAIN);
    enc.digest(scope_digest(scope)?);
    match record {
        Record::Accepted(entry) => {
            validate_entry(scope, entry)?;
            enc.tag(1);
            enc.u64(entry.accepted_sequence);
            enc.text(entry.command.operation_id.as_str());
            entry.command.op.encode_canonical(&mut enc);
            enc.bool(entry.command.target_camera_id.is_some());
            if let Some(target) = &entry.command.target_camera_id {
                enc.text(target);
            }
            enc.digest(entry.command.approval_digest);
            enc.text(entry.principal.as_str());
            enc.digest(entry.contract_basis_digest);
            enc.u32(entry.granted_capabilities.len() as u32);
            for capability in &entry.granted_capabilities {
                enc.text(capability);
            }
            enc.u64(entry.connection_id);
            enc.u64(entry.request_id);
        }
        Record::Progress {
            operation_id,
            progress,
        } => {
            enc.tag(match progress {
                ControlProgress::DispatchStarted => 2,
                ControlProgress::SubsystemReturned => 3,
                ControlProgress::CancelledBeforeExecution => 4,
                ControlProgress::NeverStarted => {
                    return Err(invalid("control cannot return to intake"));
                }
            });
            if !text_valid(operation_id.as_str()) {
                return Err(invalid("control transition identity"));
            }
            enc.text(operation_id.as_str());
        }
    }
    let bytes = enc
        .finish_checked()
        .map_err(|_| invalid("control record encoding"))?;
    if bytes.len() > MAX_CONTROL_RECORD_BYTES {
        return Err(EffectPersistenceError::Capacity);
    }
    Ok(bytes)
}

pub(super) fn decode(scope: &Scope, bytes: &[u8]) -> Result<Record, EffectPersistenceError> {
    if bytes.len() > MAX_CONTROL_RECORD_BYTES {
        return Err(EffectPersistenceError::Capacity);
    }
    let malformed = |_| invalid("control record decoding");
    let mut dec = CanonicalDecoder::new(bytes);
    if dec.text().map_err(malformed)? != CONTROL_JOURNAL_DOMAIN
        || dec.digest().map_err(malformed)? != scope_digest(scope)?
    {
        return Err(invalid("control record domain or scope mismatch"));
    }
    let tag = dec.tag().map_err(malformed)?;
    let record = match tag {
        1 => {
            let accepted_sequence = dec.u64().map_err(malformed)?;
            let operation_id =
                OperationId::parse(dec.text().map_err(malformed)?).map_err(malformed)?;
            let op = BoundedControlOp::decode_canonical(&mut dec).map_err(malformed)?;
            let target_camera_id = if dec.bool().map_err(malformed)? {
                Some(dec.text().map_err(malformed)?.to_owned())
            } else {
                None
            };
            let approval_digest = dec.digest().map_err(malformed)?;
            let principal =
                PrincipalId::parse(dec.text().map_err(malformed)?).map_err(malformed)?;
            let contract_basis_digest = dec.digest().map_err(malformed)?;
            let count = dec.u32().map_err(malformed)? as usize;
            if count > 64 {
                return Err(EffectPersistenceError::Capacity);
            }
            let mut granted_capabilities = Vec::with_capacity(count);
            for _ in 0..count {
                granted_capabilities.push(dec.text().map_err(malformed)?.to_owned());
            }
            Record::Accepted(ControlHistoryEntry {
                command: PendingControlCommand {
                    operation_id,
                    op,
                    target_camera_id,
                    approval_digest,
                },
                principal,
                contract_basis_digest,
                granted_capabilities,
                accepted_sequence,
                connection_id: dec.u64().map_err(malformed)?,
                request_id: dec.u64().map_err(malformed)?,
                progress: ControlProgress::NeverStarted,
                recovered: true,
            })
        }
        2..=4 => Record::Progress {
            operation_id: OperationId::parse(dec.text().map_err(malformed)?).map_err(malformed)?,
            progress: match tag {
                2 => ControlProgress::DispatchStarted,
                3 => ControlProgress::SubsystemReturned,
                _ => ControlProgress::CancelledBeforeExecution,
            },
        },
        _ => return Err(invalid("unsupported control record version or transition")),
    };
    dec.ensure_finished().map_err(malformed)?;
    if encode(scope, &record)? != bytes {
        return Err(invalid("noncanonical control record"));
    }
    Ok(record)
}
