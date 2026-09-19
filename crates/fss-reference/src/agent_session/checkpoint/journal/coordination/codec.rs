#![forbid(unsafe_code)]
//! Private, versioned, bounded command records. No serde or decoded claim authority.

use std::collections::BTreeSet;

use fss_core::{CanonicalEncoder, CanonicalDecoder, CaseId, ContentDigest, PrincipalId, SessionId, TimestampNs};

use super::{
    CoordinationCommand, DurableSessionError, MAX_COORDINATION_RECORD_BYTES, WorkClaimError,
    WorkClaimLimits, WorkClaimRecovery, WorkClaimRequest, WorkClaimRevision, WorkClaimUpdate,
};

const INIT_FORMAT: &str = "fss.reference_coordination_init.v1";
const REQUEST_FORMAT: &str = "fss.reference_coordination_request.v1";
const RECORD_FORMAT: &str = "fss.reference_coordination_record.v1";
const MAX_DEPENDENCIES: usize = 4_096;
const HARD_LIMITS: WorkClaimLimits = WorkClaimLimits {
    max_claims: 16_384, max_revisions: 262_144,
    max_dependencies: MAX_DEPENDENCIES, max_lease_ns: u64::MAX,
};

#[derive(Debug)]
pub(super) struct Request {
    pub(super) principal: PrincipalId,
    pub(super) session: SessionId,
    pub(super) command: CoordinationCommand,
    pub(super) now: TimestampNs,
}

pub(super) struct Record {
    pub(super) request: Request,
    pub(super) before: ContentDigest,
    pub(super) after: ContentDigest,
    pub(super) outcome: ContentDigest,
}

fn bounded_text(value: &str, limit: usize) -> Result<(), DurableSessionError> {
    if value.len() > limit { return Err(DurableSessionError::CapacityExceeded); }
    Ok(())
}

fn read_text(decoder: &mut CanonicalDecoder<'_>, limit: usize) -> Result<String, DurableSessionError> {
    let value = decoder.text()?;
    bounded_text(value, limit)?;
    Ok(value.to_owned())
}

fn check_limits(value: WorkClaimLimits, ceiling: WorkClaimLimits) -> Result<(), DurableSessionError> {
    if value.max_claims > ceiling.max_claims.min(HARD_LIMITS.max_claims)
        || value.max_revisions > ceiling.max_revisions.min(HARD_LIMITS.max_revisions)
        || value.max_dependencies > ceiling.max_dependencies.min(HARD_LIMITS.max_dependencies)
        || value.max_lease_ns > ceiling.max_lease_ns
    { return Err(DurableSessionError::CapacityExceeded); }
    Ok(())
}

pub(super) fn encode_initialization(limits: WorkClaimLimits, session: ContentDigest) -> Result<Vec<u8>, DurableSessionError> {
    check_limits(limits, HARD_LIMITS)?;
    let mut encoder = CanonicalEncoder::new();
    encoder.text(INIT_FORMAT);
    for count in [limits.max_claims, limits.max_revisions, limits.max_dependencies] {
        encoder.u64(u64::try_from(count).map_err(|_| DurableSessionError::CapacityExceeded)?);
    }
    encoder.u64(limits.max_lease_ns);
    encoder.digest(session);
    Ok(encoder.finish_checked()?)
}

pub(super) fn decode_initialization(bytes: &[u8], session: ContentDigest, ceiling: WorkClaimLimits) -> Result<WorkClaimLimits, DurableSessionError> {
    if bytes.len() > MAX_COORDINATION_RECORD_BYTES { return Err(DurableSessionError::CapacityExceeded); }
    let mut decoder = CanonicalDecoder::new(bytes);
    if decoder.text()? != INIT_FORMAT { return Err(DurableSessionError::InvalidHistory); }
    let limits = WorkClaimLimits {
        max_claims: usize::try_from(decoder.u64()?).map_err(|_| DurableSessionError::CapacityExceeded)?,
        max_revisions: usize::try_from(decoder.u64()?).map_err(|_| DurableSessionError::CapacityExceeded)?,
        max_dependencies: usize::try_from(decoder.u64()?).map_err(|_| DurableSessionError::CapacityExceeded)?,
        max_lease_ns: decoder.u64()?,
    };
    check_limits(limits, ceiling)?;
    if decoder.digest()? != session { return Err(DurableSessionError::InvalidHistory); }
    decoder.ensure_finished()?;
    if encode_initialization(limits, session)? != bytes { return Err(DurableSessionError::InvalidHistory); }
    Ok(limits)
}

pub(super) fn encode_request(request: &Request) -> Result<Vec<u8>, DurableSessionError> {
    let command = &request.command;
    let claim_id = match command {
        CoordinationCommand::Acquire(input) => {
            bounded_text(&input.privacy_class, 256)?;
            if input.dependencies.len() > MAX_DEPENDENCIES { return Err(DurableSessionError::CapacityExceeded); }
            for dependency in &input.dependencies { bounded_text(dependency, 128)?; }
            &input.claim_id
        }
        CoordinationCommand::Inspect { claim_id }
        | CoordinationCommand::InspectRevision { claim_id, .. }
        | CoordinationCommand::Update { claim_id, .. }
        | CoordinationCommand::Recover { claim_id, .. } => claim_id,
    };
    bounded_text(claim_id, 128)?;
    let mut encoder = CanonicalEncoder::new();
    encoder.text(REQUEST_FORMAT);
    encoder.text(request.principal.as_str());
    encoder.text(request.session.as_str());
    encoder.i128(request.now.0);
    match command {
        CoordinationCommand::Acquire(input) => {
            encoder.tag(0);
            encoder.text(&input.claim_id);
            encoder.text(input.case_id.as_str());
            encoder.digest(input.work_root);
            encoder.text(&input.privacy_class);
            encoder.i128(input.expires_at.0);
            encoder.u32(u32::try_from(input.dependencies.len()).map_err(|_| DurableSessionError::CapacityExceeded)?);
            for dependency in &input.dependencies { encoder.text(dependency); }
        }
        CoordinationCommand::Inspect { claim_id } => { encoder.tag(1); encoder.text(claim_id); }
        CoordinationCommand::InspectRevision { claim_id, revision } => {
            encoder.tag(2); encoder.text(claim_id); encoder.digest(*revision);
        }
        CoordinationCommand::Update { claim_id, expected, change } => {
            encoder.tag(3); encoder.text(claim_id); encoder.digest(*expected);
            match change {
                WorkClaimUpdate::Activate => encoder.tag(0),
                WorkClaimUpdate::Block(root) => { encoder.tag(1); encoder.digest(*root); }
                WorkClaimUpdate::Progress(root) => { encoder.tag(2); encoder.digest(*root); }
                WorkClaimUpdate::Complete(root) => { encoder.tag(3); encoder.digest(*root); }
                WorkClaimUpdate::Release => encoder.tag(4),
                WorkClaimUpdate::Renew(expires) => { encoder.tag(5); encoder.i128(expires.0); }
            }
        }
        CoordinationCommand::Recover { claim_id, expected, recovery } => {
            encoder.tag(4); encoder.text(claim_id); encoder.digest(*expected);
            match recovery {
                WorkClaimRecovery::Expire => encoder.tag(0),
                WorkClaimRecovery::Transfer { recipient } => { encoder.tag(1); encoder.text(recipient.as_str()); }
                WorkClaimRecovery::Reclaim { expires_at } => { encoder.tag(2); encoder.i128(expires_at.0); }
            }
        }
    }
    let bytes = encoder.finish_checked()?;
    if bytes.len() > MAX_COORDINATION_RECORD_BYTES - 256 { return Err(DurableSessionError::CapacityExceeded); }
    Ok(bytes)
}

fn decode_request(bytes: &[u8]) -> Result<Request, DurableSessionError> {
    if bytes.len() > MAX_COORDINATION_RECORD_BYTES - 256 { return Err(DurableSessionError::CapacityExceeded); }
    let mut decoder = CanonicalDecoder::new(bytes);
    if decoder.text()? != REQUEST_FORMAT { return Err(DurableSessionError::InvalidHistory); }
    let principal = PrincipalId::parse(read_text(&mut decoder, 128)?)?;
    let session = SessionId::parse(read_text(&mut decoder, 128)?)?;
    let now = TimestampNs(decoder.i128()?);
    let tag = decoder.tag()?;
    let claim_id = read_text(&mut decoder, 128)?;
    let command = match tag {
        0 => {
            let case_id = CaseId::parse(read_text(&mut decoder, 128)?)?;
            let work_root = decoder.digest()?;
            let privacy_class = read_text(&mut decoder, 256)?;
            let expires_at = TimestampNs(decoder.i128()?);
            let count = usize::try_from(decoder.u32()?).map_err(|_| DurableSessionError::CapacityExceeded)?;
            if count > MAX_DEPENDENCIES { return Err(DurableSessionError::CapacityExceeded); }
            let mut dependencies = BTreeSet::<String>::new();
            for _ in 0..count {
                let value = read_text(&mut decoder, 128)?;
                if dependencies.last().is_some_and(|prior| prior >= &value) { return Err(DurableSessionError::InvalidHistory); }
                dependencies.insert(value);
            }
            CoordinationCommand::Acquire(WorkClaimRequest { claim_id, case_id, work_root, privacy_class, expires_at, dependencies })
        }
        1 => CoordinationCommand::Inspect { claim_id },
        2 => CoordinationCommand::InspectRevision { claim_id, revision: decoder.digest()? },
        3 => {
            let expected = decoder.digest()?;
            let change = match decoder.tag()? {
                0 => WorkClaimUpdate::Activate,
                1 => WorkClaimUpdate::Block(decoder.digest()?),
                2 => WorkClaimUpdate::Progress(decoder.digest()?),
                3 => WorkClaimUpdate::Complete(decoder.digest()?),
                4 => WorkClaimUpdate::Release,
                5 => WorkClaimUpdate::Renew(TimestampNs(decoder.i128()?)),
                _ => return Err(DurableSessionError::InvalidHistory),
            };
            CoordinationCommand::Update { claim_id, expected, change }
        }
        4 => {
            let expected = decoder.digest()?;
            let recovery = match decoder.tag()? {
                0 => WorkClaimRecovery::Expire,
                1 => WorkClaimRecovery::Transfer { recipient: SessionId::parse(read_text(&mut decoder, 128)?)? },
                2 => WorkClaimRecovery::Reclaim { expires_at: TimestampNs(decoder.i128()?) },
                _ => return Err(DurableSessionError::InvalidHistory),
            };
            CoordinationCommand::Recover { claim_id, expected, recovery }
        }
        _ => return Err(DurableSessionError::InvalidHistory),
    };
    decoder.ensure_finished()?;
    let request = Request { principal, session, command, now };
    if encode_request(&request)? != bytes { return Err(DurableSessionError::InvalidHistory); }
    Ok(request)
}

pub(super) fn encode_record(
    request: &[u8], before: ContentDigest, after: ContentDigest, outcome: ContentDigest,
) -> Result<Vec<u8>, DurableSessionError> {
    if request.len() > MAX_COORDINATION_RECORD_BYTES - 256 { return Err(DurableSessionError::CapacityExceeded); }
    let mut encoder = CanonicalEncoder::new();
    encoder.text(RECORD_FORMAT);
    encoder.bytes(request);
    encoder.digest(before);
    encoder.digest(after);
    encoder.digest(outcome);
    let bytes = encoder.finish_checked()?;
    if bytes.len() > MAX_COORDINATION_RECORD_BYTES { return Err(DurableSessionError::CapacityExceeded); }
    Ok(bytes)
}

pub(super) fn decode_record(bytes: &[u8]) -> Result<Record, DurableSessionError> {
    if bytes.len() > MAX_COORDINATION_RECORD_BYTES { return Err(DurableSessionError::CapacityExceeded); }
    let mut decoder = CanonicalDecoder::new(bytes);
    if decoder.text()? != RECORD_FORMAT { return Err(DurableSessionError::InvalidHistory); }
    let request_bytes = decoder.bytes()?;
    let request = decode_request(request_bytes)?;
    let before = decoder.digest()?;
    let after = decoder.digest()?;
    let outcome = decoder.digest()?;
    decoder.ensure_finished()?;
    if encode_record(request_bytes, before, after, outcome)? != bytes { return Err(DurableSessionError::InvalidHistory); }
    Ok(Record { request, before, after, outcome })
}

pub(super) fn outcome_digest(result: &Result<WorkClaimRevision, WorkClaimError>) -> Result<ContentDigest, DurableSessionError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.reference_coordination_outcome.v1");
    match result {
        Ok(revision) => { encoder.tag(0); encoder.digest(revision.digest()); }
        Err(error) => {
            // Exhaustive private refusal tags. Only the fingerprint is persisted, never error
            // prose containing caller input. Nested Display identities are version-bound here.
            encoder.tag(match error {
                WorkClaimError::Unavailable => 1,
                WorkClaimError::Conflict => 2,
                WorkClaimError::StaleRevision => 3,
                WorkClaimError::StaleBasis => 4,
                WorkClaimError::InvalidLease => 5,
                WorkClaimError::InvalidTransition => 6,
                WorkClaimError::DependencyPending => 7,
                WorkClaimError::CapacityExceeded => 8,
                WorkClaimError::CounterExhausted => 9,
                WorkClaimError::ClockRegression => 10,
                WorkClaimError::Contract(_) => 11,
                WorkClaimError::Session(_) => 12,
            });
            match error {
                WorkClaimError::Contract(source) => encoder.text(&source.to_string()),
                WorkClaimError::Session(source) => encoder.text(&source.to_string()),
                _ => {}
            }
        }
    }
    Ok(ContentDigest::sha256(&encoder.finish_checked()?))
}
