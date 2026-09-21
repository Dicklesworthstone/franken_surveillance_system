#![forbid(unsafe_code)]
//! Small canonical pin records inside the existing crash-classifying Journal framing.
use super::*;
use fss_core::{CanonicalDecoder, CanonicalEncoder};
const DOMAIN: &str = "fss.archive_pin_journal.v1";

fn digest_ok(digest: ContentDigest) -> bool {
    digest.algorithm() == DigestAlgorithm::Sha256 && digest.bytes() != [0; 32]
}
pub(super) fn validate_scope(scope: ArchivePinScope) -> PinResult<()> {
    if !digest_ok(scope.journal_id) || !digest_ok(scope.archive_namespace) { return Err(ArchivePinError::Scope); }
    Ok(())
}
pub(super) fn validate_pin(pin: &StoredArchivePin) -> PinResult<()> {
    if !digest_ok(pin.root) || !digest_ok(pin.retirement) || pin.new_payload_bytes == 0
        || pin.new_payload_bytes > MAX_ARCHIVE_WORK_BYTES { return Err(ArchivePinError::History); }
    let retirement = pin.retirement.to_text();
    let hex = retirement.strip_prefix("sha256:").ok_or(ArchivePinError::History)?;
    if pin.slot.as_str() != format!("fssaw1-{hex}-r") { return Err(ArchivePinError::History); }
    Ok(())
}
pub(super) fn encode(scope: ArchivePinScope, tag: u8, pin: Option<&StoredArchivePin>) -> PinResult<Vec<u8>> {
    validate_scope(scope)?;
    if tag > 2 || (tag == 0) != pin.is_none() { return Err(ArchivePinError::History); }
    let mut e = CanonicalEncoder::new(); e.text(DOMAIN);
    e.digest(scope.journal_id); e.digest(scope.archive_namespace); e.tag(tag);
    if let Some(pin) = pin {
        validate_pin(pin)?;
        e.text(pin.slot.as_str()); e.digest(pin.root); e.digest(pin.retirement); e.u64(pin.new_payload_bytes as u64);
    }
    let bytes = e.finish_checked().map_err(|_| ArchivePinError::Limit)?;
    if bytes.len() > MAX_PAYLOAD { return Err(ArchivePinError::Limit); }
    Ok(bytes)
}
fn decode(bytes: &[u8], expected: ArchivePinScope) -> PinResult<(u8, Option<StoredArchivePin>)> {
    let decode = || -> Result<_, fss_core::ContractError> {
        let mut d = CanonicalDecoder::new(bytes);
        if d.text()? != DOMAIN { return Err(fss_core::ContractError::InvalidIdentifier); }
        let scope = ArchivePinScope { journal_id: d.digest()?, archive_namespace: d.digest()? };
        let tag = d.tag()?;
        let pin = if tag == 0 { None } else {
            Some((d.text()?.to_owned(), d.digest()?, d.digest()?, d.u64()?))
        };
        d.ensure_finished()?;
        Ok((scope, tag, pin))
    };
    if bytes.len() > MAX_PAYLOAD { return Err(ArchivePinError::Limit); }
    let (scope, tag, fields) = decode().map_err(|_| ArchivePinError::History)?;
    if scope != expected { return Err(ArchivePinError::Scope); }
    let pin = fields.map(|(slot, root, retirement, count)| -> PinResult<_> {
        Ok(StoredArchivePin { slot: SlotName::parse(&slot).map_err(|_| ArchivePinError::History)?,
            root, retirement, new_payload_bytes: usize::try_from(count).map_err(|_| ArchivePinError::Limit)? })
    }).transpose()?;
    if encode(scope, tag, pin.as_ref())? != bytes { return Err(ArchivePinError::History); }
    Ok((tag, pin))
}
pub(super) fn apply(state: &mut ReplayState, tag: u8, pin: StoredArchivePin) -> PinResult<()> {
    validate_pin(&pin)?;
    match tag {
        1 => {
            if state.pins.candidate.is_some() || state.seen.iter().any(|(root, retirement)|
                *root == pin.root || *retirement == pin.retirement) { return Err(ArchivePinError::History); }
            state.seen.try_reserve_exact(1).map_err(|_| ArchivePinError::Limit)?;
            state.seen.push((pin.root, pin.retirement));
            state.pins.candidate = Some(pin);
        }
        2 if state.pins.candidate.as_ref() == Some(&pin) => {
            state.pins.confirmed = Some(pin); state.pins.candidate = None;
        }
        _ => return Err(ArchivePinError::History),
    }
    Ok(())
}
pub(super) fn replay(report: &RecoveryReport, scope: ArchivePinScope, limits: ArchivePinLimits) -> PinResult<ReplayState> {
    if report.records().is_empty() || report.records().len() > limits.max_records { return Err(ArchivePinError::History); }
    let mut state = ReplayState::default();
    for (i, record) in report.records().iter().enumerate() {
        if record.kind() != RECORD_KIND || record.sequence() != i as u64 + 1 { return Err(ArchivePinError::History); }
        let (tag, pin) = decode(record.payload(), scope)?;
        if i == 0 {
            if tag != 0 || pin.is_some() { return Err(ArchivePinError::History); }
        } else {
            apply(&mut state, tag, pin.ok_or(ArchivePinError::History)?)?;
        }
    }
    Ok(state)
}
