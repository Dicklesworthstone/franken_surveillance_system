#![forbid(unsafe_code)]
//! Reuse the existing exclusive file journal and explicitly trusted local pin custodian.

use std::path::Path;
use std::sync::Arc;

use fss_core::reference_contract_basis;
use fss_object::{
    SpoolIo,
    effect_journal::{EffectJournalLimits, FileEffectJournal, FileTrustedRootPinRetainer},
};
use fss_runtime::effect_journal::{
    EffectPersistenceError, EffectPinRetainer, PinRetainedEffectJournal,
};

use super::{
    ControlHistoryReport, DurableControlJournal, MAX_CONTROL_HISTORY_RECORDS,
    MAX_CONTROL_RECORD_BYTES, Scope, codec, invalid,
};

const JOURNAL_DIR: &str = "control-history";
const CUSTODY_DIR: &str = "control-history-pins";

fn exists(io: &dyn SpoolIo, path: &Path) -> Result<bool, EffectPersistenceError> {
    match io.symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(invalid("control custody path is not a real directory")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(EffectPersistenceError::Storage(error.to_string())),
    }
}

pub(super) fn open(
    root: &Path,
    deployment_id: &str,
    io: Arc<dyn SpoolIo>,
    allow_create: bool,
) -> Result<DurableControlJournal, EffectPersistenceError> {
    let root = std::path::absolute(root)
        .map_err(|error| EffectPersistenceError::Storage(error.to_string()))?;
    let scope = Scope {
        deployment_id: deployment_id.to_owned(),
        root_digest: fss_ipc::deployment_root_digest(&root),
        basis_digest: reference_contract_basis().basis_digest(),
    };
    let custody_scope = codec::scope_digest(&scope)?;
    let journal_root = root.join(JOURNAL_DIR);
    let custody_root = root.join(CUSTODY_DIR);
    let journal_exists = exists(io.as_ref(), &journal_root)?;
    let custody_exists = exists(io.as_ref(), &custody_root)?;
    let limits = EffectJournalLimits {
        max_records: MAX_CONTROL_HISTORY_RECORDS,
        max_record_bytes: MAX_CONTROL_RECORD_BYTES,
        max_total_bytes: 256 * 1024 * 1024,
        max_read_bytes: 16 * 1024 * 1024 * 1024,
    };
    let custody_limits = EffectJournalLimits {
        max_records: MAX_CONTROL_HISTORY_RECORDS + 1,
        ..limits
    };
    let (store, fresh) = match (journal_exists, custody_exists) {
        (false, false) if allow_create => {
            let journal = FileEffectJournal::create(&journal_root, limits, Arc::clone(&io))?;
            let keeper = FileTrustedRootPinRetainer::create(
                &custody_root,
                custody_limits,
                io,
                custody_scope,
            )?;
            (
                PinRetainedEffectJournal::new(Box::new(journal), Box::new(keeper))?,
                true,
            )
        }
        (true, true) => {
            let mut keeper = FileTrustedRootPinRetainer::open_trusting_storage(
                &custody_root,
                custody_limits,
                Arc::clone(&io),
                custody_scope,
            )?;
            let minimum = keeper
                .retained_pin()?
                .ok_or_else(|| invalid("control bootstrap pin is missing"))?;
            let journal = FileEffectJournal::open(&journal_root, limits, io, minimum)?;
            // A later journal head is ambiguous. Preserve it for explicit reconciliation;
            // never adopt the later record or reinitialize either custody owner.
            (
                PinRetainedEffectJournal::for_reconciliation(Box::new(journal), Box::new(keeper))?,
                false,
            )
        }
        _ => {
            return Err(invalid(
                "control history or pin custody is missing or partially initialized",
            ));
        }
    };
    DurableControlJournal::from_store(scope, Box::new(store), fresh)
}

/// Inspects existing custody while the daemon is stopped, without starting cameras.
/// This takes exclusive locks and syncs recovered names, but creates no history and appends
/// no records. Missing, corrupt, or ambiguous custody is refused.
pub fn inspect_control_history(
    root: &Path,
    deployment_id: &str,
    io: Arc<dyn SpoolIo>,
    maximum: usize,
) -> Result<ControlHistoryReport, EffectPersistenceError> {
    open(root, deployment_id, io, false)?.inspect(maximum)
}
