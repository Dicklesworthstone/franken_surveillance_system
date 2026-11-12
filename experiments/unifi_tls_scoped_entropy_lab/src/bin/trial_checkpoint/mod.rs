#![forbid(unsafe_code)]
//! Explicitly scoped laboratory effect custody; the root is an operator trust boundary.

use std::{error::Error, path::Path, sync::Arc};

use fss_core::{CanonicalEncoder, ContentDigest};
use fss_object::{
    HostSpoolIo,
    effect_journal::{EffectJournalLimits, FileEffectJournal, FileTrustedRootPinRetainer},
};
use fss_runtime::effect_journal::{
    EffectJournalPin, EffectJournalStore, EffectPinRetainer, PinRetainedEffectJournal,
    keeper::{JournalPinRetainer, RootAnchoredJournalPinRetainer},
};

type ResultBox<T> = Result<T, Box<dyn Error>>;

fn scope(domain: &str, uuid: &str, mac: [u8; 6]) -> ResultBox<ContentDigest> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(domain);
    encoder.text(uuid);
    encoder.bytes(&mac);
    Ok(ContentDigest::sha256(&encoder.finish_checked()?))
}

/// Reopen existing custody for reconciliation only. Trusting the root storage
/// does not establish that it is independent or has not itself been rolled back.
#[allow(dead_code)]
pub fn reopen(
    effect_path: &Path,
    keeper_path: &Path,
    root_path: &Path,
    uuid: &str,
    mac: [u8; 6],
) -> ResultBox<(Box<dyn EffectJournalStore>, EffectJournalPin)> {
    let keeper_scope = scope("fss.unifi-direct.trial-keeper.v1", uuid, mac)?;
    let root_scope = scope("fss.unifi-direct.trial-trusted-root.v1", uuid, mac)?;
    let limits = EffectJournalLimits::default();
    let mut root = FileTrustedRootPinRetainer::open_trusting_storage(
        root_path,
        limits,
        Arc::new(HostSpoolIo),
        root_scope,
    )?;
    let keeper_pin = root.retained_pin()?.ok_or("missing keeper checkpoint")?;
    let keeper_file =
        FileEffectJournal::open(keeper_path, limits, Arc::new(HostSpoolIo), keeper_pin)?;
    let keeper = JournalPinRetainer::reopen(Box::new(keeper_file), keeper_scope, keeper_pin)?;
    let mut keeper = RootAnchoredJournalPinRetainer::new(keeper, Box::new(root))?;
    let effect_pin = keeper.retained_pin()?.ok_or("missing effect checkpoint")?;
    let effect = FileEffectJournal::open(effect_path, limits, Arc::new(HostSpoolIo), effect_pin)?;
    let journal = PinRetainedEffectJournal::for_reconciliation(Box::new(effect), Box::new(keeper))?;
    Ok((Box::new(journal), effect_pin))
}

/// Create separate effect, keeper and root stores before any camera effect.
/// The caller must independently choose and authorize the storage domains.
pub fn create(
    effect_path: &Path,
    keeper_path: &Path,
    root_path: &Path,
    uuid: &str,
    mac: [u8; 6],
) -> ResultBox<Box<dyn EffectJournalStore>> {
    let keeper_scope = scope("fss.unifi-direct.trial-keeper.v1", uuid, mac)?;
    let root_scope = scope("fss.unifi-direct.trial-trusted-root.v1", uuid, mac)?;
    let limits = EffectJournalLimits::default();
    let effect = FileEffectJournal::create(effect_path, limits, Arc::new(HostSpoolIo))?;
    let keeper_file = FileEffectJournal::create(keeper_path, limits, Arc::new(HostSpoolIo))?;
    let (keeper, bootstrap) = JournalPinRetainer::create(Box::new(keeper_file), keeper_scope)?;
    let mut root =
        FileTrustedRootPinRetainer::create(root_path, limits, Arc::new(HostSpoolIo), root_scope)?;
    root.retain(None, bootstrap)?;
    let keeper = RootAnchoredJournalPinRetainer::new(keeper, Box::new(root))?;
    Ok(Box::new(PinRetainedEffectJournal::new(
        Box::new(effect),
        Box::new(keeper),
    )?))
}
