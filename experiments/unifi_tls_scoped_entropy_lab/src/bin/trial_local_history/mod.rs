#![forbid(unsafe_code)]
//! Bounded local-history observation. This never returns a replay pin or effect authority.
//!
//! All heads are derived from the observed storage itself, without an independent
//! minimum. Namespaces are checked for consistency within each chain, not bound
//! to the current physical directory. Observations are not an atomic snapshot.

use std::{collections::BTreeMap, path::Path};

use fss_core::{CanonicalDecoder, ContentDigest};
use fss_object::{HostSpoolIo, SpoolLimits, effect_journal::EFFECT_JOURNAL_RECORD_DOMAIN};

struct Record {
    root: ContentDigest,
    payload: Vec<u8>,
}

fn records(path: &Path) -> Result<Vec<Record>, &'static str> {
    let limits = SpoolLimits::new(128, 2 * 1024 * 1024, 4096, 272);
    let before = fss_object::inspect(path, &limits).map_err(|_| "history inspection refused")?;
    if before.missing_layout || before.over_capacity || !before.report.is_clean()
        || before.report.admitted.is_empty() || before.report.admitted.len() > 128 {
        return Err("history layout unavailable");
    }
    let mut ordered = BTreeMap::new();
    let mut namespace = None;
    for root in &before.report.admitted {
        let bytes = fss_object::read_verified_payload(path, *root, 4096, &HostSpoolIo)
            .map_err(|_| "history object unavailable")?;
        let mut d = CanonicalDecoder::new(&bytes);
        if d.text().map_err(|_| "history envelope invalid")? != EFFECT_JOURNAL_RECORD_DOMAIN {
            return Err("history envelope invalid");
        }
        let claimed_namespace = d.digest().map_err(|_| "history envelope invalid")?;
        if namespace.is_some_and(|value| value != claimed_namespace) {
            return Err("history namespaces differ");
        }
        namespace = Some(claimed_namespace);
        let sequence = d.u64().map_err(|_| "history envelope invalid")?;
        let previous = if d.bool().map_err(|_| "history envelope invalid")? {
            Some(d.digest().map_err(|_| "history envelope invalid")?)
        } else { None };
        let payload = d.bytes().map_err(|_| "history envelope invalid")?.to_vec();
        d.ensure_finished().map_err(|_| "history envelope invalid")?;
        if sequence == 0 || ordered.insert(sequence, (previous, Record { root: *root, payload })).is_some() {
            return Err("history sequence invalid");
        }
    }
    let mut result = Vec::with_capacity(ordered.len());
    let mut previous = None;
    for (sequence, (claimed_previous, record)) in ordered {
        if sequence != result.len() as u64 + 1 || claimed_previous != previous {
            return Err("history predecessor mismatch");
        }
        previous = Some(record.root);
        result.push(record);
    }
    let after = fss_object::inspect(path, &limits).map_err(|_| "history reinspection refused")?;
    if before != after { return Err("history changed during inspection"); }
    Ok(result)
}

/// Observe a confirmed source root in the local intent chain and its caught-up
/// local keeper. No independent minimum, namespace identity or camera identity
/// is established, and the result must never be used to authorize dispatch.
pub fn source_confirmed(archive: &Path, requested: ContentDigest) -> Result<(), &'static str> {
    let journal = records(&archive.join("source-intent"))?;
    let keeper = records(&archive.join("source-anchor"))?;
    let scope = ContentDigest::sha256(b"http-trial-source");
    let retention = ContentDigest::sha256(b"unifi-http-record-trial-retention");
    let mut pending = None;
    let mut matched = false;
    for (index, record) in journal.iter().enumerate() {
        let mut d = CanonicalDecoder::new(&record.payload);
        if d.text().map_err(|_| "intent invalid")? != "fss.unifi-direct.av-unknown-time-intent.v1"
            || d.digest().map_err(|_| "intent invalid")? != scope {
            return Err("intent scope invalid");
        }
        let kind = d.u8().map_err(|_| "intent invalid")?;
        let pin = if kind == 0 { None } else {
            let root = d.digest().map_err(|_| "intent invalid")?;
            let retained = d.digest().map_err(|_| "intent invalid")?;
            if retained != retention || d.i128().map_err(|_| "intent invalid")? != i128::MIN
                || d.i128().map_err(|_| "intent invalid")? != i128::MAX {
                return Err("intent retention or time mismatch");
            }
            Some(root)
        };
        d.ensure_finished().map_err(|_| "intent invalid")?;
        match (index, kind, pin) {
            (0, 0, None) => (),
            (n, 1, Some(root)) if n > 0 && pending.is_none() => pending = Some(root),
            (n, 2, Some(root)) if n > 0 && pending == Some(root) => {
                pending = None;
                matched |= root == requested;
            }
            _ => return Err("intent transition invalid"),
        }
    }
    if !matched || pending.is_some() { return Err("source intent not confirmed"); }
    let mut last = 0usize;
    for record in &keeper {
        let mut d = CanonicalDecoder::new(&record.payload);
        if d.text().map_err(|_| "keeper invalid")? != "fss.unifi-direct.av-publication-anchor.v1"
            || d.digest().map_err(|_| "keeper invalid")? != scope {
            return Err("keeper scope invalid");
        }
        let sequence = usize::try_from(d.u64().map_err(|_| "keeper invalid")?).map_err(|_| "keeper invalid")?;
        let root = d.digest().map_err(|_| "keeper invalid")?;
        d.ensure_finished().map_err(|_| "keeper invalid")?;
        if sequence <= last || journal.get(sequence - 1).is_none_or(|record| record.root != root) {
            return Err("keeper target mismatch");
        }
        last = sequence;
    }
    if last != journal.len() { return Err("keeper is behind intent history"); }
    Ok(())
}
