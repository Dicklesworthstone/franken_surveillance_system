#![forbid(unsafe_code)]
//! Source-first custody is delegated per attempt, never reused across connections.
//! Reuse the single-session source parser and native owner. This module performs
//! no I/O and grants no retry permission; the ordinary controller owns successors.

use super::super::source_mode::{SourceConfig, SourcePlan};
use super::*;

pub(super) const POLICY: &str = "source-first-reconnect:independent-preapproved-spools:\
whole-attempt-source-budgets:stop-on-unsettled-source:no-source-resume:v1";
const KEYS: [&str; 5] = [
    "--source-root",
    "--source-retention-evidence",
    "--max-datagrams",
    "--source-storage-bytes",
    "--source-work",
];

/// Presence of ANY source option requires the complete explicit source grant.
pub(super) struct SourceArguments(BTreeMap<String, String>);
impl SourceArguments {
    pub(super) fn take(values: &mut BTreeMap<String, String>) -> Option<Self> {
        let selected: BTreeMap<_, _> = KEYS
            .iter()
            .filter_map(|key| values.remove(*key).map(|value| ((*key).to_owned(), value)))
            .collect();
        (!selected.is_empty()).then_some(Self(selected))
    }

    pub(super) fn validate(&self, native: &BTreeMap<String, String>) -> Result<(), &'static str> {
        self.parse(native, None).map(|_| ())
    }

    pub(super) fn attempt(
        &self,
        native: &BTreeMap<String, String>,
        index: usize,
    ) -> Result<SourcePlan, &'static str> {
        self.parse(native, Some(index))
    }

    fn parse(
        &self,
        native: &BTreeMap<String, String>,
        index: Option<usize>,
    ) -> Result<SourcePlan, &'static str> {
        let mut source = self.0.clone();
        if let Some(index) = index {
            let root = source
                .get("--source-root")
                .ok_or("--source-root required")?;
            let ordinal = index.checked_add(1).ok_or("source attempt overflow")?;
            source.insert(
                "--source-root".into(),
                format!("{root}.attempt-{ordinal:04}"),
            );
        }
        let mut args = arguments(native);
        args.extend(arguments(&source));
        // This revalidates the child's exact generation, receive clock, channels,
        // paths, retention evidence and budgets, rather than cloning the base scope.
        SourcePlan::parse(&args)
    }
}

pub(super) struct SourcePlans {
    entries: Vec<SourceConfig>,
    datagrams: u64,
    payload_bytes: u64,
    storage_bytes: u64,
    work: u64,
}
impl SourcePlans {
    pub(super) fn new() -> Self {
        Self {
            entries: Vec::new(),
            datagrams: 0,
            payload_bytes: 0,
            storage_bytes: 0,
            work: 0,
        }
    }

    pub(super) fn push(&mut self, source: SourceConfig) -> Result<(), &'static str> {
        if self.entries.len() >= 16 {
            return Err("source attempt limit exceeded");
        }
        self.datagrams = self
            .datagrams
            .checked_add(source.limits.max_datagrams as u64)
            .ok_or("source datagram budget overflow")?;
        self.payload_bytes = self
            .payload_bytes
            .checked_add(source.limits.max_payload_bytes)
            .ok_or("source payload budget overflow")?;
        self.storage_bytes = self
            .storage_bytes
            .checked_add(source.storage.spool.max_total_bytes)
            .ok_or("source storage budget overflow")?;
        self.work = self
            .work
            .checked_add(source.work)
            .ok_or("source work budget overflow")?;
        self.entries.push(source);
        Ok(())
    }

    pub(super) fn get(&self, index: usize) -> Result<&SourceConfig, &'static str> {
        self.entries.get(index).ok_or("ERR-CAPTURE-RTSP-STATE-001")
    }

    pub(super) fn encode(
        &self,
        attempts: &[Options],
        e: &mut CanonicalEncoder,
    ) -> Result<(), &'static str> {
        if self.entries.len() != attempts.len() || attempts.is_empty() {
            return Err("source attempt count mismatch");
        }
        e.text(POLICY);
        e.u64(self.entries.len() as u64);
        for (source, attempt) in self.entries.iter().zip(attempts) {
            e.digest(source.digest(attempt)?);
        }
        Ok(())
    }

    pub(super) fn report(&self, attempts: &[Options]) -> Result<String, &'static str> {
        if self.entries.len() != attempts.len() {
            return Err("source attempt count mismatch");
        }
        let mut entries = Vec::new();
        for (index, (source, attempt)) in self.entries.iter().zip(attempts).enumerate() {
            entries.push(object(&[
                ("attempt", (index + 1).to_string()),
                (
                    "attempt_approval",
                    string(&source.digest(attempt)?.to_text()),
                ),
                ("source_custody", source.report()),
            ]));
        }
        Ok(object(&[
            ("policy", string(POLICY)),
            ("maximum_datagrams_all_attempts", self.datagrams.to_string()),
            (
                "maximum_payload_bytes_all_attempts",
                self.payload_bytes.to_string(),
            ),
            (
                "maximum_source_spool_bytes_all_attempts",
                self.storage_bytes.to_string(),
            ),
            ("maximum_source_work_all_attempts", self.work.to_string()),
            ("limits_scope", string("per_attempt_no_carryover")),
            ("source_recovery_supported", "true".into()),
            ("source_epoch_reused", "false".into()),
            ("attempts", format!("[{}]", entries.join(","))),
        ]))
    }
}
