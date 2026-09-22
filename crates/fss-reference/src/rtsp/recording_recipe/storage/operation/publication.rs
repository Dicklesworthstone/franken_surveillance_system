#![forbid(unsafe_code)]
//! Exact retryable output slots followed by the one complete reconstruction root.
use super::*;
use crate::rtsp::recording::local::{RecordingProgress, RecordingPublication};

/// Complete-result durability is distinct from each individually published recording.
#[derive(Debug)]
pub struct ReconstructionPublication {
    /// The prepared completion identity, unchanged across exact retries.
    pub pin: ReconstructionPin,
    /// Actual receipts in recording ordinal order, including AlreadyPublished on retries.
    pub windows: Vec<LocalPublicationReceipt>,
    /// Published last, only after every original output root is durable and reverified.
    pub completion: LocalPublicationReceipt,
}
/// A failed call can have committed recordings or even an uncertain completion root. Keep the
/// same plan/pin and reopen/reconcile the same publisher; do not change ordinals or delete state.
#[derive(Debug)]
#[must_use]
pub struct ReconstructionPublishFailure {
    /// Original typed recording/source failure, not a fabricated all-or-nothing result.
    pub reason: ReconstructionError,
    /// All output acknowledgements observed before this call failed.
    pub windows: Vec<LocalPublicationReceipt>,
}
impl std::fmt::Display for ReconstructionPublishFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { std::fmt::Display::fmt(&self.reason, f) }
}
impl std::error::Error for ReconstructionPublishFailure {}

impl PreparedReconstruction<'_> {
    /// Reverify the pinned source recipe, publish each existing PreparedRecording using its
    /// native source-first owner, then publish the complete derived-result graph last. No camera,
    /// new archive ordinal, additional catalog, automatic retry or cleanup is introduced.
    /// deadline_ns is a fresh current-operation lease, never obtained from stored instructions.
    pub fn publish(&self, p: &mut LocalRootPublisher, deadline_ns: u64,
        clock: &dyn ReconstructionClock, cancel: &dyn PublishCancellation, budget: &mut WorkBudget<'_>)
        -> Result<ReconstructionPublication, ReconstructionPublishFailure> {
        let mut receipts = Vec::new();
        let mut last = 0;
        let result = (|| -> Result<_, ReconstructionError> {
            tick(clock, &mut last, deadline_ns)?;
            self.loaded.verify(p, cancel, budget)?;
            self.check_outputs(p, cancel, budget)?;
            receipts.try_reserve_exact(self.windows.len()).map_err(|_| ReconstructionError::Limit)?;
            // Allocate all result metadata before the first potentially committing operation.
            let pin = self.pin.clone();
            for (index, window) in self.windows.iter().enumerate() {
                super::super::probe(cancel, budget)?;
                budget.charge(window.byte_len() as u64 * 8 + 4096)
                    .map_err(|e| RecordingRecipeError::Source(DatagramArchiveError::Work(e)))?;
                let slot = self.window_slot(index)?;
                let mut job = RecordingPublication::new(window, p, slot, window.byte_len(), deadline_ns)?;
                let mut published = false;
                for _ in 0..5 {
                    let now = tick(clock, &mut last, deadline_ns)?;
                    if let RecordingProgress::Published(receipt) = job.step(now, cancel)? {
                        // No fallible checks/allocation between successful publication and retaining
                        // its actual receipt. Further failure returns it with the other acknowledgements.
                        receipts.push(receipt); published = true; break;
                    }
                }
                if !published { return Err(ReconstructionError::Incomplete); }
            }
            tick(clock, &mut last, deadline_ns)?;
            super::super::probe(cancel, budget)?;
            budget.charge(self.metadata.len() as u64 * 8 + self.manifest.children().len() as u64 * 128 + 4096)
                .map_err(|e| RecordingRecipeError::Source(DatagramArchiveError::Work(e)))?;
            let metadata = p.stage_object(&self.metadata)
                .map_err(|e| RecordingRecipeError::Source(DatagramArchiveError::Publication(e)))?;
            if self.manifest.metadata_digest() != Some(metadata) { return Err(ReconstructionError::Conflict); }
            tick(clock, &mut last, deadline_ns)?;
            super::super::probe(cancel, budget)?;
            // The existing publisher re-verifies the recipe and every output's source closure
            // immediately before the final root commit. A result root is never written first.
            let completion = p.publish_cancellable(&self.pin.slot, &self.manifest, cancel)
                .map_err(|e| RecordingRecipeError::Source(DatagramArchiveError::Publication(e)))?;
            // Return the actual completed receipt even if a new cancellation happens afterwards.
            Ok((pin, completion))
        })();
        match result {
            Ok((pin, completion)) => Ok(ReconstructionPublication { pin, windows: receipts, completion }),
            Err(reason) => Err(ReconstructionPublishFailure { reason, windows: receipts }),
        }
    }

    fn check_outputs(&self, p: &LocalRootPublisher, cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>) -> Result<(), ReconstructionError> {
        let text = self.loaded.pin.root.to_text();
        let hex = text.strip_prefix("sha256:").ok_or(ReconstructionError::Conflict)?;
        let prefix = format!("fssrx1-{hex}-");
        let mut examined = 0;
        let mut scan = || -> Result<(), ReconstructionError> {
            super::super::probe(cancel, budget)?;
            budget.charge(128).map_err(|e| RecordingRecipeError::Source(DatagramArchiveError::Work(e)))?;
            examined += 1;
            if examined > self.limits.max_scan_roots { return Err(ReconstructionError::Limit); }
            Ok(())
        };
        for root in p.visible_roots() {
            scan()?;
            let Some(suffix) = root.slot.as_str().strip_prefix(&prefix) else { continue; };
            let expected = if suffix == "complete" { self.pin.root } else {
                let index = suffix.strip_prefix('w').and_then(|s| usize::from_str_radix(s, 16).ok())
                    .ok_or(ReconstructionError::Conflict)?;
                if root.slot != self.window_slot(index)? { return Err(ReconstructionError::Conflict); }
                self.windows.get(index).ok_or(ReconstructionError::Conflict)?.manifest().root()
            };
            if root.root != expected || root.state != LocalPublicationState::Durable {
                return Err(ReconstructionError::Conflict);
            }
        }
        for slot in p.broken_slots() {
            scan()?; if slot.as_str().starts_with(&prefix) { return Err(ReconstructionError::Conflict); }
        }
        let report = p.recovery_report();
        for path in report.orphaned_temps.iter().chain(report.foreign.iter())
            .chain(report.broken_roots.iter().map(|b| &b.path)) {
            scan()?;
            if path.file_name().is_some_and(|n| n.as_encoded_bytes().starts_with(prefix.as_bytes())) {
                return Err(ReconstructionError::Conflict);
            }
        }
        Ok(())
    }
}
