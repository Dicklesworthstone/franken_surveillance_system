#![forbid(unsafe_code)]
//! Validate a caller-declared, property-disjoint corpus before looking at candidates.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{CanonicalEncoder, ContentDigest};
use fss_reference::evaluation::{LabelSet, MAX_EVALUATION_CLIPS, MAX_EVALUATION_ID_BYTES};

use super::{Failure, Result, integer, object, rows, text};
#[path = "holdout/comparison.rs"]
mod comparison;

const MANIFEST_SCHEMA: &str = "fss-evaluation-holdout.v1";
const RECEIPT_SCHEMA: &str = "fss.evaluation.holdout.v1";

#[derive(Clone, Copy, Eq, PartialEq)]
enum Partition {
    Training = 0,
    Calibration = 1,
    Holdout = 2,
}

#[derive(Debug)]
pub(super) struct Holdout {
    manifest_digest: ContentDigest,
    threshold_ppm: u32,
    counts: [usize; 3],
}

fn digest(encoder: CanonicalEncoder) -> Result<ContentDigest> {
    encoder
        .finish_checked()
        .map(|bytes| ContentDigest::sha256(&bytes))
        .map_err(|_| Failure::new("evaluation.holdout.encoding"))
}

impl Holdout {
    pub(super) fn receipt(&self, report: ContentDigest) -> Result<String> {
        let mut binding = CanonicalEncoder::new();
        binding.text(RECEIPT_SCHEMA);
        binding.digest(self.manifest_digest);
        binding.digest(report);
        Ok(object(&[
            ("schema", text(RECEIPT_SCHEMA)),
            ("membership_basis", text("caller_declared")),
            (
                "training_clips",
                self.counts[Partition::Training as usize].to_string(),
            ),
            (
                "calibration_clips",
                self.counts[Partition::Calibration as usize].to_string(),
            ),
            (
                "holdout_clips",
                self.counts[Partition::Holdout as usize].to_string(),
            ),
            ("fixed_threshold_ppm", self.threshold_ppm.to_string()),
            ("manifest_digest", text(&self.manifest_digest.to_string())),
            ("report_digest", text(&report.to_string())),
            ("digest", text(&digest(binding)?.to_string())),
        ]))
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_EVALUATION_ID_BYTES
        && value.bytes().all(|b| b.is_ascii_graphic())
}

pub(super) fn validate(input: &str, labels: &LabelSet, fixed: Option<u32>) -> Result<Holdout> {
    let mut threshold = None;
    let mut clips = BTreeMap::new();
    let mut properties = BTreeMap::new();
    let mut sessions = BTreeMap::new();
    let mut recordings = BTreeMap::new();
    let mut counts = [0usize; 3];
    for (line, fields) in rows(input, MANIFEST_SCHEMA)? {
        if let ["threshold_ppm", raw] = fields.as_slice() {
            let value = integer(raw).map_err(|error| error.at(line))?;
            if value > 1_000_000 || threshold.replace(value as u32).is_some() {
                return Err(Failure::new("evaluation.holdout.threshold").at(line));
            }
            continue;
        }
        let ["clip", partition, clip, property, session, source] = fields.as_slice() else {
            return Err(Failure::new("evaluation.cli.invalid_row").at(line));
        };
        let partition = match *partition {
            "training" => Partition::Training,
            "calibration" => Partition::Calibration,
            "holdout" => Partition::Holdout,
            _ => return Err(Failure::new("evaluation.holdout.partition").at(line)),
        };
        if counts[partition as usize] >= MAX_EVALUATION_CLIPS {
            return Err(Failure::new("evaluation.limit_exceeded").at(line));
        }
        if ![clip, property, session].iter().all(|id| valid_id(id)) {
            return Err(Failure::new("evaluation.holdout.identifier").at(line));
        }
        // Require the unique lowercase SHA-256 spelling, so aliases cannot bypass separation.
        let canonical_source = source.strip_prefix("sha256:").is_some_and(|hex| {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        });
        if !canonical_source {
            return Err(Failure::new("evaluation.holdout.source_digest").at(line));
        }
        if clips
            .insert(*clip, (partition, *property, *session, *source))
            .is_some()
        {
            return Err(Failure::new("evaluation.holdout.duplicate_clip").at(line));
        }
        let property_conflict = properties
            .insert(*property, partition)
            .is_some_and(|old| old != partition);
        let session_conflict = sessions
            .insert(*session, (partition, *property))
            .is_some_and(|old| old != (partition, *property));
        let source_conflict = recordings
            .insert(*source, partition)
            .is_some_and(|old| old != partition);
        if property_conflict || session_conflict || source_conflict {
            return Err(Failure::new("evaluation.holdout.group_conflict").at(line));
        }
        counts[partition as usize] += 1;
    }
    let threshold_ppm = threshold.ok_or_else(|| Failure::new("evaluation.holdout.threshold"))?;
    if Some(threshold_ppm) != fixed {
        return Err(Failure::new("evaluation.holdout.threshold"));
    }
    if counts[Partition::Calibration as usize] == 0 || counts[Partition::Holdout as usize] == 0 {
        return Err(Failure::new("evaluation.holdout.empty_partition"));
    }
    let labeled: BTreeSet<_> = labels
        .clips
        .iter()
        .map(|clip| clip.clip_id.as_str())
        .collect();
    let expected = clips
        .iter()
        .filter_map(|(&id, row)| (row.0 == Partition::Holdout).then_some(id));
    if !expected.eq(labeled) {
        return Err(Failure::new("evaluation.holdout.membership"));
    }
    let mut manifest = CanonicalEncoder::new();
    manifest.text(MANIFEST_SCHEMA);
    manifest.u32(threshold_ppm);
    manifest.u64(clips.len() as u64);
    for (clip, (partition, property, session, source)) in clips {
        manifest.text(clip);
        manifest.tag(partition as u8);
        manifest.text(property);
        manifest.text(session);
        manifest.text(source);
    }
    Ok(Holdout {
        manifest_digest: digest(manifest)?,
        threshold_ppm,
        counts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = include_str!("../../../../../fixtures/evaluation/cli-smoke/holdout.tsv");
    const LABELS: &str = include_str!("../../../../../fixtures/evaluation/cli-smoke/labels.tsv");

    #[test]
    fn source_property_session_and_complete_holdout_are_enforced() -> Result<()> {
        let labels = super::super::parse_labels(LABELS)?;
        let source = "3".repeat(64);
        for (old, new, expected) in [
            (
                "training-property",
                "held-property",
                "evaluation.holdout.group_conflict",
            ),
            (
                "cal-session",
                "held-session",
                "evaluation.holdout.group_conflict",
            ),
            (
                &source[..],
                &"2".repeat(64)[..],
                "evaluation.holdout.group_conflict",
            ),
            (
                "holdout\tc\t",
                "holdout\tcal\t",
                "evaluation.holdout.duplicate_clip",
            ),
            (
                "holdout\tc\t",
                "holdout\tunscored\t",
                "evaluation.holdout.membership",
            ),
            (
                "clip\tcalibration",
                "clip\ttraining",
                "evaluation.holdout.empty_partition",
            ),
            ("800000", "800001", "evaluation.holdout.threshold"),
            ("sha256:", "SHA256:", "evaluation.holdout.source_digest"),
        ] {
            assert_eq!(
                validate(&MANIFEST.replace(old, new), &labels, Some(800_000))
                    .err()
                    .map(|error| error.code),
                Some(expected)
            );
        }
        let extra = format!("{LABELS}clip\tcal\t1000\n");
        let extra = super::super::parse_labels(&extra)?;
        assert_eq!(
            validate(MANIFEST, &extra, Some(800_000))
                .err()
                .map(|e| e.code),
            Some("evaluation.holdout.membership")
        );
        Ok(())
    }

    #[test]
    fn manifest_permutation_preserves_binding_and_input_changes_invalidate_it() -> Result<()> {
        let labels = super::super::parse_labels(LABELS)?;
        let holdout = validate(MANIFEST, &labels, Some(800_000))?;
        let mut lines: Vec<_> = MANIFEST.lines().skip(1).collect();
        lines.reverse();
        let reordered = format!("{MANIFEST_SCHEMA}\n{}", lines.join("\n"));
        let reordered = validate(&reordered, &labels, Some(800_000))?;
        assert_eq!(holdout.manifest_digest, reordered.manifest_digest);
        let changed = MANIFEST.replace("cal-property", "other-property");
        let changed = validate(&changed, &labels, Some(800_000))?;
        assert_ne!(holdout.manifest_digest, changed.manifest_digest);
        assert_ne!(
            holdout.receipt(ContentDigest::sha256(b"report 1"))?,
            holdout.receipt(ContentDigest::sha256(b"report 2"))?
        );
        Ok(())
    }
}
