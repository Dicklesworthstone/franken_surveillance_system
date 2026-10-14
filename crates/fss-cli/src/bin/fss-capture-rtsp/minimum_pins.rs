#![forbid(unsafe_code)]
//! Explicit independently retained journal prefixes. No I/O or source authority.

use super::{ArchivePinAnchor, CanonicalEncoder, ContentDigest, Options, Result, object, string};

const MAX_ATTEMPTS: usize = 16;
const MAX_TEXT_BYTES: usize = 1600;
const DOMAIN: &str = "fss.rtsp_recovery_minimum_pins.v1";
const MALFORMED: &str = "minimum pin anchors require unique ATTEMPT:SEQUENCE:sha256:HEX rows";

/// A bounded, canonical map of one-based capture attempts to independent journal prefixes.
/// An omitted attempt has no independent rollback guarantee. A supplied prefix cannot be
/// dropped because its stores disappeared, a newer candidate is damaged, or a reply was lost.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MinimumPins {
    entries: [Option<ArchivePinAnchor>; MAX_ATTEMPTS],
}

fn positive(text: &str) -> Result<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(MALFORMED);
    }
    text.parse::<u64>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or(MALFORMED)
}

impl MinimumPins {
    /// Parse at most sixteen comma-separated `attempt:sequence:sha256:hex` rows.
    /// Bound bytes before splitting or allocating; row order is not semantic identity.
    pub(crate) fn parse(text: &str) -> Result<Self> {
        if text.is_empty() || text.len() > MAX_TEXT_BYTES {
            return Err(MALFORMED);
        }
        let mut result = Self {
            entries: [None; MAX_ATTEMPTS],
        };
        for (count, row) in text.split(',').enumerate() {
            if count >= MAX_ATTEMPTS {
                return Err(MALFORMED);
            }
            let (attempt, tail) = row.split_once(':').ok_or(MALFORMED)?;
            let (sequence, root) = tail.split_once(':').ok_or(MALFORMED)?;
            let ordinal = positive(attempt)?;
            if ordinal > MAX_ATTEMPTS as u64 || !root.starts_with("sha256:") {
                return Err(MALFORMED);
            }
            let index = (ordinal - 1) as usize;
            if result.entries[index].is_some() {
                return Err(MALFORMED);
            }
            result.entries[index] = Some(ArchivePinAnchor {
                sequence: positive(sequence)?,
                root: ContentDigest::parse(root).map_err(|_| MALFORMED)?,
            });
        }
        Ok(result)
    }

    /// Keep the original capture's attempt and journal-record ceilings. An independent
    /// receipt cannot authorize a new attempt, a wider read, or an increased recovery budget.
    pub(crate) fn validate(&self, attempts: &[Options]) -> Result<()> {
        if attempts.is_empty() || attempts.len() > MAX_ATTEMPTS {
            return Err(MALFORMED);
        }
        for (index, entry) in self.entries.iter().enumerate() {
            if let Some(anchor) = entry {
                let attempt = attempts.get(index).ok_or(MALFORMED)?;
                if anchor.sequence > attempt.pin_limits().max_records as u64 {
                    return Err("minimum pin exceeds the original journal record limit");
                }
            }
        }
        Ok(())
    }

    /// Zero-based internal lookup; CLI and rendered ordinals remain one-based.
    pub(crate) fn get(&self, index: usize) -> Option<ArchivePinAnchor> {
        self.entries.get(index).copied().flatten()
    }

    /// Extend only the recovery approval, never the original capture's identity.
    pub(crate) fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(DOMAIN);
        encoder.u64(self.entries.iter().flatten().count() as u64);
        for (index, entry) in self.entries.iter().enumerate() {
            if let Some(anchor) = entry {
                encoder.u64(index as u64 + 1);
                encoder.u64(anchor.sequence);
                encoder.digest(anchor.root);
            }
        }
    }

    pub(crate) fn json(&self) -> String {
        let rows = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                entry.map(|anchor| {
                    object(&[
                        ("attempt", (index + 1).to_string()),
                        ("sequence", anchor.sequence.to_string()),
                        ("root", string(&anchor.root.to_text())),
                    ])
                })
            })
            .collect::<Vec<_>>();
        format!("[{}]", rows.join(","))
    }

    /// Extend either existing internally rendered preview without parsing arbitrary JSON
    /// or changing its approval/schema. Both codec owners emit one complete object here.
    /// The caller rechecks the complete output bound after appending this bounded receipt.
    pub(crate) fn annotate(&self, mut report: String) -> Result<String> {
        if report.pop() != Some('}') || !report.starts_with('{') {
            return Err(super::STATE);
        }
        let receipt = object(&[
            ("minimum_pin_anchors", self.json()),
            ("minimum_prefixes_verified", "true".into()),
            (
                "minimum_prefix_scope",
                string("listed-attempts-only:caller-retained:not-a-signature-or-media-custody-proof"),
            ),
        ]);
        report.push(',');
        report.push_str(receipt.strip_prefix('{').ok_or(super::STATE)?);
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(attempt: u64, sequence: u64, root: &str) -> String {
        format!("{attempt}:{sequence}:{}", ContentDigest::sha256(root.as_bytes()).to_text())
    }

    fn encoded(pins: &MinimumPins) -> Result<Vec<u8>> {
        let mut encoder = CanonicalEncoder::new();
        pins.encode(&mut encoder);
        encoder.finish_checked().map_err(|_| MALFORMED)
    }

    #[test]
    fn ordering_is_canonical_but_every_anchor_coordinate_is_bound() -> Result<()> {
        let a = row(1, 3, "first");
        let b = row(2, 4, "second");
        let left = MinimumPins::parse(&format!("{a},{b}"))?;
        let right = MinimumPins::parse(&format!("{b},{a}"))?;
        assert_eq!(left, right);
        assert_eq!(encoded(&left)?, encoded(&right)?);
        for changed in [row(1, 4, "first"), row(2, 3, "first"), row(1, 3, "other")] {
            assert_ne!(encoded(&MinimumPins::parse(&a)?)?, encoded(&MinimumPins::parse(&changed)?)?);
        }
        Ok(())
    }

    #[test]
    fn malformed_duplicate_and_unbounded_inputs_are_rejected() {
        let valid = row(1, 3, "first");
        let bad = [
            String::new(), " ".into(), "1:1".into(), "1:1:sha256:00".into(),
            row(0, 1, "zero"), row(17, 1, "many"), row(1, 0, "zero"),
            format!("{valid},"), format!(",{valid}"), format!("{valid},{valid}"),
            format!("{valid},{}", row(1, 4, "different")), format!(" {valid}"),
            valid.replacen("1:", "+1:", 1), valid.replacen("1:", "18446744073709551616:", 1),
            valid.replacen(":3:", ":18446744073709551616:", 1),
            "x".repeat(MAX_TEXT_BYTES + 1),
        ];
        for input in bad {
            assert!(MinimumPins::parse(&input).is_err(), "accepted malformed minimum pins");
        }
    }

    #[test]
    fn full_attempt_matrix_fits_the_explicit_text_bound() -> Result<()> {
        let text = (1..=16).map(|n| row(n, u64::MAX, "maximum"))
            .collect::<Vec<_>>().join(",");
        assert!(text.len() <= MAX_TEXT_BYTES);
        let pins = MinimumPins::parse(&text)?;
        assert!(pins.get(15).is_some());
        assert!(pins.get(16).is_none());
        assert!(MinimumPins::parse(&format!("{text},{}", row(1, 1, "extra"))).is_err());
        Ok(())
    }

    #[test]
    fn preview_receipt_is_bounded_complete_and_does_not_replace_the_approval() -> Result<()> {
        let pins = MinimumPins::parse(&row(1, 2, "saved"))?;
        let original = object(&[("approval", string("original")), ("detail", string("braces } {"))]);
        let report = pins.annotate(original.clone())?;
        assert!(report.starts_with(original.strip_suffix('}').ok_or(MALFORMED)?));
        assert!(report.ends_with('}'));
        assert!(report.contains("\"minimum_prefixes_verified\":true"));
        assert!(report.contains(&pins.json()));
        assert!(pins.annotate("[]".into()).is_err());
        Ok(())
    }
}
