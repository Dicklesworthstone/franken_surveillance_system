#![forbid(unsafe_code)]
//! Independently saved datagram prefixes, interpreted only in the original capture scope.

use super::*;
use fss_core::DigestAlgorithm;
use fss_reference::rtsp::datagram_archive::DatagramPin;

const MAX_ATTEMPTS: usize = 16;
const MAX_TEXT_BYTES: usize = 1900;
const MALFORMED: &str =
    "minimum source pins require unique ATTEMPT:DATAGRAMS:PAYLOAD_BYTES:sha256:HEAD rows";
const POLICY: &str =
    "source-recovery-minimum-pins:original-attempt-scope:exact-count-bytes-head:v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct MinimumSourcePin {
    head: ContentDigest,
    datagrams: u64,
    payload_bytes: u64,
}
impl MinimumSourcePin {
    pub(super) fn pin(self, config: &SourceConfig) -> Result<DatagramPin> {
        Ok(DatagramPin {
            scope: config.scope.digest().map_err(|_| MALFORMED)?,
            head: self.head,
            datagrams: self.datagrams,
            payload_bytes: self.payload_bytes,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MinimumSourcePins {
    entries: [Option<MinimumSourcePin>; MAX_ATTEMPTS],
}

fn decimal(text: &str) -> Result<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(MALFORMED);
    }
    text.parse().map_err(|_| MALFORMED)
}

impl MinimumSourcePins {
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
            let (datagrams, tail) = tail.split_once(':').ok_or(MALFORMED)?;
            let (payload_bytes, head) = tail.split_once(':').ok_or(MALFORMED)?;
            let attempt = decimal(attempt)?;
            let datagrams = decimal(datagrams)?;
            let payload_bytes = decimal(payload_bytes)?;
            let head = ContentDigest::parse(head).map_err(|_| MALFORMED)?;
            if !(1..=MAX_ATTEMPTS as u64).contains(&attempt)
                || datagrams == 0
                || head.algorithm() != DigestAlgorithm::Sha256
                || head.bytes() == [0; 32]
            {
                return Err(MALFORMED);
            }
            let entry = &mut result.entries[(attempt - 1) as usize];
            if entry.is_some() {
                return Err(MALFORMED);
            }
            *entry = Some(MinimumSourcePin {
                head,
                datagrams,
                payload_bytes,
            });
        }
        Ok(result)
    }

    pub(crate) fn validate(&self, plan: &impl RecoveryPlan) -> Result<()> {
        if plan.attempts().is_empty() || plan.attempts().len() > MAX_ATTEMPTS {
            return Err(MALFORMED);
        }
        for (index, entry) in self.entries.iter().enumerate() {
            if let Some(pin) = entry {
                if index >= plan.attempts().len() {
                    return Err(MALFORMED);
                }
                let source = plan.source(index)?.ok_or(MALFORMED)?;
                if pin.datagrams > source.limits.max_datagrams as u64
                    || pin.payload_bytes > source.limits.max_payload_bytes
                {
                    return Err("minimum source pin exceeds the original capture bounds");
                }
            }
        }
        Ok(())
    }

    pub(super) fn get(&self, index: usize) -> Option<MinimumSourcePin> {
        self.entries.get(index).copied().flatten()
    }

    pub(super) fn encode(&self, e: &mut CanonicalEncoder) {
        e.text(POLICY);
        e.u64(self.entries.iter().flatten().count() as u64);
        for (index, entry) in self.entries.iter().enumerate() {
            if let Some(pin) = entry {
                e.u64(index as u64 + 1);
                e.u64(pin.datagrams);
                e.u64(pin.payload_bytes);
                e.digest(pin.head);
            }
        }
    }

    pub(super) fn json(&self) -> String {
        let entries = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                entry.map(|pin| {
                    object(&[
                        ("attempt", (index + 1).to_string()),
                        ("datagrams", pin.datagrams.to_string()),
                        ("payload_bytes", pin.payload_bytes.to_string()),
                        ("head", string(&pin.head.to_text())),
                    ])
                })
            })
            .collect::<Vec<_>>();
        format!("[{}]", entries.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(attempt: u64, datagrams: u64, bytes: u64, label: &str) -> String {
        format!(
            "{attempt}:{datagrams}:{bytes}:{}",
            ContentDigest::sha256(label.as_bytes())
        )
    }
    fn encoding(pins: &MinimumSourcePins) -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        pins.encode(&mut e);
        e.finish()
    }

    #[test]
    fn exact_source_prefixes_are_canonical_and_all_coordinates_are_bound() -> Result<()> {
        let a = row(1, 2, 7, "first");
        let b = row(2, 4, 9, "second");
        let left = MinimumSourcePins::parse(&format!("{a},{b}"))?;
        let right = MinimumSourcePins::parse(&format!("{b},{a}"))?;
        assert_eq!(left, right);
        assert_eq!(encoding(&left), encoding(&right));
        let original = encoding(&MinimumSourcePins::parse(&a)?);
        for changed in [
            row(2, 2, 7, "first"),
            row(1, 3, 7, "first"),
            row(1, 2, 8, "first"),
            row(1, 2, 7, "other"),
        ] {
            assert_ne!(original, encoding(&MinimumSourcePins::parse(&changed)?));
        }
        assert!(MinimumSourcePins::parse(&row(1, 1, 0, "zero-byte-datagram")).is_ok());
        Ok(())
    }

    #[test]
    fn malformed_duplicate_empty_and_unbounded_minimums_refuse() {
        let valid = row(1, 2, 7, "source");
        for bad in [
            String::new(),
            " ".into(),
            "1:2:7".into(),
            "1:2:7:sha256:00".into(),
            row(0, 1, 7, "zero-attempt"),
            row(17, 1, 7, "many"),
            row(1, 0, 0, "empty"),
            format!("{valid},"),
            format!("{valid},{valid}"),
            format!(" {valid}"),
            valid.replacen("1:", "+1:", 1),
            valid.replacen(":2:", ":-2:", 1),
            valid.replacen(":7:", ":18446744073709551616:", 1),
            format!("1:2:7:sha256:{}", "0".repeat(64)),
            "x".repeat(MAX_TEXT_BYTES + 1),
        ] {
            assert!(MinimumSourcePins::parse(&bad).is_err());
        }
        let full = (1..=16)
            .map(|n| row(n, u64::MAX, u64::MAX, "full"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(full.len() <= MAX_TEXT_BYTES);
        assert!(MinimumSourcePins::parse(&full).is_ok());
    }
}
