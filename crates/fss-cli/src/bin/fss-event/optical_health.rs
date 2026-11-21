#![forbid(unsafe_code)]
//! One exact opt-in optical policy parser shared by short watch and corroboration.

use fss_reference::ingest::recorded_health::RecordedHealthPolicy;
use fss_reference::ingest::sensor_health::{OpticalThresholds, POLICY_NAME};

const POLICY: &str = "conservative-optical-v1";
pub(super) const OPTIONS: &[&str] = &[
    "--min-laplacian-variance-x1000",
    "--glare-luma-min",
    "--max-glare-ppm",
];

fn unsigned(values: &[(String, String)], key: &str, default: u64) -> Result<u64, String> {
    let Some((_, value)) = values.iter().find(|(name, _)| name == key) else {
        return Ok(default);
    };
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(format!(
            "{key} requires a canonical unsigned decimal integer"
        ));
    }
    value
        .parse()
        .map_err(|_| format!("{key} exceeds the supported integer range"))
}

pub(super) fn parse(values: &[(String, String)]) -> Result<Option<RecordedHealthPolicy>, String> {
    let selected = values
        .iter()
        .find(|(key, _)| key == "--sensor-health")
        .map(|(_, value)| value.as_str());
    if selected != Some(POLICY)
        && values
            .iter()
            .any(|(key, _)| OPTIONS.contains(&key.as_str()))
    {
        return Err(
            "optical thresholds require --sensor-health conservative-optical-v1".to_owned(),
        );
    }
    match selected {
        None => Ok(None),
        Some(POLICY_NAME) => Ok(Some(RecordedHealthPolicy::ConservativeV1)),
        Some(POLICY) => {
            let defaults = OpticalThresholds::default();
            let min_laplacian_variance_x1000 = unsigned(
                values,
                "--min-laplacian-variance-x1000",
                defaults.min_laplacian_variance_x1000,
            )?;
            let glare_luma_min = u8::try_from(unsigned(
                values,
                "--glare-luma-min",
                u64::from(defaults.glare_luma_min),
            )?)
            .map_err(|_| "--glare-luma-min must be in 0..255")?;
            let max_glare_ppm =
                unsigned(values, "--max-glare-ppm", u64::from(defaults.max_glare_ppm))?;
            if max_glare_ppm > 1_000_000 {
                return Err("--max-glare-ppm must be in 0..1000000".to_owned());
            }
            Ok(Some(RecordedHealthPolicy::ConservativeOpticalV1(
                OpticalThresholds {
                    min_laplacian_variance_x1000,
                    glare_luma_min,
                    max_glare_ppm: max_glare_ppm as u32,
                },
            )))
        }
        Some(_) => Err(format!(
            "--sensor-health requires {POLICY_NAME} or {POLICY}"
        )),
    }
}

/// Reject modes that cannot yet preserve the complete optical admission receipt.
pub(super) fn short_only(
    policy: Option<RecordedHealthPolicy>,
    incompatible_mode: bool,
) -> Result<(), String> {
    if incompatible_mode && matches!(policy, Some(RecordedHealthPolicy::ConservativeOpticalV1(_))) {
        return Err(
            "conservative-optical-v1 requires short entry watch or short corroboration; stream and dwell modes are unsupported".to_owned(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn legacy_defaults_and_exact_optical_thresholds_have_distinct_admission() {
        assert_eq!(parse(&[]), Ok(None));
        assert_eq!(
            parse(&values(&[("--sensor-health", POLICY_NAME)])),
            Ok(Some(RecordedHealthPolicy::ConservativeV1)),
        );
        assert_eq!(
            parse(&values(&[("--sensor-health", POLICY)])),
            Ok(Some(RecordedHealthPolicy::ConservativeOpticalV1(
                OpticalThresholds::default()
            ))),
        );
        let selected = parse(&values(&[
            ("--sensor-health", POLICY),
            ("--min-laplacian-variance-x1000", "12345"),
            ("--glare-luma-min", "239"),
            ("--max-glare-ppm", "75000"),
        ]))
        .expect("explicit optical policy");
        assert_eq!(
            selected,
            Some(RecordedHealthPolicy::ConservativeOpticalV1(
                OpticalThresholds {
                    min_laplacian_variance_x1000: 12345,
                    glare_luma_min: 239,
                    max_glare_ppm: 75000,
                }
            ))
        );
        assert!(short_only(selected, false).is_ok());
        assert!(short_only(selected, true).is_err());
        assert!(short_only(Some(RecordedHealthPolicy::ConservativeV1), true).is_ok());
    }

    #[test]
    fn optical_thresholds_never_implicitly_enable_or_widen_policy() {
        for selected in [None, Some(POLICY_NAME)] {
            let mut pairs = values(&[("--max-glare-ppm", "75000")]);
            if let Some(policy) = selected {
                pairs.push(("--sensor-health".into(), policy.into()));
            }
            assert!(parse(&pairs).is_err());
        }
        for (key, value) in [
            ("--glare-luma-min", "256"),
            ("--max-glare-ppm", "1000001"),
            ("--min-laplacian-variance-x1000", "18446744073709551616"),
            ("--min-laplacian-variance-x1000", "-1"),
            ("--min-laplacian-variance-x1000", "+1"),
            ("--min-laplacian-variance-x1000", "01"),
        ] {
            assert!(
                parse(&values(&[("--sensor-health", POLICY), (key, value)])).is_err(),
                "{key}={value}"
            );
        }
    }
}
