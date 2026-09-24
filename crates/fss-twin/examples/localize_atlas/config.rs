#![forbid(unsafe_code)]
//! Strict compatibility-preserving input selection for the owner-run file harness.

use fss_geometry::PinholeIntrinsics;
use fss_twin::rectification::{LensDistortion, LumaRange, RectificationSpec};
use std::{collections::BTreeMap, error::Error};

const KEYS: [&str; 19] = [
    "twin",
    "twin_sha256",
    "source_scene_sha256",
    "atlas",
    "atlas_sha256",
    "provenance_sha256",
    "query",
    "allowed_mask",
    "query_sha256",
    "mask_sha256",
    "exposure_sha256",
    "image_domain_sha256",
    "width",
    "height",
    "fx",
    "fy",
    "cx",
    "cy",
    "work_units",
];
const RECTIFY_KEYS: [&str; 12] = [
    "rectification",
    "source_calibration_sha256",
    "row_stride",
    "luma_range",
    "maximum_radius",
    "target_width",
    "target_height",
    "target_fx",
    "target_fy",
    "target_cx",
    "target_cy",
    "distortion_coefficients",
];

pub(super) struct Config<'a> {
    values: BTreeMap<&'a str, &'a str>,
}
impl<'a> Config<'a> {
    pub(super) fn parse(text: &'a str) -> Result<Self, Box<dyn Error>> {
        if text.len() > 16 * 1024 {
            return Err("config exceeds bound".into());
        }
        let mut values = BTreeMap::new();
        for line in text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
        {
            let (key, value) = line.split_once('=').ok_or("invalid config row")?;
            let (key, value) = (key.trim(), value.trim());
            if (!KEYS.contains(&key) && !RECTIFY_KEYS.contains(&key))
                || value.is_empty()
                || values.insert(key, value).is_some()
            {
                return Err("unknown, empty, or duplicate config field".into());
            }
        }
        if KEYS.iter().any(|key| !values.contains_key(key)) {
            return Err("missing config field".into());
        }
        let added = RECTIFY_KEYS
            .iter()
            .filter(|key| values.contains_key(**key))
            .count();
        if added != 0 && added != RECTIFY_KEYS.len() {
            return Err("rectification requires its complete explicit configuration".into());
        }
        Ok(Self { values })
    }
    pub(super) fn value(&self, key: &str) -> Result<&'a str, Box<dyn Error>> {
        self.values
            .get(key)
            .copied()
            .ok_or_else(|| "missing config field".into())
    }
    pub(super) fn source_intrinsics(&self) -> Result<PinholeIntrinsics, Box<dyn Error>> {
        Ok(PinholeIntrinsics::new(
            self.value("width")?.parse()?,
            self.value("height")?.parse()?,
            self.value("fx")?.parse()?,
            self.value("fy")?.parse()?,
            self.value("cx")?.parse()?,
            self.value("cy")?.parse()?,
        )?)
    }
    pub(super) fn rectification(
        &self,
        source: PinholeIntrinsics,
    ) -> Result<Option<(RectificationSpec, u32)>, Box<dyn Error>> {
        if !self.values.contains_key("rectification") {
            return Ok(None);
        }
        let text = self.value("distortion_coefficients")?;
        let mut coefficients = [0.0; 5];
        let expected = match self.value("rectification")? {
            "pinhole" => 0,
            "brown" => 5,
            "fisheye" => 4,
            _ => return Err("unsupported rectification model".into()),
        };
        if expected == 0 {
            if text != "none" {
                return Err("pinhole requires distortion_coefficients=none".into());
            }
        } else {
            let mut count = 0;
            for field in text.split(',') {
                if count == expected {
                    return Err("wrong distortion coefficient count".into());
                }
                let value: f64 = field.trim().parse()?;
                if !value.is_finite() || value.abs() > 100.0 {
                    return Err("invalid distortion coefficient".into());
                }
                coefficients[count] = value;
                count += 1;
            }
            if count != expected {
                return Err("wrong distortion coefficient count".into());
            }
        }
        let distortion = match expected {
            0 => LensDistortion::Pinhole,
            5 => LensDistortion::BrownConrady {
                radial: [coefficients[0], coefficients[1], coefficients[2]],
                tangential: [coefficients[3], coefficients[4]],
            },
            _ => LensDistortion::Fisheye {
                coefficients: [
                    coefficients[0],
                    coefficients[1],
                    coefficients[2],
                    coefficients[3],
                ],
            },
        };
        let range = match self.value("luma_range")? {
            "full" => LumaRange::Full,
            "video" => LumaRange::Video,
            _ => return Err("luma_range must be full or video".into()),
        };
        let row_stride: u32 = self.value("row_stride")?.parse()?;
        if row_stride < source.dimensions()[0] || row_stride > 65_536 {
            return Err("invalid row stride".into());
        }
        let maximum_radius: f64 = self.value("maximum_radius")?.parse()?;
        if !maximum_radius.is_finite() || !(1e-6..=64.0).contains(&maximum_radius) {
            return Err("invalid lens radius".into());
        }
        let target = PinholeIntrinsics::new(
            self.value("target_width")?.parse()?,
            self.value("target_height")?.parse()?,
            self.value("target_fx")?.parse()?,
            self.value("target_fy")?.parse()?,
            self.value("target_cx")?.parse()?,
            self.value("target_cy")?.parse()?,
        )?;
        Ok(Some((
            RectificationSpec {
                source,
                target,
                distortion,
                maximum_radius,
                source_domain: super::hash(self.value("image_domain_sha256")?)?,
                calibration: super::hash(self.value("source_calibration_sha256")?)?,
                range,
            },
            row_stride,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type Test = Result<(), Box<dyn Error>>;
    fn base() -> String {
        KEYS.iter()
            .map(|key| {
                let value = match *key {
                    "width" | "height" => "96",
                    "fx" | "fy" => "80",
                    "cx" | "cy" => "48",
                    "work_units" => "1000000000",
                    "image_domain_sha256" => {
                        "0303030303030303030303030303030303030303030303030303030303030303"
                    }
                    _ => "fixture",
                };
                format!("{key}={value}\n")
            })
            .collect()
    }
    fn extra() -> String {
        format!(
            "rectification=brown\nsource_calibration_sha256={}\nrow_stride=96\nluma_range=full\nmaximum_radius=1\ntarget_width=96\ntarget_height=96\ntarget_fx=80\ntarget_fy=80\ntarget_cx=48\ntarget_cy=48\ndistortion_coefficients=0.04,0.002,0.0001,0.003,-0.002\n",
            "04".repeat(32)
        )
    }
    #[test]
    fn legacy_configuration_remains_pinhole_only() -> Test {
        let text = base();
        let config = Config::parse(&text)?;
        assert!(config.rectification(config.source_intrinsics()?)?.is_none());
        Ok(())
    }
    #[test]
    fn every_partial_lens_configuration_is_rejected() {
        let complete = base() + &extra();
        for key in RECTIFY_KEYS {
            let partial = complete
                .lines()
                .filter(|line| !line.starts_with(&format!("{key}=")))
                .map(|line| format!("{line}\n"))
                .collect::<String>();
            assert!(Config::parse(&partial).is_err());
        }
    }
    #[test]
    fn brown_order_and_target_camera_are_explicit() -> Test {
        let text = base() + &extra();
        let config = Config::parse(&text)?;
        let (spec, stride) = config
            .rectification(config.source_intrinsics()?)?
            .ok_or("missing rectification")?;
        assert_eq!(
            spec.distortion,
            LensDistortion::BrownConrady {
                radial: [0.04, 0.002, 0.0001],
                tangential: [0.003, -0.002]
            }
        );
        assert_eq!(stride, 96);
        assert_eq!(spec.target.dimensions(), [96, 96]);
        Ok(())
    }
    #[test]
    fn malformed_model_range_and_coefficients_never_fall_back() -> Test {
        let complete = base() + &extra();
        for (from, to) in [
            ("rectification=brown", "rectification=guess"),
            ("luma_range=full", "luma_range=auto"),
            ("row_stride=96", "row_stride=1"),
            ("maximum_radius=1", "maximum_radius=NaN"),
            ("0.04,0.002,0.0001,0.003,-0.002", "0.04,0.002,0.0001,0.003"),
            (
                "0.04,0.002,0.0001,0.003,-0.002",
                "0.04,0.002,0.0001,0.003,NaN",
            ),
            ("0.04,0.002,0.0001,0.003,-0.002", "0,0,0,0,0,0"),
        ] {
            let text = complete.replace(from, to);
            let config = Config::parse(&text)?;
            assert!(config.rectification(config.source_intrinsics()?).is_err());
        }
        assert!(Config::parse(&(base() + "unknown=1\n")).is_err());
        assert!(Config::parse(&(base() + "width=96\n")).is_err());
        Ok(())
    }
}
