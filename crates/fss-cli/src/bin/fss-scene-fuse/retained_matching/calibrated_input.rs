#![forbid(unsafe_code)]
//! Strict declarations for a scene rig resolved from retained calibration authority.
//!
//! This parser performs no file reads and authenticates no calibration or adoption. The
//! owner must open every declared file under its byte allowance, resolve the exact current
//! adoption, and bind each selected source to that sealed result. Camera geometry can only
//! come from the verified calibration; this format has no pose or intrinsics override.

use std::collections::BTreeSet;

use fss_cli::json_input::{self, Value};
use fss_core::{ContentDigest, SensorId};
use fss_twin::localization::native::ExtractionOptions;

use super::images::ImageDeclaration;
use super::input::{self as shared, View, digest, fields, get, text, unsigned};
use super::{Result, input_error, multiview, temporal_input};

pub(super) const SCHEMA: &str = "fss.scene_camera_rig_adopted.v1";
pub(super) const RECTIFIED_SCHEMA: &str = "fss.scene_camera_rig_adopted.v2";
const MAX_CAMERAS: usize = 16;
const MAX_PATH_BYTES: usize = 4096;

/// An exact original camera observation file or frame metadata file, never a replacement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PinnedFile {
    pub path: String,
    pub digest: ContentDigest,
}

/// Both identities are explicit: FSSCAL's domain-separated identity and the whole-file SHA.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CalibrationFile {
    pub path: String,
    pub digest: ContentDigest,
    pub file_digest: ContentDigest,
}

/// Owner-declared local names and validity; none replaces measured calibration geometry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AdoptedCamera {
    pub camera: u64,
    pub sensor_id: SensorId,
    pub adoption_digest: ContentDigest,
    pub original_input: PinnedFile,
    pub source_object_id: String,
    pub image_domain: u64,
    pub clock: u64,
    pub privacy_domain: u64,
    pub validity: [u64; 2],
}

/// Parsed declarations only. The owner verifies the exact twin and current adoption later.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AdoptedRig {
    /// Explicit v2 opt-in to calibrated native radial rectification.
    pub rectification: bool,
    pub source_scene_digest: ContentDigest,
    pub twin_digest: ContentDigest,
    pub geometry_basis: (u64, u64),
    pub evaluation_scope: String,
    pub calibration: CalibrationFile,
    /// Ascending unique camera handles, independent of declaration order.
    pub cameras: Vec<AdoptedCamera>,
}

fn bounded_text(value: &Value, maximum: usize) -> Result<&str> {
    let value = text(value)?;
    if value.len() > maximum
        || value.is_empty()
        || value.trim().is_empty()
        || value.chars().any(char::is_control)
    {
        return Err(input_error(
            "adopted rig text is empty, unbounded or contains a control",
        ));
    }
    Ok(value)
}

fn pinned_file(value: &Value) -> Result<PinnedFile> {
    let row = fields(value, &["path", "digest"])?;
    Ok(PinnedFile {
        path: bounded_text(get(row, "path")?, MAX_PATH_BYTES)?.to_owned(),
        digest: digest(get(row, "digest")?)?,
    })
}

fn camera(value: &Value) -> Result<AdoptedCamera> {
    let row = fields(
        value,
        &[
            "camera",
            "sensor_id",
            "adoption_digest",
            "original_input",
            "source_object_id",
            "image_domain",
            "clock",
            "privacy_domain",
            "validity_ns",
        ],
    )?;
    let validity = get(row, "validity_ns")?
        .array()
        .filter(|values| values.len() == 2)
        .ok_or_else(|| input_error("adopted rig validity requires two inclusive clock bounds"))?;
    let validity = [
        unsigned(&validity[0], 0, u64::MAX)?,
        unsigned(&validity[1], 0, u64::MAX)?,
    ];
    if validity[0] > validity[1] {
        return Err(input_error("adopted rig validity bounds are reversed"));
    }
    let sensor_id = SensorId::parse(bounded_text(get(row, "sensor_id")?, 256)?)
        .map_err(|_| input_error("adopted rig sensor identity is malformed"))?;
    Ok(AdoptedCamera {
        camera: unsigned(get(row, "camera")?, 1, u64::MAX)?,
        sensor_id,
        adoption_digest: digest(get(row, "adoption_digest")?)?,
        original_input: pinned_file(get(row, "original_input")?)?,
        source_object_id: bounded_text(get(row, "source_object_id")?, 256)?.to_owned(),
        image_domain: unsigned(get(row, "image_domain")?, 1, u64::MAX)?,
        clock: unsigned(get(row, "clock")?, 1, u64::MAX)?,
        privacy_domain: unsigned(get(row, "privacy_domain")?, 1, u64::MAX)?,
        validity,
    })
}

pub(super) fn parse_rig(bytes: &[u8]) -> Result<AdoptedRig> {
    let document = json_input::parse(
        std::str::from_utf8(bytes).map_err(|_| input_error("adopted rig must be UTF-8"))?,
    )
    .map_err(|_| input_error("malformed or unbounded adopted rig JSON"))?;
    let top = fields(
        &document,
        &[
            "schema",
            "source_scene_digest",
            "twin_digest",
            "geometry_basis",
            "coordinate_frame",
            "evaluation_scope",
            "calibration",
            "cameras",
        ],
    )?;
    let rectification = match text(get(top, "schema")?)? {
        SCHEMA => false,
        RECTIFIED_SCHEMA => true,
        _ => return Err(input_error("unsupported adopted rig image profile")),
    };
    if text(get(top, "coordinate_frame")?)? != "RH_Z_UP" {
        return Err(input_error(
            "adopted rig schema or world convention differs",
        ));
    }
    let basis = fields(get(top, "geometry_basis")?, &["property", "revision"])?;
    let calibration = fields(get(top, "calibration")?, &["path", "digest", "file_digest"])?;
    let calibration = CalibrationFile {
        path: bounded_text(get(calibration, "path")?, MAX_PATH_BYTES)?.to_owned(),
        digest: digest(get(calibration, "digest")?)?,
        file_digest: digest(get(calibration, "file_digest")?)?,
    };
    let rows = get(top, "cameras")?
        .array()
        .filter(|rows| (1..=MAX_CAMERAS).contains(&rows.len()))
        .ok_or_else(|| input_error("adopted rig requires one through sixteen cameras"))?;
    let mut cameras = Vec::with_capacity(rows.len());
    let mut handles = BTreeSet::new();
    let mut sensors = BTreeSet::new();
    let mut objects = BTreeSet::new();
    for row in rows {
        let camera = camera(row)?;
        if !handles.insert(camera.camera)
            || !sensors.insert(camera.sensor_id.clone())
            || !objects.insert(camera.source_object_id.clone())
        {
            return Err(input_error(
                "adopted rig reuses a camera, sensor or scene object",
            ));
        }
        cameras.push(camera);
    }
    cameras.sort_by_key(|camera| camera.camera);
    Ok(AdoptedRig {
        rectification,
        source_scene_digest: digest(get(top, "source_scene_digest")?)?,
        twin_digest: digest(get(top, "twin_digest")?)?,
        geometry_basis: (
            unsigned(get(basis, "property")?, 1, u64::MAX)?,
            unsigned(get(basis, "revision")?, 1, u64::MAX)?,
        ),
        evaluation_scope: bounded_text(get(top, "evaluation_scope")?, 2048)?.to_owned(),
        calibration,
        cameras,
    })
}

/// Existing exact query schemas and their established native binding/geometry policies.
pub(super) enum MatchingQuery {
    Pair(shared::Query),
    Multi(multiview::input::Query),
    Temporal(temporal_input::Query),
}

impl MatchingQuery {
    /// Preserve the original pinhole-only query profile and its early refusal.
    pub(super) fn parse(bytes: &[u8], rig_file_digest: ContentDigest) -> Result<Self> {
        Self::parse_profile(bytes, rig_file_digest, false)
    }

    /// V2 admits explicit lens declarations; the sealed owner must authenticate every model.
    pub(super) fn parse_for_rectification(
        bytes: &[u8],
        rig_file_digest: ContentDigest,
    ) -> Result<Self> {
        Self::parse_profile(bytes, rig_file_digest, true)
    }

    pub(super) fn for_rig(
        bytes: &[u8],
        rig_file_digest: ContentDigest,
        rig: &AdoptedRig,
    ) -> Result<Self> {
        if rig.rectification {
            Self::parse_for_rectification(bytes, rig_file_digest)
        } else {
            Self::parse(bytes, rig_file_digest)
        }
    }

    fn parse_profile(
        bytes: &[u8],
        rig_file_digest: ContentDigest,
        rectification: bool,
    ) -> Result<Self> {
        let schema = {
            let document = json_input::parse(
                std::str::from_utf8(bytes)
                    .map_err(|_| input_error("calibrated matching query must be UTF-8"))?,
            )
            .map_err(|_| input_error("malformed or unbounded calibrated matching query"))?;
            let top = document
                .object()
                .ok_or_else(|| input_error("expected a calibrated matching query object"))?;
            match text(get(top, "schema")?)? {
                shared::SCHEMA | shared::SCHEMA_V2 => 0,
                multiview::input::SCHEMA | multiview::input::SCHEMA_V2 => 1,
                temporal_input::SCHEMA => 2,
                _ => {
                    return Err(input_error(
                        "unsupported exact calibrated matching query schema",
                    ));
                }
            }
        };
        let query = match schema {
            0 => Self::Pair(shared::parse(bytes, rig_file_digest)?),
            1 => Self::Multi(multiview::input::parse(bytes, rig_file_digest)?),
            _ => Self::Temporal(temporal_input::parse(bytes, rig_file_digest)?),
        };
        if !rectification
            && query
                .views()
                .iter()
                .any(|view| !matches!(view.image, ImageDeclaration::Pinhole(_)))
        {
            return Err(input_error(
                "adopted calibration matching requires its original direct pinhole image domain",
            ));
        }
        Ok(query)
    }

    pub(super) fn views(&self) -> &[View] {
        match self {
            Self::Pair(query) => &query.views,
            Self::Multi(query) => &query.views,
            Self::Temporal(query) => &query.views,
        }
    }

    pub(super) fn extraction(&self) -> ExtractionOptions {
        match self {
            Self::Pair(query) => query.extraction,
            Self::Multi(query) => query.extraction,
            Self::Temporal(query) => query.extraction,
        }
    }

    pub(super) fn declarations(&self) -> &str {
        match self {
            Self::Pair(query) => &query.declarations,
            Self::Multi(query) => &query.declarations,
            Self::Temporal(query) => &query.declarations,
        }
    }

    pub(super) const fn kind(&self) -> &'static str {
        match self {
            Self::Pair(_) => "static_pair",
            Self::Multi(_) => "static_multiview",
            Self::Temporal(_) => "temporal",
        }
    }
}

#[cfg(test)]
#[path = "calibrated_input_tests.rs"]
mod tests;
