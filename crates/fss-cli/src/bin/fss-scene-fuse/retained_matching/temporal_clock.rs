#![forbid(unsafe_code)]
//! Replay the original finite clock query and bind its full envelopes to retained exposures.
//!
//! Geometry equality and exact source-generation membership are checked independently of
//! conditional clock support. Unsupported candidates stay in every mapped capture hull.

use std::collections::BTreeSet;

use fss_cli::clock_alignment::{ClockValidationQuery, ClockValidationReplay};
use fss_cli::json_input::Value;
use fss_cli::json_output::{array, object, string};
use fss_cli::scene_rig::SceneRig;
use fss_core::{ClockBasis, ContentDigest, SensorCapsule, SensorId, StreamId};
use fss_geometry::{GeometryError, WorkBudget};

use super::images::PreparedImage;
use super::input::{self as shared, ResolvedFrame, View, digest, fields, get, text, unsigned};
use super::{Result, fail, input_error};

/// Exactly one source stream generation for each of the original query's two clocks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Binding {
    pub camera: u64,
    pub sensor: String,
    pub stream: String,
    pub basis: ClockBasis,
    pub clock: u64,
    pub calibration: u64,
    pub image_domain: u64,
    pub calibration_digest: ContentDigest,
}

/// A source capsule, not its position in a mutable list, names one original projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Projection {
    pub capsule: ContentDigest,
    pub projection: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Spec {
    pub path: String,
    pub digest: ContentDigest,
    pub bindings: [Binding; 2],
    pub projections: Vec<Projection>,
}

fn bounded_text(value: &Value) -> Result<&str> {
    let value = text(value)?;
    if value.is_empty()
        || value.len() > 4096
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(input_error(
            "clock replay path or identity is empty, unbounded or malformed",
        ));
    }
    Ok(value)
}
fn binding(value: &Value) -> Result<Binding> {
    let row = fields(
        value,
        &[
            "camera",
            "sensor_id",
            "stream_id",
            "clock_basis",
            "clock_generation",
            "calibration_generation",
            "image_generation",
            "calibration_digest",
        ],
    )?;
    let sensor = SensorId::parse(bounded_text(get(row, "sensor_id")?)?)
        .map_err(|_| input_error("clock binding sensor identity is invalid"))?;
    let stream = StreamId::parse(bounded_text(get(row, "stream_id")?)?)
        .map_err(|_| input_error("clock binding stream generation is invalid"))?;
    Ok(Binding {
        camera: unsigned(get(row, "camera")?, 1, u64::MAX)?,
        sensor: sensor.as_str().to_owned(),
        stream: stream.as_str().to_owned(),
        basis: ClockBasis::parse(text(get(row, "clock_basis")?)?)
            .map_err(|_| input_error("clock binding original basis is invalid"))?,
        clock: unsigned(get(row, "clock_generation")?, 1, u64::MAX)?,
        calibration: unsigned(get(row, "calibration_generation")?, 1, u64::MAX)?,
        image_domain: unsigned(get(row, "image_generation")?, 1, u64::MAX)?,
        calibration_digest: digest(get(row, "calibration_digest")?)?,
    })
}

impl Spec {
    pub(super) fn parse(
        value: &Value,
        views: &[View],
        common_clock: u64,
        clock_evidence: [u8; 32],
    ) -> Result<Self> {
        let row = fields(
            value,
            &["query_path", "query_digest", "bindings", "projections"],
        )?;
        let rows = get(row, "bindings")?
            .array()
            .filter(|v| v.len() == 2)
            .ok_or_else(|| {
                input_error("clock replay needs exactly reference and target source bindings")
            })?;
        let bindings = [binding(&rows[0])?, binding(&rows[1])?];
        if bindings[0].camera == bindings[1].camera
            || bindings[0].sensor == bindings[1].sensor
            || bindings[0].clock == bindings[1].clock
            || bindings[0].clock != common_clock
        {
            return Err(input_error(
                "clock replay bindings need distinct sensors/clocks and the declared reference clock",
            ));
        }
        let pin = digest(get(row, "query_digest")?)?;
        if pin.bytes() != clock_evidence {
            return Err(input_error(
                "common clock evidence must pin the original clock validation query",
            ));
        }
        let rows = get(row, "projections")?
            .array()
            .filter(|v| !v.is_empty() && v.len() <= 16)
            .ok_or_else(|| {
                input_error("clock replay needs a complete bounded target-exposure inventory")
            })?;
        let mut projections = Vec::new();
        let mut capsules = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for row in rows {
            let row = fields(row, &["capsule_digest", "projection_id"])?;
            let projection = Projection {
                capsule: digest(get(row, "capsule_digest")?)?,
                projection: unsigned(get(row, "projection_id")?, 1, u64::MAX)?,
            };
            if !capsules.insert(projection.capsule) || !ids.insert(projection.projection) {
                return Err(input_error(
                    "clock replay repeats a source capsule or projection identity",
                ));
            }
            projections.push(projection);
        }
        projections.sort_by_key(|p| p.capsule);
        let spec = Self {
            path: bounded_text(get(row, "query_path")?)?.to_owned(),
            digest: pin,
            bindings,
            projections,
        };
        spec.validate_views(views)?;
        Ok(spec)
    }

    fn validate_views(&self, views: &[View]) -> Result<()> {
        let mut targets = BTreeSet::new();
        let mut cameras = BTreeSet::new();
        for view in views {
            let binding = self
                .bindings
                .iter()
                .find(|b| b.camera == view.camera)
                .ok_or_else(|| input_error("retained view leaves the frozen clock camera pair"))?;
            if view.source.pins().sensor_id != binding.sensor
                || view.alignment.stream_id != binding.stream
                || view.alignment.clock_basis != binding.basis
                || view.alignment.offset_ns != [0, 0]
                || view.alignment.basis != self.digest
            {
                return Err(input_error(
                    "clock replay source binding differs or adds an unsupported offset",
                ));
            }
            cameras.insert(view.camera);
            if view.camera == self.bindings[1].camera {
                targets.insert(view.source.pins().capsule_digest);
            }
        }
        if cameras.len() != 2 || targets != self.projections.iter().map(|p| p.capsule).collect() {
            return Err(input_error(
                "clock replay projection membership must equal the complete selected target exposures",
            ));
        }
        Ok(())
    }

    /// No source I/O or custody assertion occurs here. All geometry and image plans are actual
    /// parsed native values; their equality is checked before any selected source is decoded.
    pub(super) fn replay(
        &self,
        bytes: &[u8],
        views: &[View],
        rig: &SceneRig,
        images: &[PreparedImage],
        work: &mut WorkBudget<'_>,
    ) -> Result<Ready> {
        self.validate_views(views)?;
        let query =
            ClockValidationQuery::parse_pinned(bytes, self.digest, work).map_err(clock_error)?;
        let pair = query.pair();
        if query.world_basis() != rig.twin_digest()
            || pair.reference_camera != self.bindings[0].camera
            || pair.target_camera != self.bindings[1].camera
            || pair.reference_clock != self.bindings[0].clock
            || pair.target_clock != self.bindings[1].clock
            || views.len() != images.len()
        {
            return Err(input_error(
                "original clock query leaves the exact world, camera or clock-generation scope",
            ));
        }
        for (view, image) in views.iter().zip(images) {
            charge(work, 256)?;
            let frozen = query
                .cameras()
                .iter()
                .find(|c| c.id == view.camera)
                .ok_or_else(|| input_error("clock query camera is unavailable"))?;
            let binding = self
                .bindings
                .iter()
                .find(|b| b.camera == view.camera)
                .ok_or_else(|| input_error("clock source binding is unavailable"))?;
            let actual = rig
                .camera(view.camera)
                .ok_or_else(|| input_error("clock rig camera is unavailable"))?;
            if actual.camera.pose != frozen.pose
                || actual.camera.intrinsics != frozen.intrinsics
                || actual.camera.calibration != binding.calibration
                || actual.camera.image_domain != binding.image_domain
                || actual.camera.clock != pair.reference_clock
                || frozen.calibration != binding.calibration_digest
                || image.domain != frozen.image_domain
            {
                return Err(input_error(
                    "clock replay camera pose, intrinsics, calibration, image or rig-clock generation differs",
                ));
            }
        }
        for selected in &self.projections {
            if !query
                .projections()
                .iter()
                .any(|p| p.id == selected.projection)
            {
                return Err(input_error(
                    "selected target exposure has no exact original projection request",
                ));
            }
        }
        let replay = query.evaluate(work).map_err(clock_error)?;
        charge(work, 0)?;
        Ok(Ready {
            rig_digest: rig.digest(),
            spec: self.clone(),
            replay,
            original_query: std::str::from_utf8(bytes)
                .map_err(|_| input_error("original clock query is not UTF-8"))?
                .to_owned(),
        })
    }
}

/// Private binding over an actual native replay; no JSON report can construct this result.
pub(super) struct Ready {
    rig_digest: ContentDigest,
    spec: Spec,
    replay: ClockValidationReplay,
    original_query: String,
}
impl Ready {
    pub(super) fn matches(&self, spec: &Spec, rig: &SceneRig, views: &[View]) -> bool {
        &self.spec == spec
            && self.rig_digest == rig.digest()
            && self.spec.validate_views(views).is_ok()
    }

    pub(super) fn validate_bound(
        &self,
        view: &fss_twin::feature_association::FeatureView,
    ) -> Result<()> {
        let frozen = self
            .replay
            .query()
            .cameras()
            .iter()
            .find(|camera| camera.id == view.camera.camera)
            .ok_or_else(|| input_error("bound feature camera leaves the replay scope"))?;
        if view.camera.pose != frozen.pose
            || view.camera.intrinsics != frozen.intrinsics
            || view.image_domain_digest != frozen.image_domain.bytes()
            || view.clock_evidence != self.spec.digest.bytes()
        {
            return Err(input_error(
                "bound feature geometry or image domain differs from original clock observations",
            ));
        }
        Ok(())
    }

    /// Preserve the exact retained interval and all candidate mappings, including candidates
    /// unsupported in every session. The source capsule is independently reopened by the owner.
    pub(super) fn capture(&self, view: &View, capsule: &SensorCapsule) -> Result<[u64; 2]> {
        shared::validate_capsule_identity(view, capsule)?;
        let binding = self
            .spec
            .bindings
            .iter()
            .find(|b| b.camera == view.camera)
            .ok_or_else(|| input_error("source camera leaves the original clock scope"))?;
        if capsule.sensor_id.as_str() != binding.sensor
            || capsule.stream_id.as_str() != binding.stream
            || capsule.clock_basis != binding.basis
            || view.alignment.offset_ns != [0, 0]
            || view.alignment.basis != self.spec.digest
        {
            return Err(input_error(
                "source sensor, stream generation, clock basis or mapping changed",
            ));
        }
        let original = [capsule.capture.earliest.0, capsule.capture.latest.0];
        if original[0] > original[1] {
            return Err(input_error(
                "original retained capture interval is reversed",
            ));
        }
        let mapped = if view.camera == self.spec.bindings[0].camera {
            original
        } else {
            let id = self
                .spec
                .projections
                .iter()
                .find(|p| p.capsule == view.source.pins().capsule_digest)
                .ok_or_else(|| input_error("source has no frozen projection binding"))?
                .projection;
            let projection = self
                .replay
                .report()
                .projections
                .iter()
                .find(|p| p.request.id == id)
                .ok_or_else(|| input_error("native replay omitted a selected projection"))?;
            if projection.request.target_interval_ns != original {
                return Err(input_error(
                    "original retained capture differs from the complete clock projection interval",
                ));
            }
            projection.reference_envelope_ns
        };
        Ok([
            u64::try_from(mapped[0])
                .map_err(|_| input_error("projected capture is outside the scene clock range"))?,
            u64::try_from(mapped[1])
                .map_err(|_| input_error("projected capture is outside the scene clock range"))?,
        ])
    }

    pub(super) fn render(
        &self,
        views: &[View],
        resolved: &[ResolvedFrame<'_>],
        work: &mut WorkBudget<'_>,
    ) -> Result<String> {
        if views.len() != resolved.len() {
            return Err(input_error("clock report source inventory differs"));
        }
        let native = self.replay.render(work).map_err(clock_error)?;
        charge(
            work,
            (native.len() + self.original_query.len()) as u64 * 8 + 4096,
        )?;
        let mut rows = Vec::new();
        for (view, source) in views.iter().zip(resolved) {
            charge(work, 256)?;
            let capture = self.capture(view, source.capsule)?;
            let id = self
                .spec
                .projections
                .iter()
                .find(|p| p.capsule == view.source.pins().capsule_digest)
                .map(|p| p.projection);
            rows.push(object(&[
                ("camera", string(&view.camera.to_string())),
                (
                    "capsule_digest",
                    string(&view.source.pins().capsule_digest.to_text()),
                ),
                ("sensor_id", string(source.capsule.sensor_id.as_str())),
                ("stream_id", string(source.capsule.stream_id.as_str())),
                (
                    "original_clock_basis",
                    string(source.capsule.clock_basis.as_str()),
                ),
                (
                    "original_capture_ns",
                    array(
                        &[
                            source.capsule.capture.earliest.0,
                            source.capsule.capture.latest.0,
                        ]
                        .map(|v| string(&v.to_string())),
                    ),
                ),
                (
                    "common_capture_ns",
                    array(&capture.map(|v| string(&v.to_string()))),
                ),
                (
                    "projection_id",
                    id.map_or_else(|| "null".into(), |v| string(&v.to_string())),
                ),
                (
                    "mapping",
                    string(if id.is_some() {
                        "complete_native_hypothesis_hull"
                    } else {
                        "reference_clock_identity"
                    }),
                ),
            ]));
        }
        Ok(object(&[
            (
                "authority",
                string("replayed_declared_clock_hypotheses_no_activation"),
            ),
            ("query_digest", string(&self.spec.digest.to_text())),
            ("original_query_json", string(&self.original_query)),
            ("native_replay", native),
            ("mapped_exposures", array(&rows)),
            ("clock_synchronization_established", "false".into()),
            ("clock_query_source_custody_verified", "false".into()),
            ("source_clock_basis_upgraded", "false".into()),
        ]))
    }
}

fn charge(work: &mut WorkBudget<'_>, units: u64) -> Result<()> {
    work.charge(units).map_err(|error| match error {
        GeometryError::Cancelled => {
            fail("ERR-SCENE-FUSION-CANCELLED-001", "clock replay cancelled")
        }
        _ => fail(
            "ERR-SCENE-FUSION-LIMIT-001",
            "clock replay exhausted shared work or allocation",
        ),
    })
}
fn clock_error(error: fss_cli::clock_alignment::Failure) -> super::super::Failure {
    let code = match error.code {
        "ERR-CLOCK-ALIGNMENT-CANCELLED-001" => "ERR-SCENE-FUSION-CANCELLED-001",
        "ERR-CLOCK-ALIGNMENT-LIMIT-001" => "ERR-SCENE-FUSION-LIMIT-001",
        _ => "ERR-SCENE-FUSION-INPUT-001",
    };
    fail(code, error.detail)
}

#[cfg(test)]
#[path = "temporal_clock_fixtures.rs"]
pub(super) mod fixtures;
