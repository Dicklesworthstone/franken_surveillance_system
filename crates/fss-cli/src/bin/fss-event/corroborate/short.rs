#![forbid(unsafe_code)]
//! Shared short-corroboration inputs and presentation for immutable and publishing owners.

use fss_cli::event_fusion::EventFusionProfile;
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_twin::PropertyTwin;

use super::*;

pub(super) struct ShortInputs {
    pub(super) fusion_profile: Option<EventFusionProfile>,
    poses: [Option<CameraPose>; 2],
    pub(super) sources: [PoseSource; 2],
    pub(super) calibration: Option<ContentDigest>,
    pub(super) covariances: [Option<PoseCovariance>; 2],
    pub(super) calibration_record: Option<SiteCalibration>,
    package: Option<RgbDetectorPackage>,
    twin: Option<PropertyTwin>,
}

impl ShortInputs {
    pub(super) fn load(
        action: &CorroborateAction,
        deployment: &dyn RetainedSource,
        cx: &ReplayCx,
        scalar: &ScalarExecCx,
    ) -> RunResult<Self> {
        let fusion_profile = super::super::detector::load_fusion(action.cascade.as_ref(), cx)?;
        // The calibration is verified against its pinned digest before retained frames are decoded.
        let (poses, mut sources, calibration, covariances, calibration_record) =
            resolve_poses(action)?;
        // Retained adoptions decide currency (or refuse a superseded calibration) before any frame is
        // decoded and before anything is appended.
        if let Some(calibration) = calibration {
            apply_adoptions(action, deployment, calibration, &mut sources, cx)?;
        }
        let package = match &action.cascade {
            Some(options) => Some(super::super::detector::load(options, cx, scalar)?),
            None => None,
        };
        // The scene mesh is verified against both owner digests before retained frames are decoded.
        let twin = match &action.mesh {
            Some(option) => {
                let bytes = read_scene_mesh(&option.path)?;
                Some(
                    import_scene_mesh(&bytes, option.package, option.source_scene)
                        .map_err(CorroborationError::Visibility)?,
                )
            }
            None => None,
        };
        Ok(Self {
            fusion_profile,
            poses,
            sources,
            calibration,
            covariances,
            calibration_record,
            package,
            twin,
        })
    }

    pub(super) fn visibility(&self, action: &CorroborateAction) -> GroundVisibilityPlan<'_> {
        GroundVisibilityPlan {
            policy: action.policy,
            poses: self.poses,
            mesh: match (&self.twin, &action.mesh) {
                (Some(twin), Some(option)) => Some(SceneMesh {
                    mesh: twin.mesh(),
                    package_digest: option.package,
                }),
                _ => None,
            },
        }
    }

    pub(super) fn cascade<'a>(
        &'a self,
        action: &CorroborateAction,
        scalar: &'a ScalarExecCx,
    ) -> RunResult<Option<DetectorCascade<'a>>> {
        match (&action.cascade, &self.package) {
            (Some(options), Some(package)) => Ok(Some(DetectorCascade::new(
                package,
                options.config,
                PackageDetectLimits::default(),
                scalar,
            )?)),
            _ => Ok(None),
        }
    }

    pub(super) fn render(
        &self,
        action: &CorroborateAction,
        report: &CorroborationReport,
        proposal: &CorroborationReport,
        guard: Option<&calibration_coverage::CoverageGuard>,
        sequence: u64,
        fusion: Option<&EventFusionReport>,
    ) -> RunResult<String> {
        let records: Vec<_> = proposal.coverage().iter().collect();
        let coverage = match guard {
            Some(guard) => guard.coverage_json(&action.rerun),
            None => super::super::coverage::render(
                &records,
                proposal.coverage_status(),
                proposal.coverage_approval(),
                &action.rerun,
            ),
        };
        let alert_hint = format!(
            "fss-event alert --root {} --site {}",
            quote(&action.root.to_string_lossy()),
            quote(&action.site)
        );
        let json = report.to_json_with_coverage(
            sequence,
            Some(&action.rerun),
            Some(&alert_hint),
            Some(&coverage),
        );
        // Pose provenance joins the report only when some camera has a pose, so reports without
        // poses keep their exact bytes.
        let json = if self.poses.iter().any(Option::is_some) {
            let body = json
                .strip_suffix('}')
                .ok_or_else(|| io::Error::other("report is not one JSON object"))?;
            format!(
                "{body},\"pose_provenance\":{}}}",
                render_pose_provenance(action, &self.sources, self.calibration)
            )
        } else {
            json
        };
        let json = match guard {
            Some(guard) => {
                let body = json
                    .strip_suffix('}')
                    .ok_or_else(|| io::Error::other("report is not one JSON object"))?;
                format!(
                    "{body},\"calibration_uncertainty_guard\":{}}}",
                    guard.to_json()
                )
            }
            None => json,
        };
        super::super::detector::with_fusion(json, fusion)
    }
}
