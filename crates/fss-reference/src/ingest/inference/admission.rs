#![forbid(unsafe_code)]
//! Fail-closed package and license admission for retained scalar inference.
//!
//! RecordedModel remains the exact laboratory execution object. This module adds the stronger
//! surveillance path: the runtime object must be an explicitly retained provenance artifact of
//! one complete immutable model package, and the package manifest must pass an independently
//! selected surveillance license policy. Admission makes no quality, calibration, event,
//! absence, or effect claim.

use super::{ModelRunError, RecordedInference, RecordedModel};
use crate::ingest::recorded_decode::RecordedDecodeRequest;
use crate::{ExecBudget, ReferenceDeployment, ReplayCx, ScalarExecCx};
use fss_core::ContentDigest;
use fss_object::{
    ModelLicenseDecision, ModelLicensePolicy, ModelLicensePolicyError, ModelPackage,
    ModelPackageError, ModelPackageLimits, ModelUseProfile,
};

#[derive(Debug)]
pub enum ModelAdmissionError {
    Package(ModelPackageError),
    License(ModelLicensePolicyError),
    WrongUseProfile,
    RuntimeModelNotProvenanced,
    IdentityMismatch,
    Execution(ModelRunError),
}
impl std::fmt::Display for ModelAdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Package(_) => "model package admission refused",
            Self::License(_) => "model license admission refused",
            Self::WrongUseProfile => "model admission is not for surveillance monitoring",
            Self::RuntimeModelNotProvenanced => "runtime model is not retained package provenance",
            Self::IdentityMismatch => "model admission identity mismatch",
            Self::Execution(_) => "admitted model execution refused",
        })
    }
}
impl std::error::Error for ModelAdmissionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Package(error) => Some(error),
            Self::License(error) => Some(error),
            Self::Execution(error) => Some(error),
            _ => None,
        }
    }
}
impl From<ModelPackageError> for ModelAdmissionError {
    fn from(error: ModelPackageError) -> Self { Self::Package(error) }
}
impl From<ModelLicensePolicyError> for ModelAdmissionError {
    fn from(error: ModelLicensePolicyError) -> Self { Self::License(error) }
}
impl From<ModelRunError> for ModelAdmissionError {
    fn from(error: ModelRunError) -> Self { Self::Execution(error) }
}

/// Exact package/license proof for one executable recorded model.
#[derive(Clone, Debug)]
pub struct AdmittedRecordedModel {
    model: RecordedModel,
    manifest_digest: ContentDigest,
    package_digest: ContentDigest,
    license_decision: ModelLicenseDecision,
}
impl AdmittedRecordedModel {
    /// Verify a complete package under a verifier-selected surveillance policy.
    pub fn admit(
        model: RecordedModel,
        package: &ModelPackage,
        policy: &ModelLicensePolicy,
        limits: &ModelPackageLimits,
    ) -> Result<Self, ModelAdmissionError> {
        if policy.target_profile() != &ModelUseProfile::SurveillanceMonitoring {
            return Err(ModelAdmissionError::WrongUseProfile);
        }
        package.verify_contents()?;
        package.validate(limits)?;
        let manifest_digest = package.manifest.manifest_digest()
            .map_err(ModelPackageError::from)?;
        let decision = policy.check_manifest(&package.manifest)?;
        if decision.target_profile() != &ModelUseProfile::SurveillanceMonitoring
            || decision.manifest_digest() != Some(manifest_digest)
            || decision.model_id() != Some(package.manifest.model_id())
            || decision.generation() != Some(package.manifest.generation())
        {
            return Err(ModelAdmissionError::IdentityMismatch);
        }
        let model_digest = model.digest();
        if !package.manifest.license().artifact_digests().contains(&model_digest) {
            return Err(ModelAdmissionError::RuntimeModelNotProvenanced);
        }
        let artifact = package.artifacts.get(&model_digest)
            .ok_or(ModelAdmissionError::RuntimeModelNotProvenanced)?;
        if artifact.digest != model_digest
            || artifact.payload.as_slice() != model.encoded()
            || ContentDigest::sha256(&artifact.payload) != model_digest
        {
            return Err(ModelAdmissionError::IdentityMismatch);
        }
        let package_digest = ContentDigest::sha256(&package.to_archive_bytes()?);
        Ok(Self { model, manifest_digest, package_digest, license_decision: decision })
    }
    #[must_use]
    pub const fn model(&self) -> &RecordedModel { &self.model }
    #[must_use]
    pub const fn manifest_digest(&self) -> ContentDigest { self.manifest_digest }
    #[must_use]
    pub const fn package_digest(&self) -> ContentDigest { self.package_digest }
    #[must_use]
    pub const fn license_decision(&self) -> &ModelLicenseDecision { &self.license_decision }
}

/// Retained numeric result accompanied by the exact admission that authorized this path.
#[derive(Clone, Debug)]
pub struct AdmittedRecordedInference {
    run: RecordedInference,
    manifest_digest: ContentDigest,
    package_digest: ContentDigest,
    license_decision_digest: ContentDigest,
}
impl AdmittedRecordedInference {
    pub fn run_and_publish(
        deployment: &mut ReferenceDeployment,
        source: &RecordedDecodeRequest,
        admitted: &AdmittedRecordedModel,
        budget: ExecBudget,
        exec_cx: &ScalarExecCx,
        cx: &ReplayCx,
    ) -> Result<Self, ModelAdmissionError> {
        let run = RecordedInference::run_and_publish(
            deployment, source, admitted.model(), budget, exec_cx, cx,
        )?;
        Self::bind(run, admitted)
    }
    pub fn open(
        deployment: &ReferenceDeployment,
        identity: ContentDigest,
        source: &RecordedDecodeRequest,
        admitted: &AdmittedRecordedModel,
        cx: &ReplayCx,
    ) -> Result<Self, ModelAdmissionError> {
        let run = RecordedInference::open(deployment, identity, source, cx)?;
        Self::bind(run, admitted)
    }
    fn bind(
        run: RecordedInference,
        admitted: &AdmittedRecordedModel,
    ) -> Result<Self, ModelAdmissionError> {
        if run.model().digest() != admitted.model().digest()
            || run.model().encoded() != admitted.model().encoded()
        {
            return Err(ModelAdmissionError::IdentityMismatch);
        }
        Ok(Self {
            run,
            manifest_digest: admitted.manifest_digest(),
            package_digest: admitted.package_digest(),
            license_decision_digest: admitted.license_decision().decision_digest(),
        })
    }
    #[must_use]
    pub const fn run(&self) -> &RecordedInference { &self.run }
    #[must_use]
    pub const fn manifest_digest(&self) -> ContentDigest { self.manifest_digest }
    #[must_use]
    pub const fn package_digest(&self) -> ContentDigest { self.package_digest }
    #[must_use]
    pub const fn license_decision_digest(&self) -> ContentDigest { self.license_decision_digest }
    pub fn verify_by_replay(
        &self,
        deployment: &ReferenceDeployment,
        source: &RecordedDecodeRequest,
        budget: ExecBudget,
        exec_cx: &ScalarExecCx,
        cx: &ReplayCx,
    ) -> Result<(), ModelAdmissionError> {
        self.run.verify_by_replay(deployment, source, budget, exec_cx, cx)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_core::{CalibrationGeneration, Generation, ModelGeneration, SchemaId};
    use fss_model_ir::{
        AttributeMap, GraphNode, ModelIrGraph, ModelIrVersion, OpCode, TensorPort,
    };
    use fss_object::{ModelId, ModelLicenseRecord, ModelManifestV1, ModelPackageArtifact};
    use fss_tensor::{DType, Shape};
    use std::collections::BTreeMap;
    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn model(value: f32) -> TestResult<RecordedModel> {
        let shape = Shape::new(vec![1, 1, 2, 2])?;
        let graph = ModelIrGraph::new_validated(
            "model:admission-test", ModelIrVersion::V1, Generation(7),
            vec![
                TensorPort::new("image", DType::F32, shape.clone(), Generation(7))?,
                TensorPort::new("parameter", DType::F32, Shape::new(vec![1])?, Generation(7))?,
            ],
            vec![TensorPort::new("result", DType::F32, shape, Generation(7))?],
            vec![GraphNode::new(
                "node:0", OpCode::Add, "admission fixture",
                vec!["image".into(), "parameter".into()], vec!["result".into()],
                AttributeMap::new(),
            )?],
        )?;
        Ok(RecordedModel::publish(
            &graph, "image", true,
            BTreeMap::from([("parameter".to_owned(), vec![value])]),
        )?)
    }

    fn package(
        runtime: &RecordedModel,
        include_runtime: bool,
        license: &str,
        restrictions: Vec<String>,
    ) -> TestResult<ModelPackage> {
        let weights = b"independent original weights".to_vec();
        let weights_digest = ContentDigest::sha256(&weights);
        let license_text = format!("{license} exact legal text").into_bytes();
        let license_digest = ContentDigest::sha256(&license_text);
        let provenance = if include_runtime {
            runtime.encoded().to_vec()
        } else {
            b"different converted runtime".to_vec()
        };
        let provenance_digest = ContentDigest::sha256(&provenance);
        let record = ModelLicenseRecord::new(
            license, Some(license_digest), true, restrictions,
            "https://example.invalid/model-source", vec![provenance_digest],
            Some("immutable-revision-1".to_owned()),
        )?;
        let manifest = ModelManifestV1::new(
            ModelId::parse("MOD-ADMISSION-001")?,
            ModelGeneration::parse("model:admission:v1")?,
            weights_digest,
            SchemaId::parse("fss.model_input.v1")?,
            SchemaId::parse("fss.model_output.v1")?,
            CalibrationGeneration::parse("cal:admission:v1")?,
            record,
        )?;
        Ok(ModelPackage::new(
            manifest,
            vec![
                ModelPackageArtifact::new("weights.bin", weights)?,
                ModelPackageArtifact::new("LICENSE.txt", license_text)?,
                ModelPackageArtifact::new("runtime.fssmodel", provenance)?,
            ],
        )?)
    }

    fn surveillance_policy() -> ModelLicensePolicy {
        let mut policy =
            ModelLicensePolicy::default_for_profile(ModelUseProfile::SurveillanceMonitoring);
        policy.set_require_text_digest(true);
        policy
    }

    #[test]
    fn exact_runtime_and_surveillance_license_mint_admission() -> TestResult {
        let runtime = model(0.25)?;
        let package = package(&runtime, true, "Apache-2.0", vec![])?;
        let admitted = AdmittedRecordedModel::admit(
            runtime.clone(), &package, &surveillance_policy(), &ModelPackageLimits::default(),
        )?;
        assert_eq!(admitted.model().digest(), runtime.digest());
        assert_eq!(admitted.manifest_digest(), package.manifest.manifest_digest()?);
        assert_eq!(
            admitted.license_decision().target_profile(),
            &ModelUseProfile::SurveillanceMonitoring
        );
        assert_eq!(
            admitted.package_digest(),
            ContentDigest::sha256(&package.to_archive_bytes()?)
        );
        Ok(())
    }

    #[test]
    fn non_surveillance_policy_cannot_authorize_surveillance_path() -> TestResult {
        let runtime = model(0.25)?;
        let package = package(&runtime, true, "Apache-2.0", vec![])?;
        let policy = ModelLicensePolicy::default_for_profile(ModelUseProfile::InternalEvaluation);
        assert!(matches!(
            AdmittedRecordedModel::admit(
                runtime, &package, &policy, &ModelPackageLimits::default()
            ),
            Err(ModelAdmissionError::WrongUseProfile)
        ));
        Ok(())
    }

    #[test]
    fn approval_does_not_transfer_to_an_unprovenanced_runtime_conversion() -> TestResult {
        let approved = model(0.25)?;
        let package = package(&approved, true, "Apache-2.0", vec![])?;
        let other = model(0.5)?;
        assert!(matches!(
            AdmittedRecordedModel::admit(
                other, &package, &surveillance_policy(), &ModelPackageLimits::default()
            ),
            Err(ModelAdmissionError::RuntimeModelNotProvenanced)
        ));
        Ok(())
    }

    #[test]
    fn package_without_exact_runtime_provenance_is_refused() -> TestResult {
        let runtime = model(0.25)?;
        let package = package(&runtime, false, "Apache-2.0", vec![])?;
        assert!(matches!(
            AdmittedRecordedModel::admit(
                runtime, &package, &surveillance_policy(), &ModelPackageLimits::default()
            ),
            Err(ModelAdmissionError::RuntimeModelNotProvenanced)
        ));
        Ok(())
    }

    #[test]
    fn surveillance_forbidden_license_never_reaches_execution_admission() -> TestResult {
        let runtime = model(0.25)?;
        let package = package(
            &runtime, true, "OpenRAIL-M", vec!["no_surveillance".to_owned()],
        )?;
        assert!(matches!(
            AdmittedRecordedModel::admit(
                runtime, &package, &surveillance_policy(), &ModelPackageLimits::default()
            ),
            Err(ModelAdmissionError::License(_))
        ));
        Ok(())
    }

    #[test]
    fn package_byte_bounds_are_checked_before_admission() -> TestResult {
        let runtime = model(0.25)?;
        let package = package(&runtime, true, "Apache-2.0", vec![])?;
        let mut limits = ModelPackageLimits::default();
        limits.max_package_total_bytes = package.total_bytes()?.saturating_sub(1);
        assert!(matches!(
            AdmittedRecordedModel::admit(runtime, &package, &surveillance_policy(), &limits),
            Err(ModelAdmissionError::Package(_))
        ));
        Ok(())
    }
}
