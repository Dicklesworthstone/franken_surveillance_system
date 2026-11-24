#![forbid(unsafe_code)]
//! Resident digest-pinned ML model pool (`ResidentModelPool`) with zero-reload guarantees.
//!
//! Each verified `.fmpk` model package (either `models/fss-activity/fss_activity_v1.fmpk` or an
//! offline RGB detector package such as `models/yolox-nano/yolox_nano.fmpk`) is verified and
//! prepared ONCE into an immutable `Arc<VerifiedResidentModel>` keyed by
//! `(model_id, package_digest, model_generation, execution_profile_digest)`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use fss_core::{CanonicalEncoder, CaptureInterval, ContentDigest, DigestAlgorithm, SensorId};
use fss_object::ModelLicensePolicy;
use fss_tensor::{Shape, Tensor};

use super::ModelPoolError;
use super::exec::{run_activity_inference, run_rgb_detector_inference};
use super::receipt::RESIDENT_MODEL_DOMAIN;
use crate::executor_activity::{ACTIVITY_MODEL_DOMAIN, ActivityThresholdPolicy};
use crate::executor_activity_package::{
    ACTIVITY_MODEL_GENERATION, ACTIVITY_MODEL_ID, ACTIVITY_PACKAGE_V1, ACTIVITY_PACKAGE_V1_SHA256,
    ACTIVITY_TENSOR_GENERATION, ACTIVITY_WEIGHTS_INPUT, VerifiedActivityPackage,
    activity_license_policy,
};
use crate::ingest::inference::executor_profile_digest;
use crate::ingest::rgb_detections::RgbDetectionContract;
use crate::ingest::rgb_inference::RgbRunLimits;
use crate::ingest::rgb_package::RgbDetectorPackage;
use crate::{ExecBudget, KernelBackend, OptimizedGraph, ReplayCx, ScalarExecCx};

pub use super::exec::ModelInferenceOutput;

/// Hard ceiling on simultaneously resident verified models in one pool.
pub const MAX_RESIDENT_MODELS: usize = 32;
/// Default resident memory ceiling for loaded model weights and packed panels (256 MiB).
pub const DEFAULT_MAX_RESIDENT_BYTES: usize = 256 * 1024 * 1024;

/// Atomic load, cache-hit, and inference counters proving zero weight reloads across streams.
#[derive(Debug, Default)]
pub struct ModelLoadMetrics {
    /// Number of cold package verifications and weight loads performed.
    pub loads: AtomicU64,
    /// Number of resident cache hits resolved without reloading weights.
    pub cache_hits: AtomicU64,
    /// Number of completed ML inference executions through this pool.
    pub frames_inferred: AtomicU64,
}

impl ModelLoadMetrics {
    /// Captures a point-in-time snapshot of all atomic counters.
    #[must_use]
    pub fn snapshot(&self) -> ModelLoadMetricsSnapshot {
        ModelLoadMetricsSnapshot {
            loads: self.loads.load(Ordering::Acquire),
            cache_hits: self.cache_hits.load(Ordering::Acquire),
            frames_inferred: self.frames_inferred.load(Ordering::Acquire),
        }
    }
}

/// Immutable point-in-time snapshot of [`ModelLoadMetrics`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelLoadMetricsSnapshot {
    /// Cumulative cold weight loads performed by the pool.
    pub loads: u64,
    /// Cumulative resident cache hits returned without reloading weights.
    pub cache_hits: u64,
    /// Cumulative ML frame inferences completed.
    pub frames_inferred: u64,
}

/// Exact immutable cache key pinning a resident model to its package, generation, and backend.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ResidentModelKey {
    /// Stable model identifier from the package manifest.
    pub model_id: String,
    /// Whole-archive SHA-256 digest of the verified `.fmpk` package.
    pub package_digest: ContentDigest,
    /// Immutable model generation string.
    pub model_generation: String,
    /// Digest binding the pure-Rust executor profile and selected [`KernelBackend`].
    pub execution_profile_digest: ContentDigest,
}

/// Computes the canonical execution-profile digest for one pure-Rust [`KernelBackend`].
#[must_use]
pub fn pool_execution_profile_digest(backend: KernelBackend) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(RESIDENT_MODEL_DOMAIN);
    e.text("execution_profile");
    e.digest(executor_profile_digest());
    e.text(backend.stable_id());
    e.digest(backend.generation());
    ContentDigest::sha256(&e.finish())
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum ResidentModelArtifact {
    Activity {
        package: VerifiedActivityPackage,
        prepared: Option<OptimizedGraph>,
        weights: Tensor,
        backend: KernelBackend,
        model_digest: ContentDigest,
        threshold_policy: ActivityThresholdPolicy,
    },
    RgbDetector {
        package: RgbDetectorPackage,
        contract_override: Option<RgbDetectionContract>,
    },
}

/// An immutable, verified `.fmpk` model pinned in memory and safely shared across worker threads.
#[derive(Debug)]
pub struct VerifiedResidentModel {
    key: ResidentModelKey,
    manifest_digest: ContentDigest,
    resident_digest: ContentDigest,
    resident_bytes: usize,
    artifact: ResidentModelArtifact,
}

impl VerifiedResidentModel {
    /// Exact cache key pinning `(model_id, package_digest, model_generation, execution_profile)`.
    #[must_use]
    pub const fn key(&self) -> &ResidentModelKey {
        &self.key
    }

    /// Canonical manifest digest of the underlying `.fmpk` archive.
    #[must_use]
    pub const fn manifest_digest(&self) -> ContentDigest {
        self.manifest_digest
    }

    /// Canonical domain-separated digest of this resident model ([`RESIDENT_MODEL_DOMAIN`]).
    #[must_use]
    pub const fn resident_digest(&self) -> ContentDigest {
        self.resident_digest
    }

    /// Pure-Rust kernel backend executing this resident model.
    #[must_use]
    pub fn backend(&self) -> KernelBackend {
        match &self.artifact {
            ResidentModelArtifact::Activity { backend, .. } => *backend,
            ResidentModelArtifact::RgbDetector { package, .. } => package.model().backend(),
        }
    }

    /// Underlying model identity digest (graph, weights, preprocessing, and backend binding).
    #[must_use]
    pub fn model_digest(&self) -> ContentDigest {
        match &self.artifact {
            ResidentModelArtifact::Activity { model_digest, .. } => *model_digest,
            ResidentModelArtifact::RgbDetector { package, .. } => package.model().digest(),
        }
    }

    /// Approximate resident memory footprint in bytes (weights + packed panels).
    #[must_use]
    pub const fn resident_bytes(&self) -> usize {
        self.resident_bytes
    }

    /// Returns `true` if this resident model is an activity package (`fss_activity_v1.fmpk`).
    #[must_use]
    pub const fn is_activity(&self) -> bool {
        matches!(self.artifact, ResidentModelArtifact::Activity { .. })
    }

    /// Returns `true` if this resident model is an RGB object detector package.
    #[must_use]
    pub const fn is_rgb_detector(&self) -> bool {
        matches!(self.artifact, ResidentModelArtifact::RgbDetector { .. })
    }

    /// Runs the verified `fss_activity_v1.fmpk` Model IR graph against an evaluated frame and
    /// stream baseline reference frame.
    #[allow(clippy::too_many_arguments)]
    pub fn infer_activity(
        &self,
        frame_pixels: &[u8],
        frame_channels: usize,
        reference_pixels: &[u8],
        reference_channels: usize,
        dimensions: [u32; 2],
        budget: ExecBudget,
        cx: &ScalarExecCx,
    ) -> Result<ModelInferenceOutput, ModelPoolError> {
        let ResidentModelArtifact::Activity {
            package,
            prepared,
            weights,
            threshold_policy,
            ..
        } = &self.artifact
        else {
            return Err(ModelPoolError::InvalidInput(
                "resident model is not an activity package",
            ));
        };
        run_activity_inference(
            self.resident_digest,
            package,
            prepared.as_ref(),
            weights,
            threshold_policy,
            frame_pixels,
            frame_channels,
            reference_pixels,
            reference_channels,
            dimensions,
            budget,
            cx,
        )
    }

    /// Runs a verified [`RgbDetectorPackage`] on packed RGB pixels and projects dense detections.
    #[allow(clippy::too_many_arguments)]
    pub fn infer_rgb_detector(
        &self,
        rgb_pixels: &[u8],
        dimensions: [u32; 2],
        source_digest: ContentDigest,
        sensor_id: &SensorId,
        capture: CaptureInterval,
        limits: RgbRunLimits,
        detection_work_units: u64,
        cx: &ScalarExecCx,
    ) -> Result<ModelInferenceOutput, ModelPoolError> {
        let ResidentModelArtifact::RgbDetector {
            package,
            contract_override,
        } = &self.artifact
        else {
            return Err(ModelPoolError::InvalidInput(
                "resident model is not an RGB detector package",
            ));
        };
        run_rgb_detector_inference(
            package,
            contract_override.as_ref(),
            rgb_pixels,
            dimensions,
            source_digest,
            sensor_id,
            capture,
            limits,
            detection_work_units,
            cx,
        )
    }
}

/// Thread-safe resident model pool pinning verified `.fmpk` packages into immutable memory.
#[derive(Debug)]
pub struct ResidentModelPool {
    models: RwLock<BTreeMap<ResidentModelKey, Arc<VerifiedResidentModel>>>,
    metrics: ModelLoadMetrics,
    max_models: usize,
    max_resident_bytes: usize,
    current_resident_bytes: AtomicUsize,
}

impl Default for ResidentModelPool {
    fn default() -> Self {
        Self::default_bounded()
    }
}

impl ResidentModelPool {
    /// Creates a bounded resident pool with explicit model-count and resident-byte ceilings.
    pub fn new(max_models: usize, max_resident_bytes: usize) -> Result<Self, ModelPoolError> {
        if max_models == 0 || max_models > MAX_RESIDENT_MODELS || max_resident_bytes == 0 {
            return Err(ModelPoolError::InvalidConfig(
                "max_models must be in 1..=32 and max_resident_bytes positive",
            ));
        }
        Ok(Self {
            models: RwLock::new(BTreeMap::new()),
            metrics: ModelLoadMetrics::default(),
            max_models,
            max_resident_bytes,
            current_resident_bytes: AtomicUsize::new(0),
        })
    }

    /// Creates a pool with [`MAX_RESIDENT_MODELS`] and [`DEFAULT_MAX_RESIDENT_BYTES`].
    #[must_use]
    pub fn default_bounded() -> Self {
        Self {
            models: RwLock::new(BTreeMap::new()),
            metrics: ModelLoadMetrics::default(),
            max_models: MAX_RESIDENT_MODELS,
            max_resident_bytes: DEFAULT_MAX_RESIDENT_BYTES,
            current_resident_bytes: AtomicUsize::new(0),
        }
    }

    /// Returns a reference to the atomic load/hit/inference metrics.
    #[must_use]
    pub const fn metrics(&self) -> &ModelLoadMetrics {
        &self.metrics
    }

    /// Captures a point-in-time snapshot of pool metrics.
    #[must_use]
    pub fn metrics_snapshot(&self) -> ModelLoadMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Current count of verified resident models held in memory.
    pub fn resident_count(&self) -> Result<usize, ModelPoolError> {
        Ok(self
            .models
            .read()
            .map_err(|_| ModelPoolError::LockPoisoned)?
            .len())
    }

    /// Total estimated resident weight bytes currently pinned in memory.
    #[must_use]
    pub fn resident_bytes(&self) -> usize {
        self.current_resident_bytes.load(Ordering::Acquire)
    }

    /// Resolves an already-loaded resident model handle by exact key, incrementing `cache_hits`.
    pub fn acquire(
        &self,
        key: &ResidentModelKey,
    ) -> Result<Arc<VerifiedResidentModel>, ModelPoolError> {
        let guard = self
            .models
            .read()
            .map_err(|_| ModelPoolError::LockPoisoned)?;
        let model = guard
            .get(key)
            .ok_or_else(|| ModelPoolError::ModelNotLoaded(key.model_id.clone()))?;
        self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
        Ok(Arc::clone(model))
    }

    /// Read-only inspection of a resident model without modifying cache-hit counters.
    pub fn inspect(
        &self,
        key: &ResidentModelKey,
    ) -> Result<Arc<VerifiedResidentModel>, ModelPoolError> {
        let guard = self
            .models
            .read()
            .map_err(|_| ModelPoolError::LockPoisoned)?;
        guard
            .get(key)
            .map(Arc::clone)
            .ok_or_else(|| ModelPoolError::ModelNotLoaded(key.model_id.clone()))
    }

    /// Records one completed ML frame inference against the pool metrics.
    pub fn record_inference(&self) {
        self.metrics.frames_inferred.fetch_add(1, Ordering::Relaxed);
    }

    /// Loads and verifies an activity `.fmpk` package ONCE into immutable resident memory, or
    /// returns the cached `Arc<VerifiedResidentModel>` on subsequent calls (`cache_hits += 1`).
    pub fn load_or_get_activity(
        &self,
        bytes: &[u8],
        expected_digest: ContentDigest,
        policy: &ModelLicensePolicy,
        threshold_policy: ActivityThresholdPolicy,
        backend: KernelBackend,
        cx: &ScalarExecCx,
    ) -> Result<Arc<VerifiedResidentModel>, ModelPoolError> {
        cx.checkpoint("model_pool:load_activity")?;
        if expected_digest.algorithm() != DigestAlgorithm::Sha256
            || ContentDigest::sha256(bytes) != expected_digest
        {
            return Err(ModelPoolError::DigestMismatch);
        }
        let exec_profile = pool_execution_profile_digest(backend);
        let fast_key = ResidentModelKey {
            model_id: ACTIVITY_MODEL_ID.to_owned(),
            package_digest: expected_digest,
            model_generation: ACTIVITY_MODEL_GENERATION.to_owned(),
            execution_profile_digest: exec_profile,
        };
        if let Some(existing) = self.try_get_cached(&fast_key)? {
            return Ok(existing);
        }

        let package = VerifiedActivityPackage::load(bytes, expected_digest, policy, cx)?;
        let weights = Tensor::from_values(
            Shape::new(vec![package.mean_weights().len(), 1])?,
            package.mean_weights(),
            ACTIVITY_TENSOR_GENERATION,
        )?;
        let prepared = match backend {
            KernelBackend::ScalarReference => None,
            KernelBackend::OptimizedCpuV1 => {
                let mut constants = BTreeMap::new();
                constants.insert(
                    ACTIVITY_WEIGHTS_INPUT.to_owned(),
                    package.mean_weights().to_vec(),
                );
                Some(OptimizedGraph::prepare(package.graph(), &constants, cx)?)
            }
        };
        let spec_bytes = package.spec().encode()?;
        let mut model_enc = CanonicalEncoder::new();
        model_enc.text(ACTIVITY_MODEL_DOMAIN);
        model_enc.text(ACTIVITY_MODEL_GENERATION);
        model_enc.digest(package.graph_digest());
        model_enc.bytes(&spec_bytes);
        model_enc.digest(package.spec().resize_digest());
        model_enc.digest(package.manifest_digest());
        model_enc.digest(package.weights_digest());
        let model_digest = ContentDigest::sha256(&model_enc.finish());

        let manifest_digest = package.manifest_digest();
        let resident_bytes = package.mean_weights().len().saturating_mul(4).max(4096);
        let key = ResidentModelKey {
            model_id: package.manifest().model_id().as_str().to_owned(),
            package_digest: package.archive_digest(),
            model_generation: package.manifest().generation().as_str().to_owned(),
            execution_profile_digest: exec_profile,
        };
        let resident_digest = compute_resident_digest(&key, manifest_digest, backend, model_digest);
        let model = Arc::new(VerifiedResidentModel {
            key: key.clone(),
            manifest_digest,
            resident_digest,
            resident_bytes,
            artifact: ResidentModelArtifact::Activity {
                package,
                prepared,
                weights,
                backend,
                model_digest,
                threshold_policy,
            },
        });
        self.insert_or_reuse(key, model)
    }

    /// Loads (or reuses from resident cache) the committed `models/fss-activity/fss_activity_v1.fmpk`.
    pub fn load_or_get_activity_committed(
        &self,
        backend: KernelBackend,
        cx: &ScalarExecCx,
    ) -> Result<Arc<VerifiedResidentModel>, ModelPoolError> {
        let expected = ContentDigest::parse(ACTIVITY_PACKAGE_V1_SHA256)
            .map_err(|_| ModelPoolError::DigestMismatch)?;
        self.load_or_get_activity(
            ACTIVITY_PACKAGE_V1,
            expected,
            &activity_license_policy()?,
            ActivityThresholdPolicy::reference()?,
            backend,
            cx,
        )
    }

    /// Loads and verifies an RGB detector `.fmpk` package ONCE into immutable resident memory.
    #[allow(clippy::too_many_arguments)]
    pub fn load_or_get_rgb_detector(
        &self,
        bytes: &[u8],
        expected_digest: ContentDigest,
        import_work: u64,
        backend: KernelBackend,
        minimum_score_ppm: Option<u32>,
        replay_cx: &ReplayCx,
        scalar_cx: &ScalarExecCx,
    ) -> Result<Arc<VerifiedResidentModel>, ModelPoolError> {
        scalar_cx.checkpoint("model_pool:load_rgb_detector")?;
        replay_cx
            .checkpoint("model_pool:load_rgb_detector")
            .map_err(|_| ModelPoolError::Cancelled)?;
        if expected_digest.algorithm() != DigestAlgorithm::Sha256
            || ContentDigest::sha256(bytes) != expected_digest
        {
            return Err(ModelPoolError::DigestMismatch);
        }
        let exec_profile = pool_execution_profile_digest(backend);
        if let Some(existing) = self.find_cached_by_package(expected_digest, exec_profile)? {
            return Ok(existing);
        }

        let package = RgbDetectorPackage::load_with_backend(
            bytes,
            expected_digest,
            import_work,
            backend,
            replay_cx,
            scalar_cx,
        )?;
        let contract_override = match minimum_score_ppm {
            None => None,
            Some(ppm) => Some(package.contract_with_threshold(ppm)?),
        };
        let manifest_digest = package.manifest_digest();
        let model_digest = package.model().digest();
        let resident_bytes = bytes.len().max(4096);
        let key = ResidentModelKey {
            model_id: package.manifest().model_id().as_str().to_owned(),
            package_digest: package.archive_digest(),
            model_generation: package.manifest().generation().as_str().to_owned(),
            execution_profile_digest: exec_profile,
        };
        let resident_digest = compute_resident_digest(&key, manifest_digest, backend, model_digest);
        let model = Arc::new(VerifiedResidentModel {
            key: key.clone(),
            manifest_digest,
            resident_digest,
            resident_bytes,
            artifact: ResidentModelArtifact::RgbDetector {
                package,
                contract_override,
            },
        });
        self.insert_or_reuse(key, model)
    }

    fn try_get_cached(
        &self,
        key: &ResidentModelKey,
    ) -> Result<Option<Arc<VerifiedResidentModel>>, ModelPoolError> {
        let guard = self
            .models
            .read()
            .map_err(|_| ModelPoolError::LockPoisoned)?;
        if let Some(existing) = guard.get(key) {
            self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(Some(Arc::clone(existing)));
        }
        Ok(None)
    }

    fn find_cached_by_package(
        &self,
        package_digest: ContentDigest,
        execution_profile_digest: ContentDigest,
    ) -> Result<Option<Arc<VerifiedResidentModel>>, ModelPoolError> {
        let guard = self
            .models
            .read()
            .map_err(|_| ModelPoolError::LockPoisoned)?;
        for (key, model) in guard.iter() {
            if key.package_digest == package_digest
                && key.execution_profile_digest == execution_profile_digest
            {
                self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Ok(Some(Arc::clone(model)));
            }
        }
        Ok(None)
    }

    fn insert_or_reuse(
        &self,
        key: ResidentModelKey,
        model: Arc<VerifiedResidentModel>,
    ) -> Result<Arc<VerifiedResidentModel>, ModelPoolError> {
        let mut guard = self
            .models
            .write()
            .map_err(|_| ModelPoolError::LockPoisoned)?;
        if let Some(existing) = guard.get(&key) {
            self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(Arc::clone(existing));
        }
        let next_bytes = self
            .current_resident_bytes
            .load(Ordering::Acquire)
            .checked_add(model.resident_bytes)
            .ok_or(ModelPoolError::PoolCapacityExceeded {
                max_models: self.max_models,
                max_bytes: self.max_resident_bytes,
            })?;
        if guard.len() >= self.max_models || next_bytes > self.max_resident_bytes {
            return Err(ModelPoolError::PoolCapacityExceeded {
                max_models: self.max_models,
                max_bytes: self.max_resident_bytes,
            });
        }
        guard.insert(key, Arc::clone(&model));
        self.current_resident_bytes
            .store(next_bytes, Ordering::Release);
        self.metrics.loads.fetch_add(1, Ordering::Release);
        Ok(model)
    }
}

fn compute_resident_digest(
    key: &ResidentModelKey,
    manifest_digest: ContentDigest,
    backend: KernelBackend,
    model_digest: ContentDigest,
) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(RESIDENT_MODEL_DOMAIN);
    e.text(&key.model_id);
    e.digest(key.package_digest);
    e.digest(manifest_digest);
    e.text(&key.model_generation);
    e.digest(key.execution_profile_digest);
    e.text(backend.stable_id());
    e.digest(model_digest);
    ContentDigest::sha256(&e.finish())
}
