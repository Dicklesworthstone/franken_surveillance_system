#![forbid(unsafe_code)]
//! Root-last custody and native cold replay of inactive camera-pose proposals.
//!
//! The exact twin and descriptor archives are retained alongside the original candidate
//! receipt and a frozen input recipe. Authoring scenes and atlas-reference photographs are
//! identified by their archives, not claimed to be retained or authenticated here.

mod wire;

use super::*;
use fss_core::{DigestAlgorithm, Plane};
use fss_geometry::GeometryBasis;
use fss_object::ObjectManifest;
use fss_publication::{LocalPublicationState, SlotName};
use fss_twin::atlas_archive::{ArchiveExpectation, MAX_ATLAS_BYTES, decode_atlas};
use fss_twin::{ImportExpectation, ImportLimits, import_twin};

/// Versioned canonical recipe; a content digest names one immutable replay package.
pub const PACKAGE_DOMAIN: &str = "fss.recorded_twin_localization_package.v1";
/// Canonical recipe ceiling, independent of image, atlas and source-media allocations.
pub const MAX_PACKAGE_BYTES: usize = 4096;
/// Existing twin archive hard bound; publication does not enlarge the twin owner's limit.
pub const MAX_TWIN_BYTES: usize = 64 * 1024 * 1024;
/// Last cancellable boundary before publishing the localization package root.
pub const STAGE_LOCALIZATION_PUBLICATION: &str = "recorded_localization:publish";

/// Explicit owner-pinned archives and image interpretation for a retained computation.
#[derive(Clone, Copy, Debug)]
pub struct RetainedLocalizationPlan<'a> {
    /// Exact complete FSSTWIN1 archive; no external URI is resolved.
    pub twin_bytes: &'a [u8],
    /// Independent twin package/scene identities and a fresh process-local geometry basis.
    pub twin: ImportExpectation,
    /// Exact complete FSATLAS1 archive containing landmarks and native descriptors.
    pub atlas_bytes: &'a [u8],
    /// Independent archive, authoring-provenance and descriptor generation identities.
    pub atlas: ArchiveExpectation,
    /// Explicit native-grid or raw-lens interpretation.
    pub image: RecordedImageMode,
    /// Complete extraction, matching and pose solver options, retained without defaults.
    pub options: ImageLocalizationOptions,
}

#[derive(Clone, Debug)]
struct Recipe {
    source: RecordedLocalizationSource,
    import_root: ContentDigest,
    source_manifest: ContentDigest,
    source_anchor: LedgerAnchor,
    capsule: ContentDigest,
    mask_binding: ContentDigest,
    decode_root: Option<ContentDigest>,
    receipt: ContentDigest,
    twin: [u8; 32],
    scene: [u8; 32],
    atlas: ArchiveExpectation,
    image: RecordedImageMode,
    options: ImageLocalizationOptions,
}

/// A completed immutable package. Inspection verifies custody and current privacy, but is
/// not a native reproduction. Call [`Self::verify_by_replay`] to run the retained computation.
#[derive(Clone, Debug)]
pub struct RetainedLocalization {
    identity: ContentDigest,
    root: ContentDigest,
    recipe: Recipe,
    receipt: Vec<u8>,
    encoded: Vec<u8>,
}

/// Native replay context shared with measured calibration residual monitoring. The package
/// remains the source owner: callers cannot substitute pixels, extracted features or map bytes.
pub(crate) struct ReplayedLocalization {
    pub result: RecordedLocalization,
    pub twin: PropertyTwin,
    pub atlas: fss_twin::atlas_archive::ArchivedAtlas,
    pub image: RecordedImageMode,
    pub options: ImageLocalizationOptions,
    pub capsule: SensorCapsule,
}

fn sha(bytes: [u8; 32]) -> ContentDigest {
    ContentDigest::new(DigestAlgorithm::Sha256, bytes)
}
fn slot(identity: ContentDigest) -> Result<SlotName> {
    if identity.algorithm() != DigestAlgorithm::Sha256 || identity.bytes() == [0; 32] {
        return Err(RecordedLocalizationError::RetainedPackage);
    }
    SlotName::parse(&format!(
        "recorded-localization-{}",
        &identity.to_text()[7..]
    ))
    .map_err(|_| RecordedLocalizationError::RetainedPackage)
}
fn manifest(identity: ContentDigest, recipe: &Recipe) -> Result<ObjectManifest> {
    let mut children = vec![
        recipe.import_root,
        recipe.receipt,
        sha(recipe.twin),
        sha(recipe.atlas.package),
    ];
    if let Some(root) = recipe.decode_root {
        children.push(root);
    }
    children.sort_unstable();
    children.dedup();
    children.retain(|digest| *digest != identity);
    ObjectManifest::new(slot(identity)?.as_str(), children, Some(identity))
        .map_err(RecordedDecodeError::from)
        .map_err(Into::into)
}

fn read(
    deployment: &ReferenceDeployment,
    digest: ContentDigest,
    maximum: usize,
    budget: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<Vec<u8>> {
    checkpoint(cx, "recorded_localization:read_package")?;
    // Reserve the entire admitted read/hash walk before the spool allocates or hashes it.
    // This intentionally conservative bound is separate from the localizer's receipt work.
    budget.charge(maximum as u64)?;
    deployment
        .publisher()
        .spool()
        .read_bounded(digest, maximum)
        .map_err(RecordedDecodeError::from)
        .map_err(Into::into)
}

fn source_binding(
    deployment: &ReferenceDeployment,
    recipe: &Recipe,
    cx: &ReplayCx,
) -> Result<SensorCapsule> {
    let retained = admit_source(deployment, &recipe.source, cx)?;
    let capsule = retained_source_capsule(deployment, &retained, recipe.source.segment())?;
    if retained.import_root() != recipe.import_root
        || retained.manifest_digest() != recipe.source_manifest
        || retained.authority_anchor() != &recipe.source_anchor
        || ContentDigest::sha256(
            &capsule
                .try_canonical_bytes()
                .map_err(RecordedDecodeError::from)?,
        ) != recipe.capsule
    {
        return Err(RecordedLocalizationError::RetainedPackage);
    }
    if current_mask(deployment, &capsule.sensor_id)?.digest() != recipe.mask_binding {
        return Err(PrivacyMaskError::UnmaskedAccessRefused.into());
    }
    Ok(capsule)
}

fn admit_source(
    deployment: &ReferenceDeployment,
    source: &RecordedLocalizationSource,
    cx: &ReplayCx,
) -> Result<RetainedFileImport> {
    let retained =
        RetainedFileImport::open(deployment, source.import_identity(), source.limits(), cx)
            .map_err(RecordedDecodeError::from)?;
    // Partition roots are independent bounded publications, not an implicit recursive
    // expansion of their aggregate import root. Refuse before any native decode or write.
    if !retained.manifest().part_roots.is_empty() {
        return Err(RecordedLocalizationError::PartitionedSource);
    }
    let format = retained.manifest().format.as_str();
    let compatible = match source {
        RecordedLocalizationSource::Jpeg(_) => format == "mjpeg",
        RecordedLocalizationSource::H264 { .. } => matches!(format, "annexb" | "mp4avc" | "mkvavc"),
        RecordedLocalizationSource::H265 { .. } => matches!(format, "hevc" | "mp4hevc" | "mkvhevc"),
    };
    if !compatible {
        return Err(RecordedLocalizationError::SourceMismatch);
    }
    Ok(retained)
}

fn check_publication(
    deployment: &ReferenceDeployment,
    slot: &SlotName,
    expected: &ObjectManifest,
    capture: fss_core::CaptureInterval,
) -> Result<()> {
    let publisher = deployment.publisher();
    let visible = publisher
        .root(slot)
        .ok_or(RecordedLocalizationError::RetainedPackage)?;
    if visible.state != LocalPublicationState::Durable || visible.root != expected.root() {
        return Err(RecordedLocalizationError::RetainedPackage);
    }
    let object = format!("object:local-root:{}", slot.as_str());
    let (batch, delta) = deployment
        .ledger()
        .batches()
        .iter()
        .rev()
        .find_map(|batch| {
            batch
                .deltas
                .iter()
                .find(|delta| delta.object_id.as_str() == object)
                .map(|delta| (batch, delta))
        })
        .ok_or(RecordedLocalizationError::RetainedPackage)?;
    let mut closure: Vec<_> = publisher
        .root_closure(slot)
        .ok_or(RecordedLocalizationError::RetainedPackage)?
        .into_iter()
        .filter(|digest| *digest != expected.root())
        .collect();
    closure.sort_unstable();
    if batch.batch_id.as_str() != format!("batch:local-root:{}", slot.as_str())
        || batch.deltas.len() != 1
        || delta.family != "local_root_reachability"
        || delta.delta_id != format!("delta:local-root:{}", slot.as_str())
        || delta.plane != Plane::Authority
        || delta.prior_generation.is_some()
        || delta.new_generation != 1
        || delta.payload_digest != expected.root()
        || delta.witness_digest.is_some()
        || delta.operation_id.is_some()
        || delta.validity != capture
        || batch.children != closure
    {
        return Err(RecordedLocalizationError::RetainedPackage);
    }
    Ok(())
}

impl RetainedLocalization {
    /// Canonical recipe digest used to reopen this exact package, never a mutable label.
    pub fn identity(&self) -> ContentDigest {
        self.identity
    }
    /// Ledgered root of receipt, archives, frozen recipe and retained source graph.
    pub fn publication_root(&self) -> ContentDigest {
        self.root
    }
    /// Whole immutable candidate receipt expected from native replay.
    pub fn receipt_digest(&self) -> ContentDigest {
        self.recipe.receipt
    }
    /// Exact bytes of that candidate receipt; inspection alone does not verify the computation.
    pub fn receipt_bytes(&self) -> &[u8] {
        &self.receipt
    }
    /// Frozen original media selection and complete codec/read limits.
    pub fn source(&self) -> &RecordedLocalizationSource {
        &self.recipe.source
    }
    /// Retained twin archive identity.
    pub fn twin_digest(&self) -> ContentDigest {
        sha(self.recipe.twin)
    }
    /// Retained descriptor archive identity, distinct from its normalized atlas fingerprint.
    pub fn atlas_package(&self) -> ContentDigest {
        sha(self.recipe.atlas.package)
    }

    /// Open by immutable identity using only deployment custody. Bounds are admitted before
    /// allocation. Exact root/ledger closure, all package objects and current source/privacy
    /// bindings are checked. No archive authoring file or reference photograph is needed.
    pub fn open(
        deployment: &ReferenceDeployment,
        identity: ContentDigest,
        read_limits: RetainedReadLimits,
        budget: &mut WorkBudget<'_>,
        cx: &ReplayCx,
    ) -> Result<Self> {
        checkpoint(cx, "recorded_localization:open")?;
        let slot = slot(identity)?;
        let visible = deployment
            .publisher()
            .root(&slot)
            .ok_or(RecordedLocalizationError::RetainedPackage)?;
        if visible.state != LocalPublicationState::Durable {
            return Err(RecordedLocalizationError::RetainedPackage);
        }
        let root = visible.root;
        let encoded = read(deployment, identity, MAX_PACKAGE_BYTES, budget, cx)?;
        let recipe = wire::decode(&encoded)?;
        let original = recipe.source.limits();
        if original.max_source_bytes > read_limits.max_source_bytes
            || original.max_chunk_bytes > read_limits.max_chunk_bytes
            || original.max_segment_bytes > read_limits.max_segment_bytes
        {
            return Err(RecordedLocalizationError::InvalidRequest);
        }
        let capsule = source_binding(deployment, &recipe, cx)?;
        let expected = manifest(identity, &recipe)?;
        check_publication(deployment, &slot, &expected, capsule.capture)?;
        if root != expected.root()
            || read(deployment, root, MAX_PACKAGE_BYTES, budget, cx)? != expected.canonical_bytes()
        {
            return Err(RecordedLocalizationError::RetainedPackage);
        }
        let receipt = read(deployment, recipe.receipt, MAX_RECEIPT_BYTES, budget, cx)?;
        // Verify complete archive custody even for a metadata-only read. Semantic import and
        // native decoding remain explicit work in verify_by_replay.
        read(deployment, sha(recipe.twin), MAX_TWIN_BYTES, budget, cx)?;
        read(
            deployment,
            sha(recipe.atlas.package),
            MAX_ATLAS_BYTES,
            budget,
            cx,
        )?;
        checkpoint(cx, "recorded_localization:opened")?;
        Ok(Self {
            identity,
            root,
            recipe,
            receipt,
            encoded,
        })
    }

    /// Rebuild native media and geometry from retained bytes, compare the complete candidate
    /// receipt, and return the reproduced proposal. JPEG performs the native decode even when
    /// cached luma exists. Every codec consumes the original recipe's limits; caller work
    /// allowances are cumulative execution ceilings, not a substitute recipe. Nothing is
    /// staged, published, activated or appended, including on divergence or cancellation.
    pub fn verify_by_replay(
        &self,
        deployment: &mut ReferenceDeployment,
        basis: GeometryBasis,
        jpeg_budget: &mut DecodeBudget<'_>,
        video_budget: &mut RecordedVideoDecodeBudget,
        geometry_budget: &mut WorkBudget<'_>,
        cx: &ReplayCx,
    ) -> Result<RecordedLocalization> {
        Ok(self
            .replay_context(
                deployment,
                basis,
                jpeg_budget,
                video_budget,
                geometry_budget,
                cx,
            )?
            .result)
    }

    /// Reproduce the existing receipt before exposing its exact maps and query features.
    pub(crate) fn replay_context(
        &self,
        deployment: &mut ReferenceDeployment,
        basis: GeometryBasis,
        jpeg_budget: &mut DecodeBudget<'_>,
        video_budget: &mut RecordedVideoDecodeBudget,
        geometry_budget: &mut WorkBudget<'_>,
        cx: &ReplayCx,
    ) -> Result<ReplayedLocalization> {
        let reopened = Self::open(
            deployment,
            self.identity,
            self.recipe.source.limits(),
            geometry_budget,
            cx,
        )?;
        if reopened.root != self.root
            || reopened.encoded != self.encoded
            || reopened.receipt != self.receipt
        {
            return Err(RecordedLocalizationError::RetainedPackage);
        }
        let anchor = deployment.current_anchor().clone();
        let twin_bytes = read(
            deployment,
            sha(self.recipe.twin),
            MAX_TWIN_BYTES,
            geometry_budget,
            cx,
        )?;
        let twin = import_twin(
            &twin_bytes,
            ImportExpectation {
                package_sha256: self.recipe.twin,
                source_scene_sha256: self.recipe.scene,
                basis,
            },
            ImportLimits::default(),
            geometry_budget,
        )?;
        let atlas_bytes = read(
            deployment,
            sha(self.recipe.atlas.package),
            MAX_ATLAS_BYTES,
            geometry_budget,
            cx,
        )?;
        let atlas = decode_atlas(&atlas_bytes, &twin, self.recipe.atlas, geometry_budget)?;
        let result = localize_inner(
            deployment,
            &self.recipe.source,
            RecordedLocalizationPlan {
                twin: &twin,
                atlas: atlas.atlas(),
                image: self.recipe.image,
                options: self.recipe.options,
            },
            jpeg_budget,
            video_budget,
            geometry_budget,
            cx,
            true,
        )?;
        if result.encoded() != self.receipt || result.digest() != self.recipe.receipt {
            return Err(RecordedLocalizationError::ReplayDiverged);
        }
        let capsule = source_binding(deployment, &self.recipe, cx)?;
        if deployment.current_anchor() != &anchor {
            return Err(RecordedLocalizationError::RetainedPackage);
        }
        checkpoint(cx, "recorded_localization:replay_verified")?;
        Ok(ReplayedLocalization {
            result,
            twin,
            atlas,
            image: self.recipe.image,
            options: self.recipe.options,
            capsule,
        })
    }
}

/// Compute a proposal and explicitly retain its complete replay inputs. Existing localize
/// callers keep their previous behavior. Repeating this exact request revalidates any already
/// published package and resumes root-to-ledger interruption without a second publication.
/// The ordinary JPEG derivative may have been published before a later localization refusal.
pub fn localize_and_retain(
    deployment: &mut ReferenceDeployment,
    source: &RecordedLocalizationSource,
    plan: RetainedLocalizationPlan<'_>,
    jpeg_budget: &mut DecodeBudget<'_>,
    video_budget: &mut RecordedVideoDecodeBudget,
    geometry_budget: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<(RecordedLocalization, RetainedLocalization)> {
    checkpoint(cx, "recorded_localization:admit_package")?;
    if plan.twin_bytes.len() > MAX_TWIN_BYTES || plan.atlas_bytes.len() > MAX_ATLAS_BYTES {
        return Err(RecordedLocalizationError::InvalidRequest);
    }
    admit_source(deployment, source, cx)?;
    validate_options(plan.options)?;
    let twin = import_twin(
        plan.twin_bytes,
        plan.twin,
        ImportLimits::default(),
        geometry_budget,
    )?;
    let atlas = decode_atlas(plan.atlas_bytes, &twin, plan.atlas, geometry_budget)?;
    let result = localize_recorded_frame(
        deployment,
        source,
        RecordedLocalizationPlan {
            twin: &twin,
            atlas: atlas.atlas(),
            image: plan.image,
            options: plan.options,
        },
        jpeg_budget,
        video_budget,
        geometry_budget,
        cx,
    )?;
    let b = result.source();
    let recipe = Recipe {
        source: source.clone(),
        import_root: b.import_root,
        source_manifest: b.manifest,
        source_anchor: b.source_anchor.clone(),
        capsule: b.capsule,
        mask_binding: b.mask_binding,
        decode_root: b.decode_root,
        receipt: result.digest(),
        twin: plan.twin.package_sha256,
        scene: plan.twin.source_scene_sha256,
        atlas: plan.atlas,
        image: plan.image,
        options: plan.options,
    };
    let encoded = wire::encode(&recipe)?;
    // Writer and cold reader share the same strict, bounded representation. Never publish
    // a recipe that this generation cannot independently admit after process restart.
    wire::decode(&encoded)?;
    geometry_budget.charge(
        (encoded.len() + result.encoded().len() + plan.twin_bytes.len() + plan.atlas_bytes.len())
            as u64,
    )?;
    let identity = ContentDigest::sha256(&encoded);
    let slot = slot(identity)?;
    let manifest = manifest(identity, &recipe)?;
    let capsule = source_binding(deployment, &recipe, cx)?;
    let existing = deployment
        .publisher()
        .root(&slot)
        .map(|root| (root.root, root.state));
    if let Some((root, _)) = existing {
        if root != manifest.root() {
            return Err(RecordedLocalizationError::RetainedPackage);
        }
        // Existing custody is not repaired as an undocumented side effect of retry.
        for (digest, bytes) in [
            (identity, encoded.as_slice()),
            (recipe.receipt, result.encoded()),
            (sha(recipe.twin), plan.twin_bytes),
            (sha(recipe.atlas.package), plan.atlas_bytes),
        ] {
            if read(deployment, digest, bytes.len(), geometry_budget, cx)? != bytes {
                return Err(RecordedLocalizationError::RetainedPackage);
            }
        }
    } else {
        for bytes in [
            encoded.as_slice(),
            result.encoded(),
            plan.twin_bytes,
            plan.atlas_bytes,
        ] {
            checkpoint(cx, "recorded_localization:stage_package")?;
            let digest = deployment
                .publisher_mut()
                .stage_object(bytes)
                .map_err(RecordedDecodeError::from)?;
            deployment
                .publisher_mut()
                .verify_object(digest)
                .map_err(RecordedDecodeError::from)?;
        }
        deployment
            .publisher_mut()
            .stage_manifest(&slot, &manifest)
            .map_err(RecordedDecodeError::from)?;
    }
    geometry_budget.charge(0)?;
    checkpoint(cx, STAGE_LOCALIZATION_PUBLICATION)?;
    deployment
        .publish_and_commit(&slot, &manifest, capsule.capture, cx)
        .map_err(RecordedDecodeError::from)?;
    cx.checkpoint_post_commit("recorded_localization:retained");
    let retained = RetainedLocalization {
        identity,
        root: manifest.root(),
        recipe,
        receipt: result.encoded().to_vec(),
        encoded,
    };
    Ok((result, retained))
}
