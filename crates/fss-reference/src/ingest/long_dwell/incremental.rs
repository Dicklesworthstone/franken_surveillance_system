#![forbid(unsafe_code)]
//! Native bounded continuation over one completed retained MJPEG recording.
//!
//! A running owner keeps the same source cursor, decoder allowance, foreground model, tracker
//! and temporal accumulator between steps. Durable checkpoints retain the exact input recipe
//! and trace, never deserialized mutable perception state. Cold resume replays the pinned prefix
//! under a separately admitted budget, compares the complete checkpoint, and only then continues.
//! Checkpoint publication is derived work custody; event publication keeps its original owner.

use super::*;
use fss_core::{CanonicalDecode, CanonicalDecoder, DigestAlgorithm, Plane, PrincipalId};
use fss_publication::ROOT_REACHABILITY_FAMILY;

/// Canonical versioned checkpoint domain. Existing whole-recording event formats are unchanged.
pub const CHECKPOINT_DOMAIN: &str = "fss.incremental_dwell_checkpoint.v1";
/// Maximum checkpoint body, including its complete bounded native trace and original recipe.
pub const MAX_CHECKPOINT_BYTES: usize = MAX_LONG_DWELL_TRACE_BYTES + 16 * 1024;
/// Durable manifest kind of this source-closed derived computation checkpoint.
pub const CHECKPOINT_MANIFEST_KIND: &str = "recorded-incremental-dwell-checkpoint-v1";
const RECIPE_DOMAIN: &str = "fss.incremental-dwell.recipe.v1";

/// Exact immutable checkpoint handles. Neither digest is authority to publish an event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DwellCheckpointPin {
    /// Canonical checkpoint body, including its prefix trace and all cumulative counters.
    pub record_digest: ContentDigest,
    /// Root-last graph binding that body to the original import and privacy policy.
    pub provenance_root: ContentDigest,
}

/// Cumulative successful scan work. Counts are never replenished at a step/checkpoint boundary.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DwellWork {
    /// Admitted source positions, including explicit decode refusals.
    pub source_positions: usize,
    /// Successfully decoded native images.
    pub frames_decoded: usize,
    /// Actual verified chunk bytes fetched by the shared forward cursor.
    pub source_chunk_bytes: u64,
    /// Decoded luma samples charged to foreground processing.
    pub pixel_samples: u64,
    /// Existing checked tracker assignment admission bounds.
    pub assignment_work: u64,
    /// Actual native JPEG decoding work, including tolerated refusal work.
    pub jpeg_work: u64,
    /// Full length-framed prefix trace bytes.
    pub trace_bytes: usize,
}

impl DwellWork {
    fn encode(self, encoder: &mut CanonicalEncoder) {
        for value in [
            self.source_positions as u64,
            self.frames_decoded as u64,
            self.source_chunk_bytes,
            self.pixel_samples,
            self.assignment_work,
            self.jpeg_work,
            self.trace_bytes as u64,
        ] {
            encoder.u64(value);
        }
    }

    fn decode(decoder: &mut CanonicalDecoder<'_>) -> Result<Self> {
        Ok(Self {
            source_positions: count(decoder, MAX_LONG_DWELL_FRAMES)?,
            frames_decoded: count(decoder, MAX_LONG_DWELL_FRAMES)?,
            source_chunk_bytes: decoder.u64()?,
            pixel_samples: decoder.u64()?,
            assignment_work: decoder.u64()?,
            jpeg_work: decoder.u64()?,
            trace_bytes: count(decoder, MAX_LONG_DWELL_TRACE_BYTES)?,
        })
    }

    /// Complete bounded structured accounting. Metadata/publication I/O has separate owners.
    pub fn to_json(self) -> String {
        format!(
            concat!(
                "{{\"source_positions\":{},\"frames_decoded\":{},\"source_chunk_bytes\":{},",
                "\"pixel_samples\":{},\"assignment_work\":{},\"jpeg_work\":{},\"trace_bytes\":{}}}"
            ),
            self.source_positions,
            self.frames_decoded,
            self.source_chunk_bytes,
            self.pixel_samples,
            self.assignment_work,
            self.jpeg_work,
            self.trace_bytes,
        )
    }
}

/// Independent explicit permission to pay cold reconstruction cost. The stored original scan
/// ceilings must fit this admission; they remain unchanged for the resumed logical analysis.
#[derive(Clone, Copy, Debug)]
pub struct DwellRestoreLimits {
    /// Maximum positions which the caller permits cold resume to decode again.
    pub maximum_prefix_frames: usize,
    /// Conservative native source/codec/whole-scan ceilings admitted for reconstruction.
    pub execution: LongDwellLimits,
}

/// Immutable validated setup. It may outlive deployment locks, but every advance and checkpoint
/// rechecks the current source, privacy, original root and principal before useful work.
pub struct PreparedIncrementalDwell {
    plan: WatchPlan,
    rule: DwellPolicy,
    options: WatchOptions,
    limits: LongDwellLimits,
    source: ScanPreparation,
    root: PathBuf,
    site: String,
    principal: String,
}

impl std::fmt::Debug for PreparedIncrementalDwell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedIncrementalDwell")
            .field("import", &self.plan.import_identity)
            .field("first_segment", &self.plan.first_segment)
            .field("segment_count", &self.plan.segment_count)
            .finish_non_exhaustive()
    }
}

impl PreparedIncrementalDwell {
    /// Admit one full MJPEG range and temporal rule without decoding or creating a checkpoint.
    /// The first version intentionally excludes inter-coded decoder state, classifiers and
    /// sensor-health screens. Those modes retain their existing whole-recording APIs.
    pub fn new(
        deployment: &ReferenceDeployment,
        plan: WatchPlan,
        rule: DwellPolicy,
        options: WatchOptions,
        limits: LongDwellLimits,
        cx: &ReplayCx,
    ) -> Result<Self> {
        let source = prepare_scan(
            deployment,
            &plan,
            ScanRule::Dwell(rule),
            options,
            &limits,
            cx,
        )?;
        if source.inter {
            return Err(WatchError::InvalidPlan(
                "incremental dwell currently requires retained MJPEG",
            ));
        }
        // A partitioned aggregate pins typed part roots in its metadata, rather than adding
        // them as graph children. Until this checkpoint format has a bounded part-closure
        // representation, linking only that aggregate would not retain all source custody.
        if !source.retained.manifest().part_roots.is_empty() {
            return Err(WatchError::InvalidPlan(
                "incremental dwell currently requires a flat retained import",
            ));
        }
        PrincipalId::parse(cx.io_authority().principal())?;
        Ok(Self {
            plan,
            rule,
            options,
            limits,
            source,
            root: deployment.root().to_path_buf(),
            site: deployment.site_lineage().to_owned(),
            principal: cx.io_authority().principal().to_owned(),
        })
    }

    /// Complete original source, zone, foreground and tracker settings.
    pub fn plan(&self) -> &WatchPlan {
        &self.plan
    }
    /// Original immutable temporal thresholds.
    pub const fn rule(&self) -> DwellPolicy {
        self.rule
    }
    /// Original refusal behavior.
    pub const fn options(&self) -> WatchOptions {
        self.options
    }
    /// Original full scan ceilings; a checkpoint never restores a fresh allowance.
    pub const fn limits(&self) -> &LongDwellLimits {
        &self.limits
    }

    /// Begin an owned native scan. No deployment/source borrow is held between steps.
    pub fn start(&self) -> Result<IncrementalDwell<'_>> {
        Ok(IncrementalDwell {
            prepared: self,
            scan: start_scan(
                &self.source,
                &self.plan,
                ScanRule::Dwell(self.rule),
                &self.limits,
                false,
                None,
            )?,
            cursor: ChunkCursor::new(self.limits.maximum_source_chunk_bytes),
            codec: DecodeBudget::new(self.limits.decode.jpeg_work_units),
            next: self.plan.first_segment,
            poisoned: false,
            restoration_work: DwellWork::default(),
        })
    }

    fn check(&self, deployment: &ReferenceDeployment, cx: &ReplayCx) -> Result<()> {
        checkpoint(cx, "incremental_dwell:revalidate")?;
        if cx.root_dir() != deployment.root()
            || deployment.root() != self.root
            || deployment.site_lineage() != self.site
            || cx.io_authority().principal() != self.principal
        {
            return Err(WatchError::Conflict);
        }
        deployment
            .ledger()
            .verify_durable_head()
            .map_err(ReferenceError::from)?;
        let current = RetainedFileImport::open(
            deployment,
            self.plan.import_identity,
            self.limits.decode.read_limits,
            cx,
        )?;
        if current != self.source.retained {
            return Err(WatchError::Conflict);
        }
        let privacy =
            current_mask(deployment, &self.source.sensor).map_err(RecordedDecodeError::from)?;
        if privacy.digest() != self.source.privacy.digest()
            || privacy.generation() != self.source.privacy.generation()
        {
            return Err(WatchError::InvalidPlan(
                "privacy generation changed; restart the incremental analysis",
            ));
        }
        Ok(())
    }

    /// Exact source, privacy, actor, native recipe and resource reservation identity. This is
    /// independent of progress and grants no event or checkpoint publication authority.
    pub fn request_digest(&self) -> Result<ContentDigest> {
        Ok(ContentDigest::sha256(&self.recipe()?))
    }

    fn recipe(&self) -> Result<Vec<u8>> {
        let mut e = CanonicalEncoder::new();
        e.text(RECIPE_DOMAIN);
        e.digest(ContentDigest::sha256(POLICY));
        e.digest(ContentDigest::sha256(&fss_codec_mjpeg::decoder_identity()));
        e.text(&self.site);
        e.text(&self.principal);
        e.digest(self.plan.digest());
        e.digest(self.plan.import_identity);
        e.u64(self.plan.first_segment as u64);
        e.u64(self.plan.segment_count as u64);
        e.u64(self.plan.zones.len() as u64);
        for zone in &self.plan.zones {
            e.text(&zone.zone_id);
            for value in [zone.x, zone.y, zone.width, zone.height] {
                e.u32(value);
            }
        }
        let parameters = super::super::recorded_watch::pipeline_parameters(
            self.plan.interpretation,
            &self.plan.detector,
            &self.plan.tracker,
        );
        e.u64(parameters.len() as u64);
        for value in parameters {
            e.u64(value);
        }
        e.u64(self.rule.minimum_duration_ns);
        e.u64(self.rule.maximum_sample_gap_ns);
        e.u64(self.rule.minimum_observations as u64);
        e.bool(self.options.tolerate_decode_refusals);
        super::limits::encode_limits(&mut e, &self.limits);
        e.digest(self.source.retained.import_root());
        e.digest(self.source.retained.manifest_digest());
        self.source
            .retained
            .authority_anchor()
            .encode_canonical(&mut e);
        e.text(self.source.sensor.as_str());
        e.digest(self.source.privacy.digest());
        e.bool(self.source.privacy.generation().is_some());
        if let Some(generation) = self.source.privacy.generation() {
            e.u64(generation);
        }
        Ok(e.finish_checked()?)
    }

    fn manifest(&self, record: ContentDigest) -> Result<ObjectManifest> {
        let mut children = BTreeSet::from([
            record,
            self.source.retained.import_root(),
            ContentDigest::sha256(POLICY),
        ]);
        if let Some(policy) = self.source.privacy.policy() {
            children.insert(policy.digest());
        }
        Ok(ObjectManifest::new(
            CHECKPOINT_MANIFEST_KIND,
            children,
            None,
        )?)
    }
}

/// One live computation owner. A failed admitted step poisons this owner; its last durable checkpoint
/// remains available for a separately budgeted retry. Calling finish consumes the owner.
pub struct IncrementalDwell<'a> {
    prepared: &'a PreparedIncrementalDwell,
    scan: Scan<'a, 'static>,
    cursor: ChunkCursor,
    codec: DecodeBudget<'static>,
    next: usize,
    poisoned: bool,
    restoration_work: DwellWork,
}

impl std::fmt::Debug for IncrementalDwell<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IncrementalDwell")
            .field("next_segment", &self.next)
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl IncrementalDwell<'_> {
    /// Continue at most this many positions, preserving native foreground, tracker, clock and
    /// dwell state. A successful step never closes the still-active temporal episode.
    pub fn advance(
        &mut self,
        deployment: &ReferenceDeployment,
        maximum_frames: usize,
        cx: &ReplayCx,
    ) -> Result<DwellWork> {
        if self.poisoned {
            return Err(WatchError::InvalidPlan(
                "incremental owner was refused; restore its last checkpoint",
            ));
        }
        if !(1..=MAX_LONG_DWELL_FRAMES).contains(&maximum_frames) {
            return Err(WatchError::Limit);
        }
        // Set before any authority check or mutable work; an error cannot leave a reusable
        // partially advanced foreground model, cursor, tracker or decoder allowance.
        self.poisoned = true;
        self.prepared.check(deployment, cx)?;
        checkpoint(cx, "incremental_dwell:advance")?;
        let end = self.prepared.plan.first_segment + self.prepared.plan.segment_count;
        let stop = self.next.saturating_add(maximum_frames).min(end);
        scan_mjpeg_range(
            &mut self.scan,
            deployment,
            &self.prepared.source,
            self.prepared.options,
            self.next,
            stop,
            &mut self.cursor,
            &mut self.codec,
            false,
            cx,
        )?;
        self.prepared.check(deployment, cx)?;
        self.next = stop;
        self.poisoned = false;
        Ok(self.work())
    }

    /// Full logical scan counters, including the reconstructed prefix after cold resume.
    pub fn work(&self) -> DwellWork {
        DwellWork {
            source_positions: self.next - self.prepared.plan.first_segment,
            frames_decoded: self.scan.decoded,
            source_chunk_bytes: self.cursor.bytes_read(),
            pixel_samples: self.scan.pixel_samples,
            assignment_work: self.scan.assignment_work,
            jpeg_work: self.codec.used(),
            trace_bytes: self.scan.trace.len(),
        }
    }

    /// Additional native work actually spent reconstructing the prefix in this process.
    /// It is not included a second time in the logical scan counters or its original allowance.
    pub const fn restoration_work(&self) -> DwellWork {
        self.restoration_work
    }

    /// Whether all requested positions were admitted; this does not imply an event or coverage.
    pub fn complete(&self) -> bool {
        !self.poisoned
            && self.next == self.prepared.plan.first_segment + self.prepared.plan.segment_count
    }

    fn record(&self) -> Result<Vec<u8>> {
        if self.poisoned || self.work().source_positions == 0 {
            return Err(WatchError::InvalidPlan(
                "only a successful nonempty prefix can be checkpointed",
            ));
        }
        let mut e = CanonicalEncoder::new();
        e.text(CHECKPOINT_DOMAIN);
        e.bytes(&self.prepared.recipe()?);
        self.work().encode(&mut e);
        e.bytes(&self.scan.trace);
        let bytes = e.finish_checked()?;
        if bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(WatchError::Limit);
        }
        Ok(bytes)
    }

    /// Retain one immutable, source-closed checkpoint root-last. Exact retries reverify original
    /// stored bytes and never repair missing/damaged published custody from this live state.
    pub fn retain(
        &self,
        deployment: &mut ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<DwellCheckpointPin> {
        self.prepared.check(deployment, cx)?;
        let bytes = self.record()?;
        let record_digest = ContentDigest::sha256(&bytes);
        let manifest = self.prepared.manifest(record_digest)?;
        let target = super::slot("ld-c", record_digest)?;
        self.prepared
            .source
            .publication_guard
            .revalidate(deployment, cx)?;
        checkpoint(cx, "incremental_dwell:retain")?;
        if deployment.publisher().root(&target).is_some() {
            let original = deployment
                .publisher()
                .spool()
                .read_bounded(record_digest, MAX_CHECKPOINT_BYTES)?;
            if original != bytes {
                return Err(WatchError::Conflict);
            }
        } else {
            for body in [bytes.as_slice(), POLICY] {
                let digest = deployment.stage_payload(body)?;
                deployment.publisher_mut().verify_object(digest)?;
            }
            if let Some(policy) = self.prepared.source.privacy.policy() {
                let digest = deployment.stage_payload(&policy.to_bytes())?;
                deployment.publisher_mut().verify_object(digest)?;
            }
        }
        // Include the requested capture hull even when every decoded position was refused.
        // This is source-time metadata, not an assertion of observed presence or continuity.
        let first = self.prepared.source.first_capsule.capture;
        let (last, _) = source_capsule(deployment, &self.prepared.source.retained, self.next - 1)?;
        let validity = CaptureInterval {
            earliest: first.earliest.min(last.capture.earliest),
            latest: first.latest.max(last.capture.latest),
        };
        super::publish_manifest(deployment, &target, &manifest, validity, cx)?;
        Ok(DwellCheckpointPin {
            record_digest,
            provenance_root: manifest.root(),
        })
    }

    /// Finish the declared full range through the existing report and event-proposal encoder.
    /// No episode is emitted from a truncated step; no checkpoint grants publication approval.
    pub fn finish(
        self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<LongDwellReport> {
        if !self.complete() {
            return Err(WatchError::InvalidPlan(
                "incremental dwell range is incomplete",
            ));
        }
        self.prepared.check(deployment, cx)?;
        self.prepared
            .source
            .publication_guard
            .revalidate(deployment, cx)?;
        let prepared = self.prepared;
        let scan = finish_scan(
            self.scan,
            deployment,
            &prepared.source,
            &prepared.plan,
            ScanRule::Dwell(prepared.rule),
            prepared.options,
            &prepared.limits,
            self.cursor.bytes_read(),
            self.codec.used(),
            false,
            cx,
        )?;
        LongDwellReport::from_scan(
            deployment,
            &prepared.plan,
            prepared.rule,
            prepared.options,
            scan,
            None,
            cx,
        )
    }
}

/// Verified immutable checkpoint metadata and source binding. Opening this value executes no
/// perception; resume must additionally admit and reproduce the original native prefix.
#[derive(Debug)]
pub struct RetainedDwellCheckpoint {
    prepared: PreparedIncrementalDwell,
    pin: DwellCheckpointPin,
    expected: DwellWork,
    bytes: Vec<u8>,
}

impl RetainedDwellCheckpoint {
    /// Open exact root/body pins, current original source/privacy, and complete retained recipe.
    /// A stale source or privacy generation refuses before native reconstruction.
    pub fn open(
        deployment: &ReferenceDeployment,
        pin: DwellCheckpointPin,
        allowed: &DwellRestoreLimits,
        cx: &ReplayCx,
    ) -> Result<Self> {
        validate_digest(pin.record_digest)?;
        validate_digest(pin.provenance_root)?;
        if !(1..=MAX_LONG_DWELL_FRAMES).contains(&allowed.maximum_prefix_frames) {
            return Err(WatchError::Limit);
        }
        allowed.execution.validate()?;
        checkpoint(cx, "incremental_dwell:open")?;
        if cx.root_dir() != deployment.root() {
            return Err(WatchError::Conflict);
        }
        deployment
            .ledger()
            .verify_durable_head()
            .map_err(ReferenceError::from)?;
        let target = super::slot("ld-c", pin.record_digest)?;
        let object = ObjectId::parse(format!("object:local-root:{}", target.as_str()))?;
        let current = deployment
            .ledger()
            .current()
            .objects
            .get(&object)
            .ok_or(WatchError::Conflict)?;
        let visible = deployment
            .publisher()
            .root(&target)
            .ok_or(WatchError::Conflict)?;
        if current.family != ROOT_REACHABILITY_FAMILY
            || current.plane != Plane::Authority
            || current.generation != 1
            || current.payload_digest != pin.provenance_root
            || visible.root != pin.provenance_root
        {
            return Err(WatchError::Conflict);
        }
        let manifest_bytes = deployment
            .publisher()
            .spool()
            .read_bounded(pin.provenance_root, 1024)?;
        let manifest = ObjectManifest::from_canonical_bytes(&manifest_bytes)?;
        if manifest.root() != pin.provenance_root
            || manifest.kind() != CHECKPOINT_MANIFEST_KIND
            || manifest.metadata_digest().is_some()
            || manifest.children().len() > 4
        {
            return Err(WatchError::Conflict);
        }
        let maximum = allowed
            .execution
            .maximum_trace_bytes
            .checked_add(16 * 1024)
            .ok_or(WatchError::Limit)?;
        let bytes = deployment
            .publisher()
            .spool()
            .read_bounded(pin.record_digest, maximum.min(MAX_CHECKPOINT_BYTES))?;
        if ContentDigest::sha256(&bytes) != pin.record_digest {
            return Err(WatchError::Conflict);
        }
        let mut d = CanonicalDecoder::new(&bytes);
        if d.text()? != CHECKPOINT_DOMAIN {
            return Err(WatchError::InvalidPlan(
                "unsupported incremental dwell checkpoint",
            ));
        }
        let recipe = d.bytes()?;
        if recipe.len() > 16 * 1024 {
            return Err(WatchError::Limit);
        }
        let decoded = decode_recipe(recipe)?;
        super::limits::validate_within(&decoded.limits, &allowed.execution)?;
        let expected = DwellWork::decode(&mut d)?;
        let trace = d.bytes()?;
        d.ensure_finished()?;
        if expected.source_positions == 0
            || expected.source_positions > allowed.maximum_prefix_frames
            || expected.source_positions > decoded.plan.segment_count
            || expected.frames_decoded > expected.source_positions
            || expected.source_chunk_bytes > decoded.limits.maximum_source_chunk_bytes
            || expected.pixel_samples > decoded.limits.maximum_pixel_samples
            || expected.assignment_work > decoded.limits.maximum_assignment_work
            || expected.jpeg_work > decoded.limits.decode.jpeg_work_units
            || expected.trace_bytes != trace.len()
            || trace.len() > decoded.limits.maximum_trace_bytes
        {
            return Err(WatchError::Limit);
        }
        let prepared = PreparedIncrementalDwell::new(
            deployment,
            decoded.plan,
            decoded.rule,
            decoded.options,
            decoded.limits,
            cx,
        )?;
        // Exact re-encoding also verifies original site, actor, source/import anchor, native
        // implementation identities, current privacy and complete compatibility bytes.
        if prepared.recipe()? != recipe || prepared.manifest(pin.record_digest)? != manifest {
            return Err(WatchError::Conflict);
        }
        prepared
            .source
            .publication_guard
            .revalidate(deployment, cx)?;
        Ok(Self {
            prepared,
            pin,
            expected,
            bytes,
        })
    }

    /// Original source/rule/configuration, usable without the loose input file.
    pub const fn prepared(&self) -> &PreparedIncrementalDwell {
        &self.prepared
    }
    /// Both exact retained pins, unchanged by cold reconstruction.
    pub const fn pin(&self) -> DwellCheckpointPin {
        self.pin
    }
    /// Expected original prefix work; its native derivation is checked only by resume.
    pub const fn prefix_work(&self) -> DwellWork {
        self.expected
    }

    /// Rebuild state by replaying the exact retained prefix. Actual work is reported separately
    /// and original logical counters are reproduced, not reset. No opaque state is accepted.
    pub fn resume(
        &self,
        deployment: &ReferenceDeployment,
        allowed: &DwellRestoreLimits,
        cx: &ReplayCx,
    ) -> Result<IncrementalDwell<'_>> {
        if self.expected.source_positions > allowed.maximum_prefix_frames {
            return Err(WatchError::Limit);
        }
        super::limits::validate_within(&self.prepared.limits, &allowed.execution)?;
        checkpoint(cx, "incremental_dwell:restore")?;
        let mut running = self.prepared.start()?;
        running.advance(deployment, self.expected.source_positions, cx)?;
        if running.work() != self.expected || running.record()? != self.bytes {
            return Err(WatchError::InvalidPlan(
                "native checkpoint reconstruction diverged",
            ));
        }
        // Recheck retained graph bytes after native work so cached metadata cannot repair or
        // bless custody which disappeared during reconstruction.
        let current = Self::open(deployment, self.pin, allowed, cx)?;
        if current.bytes != self.bytes {
            return Err(WatchError::Conflict);
        }
        running.restoration_work = running.work();
        checkpoint(cx, "incremental_dwell:restored")?;
        Ok(running)
    }
}

struct DecodedRecipe {
    plan: WatchPlan,
    rule: DwellPolicy,
    options: WatchOptions,
    limits: LongDwellLimits,
}

fn validate_digest(value: ContentDigest) -> Result<()> {
    if value.algorithm() != DigestAlgorithm::Sha256 || value.bytes() == [0; 32] {
        return Err(WatchError::Conflict);
    }
    Ok(())
}
fn count(d: &mut CanonicalDecoder<'_>, maximum: usize) -> Result<usize> {
    let value = usize::try_from(d.u64()?).map_err(|_| WatchError::Limit)?;
    if value > maximum {
        return Err(WatchError::Limit);
    }
    Ok(value)
}

fn decode_recipe(bytes: &[u8]) -> Result<DecodedRecipe> {
    use super::super::recorded_decode::ComponentInterpretation;
    use super::super::recorded_watch::{WatchDetectorConfig, WatchTrackerConfig};
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != RECIPE_DOMAIN
        || d.digest()? != ContentDigest::sha256(POLICY)
        || d.digest()? != ContentDigest::sha256(&fss_codec_mjpeg::decoder_identity())
    {
        return Err(WatchError::InvalidPlan(
            "unsupported incremental dwell recipe",
        ));
    }
    let site = d.text()?;
    crate::reference_deployment::validate_site_lineage(site)?;
    if site.len() > 256 {
        return Err(WatchError::Limit);
    }
    let principal = d.text()?;
    PrincipalId::parse(principal)?;
    if principal.len() > 128 {
        return Err(WatchError::Limit);
    }
    let expected_plan = d.digest()?;
    let import_identity = d.digest()?;
    validate_digest(import_identity)?;
    let first_segment = usize::try_from(d.u64()?).map_err(|_| WatchError::Limit)?;
    let segment_count = count(&mut d, MAX_LONG_DWELL_FRAMES)?;
    let zones_count = count(&mut d, super::super::recorded_watch::MAX_WATCH_ZONES)?;
    let mut zones = Vec::with_capacity(zones_count);
    for _ in 0..zones_count {
        let zone_id = d.text()?;
        if zone_id.len() > 64 {
            return Err(WatchError::Limit);
        }
        zones.push(WatchZone {
            zone_id: zone_id.to_owned(),
            x: d.u32()?,
            y: d.u32()?,
            width: d.u32()?,
            height: d.u32()?,
        });
    }
    if d.u64()? != 11 {
        return Err(WatchError::Conflict);
    }
    let mut p = [0_u64; 11];
    for value in &mut p {
        *value = d.u64()?;
    }
    if p[9] != 1_f64.to_bits() || p[10] != 1_f64.to_bits() {
        return Err(WatchError::Conflict);
    }
    let plan = WatchPlan {
        import_identity,
        first_segment,
        segment_count,
        zones,
        interpretation: match p[0] {
            0 => ComponentInterpretation::Grayscale,
            1 => ComponentInterpretation::YCbCr,
            _ => return Err(WatchError::Conflict),
        },
        detector: WatchDetectorConfig {
            base_threshold: u16::try_from(p[1]).map_err(|_| WatchError::Limit)?,
            threshold_sigma: u16::try_from(p[2]).map_err(|_| WatchError::Limit)?,
            learning_rate_num: u16::try_from(p[3]).map_err(|_| WatchError::Limit)?,
            learning_rate_den: u16::try_from(p[4]).map_err(|_| WatchError::Limit)?,
            minimum_region_pixels: usize::try_from(p[5]).map_err(|_| WatchError::Limit)?,
        },
        tracker: WatchTrackerConfig {
            confirmation_hits: u32::try_from(p[6]).map_err(|_| WatchError::Limit)?,
            maximum_missed_frames: u32::try_from(p[7]).map_err(|_| WatchError::Limit)?,
            minimum_iou_ppm: u32::try_from(p[8]).map_err(|_| WatchError::Limit)?,
        },
    };
    let rule = DwellPolicy {
        minimum_duration_ns: d.u64()?,
        maximum_sample_gap_ns: d.u64()?,
        minimum_observations: count(&mut d, MAX_LONG_DWELL_FRAMES)?,
    };
    let options = WatchOptions {
        tolerate_decode_refusals: d.bool()?,
    };
    let limits = super::limits::decode_limits(&mut d)?;
    validate_digest(d.digest()?)?;
    validate_digest(d.digest()?)?;
    let anchor = LedgerAnchor::decode_canonical(&mut d)?;
    if anchor.site_lineage != site {
        return Err(WatchError::Conflict);
    }
    SensorId::parse(d.text()?)?;
    validate_digest(d.digest()?)?;
    if d.bool()? && d.u64()? == 0 {
        return Err(WatchError::Conflict);
    }
    d.ensure_finished()?;
    if segment_count == 0
        || first_segment.checked_add(segment_count).is_none()
        || plan.digest() != expected_plan
    {
        return Err(WatchError::Conflict);
    }
    rule.validate().map_err(dwell_error)?;
    limits.validate()?;
    let mut admission = plan.clone();
    admission.segment_count = 1;
    admission.validate()?;
    Ok(DecodedRecipe {
        plan,
        rule,
        options,
        limits,
    })
}
