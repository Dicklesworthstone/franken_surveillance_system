#![forbid(unsafe_code)]
//! Frozen, source-scoped replay ingredients for the existing temporal engines.
use super::{HistoryError, Result, backend, count, digest, raw};
use crate::ingest::http_archive::HttpWireScope;
use crate::ingest::rgb_detections::RgbDetectionContract;
use crate::ingest::rgb_tracking::{RgbTrackingContract, RgbZoneTracker};
use fss_codec_mjpeg::stream::StreamBasis;
use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, SensorId, CaptureInterval, TimestampNs};
use fss_geometry::WorkBudget;
use fss_twin::image_tracking::{ImageTracker, ImageTrackingPolicy};
use fss_twin::image_zones::{ImageZoneBasis, ImageZoneMonitor, ImageZonePolicy, ImageZoneSpec, MAX_IMAGE_ZONES, MAX_ZONE_VERTICES};

/// Canonical configuration identity. A change starts a different history, never a new policy
/// in the middle of an existing episode. Numerical engine identities remain unchanged.
pub const CONFIG_DOMAIN: &str = "fss.http_rgb_history_config.v1";
/// Complete canonical configuration bound, including all polygons.
pub const MAX_CONFIG_BYTES: usize = 16 * 1024;

/// Explicit replay inputs. Nothing is inferred from HTTP receive time or a model score.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpRgbHistorySpec {
    /// Original source generation, receive clock and original-byte retention scope.
    pub source: HttpWireScope,
    /// Named sensor whose current policy every numerical replay must resolve.
    pub sensor: SensorId,
    /// Owner-declared validity of this recording session; not inferred receive/capture time.
    pub validity: CaptureInterval,
    /// Independently chosen anonymous tracking episode, not a physical identity.
    pub episode: [u8; 32],
    /// Exact detector contract, including vocabulary and thresholds.
    pub head: ContentDigest,
    /// Exact neural/preprocessing generation.
    pub model: ContentDigest,
    /// Exact retention decision for the source-closed detector archives.
    pub retention: ContentDigest,
    /// Frozen vocabulary index for the existing temporal owner.
    pub class_index: usize,
    /// Evidence for the class selection, not an effect grant.
    pub class_selection: ContentDigest,
    /// Existing complete tracker policy, including lifetime and association bounds.
    pub tracking: ImageTrackingPolicy,
    /// Existing coordinate and capture-clock basis.
    pub basis: ImageZoneBasis,
    /// Existing zone timing/selection policy.
    pub zone_policy: ImageZonePolicy,
    /// Complete owner-selected zone set; normalized by the native zone engine.
    pub zones: Vec<ImageZoneSpec>,
}

/// Validated immutable configuration plus native initial-chain fingerprints.
#[derive(Clone, Debug)]
pub struct HttpRgbHistoryConfig {
    spec: HttpRgbHistorySpec,
    initial: [[u8; 32]; 2],
    zones: [u8; 32],
    bytes: Vec<u8>,
    identity: ContentDigest,
}
impl HttpRgbHistoryConfig {
    /// Validate with the actual tracker/zone constructors and retain their canonical polygons.
    /// No model execution, I/O or caller-provided fingerprint substitutes for these constructors.
    pub fn new(mut spec: HttpRgbHistorySpec, work: &mut WorkBudget<'_>) -> Result<Self> {
        if spec.episode == [0; 32] || spec.class_index >= 256
            || spec.validity.earliest > spec.validity.latest
            || ![spec.head, spec.model, spec.retention, spec.class_selection].into_iter().all(digest)
            || spec.zones.is_empty() || spec.zones.len() > MAX_IMAGE_ZONES
            || spec.zones.iter().any(|z| z.vertices.len() > MAX_ZONE_VERTICES)
        { return Err(HistoryError::Mismatch); }
        spec.source.digest().map_err(backend)?;
        let tracker = ImageTracker::new(spec.episode, spec.tracking, work).map_err(backend)?;
        let monitor = ImageZoneMonitor::new(&tracker, spec.basis, spec.zone_policy, &spec.zones, work).map_err(backend)?;
        work.charge(MAX_CONFIG_BYTES as u64).map_err(backend)?;
        spec.zones = monitor.zones().to_vec();
        let initial = [tracker.digest(), monitor.digest()];
        let zones = monitor.config_digest();
        let bytes = encode(&spec)?;
        if bytes.len() > MAX_CONFIG_BYTES { return Err(HistoryError::Limit); }
        let identity = ContentDigest::sha256(&bytes);
        Ok(Self { spec, initial, zones, bytes, identity })
    }
    /// Content identity used to discover this history in the existing canonical ledger.
    pub fn identity(&self) -> ContentDigest { self.identity }
    /// Complete canonical configuration, including all temporal assumptions.
    pub fn encoded(&self) -> &[u8] { &self.bytes }
    /// Frozen replay inputs. No mutable configuration escape exists.
    pub fn spec(&self) -> &HttpRgbHistorySpec { &self.spec }
    /// Actual initial tracking and zone-chain identities produced by the native constructors.
    pub fn initial_stages(&self) -> [[u8; 32]; 2] { self.initial }
    /// Native normalized zone configuration identity.
    pub fn zone_config(&self) -> [u8; 32] { self.zones }
    /// Start the actual existing temporal engine, validating the restored detector vocabulary.
    pub fn tracker(&self, head: &RgbDetectionContract, work: &mut WorkBudget<'_>) -> Result<RgbZoneTracker> {
        if head.digest() != self.spec.head || head.spec().model != self.spec.model {
            return Err(HistoryError::Mismatch);
        }
        let contract = RgbTrackingContract::new(head, self.spec.class_index, self.spec.class_selection).map_err(backend)?;
        RgbZoneTracker::new(self.spec.episode, contract, self.spec.tracking, self.spec.basis,
            self.spec.zone_policy, &self.spec.zones, work).map_err(backend)
    }
    /// Strict bounded canonical decode; numerical configuration validation is not bypassed.
    pub fn decode(bytes: &[u8], expected: ContentDigest, work: &mut WorkBudget<'_>) -> Result<Self> {
        if bytes.len() > MAX_CONFIG_BYTES { return Err(HistoryError::Limit); }
        work.charge(bytes.len() as u64).map_err(backend)?;
        if ContentDigest::sha256(bytes) != expected { return Err(HistoryError::Mismatch); }
        let mut d = CanonicalDecoder::new(bytes);
        if d.text().map_err(backend)? != CONFIG_DOMAIN { return Err(HistoryError::Mismatch); }
        let source = HttpWireScope {
            stream: StreamBasis { source: raw(&mut d)?, generation: d.u64().map_err(backend)? },
            receive_clock: raw(&mut d)?, retention_evidence: raw(&mut d)?,
        };
        let sensor = SensorId::parse(d.text().map_err(backend)?).map_err(backend)?;
        let validity = CaptureInterval::new(TimestampNs(d.i128().map_err(backend)?), TimestampNs(d.i128().map_err(backend)?)).map_err(backend)?;
        let episode = raw(&mut d)?;
        let head = d.digest().map_err(backend)?;
        let model = d.digest().map_err(backend)?;
        let retention = d.digest().map_err(backend)?;
        let class_index = count(&mut d, 255)?;
        let class_selection = d.digest().map_err(backend)?;
        let tracking = ImageTrackingPolicy {
            maximum_tracks: count(&mut d, 64)?, maximum_detections: count(&mut d, 64)?,
            maximum_exposures: count(&mut d, 4096)?,
            minimum_observations: d.u32().map_err(backend)?, maximum_misses: d.u32().map_err(backend)?,
            maximum_gap_ns: d.u64().map_err(backend)?, maximum_speed: d.u32().map_err(backend)?,
            gate_padding: d.u32().map_err(backend)?, miss_cost: d.u32().map_err(backend)?,
            ambiguity_margin: d.u32().map_err(backend)?,
        };
        let basis = ImageZoneBasis { camera: d.u64().map_err(backend)?, clock: d.u64().map_err(backend)?,
            calibration: raw(&mut d)?, image_domain: raw(&mut d)?,
            dimensions: [d.u32().map_err(backend)?, d.u32().map_err(backend)?] };
        let zone_policy = ImageZonePolicy { selection_evidence: raw(&mut d)?, maximum_sample_gap_ns: d.u64().map_err(backend)? };
        let n = count(&mut d, MAX_IMAGE_ZONES)?;
        let mut zones = Vec::with_capacity(n);
        for _ in 0..n {
            let id = d.u64().map_err(backend)?;
            let margin = d.u32().map_err(backend)?;
            let dwell_ns = if d.bool().map_err(backend)? { Some(d.u64().map_err(backend)?) } else { None };
            let n = count(&mut d, MAX_ZONE_VERTICES)?;
            let mut vertices = Vec::with_capacity(n);
            for _ in 0..n { vertices.push([d.u32().map_err(backend)?, d.u32().map_err(backend)?]); }
            zones.push(ImageZoneSpec { id, vertices, margin, dwell_ns });
        }
        d.ensure_finished().map_err(backend)?;
        let config = Self::new(HttpRgbHistorySpec { source, sensor, validity, episode, head, model, retention,
            class_index, class_selection, tracking, basis, zone_policy, zones }, work)?;
        if config.bytes != bytes { return Err(HistoryError::Mismatch); }
        Ok(config)
    }
}
fn encode(s: &HttpRgbHistorySpec) -> Result<Vec<u8>> {
    let mut e = CanonicalEncoder::new();
    e.text(CONFIG_DOMAIN);
    e.digest(super::sha(s.source.stream.source)); e.u64(s.source.stream.generation);
    e.digest(super::sha(s.source.receive_clock)); e.digest(super::sha(s.source.retention_evidence));
    e.text(s.sensor.as_str()); e.i128(s.validity.earliest.0); e.i128(s.validity.latest.0); e.digest(super::sha(s.episode));
    for d in [s.head, s.model, s.retention] { e.digest(d); }
    e.u64(s.class_index as u64); e.digest(s.class_selection);
    for n in [s.tracking.maximum_tracks, s.tracking.maximum_detections, s.tracking.maximum_exposures] { e.u64(n as u64); }
    e.u32(s.tracking.minimum_observations); e.u32(s.tracking.maximum_misses); e.u64(s.tracking.maximum_gap_ns);
    e.u32(s.tracking.maximum_speed); e.u32(s.tracking.gate_padding); e.u32(s.tracking.miss_cost); e.u32(s.tracking.ambiguity_margin);
    e.u64(s.basis.camera); e.u64(s.basis.clock); e.digest(super::sha(s.basis.calibration)); e.digest(super::sha(s.basis.image_domain));
    for n in s.basis.dimensions { e.u32(n); }
    e.digest(super::sha(s.zone_policy.selection_evidence)); e.u64(s.zone_policy.maximum_sample_gap_ns);
    e.u64(s.zones.len() as u64);
    for z in &s.zones {
        e.u64(z.id); e.u32(z.margin); e.bool(z.dwell_ns.is_some());
        if let Some(n) = z.dwell_ns { e.u64(n); }
        e.u64(z.vertices.len() as u64);
        for p in &z.vertices { e.u32(p[0]); e.u32(p[1]); }
    }
    e.finish_checked().map_err(backend)
}
