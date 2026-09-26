#![forbid(unsafe_code)]
//! Canonical/fault contracts; generated identities are structural fixtures, not model output.
use super::*;
use crate::ingest::http_archive::HttpWireScope;
use crate::ingest::rgb_archive::{RgbArchiveAuthority, RgbArchiveOperation};
use crate::ReferenceDeployment;
use crate::ingest::rgb_evidence::RgbEvidenceBudget;
use fss_codec_mjpeg::stream::StreamBasis;
use fss_core::{CaptureInterval, SensorId, TimestampNs};
use fss_twin::image_tracking::ImageTrackingPolicy;
use fss_twin::image_zones::{ImageZoneBasis, ImageZonePolicy, ImageZoneSpec};
use std::cell::Cell;
use std::path::PathBuf;

type Test = std::result::Result<(), Box<dyn Error>>;
const WORK: u64 = 100_000_000_000;
fn spec() -> Result<HttpRgbHistorySpec> {
    Ok(HttpRgbHistorySpec {
        source: HttpWireScope { stream: StreamBasis { source: [7; 32], generation: 3 }, receive_clock: [21; 32], retention_evidence: [22; 32] },
        sensor: SensorId::parse("sensor:history-test").map_err(backend)?,
        validity: CaptureInterval { earliest: TimestampNs(0), latest: TimestampNs(100_000_000_000) },
        episode: [9; 32], head: ContentDigest::sha256(b"head"), model: ContentDigest::sha256(b"model"),
        retention: ContentDigest::sha256(b"retention"), class_index: 0, class_selection: ContentDigest::sha256(b"class"),
        tracking: ImageTrackingPolicy { maximum_tracks: 8, maximum_detections: 8, maximum_exposures: 100,
            minimum_observations: 2, maximum_misses: 2, maximum_gap_ns: 10_000_000_000,
            maximum_speed: 100, gate_padding: 4, miss_cost: 1000, ambiguity_margin: 0 },
        basis: ImageZoneBasis { camera: 1, clock: 2, image_domain: [3; 32], calibration: [4; 32], dimensions: [32, 16] },
        zone_policy: ImageZonePolicy { selection_evidence: [8; 32], maximum_sample_gap_ns: 10_000_000_000 },
        zones: vec![ImageZoneSpec { id: 1, vertices: vec![[14, 1], [30, 1], [30, 15], [14, 15]], margin: 0, dwell_ns: Some(1_000_000_000) }],
    })
}
fn fixture(count: usize) -> Result<HttpRgbHistory> {
    let config = HttpRgbHistoryConfig::new(spec()?, &mut WorkBudget::new(WORK))?;
    let wire = HttpWirePin { scope: config.spec().source.digest().map_err(backend)?, head: ContentDigest::sha256(b"wire"), reads: 1, bytes: 10000 };
    let frames = (0..count).map(|index| {
        let id = ContentDigest::sha256(&(index as u64).to_le_bytes());
        HttpRgbEvidencePin {
            archive: RgbArchivePin { root: id, evidence: id, retention: config.spec().retention,
                capture: [(index as u64 + 1) * 1_000_000_000; 2] },
            wire, exposure: id.bytes(), ordinal: index as u64 + 1,
            encoded: ContentDigest::sha256(b"identical JPEG bytes in distinct HTTP parts").bytes(),
            stages: [id.bytes(); 4], mask_policy: None, mask_generation: None,
        }
    }).collect();
    Ok(HttpRgbHistory { config, frames, complete: None })
}
#[test]
fn native_config_roundtrip_binds_every_policy_and_normalizes_zones() -> Test {
    let config = HttpRgbHistoryConfig::new(spec()?, &mut WorkBudget::new(WORK))?;
    let decoded = HttpRgbHistoryConfig::decode(config.encoded(), config.identity(), &mut WorkBudget::new(WORK))?;
    assert_eq!(decoded.spec(), config.spec());
    assert_eq!(decoded.initial_stages(), config.initial_stages());
    assert_eq!(decoded.zone_config(), config.zone_config());
    for field in 0..8 {
        let mut changed = spec()?;
        match field {
            0 => changed.episode[0] ^= 1,
            1 => changed.tracking.minimum_observations += 1,
            2 => changed.tracking.maximum_speed += 1,
            3 => changed.zone_policy.maximum_sample_gap_ns += 1,
            4 => changed.zones[0].dwell_ns = None,
            5 => changed.class_index = 1,
            6 => changed.sensor = SensorId::parse("sensor:other")?,
            _ => changed.source.stream.generation += 1,
        }
        let changed = HttpRgbHistoryConfig::new(changed, &mut WorkBudget::new(WORK))?;
        assert_ne!(config.identity(), changed.identity());
    }
    let mut reversed = spec()?; reversed.zones[0].vertices.reverse();
    let reversed = HttpRgbHistoryConfig::new(reversed, &mut WorkBudget::new(WORK))?;
    assert_eq!(config.zone_config(), reversed.zone_config());
    Ok(())
}
#[test]
fn every_config_and_history_truncation_and_trailing_byte_is_refused() -> Test {
    let history = fixture(2)?;
    let bytes = history.record()?;
    assert_eq!(HttpRgbHistory::decode(&bytes, history.config.clone())?.tip()?, history.tip()?);
    for n in 0..bytes.len() { assert!(HttpRgbHistory::decode(&bytes[..n], history.config.clone()).is_err()); }
    let mut trailing = bytes; trailing.push(0);
    assert!(HttpRgbHistory::decode(&trailing, history.config.clone()).is_err());
    let config = history.config.encoded();
    for n in 0..config.len() {
        assert!(HttpRgbHistoryConfig::decode(&config[..n], ContentDigest::sha256(&config[..n]), &mut WorkBudget::new(WORK)).is_err());
    }
    Ok(())
}
#[test]
fn gaps_duplicates_reordering_retention_and_privacy_changes_cannot_join_an_episode() -> Test {
    let base = fixture(2)?; base.validate()?;
    assert_eq!(base.frames[0].encoded, base.frames[1].encoded);
    for field in 0..8 {
        let mut changed = base.clone();
        match field {
            0 => changed.frames.swap(0, 1),
            1 => changed.frames[1].ordinal = 3,
            2 => changed.frames[1].exposure = changed.frames[0].exposure,
            3 => changed.frames[1].archive.capture = changed.frames[0].archive.capture,
            4 => changed.frames[1].archive.retention = ContentDigest::sha256(b"rival"),
            5 => changed.frames[1].mask_policy = Some(ContentDigest::sha256(b"mask")),
            6 => changed.frames[1].wire.head = ContentDigest::sha256(b"rival chain"),
            _ => changed.frames[1].archive.capture = [u64::MAX; 2],
        }
        assert!(changed.record().is_err());
    }
    Ok(())
}
#[test]
fn bounded_complete_prefix_keeps_every_pin_and_sealing_is_a_distinct_revision() -> Test {
    let mut history = fixture(MAX_HISTORY_FRAMES)?;
    assert!(history.record()?.len() < MAX_HISTORY_BYTES);
    for n in 0..=MAX_HISTORY_FRAMES {
        let prefix = history.at_revision(n)?;
        assert_eq!(prefix.frames().len(), n);
        assert_eq!(prefix.tip()?.revision, n as u64);
        assert!(!prefix.is_complete());
    }
    let prior = history.tip()?;
    history.complete = Some(HttpCompletionPin { root: ContentDigest::sha256(b"native end"), wire: history.frames[0].wire });
    let sealed = history.tip()?;
    assert_ne!(prior.root, sealed.root);
    assert_eq!(sealed.revision, prior.revision + 1);
    assert!(HttpRgbHistory::decode(&history.record()?, history.config.clone())?.is_complete());
    history.frames.push(history.frames[0]);
    assert!(matches!(history.record(), Err(HistoryError::Limit)));
    Ok(())
}
#[test]
fn malformed_native_policy_and_work_exhaustion_refuse_config() -> Test {
    let mut invalid = spec()?; invalid.tracking.minimum_observations = 0;
    assert!(HttpRgbHistoryConfig::new(invalid, &mut WorkBudget::new(WORK)).is_err());
    let mut invalid = spec()?; invalid.zones[0].vertices[0] = [u32::MAX; 2];
    assert!(HttpRgbHistoryConfig::new(invalid, &mut WorkBudget::new(WORK)).is_err());
    assert!(HttpRgbHistoryConfig::new(spec()?, &mut WorkBudget::new(0)).is_err());
    Ok(())
}

struct Directory(PathBuf);
impl Directory {
    fn new() -> std::result::Result<Self, Box<dyn Error>> {
        for n in 0..128 {
            let path = std::env::temp_dir().join(format!("fss-rgb-history-{}-{n}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("test directory bound".into())
    }
    fn cx(&self) -> std::result::Result<ReplayCx, Box<dyn Error>> {
        use fss_core::region::{ContextAuthority, RootAuthoritySpec};
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:rgb-history".into(), operation_id: fss_core::OperationId::parse("operation:rgb-history")?,
            principal: "principal:history-test".into(), capabilities: vec!["ADP-REPLAY-001".into()], deadline: None, priority: 10,
            budgets: fss_core::BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
            privacy_scope: "privacy:test".into(), retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"site:history-test"), generation: 1,
        })?;
        Ok(ReplayCx::from_context_authority(&authority, self.0.clone())?)
    }
}
impl Drop for Directory { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
struct Access { read: Cell<bool>, write: Cell<bool> }
impl HistoryAuthority for Access {
    fn permits(&self, op: HistoryOperation, _: ContentDigest) -> bool {
        match op { HistoryOperation::Read => self.read.get(), HistoryOperation::Retain => self.write.get() }
    }
}
impl RgbArchiveAuthority for Access { fn permits(&self, _: RgbArchiveOperation, _: ContentDigest, _: ContentDigest) -> bool { false } }
#[test]
fn header_is_discovered_after_cold_reopen_and_exact_retry_does_not_append() -> Test {
    let dir = Directory::new()?; let cx = dir.cx()?;
    let root = dir.0.join("deployment");
    let access = Access { read: Cell::new(true), write: Cell::new(true) };
    let history = fixture(0)?; let tip = history.tip()?;
    let mut d = ReferenceDeployment::open(&root, "site:history-test", &cx)?;
    let first = history.publish(tip, &mut d, HistoryAccess { history: &access, evidence: &access }, HistoryLimits::default(), &mut RgbEvidenceBudget::new(WORK), &mut WorkBudget::new(WORK), &cx)?;
    let anchor = d.current_anchor().clone(); drop(d);
    let mut d = ReferenceDeployment::reopen(&root, "site:history-test", &cx)?;
    let recovery = read_latest_history(&mut d, tip.session, HistoryLimits::default(), &access, &mut WorkBudget::new(WORK), &cx)?;
    assert!(recovery.pending.is_none());
    let restored = recovery.committed.ok_or("missing committed configuration")?;
    assert_eq!(restored.config().spec(), history.config().spec());
    let retry = restored.publish(tip, &mut d, HistoryAccess { history: &access, evidence: &access }, HistoryLimits::default(), &mut RgbEvidenceBudget::new(WORK), &mut WorkBudget::new(WORK), &cx)?;
    assert_eq!(retry.outcome, fss_publication::RootLedgerOutcome::AlreadyLedgered);
    assert_eq!(retry.root, first.root); assert_eq!(d.current_anchor(), &anchor);
    access.read.set(false);
    assert!(matches!(read_latest_history(&mut d, tip.session, HistoryLimits::default(), &access, &mut WorkBudget::new(WORK), &cx), Err(HistoryError::Denied)));
    assert_eq!(d.current_anchor(), &anchor);
    Ok(())
}
#[test]
fn root_only_header_stays_pending_until_explicit_exact_reconciliation() -> Test {
    let dir = Directory::new()?; let cx = dir.cx()?; let root = dir.0.join("deployment");
    let access = Access { read: Cell::new(true), write: Cell::new(true) };
    let history = fixture(0)?; let tip = history.tip()?;
    let mut d = ReferenceDeployment::open(&root, "site:history-test", &cx)?;
    history.publish(tip, &mut d, HistoryAccess { history: &access, evidence: &access }, HistoryLimits::default(), &mut RgbEvidenceBudget::new(WORK), &mut WorkBudget::new(WORK), &cx)?;
    drop(d);
    // Plant root-durable / ledger-absent state only in this owned one-batch fixture.
    std::fs::write(root.join("ledger/journal.fssj"), [])?;
    let mut d = ReferenceDeployment::reopen(&root, "site:history-test", &cx)?;
    let recovery = read_latest_history(&mut d, tip.session, HistoryLimits::default(), &access, &mut WorkBudget::new(WORK), &cx)?;
    assert!(recovery.committed.is_none());
    let pending = recovery.pending.ok_or("root-only work disappeared")?;
    assert_eq!(pending.tip()?, tip); assert!(d.ledger().batches().is_empty());
    access.write.set(false);
    assert!(matches!(pending.publish(tip, &mut d, HistoryAccess { history: &access, evidence: &access }, HistoryLimits::default(), &mut RgbEvidenceBudget::new(WORK), &mut WorkBudget::new(WORK), &cx), Err(HistoryError::Denied)));
    assert!(d.ledger().batches().is_empty());
    access.write.set(true);
    pending.publish(tip, &mut d, HistoryAccess { history: &access, evidence: &access }, HistoryLimits::default(), &mut RgbEvidenceBudget::new(WORK), &mut WorkBudget::new(WORK), &cx)?;
    assert_eq!(d.ledger().batches().len(), 1);
    Ok(())
}
