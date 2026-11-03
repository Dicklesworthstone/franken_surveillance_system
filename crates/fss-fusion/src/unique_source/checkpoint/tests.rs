#![forbid(unsafe_code)]
//! Continuation parity, adversarial envelopes and lifetime replay/capacity contracts.

use super::*;
use crate::{
    Calibration, Coverage, EProcessConfig, EvidenceItem, FusionOutcome, FusionPolicy, FusionQuery,
    LlrInterval, Observability, RegimeResetReason, Severity, SourceDisposition, UniqueSourceError,
    UniqueSourceStepOutcome,
};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
type Bindings = BTreeMap<String, Option<ContentDigest>>;

fn item(id: &str, sensor: &str, lo: i64, hi: i64) -> Result<EvidenceItem> {
    Ok(EvidenceItem {
        id: id.to_owned(),
        sensor: sensor.to_owned(),
        failure_domains: [format!("sensor:{sensor}")].into_iter().collect(),
        calibration: Calibration::Calibrated {
            generation: "cal:v1".to_owned(),
            llr: LlrInterval::new(lo, hi).map_err(|_| UniqueSourceCheckpointError::InvalidState)?,
        },
        observability: Observability::Observed,
    })
}

fn query(evidence: Vec<EvidenceItem>) -> Result<FusionQuery> {
    Ok(FusionQuery {
        hypothesis: "hyp:door".to_owned(),
        kind: "zone_entry".to_owned(),
        prior: LlrInterval::point(0).map_err(|_| UniqueSourceCheckpointError::InvalidState)?,
        evidence,
        coverage: Coverage::Complete,
        opportunities: Vec::new(),
        probes: Vec::new(),
        severity: Severity {
            expected_harm: 10_000,
            false_alert_cost: 500,
            delay_cost_per_second: 100,
            reversible: false,
        },
        policy: FusionPolicy {
            generation: "policy:v1".to_owned(),
            alert_threshold: 1_800,
            retain_threshold: 0,
            reject_threshold: -1_000,
            min_independent_support: 2,
            urgent_single_domain_threshold: None,
            max_wait_ns: 0,
            look_penalty_per_doubling: 0,
            operator_confirmation_available: false,
        },
        looks: 1,
        now_ns: 1_000_000_000,
    })
}

fn bindings(rows: &[(&str, &str)]) -> Bindings {
    rows.iter()
        .map(|(id, source)| {
            (
                (*id).to_owned(),
                Some(ContentDigest::sha256(source.as_bytes())),
            )
        })
        .collect()
}

fn process(limit: usize) -> std::result::Result<UniqueSourceEProcess, UniqueSourceError> {
    UniqueSourceEProcess::new("hyp:door", EProcessConfig::default(), limit)
}

fn restored(process: &UniqueSourceEProcess) -> Result<UniqueSourceEProcess> {
    let checkpoint = process.checkpoint()?;
    let restored = UniqueSourceEProcess::from_checkpoint(checkpoint.bytes(), checkpoint.digest())?;
    assert_eq!(restored.checkpoint()?, checkpoint);
    assert_eq!(restored.inventory_digest(), process.inventory_digest());
    assert_eq!(restored.transcript_head(), process.transcript_head());
    assert_eq!(
        restored.accumulator().transcript_head(),
        process.accumulator().transcript_head()
    );
    assert_eq!(
        restored.admitted_sources().collect::<Vec<_>>(),
        process.admitted_sources().collect::<Vec<_>>()
    );
    Ok(restored)
}

#[test]
fn initial_snapshot_preserves_config_without_inventing_a_history() -> TestResult {
    let original = process(2)?;
    let checkpoint = original.checkpoint()?;
    assert_eq!(&checkpoint.bytes()[..8], &UNIQUE_SOURCE_CHECKPOINT_MAGIC);
    assert_eq!(checkpoint.bytes().len(), 195);
    // Independently constructed header/payload/footer fixture freezes the v1 wire identity.
    assert_eq!(
        checkpoint.digest().to_text(),
        "sha256:e9ad276059bebdca9ed155e8e68917318224821698dd1fdb5deb40758c866a52"
    );
    assert_eq!(
        checkpoint.digest(),
        ContentDigest::sha256(checkpoint.bytes())
    );
    let next = restored(&original)?;
    assert_eq!(next.accumulator().step_index(), 0);
    assert_eq!(next.sources_seen(), 0);
    assert_eq!(next.source_limit(), 2);
    assert_eq!(next.transcript_head(), None);
    assert_eq!(next.accumulator().transcript_head(), None);
    let config = EProcessConfig {
        alert_threshold_mban: 1_300,
        floor_mban: -500,
        ceiling_mban: 1_700,
        min_independent_clusters: 3,
    };
    let configured = UniqueSourceEProcess::new("hyp:door", config, 2)?;
    assert_eq!(*restored(&configured)?.accumulator().config(), config);
    assert_ne!(configured.checkpoint()?.digest(), checkpoint.digest());
    assert!(matches!(
        UniqueSourceEProcess::from_checkpoint(
            configured.checkpoint()?.bytes(),
            checkpoint.digest()
        ),
        Err(UniqueSourceCheckpointError::DigestMismatch)
    ));
    Ok(())
}

#[derive(Clone)]
enum Transition {
    Observe(Box<FusionQuery>, Bindings),
    Reset(RegimeResetReason),
}

impl Transition {
    fn observe(query: FusionQuery, bindings: Bindings) -> Self {
        Self::Observe(Box::new(query), bindings)
    }

    fn apply(
        &self,
        process: &mut UniqueSourceEProcess,
    ) -> std::result::Result<(Option<FusionOutcome>, UniqueSourceStepOutcome), UniqueSourceError>
    {
        match self {
            Self::Observe(query, bindings) => {
                let (fusion, step) = process.observe_step(query, bindings)?;
                Ok((Some(fusion), step))
            }
            Self::Reset(reason) => Ok((None, process.reset_regime(reason.clone()))),
        }
    }
}

#[test]
fn every_checkpoint_cut_preserves_complete_future_observation_and_reset_receipts() -> TestResult {
    let mut east = item("east", "east", 700, 900)?;
    east.failure_domains.insert("model:a".into());
    let mut west = item("west", "west", 800, 1_100)?;
    west.failure_domains.insert("model:b".into());
    let mut bridge = item("bridge", "north", 400, 600)?;
    bridge
        .failure_domains
        .extend(["model:a".into(), "model:b".into()]);
    let mut alias = east.clone();
    alias.id = "east:retry".into();
    let mut neutral = item("missing", "south", 700, 900)?;
    neutral.observability = Observability::NotObservable {
        reason: "occluded".into(),
    };
    let mut retry_bindings = bindings(&[("east:retry", "frame:east")]);
    retry_bindings.insert("missing".into(), None);
    let mut missing_query = query(vec![alias.clone(), neutral])?;
    missing_query.coverage = Coverage::Gap {
        reason: "south occluded".into(),
    };
    let steps = vec![
        Transition::observe(query(vec![east])?, bindings(&[("east", "frame:east")])),
        Transition::observe(query(vec![west])?, bindings(&[("west", "frame:west")])),
        Transition::observe(missing_query, retry_bindings),
        Transition::observe(query(vec![bridge])?, bindings(&[("bridge", "frame:north")])),
        Transition::Reset(RegimeResetReason::SensorHealthDegraded {
            sensor: "east".into(),
            reason: "camera moved\n\0observed".into(),
        }),
        Transition::observe(
            query(vec![alias])?,
            bindings(&[("east:retry", "frame:east")]),
        ),
        Transition::observe(
            query(vec![item("refute", "south", -900, -400)?])?,
            bindings(&[("refute", "frame:south")]),
        ),
        Transition::Reset(RegimeResetReason::ClockContinuityBroken {
            sensor: "south".into(),
            gap_ns: u64::MAX,
        }),
        Transition::observe(
            query(vec![item("later", "east", 500, 800)?])?,
            bindings(&[("later", "frame:east:later")]),
        ),
        Transition::Reset(RegimeResetReason::OperatorReset { reason: "".into() }),
        Transition::observe(
            query(vec![item("last", "west", 500, 800)?])?,
            bindings(&[("last", "frame:west:later")]),
        ),
    ];
    for config in [
        EProcessConfig::default(),
        EProcessConfig {
            floor_mban: -700,
            ceiling_mban: 1_900,
            ..EProcessConfig::default()
        },
    ] {
        for cut in 0..=steps.len() {
            let mut uninterrupted = UniqueSourceEProcess::new("hyp:door", config, 8)?;
            for transition in &steps[..cut] {
                transition.apply(&mut uninterrupted)?;
            }
            let mut resumed = restored(&uninterrupted)?;
            for transition in &steps[cut..] {
                assert_eq!(
                    transition.apply(&mut uninterrupted)?,
                    transition.apply(&mut resumed)?
                );
            }
            assert_eq!(uninterrupted.checkpoint()?, resumed.checkpoint()?);
        }
    }
    Ok(())
}

#[test]
fn replay_conflict_and_exhausted_capacity_survive_cold_resume_and_reset() -> TestResult {
    let mut original = process(2)?;
    let initial = query(vec![
        item("east", "east", 700, 900)?,
        item("west", "west", 700, 900)?,
    ])?;
    original.observe_step(&initial, &bindings(&[("east", "east"), ("west", "west")]))?;
    let mut resumed = restored(&original)?;
    let replay = query(vec![item("new-alias", "east", 700, 900)?])?;
    let (_, receipt) = resumed.observe_step(&replay, &bindings(&[("new-alias", "east")]))?;
    assert_eq!(receipt.step().step_delta_llr, LlrInterval::point(0)?);
    assert_eq!(
        receipt.admissions()[0].disposition(),
        SourceDisposition::AlreadyAdmitted
    );
    assert_eq!(receipt.admissions()[0].first_admitted_step(), Some(1));
    let before = resumed.checkpoint()?;
    let conflict = query(vec![item("new-alias", "east", 701, 900)?])?;
    assert!(matches!(
        resumed.observe_step(&conflict, &bindings(&[("new-alias", "east")])),
        Err(UniqueSourceError::ConflictingSource { .. })
    ));
    assert_eq!(resumed.checkpoint()?, before);
    resumed.reset_regime(RegimeResetReason::OperatorReset {
        reason: "health recovered".into(),
    });
    let mut resumed = restored(&resumed)?;
    let before = resumed.checkpoint()?;
    let extra = query(vec![item("south", "south", 700, 900)?])?;
    assert!(matches!(
        resumed.observe_step(&extra, &bindings(&[("south", "south")])),
        Err(UniqueSourceError::SourceCapacity {
            limit: 2,
            existing: 2,
            additional: 1
        })
    ));
    assert_eq!(resumed.checkpoint()?, before);
    let (_, receipt) = resumed.observe_step(&replay, &bindings(&[("new-alias", "east")]))?;
    assert_eq!(receipt.step().accumulated_llr, LlrInterval::point(0)?);
    assert_eq!(receipt.sources_seen(), 2);
    Ok(())
}

fn envelope(payload: &[u8]) -> Vec<u8> {
    let mut bytes = UNIQUE_SOURCE_CHECKPOINT_MAGIC.to_vec();
    bytes.extend_from_slice(&UNIQUE_SOURCE_CHECKPOINT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    bytes.extend_from_slice(payload);
    let checksum = ContentDigest::sha256(&bytes);
    bytes.extend_from_slice(&checksum.bytes());
    bytes
}

fn payload(checkpoint: &UniqueSourceCheckpoint) -> Vec<u8> {
    checkpoint.bytes()[HEADER_BYTES..checkpoint.bytes().len() - CHECKSUM_BYTES].to_vec()
}

fn refuses(payload: &[u8]) {
    let bytes = envelope(payload);
    assert!(UniqueSourceEProcess::from_checkpoint(&bytes, ContentDigest::sha256(&bytes)).is_err());
}

#[test]
fn external_pin_precedes_format_parsing_and_footer_is_independently_checked() -> TestResult {
    let checkpoint = process(2)?.checkpoint()?;
    let wrong = ContentDigest::sha256(b"different custody identity");
    assert!(matches!(
        UniqueSourceEProcess::from_checkpoint(b"not a checkpoint", wrong),
        Err(UniqueSourceCheckpointError::DigestMismatch)
    ));
    assert!(matches!(
        UniqueSourceEProcess::from_checkpoint(
            checkpoint.bytes(),
            ContentDigest::new(DigestAlgorithm::Blake3, checkpoint.digest().bytes())
        ),
        Err(UniqueSourceCheckpointError::DigestMismatch)
    ));
    assert!(matches!(
        UniqueSourceEProcess::from_checkpoint(
            checkpoint.bytes(),
            checkpoint.digest().with_laboratory(true)
        ),
        Err(UniqueSourceCheckpointError::DigestMismatch)
    ));
    let mut changed = checkpoint.bytes().to_vec();
    changed[HEADER_BYTES] ^= 1;
    assert!(matches!(
        UniqueSourceEProcess::from_checkpoint(&changed, checkpoint.digest()),
        Err(UniqueSourceCheckpointError::DigestMismatch)
    ));
    assert!(matches!(
        UniqueSourceEProcess::from_checkpoint(&changed, ContentDigest::sha256(&changed)),
        Err(UniqueSourceCheckpointError::DigestMismatch)
    ));
    changed = checkpoint.bytes().to_vec();
    changed[8..12].copy_from_slice(&2_u32.to_be_bytes());
    assert!(matches!(
        UniqueSourceEProcess::from_checkpoint(&changed, checkpoint.digest()),
        Err(UniqueSourceCheckpointError::DigestMismatch)
    ));
    assert!(matches!(
        UniqueSourceEProcess::from_checkpoint(&changed, ContentDigest::sha256(&changed)),
        Err(UniqueSourceCheckpointError::UnsupportedVersion)
    ));
    for length in 0..checkpoint.bytes().len() {
        let truncated = &checkpoint.bytes()[..length];
        assert!(
            UniqueSourceEProcess::from_checkpoint(truncated, ContentDigest::sha256(truncated))
                .is_err()
        );
    }
    for excess in [b"\0".as_slice(), b"appended frame".as_slice()] {
        let bytes = [checkpoint.bytes(), excess].concat();
        assert!(
            UniqueSourceEProcess::from_checkpoint(&bytes, ContentDigest::sha256(&bytes)).is_err()
        );
    }
    let oversized = vec![0; MAX_UNIQUE_SOURCE_CHECKPOINT_BYTES + 1];
    assert!(matches!(
        UniqueSourceEProcess::from_checkpoint(&oversized, wrong),
        Err(UniqueSourceCheckpointError::Limit)
    ));
    Ok(())
}

#[test]
fn hostile_initial_state_fields_cannot_create_statistics_or_transcript_ancestry() -> TestResult {
    let body = payload(&process(2)?.checkpoint()?);
    // Frozen v1 payload offsets for the eight-byte hypothesis and absent transcript heads.
    // Config starts at 25; index at 77, epoch at 85, interval at 89/105, supremum at 121.
    for (offset, value) in [(25, 0_i128), (41, 1), (57, 1), (89, 1), (105, -1), (121, 1)] {
        let mut corrupted = body.clone();
        corrupted[offset..offset + 16].copy_from_slice(&value.to_be_bytes());
        refuses(&corrupted);
    }
    for (offset, value) in [
        (0, 0_u32),
        (0, u32::MAX),
        (4, u32::MAX),
        (73, 0),
        (85, 1),
        (139, 1),
    ] {
        let mut corrupted = body.clone();
        corrupted[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        refuses(&corrupted);
    }
    let mut corrupted = body.clone();
    corrupted[77..85].copy_from_slice(&1_u64.to_be_bytes());
    refuses(&corrupted);
    for offset in [8, 137, 138] {
        let mut corrupted = body.clone();
        corrupted[offset] = 255;
        refuses(&corrupted);
    }
    let mut corrupted = body.clone();
    corrupted[9..17].copy_from_slice(&u64::MAX.to_be_bytes());
    refuses(&corrupted);
    let mut corrupted = body.clone();
    corrupted[17] = 0xff;
    refuses(&corrupted);
    let mut corrupted = body.clone();
    corrupted.push(0);
    refuses(&corrupted);
    Ok(())
}

#[test]
fn source_inventory_order_types_capacity_and_first_step_are_strict() -> TestResult {
    let mut original = process(4)?;
    original.observe_step(
        &query(vec![
            item("east", "east", 700, 900)?,
            item("west", "west", 700, 900)?,
        ])?,
        &bindings(&[("east", "east"), ("west", "west")]),
    )?;
    let body = payload(&original.checkpoint()?);
    let first = 8;
    let second = first + SOURCE_RECORD_BYTES;
    let mut swapped = body.clone();
    swapped[first..second].copy_from_slice(&body[second..second + SOURCE_RECORD_BYTES]);
    swapped[second..second + SOURCE_RECORD_BYTES].copy_from_slice(&body[first..second]);
    refuses(&swapped);
    let mut duplicate = body.clone();
    duplicate[second..second + SOURCE_RECORD_BYTES].copy_from_slice(&body[first..second]);
    refuses(&duplicate);
    for index in [0_u64, 2, u64::MAX] {
        let mut corrupted = body.clone();
        corrupted[first + 66..first + 74].copy_from_slice(&index.to_be_bytes());
        refuses(&corrupted);
    }
    for (offset, tag) in [(first, 0_u8), (first, 3), (first + 33, 2)] {
        let mut corrupted = body.clone();
        corrupted[offset] = tag;
        refuses(&corrupted);
    }
    let mut limited = body.clone();
    limited[..4].copy_from_slice(&1_u32.to_be_bytes());
    refuses(&limited);
    let mut extended = body.clone();
    extended[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
    refuses(&extended);
    Ok(())
}

#[test]
fn supporting_domains_must_remain_disjoint_ordered_and_source_bounded() -> TestResult {
    let mut original = process(4)?;
    let mut east = item("east", "east", 700, 900)?;
    let mut west = item("west", "west", 700, 900)?;
    east.failure_domains.insert("model:a".into());
    west.failure_domains.insert("model:b".into());
    original.observe_step(
        &query(vec![east, west])?,
        &bindings(&[("east", "east"), ("west", "west")]),
    )?;
    let body = payload(&original.checkpoint()?);
    let b = body
        .windows(7)
        .rposition(|window| window == b"model:b")
        .ok_or("model:b missing")?;
    let mut shared = body.clone();
    shared[b..b + 7].copy_from_slice(b"model:a");
    refuses(&shared);
    // With two domains per component the tail is: count + two (count + text7 + text11) rows.
    let component_bytes = 4 + 8 + 7 + 8 + 11;
    let start = body.len() - 4 - 2 * component_bytes;
    let mut swapped = body.clone();
    swapped[start + 4..start + 4 + component_bytes]
        .copy_from_slice(&body[start + 4 + component_bytes..]);
    swapped[start + 4 + component_bytes..]
        .copy_from_slice(&body[start + 4..start + 4 + component_bytes]);
    refuses(&swapped);
    for offset in [start, start + 4] {
        let mut oversized = body.clone();
        oversized[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        refuses(&oversized);
    }
    let sensor = body
        .windows(11)
        .rposition(|window| window == b"sensor:west")
        .ok_or("sensor missing")?;
    let mut without_sensor = body.clone();
    without_sensor[sensor..sensor + 11].copy_from_slice(b"zzzzzz:west");
    refuses(&without_sensor);
    let mut bad_domain = body.clone();
    bad_domain[b] = 0;
    refuses(&bad_domain);
    Ok(())
}

#[test]
fn full_lifetime_capacity_roundtrips_without_resetting_or_refunding_any_source() -> TestResult {
    let mut original = process(MAX_UNIQUE_SOURCES)?;
    for start in (0..MAX_UNIQUE_SOURCES).step_by(MAX_EVIDENCE) {
        let mut evidence = Vec::new();
        let mut mapping = BTreeMap::new();
        for n in start..start + MAX_EVIDENCE {
            let id = format!("observation:{n:04}");
            mapping.insert(id.clone(), Some(ContentDigest::sha256(id.as_bytes())));
            evidence.push(item(&id, "east", 1, 2)?);
        }
        original.observe_step(&query(evidence)?, &mapping)?;
    }
    let mut resumed = restored(&original)?;
    assert_eq!(resumed.sources_seen(), MAX_UNIQUE_SOURCES);
    assert_eq!(resumed.admitted_sources().len(), MAX_UNIQUE_SOURCES);
    resumed.reset_regime(RegimeResetReason::OperatorReset {
        reason: "new regime".into(),
    });
    let mut resumed = restored(&resumed)?;
    let additional = query(vec![item("new", "west", 1, 2)?])?;
    assert!(matches!(
        resumed.observe_step(&additional, &bindings(&[("new", "new source")])),
        Err(UniqueSourceError::SourceCapacity { .. })
    ));
    Ok(())
}

#[test]
fn exact_reset_bytes_and_maximum_intrinsic_domain_survive_export() -> TestResult {
    let mut original = process(2)?;
    let sensor = "x".repeat(crate::model::MAX_TEXT);
    let mut observation = item("max-sensor", &sensor, 700, 900)?;
    // Declared domains remain <=256 bytes. Fusion itself adds the longer intrinsic domain.
    observation.failure_domains = ["model:fixture".into()].into_iter().collect();
    original.observe_step(
        &query(vec![observation])?,
        &bindings(&[("max-sensor", "source")]),
    )?;
    restored(&original)?;
    let reason = "🚧".repeat(65_536 / 4);
    original.reset_regime(RegimeResetReason::SensorHealthDegraded {
        sensor: "\0\n".into(),
        reason: reason.clone(),
    });
    let mut resumed = restored(&original)?;
    let neutral = query(Vec::new())?;
    assert_eq!(
        original.observe_step(&neutral, &BTreeMap::new())?,
        resumed.observe_step(&neutral, &BTreeMap::new())?
    );
    original.reset_regime(RegimeResetReason::OperatorReset {
        reason: reason + "x",
    });
    let head = original.transcript_head();
    assert_eq!(
        original.checkpoint(),
        Err(UniqueSourceCheckpointError::Limit)
    );
    assert_eq!(original.transcript_head(), head);
    Ok(())
}

#[test]
fn canonical_declared_digest_algorithms_survive_without_laboratory_alias_slots() -> TestResult {
    let mut original = process(2)?;
    let source = ContentDigest::sha256(b"one source");
    let mapping = BTreeMap::from([
        ("east".into(), Some(source.with_laboratory(true))),
        (
            "west".into(),
            Some(ContentDigest::new(DigestAlgorithm::Blake3, [0; 32])),
        ),
    ]);
    original.observe_step(
        &query(vec![
            item("east", "east", 700, 900)?,
            item("west", "west", 700, 900)?,
        ])?,
        &mapping,
    )?;
    let mut resumed = restored(&original)?;
    assert!(
        resumed
            .admitted_sources()
            .all(|(source, _, _)| !source.is_laboratory())
    );
    let (_, step) = resumed.observe_step(
        &query(vec![item("alias", "east", 700, 900)?])?,
        &BTreeMap::from([("alias".into(), Some(source))]),
    )?;
    assert_eq!(step.step().step_delta_llr, LlrInterval::point(0)?);
    assert_eq!(step.sources_seen(), 2);
    Ok(())
}
