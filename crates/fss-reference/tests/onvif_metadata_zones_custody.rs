#![forbid(unsafe_code)]
//! Actual retained XML -> bounded vendor-zone observations under shared two-pass custody.
//! These source fixtures establish no camera calibration, physical identity or coverage.

use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, EffectIntent, EffectState,
    IdempotencyKey, ObligationId, OperationId, Plane, ProvenanceClass, RootAuthoritySpec, SensorId,
    TimestampNs,
};
use fss_reference::onvif::metadata::tracks::{
    RetainedTrackError, RetainedTracklets, TrackReadLimits, TrackSourcePin,
};
use fss_reference::onvif::metadata::zones::contract::{
    VendorZone, ZoneError, ZonePolicy, ZoneRelation, ZoneTransitionKind, ZoneUnavailable,
};
use fss_reference::onvif::metadata::zones::{RetainedZoneError, RetainedZones, ZoneReadLimits};
use fss_reference::onvif::metadata::{Interpretation, SourceBinding, retain_with_interpretation};
use fss_reference::{ReferenceDeployment, ReplayAdmissionError, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:onvif-zones-test";
const PRIVATE_MODULE: &str = "private_zone_module_canary";
const PRIVATE_OBJECT: &str = "910000011";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..64 {
            let root = std::env::temp_dir().join(format!(
                "fss-onvif-zones-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => return Ok(Self(root)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("owned fixture directory capacity".into())
    }

    fn cx(&self) -> Test<ReplayCx> {
        context(&self.0)
    }

    fn retain(&self, bytes: &[u8]) -> Test<TrackSourcePin> {
        let cx = self.cx()?;
        let mut deployment = ReferenceDeployment::open(&self.0, SITE, &cx)?;
        let source = retain_with_interpretation(
            &mut deployment,
            binding()?,
            bytes,
            Interpretation::AnalyticsV2,
            &cx,
        )?;
        Ok(TrackSourcePin::Xml {
            identity: source.identity(),
            root: source.publication_root(),
        })
    }

    fn tracks(&self, pins: &[TrackSourcePin]) -> Test<RetainedTracklets> {
        Ok(RetainedTracklets::open(
            &self.0,
            SITE,
            pins,
            ZoneReadLimits::default().source,
            &self.cx()?,
        )?)
    }

    fn query(
        &self,
        pins: &[TrackSourcePin],
        policy: &ZonePolicy,
        limits: ZoneReadLimits,
    ) -> Test<RetainedZones> {
        Ok(RetainedZones::open(
            &self.0,
            SITE,
            pins,
            policy,
            limits,
            &self.cx()?,
        )?)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:onvif-zones-test".into(),
        operation_id: OperationId::parse("operation:onvif-zones-test")?,
        principal: "operator:onvif-zones-test".into(),
        capabilities: vec![fss_reference::ADP_REPLAY_ROW_ID.into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(128 * 1024 * 1024)
            .storage_operations(16_384)
            .build()?,
        privacy_scope: "privacy:fixture".into(),
        retention_scope: "retention:fixture".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority_read_only(
        &authority, root,
    )?)
}

fn binding() -> Test<SourceBinding> {
    Ok(SourceBinding {
        sensor_id: SensorId::parse("sensor:front")?,
        device_generation: ContentDigest::sha256(b"zone-device-generation"),
        profile_generation: ContentDigest::sha256(b"zone-profile-generation"),
        profile_token: "private-zone-profile-canary".into(),
        receive_interval: CaptureInterval::new(TimestampNs(100), TimestampNs(110))?,
    })
}

fn object(bounds: [&str; 4]) -> String {
    format!(
        r#"<t:Object ObjectId="{PRIVATE_OBJECT}"><t:Appearance><t:Shape><t:BoundingBox left="{}" right="{}" top="{}" bottom="{}"/><t:CenterOfGravity x="0.5" y="0.5"/></t:Shape></t:Appearance></t:Object>"#,
        bounds[0], bounds[1], bounds[2], bounds[3]
    )
}

fn frame(second: u8, object: &str) -> String {
    format!(
        r#"<t:Frame UtcTime="2026-11-09T00:00:{second:02}Z" Source="{PRIVATE_MODULE}">{object}</t:Frame>"#
    )
}

fn xml(frames: &str) -> Vec<u8> {
    format!(
        r#"<t:MetadataStream xmlns:t="http://www.onvif.org/ver10/schema"><t:VideoAnalytics>{frames}</t:VideoAnalytics></t:MetadataStream>"#
    )
    .into_bytes()
}

fn observed_boxes() -> Vec<u8> {
    xml(&(frame(0, &object(["2", "3", ".2", ".4"]))
        + &frame(1, &object([".2", ".4", ".2", ".4"]))
        + &frame(2, &object([".8", "1.2", ".2", ".4"]))
        + &frame(
            3,
            &format!(r#"<t:Object ObjectId="{PRIVATE_OBJECT}"><t:Appearance/></t:Object>"#),
        )))
}

fn policy_from(snapshot: &RetainedTracklets) -> Test<ZonePolicy> {
    let frame = snapshot.report().frames.first().ok_or("fixture frame")?;
    let occurrence = snapshot
        .report()
        .occurrences
        .first()
        .ok_or("fixture object occurrence")?;
    Ok(ZonePolicy {
        zones: vec![VendorZone {
            id: "private_zone_annotation".into(),
            scope: frame.reference.scope,
            module_digest: frame.module_digest.ok_or("fixture named module")?,
            frame_transform_digest: frame.transformation_digest,
            object_transform_digest: occurrence.transformation_digest,
            min: [0, 0],
            max: [1_000_000, 1_000_000],
            margin: 0,
        }],
    })
}

#[test]
fn cold_xml_zone_observations_preserve_the_exact_original_tracks_and_policy() -> Test {
    let dir = Directory::new("cold-xml")?;
    let bytes = observed_boxes();
    let pin = dir.retain(&bytes)?;
    let original = dir.tracks(&[pin])?;
    let policy = policy_from(&original)?;
    let result = dir.query(&[pin], &policy, ZoneReadLimits::default())?;
    assert_eq!(result.snapshot().report(), original.report());
    assert_eq!(result.snapshot().report().tracklets.len(), 1);
    assert_eq!(result.snapshot().sources()[0].pin, pin);
    assert_eq!(
        result.snapshot().sources()[0].source_digest,
        ContentDigest::sha256(&bytes)
    );
    assert_eq!(
        result.report().tracklet_report_digest,
        original.report().report_digest
    );
    assert_eq!(result.report().policy, policy);
    assert_eq!(result.report().policy_digest, policy.digest()?);
    assert_eq!(
        result
            .report()
            .cells
            .iter()
            .map(|row| row.relation)
            .collect::<Vec<_>>(),
        [
            ZoneRelation::Outside,
            ZoneRelation::Inside,
            ZoneRelation::Boundary,
            ZoneRelation::Unavailable
        ]
    );
    assert_eq!(
        result.report().cells[3].reason,
        Some(ZoneUnavailable::MissingShape)
    );
    assert_eq!(
        result
            .report()
            .frame_samples
            .iter()
            .map(|row| (row.inside, row.outside, row.boundary, row.unavailable))
            .collect::<Vec<_>>(),
        [(0, 1, 0, 0), (1, 0, 0, 0), (0, 0, 1, 0), (0, 0, 0, 1)]
    );
    let transitions = &result.report().transitions;
    assert_eq!(transitions.len(), 2);
    assert_eq!(
        transitions[0].kind,
        ZoneTransitionKind::EnteredBetweenObservations
    );
    assert_eq!(
        (
            transitions[0].previous_occurrence,
            transitions[0].occurrence
        ),
        (Some(0), 1)
    );
    assert_eq!(
        transitions[1].kind,
        ZoneTransitionKind::ObservationInterrupted
    );
    assert_eq!(
        (
            transitions[1].previous_occurrence,
            transitions[1].occurrence
        ),
        (Some(1), 3)
    );
    for transition in transitions {
        assert_eq!(
            transition.tracklet_identity,
            original.report().tracklets[0].identity
        );
    }
    assert_eq!(result.plane(), Plane::Cognition);
    assert_eq!(result.provenance(), ProvenanceClass::Derived);
    assert_eq!(result.source_provenance(), ProvenanceClass::VendorClaimed);
    let debug = format!("{result:?}");
    for private in [
        PRIVATE_MODULE,
        PRIVATE_OBJECT,
        "private_zone_annotation",
        "private-zone-profile-canary",
        "2026-11-09T",
    ] {
        assert!(!debug.contains(private));
    }
    let cold = dir.query(&[pin], &policy, ZoneReadLimits::default())?;
    assert_eq!(cold.digest(), result.digest());
    assert_eq!(cold.report(), result.report());
    Ok(())
}

#[test]
fn retained_policy_pins_make_wrong_domains_unavailable_without_rewriting_sources() -> Test {
    let dir = Directory::new("coordinate-pins")?;
    let pin = dir.retain(&xml(&frame(0, &object([".2", ".4", ".2", ".4"]))))?;
    let original = dir.tracks(&[pin])?;
    let policy = policy_from(&original)?;
    let baseline = dir.query(&[pin], &policy, ZoneReadLimits::default())?;
    assert_eq!(baseline.report().cells[0].relation, ZoneRelation::Inside);
    for (index, reason) in [
        ZoneUnavailable::ScopeMismatch,
        ZoneUnavailable::ModuleMismatch,
        ZoneUnavailable::FrameTransformMismatch,
        ZoneUnavailable::ObjectTransformMismatch,
    ]
    .into_iter()
    .enumerate()
    {
        let mut changed = policy.clone();
        let wrong = ContentDigest::sha256(b"different declared domain");
        match index {
            0 => changed.zones[0].scope = wrong,
            1 => changed.zones[0].module_digest = wrong,
            2 => changed.zones[0].frame_transform_digest = wrong,
            _ => changed.zones[0].object_transform_digest = wrong,
        }
        let query = dir.query(&[pin], &changed, ZoneReadLimits::default())?;
        assert_eq!(query.report().cells[0].relation, ZoneRelation::Unavailable);
        assert_eq!(query.report().cells[0].reason, Some(reason));
        assert_eq!(query.report().frame_samples[0].outside, 0);
        assert_ne!(
            query.report().policy_digest,
            baseline.report().policy_digest
        );
        assert_ne!(query.digest(), baseline.digest());
        assert_eq!(query.snapshot().report(), original.report());
    }
    let wrong_root = TrackSourcePin::Xml {
        identity: pin.identity(),
        root: ContentDigest::sha256(b"wrong publication root"),
    };
    assert!(
        RetainedZones::open(
            &dir.0,
            SITE,
            &[wrong_root],
            &policy,
            ZoneReadLimits::default(),
            &dir.cx()?
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn exact_source_and_work_balances_cover_both_complete_zone_passes() -> Test {
    let dir = Directory::new("two-pass-budget")?;
    let pin = dir.retain(&observed_boxes())?;
    let policy = policy_from(&dir.tracks(&[pin])?)?;
    let base = ZoneReadLimits::default();
    let completed = dir.query(&[pin], &policy, base)?;
    let usage = completed.snapshot().usage();
    assert!(usage.indexed_reads.used_bytes > 1);
    assert!(usage.indexed_reads.used_read_attempts > 1);
    assert!(usage.reserved_work_units > 1);
    for source in [
        TrackReadLimits {
            max_stored_bytes: usage.indexed_reads.used_bytes - 1,
            ..base.source
        },
        TrackReadLimits {
            max_indexed_reads: usage.indexed_reads.used_read_attempts - 1,
            ..base.source
        },
        TrackReadLimits {
            max_work_units: usage.reserved_work_units - 1,
            ..base.source
        },
    ] {
        let second_pass = Cell::new(false);
        let cx = dir.cx()?.with_admission(|stage| {
            if stage == "onvif_tracks:revalidate" {
                second_pass.set(true);
            }
            Ok(())
        });
        let result = RetainedZones::open(
            &dir.0,
            SITE,
            &[pin],
            &policy,
            ZoneReadLimits { source, ..base },
            &cx,
        );
        assert!(
            matches!(result, Err(RetainedZoneError::Source(error)) if matches!(error.as_ref(), RetainedTrackError::Limit))
        );
        assert!(second_pass.get());
    }
    let exact = ZoneReadLimits {
        source: TrackReadLimits {
            max_stored_bytes: usage.indexed_reads.used_bytes,
            max_indexed_reads: usage.indexed_reads.used_read_attempts,
            max_work_units: usage.reserved_work_units,
            ..base.source
        },
        ..base
    };
    let accepted = dir.query(&[pin], &policy, exact)?;
    let exact_reads = accepted.snapshot().usage().indexed_reads;
    assert_eq!(exact_reads.used_bytes, usage.indexed_reads.used_bytes);
    assert_eq!(
        exact_reads.used_read_attempts,
        usage.indexed_reads.used_read_attempts
    );
    assert_eq!(exact_reads.remaining_bytes, Some(0));
    assert_eq!(exact_reads.remaining_read_attempts, Some(0));
    assert_eq!(
        accepted.snapshot().usage().reserved_work_units,
        usage.reserved_work_units
    );
    assert_eq!(accepted.report(), completed.report());
    Ok(())
}

#[test]
fn invalid_policy_impossible_work_and_missing_store_refuse_without_initialization() -> Test {
    let dir = Directory::new("no-initialization")?;
    let pin = TrackSourcePin::Xml {
        identity: ContentDigest::sha256(b"fixture identity"),
        root: ContentDigest::sha256(b"fixture publication root"),
    };
    let policy = ZonePolicy {
        zones: vec![VendorZone {
            id: "fixture_zone".into(),
            scope: ContentDigest::sha256(b"fixture scope"),
            module_digest: ContentDigest::sha256(b"fixture module"),
            frame_transform_digest: ContentDigest::sha256(b"fixture frame coordinates"),
            object_transform_digest: ContentDigest::sha256(b"fixture object coordinates"),
            min: [0, 0],
            max: [1_000_000, 1_000_000],
            margin: 0,
        }],
    };
    let mut invalid = policy.clone();
    invalid.zones[0].min = invalid.zones[0].max;
    let attempted = Cell::new(false);
    let cx = dir.cx()?.with_admission(|_| {
        attempted.set(true);
        Ok(())
    });
    assert!(matches!(
        RetainedZones::open(
            &dir.0,
            SITE,
            &[pin],
            &invalid,
            ZoneReadLimits::default(),
            &cx
        ),
        Err(RetainedZoneError::Projection(ZoneError::InvalidPolicy))
    ));
    assert!(!attempted.get());
    let mut too_little = ZoneReadLimits::default();
    too_little.source.max_work_units = 1;
    assert!(RetainedZones::open(&dir.0, SITE, &[pin], &policy, too_little, &cx).is_err());
    let mut replay_only = ZoneReadLimits::default();
    replay_only.projection.max_work_units = replay_only.source.projection.max_work_units;
    assert!(RetainedZones::open(&dir.0, SITE, &[pin], &policy, replay_only, &cx).is_err());
    assert!(!attempted.get());
    assert_eq!(fs::read_dir(&dir.0)?.count(), 0);
    let missing = dir.0.join("missing");
    assert!(
        RetainedZones::open(
            &missing,
            SITE,
            &[pin],
            &policy,
            ZoneReadLimits::default(),
            &context(&missing)?
        )
        .is_err()
    );
    assert!(!missing.exists());
    assert!(
        RetainedZones::open(
            &dir.0,
            SITE,
            &[],
            &policy,
            ZoneReadLimits::default(),
            &dir.cx()?
        )
        .is_err()
    );
    assert_eq!(fs::read_dir(&dir.0)?.count(), 0);
    Ok(())
}

#[test]
fn second_pass_revalidates_a_later_source_with_no_zone_cells() -> Test {
    let dir = Directory::new("later-empty-tamper")?;
    let first = dir.retain(&observed_boxes())?;
    let empty_bytes = xml("");
    let empty = dir.retain(&empty_bytes)?;
    let pins = [first, empty];
    let policy = policy_from(&dir.tracks(&pins)?)?;
    let initial = dir.query(&pins, &policy, ZoneReadLimits::default())?;
    assert_eq!(initial.snapshot().sources().len(), 2);
    assert_eq!(initial.snapshot().sources()[1].pin, empty);
    assert_eq!(initial.snapshot().sources()[1].analytics_frames, 0);
    assert_eq!(initial.snapshot().sources()[1].empty_analytics_documents, 1);
    let source_path = {
        let cx = dir.cx()?;
        let deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        deployment
            .publisher()
            .spool()
            .object_path(ContentDigest::sha256(&empty_bytes))
    };
    let changed = Cell::new(false);
    let cx = dir.cx()?.with_admission(|stage| {
        if stage == "onvif_tracks:revalidate" && !changed.replace(true) {
            fs::write(&source_path, b"changed-empty-zone-source")
                .map_err(|_| ReplayAdmissionError::Authority)?;
        }
        Ok(())
    });
    assert!(
        RetainedZones::open(&dir.0, SITE, &pins, &policy, ZoneReadLimits::default(), &cx).is_err()
    );
    assert!(changed.get());
    Ok(())
}

#[test]
fn cancellation_during_projection_revalidation_or_final_admission_returns_no_report() -> Test {
    let dir = Directory::new("cancellation")?;
    let pin = dir.retain(&observed_boxes())?;
    let policy = policy_from(&dir.tracks(&[pin])?)?;
    for stop in [
        "onvif_zones:projection",
        "onvif_tracks:revalidate",
        "onvif_tracks:complete",
    ] {
        let cx = dir.cx()?.with_admission(|stage| {
            if stage == stop {
                Err(ReplayAdmissionError::Cancelled)
            } else {
                Ok(())
            }
        });
        let result = RetainedZones::open(
            &dir.0,
            SITE,
            &[pin],
            &policy,
            ZoneReadLimits::default(),
            &cx,
        );
        assert!(match result {
            Err(RetainedZoneError::Projection(ZoneError::Cancelled)) => true,
            Err(RetainedZoneError::Source(error)) =>
                matches!(error.as_ref(), RetainedTrackError::Cancelled),
            _ => false,
        });
    }
    Ok(())
}

#[test]
fn zones_query_neither_reconciles_pending_effects_nor_publishes_derived_roots() -> Test {
    let dir = Directory::new("pending-effects")?;
    let pin = dir.retain(&observed_boxes())?;
    let policy = policy_from(&dir.tracks(&[pin])?)?;
    {
        let cx = dir.cx()?;
        let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        for label in ["prepared", "committed"] {
            let intent = EffectIntent::new(
                OperationId::parse(format!("operation:zones:{label}"))?,
                IdempotencyKey::parse(format!("idempotency:zones:{label}"))?,
                "fixture:notification",
                ContentDigest::sha256(label.as_bytes()),
                ContentDigest::sha256(b"zone-authority"),
            )?;
            deployment.effects_mut().prepare(
                intent.clone(),
                ObligationId::parse(format!("obligation:zones:{label}"))?,
                "notification observed",
                TimestampNs(1),
            )?;
            if label == "committed" {
                deployment.effects_mut().transition(
                    &intent.operation_id,
                    EffectState::Committed,
                    TimestampNs(2),
                    None,
                    None,
                )?;
            }
        }
    }
    let ledger = dir.0.join("ledger/journal.fssj");
    let effects = dir.0.join("effects/journal.fssj");
    let before = (fs::read(&ledger)?, fs::read(&effects)?);
    assert_eq!(
        dir.query(&[pin], &policy, ZoneReadLimits::default())?
            .report()
            .cells
            .len(),
        4
    );
    assert_eq!(fs::read(ledger)?, before.0);
    assert_eq!(fs::read(effects)?, before.1);
    Ok(())
}
