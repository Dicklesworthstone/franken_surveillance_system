#![forbid(unsafe_code)]
#![cfg(unix)]
//! Controller handoff bindings and durable effect preparation without network I/O.
use asupersync::http::h1::Response;
use fss_core::{
    BudgetVector, ContentDigest, IdempotencyKey, OperationId, RegionId, RegionKind,
    RootAuthoritySpec, RuntimeGrant, TimestampNs,
};
use fss_object::{
    HostSpoolIo,
    effect_journal::{EffectJournalLimits, FileEffectJournal},
};
use fss_reference::unifi_direct::{
    camera_api::{Session, SettingsObservation, WriteOutcome},
    handoff::{Error, Plan, Preconditions, Readback},
};
use fss_runtime::{
    authority::AuthorityCx,
    effect::{CommitApproval, EffectCoordinator, PrepareSpec},
    lease::LeaseRegistry,
};
use std::{error::Error as StdError, net::Ipv4Addr, path::PathBuf, sync::Arc};

type Test = Result<(), Box<dyn StdError>>;
struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn observed(
    peer: Ipv4Addr,
    generation: u64,
    body: &[u8],
) -> Result<SettingsObservation, Box<dyn StdError>> {
    let mut s = Session::new(peer, generation)?;
    let r = s.prepare_login(br#"{"username":"fixture","password":"synthetic"}"#)?;
    s.finish_write(r, WriteOutcome::Written)?;
    s.accept_login(
        Response::new(200, "OK", Vec::new()).with_header("Set-Cookie", "authId=synthetic"),
    )?;
    let r = s.prepare_status()?;
    s.finish_write(r, WriteOutcome::Written)?;
    s.accept_status(Response::new(200, "OK", b"{}".to_vec()))?;
    let r = s.prepare_settings()?;
    s.finish_write(r, WriteOutcome::Written)?;
    Ok(s.accept_settings(Response::new(200, "OK", body.to_vec()))?)
}
fn conditions(settings: SettingsObservation) -> Preconditions {
    Preconditions {
        camera: ContentDigest::sha256(b"fixture camera"),
        peer_admission: ContentDigest::sha256(b"fixture peer policy"),
        session_generation: 1,
        lease_fence: 1,
        settings,
    }
}

#[test]
fn plans_bind_exact_forward_prior_and_live_conditions() -> Test {
    let peer = Ipv4Addr::new(192, 168, 1, 30);
    let target = Ipv4Addr::new(192, 168, 1, 40);
    let prior = observed(peer, 1, br#"{"controller":{"addr":"192.168.1.10"}}"#)?;
    let c = conditions(prior);
    let plan = Plan::new(peer, target, c)?;
    assert_ne!(plan.request_digest(), plan.reverse_preview_digest());
    assert!(!format!("{plan:?}").contains("192.168."));
    plan.check_current(c)?;
    assert_eq!(
        plan.check_current(Preconditions {
            lease_fence: 2,
            ..c
        }),
        Err(Error::Stale)
    );
    assert!(
        plan.check_current(Preconditions {
            session_generation: 2,
            ..c
        })
        .is_err()
    );
    let changed = observed(peer, 1, br#"{"controller":{"addr":"192.168.1.11"}}"#)?;
    assert_eq!(
        plan.check_current(Preconditions {
            settings: changed,
            ..c
        }),
        Err(Error::Stale)
    );
    assert!(Plan::new(peer, Ipv4Addr::LOCALHOST, c).is_err());
    assert!(Plan::new(peer, Ipv4Addr::new(192, 168, 1, 10), c).is_err());
    assert!(Plan::new(Ipv4Addr::new(192, 168, 1, 31), target, c).is_err());
    let other = Plan::new(peer, Ipv4Addr::new(192, 168, 1, 41), c)?;
    assert_ne!(plan.request_digest(), other.request_digest());
    Ok(())
}

#[test]
fn readback_classifies_untrusted_claims_and_refuses_wrong_binding() -> Test {
    let peer = Ipv4Addr::new(192, 168, 1, 30);
    let prior = observed(peer, 1, br#"{"controller":{"addr":"192.168.1.10"}}"#)?;
    let plan = Plan::new(peer, Ipv4Addr::new(192, 168, 1, 40), conditions(prior))?;
    let cases: [(&[u8], Readback); 6] = [
        (
            br#"{"controller":{"addr":"192.168.1.40"}}"#,
            Readback::Requested,
        ),
        (
            br#"{"controller":{"addr":"192.168.1.10"}}"#,
            Readback::Previous,
        ),
        (
            br#"{"controller":{"addr":"192.168.1.99"}}"#,
            Readback::Different,
        ),
        (br#"{"controller":{"addr":null}}"#, Readback::Unset),
        (br#"{"controller":{}}"#, Readback::Missing),
        (
            br#"{"controller":{"addr":"invalid.example"}}"#,
            Readback::Unsupported,
        ),
    ];
    for (body, expected) in cases {
        assert_eq!(plan.classify_readback(observed(peer, 1, body)?)?, expected);
    }
    let other = observed(
        Ipv4Addr::new(192, 168, 1, 31),
        1,
        br#"{"controller":{"addr":"192.168.1.40"}}"#,
    )?;
    assert_eq!(plan.classify_readback(other), Err(Error::Preconditions));
    let stale = observed(peer, 2, br#"{"controller":{"addr":"192.168.1.40"}}"#)?;
    assert_eq!(plan.classify_readback(stale), Err(Error::Preconditions));
    Ok(())
}

#[test]
fn unknown_or_unset_prior_never_becomes_automatic_restoration() -> Test {
    let peer = Ipv4Addr::new(192, 168, 1, 30);
    let target = Ipv4Addr::new(192, 168, 1, 40);
    for body in [
        br#"{"controller":{}}"#.as_slice(),
        br#"{"controller":{"addr":null}}"#,
        br#"{"controller":{"addr":"controller.example"}}"#,
    ] {
        let c = conditions(observed(peer, 1, body)?);
        assert!(matches!(
            Plan::new(peer, target, c),
            Err(Error::PriorUnknown)
        ));
    }
    Ok(())
}

#[test]
fn exact_plan_can_be_committed_only_through_registered_journaled_effect() -> Test {
    let path = std::fs::canonicalize(std::env::temp_dir())?
        .join(format!("fss-unifi-handoff-journal-{}", std::process::id()));
    std::fs::create_dir(&path)?;
    let temp = Temp(path);
    let store = FileEffectJournal::create(
        temp.0.join("journal"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut effects = EffectCoordinator::with_journal(Box::new(store))?;
    let budget = BudgetVector::ZERO;
    let (authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:handoff-fixture".into(),
            operation_id: OperationId::parse("operation:handoff-owner")?,
            principal: "principal:fixture".into(),
            capabilities: vec![
                RuntimeGrant::CameraManagementPrepare.as_str().into(),
                RuntimeGrant::CameraManagementCommit.as_str().into(),
            ],
            deadline: Some(TimestampNs(1_000_000)),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"fixture"),
            generation: 1,
        },
        RegionId::new("region:handoff-fixture")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let peer = Ipv4Addr::new(192, 168, 1, 30);
    let mut leases = LeaseRegistry::new();
    let camera = ContentDigest::sha256(b"fixture camera");
    let resource = format!("camera:{}", camera.to_text());
    let fence = leases
        .acquire(&resource, authority.region().as_str(), None, TimestampNs(2))?
        .fence;
    let c = Preconditions {
        lease_fence: fence,
        ..conditions(observed(
            peer,
            1,
            br#"{"controller":{"addr":"192.168.1.10"}}"#,
        )?)
    };
    let plan = Plan::new(peer, Ipv4Addr::new(192, 168, 1, 40), c)?;
    let op = OperationId::parse("operation:handoff-fixture")?;
    let prepared = effects.prepare(
        &authority,
        &mut tree,
        &mut leases,
        PrepareSpec {
            operation: &op,
            idempotency_key: IdempotencyKey::parse(op.as_str())?,
            request_digest: plan.request_digest(),
            precondition_digest: plan.precondition_digest(),
            resource: &resource,
            fence,
            prepare_grant: RuntimeGrant::CameraManagementPrepare,
            commit_grant: RuntimeGrant::CameraManagementCommit,
            terminal_predicate: "independent association observation or reconciliation",
        },
        TimestampNs(3),
    )?;
    let approval = CommitApproval {
        prepared_digest: prepared.digest(),
        current_precondition_digest: plan.precondition_digest(),
    };
    plan.check_current(c)?;
    let permit = effects.commit(
        &authority,
        &tree,
        &mut leases,
        prepared,
        TimestampNs(4),
        approval,
    )?;
    assert!(permit.journal_backed());
    assert_eq!(
        permit.prepared().effect_class(),
        "EFFECT-CAMERA-MANAGEMENT-001"
    );
    assert_eq!(permit.prepared().request_digest(), plan.request_digest());
    assert_eq!(
        permit.prepared().precondition_digest(),
        plan.precondition_digest()
    );
    assert_eq!(permit.resource(), plan.resource());
    assert_eq!(permit.fence(), plan.fence());
    assert!(!authority.finalize_report(&tree)?.is_empty());
    Ok(())
}
