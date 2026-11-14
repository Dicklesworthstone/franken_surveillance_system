#![forbid(unsafe_code)]
#![cfg(unix)]
//! Event source custody through explicit unknown-time publication and readback.

use std::{cell::Cell, error::Error, path::PathBuf, sync::Arc};

use asupersync::bytes::Bytes;
use fss_container::flv_avc::SourceKey;
use fss_core::{BudgetVector, ContentDigest, OperationId, RootAuthoritySpec};
use fss_geometry::WorkBudget;
use fss_object::{
    HostSpoolIo,
    effect_journal::{EffectJournalLimits, FileEffectJournal},
};
use fss_reference::{
    ReferenceDeployment, ReplayCx,
    unifi_direct::{
        archive, event_evidence,
        events::{Frame, Kind},
    },
};
use fss_runtime::effect_journal::EffectJournalStore;

struct Access(ContentDigest);
impl archive::RetainAuthority for Access {
    fn permits(&self, retention: ContentDigest, _: ContentDigest) -> bool {
        retention == self.0
    }
}
impl archive::ReadAuthority for Access {
    fn permits(&self, retention: ContentDigest, _: ContentDigest) -> bool {
        retention == self.0
    }
}
struct Deny;
struct Cutoff(Cell<usize>);
impl archive::RetainAuthority for Cutoff {
    fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
        let next = self.0.get() + 1;
        self.0.set(next);
        next <= 4
    }
}
impl archive::RetainAuthority for Deny {
    fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
        false
    }
}
impl archive::ReadAuthority for Deny {
    fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
        false
    }
}

#[test]
fn event_preparation_refuses_invalid_claims_without_losing_source() -> Result<(), Box<dyn Error>> {
    let source = Bytes::from_static(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"EventSmartAudio","messageId":7,"responseExpected":false,"payload":{}}"#);
    let frame = Frame::from_untrusted_source(source.clone()).map_err(|_| "event refused")?;
    assert_eq!(frame.kind(), Kind::SmartAudio);
    let key = SourceKey {
        connection: 1,
        generation: 1,
    };
    let camera = ContentDigest::sha256(b"fixture camera");
    let retention = ContentDigest::sha256(b"fixture retention");
    let prepared = event_evidence::Prepared::new(&frame, key, camera, retention)?;
    assert_eq!(prepared.source_digest(), ContentDigest::sha256(&source));
    assert!(
        event_evidence::Prepared::new(
            &frame,
            SourceKey {
                connection: 0,
                generation: 1
            },
            camera,
            retention
        )
        .is_err()
    );
    assert!(
        event_evidence::Prepared::new(
            &frame,
            key,
            camera,
            ContentDigest::sha256(b"lab").with_laboratory(true)
        )
        .is_err()
    );
    let malformed = Bytes::from_static(br#"{"functionName":"EventSmartAudio"}"#);
    let (_, returned) = match Frame::from_untrusted_source(malformed.clone()) {
        Err(value) => value,
        Ok(_) => return Err("malformed event accepted".into()),
    };
    assert_eq!(returned, malformed);
    assert_eq!(frame.source(), source.as_ref());
    Ok(())
}

#[test]
#[ignore = "requires a fresh private FSS_EVENT_ARCHIVE_TEST_ROOT; retains all test files"]
fn event_archive_retains_and_reopens_exact_source() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;

    let root =
        PathBuf::from(std::env::var_os("FSS_EVENT_ARCHIVE_TEST_ROOT").ok_or("missing test root")?);
    if !root.is_absolute()
        || !root.is_dir()
        || std::fs::metadata(&root)?.permissions().mode() & 0o077 != 0
    {
        return Err("expected a private existing test root".into());
    }
    let authority = fss_core::region::ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:event-archive-fixture".into(),
        operation_id: OperationId::parse("operation:event-archive-fixture")?,
        principal: "principal:fixture".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 1,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"event archive fixture"),
        generation: 1,
    })?;
    let replay = ReplayCx::from_context_authority(&authority, root.clone())?;
    let mut deployment =
        ReferenceDeployment::open(&root.join("archive"), "site:event-fixture", &replay)?;
    let store = |name: &str| -> Result<Box<dyn EffectJournalStore>, Box<dyn Error>> {
        Ok(Box::new(FileEffectJournal::create(
            root.join(name),
            EffectJournalLimits::default(),
            Arc::new(HostSpoolIo),
        )?))
    };
    let scope = ContentDigest::sha256(b"event archive journal");
    let retention = ContentDigest::sha256(b"event archive retention");
    let camera = ContentDigest::sha256(b"event archive camera claim");
    let access = Access(retention);
    let mut journal =
        archive::journal::UnknownTimeJournal::create(store("journal")?, scope, &replay)?;
    let mut keeper =
        archive::journal::UnknownTimeAnchorKeeper::create(store("keeper")?, &journal, &replay)?;
    let source = Bytes::from_static(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"EventSmartAudio","messageId":7,"responseExpected":false,"payload":{"levelDb":-40}}"#);
    let frame = Frame::from_untrusted_source(source.clone()).map_err(|_| "event refused")?;
    let key = SourceKey {
        connection: 5,
        generation: 3,
    };
    let plan = event_evidence::Prepared::new(&frame, key, camera, retention)?;
    let pin = archive::UnknownTimePin::from_event_plan(&plan);
    assert!(
        archive::publish_unknown_time_event_anchored(
            &plan,
            &mut deployment,
            &Deny,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &replay,
            &mut journal,
            &mut keeper
        )
        .is_err()
    );
    assert_eq!(frame.source(), source.as_ref());
    archive::publish_unknown_time_event_anchored(
        &plan,
        &mut deployment,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &replay,
        &mut journal,
        &mut keeper,
    )?;
    assert!(
        archive::read_unknown_time_event(
            &mut deployment,
            pin,
            &Deny,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &replay
        )
        .is_err()
    );
    let recovered = archive::read_unknown_time_event(
        &mut deployment,
        pin,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &replay,
    )?;
    assert_eq!(
        recovered.publication_state(),
        archive::SourcePublicationState::Ledgered
    );
    assert_eq!(recovered.key(), key);
    assert_eq!(recovered.camera_claim(), camera);
    assert_eq!(recovered.frame().kind(), Kind::SmartAudio);
    assert_eq!(recovered.frame().source(), source.as_ref());
    assert_eq!(
        event_evidence::Prepared::from_recovered(&recovered)
            .manifest()
            .root(),
        pin.root
    );

    // Refuse after staging, reopen the independently anchored histories, and
    // recover the pending source without claiming publication succeeded.
    let pending_source = Bytes::from_static(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"EventSmartAudio","messageId":8,"responseExpected":false,"payload":{"levelDb":-35}}"#);
    let pending_frame = Frame::from_untrusted_source(pending_source.clone())
        .map_err(|_| "pending event refused")?;
    let pending_plan = event_evidence::Prepared::new(&pending_frame, key, camera, retention)?;
    let pending_pin = archive::UnknownTimePin::from_event_plan(&pending_plan);
    let cutoff = Cutoff(Cell::new(0));
    assert!(
        archive::publish_unknown_time_event_anchored(
            &pending_plan,
            &mut deployment,
            &cutoff,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &replay,
            &mut journal,
            &mut keeper,
        )
        .is_err()
    );
    assert_eq!(cutoff.0.get(), 5);
    assert_eq!(journal.pending(), Some(pending_pin));
    let journal_anchor = journal.anchor();
    let keeper_anchor = keeper.anchor();
    drop(keeper);
    drop(journal);
    drop(deployment);
    let journal_store = FileEffectJournal::open(
        root.join("journal"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
        journal_anchor,
    )?;
    let mut journal = archive::journal::UnknownTimeJournal::reopen(
        Box::new(journal_store),
        scope,
        journal_anchor,
        &replay,
    )?;
    let keeper_store = FileEffectJournal::open(
        root.join("keeper"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
        keeper_anchor,
    )?;
    let mut keeper = archive::journal::UnknownTimeAnchorKeeper::reopen(
        Box::new(keeper_store),
        &journal,
        keeper_anchor,
        &replay,
    )?;
    let mut deployment =
        ReferenceDeployment::open(&root.join("archive"), "site:event-fixture", &replay)?;
    assert!(
        archive::read_staged_unknown_time_event(
            &deployment,
            &journal,
            &keeper,
            &Deny,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &replay,
        )
        .is_err()
    );
    let staged = archive::read_staged_unknown_time_event(
        &deployment,
        &journal,
        &keeper,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &replay,
    )?;
    assert_eq!(
        staged.publication_state(),
        archive::SourcePublicationState::Staged
    );
    assert_eq!(staged.frame().source(), pending_source.as_ref());
    let staged_plan = event_evidence::Prepared::from_recovered(&staged);
    assert_eq!(staged_plan.manifest().root(), pending_pin.root);
    archive::publish_unknown_time_event_anchored(
        &staged_plan,
        &mut deployment,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &replay,
        &mut journal,
        &mut keeper,
    )?;
    let final_event = archive::read_unknown_time_event(
        &mut deployment,
        pending_pin,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &replay,
    )?;
    assert_eq!(final_event.frame().source(), pending_source.as_ref());
    Ok(())
}
